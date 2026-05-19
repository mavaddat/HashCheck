/**
 * HashCheck Shell Extension
 * Original work copyright (C) Kai Liu.  All rights reserved.
 * Modified work copyright (C) 2016 Christopher Gurnee.  All rights reserved.
 * Modified work copyright (C) 2021-2026 Mounir IDRASSI.  All rights reserved.
 *
 * Please refer to readme.txt for information about this source code.
 * Please refer to license.txt for details about distribution and modification.
 **/

#include <assert.h>
#include "globals.h"
#include "HashCheckCommon.h"
#include "IsSSD.h"
#include "GetHighMSB.h"
#include <Strsafe.h>

#define PROGRESS_BAR_STEPS 300
#define BLAKE3_TBB_MIN_FILE_SIZE (512ULL * 1024ULL)
#define JOB_QUEUE_WAIT_INTERVAL_MS 200
#define JOB_QUEUE_LOCK_TIMEOUT_MS 30000
#define JOB_QUEUE_FULL_RETRY_LIMIT 50
#define JOB_QUEUE_CAPACITY 16384
#define JOB_QUEUE_MAGIC 0x314A5148UL
#define JOB_QUEUE_VERSION 3

static const TCHAR HASHCHECK_JOB_QUEUE_MUTEX_NAME[] = TEXT("Local\\HashCheck.JobQueue.Mutex.v3");
static const TCHAR HASHCHECK_JOB_QUEUE_EVENT_NAME[] = TEXT("Local\\HashCheck.JobQueue.Event.v3");
static const TCHAR HASHCHECK_JOB_QUEUE_MAP_NAME[] = TEXT("Local\\HashCheck.JobQueue.State.v3");

// The named mutex protects only this short shared-memory update path. FIFO
// ordering comes from the explicit ticket queue, not from mutex wake ordering.
typedef struct {
	ULONGLONG ullJobId;
	DWORD dwProcessId;
	ULONGLONG ullProcessCreationTime;
} HASHCHECK_JOB_QUEUE_ENTRY, *PHASHCHECK_JOB_QUEUE_ENTRY;

typedef struct {
	DWORD dwMagic;
	DWORD dwVersion;
	DWORD cCapacity;
	DWORD iHead;
	DWORD cEntries;
	ULONGLONG ullNextJobId;
	HASHCHECK_JOB_QUEUE_ENTRY rgEntries[JOB_QUEUE_CAPACITY];
} HASHCHECK_JOB_QUEUE_STATE, *PHASHCHECK_JOB_QUEUE_STATE;

C_ASSERT(sizeof(HASHCHECK_JOB_QUEUE_ENTRY) == 24);
C_ASSERT(FIELD_OFFSET(HASHCHECK_JOB_QUEUE_STATE, rgEntries) == 32);

typedef struct {
	HANDLE hQueueMutex;
	HANDLE hQueueEvent;
	HANDLE hMap;
	PHASHCHECK_JOB_QUEUE_STATE pState;
	ULONGLONG ullJobId;
	DWORD dwProcessId;
	ULONGLONG ullProcessCreationTime;
	BOOL bEnqueued;
} HASHCHECK_JOB_SLOT, *PHASHCHECK_JOB_SLOT;

static LONG WINAPI WorkerThreadGetStatus( PCOMMONCONTEXT pcmnctx )
{
	return(InterlockedCompareExchange(&pcmnctx->status, 0, 0));
}

static DWORD WINAPI WorkerThreadGetFlags( PCOMMONCONTEXT pcmnctx )
{
	return((DWORD)InterlockedCompareExchange((PVLONG)&pcmnctx->dwFlags, 0, 0));
}

static VOID WINAPI WorkerThreadSetFlags( PCOMMONCONTEXT pcmnctx, DWORD dwFlags )
{
	for (;;)
	{
		DWORD dwPrevFlags = WorkerThreadGetFlags(pcmnctx);
		DWORD dwNextFlags = dwPrevFlags | dwFlags;

		if (dwPrevFlags == dwNextFlags ||
		    InterlockedCompareExchange((PVLONG)&pcmnctx->dwFlags, (LONG)dwNextFlags, (LONG)dwPrevFlags) == (LONG)dwPrevFlags)
		{
			return;
		}
	}
}

static VOID WINAPI WorkerThreadClearFlags( PCOMMONCONTEXT pcmnctx, DWORD dwFlags )
{
	for (;;)
	{
		DWORD dwPrevFlags = WorkerThreadGetFlags(pcmnctx);
		DWORD dwNextFlags = dwPrevFlags & ~dwFlags;

		if (dwPrevFlags == dwNextFlags ||
		    InterlockedCompareExchange((PVLONG)&pcmnctx->dwFlags, (LONG)dwNextFlags, (LONG)dwPrevFlags) == (LONG)dwPrevFlags)
		{
			return;
		}
	}
}

static BOOL WINAPI WorkerThreadSetStatusIf( PCOMMONCONTEXT pcmnctx, LONG lStatus, LONG lExpectedStatus )
{
	return(InterlockedCompareExchange(&pcmnctx->status, lStatus, lExpectedStatus) == lExpectedStatus);
}

static VOID WINAPI WorkerThreadSetStatus( PCOMMONCONTEXT pcmnctx, LONG lStatus )
{
	InterlockedExchange(&pcmnctx->status, lStatus);
}

static BOOL WINAPI WorkerThreadSetStatusUnlessCanceled( PCOMMONCONTEXT pcmnctx, LONG lStatus )
{
	for (;;)
	{
		LONG lPrevStatus = WorkerThreadGetStatus(pcmnctx);

		if (lPrevStatus == CANCEL_REQUESTED ||
		    lPrevStatus == INACTIVE ||
		    lPrevStatus == CLEANUP_COMPLETED)
		{
			return(lPrevStatus == lStatus);
		}

		if (lPrevStatus == lStatus ||
		    WorkerThreadSetStatusIf(pcmnctx, lStatus, lPrevStatus))
		{
			return(TRUE);
		}
	}
}

static BOOL WINAPI WorkerThreadIsCancelRequested( PCOMMONCONTEXT pcmnctx )
{
	return(WorkerThreadGetStatus(pcmnctx) == CANCEL_REQUESTED);
}

static PTSTR WINAPI AllocLongPath( PCTSTR pszPath )
{
	static const TCHAR szLongPathPrefix[] = TEXT("\\\\?\\");
	static const TCHAR szLongUncPrefix[] = TEXT("\\\\?\\UNC\\");

	if (!pszPath)
		return(NULL);

	if (pszPath[0] == TEXT('\\') && pszPath[1] == TEXT('\\'))
	{
		if (pszPath[2] == TEXT('?') || pszPath[2] == TEXT('.'))
			return(NULL);

		SIZE_T cchPath = SSLen(pszPath);
		PTSTR pszLongPath = (PTSTR)malloc((countof(szLongUncPrefix) + cchPath - 2) * sizeof(TCHAR));

		if (pszLongPath)
			SSChainNCpy2(pszLongPath, szLongUncPrefix, countof(szLongUncPrefix) - 1, pszPath + 2, cchPath - 1);

		return(pszLongPath);
	}

	if (pszPath[0] && pszPath[1] == TEXT(':') && pszPath[2] == TEXT('\\'))
	{
		SIZE_T cchPath = SSLen(pszPath);
		PTSTR pszLongPath = (PTSTR)malloc((countof(szLongPathPrefix) + cchPath) * sizeof(TCHAR));

		if (pszLongPath)
			SSChainNCpy2(pszLongPath, szLongPathPrefix, countof(szLongPathPrefix) - 1, pszPath, cchPath + 1);

		return(pszLongPath);
	}

	return(NULL);
}

HANDLE __fastcall CreateThreadCRT( PVOID pThreadProc, PVOID pvParam )
{
	if (!pThreadProc)
	{
		// If we have a NULL pThreadProc, then we are starting a worker thread,
		// and there is some initialization that we need to take care of...

		PCOMMONCONTEXT pcmnctx = pvParam;
		WorkerThreadSetStatus(pcmnctx, ACTIVE);
		pcmnctx->cSentMsgs = 0;
		pcmnctx->cHandledMsgs = 0;
		pcmnctx->hWndPBTotal = GetDlgItem(pcmnctx->hWnd, IDC_PROG_TOTAL);
		pcmnctx->hWndPBFile = GetDlgItem(pcmnctx->hWnd, IDC_PROG_FILE);
        if (pcmnctx->hUnpauseEvent == NULL)
            pcmnctx->hUnpauseEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
        else
            SetEvent(pcmnctx->hUnpauseEvent);
        if (pcmnctx->hCancelEvent == NULL)
            pcmnctx->hCancelEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        else
            ResetEvent(pcmnctx->hCancelEvent);
		SendMessage(pcmnctx->hWndPBFile, PBM_SETRANGE, 0, MAKELPARAM(0, PROGRESS_BAR_STEPS));

		pThreadProc = WorkerThreadStartup;
	}

	return((HANDLE)_beginthreadex(
		NULL,
		BASE_STACK_SIZE,
		pThreadProc,
		pvParam,
		0,
		NULL
	));
}

static BOOL WINAPI FileOpenShouldAbort( PFNFILEOPENSHOULDABORT pfnShouldAbort,
                                        PVOID pvAbortContext )
{
	return(pfnShouldAbort && pfnShouldAbort(pvAbortContext));
}

static HANDLE __fastcall CreateFileWithLongPathRetryAbortable( PCTSTR pszPath, DWORD dwDesiredAccess,
                                                               DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                                               DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                                                               HANDLE hTemplateFile,
                                                               PFNFILEOPENSHOULDABORT pfnShouldAbort,
                                                               PVOID pvAbortContext )
{
	HANDLE hFile;

	if (FileOpenShouldAbort(pfnShouldAbort, pvAbortContext))
	{
		SetLastError(ERROR_CANCELLED);
		return(INVALID_HANDLE_VALUE);
	}

	hFile = CreateFile(
		pszPath,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		DWORD dwLastError = GetLastError();

		if (FileOpenShouldAbort(pfnShouldAbort, pvAbortContext))
		{
			SetLastError(ERROR_CANCELLED);
			return(INVALID_HANDLE_VALUE);
		}

		PTSTR pszLongPath = AllocLongPath(pszPath);

		if (pszLongPath)
		{
			if (FileOpenShouldAbort(pfnShouldAbort, pvAbortContext))
			{
				SetLastError(ERROR_CANCELLED);
			}
			else
			{
				hFile = CreateFile(
					pszLongPath,
					dwDesiredAccess,
					dwShareMode,
					lpSecurityAttributes,
					dwCreationDisposition,
					dwFlagsAndAttributes,
					hTemplateFile
				);
			}

			free(pszLongPath);
		}
		else
		{
			SetLastError(dwLastError);
		}
	}

	return(hFile);
}

HANDLE __fastcall CreateFileWithLongPathRetry( PCTSTR pszPath, DWORD dwDesiredAccess,
                                               DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                               DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                                               HANDLE hTemplateFile )
{
	return(CreateFileWithLongPathRetryAbortable(
		pszPath,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile,
		NULL,
		NULL
	));
}

HANDLE __fastcall OpenFileForReading( PCTSTR pszPath )
{
	return(OpenFileForReadingAbortable(pszPath, NULL, NULL));
}

HANDLE __fastcall OpenFileForReadingAbortable( PCTSTR pszPath,
                                               PFNFILEOPENSHOULDABORT pfnShouldAbort,
                                               PVOID pvAbortContext )
{
	return(CreateFileWithLongPathRetryAbortable(
		pszPath,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
		NULL,
		pfnShouldAbort,
		pvAbortContext
	));
}

DWORD WINAPI GetReadBufferSizeForPath( PCTSTR pszPath )
{
	return((pszPath && IsSSD(pszPath)) ? READ_BUFFER_SIZE_SSD : READ_BUFFER_SIZE_HDD);
}

#if defined(HASHCHECK_BLAKE3_TBB_ENABLED) && defined(HASHCHECK_BLAKE3_TBB_DELAYLOAD)
static BOOL WINAPI IsBLAKE3TbbRuntimeAvailable( )
{
	static volatile LONG s_lTbbState = 0; // 0 = unknown, 1 = unavailable, 2 = available, 3 = checking
	static HMODULE s_hTbb = NULL;

	LONG lState = InterlockedCompareExchange(&s_lTbbState, 3, 0);

	if (lState == 0)
	{
		if (g_hModThisDll)
		{
			TCHAR szTbbPath[MAX_PATH << 1];
			if (GetModuleFileName(g_hModThisDll, szTbbPath, countof(szTbbPath)))
			{
				PTSTR pszFileName = StrRChr(szTbbPath, NULL, TEXT('\\'));
				if (pszFileName)
				{
					*(pszFileName + 1) = 0;
					if (SUCCEEDED(StringCchCat(szTbbPath, countof(szTbbPath), TEXT("tbb12.dll"))))
						s_hTbb = LoadLibrary(szTbbPath);
				}
			}
		}

		if (!s_hTbb)
			s_hTbb = LoadLibrary(TEXT("tbb12.dll"));
		InterlockedExchange(&s_lTbbState, s_hTbb ? 2 : 1);
	}
	else
	{
		while (lState == 3)
		{
			Sleep(0);
			lState = s_lTbbState;
		}
	}

	return(s_lTbbState == 2);
}
#endif

BOOL WINAPI ShouldUseBLAKE3Tbb( const WHCTXEX* pwhctx, ULONGLONG cbFileSize,
                                DWORD dwReadBufferSize, BOOL bOuterMultithreaded )
{
#if defined(HASHCHECK_BLAKE3_TBB_ENABLED)
	if (!pwhctx)
		return(FALSE);

	if (pwhctx->dwFlags != WHEX_CHECKBLAKE3)
		return(FALSE);

	if (bOuterMultithreaded)
		return(FALSE);

	if (g_uWinVer < 0x0600)
		return(FALSE);

	if (dwReadBufferSize == 0)
		return(FALSE);

	if (cbFileSize < BLAKE3_TBB_MIN_FILE_SIZE || cbFileSize > dwReadBufferSize)
		return(FALSE);

#if defined(HASHCHECK_BLAKE3_TBB_DELAYLOAD)
	return(IsBLAKE3TbbRuntimeAvailable());
#else
	return(TRUE);
#endif
#else
	UNREFERENCED_PARAMETER(pwhctx);
	UNREFERENCED_PARAMETER(cbFileSize);
	UNREFERENCED_PARAMETER(dwReadBufferSize);
	UNREFERENCED_PARAMETER(bOuterMultithreaded);
	return(FALSE);
#endif
}

VOID __fastcall HCNormalizeString( PTSTR psz )
{
	if (!psz) return;

	while (*psz)
	{
		switch (*psz)
		{
			case TEXT('\r'):
				*psz = TEXT('\n');
				break;

			case TEXT('\t'):
			case TEXT('"'):
			case TEXT('*'):
				*psz = TEXT(' ');
				break;

			case TEXT('/'):
				*psz = TEXT('\\');
				break;
		}

		++psz;
	}
}

VOID WINAPI SetControlText( HWND hWnd, UINT uCtrlID, UINT uStringID )
{
	TCHAR szBuffer[MAX_STRINGMSG];
	LoadString(g_hModThisDll, uStringID, szBuffer, countof(szBuffer));
	SetDlgItemText(hWnd, uCtrlID, szBuffer);
}

VOID WINAPI EnableControl( HWND hWnd, UINT uCtrlID, BOOL bEnable )
{
	HWND hWndControl = GetDlgItem(hWnd, uCtrlID);
	ShowWindow(hWndControl, (bEnable) ? SW_SHOW : SW_HIDE);
	EnableWindow(hWndControl, bEnable);
}

VOID WINAPI FormatFractionalResults( PTSTR pszFormat, PTSTR pszBuffer, UINT uPart, UINT uTotal )
{
	// pszFormat must be at least MAX_STRINGRES TCHARs long
	// pszBuffer must be at least MAX_STRINGMSG TCHARs long

	if (*pszFormat == 0)
	{
		LoadString(
			g_hModThisDll,
			(uTotal == 1) ? IDS_HP_RESULT_FMT : IDS_HP_RESULTS_FMT,
			pszFormat,
			MAX_STRINGRES
		);
	}

	if (*pszFormat != TEXT('!'))
		StringCchPrintf(pszBuffer, MAX_STRINGMSG, pszFormat, uPart, uTotal);
	else
		StringCchPrintf(pszBuffer, MAX_STRINGMSG, pszFormat + 1, uTotal, uPart);
}

VOID WINAPI SetProgressBarPause( PCOMMONCONTEXT pcmnctx, WPARAM iState )
{
	// For Windows Classic, we can change the color to indicate a pause
	COLORREF clrProgress = (iState == PBST_NORMAL) ? CLR_DEFAULT : RGB(0xFF, 0x80, 0x00);
	SendMessage(pcmnctx->hWndPBTotal, PBM_SETBARCOLOR, 0, clrProgress);
	SendMessage(pcmnctx->hWndPBFile, PBM_SETBARCOLOR, 0, clrProgress);

	// Toggle the marquee animation if applicable
	if (pcmnctx->dwFlags & HCF_MARQUEE)
		SendMessage(pcmnctx->hWndPBTotal, PBM_SETMARQUEE, iState == PBST_NORMAL, MARQUEE_INTERVAL);

	if (g_uWinVer >= 0x0600)
	{
		// If this is Vista, we can also set the state
		SendMessage(pcmnctx->hWndPBTotal, PBM_SETSTATE, iState, 0);
		SendMessage(pcmnctx->hWndPBFile, PBM_SETSTATE, iState, 0);

		// Vista's progress bar is buggy--if you pause it while it is animating,
		// the color will not change (but it will stop animating), so it may
		// be necessary to send another PBM_SETSTATE to get it right
        if (iState == PBST_PAUSED)
            SetTimer(pcmnctx->hWnd, TIMER_ID_PAUSE, PAUSE_TIMER_INTERVAL_MS, NULL);
	}
}

VOID WINAPI WorkerThreadTogglePause( PCOMMONCONTEXT pcmnctx )
{
	if (WorkerThreadGetStatus(pcmnctx) == ACTIVE)
	{
        ResetEvent(pcmnctx->hUnpauseEvent);
		if (!WorkerThreadSetStatusIf(pcmnctx, PAUSED, ACTIVE))
		{
			SetEvent(pcmnctx->hUnpauseEvent);
			return;
		}

		if (!(pcmnctx->dwFlags & HCF_EXIT_PENDING))
		{
			SetControlText(pcmnctx->hWnd, IDC_PAUSE, IDS_HC_RESUME);
			SetProgressBarPause(pcmnctx, PBST_PAUSED);
		}
	}
	else if (WorkerThreadSetStatusIf(pcmnctx, ACTIVE, PAUSED))
	{
		if (!(pcmnctx->dwFlags & HCF_EXIT_PENDING))
		{
			SetControlText(pcmnctx->hWnd, IDC_PAUSE, IDS_HC_PAUSE);
			SetProgressBarPause(pcmnctx, PBST_NORMAL);
		}

        SetEvent(pcmnctx->hUnpauseEvent);
	}
}

static VOID WINAPI JobQueueInitializeState( PHASHCHECK_JOB_QUEUE_STATE pState )
{
	ZeroMemory(pState, sizeof(*pState));
	pState->dwMagic = JOB_QUEUE_MAGIC;
	pState->dwVersion = JOB_QUEUE_VERSION;
	pState->cCapacity = JOB_QUEUE_CAPACITY;
	pState->ullNextJobId = 1;
}

static BOOL WINAPI JobQueueStateIsValid( PHASHCHECK_JOB_QUEUE_STATE pState )
{
	DWORD i;

	if (!pState)
		return(FALSE);

	if (pState->dwMagic != JOB_QUEUE_MAGIC ||
	    pState->dwVersion != JOB_QUEUE_VERSION ||
	    pState->cCapacity != JOB_QUEUE_CAPACITY ||
	    pState->iHead >= JOB_QUEUE_CAPACITY ||
	    pState->cEntries > JOB_QUEUE_CAPACITY ||
	    !pState->ullNextJobId)
	{
		return(FALSE);
	}

	for (i = 0; i < pState->cEntries; ++i)
	{
		DWORD iEntry = (pState->iHead + i) % JOB_QUEUE_CAPACITY;
		if (!pState->rgEntries[iEntry].ullJobId ||
		    !pState->rgEntries[iEntry].dwProcessId ||
		    !pState->rgEntries[iEntry].ullProcessCreationTime)
		{
			return(FALSE);
		}
	}

	return(TRUE);
}

static VOID WINAPI JobQueueValidateState( PHASHCHECK_JOB_QUEUE_STATE pState )
{
	if (!JobQueueStateIsValid(pState))
		JobQueueInitializeState(pState);
}

static BOOL WINAPI JobQueueLock( HANDLE hQueueMutex )
{
	DWORD dwWait = WaitForSingleObject(hQueueMutex, JOB_QUEUE_LOCK_TIMEOUT_MS);
	return(dwWait == WAIT_OBJECT_0 || dwWait == WAIT_ABANDONED);
}

static VOID WINAPI JobQueueSignalWaiters( VOID )
{
	HANDLE hQueueEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, HASHCHECK_JOB_QUEUE_EVENT_NAME);
	if (hQueueEvent)
	{
		SetEvent(hQueueEvent);
		CloseHandle(hQueueEvent);
	}
}

BOOL WINAPI WorkerThreadRequestRunNow( PCOMMONCONTEXT pcmnctx )
{
	if (!pcmnctx ||
	    WorkerThreadGetStatus(pcmnctx) != QUEUED ||
	    !WorkerThreadIsRunNowAvailable(pcmnctx))
	{
		return(FALSE);
	}

	WorkerThreadSetFlags(pcmnctx, HCF_RUN_NOW_REQUESTED);
	WorkerThreadClearFlags(pcmnctx, HCF_RUN_NOW_AVAILABLE);

	if (WorkerThreadGetStatus(pcmnctx) != QUEUED)
	{
		WorkerThreadClearFlags(pcmnctx, HCF_RUN_NOW_REQUESTED);
		return(FALSE);
	}

	if (pcmnctx->hWnd && !(WorkerThreadGetFlags(pcmnctx) & HCF_EXIT_PENDING))
		EnableWindow(GetDlgItem(pcmnctx->hWnd, IDC_PAUSE), FALSE);

	JobQueueSignalWaiters();
	return(TRUE);
}

BOOL WINAPI WorkerThreadIsRunNowAvailable( PCOMMONCONTEXT pcmnctx )
{
	return(pcmnctx && (WorkerThreadGetFlags(pcmnctx) & HCF_RUN_NOW_AVAILABLE));
}

VOID WINAPI WorkerThreadSetRunNowAvailable( PCOMMONCONTEXT pcmnctx, BOOL bAvailable )
{
	if (!pcmnctx)
		return;

	if (bAvailable)
		WorkerThreadSetFlags(pcmnctx, HCF_RUN_NOW_AVAILABLE);
	else
		WorkerThreadClearFlags(pcmnctx, HCF_RUN_NOW_AVAILABLE);
}

static DWORD WINAPI WorkerThreadWaitForQueueEvent( PCOMMONCONTEXT pcmnctx, HANDLE hQueueEvent )
{
	// This event is an advisory wakeup, not the source of queue correctness.
	// It is auto-reset so one waiter rechecks the shared FIFO at a time; the
	// timed wait handles missed wakeups and cases where the woken waiter is not
	// the next runnable job. Avoid PulseEvent-style broadcast pulses because
	// they are unreliable if waiters are briefly outside the wait state.
	if (pcmnctx->hCancelEvent)
	{
		HANDLE rgHandles[2] = { hQueueEvent, pcmnctx->hCancelEvent };
		return(WaitForMultipleObjects(2, rgHandles, FALSE, JOB_QUEUE_WAIT_INTERVAL_MS));
	}

	return(WaitForSingleObject(hQueueEvent, JOB_QUEUE_WAIT_INTERVAL_MS));
}

static BOOL WINAPI JobQueueGetProcessCreationTime( HANDLE hProcess, PULONGLONG pullCreationTime )
{
	FILETIME ftCreation, ftExit, ftKernel, ftUser;

	if (!pullCreationTime)
		return(FALSE);

	*pullCreationTime = 0;

	if (!GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser))
		return(FALSE);

	*pullCreationTime = ((ULONGLONG)ftCreation.dwHighDateTime << 32) | ftCreation.dwLowDateTime;
	return(*pullCreationTime != 0);
}

static BOOL WINAPI JobQueueIsProcessAlive( PHASHCHECK_JOB_QUEUE_ENTRY pEntry )
{
	HANDLE hProcess;
	DWORD dwWait;
	ULONGLONG ullCreationTime;

	if (!pEntry || !pEntry->dwProcessId || !pEntry->ullProcessCreationTime)
		return(FALSE);

	if (pEntry->dwProcessId == GetCurrentProcessId())
	{
		return(JobQueueGetProcessCreationTime(GetCurrentProcess(), &ullCreationTime) &&
		       ullCreationTime == pEntry->ullProcessCreationTime);
	}

	hProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pEntry->dwProcessId);
	// Treat access-denied and transient OpenProcess failures as alive. In the
	// Local namespace this is expected to be same-session/same-user; only an
	// invalid PID is a reliable stale-entry signal here.
	if (!hProcess)
		return(GetLastError() != ERROR_INVALID_PARAMETER);

	dwWait = WaitForSingleObject(hProcess, 0);
	if (dwWait == WAIT_OBJECT_0)
	{
		CloseHandle(hProcess);
		return(FALSE);
	}

	if (!JobQueueGetProcessCreationTime(hProcess, &ullCreationTime))
	{
		CloseHandle(hProcess);
		return(TRUE);
	}

	CloseHandle(hProcess);
	return(ullCreationTime == pEntry->ullProcessCreationTime);
}

static VOID WINAPI JobQueueRemoveAt( PHASHCHECK_JOB_QUEUE_STATE pState, DWORD iRemove )
{
	DWORD i, iTail;

	assert(pState && iRemove < pState->cEntries);

	for (i = iRemove; i + 1 < pState->cEntries; ++i)
	{
		DWORD iDst = (pState->iHead + i) % JOB_QUEUE_CAPACITY;
		DWORD iSrc = (pState->iHead + i + 1) % JOB_QUEUE_CAPACITY;
		pState->rgEntries[iDst] = pState->rgEntries[iSrc];
	}

	iTail = (pState->iHead + pState->cEntries - 1) % JOB_QUEUE_CAPACITY;
	ZeroMemory(&pState->rgEntries[iTail], sizeof(pState->rgEntries[iTail]));

	if (--pState->cEntries == 0)
		pState->iHead = 0;
}

static BOOL WINAPI JobQueueRemoveStaleFrontEntries( PHASHCHECK_JOB_QUEUE_STATE pState )
{
	BOOL bChanged = FALSE;
	PHASHCHECK_JOB_QUEUE_ENTRY pEntry;

	while (pState->cEntries)
	{
		pEntry = &pState->rgEntries[pState->iHead];
		if (JobQueueIsProcessAlive(pEntry))
			break;

		JobQueueRemoveAt(pState, 0);
		bChanged = TRUE;
	}

	return(bChanged);
}

static BOOL WINAPI JobQueueEnqueue( PHASHCHECK_JOB_QUEUE_STATE pState, PHASHCHECK_JOB_SLOT pSlot )
{
	DWORD iTail;

	if (pState->cEntries >= JOB_QUEUE_CAPACITY)
		return(FALSE);

	pSlot->ullJobId = pState->ullNextJobId++;
	if (!pState->ullNextJobId)
		pState->ullNextJobId = 1;

	iTail = (pState->iHead + pState->cEntries) % JOB_QUEUE_CAPACITY;
	pState->rgEntries[iTail].ullJobId = pSlot->ullJobId;
	pState->rgEntries[iTail].dwProcessId = pSlot->dwProcessId;
	pState->rgEntries[iTail].ullProcessCreationTime = pSlot->ullProcessCreationTime;
	++pState->cEntries;
	pSlot->bEnqueued = TRUE;

	return(TRUE);
}

static BOOL WINAPI JobQueueIsFront( PHASHCHECK_JOB_QUEUE_STATE pState, PHASHCHECK_JOB_SLOT pSlot )
{
	PHASHCHECK_JOB_QUEUE_ENTRY pEntry;

	if (!pState->cEntries || !pSlot->bEnqueued)
		return(FALSE);

	pEntry = &pState->rgEntries[pState->iHead];
	return(pEntry->ullJobId == pSlot->ullJobId &&
	       pEntry->dwProcessId == pSlot->dwProcessId &&
	       pEntry->ullProcessCreationTime == pSlot->ullProcessCreationTime);
}

static BOOL WINAPI JobQueueRemoveSlot( PHASHCHECK_JOB_QUEUE_STATE pState, PHASHCHECK_JOB_SLOT pSlot )
{
	DWORD i;

	for (i = 0; i < pState->cEntries; ++i)
	{
		DWORD iEntry = (pState->iHead + i) % JOB_QUEUE_CAPACITY;
		PHASHCHECK_JOB_QUEUE_ENTRY pEntry = &pState->rgEntries[iEntry];

		if (pEntry->ullJobId == pSlot->ullJobId &&
		    pEntry->dwProcessId == pSlot->dwProcessId &&
		    pEntry->ullProcessCreationTime == pSlot->ullProcessCreationTime)
		{
			JobQueueRemoveAt(pState, i);
			pSlot->bEnqueued = FALSE;
			return(TRUE);
		}
	}

	return(FALSE);
}

static VOID WINAPI JobQueueCloseSlot( PHASHCHECK_JOB_SLOT pSlot )
{
	if (!pSlot)
		return;

	if (pSlot->pState)
		UnmapViewOfFile(pSlot->pState);
	if (pSlot->hMap)
		CloseHandle(pSlot->hMap);
	if (pSlot->hQueueEvent)
		CloseHandle(pSlot->hQueueEvent);
	if (pSlot->hQueueMutex)
		CloseHandle(pSlot->hQueueMutex);

	LocalFree(pSlot);
}

static PHASHCHECK_JOB_SLOT WINAPI JobQueueOpenSlot( )
{
	PHASHCHECK_JOB_SLOT pSlot = (PHASHCHECK_JOB_SLOT)LocalAlloc(LPTR, sizeof(HASHCHECK_JOB_SLOT));
	if (!pSlot)
		return(NULL);

	pSlot->dwProcessId = GetCurrentProcessId();
	if (!JobQueueGetProcessCreationTime(GetCurrentProcess(), &pSlot->ullProcessCreationTime))
		goto err;

	pSlot->hQueueMutex = CreateMutex(NULL, FALSE, HASHCHECK_JOB_QUEUE_MUTEX_NAME);
	if (!pSlot->hQueueMutex)
		goto err;

	pSlot->hQueueEvent = CreateEvent(NULL, FALSE, FALSE, HASHCHECK_JOB_QUEUE_EVENT_NAME);
	if (!pSlot->hQueueEvent)
		goto err;

	pSlot->hMap = CreateFileMapping(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_READWRITE,
		0,
		(DWORD)sizeof(HASHCHECK_JOB_QUEUE_STATE),
		HASHCHECK_JOB_QUEUE_MAP_NAME
	);
	if (!pSlot->hMap)
		goto err;

	pSlot->pState = (PHASHCHECK_JOB_QUEUE_STATE)MapViewOfFile(
		pSlot->hMap,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		sizeof(HASHCHECK_JOB_QUEUE_STATE)
	);
	if (!pSlot->pState)
		goto err;

	if (!JobQueueLock(pSlot->hQueueMutex))
		goto err;

	JobQueueValidateState(pSlot->pState);
	ReleaseMutex(pSlot->hQueueMutex);

	return(pSlot);

err:
	JobQueueCloseSlot(pSlot);
	return(NULL);
}

// Return values:
//   NULL                 - canceled before acquiring a runnable slot
//   INVALID_HANDLE_VALUE - queue bypassed or unavailable; run without queue gating
//   other handle          - queued slot owned by caller; release when hashing ends
HANDLE WINAPI WorkerThreadAcquireJobSlot( PCOMMONCONTEXT pcmnctx )
{
	PHASHCHECK_JOB_SLOT pSlot;
	BOOL bQueued = FALSE;
	DWORD cQueueFullRetries = 0;

	if (pcmnctx->dwFlags & HCF_BYPASS_QUEUE)
		return(INVALID_HANDLE_VALUE);

	pSlot = JobQueueOpenSlot();

	// Hashing should remain available even if the optional cross-process queue
	// cannot be created. Return a sentinel that means "run without gating".
	if (!pSlot)
		return(INVALID_HANDLE_VALUE);

	for (;;)
	{
		BOOL bAtFront = FALSE;
		BOOL bQueueChanged = FALSE;
		BOOL bQueueFull = FALSE;
		BOOL bRunNow = FALSE;

		if (WorkerThreadIsCancelRequested(pcmnctx))
		{
			WorkerThreadReleaseJobSlot((HANDLE)pSlot);
			return(NULL);
		}

		if (!JobQueueLock(pSlot->hQueueMutex))
		{
			if (!pSlot->bEnqueued)
			{
				if (bQueued &&
				    WorkerThreadSetStatusUnlessCanceled(pcmnctx, ACTIVE) &&
				    pcmnctx->hWnd)
				{
					PostMessage(pcmnctx->hWnd, HM_WORKERTHREAD_QUEUESTATE, (WPARAM)pcmnctx, FALSE);
				}

				if (WorkerThreadIsCancelRequested(pcmnctx))
				{
					JobQueueCloseSlot(pSlot);
					return(NULL);
				}

				JobQueueCloseSlot(pSlot);
				return(INVALID_HANDLE_VALUE);
			}

			WorkerThreadWaitForQueueEvent(pcmnctx, pSlot->hQueueEvent);
			continue;
		}

		JobQueueValidateState(pSlot->pState);
		bQueueChanged = JobQueueRemoveStaleFrontEntries(pSlot->pState);

		if (!pSlot->bEnqueued)
		{
			if (JobQueueEnqueue(pSlot->pState, pSlot))
			{
				bQueueChanged = TRUE;
				cQueueFullRetries = 0;
			}
			else
			{
				bQueueFull = TRUE;
			}
		}

		bAtFront = JobQueueIsFront(pSlot->pState, pSlot);
		if (!bAtFront &&
		    pSlot->bEnqueued &&
		    (WorkerThreadGetFlags(pcmnctx) & HCF_RUN_NOW_REQUESTED))
		{
			bRunNow = JobQueueRemoveSlot(pSlot->pState, pSlot);
			if (bRunNow)
				bQueueChanged = TRUE;
		}
		ReleaseMutex(pSlot->hQueueMutex);

		if (bQueueChanged)
			SetEvent(pSlot->hQueueEvent);

		if (bQueueFull)
		{
			if (WorkerThreadIsCancelRequested(pcmnctx))
			{
				WorkerThreadReleaseJobSlot((HANDLE)pSlot);
				return(NULL);
			}

			if (++cQueueFullRetries >= JOB_QUEUE_FULL_RETRY_LIMIT)
			{
				JobQueueCloseSlot(pSlot);
				return(INVALID_HANDLE_VALUE);
			}

			WorkerThreadWaitForQueueEvent(pcmnctx, pSlot->hQueueEvent);
			continue;
		}

		if (bRunNow)
		{
			WorkerThreadClearFlags(pcmnctx, HCF_RUN_NOW_REQUESTED | HCF_RUN_NOW_AVAILABLE);
			if (!WorkerThreadSetStatusUnlessCanceled(pcmnctx, ACTIVE))
			{
				JobQueueCloseSlot(pSlot);
				return(NULL);
			}

			if (bQueued && pcmnctx->hWnd)
				PostMessage(pcmnctx->hWnd, HM_WORKERTHREAD_QUEUESTATE, (WPARAM)pcmnctx, FALSE);

			JobQueueCloseSlot(pSlot);
			return(INVALID_HANDLE_VALUE);
		}

		if (bAtFront)
		{
			if (!WorkerThreadSetStatusUnlessCanceled(pcmnctx, ACTIVE))
			{
				WorkerThreadReleaseJobSlot((HANDLE)pSlot);
				return(NULL);
			}

			// Keep HCF_RUN_NOW_AVAILABLE aligned with the visible Run now button
			// until the queued-state message changes it back to Pause.
			WorkerThreadClearFlags(
				pcmnctx,
				HCF_RUN_NOW_REQUESTED | (bQueued && pcmnctx->hWnd ? 0 : HCF_RUN_NOW_AVAILABLE)
			);

			if (bQueued)
			{
				if (pcmnctx->hWnd)
					PostMessage(pcmnctx->hWnd, HM_WORKERTHREAD_QUEUESTATE, (WPARAM)pcmnctx, FALSE);
			}
			return((HANDLE)pSlot);
		}

		if (!bQueued)
		{
			if (!WorkerThreadSetStatusUnlessCanceled(pcmnctx, QUEUED))
			{
				WorkerThreadReleaseJobSlot((HANDLE)pSlot);
				return(NULL);
			}

			if (pcmnctx->hWnd)
				PostMessage(pcmnctx->hWnd, HM_WORKERTHREAD_QUEUESTATE, (WPARAM)pcmnctx, TRUE);
			bQueued = TRUE;
		}

		WorkerThreadWaitForQueueEvent(pcmnctx, pSlot->hQueueEvent);
	}
}

VOID WINAPI WorkerThreadReleaseJobSlot( HANDLE hJobSlot )
{
	if (hJobSlot && hJobSlot != INVALID_HANDLE_VALUE)
	{
		PHASHCHECK_JOB_SLOT pSlot = (PHASHCHECK_JOB_SLOT)hJobSlot;
		BOOL bQueueChanged = FALSE;

		if (pSlot->pState && pSlot->hQueueMutex && JobQueueLock(pSlot->hQueueMutex))
		{
			JobQueueValidateState(pSlot->pState);
			if (pSlot->bEnqueued)
				bQueueChanged = JobQueueRemoveSlot(pSlot->pState, pSlot);
			ReleaseMutex(pSlot->hQueueMutex);
		}

		if (bQueueChanged && pSlot->hQueueEvent)
			SetEvent(pSlot->hQueueEvent);

		JobQueueCloseSlot(pSlot);
	}
}

VOID WINAPI WorkerThreadStop( PCOMMONCONTEXT pcmnctx )
{
	LONG lPrevStatus;

	for (;;)
	{
		lPrevStatus = WorkerThreadGetStatus(pcmnctx);
		if (lPrevStatus == INACTIVE ||
		    lPrevStatus == CLEANUP_COMPLETED ||
		    lPrevStatus == CANCEL_REQUESTED)
		{
			return;
		}

		if (WorkerThreadSetStatusIf(pcmnctx, CANCEL_REQUESTED, lPrevStatus))
			break;
	}

	WorkerThreadClearFlags(pcmnctx, HCF_RUN_NOW_REQUESTED | HCF_RUN_NOW_AVAILABLE);

	// If the thread is paused, unpause it
    if (lPrevStatus == PAUSED && pcmnctx->hUnpauseEvent)
        SetEvent(pcmnctx->hUnpauseEvent);

    if (pcmnctx->hCancelEvent)
        SetEvent(pcmnctx->hCancelEvent);
    JobQueueSignalWaiters();

	// Disable the control buttons
	if (! (pcmnctx->dwFlags & (HCF_EXIT_PENDING | HCF_RESTARTING)))
	{
		EnableWindow(GetDlgItem(pcmnctx->hWnd, IDC_PAUSE), FALSE);
		EnableWindow(GetDlgItem(pcmnctx->hWnd, IDC_STOP), FALSE);
	}
}

VOID WINAPI WorkerThreadCleanup( PCOMMONCONTEXT pcmnctx )
{
	if (WorkerThreadGetStatus(pcmnctx) == CLEANUP_COMPLETED)
		return;

	// There are only two times this function gets called:
	// Case 1: The worker thread has exited on its own, and this function
	// was invoked in response to the thread's exit notification.
	// Case 2: A forced abort was requested (app exit, settings change, etc.),
	// where this is called right after calling WorkerThreadStop to signal the
	// thread to exit.

	if (pcmnctx->hThread != NULL)
	{
		if (WorkerThreadGetStatus(pcmnctx) != INACTIVE)
		{
			// Forced abort, where the thread has been told to stop but has not yet
			// stopped. The common context and UI resources are owned by the caller,
			// so it is not safe to detach a still-running worker here. Do not crash
			// Explorer; after the grace period, keep waiting for a real stop.
			if (WaitForSingleObject(pcmnctx->hThread, WORKER_THREAD_CLEANUP_TIMEOUT_MS) == WAIT_TIMEOUT)
				WaitForSingleObject(pcmnctx->hThread, INFINITE);
		}

		CloseHandle(pcmnctx->hThread);
        pcmnctx->hThread = NULL;
	}

    // If we're done with the Unpause event and it's open, close it
    if (!(pcmnctx->dwFlags & HCF_RESTARTING) && pcmnctx->hUnpauseEvent != NULL)
    {
        CloseHandle(pcmnctx->hUnpauseEvent);
        pcmnctx->hUnpauseEvent = NULL;
    }
    if (!(pcmnctx->dwFlags & HCF_RESTARTING) && pcmnctx->hCancelEvent != NULL)
    {
        CloseHandle(pcmnctx->hCancelEvent);
        pcmnctx->hCancelEvent = NULL;
    }

	WorkerThreadSetStatus(pcmnctx, CLEANUP_COMPLETED);

	if (! (pcmnctx->dwFlags & (HCF_EXIT_PENDING | HCF_RESTARTING)))
	{
		static const UINT16 arCtrls[] =
		{
			IDC_PROG_TOTAL,
			IDC_PROG_FILE,
			IDC_PAUSE,
			IDC_STOP
		};

		UINT i;

		for (i = 0; i < countof(arCtrls); ++i)
			EnableControl(pcmnctx->hWnd, arCtrls[i], FALSE);
	}
}

DWORD WINAPI WorkerThreadStartup( PCOMMONCONTEXT pcmnctx )
{
    pcmnctx->pfnWorkerMain(pcmnctx);

	WorkerThreadSetStatus(pcmnctx, INACTIVE);

	if (! (pcmnctx->dwFlags & (HCF_EXIT_PENDING | HCF_RESTARTING)))
		PostMessage(pcmnctx->hWnd, HM_WORKERTHREAD_DONE, (WPARAM)pcmnctx, 0);

	return(0);
}

// Post messages to update the progress bar. If there are multiple file-hashing threads,
// then only the thread currently operating on the largest file updates the progress bar.
__inline VOID UpdateProgressBar( HWND hWndPBFile, PCRITICAL_SECTION pCritSec,
                                 PBOOL pbCurrentlyUpdating, volatile ULONGLONG* pcbCurrentMaxSize,
                                 ULONGLONG cbFileSize, ULONGLONG cbFileRead, PUINT pLastProgress )
{
    if (!hWndPBFile)
        return;

    if (pCritSec)  // if we're one among many file-hashing threads
    {
        // All the checks below outside of critical sections are innacurate; they're meant
        // to quickly check if entering the critical section can be avoided, but they must
        // be repeated inside the critical sections to avoid potential race conditions

        if (*pbCurrentlyUpdating)
        {
            if (cbFileSize != *pcbCurrentMaxSize)
            {
                // Some other thread is now updating the progress bar
                *pbCurrentlyUpdating = FALSE;
                return;
            }
            UINT newProgress = (UINT) (PROGRESS_BAR_STEPS * cbFileRead / cbFileSize);
            if (newProgress == *pLastProgress)
                return;

            EnterCriticalSection(pCritSec);
            if (cbFileSize != *pcbCurrentMaxSize)
            {
                LeaveCriticalSection(pCritSec);
                // Some other thread is now updating the progress bar
                *pbCurrentlyUpdating = FALSE;
                return;
            }
            // Special case for when this file has been completed:
            if (cbFileRead == 0)
                *pcbCurrentMaxSize = 0;  // relinquish progress bar control to the next largest file
            PostMessage(hWndPBFile, PBM_SETPOS, newProgress, 0);
            LeaveCriticalSection(pCritSec);
            *pLastProgress = newProgress;
        }
        else  // if not *pbCurrentlyUpdating
        {
            if (cbFileSize > *pcbCurrentMaxSize)  // if we should take over updating the progress bar
            {
                UINT newProgress = (UINT)(PROGRESS_BAR_STEPS * cbFileRead / cbFileSize);
                EnterCriticalSection(pCritSec);
                if (cbFileSize > *pcbCurrentMaxSize)  // if we should definitely take over updating the progress bar
                {
                    *pcbCurrentMaxSize = cbFileSize;
                    PostMessage(hWndPBFile, PBM_SETPOS, newProgress, 0);
                }
                LeaveCriticalSection(pCritSec);
                *pbCurrentlyUpdating = TRUE;
                *pLastProgress = newProgress;
            }
        }
    }
    else  // if we're the only file-hashing thread
    {
        UINT newProgress = (UINT)(PROGRESS_BAR_STEPS * cbFileRead / cbFileSize);
        if (newProgress != *pLastProgress)
        {
            PostMessage(hWndPBFile, PBM_SETPOS, newProgress, 0);
            *pLastProgress = newProgress;
        }
    }
}

VOID WINAPI WorkerThreadHashFile( PCOMMONCONTEXT pcmnctx, PCTSTR pszPath,
                                  PWHCTXEX pwhctx, PWHRESULTEX pwhres, PBYTE pbuffer,
                                  PFILESIZE pFileSize, LPARAM lParam,
                                  PCRITICAL_SECTION pUpdateCritSec, volatile ULONGLONG* pcbCurrentMaxSize
#ifdef _TIMED
                                , PDWORD pdwElapsed
#endif
                                )
{
	HANDLE hFile;
	DWORD dwReadBufferSize = pcmnctx->dwReadBufferSize ? pcmnctx->dwReadBufferSize : READ_BUFFER_SIZE;

	// If the worker thread is working so fast that the UI cannot catch up,
	// pause for a bit to let things settle down
	while (pcmnctx->cSentMsgs > pcmnctx->cHandledMsgs + MSG_THROTTLE_THRESHOLD)
	{
		Sleep(50);
        if (WorkerThreadGetStatus(pcmnctx) == PAUSED)
            WaitForSingleObject(pcmnctx->hUnpauseEvent, INFINITE);
		if (WorkerThreadGetStatus(pcmnctx) == CANCEL_REQUESTED)
			return;
	}

    // This can happen if a user changes the hash selection in HashProp (if no
    // new hashes were selected; we still want to run the throttling code above)
    if (pwhctx->dwFlags == 0)
    {
#ifdef _TIMED
        if (pdwElapsed)
            *pdwElapsed = 0;
#endif
        return;
    }

	// Indicate that we want lower-case results (TODO: make this an option)
	pwhctx->uCaseMode = WHFMT_LOWERCASE;

	if ((hFile = OpenFileForReading(pszPath)) != INVALID_HANDLE_VALUE)
	{
		ULONGLONG cbFileSize, cbFileRead = 0;
		DWORD cbBufferRead;
		UINT lastProgress = 0;
		UINT8 cInner = 0;

		if (GetFileSizeEx(hFile, (PLARGE_INTEGER)&cbFileSize))
		{
			BOOL bReadError = FALSE;

			// The progress bar is updates only once every 4 buffer reads; if
			// the file is small enough that it requires only one such cycle,
			// then do not bother with updating the progress bar; this improves
			// performance when working with large numbers of small files
			BOOL bUpdateProgress = cbFileSize >= dwReadBufferSize * 4,
			     bCurrentlyUpdating = FALSE;

			// If the caller provides a way to return the file size, then set
			// the file size; send a SETSIZE notification only if it was "big"
			if (pFileSize)
			{
				pFileSize->ui64 = cbFileSize;
				StrFormatKBSize(cbFileSize, pFileSize->sz, countof(pFileSize->sz));
				if (cbFileSize > dwReadBufferSize)
				    PostMessage(pcmnctx->hWnd, HM_WORKERTHREAD_SETSIZE, (WPARAM)pcmnctx, lParam != -1 ? lParam : (LPARAM)pFileSize);
			}
#ifdef _TIMED
            DWORD dwStarted;
            if (pdwElapsed)
                dwStarted = GetTickCount();
#endif
			// Finally, read the file and calculate the checksum; the
			// progress bar is updated only once every 4 buffer reads (512K)
			WHInitEx(pwhctx);

#if defined(HASHCHECK_BLAKE3_TBB_ENABLED)
			if (ShouldUseBLAKE3Tbb(pwhctx, cbFileSize, dwReadBufferSize, pcmnctx->bOuterMultithreaded))
			{
                if (WorkerThreadGetStatus(pcmnctx) == PAUSED)
                    WaitForSingleObject(pcmnctx->hUnpauseEvent, INFINITE);
				if (WorkerThreadGetStatus(pcmnctx) == CANCEL_REQUESTED)
				{
					CloseHandle(hFile);
					return;
				}

				if (!ReadFile(hFile, pbuffer, (DWORD)cbFileSize, &cbBufferRead, NULL))
				{
					cbBufferRead = 0;
					bReadError = TRUE;
				}
				else
				{
					WHUpdateBLAKE3Tbb(&pwhctx->ctxBLAKE3, pbuffer, cbBufferRead);
					cbFileRead += cbBufferRead;
				}
			}
			else
#endif
			{
				do // Outer loop: keep going until the end
				{
					do // Inner loop: break every 4 cycles or if the end is reached
					{
                        if (WorkerThreadGetStatus(pcmnctx) == PAUSED)
                            WaitForSingleObject(pcmnctx->hUnpauseEvent, INFINITE);
						if (WorkerThreadGetStatus(pcmnctx) == CANCEL_REQUESTED)
						{
							CloseHandle(hFile);
							return;
						}

						if (!ReadFile(hFile, pbuffer, dwReadBufferSize, &cbBufferRead, NULL))
						{
							cbBufferRead = 0;
							bReadError = TRUE;
						}
						else
						{
							WHUpdateEx(pwhctx, pbuffer, cbBufferRead);
							cbFileRead += cbBufferRead;
						}

					} while (cbBufferRead == dwReadBufferSize && (++cInner & 0x03));

					if (bUpdateProgress)
						UpdateProgressBar(pcmnctx->hWndPBFile, pUpdateCritSec, &bCurrentlyUpdating,
						                  pcbCurrentMaxSize, cbFileSize, cbFileRead, &lastProgress);

				} while (cbBufferRead == dwReadBufferSize);
			}

			WHFinishEx(pwhctx, pwhres);
#ifdef _TIMED
            if (pdwElapsed)
                *pdwElapsed = GetTickCount() - dwStarted;
#endif
            // If we encountered a file read error
            if (bReadError || cbFileRead != cbFileSize)
                // Clear the valid-results bits for the hashes we just calculated
                // (they are set by WHFinishEx, but they're apparently *not* valid)
                pwhres->dwFlags &= ~pwhctx->dwFlags;

			if (bUpdateProgress)
				UpdateProgressBar(pcmnctx->hWndPBFile, pUpdateCritSec, &bCurrentlyUpdating,
				                  pcbCurrentMaxSize, cbFileSize, 0, &lastProgress);
		}

		CloseHandle(hFile);
	}
}

__forceinline HANDLE WINAPI GetActCtx( HMODULE hModule, PCTSTR pszResourceName )
{
	// Wraps away the silliness of CreateActCtx, including the fact that
	// it will fail if you do not provide a valid path string even if you
	// supply a valid module handle, which is quite silly since the path is
	// just going to get translated into a module handle anyway by the API.

	ACTCTX ctx;
	TCHAR szModule[MAX_PATH << 1];

	GetModuleFileName(hModule, szModule, countof(szModule));

	ctx.cbSize = sizeof(ctx);
	ctx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID | ACTCTX_FLAG_HMODULE_VALID;
	ctx.lpSource = szModule;
	ctx.lpResourceName = pszResourceName;
	ctx.hModule = hModule;

	return(CreateActCtx(&ctx));
}

ULONG_PTR WINAPI ActivateManifest( BOOL bActivate )
{
	// XP-compatible one-time initialization. InitOnceExecuteOnce is Vista+ and
	// would be a static import, so use Interlocked* instead.
	static volatile LONG s_lActCtxInitState = 0; // 0 = new, 1 = creating, 2 = done

	if (InterlockedCompareExchange(&s_lActCtxInitState, 1, 0) == 0)
	{
		g_hActCtx = GetActCtx(g_hModThisDll, MAKEINTRESOURCE(IDR_RT_MANIFEST));
		g_bActCtxCreated = TRUE;
		InterlockedExchange(&s_lActCtxInitState, 2);
	}
	else
	{
		while (s_lActCtxInitState != 2)
			Sleep(0);
	}

	if (g_hActCtx != INVALID_HANDLE_VALUE)
	{
		ULONG_PTR uCookie;

		if (!bActivate)
			return(1);  // Just indicate that we have a good g_hActCtx
		else if (ActivateActCtx(g_hActCtx, &uCookie))
			return(uCookie);
	}

	// We can assume that zero is never a valid cookie value...
	// * http://support.microsoft.com/kb/830033
	// * http://blogs.msdn.com/jonwis/archive/2006/01/12/512405.aspx
	return(0);
}

ULONG_PTR __fastcall HostAddRef( )
{
	LPUNKNOWN pUnknown;

	if (SHGetInstanceExplorer(&pUnknown) == S_OK)
		return((ULONG_PTR)pUnknown);
	else
		return(0);
}

VOID __fastcall HostRelease( ULONG_PTR uCookie )
{
	if (uCookie)
	{
		LPUNKNOWN pUnknown = (LPUNKNOWN)uCookie;
		pUnknown->lpVtbl->Release(pUnknown);
	}
}
