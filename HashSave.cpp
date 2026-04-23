/**
 * HashCheck Shell Extension
 * Original work copyright (C) Kai Liu.  All rights reserved.
 * Modified work copyright (C) 2014, 2016 Christopher Gurnee.  All rights reserved.
 * Modified work copyright (C) 2016 Tim Schlueter.  All rights reserved.
 * Modified work copyright (C) 2021 Mounir IDRASSI.  All rights reserved.
 *
 * Please refer to readme.txt for information about this source code.
 * Please refer to license.txt for details about distribution and modification.
 **/

#include "globals.h"
#include "HashCheckCommon.h"
#include "HashCalc.h"
#include "SetAppID.h"
#include <Strsafe.h>
#include <vector>
#include <cassert>
#include <algorithm>
#ifdef USE_PPL
#include <ppl.h>
#include <concurrent_vector.h>
#endif

#ifdef UNICODE
#define StrCmpLogical StrCmpLogicalW
#else
#define StrCmpLogical StrCmpIA
#endif

// Control structures, from HashCalc.h
#define  HASHSAVESCRATCH  HASHCALCSCRATCH
#define PHASHSAVESCRATCH PHASHCALCSCRATCH
#define  HASHSAVECONTEXT  HASHCALCCONTEXT
#define PHASHSAVECONTEXT PHASHCALCCONTEXT
#define  HASHSAVEITEM     HASHCALCITEM
#define PHASHSAVEITEM    PHASHCALCITEM



/*============================================================================*\
	Function declarations
\*============================================================================*/

// Entry points / main functions
DWORD WINAPI HashSaveThread( PHASHSAVECONTEXT phsctx );
HSIMPLELIST WINAPI HashSaveLoadPathListFile( PWSTR pszPathListFile );
PHASHSAVECONTEXT WINAPI HashSaveCreateContext( HWND hWndOwner, HSIMPLELIST hListRaw );
VOID WINAPI HashSaveReleaseContext( PHASHSAVECONTEXT phsctx );
BOOL WINAPI HashSaveStartThread( PHASHSAVECONTEXT phsctx );

// Worker thread
VOID __fastcall HashSaveWorkerMain( PHASHSAVECONTEXT phsctx );

// Dialog general
INT_PTR CALLBACK HashSaveDlgProc( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam );
VOID WINAPI HashSaveDlgInit( PHASHSAVECONTEXT phsctx );



/*============================================================================*\
	Entry points / main functions
\*============================================================================*/

VOID CALLBACK HashSave_RunDLLW( HWND hWnd, HINSTANCE, PWSTR pszCmdLine, INT )
{
	HSIMPLELIST hListRaw = HashSaveLoadPathListFile(pszCmdLine);
	if (hListRaw)
	{
		PHASHSAVECONTEXT phsctx = HashSaveCreateContext(hWnd, hListRaw);
		if (phsctx)
			HashSaveThread(phsctx);

		SLRelease(hListRaw);
	}
}

VOID WINAPI HashSaveStart( HWND hWndOwner, HSIMPLELIST hListRaw )
{
	// Explorer will be blocking as long as this function is running, so we
	// want to return as quickly as possible and leave the work up to the
	// thread that we are going to spawn

	PHASHSAVECONTEXT phsctx = HashSaveCreateContext(hWndOwner, hListRaw);

	if (phsctx)
	{
		if (HashSaveStartThread(phsctx))
			return;

		HashSaveReleaseContext(phsctx);
	}
}

HSIMPLELIST WINAPI HashSaveLoadPathListFile( PWSTR pszPathListFile )
{
	static const WCHAR szPathListHeader[] = L"HashCheckPathListV1";

	if (!pszPathListFile || !*pszPathListFile)
		return(NULL);

	HANDLE hFile = CreateFileW(
		pszPathListFile,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
		return(NULL);

	LARGE_INTEGER cbFile;
	BOOL bReadOk = GetFileSizeEx(hFile, &cbFile) &&
	               cbFile.HighPart == 0 &&
	               cbFile.LowPart >= sizeof(szPathListHeader) &&
	               (cbFile.LowPart % sizeof(WCHAR)) == 0;

	PWSTR pszBuffer = NULL;
	DWORD cbRead = 0;
	if (bReadOk)
	{
		pszBuffer = (PWSTR)malloc(cbFile.LowPart + sizeof(WCHAR));
		bReadOk = pszBuffer &&
		          ReadFile(hFile, pszBuffer, cbFile.LowPart, &cbRead, NULL) &&
		          cbRead == cbFile.LowPart;
	}

	CloseHandle(hFile);
	DeleteFileW(pszPathListFile);

	HSIMPLELIST hListRaw = NULL;
	if (bReadOk)
	{
		UINT cchBuffer = cbRead / sizeof(WCHAR);
		pszBuffer[cchBuffer] = 0;

		PWSTR pszPath = pszBuffer;
		if (StrCmpW(pszPath, szPathListHeader) == 0)
		{
			pszPath += countof(szPathListHeader);
			hListRaw = SLCreate();

			while (hListRaw && *pszPath)
			{
				if (!SLAddStringI(hListRaw, pszPath))
				{
					SLRelease(hListRaw);
					hListRaw = NULL;
					break;
				}

				pszPath += lstrlenW(pszPath) + 1;
			}

			if (hListRaw && !SLCheck(hListRaw))
			{
				SLRelease(hListRaw);
				hListRaw = NULL;
			}
		}
	}

	free(pszBuffer);
	return(hListRaw);
}

PHASHSAVECONTEXT WINAPI HashSaveCreateContext( HWND hWndOwner, HSIMPLELIST hListRaw )
{
	PHASHSAVECONTEXT phsctx = (PHASHSAVECONTEXT)SLSetContextSize(hListRaw, sizeof(HASHSAVECONTEXT));

	if (phsctx)
	{
		phsctx->hWnd = hWndOwner;
		phsctx->hListRaw = hListRaw;
		phsctx->dwFlags = 0;
		phsctx->dwReadBufferSize = GetReadBufferSizeForPath(NULL);
		phsctx->bOuterMultithreaded = FALSE;
		phsctx->hFileOut = INVALID_HANDLE_VALUE;

		InterlockedIncrement(&g_cRefThisDll);
		SLAddRef(hListRaw);
		// Balance the asynchronous UI/work lifetime against COM server
		// shutdown in hosts that honor the server-process lock count.
		CoAddRefServerProcess();
	}

	return(phsctx);
}

VOID WINAPI HashSaveReleaseContext( PHASHSAVECONTEXT phsctx )
{
	HSIMPLELIST hListRaw = phsctx->hListRaw;

	SLRelease(hListRaw);
	InterlockedDecrement(&g_cRefThisDll);
	CoReleaseServerProcess();
}

BOOL WINAPI HashSaveStartThread( PHASHSAVECONTEXT phsctx )
{
	HANDLE hThread = CreateThreadCRT(HashSaveThread, phsctx);

	if (hThread)
	{
		CloseHandle(hThread);
		return(TRUE);
	}

	return(FALSE);
}

DWORD WINAPI HashSaveThread( PHASHSAVECONTEXT phsctx )
{
	HRESULT hrCoInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	BOOL bCoUninitialize = SUCCEEDED(hrCoInit);

	// First, activate our manifest and AddRef our host
	ULONG_PTR uActCtxCookie = ActivateManifest(TRUE);
	ULONG_PTR uHostCookie = HostAddRef();

	// Calling HashCalcPrepare with a NULL hList will cause it to calculate
	// and set cchPrefix, but it will not copy the data or walk the directories
	// (we will leave that for the worker thread to do); the reason we do a
	// limited scan now is so that we can show the file dialog (which requires
	// cchPrefix for the automatic name generation) as soon as possible
	phsctx->status = INACTIVE;
	phsctx->hList = NULL;
	HashCalcPrepare(phsctx);

	// Get a file name from the user
	ZeroMemory(&phsctx->ofn, sizeof(phsctx->ofn));
	HashCalcInitSave(phsctx);

	if (phsctx->hFileOut != INVALID_HANDLE_VALUE)
	{
        BOOL bDeletionFailed = TRUE;
		if (phsctx->hList = SLCreateEx(TRUE))
		{
            bDeletionFailed = ! DialogBoxParam(
				g_hModThisDll,
				MAKEINTRESOURCE(IDD_HASHSAVE),
				NULL,
				HashSaveDlgProc,
				(LPARAM)phsctx
			);

			SLRelease(phsctx->hList);
		}

		CloseHandle(phsctx->hFileOut);

        // Should only happen on Windows XP
        if (bDeletionFailed)
            DeleteFile(phsctx->ofn.lpstrFile);
	}

	// This must be the last thing that we free, since this is what supports
	// our context!
	SLRelease(phsctx->hListRaw);

	// Clean up the manifest activation and release our host
	DeactivateManifest(uActCtxCookie);
	HostRelease(uHostCookie);

	InterlockedDecrement(&g_cRefThisDll);
	CoReleaseServerProcess();
	if (bCoUninitialize)
		CoUninitialize();
	return(0);
}



/*============================================================================*\
	Worker thread
\*============================================================================*/

VOID __fastcall HashSaveWorkerMain( PHASHSAVECONTEXT phsctx )
{
	// Note that ALL message communication to and from the main window MUST
	// be asynchronous, or else there may be a deadlock.

	// Prep: expand directories, max path, etc. (prefix was set by earlier call)
	PostMessage(phsctx->hWnd, HM_WORKERTHREAD_TOGGLEPREP, (WPARAM)phsctx, TRUE);
	if (! HashCalcPrepare(phsctx))
        return;
    HashCalcSetSaveFormat(phsctx);
	PostMessage(phsctx->hWnd, HM_WORKERTHREAD_TOGGLEPREP, (WPARAM)phsctx, FALSE);

    // Extract the slist into a vector for parallel_for_each
    std::vector<PHASHSAVEITEM> vecpItems;
    vecpItems.resize(phsctx->cTotal + 1);
    SLBuildIndex(phsctx->hList, (PVOID*)vecpItems.data());
    assert(vecpItems.back() == nullptr);
    vecpItems.pop_back();
    assert(vecpItems.back() != nullptr);

    phsctx->dwReadBufferSize = GetReadBufferSizeForPath(vecpItems.empty() ? NULL : vecpItems[0]->szPath);

#ifdef USE_PPL
    const bool bMultithreaded = vecpItems.size() > 1 && phsctx->dwReadBufferSize == READ_BUFFER_SIZE_SSD;
    concurrency::concurrent_vector<void*> vecBuffers;  // a vector of all allocated read buffers (one per thread)
    DWORD dwBufferTlsIndex = TlsAlloc();               // TLS index of the current thread's read buffer
    if (dwBufferTlsIndex == TLS_OUT_OF_INDEXES)
        return;
#else
    constexpr bool bMultithreaded = false;
#endif
    phsctx->bOuterMultithreaded = bMultithreaded ? TRUE : FALSE;

    PBYTE pbTheBuffer;  // file read buffer, used iff not multithreaded
    if (! bMultithreaded)
    {
        pbTheBuffer = (PBYTE)malloc(phsctx->dwReadBufferSize);
        if (pbTheBuffer == NULL)
            return;
    }

    // Initialize the progress bar update synchronization vars
    CRITICAL_SECTION updateCritSec;
    volatile ULONGLONG cbCurrentMaxSize = 0;
    if (bMultithreaded)
        InitializeCriticalSection(&updateCritSec);

#ifdef _TIMED
    DWORD dwStarted;
    dwStarted = GetTickCount();
#endif

    class CanceledException {};

    // concurrency::parallel_for_each(vecpItems.cbegin(), vecpItems.cend(), ...
    auto per_file_worker = [&](PHASHSAVEITEM pItem)
	{
        WHCTXEX whctx;

        // Indicate which hash type we are after, see WHEX... values in WinHash.h
        whctx.dwFlags = 1 << (phsctx->ofn.nFilterIndex - 1);

        PBYTE pbBuffer;
#ifdef USE_PPL
        if (bMultithreaded)
        {
            // Allocate or retrieve the already-allocated read buffer for the current thread
            pbBuffer = (PBYTE)TlsGetValue(dwBufferTlsIndex);
            if (pbBuffer == NULL)
            {
                pbBuffer = (PBYTE)malloc(phsctx->dwReadBufferSize);
                if (pbBuffer == NULL)
                    throw CanceledException();
                // Cache the read buffer for the current thread
                vecBuffers.push_back(pbBuffer);
                TlsSetValue(dwBufferTlsIndex, pbBuffer);
            }
        }
#endif

#pragma warning(push)
#pragma warning(disable: 4700 4703)  // potentially uninitialized local pointer variable 'pbBuffer' used
		// Get the hash
		WorkerThreadHashFile(
			(PCOMMONCONTEXT)phsctx,
			pItem->szPath,
			&whctx,
			&pItem->results,
            bMultithreaded ? pbBuffer : pbTheBuffer,
			NULL, 0,
            bMultithreaded ? &updateCritSec : NULL, &cbCurrentMaxSize
#ifdef _TIMED
          , &pItem->dwElapsed
#endif
        );

        if (phsctx->status == PAUSED)
            WaitForSingleObject(phsctx->hUnpauseEvent, INFINITE);
		if (phsctx->status == CANCEL_REQUESTED)
            throw CanceledException();

		// Update the UI
		InterlockedIncrement(&phsctx->cSentMsgs);
		PostMessage(phsctx->hWnd, HM_WORKERTHREAD_UPDATE, (WPARAM)phsctx, (LPARAM)pItem);
    };
#pragma warning(pop)

    bool bHashingCompleted = false;
    try
    {
#ifdef USE_PPL
        if (bMultithreaded)
            concurrency::parallel_for_each(vecpItems.cbegin(), vecpItems.cend(), per_file_worker);
        else
#endif
            std::for_each(vecpItems.cbegin(), vecpItems.cend(), per_file_worker);
        bHashingCompleted = true;
    }
    catch (CanceledException) {}  // ignore cancellation requests

    if (bHashingCompleted && phsctx->status != CANCEL_REQUESTED)
    {
        std::stable_sort(
            vecpItems.begin(),
            vecpItems.end(),
            [phsctx](PHASHSAVEITEM pItemA, PHASHSAVEITEM pItemB)
            {
                return(StrCmpLogical(
                    pItemA->szPath + phsctx->cchAdjusted,
                    pItemB->szPath + phsctx->cchAdjusted) < 0);
            }
        );

        for (PHASHSAVEITEM pItem : vecpItems)
            HashCalcWriteResult(phsctx, pItem);
    }

#ifdef _TIMED
    if (bHashingCompleted && phsctx->cTotal > 1 && phsctx->status != CANCEL_REQUESTED)
    {
        union {
            CHAR  szA[MAX_STRINGMSG];
            WCHAR szW[MAX_STRINGMSG];
        } buffer;
        size_t cbBufferLeft;
        if (phsctx->opt.dwSaveEncoding == 1)  // UTF-16
        {
            StringCbPrintfExW(
                buffer.szW,
                sizeof(buffer),
                NULL,
                &cbBufferLeft,
                0,
                L"; Total elapsed: %d ms%s",
                GetTickCount() - dwStarted,
                phsctx->opt.dwSaveEol == 1 ? L"\n" : L"\r\n");
        }
        else                                  // UTF-8 or ANSI
        {
            StringCbPrintfExA(
                buffer.szA,
                sizeof(buffer),
                NULL,
                &cbBufferLeft,
                0,
                "; Total elapsed: %d ms%s",
                GetTickCount() - dwStarted,
                phsctx->opt.dwSaveEol == 1 ? "\n" : "\r\n");
        }
        DWORD dwUnused;
        WriteFile(phsctx->hFileOut, buffer.szA, (DWORD) (sizeof(buffer) - cbBufferLeft), &dwUnused, NULL);
    }
#endif

#ifdef USE_PPL
    if (bMultithreaded)
    {
        for (void* pBuffer : vecBuffers)
            free(pBuffer);
        DeleteCriticalSection(&updateCritSec);
    }
    else
#endif
        free(pbTheBuffer);
}



/*============================================================================*\
	Dialog general
\*============================================================================*/

INT_PTR CALLBACK HashSaveDlgProc( HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam )
{
	PHASHSAVECONTEXT phsctx;

	switch (uMsg)
	{
		case WM_INITDIALOG:
		{
			phsctx = (PHASHSAVECONTEXT)lParam;

			// Associate the window with the context and vice-versa
			phsctx->hWnd = hWnd;
			SetWindowLongPtr(hWnd, DWLP_USER, (LONG_PTR)phsctx);

			SetAppIDForWindow(hWnd, TRUE);

			HashSaveDlgInit(phsctx);

			phsctx->pfnWorkerMain = (PFNWORKERMAIN)HashSaveWorkerMain;
			phsctx->hThread = CreateThreadCRT(NULL, phsctx);

			if (!phsctx->hThread)
			{
				WorkerThreadCleanup((PCOMMONCONTEXT)phsctx);
                BOOL bDeleted = HashCalcDeleteFileByHandle(phsctx->hFileOut);
				EndDialog(hWnd, bDeleted);
			}
            if (WaitForSingleObject(phsctx->hThread, 1000) != WAIT_TIMEOUT)
            {
                WorkerThreadCleanup((PCOMMONCONTEXT)phsctx);
                EndDialog(hWnd, TRUE);
            }

			return(TRUE);
		}

		case WM_DESTROY:
		{
			SetAppIDForWindow(hWnd, FALSE);
			break;
		}

		case WM_ENDSESSION:
        {
            if (wParam == FALSE)  // if TRUE, fall through to WM_CLOSE
                break;
        }
		case WM_CLOSE:
		{
			phsctx = (PHASHSAVECONTEXT)GetWindowLongPtr(hWnd, DWLP_USER);
			goto cleanup_and_exit;
		}

		case WM_COMMAND:
		{
			phsctx = (PHASHSAVECONTEXT)GetWindowLongPtr(hWnd, DWLP_USER);

			switch (LOWORD(wParam))
			{
				case IDC_PAUSE:
				{
					WorkerThreadTogglePause((PCOMMONCONTEXT)phsctx);
					return(TRUE);
				}

				case IDC_CANCEL:
				{
					cleanup_and_exit:
					phsctx->dwFlags |= HCF_EXIT_PENDING;
					WorkerThreadStop((PCOMMONCONTEXT)phsctx);
					WorkerThreadCleanup((PCOMMONCONTEXT)phsctx);

                    // Don't keep partially generated checksum files
                    BOOL bDeleted = HashCalcDeleteFileByHandle(phsctx->hFileOut);

					EndDialog(hWnd, bDeleted);
					break;
				}
			}

			break;
		}

		case WM_TIMER:
		{
			// Vista: Workaround to fix their buggy progress bar
			KillTimer(hWnd, TIMER_ID_PAUSE);
			phsctx = (PHASHSAVECONTEXT)GetWindowLongPtr(hWnd, DWLP_USER);
			if (phsctx->status == PAUSED)
				SetProgressBarPause((PCOMMONCONTEXT)phsctx, PBST_PAUSED);
			return(TRUE);
		}

		case HM_WORKERTHREAD_DONE:
		{
			phsctx = (PHASHSAVECONTEXT)wParam;
			WorkerThreadCleanup((PCOMMONCONTEXT)phsctx);
			EndDialog(hWnd, TRUE);
			return(TRUE);
		}

		case HM_WORKERTHREAD_UPDATE:
		{
			phsctx = (PHASHSAVECONTEXT)wParam;
			++phsctx->cHandledMsgs;
			SendMessage(phsctx->hWndPBTotal, PBM_SETPOS, phsctx->cHandledMsgs, 0);
			return(TRUE);
		}

		case HM_WORKERTHREAD_TOGGLEPREP:
		{
			HashCalcTogglePrep((PHASHSAVECONTEXT)wParam, (BOOL)lParam);
			return(TRUE);
		}
	}

	return(FALSE);
}

VOID WINAPI HashSaveDlgInit( PHASHSAVECONTEXT phsctx )
{
	HWND hWnd = phsctx->hWnd;

	// Load strings
	{
		SetControlText(hWnd, IDC_PAUSE, IDS_HS_PAUSE);
		SetControlText(hWnd, IDC_CANCEL, IDS_HS_CANCEL);
	}

	// Set the window icon and title
	{
		PTSTR pszFileName = phsctx->ofn.lpstrFile + phsctx->ofn.nFileOffset;
		TCHAR szFormat[MAX_STRINGRES];
		LoadString(g_hModThisDll, IDS_HS_TITLE_FMT, szFormat, countof(szFormat));
		StringCchPrintf(phsctx->scratch.sz, countof(phsctx->scratch.sz), szFormat, pszFileName);

		SendMessage(
			hWnd,
			WM_SETTEXT,
			0,
			(LPARAM)phsctx->scratch.sz
		);

		SendMessage(
			hWnd,
			WM_SETICON,
			ICON_BIG, // No need to explicitly set the small icon
			(LPARAM)LoadIcon(g_hModThisDll, MAKEINTRESOURCE(IDI_FILETYPE))
		);
	}

	// Initialize miscellaneous stuff
	{
		phsctx->dwFlags = 0;
		phsctx->cTotal = 0;
        phsctx->hThread = NULL;
        phsctx->hUnpauseEvent = NULL;
    }
}
