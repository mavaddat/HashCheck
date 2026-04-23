#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>
#include <wchar.h>

typedef VOID (CALLBACK *PFNHASHCHECKRUNDLL)( HWND, HINSTANCE, PWSTR, INT );

static HRESULT GetHashCheckDllPath( PWSTR pszDllPath, UINT cchDllPath )
{
	if (!GetModuleFileNameW(NULL, pszDllPath, cchDllPath))
		return(HRESULT_FROM_WIN32(GetLastError()));

	PWSTR pszSlash = wcsrchr(pszDllPath, L'\\');
	if (!pszSlash)
		return(E_FAIL);

	*(pszSlash + 1) = 0;
	return(StringCchCatW(pszDllPath, cchDllPath, L"HashCheck.dll"));
}

static INT RunHashCheckDllVerb( PCSTR pszExportName, PWSTR pszArgument )
{
	WCHAR szDllPath[MAX_PATH << 1];
	HRESULT hr = GetHashCheckDllPath(szDllPath, ARRAYSIZE(szDllPath));
	if (FAILED(hr))
		return((INT)hr);

	HMODULE hDll = LoadLibraryW(szDllPath);
	if (!hDll)
		return((INT)HRESULT_FROM_WIN32(GetLastError()));

	PFNHASHCHECKRUNDLL pfnVerb = (PFNHASHCHECKRUNDLL)GetProcAddress(hDll, pszExportName);
	if (!pfnVerb)
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
		FreeLibrary(hDll);
		return((INT)hr);
	}

	pfnVerb(NULL, hDll, pszArgument, SW_SHOWNORMAL);
	FreeLibrary(hDll);
	return(0);
}

int WINAPI wWinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPWSTR lpCmdLine, int nShowCmd )
{
	(void)hInstance;
	(void)hPrevInstance;
	(void)lpCmdLine;
	(void)nShowCmd;

	int argc = 0;
	LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (!argv)
		return((INT)HRESULT_FROM_WIN32(GetLastError()));

	INT iResult = 0;
	if (argc == 3 && lstrcmpiW(argv[1], L"/hashcheck-create") == 0)
		iResult = RunHashCheckDllVerb("HashSave_RunDLLW", argv[2]);
	else if (argc == 3 && lstrcmpiW(argv[1], L"/hashcheck-verify") == 0)
		iResult = RunHashCheckDllVerb("HashVerify_RunDLLW", argv[2]);

	LocalFree(argv);
	return(iResult);
}
