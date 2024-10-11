#include <windows.h>
#include <TlHelp32.h>

typedef VOID(WINAPI* SERVICEMAIN)(DWORD, LPTSTR*);
typedef VOID(WINAPI* SVCHOSTPUSHSERVICEGLOBALS)(VOID*);

HMODULE hMod;
SERVICEMAIN _ServiceMain;
SVCHOSTPUSHSERVICEGLOBALS _SvchostPushServiceGlobals;

extern void patch(HMODULE hMod);

void SetThreadsState(bool Resume)
{
	auto CurrTh = GetCurrentThreadId();
	auto CurrPr = GetCurrentProcessId();
	THREADENTRY32 Thread;

	auto h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE)
	{
		Thread.dwSize = sizeof(THREADENTRY32);
		Thread32First(h, &Thread);
		do
		{
			if (Thread.th32ThreadID != CurrTh && Thread.th32OwnerProcessID == CurrPr)
			{
				auto hThread = OpenThread(THREAD_SUSPEND_RESUME, false, Thread.th32ThreadID);
				if (hThread)
				{
					if (Resume) ResumeThread(hThread);
					else SuspendThread(hThread);
					CloseHandle(hThread);
				}
			}
		} while (Thread32Next(h, &Thread));
		CloseHandle(h);
	}
}

void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
	_ServiceMain(dwArgc, lpszArgv);
}

void WINAPI SvchostPushServiceGlobals(void* lpGlobalData)
{
	_SvchostPushServiceGlobals(lpGlobalData);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH) {
		hMod = LoadLibraryExW(L"termsrv.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (!hMod) return false;

		_ServiceMain = (SERVICEMAIN)GetProcAddress(hMod, "ServiceMain");
		_SvchostPushServiceGlobals = (SVCHOSTPUSHSERVICEGLOBALS)GetProcAddress(hMod, "SvchostPushServiceGlobals");

		SetThreadsState(false);
		patch(hMod);
		SetThreadsState(true);
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
		FreeLibrary(hMod);
	return true;
}