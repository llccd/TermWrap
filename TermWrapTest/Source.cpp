#include <windows.h>

#ifdef TEST_UMRDP
#define FILENAME L"umrdp.dll"
#else
#define FILENAME L"termsrv.dll"
#endif

extern void patch(HMODULE hMod);

LONG NTAPI VexHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;

	if (ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C) {
		if (ExceptionRecord->NumberParameters >= 2) {
			ULONG len = (ULONG)ExceptionRecord->ExceptionInformation[0];
			ULONG_PTR str = ExceptionRecord->ExceptionInformation[1];
			HANDLE hOut = GetStdHandle(STD_ERROR_HANDLE);
			if (len)
				WriteConsoleA(hOut, (void *)str, len - 1, &len, 0);
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char** argv)
{
	HMODULE hMod;
	if (argc >= 2) hMod = LoadLibraryExA(argv[1], NULL, DONT_RESOLVE_DLL_REFERENCES);
	else hMod = LoadLibraryExW(FILENAME, NULL, DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!hMod) return -1;
	AddVectoredExceptionHandler(TRUE, VexHandler);
	patch(hMod);
	return 0;
}