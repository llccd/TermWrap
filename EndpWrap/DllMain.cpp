#include <windows.h>
#include <mmdeviceapi.h>

typedef HRESULT(* GETTSAUDIOENDPOINTENUMERATORFORSESSION)(_In_ DWORD SessionId, _Out_ IMMDeviceEnumerator** ppEndpointEnumerator);

HMODULE hMod;
GETTSAUDIOENDPOINTENUMERATORFORSESSION _GetTSAudioEndpointEnumeratorForSession;
LPFNGETCLASSOBJECT _DllGetClassObject;
LPFNCANUNLOADNOW _DllCanUnloadNow;

extern void patch(HMODULE hMod);

HRESULT GetTSAudioEndpointEnumeratorForSession(_In_ DWORD SessionId, _Out_ IMMDeviceEnumerator** ppEndpointEnumerator)
{
	return _GetTSAudioEndpointEnumeratorForSession(SessionId, ppEndpointEnumerator);
}

HRESULT CALLBACK DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID FAR* ppv) {
	return _DllGetClassObject(rclsid, riid, ppv);
}

HRESULT CALLBACK DllCanUnloadNow() {
	return _DllCanUnloadNow();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH) {
		hMod = LoadLibraryExW(L"rdpendp.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (!hMod) return false;

		_GetTSAudioEndpointEnumeratorForSession = (GETTSAUDIOENDPOINTENUMERATORFORSESSION)GetProcAddress(hMod, "GetTSAudioEndpointEnumeratorForSession");
		_DllGetClassObject = (LPFNGETCLASSOBJECT)GetProcAddress(hMod, "DllGetClassObject");
		_DllCanUnloadNow = (LPFNCANUNLOADNOW)GetProcAddress(hMod, "DllCanUnloadNow");

		patch(hMod);
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
		FreeLibrary(hMod);
	return true;
}