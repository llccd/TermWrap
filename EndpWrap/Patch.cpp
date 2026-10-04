#include "../TermWrap/Utils.cpp"

constexpr const WCHAR AllowAudioCapture[] = L"TerminalServices-DeviceRedirection-Licenses-TSAudioCaptureAllowed";

void patch(HMODULE hMod)
{
	auto base = (size_t)hMod;
	auto pDos = (PIMAGE_DOS_HEADER)base;
	auto pNT = (PIMAGE_NT_HEADERS)(base + pDos->e_lfanew);
	auto rdata = findSection(pNT, ".rdata");
	if (!rdata) rdata = findSection(pNT, ".text");

	auto AudioCaptureAllowed = pattenMatch(base, rdata, AllowAudioCapture, sizeof(AllowAudioCapture));

	auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	auto FunctionTable = (PRUNTIME_FUNCTION)(base + pExceptionDirectory->VirtualAddress);
	auto FunctionTableSize = pExceptionDirectory->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
	if (!FunctionTableSize) return;

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	for (DWORD i = 0; i < FunctionTableSize; i++) {
		if (searchXref(&decoder, base, FunctionTable + i, AudioCaptureAllowed)) {
			size_t written = 0;
			DWORD64 IsAudioCaptureEnabled_addr = backtrace(base, FunctionTable + i)->BeginAddress;
			// mov eax, 1
			// retn
			WriteProcessMemory(GetCurrentProcess(), (void*)(base + IsAudioCaptureEnabled_addr), "\xB8\x01\x00\x00\x00\xC3", 6, &written);
			return;
		}
		OutputDebugStringA("AllowAudioCapture not found\n");
	}
}