#include <windows.h>
#include <Zydis/Zydis.h>

constexpr const WCHAR AllowPnp[] = L"TerminalServices-DeviceRedirection-Licenses-PnpRedirectionAllowed";
constexpr const WCHAR AllowCamera[] = L"TerminalServices-DeviceRedirection-Licenses-CameraRedirectionAllowed";

PIMAGE_SECTION_HEADER findSection(PIMAGE_NT_HEADERS64 pNT, const char* str)
{
	auto pSection = IMAGE_FIRST_SECTION(pNT);

	for (DWORD64 i = 0; i < pNT->FileHeader.NumberOfSections; i++)
		if (CSTR_EQUAL == CompareStringA(LOCALE_INVARIANT, 0, (char*)pSection[i].Name, -1, str, -1))
			return pSection + i;

	return NULL;
}

DWORD64 pattenMatch(DWORD64 base, PIMAGE_SECTION_HEADER pSection, const void* str, DWORD64 size)
{
	auto rdata = base + pSection->VirtualAddress;

	for (DWORD64 i = 0; i < pSection->SizeOfRawData; i += 4)
		if (!memcmp((void*)(rdata + i), str, size)) return pSection->VirtualAddress + i;

	return -1;
}

bool searchPatch(ZydisDecoder* decoder, DWORD64 base, PRUNTIME_FUNCTION func, DWORD64 target)
{
	if (target == -1) return false;

	auto IP = base + func->BeginAddress;
	auto length = (ZyanUSize)func->EndAddress - func->BeginAddress;
	ZydisDecodedInstruction instruction;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(decoder, (void*)IP, length, &instruction)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
			instruction.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP &&
			instruction.operands[1].mem.disp.value + IP == target + base &&
			instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			length = 16;
			while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(decoder, (void*)IP, length, &instruction))) {
				if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL && instruction.length == 5) {
					size_t written = 0;
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x01\x00\x00\x00", 5, &written);
					return true;
				}
				IP += instruction.length;
				length -= instruction.length;
			}
			return false;
		}
	}

	return false;
}


void patch(HMODULE hMod)
{
	auto base = (size_t)hMod;
	auto pDos = (PIMAGE_DOS_HEADER)base;
	auto pNT = (PIMAGE_NT_HEADERS64)(base + pDos->e_lfanew);
	auto rdata = findSection(pNT, ".rdata");
	if (!rdata) rdata = findSection(pNT, ".text");

	auto PnpRedirectionAllowed = pattenMatch(base, rdata, AllowPnp, sizeof(AllowPnp));
	auto CameraRedirectionAllowed = pattenMatch(base, rdata, AllowCamera, sizeof(AllowCamera));

	auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	auto FunctionTable = (PRUNTIME_FUNCTION)(base + pExceptionDirectory->VirtualAddress);
	auto FunctionTableSize = pExceptionDirectory->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
	if (!FunctionTableSize) return;

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	auto patched = false;

	for (DWORD i = 0; i < FunctionTableSize; i++) {
		if (searchPatch(&decoder, base, FunctionTable + i, PnpRedirectionAllowed))
			patched = true;
		if (searchPatch(&decoder, base, FunctionTable + i, CameraRedirectionAllowed))
			patched = true;

		if (patched) return;
	}
}