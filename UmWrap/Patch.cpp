#include <windows.h>
#include <Zydis/Zydis.h>

constexpr const WCHAR AllowPnp[] = L"TerminalServices-DeviceRedirection-Licenses-PnpRedirectionAllowed";
constexpr const WCHAR AllowCamera[] = L"TerminalServices-DeviceRedirection-Licenses-CameraRedirectionAllowed";

typedef union _UNWIND_CODE {
	struct {
		BYTE CodeOffset;
		BYTE UnwindOp : 4;
		BYTE OpInfo : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE;

typedef struct _UNWIND_INFO {
	BYTE Version : 3;
	BYTE Flags : 5;
	BYTE SizeOfProlog;
	BYTE CountOfCodes;
	BYTE FrameRegister : 4;
	BYTE FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;

PRUNTIME_FUNCTION backtrace(DWORD64 base, PRUNTIME_FUNCTION func) {
	if (func->UnwindData & RUNTIME_FUNCTION_INDIRECT)
		func = (PRUNTIME_FUNCTION)(base + func->UnwindData & ~3);

	auto unwindInfo = (PUNWIND_INFO)(base + func->UnwindData);
	while (unwindInfo->Flags & UNW_FLAG_CHAININFO)
	{
		func = (PRUNTIME_FUNCTION) & (unwindInfo->UnwindCode[(unwindInfo->CountOfCodes + 1) & ~1]);
		unwindInfo = (PUNWIND_INFO)(base + func->UnwindData);
	}

	return func;
}

PIMAGE_SECTION_HEADER findSection(PIMAGE_NT_HEADERS pNT, const char* str)
{
	auto pSection = IMAGE_FIRST_SECTION(pNT);

	for (size_t i = 0; i < pNT->FileHeader.NumberOfSections; i++)
		if (CSTR_EQUAL == CompareStringA(LOCALE_INVARIANT, 0, (char*)pSection[i].Name, -1, str, -1))
			return pSection + i;

	return NULL;
}

DWORD64 pattenMatch(size_t base, PIMAGE_SECTION_HEADER pSection, const void* str, size_t size)
{
	size_t rdata = base + pSection->VirtualAddress;

	for (size_t i = 0; i < pSection->SizeOfRawData; i += 4)
		if (!memcmp((void*)(rdata + i), str, size)) return pSection->VirtualAddress + i;

	return -1;
}

PIMAGE_IMPORT_DESCRIPTOR findImportImage(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, size_t base, LPCSTR str) {
	while (pImportDescriptor->Name)
	{
		if (!lstrcmpiA((LPCSTR)(base + pImportDescriptor->Name), str)) return pImportDescriptor;
		pImportDescriptor++;
	}
	return NULL;
}

bool searchPatch(ZydisDecoder* decoder, DWORD64 base, PRUNTIME_FUNCTION func, DWORD64 target)
{
	if (target == -1) return false;

	auto IP = base + func->BeginAddress;
	auto length = (ZyanUSize)func->EndAddress - func->BeginAddress;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
			operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operands[1].mem.base == ZYDIS_REGISTER_RIP &&
			operands[1].mem.disp.value + IP == target + base &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			length = 16;
			while (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)IP, length, &instruction))) {
				if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL && instruction.length == 5) {
					size_t written = 0;
					// mov eax, 1
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
	auto pNT = (PIMAGE_NT_HEADERS)(base + pDos->e_lfanew);
	auto rdata = findSection(pNT, ".rdata");
	if (!rdata) rdata = findSection(pNT, ".text");

	auto PnpRedirectionAllowed = pattenMatch(base, rdata, AllowPnp, sizeof(AllowPnp));
	if (PnpRedirectionAllowed == -1) {
		OutputDebugStringA("PnpRedirectionAllowed not found\n");
		return;
	}
	auto CameraRedirectionAllowed = pattenMatch(base, rdata, AllowCamera, sizeof(AllowCamera));

	auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	auto FunctionTable = (PRUNTIME_FUNCTION)(base + pExceptionDirectory->VirtualAddress);
	auto FunctionTableSize = pExceptionDirectory->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
	if (!FunctionTableSize) return;

	auto legacy = false;
	auto pImportDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
	auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base + pImportDirectory->VirtualAddress);
	if (findImportImage(pImportDescriptor, base, "slc.dll"))
		legacy = true;

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	for (DWORD i = 0; i < FunctionTableSize; i++) {
		auto IP = base + (FunctionTable + i)->BeginAddress;
		auto length = (ZyanUSize)(FunctionTable + i)->EndAddress - (FunctionTable + i)->BeginAddress;
		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

		while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)IP, length, &instruction, operands)))
		{
			IP += instruction.length;
			length -= instruction.length;
			if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
				operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
				operands[1].mem.base == ZYDIS_REGISTER_RIP &&
				operands[1].mem.disp.value + IP == PnpRedirectionAllowed + base &&
				operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
			{
				size_t written = 0;
				if (length > 0x1000 && CameraRedirectionAllowed == -1 && !legacy) {
					// xor eax, eax
					// inc eax
					// retn
					WriteProcessMemory(GetCurrentProcess(), (void*)(base + backtrace(base, FunctionTable + i)->BeginAddress), "\x31\xC0\xFF\xC0\xC3", 5, &written);
					return;
				}
				length = 16;
				while (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, (ZydisDecoderContext*)0, (void*)IP, length, &instruction))) {
					if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL && instruction.length == 5) {
						if (!legacy) {
							// mov eax, 1
							WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x01\x00\x00\x00", 5, &written);
							if (!searchPatch(&decoder, base, FunctionTable + i, CameraRedirectionAllowed))
								OutputDebugStringA("CameraRedirection patch not found\n");
							return;
						}
						else {
							if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, (ZydisDecoderContext*)0, (void*)(IP + instruction.length), length, &instruction)) ||
								instruction.mnemonic != ZYDIS_MNEMONIC_TEST || instruction.length != 2) continue;
							// or dword ptr [rsp+0x40], 1
							// xor eax, eax
							WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\x83\x4C\x24\x40\x01\x31\xC0", 7, &written);
							return;
						}
					}
					IP += instruction.length;
					length -= instruction.length;
				}
				OutputDebugStringA("PnpRedirection patch not found\n");
				return;
			}
		}
	}
	OutputDebugStringA("Found nothing to patch\n");
}