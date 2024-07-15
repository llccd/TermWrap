#include <windows.h>
#include <Zydis/Zydis.h>

constexpr const char Query[] = "CDefPolicy::Query";
constexpr const char LocalOnly[] = "CSLQuery::IsTerminalTypeLocalOnly";
constexpr const char AppServer[] = "CSLQuery::IsAppServerInstalled";
constexpr const char NonRDP[] = "CRemoteConnectionManager::IsAllowNonRDPStack";
constexpr const char SingleSessionEnabled[] = "CSessionArbitrationHelper::IsSingleSessionPerUserEnabled";
constexpr const char InstanceOfLicense[] = "CEnforcementCore::GetInstanceOfTSLicense ";
constexpr const char ConnectionProperty[] = "CConnectionEx::GetConnectionProperty";

constexpr const GUID IS_PNP_DISABLED = { 0x93D359D5, 0x831F, 0x47B4, {0x90, 0xBE, 0x83, 0x83, 0xAF, 0x8F, 0x1B, 0x0E} };

constexpr const WCHAR AllowRemote[] = L"TerminalServices-RemoteConnectionManager-AllowRemoteConnections";
constexpr const WCHAR AllowMultipleSessions[] = L"TerminalServices-RemoteConnectionManager-AllowMultipleSessions";
constexpr const WCHAR AllowAppServer[] = L"TerminalServices-RemoteConnectionManager-AllowAppServerMode";
constexpr const WCHAR AllowMultimon[] = L"TerminalServices-RemoteConnectionManager-AllowMultimon";

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

DWORD64 searchXref(ZydisDecoder* decoder, DWORD64 base, PRUNTIME_FUNCTION func, DWORD64 target)
{
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
			return IP - base;
	}

	return 0;
}

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

PIMAGE_IMPORT_DESCRIPTOR findImportImage(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, DWORD64 base, LPCSTR str) {
	while (pImportDescriptor->Name)
	{
		if (!lstrcmpiA((LPCSTR)(base + pImportDescriptor->Name), str)) return pImportDescriptor;
		pImportDescriptor++;
	}
	return NULL;
}

DWORD64 findImportFunction(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, DWORD64 base, LPCSTR str) {
	auto pThunk = (PIMAGE_THUNK_DATA)(pImportDescriptor->OriginalFirstThunk + base);
	while (pThunk->u1.AddressOfData)
	{
		if (!lstrcmpiA(((PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + base))->Name, str))
			return (DWORD64)pThunk - base - pImportDescriptor->OriginalFirstThunk + pImportDescriptor->FirstThunk;
		pThunk++;
	}
	return -1;
}

void LocalOnlyPatch(ZydisDecoder* decoder, DWORD64 RVA, DWORD64 base, DWORD64 target) {
	ZyanUSize length = 256;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	target += base;
	size_t written = 0;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
			operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			operands[0].imm.is_relative == ZYAN_TRUE &&
			operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].reg.value == ZYDIS_REGISTER_RIP &&
			target == IP + operands[0].imm.value.u)
		{   
			while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)) && instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
                IP += instruction.length;
                length -= instruction.length;
            }
			if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)IP, length, &instruction)) ||
				instruction.mnemonic != ZYDIS_MNEMONIC_TEST) break;

			IP += instruction.length;
			length -= instruction.length;
			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)) ||
				instruction.operand_count != 3 ||
				operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
				operands[0].imm.is_relative != ZYAN_TRUE ||
				operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
				operands[1].reg.value != ZYDIS_REGISTER_RIP) break;

			if (instruction.mnemonic == ZYDIS_MNEMONIC_JNS)
			{
				target = IP + instruction.length;
				IP = target + operands[0].imm.value.u;
			}
			else if (instruction.mnemonic != ZYDIS_MNEMONIC_JS) break;
			else
			{
				IP += instruction.length;
				target = IP + operands[0].imm.value.u;
			}

			length -= instruction.length;
			if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)IP, length, &instruction)) ||
				instruction.mnemonic != ZYDIS_MNEMONIC_CMP) break;

			IP += instruction.length;
			length -= instruction.length;
			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)) ||
				instruction.mnemonic != ZYDIS_MNEMONIC_JZ ||
				operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
				operands[0].imm.is_relative != ZYAN_TRUE ||
				operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
				operands[1].reg.value != ZYDIS_REGISTER_RIP ||
				target != IP + operands[0].imm.value.u + instruction.length) break;

			if (instruction.raw.imm[0].offset == 2) WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\x90\xE9", 2, &written);
			else WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xEB", 1, &written);

			return;
		}
	}
	OutputDebugStringA("LocalOnlyPatch not found\n");
}

void DefPolicyPatch(ZydisDecoder* decoder, DWORD64 RVA, DWORD64 base) {
	ZyanUSize length = 128;
	ZyanUSize lastLength = 0;
	ZyanUSize instLength;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	auto mov_base = ZYDIS_REGISTER_NONE;
	auto mov_target = ZYDIS_REGISTER_NONE;
	size_t written = 0;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		instLength = instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
			operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operands[0].mem.disp.value == 0x63c &&
			operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			auto reg1 = operands[1].reg.value;
			auto reg2 = operands[0].mem.base;

			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)(IP + instLength), length - instLength, &instruction, operands)))
				break;

			if (instruction.mnemonic == ZYDIS_MNEMONIC_JNZ)
			{
				IP -= lastLength;

				if (reg1 != ZYDIS_REGISTER_EAX) {
					OutputDebugStringA("DefPolicyPatch: Unknown reg1\n");
					return;
				}

				switch (reg2) {
				case ZYDIS_REGISTER_RCX:
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x81\x38\x06\x00\x00\x90\xEB", 13, &written);
					break;
				case ZYDIS_REGISTER_ECX:
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x81\x20\x03\x00\x00\xEB\x0E", 13, &written);
					break;
				case ZYDIS_REGISTER_RDI:
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x87\x38\x06\x00\x00\x90\xEB", 13, &written);
					break;
				default:
					OutputDebugStringA("DefPolicyPatch: Unknown reg2\n");
					break;
				}
				return;
			}
			else if (instruction.mnemonic != ZYDIS_MNEMONIC_JZ && instruction.mnemonic != ZYDIS_MNEMONIC_POP)
				break;

			if (reg1 == ZYDIS_REGISTER_EDX) {
				if (operands[0].mem.base != ZYDIS_REGISTER_ECX) {
					OutputDebugStringA("DefPolicyPatch: Unknown reg2\n");
					return;
				}
				WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xBA\x00\x01\x00\x00\x89\x91\x20\x03\x00\x00\x5E\x90", 13, &written);
				return;
			}
			else if (reg1 != ZYDIS_REGISTER_EAX) {
				OutputDebugStringA("DefPolicyPatch: Unknown reg1\n");
				return;
			}

			switch (reg2) {
			case ZYDIS_REGISTER_RCX:
				WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x81\x38\x06\x00\x00\x90", 12, &written);
				break;
			case ZYDIS_REGISTER_ECX:
				WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x81\x20\x03\x00\x00\x90", 12, &written);
				break;
			case ZYDIS_REGISTER_ESI:
				WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x86\x20\x03\x00\x00\x90", 12, &written);
				break;
			case ZYDIS_REGISTER_RDI:
				WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x87\x38\x06\x00\x00\x90", 12, &written);
				break;
			default:
				OutputDebugStringA("DefPolicyPatch: Unknown reg2\n");
				break;
			}
			return;
		}
		else if (!mov_base && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operands[1].mem.disp.value == 0x63c)
		{
			mov_base = operands[1].mem.base;
			mov_target = operands[0].reg.value;
		}
		else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operands[1].mem.base == mov_base &&
			operands[1].mem.disp.value == 0x638)
		{
			auto mov_target2 = operands[0].reg.value;

			auto offset = instLength;
			while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)(IP + offset), length - offset, &instruction, operands))) {
				offset += instruction.length;
				if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
					operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					(operands[0].reg.value == mov_target && operands[1].reg.value == mov_target2 ||
						operands[0].reg.value == mov_target2 && operands[1].reg.value == mov_target))
					break;
			}

			if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(decoder, (ZydisDecoderContext*)0, (void*)(IP + offset), length - offset, &instruction)))
				break;

			if (instruction.mnemonic == ZYDIS_MNEMONIC_JNZ)
			{
				IP -= lastLength;
				OutputDebugStringA("DefPolicyPatch: Unknown _jmp\n");
				return;
			}
			else if (instruction.mnemonic != ZYDIS_MNEMONIC_JZ && instruction.mnemonic != ZYDIS_MNEMONIC_POP)
				break;

			if (mov_target2 == ZYDIS_REGISTER_EDI) {
				if (operands[1].mem.base == ZYDIS_REGISTER_RCX)
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xBF\x00\x01\x00\x00\x89\xB9\x38\x06\x00\x00\x90\x90\x90", 14, &written);
				else
					OutputDebugStringA("DefPolicyPatch: Unknown reg2\n");
			}
			else
				OutputDebugStringA("DefPolicyPatch: Unknown reg1\n");

			return;
		}

		IP += instLength;
		length -= instLength;
		lastLength = instLength;
	}
	OutputDebugStringA("DefPolicyPatch not found\n");
}

int SingleUserPatch(ZydisDecoder* decoder, DWORD64 RVA, DWORD64 base, DWORD64 target, DWORD64 target2) {
	ZyanUSize length = 256;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	target += base;
	target2 += base;
	size_t written = 0;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
			operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			operands[0].imm.is_relative == ZYAN_TRUE &&
			operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].reg.value == ZYDIS_REGISTER_RIP)
		{
			auto jmp_addr = IP + operands[0].imm.value.u;
			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)jmp_addr, length, &instruction, operands)) ||
				instruction.mnemonic != ZYDIS_MNEMONIC_JMP ||
				operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
				operands[0].mem.base != ZYDIS_REGISTER_RIP ||
				operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
				operands[1].reg.value != ZYDIS_REGISTER_RIP ||
				operands[0].mem.disp.value + jmp_addr + instruction.length != target) continue;

			while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
			{
				if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
					instruction.length >= 5 && instruction.length <= 7 &&
					operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
					operands[0].mem.base == ZYDIS_REGISTER_RIP &&
					operands[0].mem.disp.value + IP + instruction.length == target2) {
					// call VerifyVersionInfoW -> mov eax, 1
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x01\x00\x00\x00\x90\x90", instruction.length, &written);
					if (instruction.length != 7) OutputDebugStringA("length != 7\n");
					return 1;
				}
				else if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
					instruction.length <= 8 && operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
					(operands[0].mem.base == ZYDIS_REGISTER_RBP || operands[0].mem.base == ZYDIS_REGISTER_RSP) &&
					(operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[1].imm.value.u == 1 ||
						operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)) {
					// cmp [rbp/rsp+XX], 1 -> nop
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\x90\x90\x90\x90\x90\x90\x90\x90", instruction.length, &written);
					return 1;
				}
				IP += instruction.length;
				length -= instruction.length;
			}
			break;
		}
	}
	return 0;
}

int NonRDPPatch(ZydisDecoder* decoder, DWORD64 RVA, DWORD64 base, DWORD64 target) {
	ZyanUSize length = 256;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	target += base;
	size_t written = 0;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
			operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			operands[0].imm.is_relative == ZYAN_TRUE &&
			operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].reg.value == ZYDIS_REGISTER_RIP &&
			target == IP + operands[0].imm.value.u)
		{

			if (instruction.length != 5) break;
			// inc dword ptr [rcx]
			// xor eax, eax
			// nop
			WriteProcessMemory(GetCurrentProcess(), (void*)(IP - instruction.length), "\xFF\x01\x31\xC0\x90", 5, &written);
			return 1;
		}
	}
	return 0;
}

DWORD64 PropertyDeviceAddr(ZydisDecoder* decoder, DWORD64 RVA, DWORD64 base, DWORD64 target) {
	ZyanUSize length = 256;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	target += base;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			(operands[1].mem.base == ZYDIS_REGISTER_RIP && target == IP + operands[1].mem.disp.value ||
			operands[1].mem.segment == ZYDIS_REGISTER_DS && target == base + operands[1].mem.disp.value))
		{
			while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
			{
				IP += instruction.length;
				length -= instruction.length;

				if (instruction.mnemonic == ZYDIS_MNEMONIC_JZ || instruction.mnemonic == ZYDIS_MNEMONIC_JMP)
					IP += operands[0].imm.value.u;

				else if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
					operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
					operands[0].imm.is_relative == ZYAN_TRUE &&
					operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					operands[1].reg.value == ZYDIS_REGISTER_RIP)
					return IP + operands[0].imm.value.u - base;
			}
		}
		else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[0].reg.value == ZYDIS_REGISTER_RCX &&
			operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			(operands[1].mem.base == ZYDIS_REGISTER_RIP && target == IP + operands[1].mem.disp.value ||
				operands[1].mem.segment == ZYDIS_REGISTER_DS && target == base + operands[1].mem.disp.value))
		{
			bool foundJNZ = false;
			while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
			{
				IP += instruction.length;
				length -= instruction.length;

				if (!foundJNZ && instruction.mnemonic == ZYDIS_MNEMONIC_JNZ) {
					IP += operands[0].imm.value.u;
					foundJNZ = true;
				}
				
				if (foundJNZ && instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
					operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
					operands[0].imm.is_relative == ZYAN_TRUE &&
					operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					operands[1].reg.value == ZYDIS_REGISTER_RIP)
					return IP + operands[0].imm.value.u - base;
			}
		}
	}
	return -1;
}

void PropertyDevicePatch(ZydisDecoder* decoder, DWORD64 RVA, DWORD64 base) {
	ZyanUSize length = 256;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	size_t written = 0;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[0].size == 32 && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operands[1].mem.base != ZYDIS_REGISTER_RIP && (operands[1].mem.disp.value == 0x1f00 || operands[1].mem.disp.value == 0x1f28))
		{
			auto reg = operands[0].reg.value;
			while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
			{
				if (instruction.mnemonic == ZYDIS_MNEMONIC_SHR && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					operands[0].reg.value == reg && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
					operands[1].imm.value.u == 0x0b)
				{
					if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)(IP + instruction.length), length, &instruction, operands)) ||
						instruction.mnemonic != ZYDIS_MNEMONIC_AND || operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
						operands[0].reg.value != reg || instruction.length > 3) break;

					switch (reg) {
					case ZYDIS_REGISTER_EAX:
						WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x00\x00\x00\x90", 3 + instruction.length, &written);
						break;
					case ZYDIS_REGISTER_ECX:
						WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB9\x00\x00\x00\x00\x90", 3 + instruction.length, &written);
						break;
					default:
						OutputDebugStringA("PropertyPatch: Unknown reg\n");
						break;
					}
					return;
				}
				IP += instruction.length;
				length -= instruction.length;
			}
			break;
		}
	}
	OutputDebugStringA("PropertyPatch not found\n");
}

void patch(HMODULE hMod)
{
	auto base = (size_t)hMod;
	auto pDos = (PIMAGE_DOS_HEADER)base;
	auto pNT = (PIMAGE_NT_HEADERS64)(base + pDos->e_lfanew);
	auto rdata = findSection(pNT, ".rdata");
	if (!rdata) rdata = findSection(pNT, ".text");

	auto CDefPolicy_Query = pattenMatch(base, rdata, Query, sizeof(Query) - 1);
	auto GetInstanceOfTSLicense = pattenMatch(base, rdata, InstanceOfLicense, sizeof(InstanceOfLicense) - 1);
	auto IsAppServerInstalled = pattenMatch(base, rdata, AppServer, sizeof(AppServer));
	auto IsAllowNonRDPStack = pattenMatch(base, rdata, NonRDP, sizeof(NonRDP));
	auto IsSingleSessionPerUserEnabled = pattenMatch(base, rdata, SingleSessionEnabled, sizeof(SingleSessionEnabled) - 1);
	auto IsSingleSessionPerUser = pattenMatch(base, rdata, "IsSingleSessionPerUser", sizeof("IsSingleSessionPerUser"));
	if (!memcmp((void*)(base + IsSingleSessionPerUser - 8), "CUtils::", 8)) IsSingleSessionPerUser -= 8;
	auto IsLicenseTypeLocalOnly = pattenMatch(base, rdata, LocalOnly, sizeof(LocalOnly) - 1);
	auto bRemoteConnAllowed = pattenMatch(base, rdata, AllowRemote, sizeof(AllowRemote));
	auto GetConnectionProperty = pattenMatch(base, rdata, ConnectionProperty, sizeof(ConnectionProperty));

	auto pImportDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
	auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base + pImportDirectory->VirtualAddress);
	auto pImportImage = findImportImage(pImportDescriptor, base, "msvcrt.dll");
	if (!pImportImage) return;
	auto memset_addr = findImportFunction(pImportImage, base, "memset");

	DWORD64 VerifyVersion_addr = -1;
	pImportImage = findImportImage(pImportDescriptor, base, "api-ms-win-core-kernel32-legacy-l1-1-1.dll");
	if (!pImportImage) pImportImage = findImportImage(pImportDescriptor, base, "KERNEL32.dll");
	if (pImportImage) VerifyVersion_addr = findImportFunction(pImportImage, base, "VerifyVersionInfoW");

	auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	auto FunctionTable = (PRUNTIME_FUNCTION)(base + pExceptionDirectory->VirtualAddress);
	auto FunctionTableSize = pExceptionDirectory->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
	if (!FunctionTableSize) return;

	DWORD64 CDefPolicy_Query_addr = 0, GetInstanceOfTSLicense_addr = 0, IsSingleSessionPerUserEnabled_addr = 0, IsAllowNonRDPStack_addr = 0,
		IsSingleSessionPerUser_addr = 0, IsLicenseTypeLocalOnly_addr = 0, IsAppServerInstalled_addr = 0, GetConnectionProperty_addr = 0, bRemoteConnAllowed_xref;
	PRUNTIME_FUNCTION CSLQuery_Initialize_func = NULL;

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	DWORD IsAppServerInstalled_idx = 0;

	for (DWORD i = 0; i < FunctionTableSize; i++) {
		if (!CDefPolicy_Query_addr && searchXref(&decoder, base, FunctionTable + i, CDefPolicy_Query))
			CDefPolicy_Query_addr = backtrace(base, FunctionTable + i)->BeginAddress;
		else if (!GetInstanceOfTSLicense_addr && searchXref(&decoder, base, FunctionTable + i, GetInstanceOfTSLicense))
			GetInstanceOfTSLicense_addr = backtrace(base, FunctionTable + i)->BeginAddress;
		else if (!IsSingleSessionPerUserEnabled_addr && searchXref(&decoder, base, FunctionTable + i, IsSingleSessionPerUserEnabled))
			IsSingleSessionPerUserEnabled_addr = backtrace(base, FunctionTable + i)->BeginAddress;
		else if (!IsAllowNonRDPStack_addr && IsAllowNonRDPStack != -1 && searchXref(&decoder, base, FunctionTable + i, IsAllowNonRDPStack))
			IsAllowNonRDPStack_addr = backtrace(base, FunctionTable + i)->BeginAddress;
		else if (!IsSingleSessionPerUser_addr && searchXref(&decoder, base, FunctionTable + i, IsSingleSessionPerUser))
			IsSingleSessionPerUser_addr = backtrace(base, FunctionTable + i)->BeginAddress;
		else if (!IsLicenseTypeLocalOnly_addr && searchXref(&decoder, base, FunctionTable + i, IsLicenseTypeLocalOnly))
			IsLicenseTypeLocalOnly_addr = backtrace(base, FunctionTable + i)->BeginAddress;
		else if (!IsAppServerInstalled_addr && searchXref(&decoder, base, FunctionTable + i, IsAppServerInstalled)) {
			IsAppServerInstalled_addr = backtrace(base, FunctionTable + i)->BeginAddress;
			IsAppServerInstalled_idx = i;
		}
		else if (!GetConnectionProperty_addr && searchXref(&decoder, base, FunctionTable + i, GetConnectionProperty))
			GetConnectionProperty_addr = backtrace(base, FunctionTable + i)->BeginAddress;
		else if (!CSLQuery_Initialize_func && (bRemoteConnAllowed_xref = searchXref(&decoder, base, FunctionTable + i, bRemoteConnAllowed)))
			CSLQuery_Initialize_func = backtrace(base, FunctionTable + i);
		if (CDefPolicy_Query_addr && GetInstanceOfTSLicense_addr && IsSingleSessionPerUserEnabled_addr && (IsAllowNonRDPStack_addr || IsAllowNonRDPStack == -1) &&
			IsSingleSessionPerUser_addr && IsLicenseTypeLocalOnly_addr && CSLQuery_Initialize_func && GetConnectionProperty_addr && IsAppServerInstalled_addr) break;
	}

	if (memset_addr)
	{
		bool patched = false;
		if (IsSingleSessionPerUserEnabled_addr && SingleUserPatch(&decoder, IsSingleSessionPerUserEnabled_addr, base, memset_addr, VerifyVersion_addr))
			patched = true;
		if (IsSingleSessionPerUser_addr && SingleUserPatch(&decoder, IsSingleSessionPerUser_addr, base, memset_addr, VerifyVersion_addr))
			patched = true;
		if (!patched)
			OutputDebugStringA("SingleUserPatch not found\n");
	}

	if (CDefPolicy_Query_addr)
		DefPolicyPatch(&decoder, CDefPolicy_Query_addr, base);
	else OutputDebugStringA("CDefPolicy_Query not found\n");

	if (!CSLQuery_Initialize_func) {
		OutputDebugStringA("CSLQuery_Initialize not found\n");
		return;
	}

	auto IP = CSLQuery_Initialize_func->BeginAddress + base;
	auto length = (ZyanUSize)CSLQuery_Initialize_func->EndAddress - CSLQuery_Initialize_func->BeginAddress;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	if (GetInstanceOfTSLicense_addr)
	{
		if (IsLicenseTypeLocalOnly_addr)
			LocalOnlyPatch(&decoder, GetInstanceOfTSLicense_addr, base, IsLicenseTypeLocalOnly_addr);
		else OutputDebugStringA("IsLicenseTypeLocalOnly not found\n");
	}
	else OutputDebugStringA("GetInstanceOfTSLicense not found\n");

	if (IsAllowNonRDPStack_addr)
	{
		if (IsAppServerInstalled_addr) {
			if (!NonRDPPatch(&decoder, IsAllowNonRDPStack_addr, base, IsAppServerInstalled_addr)) {
				// CSLQuery::IsAppServerInstalled may be inlined, search all occurrence
				DWORD i = IsAppServerInstalled_idx;
				for (; i < FunctionTableSize; i++) {
					if (searchXref(&decoder, base, FunctionTable + i, IsAppServerInstalled) &&
						NonRDPPatch(&decoder, IsAllowNonRDPStack_addr, base, backtrace(base, FunctionTable + i)->BeginAddress))
						break;
				}
				if (i == FunctionTableSize)
					OutputDebugStringA("NonRDPPatch not found\n");
			}
		}
		else OutputDebugStringA("IsAppServerInstalled not found\n");
	}
	else OutputDebugStringA("IsAllowNonRDPStack not found\n");

	if (GetConnectionProperty_addr)
	{
		auto pnpDisabled = pattenMatch(base, rdata, &IS_PNP_DISABLED, sizeof(IS_PNP_DISABLED));
		if (pnpDisabled != -1) {
			auto PropertyDevice_addr = PropertyDeviceAddr(&decoder, GetConnectionProperty_addr, base, pnpDisabled);
			if (PropertyDevice_addr != -1) PropertyDevicePatch(&decoder, PropertyDevice_addr, base);
			else OutputDebugStringA("PropertyAddr not found\n");
		}
		else OutputDebugStringA("IS_PNP_DISABLED not found\n");
	}
	else OutputDebugStringA("GetConnectionProperty not found\n");

	auto bFUSEnabled = pattenMatch(base, rdata, AllowMultipleSessions, sizeof(AllowMultipleSessions));
	auto bAppServerAllowed = pattenMatch(base, rdata, AllowAppServer, sizeof(AllowAppServer));
	auto bMultimonAllowed = pattenMatch(base, rdata, AllowMultimon, sizeof(AllowMultimon));

	auto found = false;
	DWORD64 bInitialized_addr = 0;

	if (length > 0x100)
		while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)IP, length, &instruction, operands)))
		{
			IP += instruction.length;
			length -= instruction.length;
			if (!found && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
				operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
				operands[0].mem.base == ZYDIS_REGISTER_RIP &&
				operands[0].mem.disp.size != 0 &&
				operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				operands[1].reg.value == ZYDIS_REGISTER_EAX)
			{
				found = true;
				*(DWORD*)(operands[0].mem.disp.value + IP) = 1;
			}
			else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
				operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
				operands[1].mem.base == ZYDIS_REGISTER_RIP &&
				operands[1].mem.disp.size != 0 &&
				operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				operands[0].reg.value == ZYDIS_REGISTER_RCX)
			{
				DWORD64 target = operands[1].mem.disp.value + IP - base;
				if (target == bRemoteConnAllowed || target == bFUSEnabled || target == bAppServerAllowed || target == bMultimonAllowed)
					found = false;
			}
			else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
				operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
				operands[0].mem.base == ZYDIS_REGISTER_RIP &&
				operands[0].mem.disp.size != 0 &&
				operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
				operands[1].imm.value.u == 1) {
				bInitialized_addr = operands[0].mem.disp.value + IP;
				break;
			}
		}
	else {
		length = 0x11000;
		while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)IP, length, &instruction, operands)))
		{
			IP += instruction.length;
			length -= instruction.length;
			if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP &&
				operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
				operands[0].imm.is_relative == ZYAN_TRUE &&
				operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				operands[1].reg.value == ZYDIS_REGISTER_RIP)
				IP += operands[0].imm.value.u;
			else if (!found && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
				operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
				operands[0].mem.base == ZYDIS_REGISTER_RIP &&
				operands[0].mem.disp.size != 0 &&
				operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
			{
				found = true;
				*(DWORD*)(operands[0].mem.disp.value + IP) = 1;
			}
			else if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
				operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
				operands[1].mem.base == ZYDIS_REGISTER_RIP &&
				operands[1].mem.disp.size != 0 &&
				operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				operands[0].reg.value == ZYDIS_REGISTER_RDX)
			{
				DWORD64 target = operands[1].mem.disp.value + IP - base;
				if (target == bRemoteConnAllowed || target == bFUSEnabled || target == bAppServerAllowed || target == bMultimonAllowed)
					found = false;
			}
			else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
				operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
				operands[0].mem.base == ZYDIS_REGISTER_RIP &&
				operands[0].mem.disp.size != 0 &&
				operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				(operands[1].reg.value == ZYDIS_REGISTER_EAX ||
					operands[1].reg.value == ZYDIS_REGISTER_ECX))
				bInitialized_addr = operands[0].mem.disp.value + IP;
			else if (instruction.mnemonic == ZYDIS_MNEMONIC_RET)
				break;
		}
	}
	if (bInitialized_addr) *(DWORD*)bInitialized_addr = 1;
	else OutputDebugStringA("bInitialized not found\n");
}
