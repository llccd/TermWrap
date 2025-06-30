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

#ifndef _WIN64
#define REG_IP ZYDIS_REGISTER_EIP
#include <queue>
#include <forward_list>

class range {
private:
	std::forward_list<std::pair<size_t, size_t>> list;
public:
	bool in_range(size_t val) {
		for (auto& p : list) {
			if (val < p.first) return false;
			if (val < p.second) return true;
		}
		return false;
	}
	size_t next_val(size_t val) {
		for (auto& p : list) {
			if (val < p.first) break;
			if (val < p.second) {
				val = p.second;
				break;
			}
		}
		return val;
	}
	void clear() {
		list.clear();
	}
	bool empty() {
		return list.empty();
	}
	void add(size_t start, size_t end) {
		auto p = std::make_pair(start, end);
		auto it = list.begin();
		auto prev = &*it;
		if (list.empty() || end < prev->first) {
			list.emplace_front(p);
			return;
		}
		if (end <= prev->second) {
			if (start < prev->first) prev->first = start;
			return;
		}
		while (next(it) != list.end()) {
			auto& i = *next(it);
			if (end < i.first) {
				if (start > prev->second) list.emplace_after(it, p);
				else prev->second = end;
				return;
			}
			if (end <= i.second) {
				if (start < i.first)
					if (start > prev->second) i.first = start;
					else {
						prev->second = i.second;
						list.erase_after(it);
					}
				return;
			}
			prev = &i;
			it++;
		}
		if (start > prev->second) list.emplace_after(it, p);
		else if (start >= prev->first && end > prev->second) prev->second = end;
	}
};
#else
#define REG_IP ZYDIS_REGISTER_RIP

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
#endif

PIMAGE_SECTION_HEADER findSection(PIMAGE_NT_HEADERS pNT, const char* str)
{
	auto pSection = IMAGE_FIRST_SECTION(pNT);

	for (size_t i = 0; i < pNT->FileHeader.NumberOfSections; i++)
		if (CSTR_EQUAL == CompareStringA(LOCALE_INVARIANT, 0, (char*)pSection[i].Name, -1, str, -1))
			return pSection + i;

	return NULL;
}

size_t pattenMatch(size_t base, PIMAGE_SECTION_HEADER pSection, const void* str, size_t size)
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

size_t findImportFunction(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, size_t base, LPCSTR str) {
	auto pThunk = (PIMAGE_THUNK_DATA)(pImportDescriptor->OriginalFirstThunk + base);
	while (pThunk->u1.AddressOfData)
	{
		if (!lstrcmpiA(((PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + base))->Name, str))
			return (size_t)pThunk - base - pImportDescriptor->OriginalFirstThunk + pImportDescriptor->FirstThunk;
		pThunk++;
	}
	return 0;
}

void LocalOnlyPatch(ZydisDecoder* decoder, size_t RVA, size_t base, size_t target) {
	ZyanUSize length = 256;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	target += base;
	SIZE_T written = 0;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
			operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			operands[0].imm.is_relative == ZYAN_TRUE &&
			operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].reg.value == REG_IP &&
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
				operands[1].reg.value != REG_IP) break;

			if (instruction.mnemonic == ZYDIS_MNEMONIC_JNS)
			{
				target = IP + instruction.length;
				IP = target + (size_t)operands[0].imm.value.u;
			}
			else if (instruction.mnemonic != ZYDIS_MNEMONIC_JS) break;
			else
			{
				IP += instruction.length;
				target = IP + (size_t)operands[0].imm.value.u;
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
				operands[1].reg.value != REG_IP ||
				target != IP + operands[0].imm.value.u + instruction.length) break;

			if (instruction.raw.imm[0].offset == 2) WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\x90\xE9", 2, &written);
			else WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xEB", 1, &written);

			return;
		}
	}
	OutputDebugStringA("LocalOnlyPatch not found\n");
}

void DefPolicyPatch(ZydisDecoder* decoder, size_t RVA, size_t base) {
	ZyanUSize length = 128;
	ZyanUSize lastLength = 0;
	ZyanUSize instLength;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	auto mov_base = ZYDIS_REGISTER_NONE;
	auto mov_target = ZYDIS_REGISTER_NONE;
	SIZE_T written = 0;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		instLength = instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP) {
#ifdef _WIN64
			if (operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
				operands[0].mem.disp.value != 0x63c ||
				operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER) goto out;
			auto reg1 = operands[1].reg.value;
			auto reg2 = operands[0].mem.base;
#else
			if (operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY ||
				operands[1].mem.disp.value != 0x320 ||
				operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) goto out;
			auto reg1 = operands[0].reg.value;
			auto reg2 = operands[1].mem.base;
#endif

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
				case ZYDIS_REGISTER_ECX:
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x81\x20\x03\x00\x00\xEB\x0E", 13, &written);
					break;
#ifdef _WIN64
				case ZYDIS_REGISTER_RCX:
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x81\x38\x06\x00\x00\x90\xEB", 13, &written);
					break;
				case ZYDIS_REGISTER_RDI:
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x87\x38\x06\x00\x00\x90\xEB", 13, &written);
					break;
#endif
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
			case ZYDIS_REGISTER_ECX:
				WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x81\x24\x03\x00\x00\x90", 12, &written);
				break;
			case ZYDIS_REGISTER_ESI:
				WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x86\x20\x03\x00\x00\x90", 12, &written);
				break;
#ifdef _WIN64
			case ZYDIS_REGISTER_RCX:
				WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x81\x38\x06\x00\x00\x90", 12, &written);
				break;
			case ZYDIS_REGISTER_RDI:
				WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x00\x01\x00\x00\x89\x87\x38\x06\x00\x00\x90", 12, &written);
				break;
#endif
			default:
				OutputDebugStringA("DefPolicyPatch: Unknown reg2\n");
				break;
			}
			return;
		}
#ifdef _WIN64
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
#endif
	out:
		IP += instLength;
		length -= instLength;
		lastLength = instLength;
	}
	OutputDebugStringA("DefPolicyPatch not found\n");
}

int SingleUserPatch(ZydisDecoder* decoder, size_t RVA, size_t base, size_t target, size_t target2) {
	ZyanUSize length = 256;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	target += base;
	target2 += base;
	SIZE_T written = 0;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
			operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			operands[0].imm.is_relative == ZYAN_TRUE &&
			operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].reg.value == REG_IP)
		{
			auto jmp_addr = IP + operands[0].imm.value.u;
			if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)jmp_addr, length, &instruction, operands)) ||
				instruction.mnemonic != ZYDIS_MNEMONIC_JMP ||
				operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY ||
				operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
				continue;
#ifndef _WIN64
			if (operands[0].mem.segment != ZYDIS_REGISTER_DS ||
				operands[1].reg.value != ZYDIS_REGISTER_EIP ||
				operands[0].mem.disp.value != target)
				continue;
#else
			if (operands[0].mem.base != ZYDIS_REGISTER_RIP ||
				operands[1].reg.value != ZYDIS_REGISTER_RIP ||
				operands[0].mem.disp.value + jmp_addr + instruction.length != target)
				continue;
#endif

			while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
			{
#ifndef _WIN64
				if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
					instruction.length >= 5 && instruction.length <= 7 &&
					operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
					operands[0].mem.segment == ZYDIS_REGISTER_DS &&
					operands[0].mem.disp.value == target2) {
					// call VerifyVersionInfoW -> pop eax; add esp, 12
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\x58\x83\xC4\x0C\x90\x90\x90", instruction.length, &written);
					return 1;
				}
				if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP && instruction.length <= 8 &&
					operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[0].mem.base == ZYDIS_REGISTER_EBP &&
					operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[1].imm.value.u == 1) {
					// cmp [ebp+XX], 1 -> nop
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\x90\x90\x90\x90\x90\x90\x90\x90", instruction.length, &written);
					return 1;
				}
#else
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
				if (instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
					instruction.length <= 8 && operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
					(operands[0].mem.base == ZYDIS_REGISTER_RBP || operands[0].mem.base == ZYDIS_REGISTER_RSP) &&
					(operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[1].imm.value.u == 1 ||
						operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)) {
					// cmp [rbp/rsp+XX], 1 -> nop
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\x90\x90\x90\x90\x90\x90\x90\x90", instruction.length, &written);
					return 1;
				}
#endif
				IP += instruction.length;
				length -= instruction.length;
			}
			break;
		}
	}
	return 0;
}

int NonRDPPatch(ZydisDecoder* decoder, size_t RVA, size_t base, size_t target) {
	ZyanUSize length = 256;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	target += base;
	SIZE_T written = 0;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
			operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			operands[0].imm.is_relative == ZYAN_TRUE &&
			operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].reg.value == REG_IP &&
			target == IP + operands[0].imm.value.u)
		{

			if (instruction.length != 5) break;
			// inc dword ptr [ecx/rcx]
			// xor eax, eax
			// nop
			WriteProcessMemory(GetCurrentProcess(), (void*)(IP - instruction.length), "\xFF\x01\x31\xC0\x90", 5, &written);
			return 1;
		}
	}
	return 0;
}

size_t PropertyDeviceAddr(ZydisDecoder* decoder, size_t RVA, size_t base, size_t target) {
	ZyanUSize length = 256;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	target += base;

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
#ifdef _WIN64
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
					IP += (size_t)operands[0].imm.value.u;

				else if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
					operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
					operands[0].imm.is_relative == ZYAN_TRUE &&
					operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					operands[1].reg.value == ZYDIS_REGISTER_RIP)
					return IP + (size_t)operands[0].imm.value.u - base;
			}
			return -1;
		}
		if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[0].reg.value == ZYDIS_REGISTER_RCX &&
			operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			(operands[1].mem.base == ZYDIS_REGISTER_RIP && target == IP + operands[1].mem.disp.value ||
				operands[1].mem.segment == ZYDIS_REGISTER_DS && target == base + operands[1].mem.disp.value))
#else
		if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			target == operands[1].imm.value.u)
#endif
		{
			bool foundJNZ = false;
			while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
			{
				IP += instruction.length;
				length -= instruction.length;

				if (!foundJNZ && instruction.mnemonic == ZYDIS_MNEMONIC_JNZ) {
					IP += (size_t)operands[0].imm.value.u;
					foundJNZ = true;
				}
				
				if (foundJNZ && instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
					operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
					operands[0].imm.is_relative == ZYAN_TRUE &&
					operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
					operands[1].reg.value == REG_IP)
					return IP + (size_t)operands[0].imm.value.u - base;
			}
			return -1;
		}
	}
	return -1;
}

void PropertyDevicePatch(ZydisDecoder* decoder, size_t RVA, size_t base) {
	ZyanUSize length = 256;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	auto IP = RVA + base;
	SIZE_T written = 0;

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
					case ZYDIS_REGISTER_ESI:
						WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xBE\x00\x00\x00\x00\x90", 3 + instruction.length, &written);
						break;
					default:
						OutputDebugStringA("PropertyPatch: Unknown reg\n");
						break;
					}
					return;
				}
				IP += instruction.length;
				length -= instruction.length;
				if (instruction.mnemonic == ZYDIS_MNEMONIC_JNZ || instruction.mnemonic == ZYDIS_MNEMONIC_JZ)
				{
					auto target = IP + (size_t)operands[0].imm.value.u;
					if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)target, length, &instruction, operands)) ||
						instruction.mnemonic != ZYDIS_MNEMONIC_SHR || operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
						operands[0].reg.value != reg || operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
						operands[1].imm.value.u != 0x0c) continue;
					if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)(target + instruction.length), length, &instruction, operands)) ||
						instruction.mnemonic != ZYDIS_MNEMONIC_AND || operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
						operands[0].reg.value != reg || operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
						operands[1].imm.value.u != 7) break;

					switch (reg) {
					case ZYDIS_REGISTER_EAX:
						WriteProcessMemory(GetCurrentProcess(), (void*)target, "\xB8\x07\x00\x00\x00\x90", 3 + instruction.length, &written);
						break;
					case ZYDIS_REGISTER_ECX:
						WriteProcessMemory(GetCurrentProcess(), (void*)target, "\xB9\x07\x00\x00\x00\x90", 3 + instruction.length, &written);
						break;
					case ZYDIS_REGISTER_ESI:
						WriteProcessMemory(GetCurrentProcess(), (void*)target, "\xBE\x07\x00\x00\x00\x90", 3 + instruction.length, &written);
						break;
					default:
						OutputDebugStringA("PropertyPatch: Unknown reg\n");
						break;
					}
				}
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
	auto pNT = (PIMAGE_NT_HEADERS)(base + pDos->e_lfanew);
	auto text = findSection(pNT, ".text");
	auto rdata = findSection(pNT, ".rdata");
	if (!rdata) rdata = text;

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

	size_t VerifyVersion_addr = -1;
	pImportImage = findImportImage(pImportDescriptor, base, "api-ms-win-core-kernel32-legacy-l1-1-1.dll");
	if (!pImportImage) pImportImage = findImportImage(pImportDescriptor, base, "KERNEL32.dll");
	if (pImportImage) VerifyVersion_addr = findImportFunction(pImportImage, base, "VerifyVersionInfoW");

	size_t CDefPolicy_Query_addr = 0, GetInstanceOfTSLicense_addr = 0, IsSingleSessionPerUserEnabled_addr = 0, IsAllowNonRDPStack_addr = 0,
		IsSingleSessionPerUser_addr = 0, IsLicenseTypeLocalOnly_addr = 0, IsAppServerInstalled_addr = 0, GetConnectionProperty_addr = 0, bRemoteConnAllowed_xref;
	size_t CSLQuery_Initialize_addr = 0, CSLQuery_Initialize_len = 0x11000;

	ZydisDecoder decoder;
	DWORD IsAppServerInstalled_idx = 0;
	size_t IP, length;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

#ifndef _WIN64
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
	range visited;
	std::priority_queue<size_t, std::vector<size_t>, std::greater<size_t>> jmpAddr;

	IP = base + text->VirtualAddress;
	length = text->SizeOfRawData;

	while (length >= 5)
		if (!memcmp((void*)IP, "\x8B\xFF\x55\x8B\xEC", 5)) {
			jmpAddr.push(IP);

			while (!jmpAddr.empty()) {
				auto addr = jmpAddr.top();
				jmpAddr.pop();
				if (visited.in_range(addr)) continue;

				auto j = addr;
				ZyanUSize l = text->SizeOfRawData - (j - base);
				while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)j, l, &instruction, operands))) {
					j += instruction.length;
					l -= instruction.length;

					size_t target;
					if (instruction.length == 5 && instruction.mnemonic == ZYDIS_MNEMONIC_PUSH && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
						target = (size_t)operands[0].imm.value.u - base;
					else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
						(operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && instruction.length == 5 ||
							operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instruction.length >= 7 && 
							(operands[0].mem.base == ZYDIS_REGISTER_EBP || operands[0].mem.base == ZYDIS_REGISTER_ESP)))
						target = (size_t)operands[1].imm.value.u - base;
					else goto nxt;

					if (!CDefPolicy_Query_addr && target == CDefPolicy_Query)
						CDefPolicy_Query_addr = IP - base;
					else if (!GetInstanceOfTSLicense_addr && target == GetInstanceOfTSLicense)
						GetInstanceOfTSLicense_addr = IP - base;
					else if (!IsSingleSessionPerUserEnabled_addr && target == IsSingleSessionPerUserEnabled)
						IsSingleSessionPerUserEnabled_addr = IP - base;
					else if (!IsAllowNonRDPStack_addr && target == IsAllowNonRDPStack)
						IsAllowNonRDPStack_addr = IP - base;
					else if (!IsSingleSessionPerUser_addr && target == IsSingleSessionPerUser)
						IsSingleSessionPerUser_addr = IP - base;
					else if (!IsLicenseTypeLocalOnly_addr && target == IsLicenseTypeLocalOnly)
						IsLicenseTypeLocalOnly_addr = IP - base;
					else if (!IsAppServerInstalled_addr && target == IsAppServerInstalled) {
						IsAppServerInstalled_addr = IP - base;
						IsAppServerInstalled_idx = visited.next_val(IP);
					}
					else if (!GetConnectionProperty_addr && target == GetConnectionProperty)
						GetConnectionProperty_addr = IP - base;
					else if (!CSLQuery_Initialize_addr && target == bRemoteConnAllowed) {
						bRemoteConnAllowed_xref = j - base;
						CSLQuery_Initialize_addr = IP - base;
					}
					else goto nxt;
					if (visited.empty()) visited.add(addr, j);
					while (!jmpAddr.empty()) jmpAddr.pop();
					if (CDefPolicy_Query_addr && GetInstanceOfTSLicense_addr && IsSingleSessionPerUserEnabled_addr && (IsAllowNonRDPStack_addr || IsAllowNonRDPStack == -1) &&
						IsSingleSessionPerUser_addr && IsLicenseTypeLocalOnly_addr && CSLQuery_Initialize_addr && GetConnectionProperty_addr) goto fin;
					goto out;

				nxt:
					if (instruction.mnemonic >= ZYDIS_MNEMONIC_JB && instruction.mnemonic <= ZYDIS_MNEMONIC_JZ &&
						instruction.operand_count >= 2 &&
						operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
						operands[0].imm.is_relative == ZYAN_TRUE &&
						operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
						operands[1].reg.value == ZYDIS_REGISTER_EIP) {
						size_t offset = j + (size_t)operands[0].imm.value.u;
						if ((offset < addr || offset > j) && !visited.in_range(offset)) jmpAddr.push(offset);
					}
					if (instruction.mnemonic == ZYDIS_MNEMONIC_RET || instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
						visited.add(addr, j);
						break;
					}
				}
			}
		out:
			auto nxt = visited.next_val(IP);
			visited.clear();
			length -= nxt - IP;
			IP = nxt;
		}
		else {
			IP++;
			length--;
		}
fin:;
#else
	auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	auto FunctionTable = (PRUNTIME_FUNCTION)(base + pExceptionDirectory->VirtualAddress);
	auto FunctionTableSize = pExceptionDirectory->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
	if (!FunctionTableSize) return;

	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
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
		else if (!CSLQuery_Initialize_addr && (bRemoteConnAllowed_xref = searchXref(&decoder, base, FunctionTable + i, bRemoteConnAllowed))) {
			auto CSLQuery_Initialize_func = backtrace(base, FunctionTable + i);
			CSLQuery_Initialize_addr = CSLQuery_Initialize_func->BeginAddress;
			CSLQuery_Initialize_len = CSLQuery_Initialize_func->EndAddress - CSLQuery_Initialize_func->BeginAddress;
		}
		if (CDefPolicy_Query_addr && GetInstanceOfTSLicense_addr && IsSingleSessionPerUserEnabled_addr && (IsAllowNonRDPStack_addr || IsAllowNonRDPStack == -1) &&
			IsSingleSessionPerUser_addr && IsLicenseTypeLocalOnly_addr && CSLQuery_Initialize_addr && GetConnectionProperty_addr && IsAppServerInstalled_addr) break;
	}
#endif

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

	if (!CSLQuery_Initialize_addr) {
		OutputDebugStringA("CSLQuery_Initialize not found\n");
		return;
	}

	IP = base + CSLQuery_Initialize_addr;
	length = CSLQuery_Initialize_len;

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
#ifndef _WIN64
			visited.clear();
			IP = base + IsAppServerInstalled_idx;
			length = text->SizeOfRawData - (IsAppServerInstalled_idx - base);

			while (length >= 5)
				if (!memcmp((void*)IP, "\x8B\xFF\x55\x8B\xEC", 5)) {
					jmpAddr.push(IP);

					while (!jmpAddr.empty()) {
						auto addr = jmpAddr.top();
						jmpAddr.pop();
						if (visited.in_range(addr)) continue;

						auto j = addr;
						ZyanUSize l = text->SizeOfRawData - (j - base);
						while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)j, l, &instruction, operands))) {
							j += instruction.length;
							l -= instruction.length;

							if (instruction.length == 5 && instruction.mnemonic == ZYDIS_MNEMONIC_PUSH && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								IsAppServerInstalled == (size_t)operands[0].imm.value.u - base ||
								instruction.mnemonic == ZYDIS_MNEMONIC_MOV && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								(operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && instruction.length == 5 ||
									operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instruction.length >= 7 &&
									(operands[0].mem.base == ZYDIS_REGISTER_EBP || operands[0].mem.base == ZYDIS_REGISTER_ESP)) &&
								IsAppServerInstalled == (size_t)operands[1].imm.value.u - base)
								if (NonRDPPatch(&decoder, IsAllowNonRDPStack_addr, base, IP - base)) goto fin2;

							if (instruction.mnemonic >= ZYDIS_MNEMONIC_JB && instruction.mnemonic <= ZYDIS_MNEMONIC_JZ &&
								instruction.operand_count >= 2 &&
								operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
								operands[0].imm.is_relative == ZYAN_TRUE &&
								operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
								operands[1].reg.value == ZYDIS_REGISTER_EIP) {
								size_t offset = j + (size_t)operands[0].imm.value.u;
								if ((offset < addr || offset > j) && !visited.in_range(offset)) jmpAddr.push(offset);
							}
							if (instruction.mnemonic == ZYDIS_MNEMONIC_RET || instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
								visited.add(addr, j);
								break;
							}
						}
					}
					auto nxt = visited.next_val(IP);
					visited.clear();
					length -= nxt - IP;
					IP = nxt;
				}
				else {
					IP++;
					length--;
				}
fin2:;
#else
				DWORD i = IsAppServerInstalled_idx;
				for (; i < FunctionTableSize; i++) {
					if (searchXref(&decoder, base, FunctionTable + i, IsAppServerInstalled) &&
						NonRDPPatch(&decoder, IsAllowNonRDPStack_addr, base, backtrace(base, FunctionTable + i)->BeginAddress))
						break;
				}
				if (i == FunctionTableSize)
					OutputDebugStringA("NonRDPPatch not found\n");
#endif
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
	size_t bInitialized_addr = 0;

#ifndef _WIN64
	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (!found && instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
			operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operands[0].mem.segment == ZYDIS_REGISTER_DS &&
			operands[0].mem.base == ZYDIS_REGISTER_NONE &&
			operands[0].mem.disp.size != 0 &&
			operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			(operands[1].reg.value == ZYDIS_REGISTER_EAX ||
				operands[1].reg.value == ZYDIS_REGISTER_EDI ||
				operands[1].reg.value == ZYDIS_REGISTER_ESI))
		{
			found = true;
			*(DWORD*)(operands[0].mem.disp.value) = 1;
		}
		else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
			operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operands[0].mem.segment == ZYDIS_REGISTER_DS &&
			operands[0].mem.base == ZYDIS_REGISTER_NONE &&
			operands[0].mem.disp.size != 0 &&
			operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			operands[1].imm.value.u == 1) {
			bInitialized_addr = (size_t)operands[0].mem.disp.value;
			break;
		}
		else if (instruction.length == 5)
		{
			size_t target;
			if (instruction.mnemonic == ZYDIS_MNEMONIC_PUSH && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
				target = (size_t)operands[0].imm.value.u - base;
			else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) target = (size_t)operands[1].imm.value.u - base;
			else continue;

			if (target == bRemoteConnAllowed || target == bFUSEnabled || target == bAppServerAllowed || target == bMultimonAllowed)
				found = false;
		}
	}
#else
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
#endif
	if (bInitialized_addr) *(DWORD*)bInitialized_addr = 1;
	else OutputDebugStringA("bInitialized not found\n");
}
