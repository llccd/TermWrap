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

	ZydisDecoder decoder;
#ifndef _WIN64
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
	range visited = NULL;
	min_heap jmpAddr = {};

	auto text = findSection(pNT, ".text");
	size_t IP = base + text->VirtualAddress;
	size_t length = text->SizeOfRawData;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	while (length >= 5)
		if (!memcmp((void*)IP, "\x8B\xFF\x55\x8B\xEC", 5)) {
			min_heap_push(&jmpAddr, IP);

			while (jmpAddr.size) {
				auto addr = jmpAddr.data[0];
				min_heap_pop(&jmpAddr);
				if (range_in_range(visited, addr)) continue;

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

					if (target == AudioCaptureAllowed) {
						SIZE_T written = 0;
						WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\xB8\x01\x00\x00\x00\xC3", 6, &written);
						min_heap_free(&jmpAddr);
						range_clear(visited);
						return;
					}

				nxt:
					if (instruction.mnemonic >= ZYDIS_MNEMONIC_JB && instruction.mnemonic <= ZYDIS_MNEMONIC_JZ &&
						instruction.operand_count >= 2 &&
						operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
						operands[0].imm.is_relative == ZYAN_TRUE &&
						operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
						operands[1].reg.value == ZYDIS_REGISTER_EIP) {
						size_t offset = j + (size_t)operands[0].imm.value.u;
						if ((offset < addr || offset > j) && !range_in_range(visited, offset)) min_heap_push(&jmpAddr, offset);
					}
					if (instruction.mnemonic == ZYDIS_MNEMONIC_RET || instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
						range_add(visited, addr, j);
						break;
					}
				}
			}
			auto nxt = range_next_val(visited, IP);
			range_clear(visited);
			length -= nxt - IP;
			IP = nxt;
		}
		else {
			IP++;
			length--;
		}
	min_heap_free(&jmpAddr);
	range_clear(visited);
#else
	auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	auto FunctionTable = (PRUNTIME_FUNCTION)(base + pExceptionDirectory->VirtualAddress);
	auto FunctionTableSize = pExceptionDirectory->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
	if (!FunctionTableSize) return;

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
	}
#endif
	OutputDebugStringA("AllowAudioCapture not found\n");
}