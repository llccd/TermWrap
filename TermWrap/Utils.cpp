#include <windows.h>

#ifndef _WIN64
#include <Zydis/Zydis.h>
#define REG_IP ZYDIS_REGISTER_EIP
typedef struct range_node {
	size_t start;
	size_t end;
	struct range_node *next;
} range_node, *range;

static void range_clear(range &r) {
	range_node *n = r;
	while (n) {
		range_node *next = n->next;
		free(n);
		n = next;
	}
	r = NULL;
}

static int range_in_range(range n, size_t val) {
	while (n) {
		if (val < n->start) return 0;
		if (val < n->end) return 1;
		n = n->next;
	}
	return 0;
}

static size_t range_next_val(range n, size_t val) {
	while (n) {
		if (val < n->start) break;
		if (val < n->end) {
			val = n->end;
			break;
		}
		n = n->next;
	}
	return val;
}

static void range_add(range &r, size_t start, size_t end) {
	range_node *prev = r;
	if (!prev || end < prev->start) {
		range_node *n = (range_node *)malloc(sizeof(range_node));
		if (!n) ExitProcess(-7);
		n->start = start;
		n->end = end;
		n->next = r;
		r = n;
		return;
	}
	if (end <= prev->end) {
		if (start < prev->start) prev->start = start;
		return;
	}
	range_node *cur = prev->next;
	while (cur) {
		if (end < cur->start) {
			if (start > prev->end) {
				range_node *n = (range_node *)malloc(sizeof(range_node));
				if (!n) ExitProcess(-7);
				n->start = start;
				n->end = end;
				n->next = cur;
				prev->next = n;
			} else {
				prev->end = end;
			}
			return;
		}
		if (end <= cur->end) {
			if (start < cur->start)
				if (start > prev->end) cur->start = start;
				else {
					prev->end = cur->end;
					prev->next = cur->next;
					free(cur);
				}
			return;
		}
		prev = cur;
		cur = cur->next;
	}
	if (start > prev->end) {
		range_node *n = (range_node *)malloc(sizeof(range_node));
		if (!n) ExitProcess(-7);
		n->start = start;
		n->end = end;
		n->next = NULL;
		prev->next = n;
	} else if (start >= prev->start && end > prev->end) {
		prev->end = end;
	}
}

typedef struct {
	size_t *data;
	size_t size;
	size_t capacity;
} min_heap;

static void min_heap_push(min_heap *h, size_t val) {
	if (h->size >= h->capacity) {
		size_t new_cap = h->capacity == 0 ? 8 : h->capacity * 2;
		h->data = (size_t *)realloc(h->data, new_cap * sizeof(size_t));
		if (!h->data) ExitProcess(-7);
		h->capacity = new_cap;
	}
	h->data[h->size++] = val;
	size_t i = h->size - 1;
	while (i > 0) {
		size_t parent = (i - 1) / 2;
		if (h->data[parent] <= h->data[i]) break;
		size_t tmp = h->data[parent];
		h->data[parent] = h->data[i];
		h->data[i] = tmp;
		i = parent;
	}
}

static void min_heap_pop(min_heap *h) {
	h->size--;
	if (h->size > 0) {
		h->data[0] = h->data[h->size];
		size_t i = 0;
		while (1) {
			size_t smallest = i;
			size_t left = 2 * i + 1;
			size_t right = 2 * i + 2;
			if (left < h->size && h->data[left] < h->data[smallest]) smallest = left;
			if (right < h->size && h->data[right] < h->data[smallest]) smallest = right;
			if (smallest == i) break;
			size_t tmp = h->data[smallest];
			h->data[smallest] = h->data[i];
			h->data[i] = tmp;
			i = smallest;
		}
	}
}

static void min_heap_free(min_heap *h) {
	free(h->data);
	h->data = NULL;
	h->size = 0;
	h->capacity = 0;
}
#endif

#ifdef _AMD64_
#include <Zydis/Zydis.h>
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

static DWORD64 searchXref(ZydisDecoder* decoder, DWORD64 base, PIMAGE_AMD64_RUNTIME_FUNCTION_ENTRY func, DWORD64 target)
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

static PRUNTIME_FUNCTION backtrace(DWORD64 base, PIMAGE_AMD64_RUNTIME_FUNCTION_ENTRY func) {
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

static DWORD readSetting(LPCSTR name, DWORD val) {
	HKEY hKey;
	DWORD data;
	if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", 0, KEY_READ, &hKey)) {
		DWORD cbData = 4;
		if (!RegQueryValueExA(hKey, name, NULL, NULL, (LPBYTE)&data, &cbData)) val = data;
		RegCloseKey(hKey);
	}
	if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services", 0, KEY_READ, &hKey)) {
		DWORD cbData = 4;
		if (!RegQueryValueExA(hKey, name, NULL, NULL, (LPBYTE)&data, &cbData)) val = data;
		RegCloseKey(hKey);
	}
	return val;
}

static PIMAGE_SECTION_HEADER findSection(PIMAGE_NT_HEADERS pNT, const char* str)
{
	auto pSection = IMAGE_FIRST_SECTION(pNT);

	for (size_t i = 0; i < pNT->FileHeader.NumberOfSections; i++)
		if (CSTR_EQUAL == CompareStringA(LOCALE_INVARIANT, 0, (char*)pSection[i].Name, -1, str, -1))
			return pSection + i;

	return NULL;
}

static size_t pattenMatch(size_t base, PIMAGE_SECTION_HEADER pSection, const void* str, size_t size)
{
	size_t rdata = base + pSection->VirtualAddress;

	for (size_t i = 0; i < pSection->SizeOfRawData; i += 4)
		if (!memcmp((void*)(rdata + i), str, size)) return pSection->VirtualAddress + i;

	return -1;
}

static PIMAGE_IMPORT_DESCRIPTOR findImportImage(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, size_t base, LPCSTR str) {
	while (pImportDescriptor->Name)
	{
		if (!lstrcmpiA((LPCSTR)(base + pImportDescriptor->Name), str)) return pImportDescriptor;
		pImportDescriptor++;
	}
	return NULL;
}

static size_t findImportFunction(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, size_t base, LPCSTR str) {
	auto pThunk = (PIMAGE_THUNK_DATA)(pImportDescriptor->OriginalFirstThunk + base);
	while (pThunk->u1.AddressOfData)
	{
		if (!lstrcmpiA(((PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + base))->Name, str))
			return (size_t)pThunk - base - pImportDescriptor->OriginalFirstThunk + pImportDescriptor->FirstThunk;
		pThunk++;
	}
	return 0;
}