#include "../TermWrap/Utils.cpp"
#include "aarch64_ic.h"

constexpr const char Query[] = "CDefPolicy::Query";
constexpr const char LocalOnly[] = "CSLQuery::IsTerminalTypeLocalOnly";
constexpr const char SingleSessionEnabled[] = "CSessionArbitrationHelper::IsSingleSessionPerUserEnabled";
constexpr const char InstanceOfLicense[] = "CEnforcementCore::GetInstanceOfTSLicense ";

constexpr const WCHAR AllowRemote[] = L"TerminalServices-RemoteConnectionManager-AllowRemoteConnections";
constexpr const WCHAR AllowMultipleSessions[] = L"TerminalServices-RemoteConnectionManager-AllowMultipleSessions";
constexpr const WCHAR AllowAppServer[] = L"TerminalServices-RemoteConnectionManager-AllowAppServerMode";
constexpr const WCHAR AllowMultimon[] = L"TerminalServices-RemoteConnectionManager-AllowMultimon";

static size_t searchXrefARM64(size_t base, PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY func, size_t target)
{
	size_t IP = base + func->BeginAddress;
	size_t endIP;
	if (func->Flag == PdataRefToFullXdata) {
		auto xdata = (IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA*)(base + (func->UnwindData & ~3));
		endIP = IP + ((xdata->HeaderData & 0x3FFFF) << 2);
	}
	else endIP = IP + (func->UnwindData & 0x1FFC);

	while (IP + 8 <= endIP) {
		uint32_t ic = *((uint32_t*)IP);
		if (is_arm64_adrp(ic)) {
			size_t addr = ((int64_t)(ic & 0xFFFFE0)) << 40 >> 31 | (ic & 0x60000000) >> 17;
			uint32_t rd = get_rt_rd(ic);
			addr += (IP - base) & ~(size_t)0xFFF;
			IP += 4;
			ic = *((uint32_t*)IP);
			if (!is_arm64_add64(ic) || get_shift(ic) || rd != get_rn(ic)) continue;
			if (addr + (get_imm12(ic) >> 10) == target) return IP - base;
		}
		IP += 4;
	}
	return 0;
}

static PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY backtraceARM64(size_t base, PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY func, PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY FunctionTable, DWORD FunctionTableSize) {
	if (func->Flag == PdataPackedUnwindFunction)
		return func;

	size_t IP;
	if (func->Flag == PdataRefToFullXdata) {
		auto xdata = (IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA*)(base + (func->UnwindData & ~3));
		if (xdata->HeaderData & 0x7E00000) return func;
		IP = base + func->BeginAddress + ((xdata->HeaderData & 0x3FFFF) << 2) - 4;
	}
	else IP = base + func->BeginAddress + (func->UnwindData & 0x1FFC) - 4;

	size_t length = 32;
	while (length >= 4) {
		uint32_t ic = *((uint32_t*)IP);
		size_t target;
		if (is_arm64_b(ic))
			target = IP + get_imm26(ic) - base;
		else if (is_arm64_bl(ic)) {
			auto rn = get_rn(ic);
			IP -= 4;
			ic = *((uint32_t*)IP);
			if (!is_arm64_add64(ic) || get_shift(ic) || rn != get_rt_rd(ic)) return func;
			target = get_imm12(ic) >> 10;
			rn = get_rn(ic);
			IP -= 4;
			ic = *((uint32_t*)IP);
			if (!is_arm64_adrp(ic) || rn != get_rt_rd(ic)) return func;
			target += ((int64_t)(ic & 0xFFFFE0)) << 40 >> 31 | (ic & 0x60000000) >> 17;
			target += (IP - base) & ~(size_t)0xFFF;
		}
		else {
			IP -= 4;
			length -= 4;
			continue;
		}

		DWORD low = 0, high = FunctionTableSize;
		while (low <= high) {
			DWORD mid = (low + high) / 2;
			if ((FunctionTable + mid)->BeginAddress < target)
				low = mid + 1;
			else
				high = mid - 1;
		}
		return FunctionTable + low - 1;
	}
	return func;
}

static size_t funcAddrARM64(size_t RVA, size_t base) {
	auto ic = *((uint32_t*)(RVA + base));
	if (!is_arm64_adrp(ic)) return 0;
	size_t addr = ((int64_t)(ic & 0xFFFFE0)) << 40 >> 31 | (ic & 0x60000000) >> 17;
	auto rd = get_rt_rd(ic);
	ic = *((uint32_t*)(RVA + base + 4));
	if (!is_arm64_ldr64_unsigned(ic) || rd != get_rn(ic)) return 0;
	addr += get_imm12(ic) >> 7;
	return addr + (RVA & ~(size_t)0xFFF);
}

static void LocalOnlyPatchARM64(size_t RVA, size_t base, size_t target) {
	size_t length = 256;
	auto IP = RVA + base;
	target += base;
	SIZE_T written = 0;

	while (length >= 12) {
		auto ic = *((uint32_t*)IP);
		if (is_arm64_bl(ic) && IP + get_imm26(ic) == target) {
			do {
				IP += 4;
				length -= 4;
				ic = *((uint32_t*)IP);
			} while (length >= 8 && !is_arm64_tbnz(ic));
			target = IP + get_imm14(ic);
			do {
				IP += 4;
				length -= 4;
				ic = *((uint32_t*)IP);
				if (is_arm64_cbz(ic) && IP + get_imm19(ic) == target) {
					ic = (get_imm19(ic) >> 2 & 0x3FFFFFF) | 0x14000000;
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, &ic, 4, &written);
					return;
				}
			} while (length >= 4);
			break;
		}
		IP += 4;
		length -= 4;
	}
	OutputDebugStringA("ERROR: LocalOnlyPatch pattern not found");
}

static void DefPolicyPatchARM64(size_t RVA, size_t base) {
	size_t length = 128;
	auto IP = RVA + base;
	uint32_t reg1, reg2, rt;
	SIZE_T written = 0;

	while (length >= 4) {
		auto ic = *((uint32_t*)IP);
		if (is_arm64_add64(ic) && get_shift(ic) == 0 && get_imm12(ic) >> 10 == 0x638) {
			reg2 = get_rn(ic);
			rt = get_rt_rd(ic);
			ic = *((uint32_t*)(IP + 4));
			if (!(is_arm64_ldp32(ic) || is_arm64_ldp32_signed(ic)) || get_imm7(ic) || rt != get_rn(ic)) goto out;
			reg1 = get_rt_rd(ic);
			rt = get_rt2(ic);
		}
		else if (is_arm64_ldr32_unsigned(ic) && get_imm12(ic) >> 8 == 0x638) {
			reg1 = get_rt_rd(ic);
			reg2 = get_rn(ic);
			ic = *((uint32_t*)(IP + 4));
			if (!is_arm64_ldr32_unsigned(ic) || get_imm12(ic) >> 8 != 0x63c || reg2 != get_rn(ic)) goto out;
			rt = get_rt_rd(ic);
		}
		else goto out;
		ic = *((uint32_t*)(IP + 8));
		if (!is_arm64_cmp32(ic) || get_imm6(ic) || (rt != get_rn(ic) || reg1 != get_rm(ic)) && (reg1 != get_rn(ic) || rt != get_rm(ic))) goto out;
		ic = *((uint32_t*)(IP + 12));
		if (is_arm64_b_cond(ic)) {
			uint32_t patchData[4] = { 0x52800C80, 0xB9063800, 0xD503201F, 0xD503201F };
			if ((ic & 0xf) == 1)
				patchData[3] = ic | 0xe;
			else if (ic & 0xf)
				break;
			patchData[0] |= reg1;
			patchData[1] |= reg1 | reg2 << 5;
			WriteProcessMemory(GetCurrentProcess(), (void*)IP, patchData, 16, &written);
			return;
		}
	out:
		IP += 4;
		length -= 4;
	}
	OutputDebugStringA("ERROR: DefPolicyPatch pattern not found");
}

static int SingleUserPatchARM64(size_t RVA, size_t base, size_t target, size_t target2) {
	size_t length = 256;
	auto IP = RVA + base;
	SIZE_T written = 0;

	while (length >= 4) {
		auto ic = *((uint32_t*)IP);

		if (is_arm64_bl(ic) && funcAddrARM64(IP + get_imm26(ic) - base, base) == target) {
			IP += 4;
			length = 128;
			while (length >= 4) {
				ic = *((uint32_t*)IP);
				if (is_arm64_bl(ic) && funcAddrARM64(IP + get_imm26(ic) - base, base) == target2) {
					//MOV W0, #1
					WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\x20\x00\x80\x52", 4, &written);
					return 1;
				}
				else if (is_arm64_adrp(ic)) {
					size_t addr = ((int64_t)(ic & 0xFFFFE0)) << 40 >> 31 | (ic & 0x60000000) >> 17;
					uint32_t rd = get_rt_rd(ic);
					addr += (IP - base) & ~(size_t)0xFFF;
					IP += 4;
					ic = *((uint32_t*)IP);
					if (!is_arm64_add64(ic) || get_shift(ic) || rd != get_rn(ic)) continue;
					rd = get_rt_rd(ic);
					if (addr + (get_imm12(ic) >> 10) == target2) {
						do {
							IP += 4;
							length -= 4;
							ic = *((uint32_t*)IP);
						} while (length >= 4 && !is_arm64_ldar64(ic) && rd != get_rn(ic));
						while (length >= 4) {
							IP += 4;
							length -= 4;
							ic = *((uint32_t*)IP);
							if (is_arm64_blr(ic) && rd != get_rn(ic)) {
								//MOV W0, #1
								WriteProcessMemory(GetCurrentProcess(), (void*)IP, "\x20\x00\x80\x52", 4, &written);
								return 1;
							}
						}
						return 0;
					}
				}
				IP += 4;
				length -= 4;
			}
			break;
		}
		IP += 4;
		length -= 4;
	}
	return 0;
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
	auto IsSingleSessionPerUserEnabled = pattenMatch(base, rdata, SingleSessionEnabled, sizeof(SingleSessionEnabled) - 1);
	auto IsSingleSessionPerUser = pattenMatch(base, rdata, "IsSingleSessionPerUser", sizeof("IsSingleSessionPerUser"));
	if (!memcmp((void*)(base + IsSingleSessionPerUser - 8), "CUtils::", 8)) IsSingleSessionPerUser -= 8;
	auto IsLicenseTypeLocalOnly = pattenMatch(base, rdata, LocalOnly, sizeof(LocalOnly) - 1);
	auto bRemoteConnAllowed = pattenMatch(base, rdata, AllowRemote, sizeof(AllowRemote));

	auto pImportDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
	auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base + pImportDirectory->VirtualAddress);
	auto pImportImage = findImportImage(pImportDescriptor, base, "api-ms-win-crt-string-l1-1-0.dll");
	if (!pImportImage) pImportImage = findImportImage(pImportDescriptor, base, "msvcrt.dll");
	if (!pImportImage) return;
	auto memset_addr = findImportFunction(pImportImage, base, "memset");

	size_t VerifyVersion_addr = -1;
	pImportImage = findImportImage(pImportDescriptor, base, "api-ms-win-core-kernel32-legacy-l1-1-1.dll");
	if (!pImportImage) pImportImage = findImportImage(pImportDescriptor, base, "KERNEL32.dll");
	if (pImportImage) VerifyVersion_addr = findImportFunction(pImportImage, base, "VerifyVersionInfoW");

	size_t CDefPolicy_Query_addr = 0, GetInstanceOfTSLicense_addr = 0, IsSingleSessionPerUserEnabled_addr = 0,
		IsSingleSessionPerUser_addr = 0, IsLicenseTypeLocalOnly_addr = 0, bRemoteConnAllowed_xref;
	size_t CSLQuery_Initialize_addr = 0, CSLQuery_Initialize_len = 0x11000;

	auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	auto FunctionTable = (PRUNTIME_FUNCTION)(base + pExceptionDirectory->VirtualAddress);
	auto FunctionTableSize = pExceptionDirectory->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
	if (!FunctionTableSize) return;

	for (DWORD i = 0; i < FunctionTableSize; i++) {
		if (!CDefPolicy_Query_addr && searchXrefARM64(base, FunctionTable + i, CDefPolicy_Query))
			CDefPolicy_Query_addr = backtraceARM64(base, FunctionTable + i, FunctionTable, FunctionTableSize)->BeginAddress;
		else if (!GetInstanceOfTSLicense_addr && searchXrefARM64(base, FunctionTable + i, GetInstanceOfTSLicense))
			GetInstanceOfTSLicense_addr = backtraceARM64(base, FunctionTable + i, FunctionTable, FunctionTableSize)->BeginAddress;
		else if (!IsSingleSessionPerUserEnabled_addr && searchXrefARM64(base, FunctionTable + i, IsSingleSessionPerUserEnabled))
			IsSingleSessionPerUserEnabled_addr = backtraceARM64(base, FunctionTable + i, FunctionTable, FunctionTableSize)->BeginAddress;
		else if (!IsSingleSessionPerUser_addr && searchXrefARM64(base, FunctionTable + i, IsSingleSessionPerUser))
			IsSingleSessionPerUser_addr = backtraceARM64(base, FunctionTable + i, FunctionTable, FunctionTableSize)->BeginAddress;
		else if (!IsLicenseTypeLocalOnly_addr && searchXrefARM64(base, FunctionTable + i, IsLicenseTypeLocalOnly))
			IsLicenseTypeLocalOnly_addr = backtraceARM64(base, FunctionTable + i, FunctionTable, FunctionTableSize)->BeginAddress;
		else if (!CSLQuery_Initialize_addr && (bRemoteConnAllowed_xref = searchXrefARM64(base, FunctionTable + i, bRemoteConnAllowed))) {
			auto CSLQuery_Initialize_func = backtraceARM64(base, FunctionTable + i, FunctionTable, FunctionTableSize);
			CSLQuery_Initialize_addr = CSLQuery_Initialize_func->BeginAddress;
			if (CSLQuery_Initialize_func->Flag == PdataRefToFullXdata) {
				auto xdata = (IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA*)(base + (CSLQuery_Initialize_func->UnwindData & ~3));
				CSLQuery_Initialize_len = (xdata->HeaderData & 0x3FFFF) << 2;
			}
			else CSLQuery_Initialize_len = CSLQuery_Initialize_func->UnwindData & 0x1FFC;
		}
		if (CDefPolicy_Query_addr && GetInstanceOfTSLicense_addr && IsSingleSessionPerUserEnabled_addr &&
			IsSingleSessionPerUser_addr && IsLicenseTypeLocalOnly_addr && CSLQuery_Initialize_addr) break;
	}

	if (memset_addr)
	{
		bool patched = false;
		if (IsSingleSessionPerUserEnabled_addr && SingleUserPatchARM64(IsSingleSessionPerUserEnabled_addr, base, memset_addr, VerifyVersion_addr))
			patched = true;
		if (IsSingleSessionPerUser_addr && SingleUserPatchARM64(IsSingleSessionPerUser_addr, base, memset_addr, VerifyVersion_addr))
			patched = true;
		if (!patched)
			OutputDebugStringA("SingleUserPatch not found\n");
	}

	if (CDefPolicy_Query_addr)
		DefPolicyPatchARM64(CDefPolicy_Query_addr, base);
	else OutputDebugStringA("CDefPolicy_Query not found\n");

	if (!CSLQuery_Initialize_addr) {
		OutputDebugStringA("CSLQuery_Initialize not found\n");
		return;
	}

	size_t IP = base + CSLQuery_Initialize_addr;
	size_t length = CSLQuery_Initialize_len;

	if (GetInstanceOfTSLicense_addr)
	{
		if (IsLicenseTypeLocalOnly_addr)
			LocalOnlyPatchARM64(GetInstanceOfTSLicense_addr, base, IsLicenseTypeLocalOnly_addr);
		else OutputDebugStringA("IsLicenseTypeLocalOnly not found\n");
	}
	else OutputDebugStringA("GetInstanceOfTSLicense not found\n");

	auto bFUSEnabled = pattenMatch(base, rdata, AllowMultipleSessions, sizeof(AllowMultipleSessions));
	auto bAppServerAllowed = pattenMatch(base, rdata, AllowAppServer, sizeof(AllowAppServer));
	auto bMultimonAllowed = pattenMatch(base, rdata, AllowMultimon, sizeof(AllowMultimon));

	auto found = false;
	size_t bInitialized_addr = 0;

	while (length >= 4) {
		uint32_t ic = *((uint32_t*)IP);
		if (is_arm64_adrp(ic)) {
			size_t target = ((int64_t)(ic & 0xFFFFE0)) << 40 >> 31 | (ic & 0x60000000) >> 17;
			uint32_t rd = get_rt_rd(ic);
			target += (IP - base) & ~(size_t)0xFFF;
			IP += 4;
			ic = *((uint32_t*)IP);
			if (!found && is_arm64_ldr32_unsigned(ic) && 31 == get_rn(ic)) {
				uint32_t rt = get_rt_rd(ic);
				IP += 4;
				ic = *((uint32_t*)IP);
				if (is_arm64_str32_unsigned(ic) && rd == get_rn(ic) && rt == get_rt_rd(ic)) {
					found = true;
					target += get_imm12(ic) >> 8;
					*(DWORD*)(target + base) = 1;
				}
			}
			else if (is_arm64_add64(ic) && !get_shift(ic) && rd == get_rn(ic)) {
				target += get_imm12(ic) >> 10;
				if (target == bRemoteConnAllowed || target == bFUSEnabled || target == bAppServerAllowed || target == bMultimonAllowed) found = false;
			}
			else if(is_arm64_movz32(ic) && !get_hw(ic) && get_imm16(ic) == 1) {
				uint32_t rt = get_rt_rd(ic);
				IP += 4;
				ic = *((uint32_t*)IP);
				if (is_arm64_str32_unsigned(ic) && rd == get_rn(ic) && rt == get_rt_rd(ic)) {
					target += get_imm12(ic) >> 8;
					bInitialized_addr = target + base;
					break;
				}
			}
		}
		IP += 4;
		length -= 4;
	}

	if (bInitialized_addr) *(DWORD*)bInitialized_addr = 1;
	else OutputDebugStringA("bInitialized not found\n");
}
