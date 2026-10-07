#pragma once
#include <stdint.h>

static inline bool is_arm64_b(uint32_t ic) {
    return (ic >> 26) == 0x5;
}

static inline bool is_arm64_bl(uint32_t ic) {
    return (ic >> 26) == 0x25;
}

static inline bool is_arm64_tbnz(uint32_t ic) {
    return (ic & 0x7E000000) == 0x36000000;
}

static inline bool is_arm64_cbz(uint32_t ic) {
    return (ic & 0x7C000000) == 0x34000000;
}

static inline bool is_arm64_ldr32_unsigned(uint32_t ic) {
    return (ic & 0xFFC00000) == 0xB9400000;
}

static inline bool is_arm64_ldr64_unsigned(uint32_t ic) {
    return (ic & 0xFFC00000) == 0xF9400000;
}

static inline bool is_arm64_ldar64(uint32_t ic) {
    return (ic & 0xFFFFFC00) == 0xC8DFFC00;
}

static inline bool is_arm64_ldp32(uint32_t ic) {
    return (ic & 0xFFC00000) == 0x28C00000;
}

static inline bool is_arm64_ldp32_signed(uint32_t ic) {
    return (ic & 0xFFC00000) == 0x29400000;
}

static inline bool is_arm64_str32_unsigned(uint32_t ic) {
    return (ic & 0xFFC00000) == 0xB9000000;
}

static inline bool is_arm64_movz32(uint32_t ic) {
    return (ic & 0xFF800000) == 0x52800000;
}

static inline bool is_arm64_add64(uint32_t ic) {
    return (ic & 0xFF000000) == 0x91000000;
}

static inline bool is_arm64_cmp32(uint32_t ic) {
    return (ic & 0xFF20001F) == 0x6B00001F;
}

static inline bool is_arm64_b_cond(uint32_t ic) {
    return (ic & 0xFF000010) == 0x54000000;
}

static inline bool is_arm64_ret(uint32_t ic) {
    return (ic & 0xFFFFFC1F) == 0xD65F0000;
}

static inline bool is_arm64_blr(uint32_t ic) {
    return (ic & 0xFFFFFC1F) == 0xD63F0000;
}

static inline bool is_arm64_br(uint32_t ic) {
    return (ic & 0xFFFFFC1F) == 0xD61F0000;
}

static inline bool is_arm64_adrp(uint32_t ic) {
    return (ic & 0x9F000000) == 0x90000000;
}

static inline uint32_t get_shift(uint32_t ic) {
    return ic & 0xC00000;
}

static inline uint32_t get_hw(uint32_t ic) {
    return ic & 0x600000;
}

static inline int32_t get_imm26(uint32_t ic) {
    return ((int32_t)ic & 0x3FFFFFF) << 6 >> 4;
}

static inline int32_t get_imm19(uint32_t ic) {
    return ((int32_t)ic & 0xFFFFE0) << 8 >> 11;
}

static inline uint32_t get_imm16(uint32_t ic) {
    return (ic & 0x1FFFE0) >> 5;
}

// imm12 and imm7 does not shift
static inline uint32_t get_imm12(uint32_t ic) {
    return ic & 0x3FFC00;
}

static inline uint32_t get_imm7(uint32_t ic) {
    return ic & 0x3F8000;
}

static inline int32_t get_imm14(uint32_t ic) {
    return ((int32_t)ic & 0x7FFE0) << 13 >> 16;
}

static inline uint32_t get_imm6(uint32_t ic) {
    return (ic & 0xFC00) >> 10;
}

static inline uint32_t get_rm(uint32_t ic) {
    return (ic & 0x1F0000) >> 16;
}

static inline uint32_t get_rt2(uint32_t ic) {
    return (ic & 0x7C00) >> 10;
}

static inline uint32_t get_rn(uint32_t ic) {
    return (ic & 0x3E0) >> 5;
}

static inline uint32_t get_rt_rd(uint32_t ic) {
    return ic & 0x1F;
}