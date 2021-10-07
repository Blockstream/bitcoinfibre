#ifndef GF256_AVX2_H
#define GF256_AVX2_H

#include "gf256.h"

#ifdef _MSC_VER
#define GF256_AVX2_ALIGNED __declspec(align(32))
#else // _MSC_VER
#define GF256_AVX2_ALIGNED __attribute__((aligned(32)))
#endif // _MSC_VER

namespace gf256_avx2 {

void gf256_mul_mem_init(uint8_t* lo, uint8_t* hi, int y);
void gf256_add_mem(GF256_M128* GF256_RESTRICT& x16,
                   const GF256_M128* GF256_RESTRICT& y16, int& bytes);
void gf256_add2_mem(const GF256_M128* GF256_RESTRICT& x16, const GF256_M128* GF256_RESTRICT& y16, GF256_M128* GF256_RESTRICT& z16, int& bytes);
void gf256_addset_mem(const GF256_M128* GF256_RESTRICT& x16, const GF256_M128* GF256_RESTRICT& y16, GF256_M128* GF256_RESTRICT& z16, int& bytes);
void gf256_mul_mem(const GF256_M128* GF256_RESTRICT& x16, GF256_M128* GF256_RESTRICT& z16, uint8_t y, int& bytes);
void gf256_muladd_mem(const GF256_M128* GF256_RESTRICT& x16, GF256_M128* GF256_RESTRICT& z16, uint8_t y, int& bytes);
} // namespace gf256_avx2

#endif