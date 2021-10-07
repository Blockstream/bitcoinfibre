#ifdef ENABLE_AVX2
#include "gf256_avx2.h"
#include <immintrin.h>

#define GF256_M256 __m256i // Compiler-specific 256-bit SIMD register keyword

namespace gf256_avx2 {

GF256_AVX2_ALIGNED GF256_M256 TABLE_LO_Y[256];
GF256_AVX2_ALIGNED GF256_M256 TABLE_HI_Y[256];

void gf256_mul_mem_init(uint8_t* lo, uint8_t* hi, int y)
{
    const GF256_M128 table_lo = _mm_loadu_si128((GF256_M128*)lo);
    const GF256_M128 table_hi = _mm_loadu_si128((GF256_M128*)hi);
    const GF256_M256 table_lo2 = _mm256_broadcastsi128_si256(table_lo);
    const GF256_M256 table_hi2 = _mm256_broadcastsi128_si256(table_hi);
    _mm256_storeu_si256(TABLE_LO_Y + y, table_lo2);
    _mm256_storeu_si256(TABLE_HI_Y + y, table_hi2);
}

void gf256_add_mem(GF256_M128* GF256_RESTRICT& x16,
                   const GF256_M128* GF256_RESTRICT& y16, int& bytes)
{
    GF256_M256* GF256_RESTRICT x32 = reinterpret_cast<GF256_M256*>(x16);
    const GF256_M256* GF256_RESTRICT y32 = reinterpret_cast<const GF256_M256*>(y16);

    while (bytes >= 128) {
        GF256_M256 x0 = _mm256_loadu_si256(x32);
        GF256_M256 y0 = _mm256_loadu_si256(y32);
        x0 = _mm256_xor_si256(x0, y0);
        GF256_M256 x1 = _mm256_loadu_si256(x32 + 1);
        GF256_M256 y1 = _mm256_loadu_si256(y32 + 1);
        x1 = _mm256_xor_si256(x1, y1);
        GF256_M256 x2 = _mm256_loadu_si256(x32 + 2);
        GF256_M256 y2 = _mm256_loadu_si256(y32 + 2);
        x2 = _mm256_xor_si256(x2, y2);
        GF256_M256 x3 = _mm256_loadu_si256(x32 + 3);
        GF256_M256 y3 = _mm256_loadu_si256(y32 + 3);
        x3 = _mm256_xor_si256(x3, y3);

        _mm256_storeu_si256(x32, x0);
        _mm256_storeu_si256(x32 + 1, x1);
        _mm256_storeu_si256(x32 + 2, x2);
        _mm256_storeu_si256(x32 + 3, x3);

        bytes -= 128, x32 += 4, y32 += 4;
    }

    // Handle multiples of 32 bytes
    while (bytes >= 32) {
        // x[i] = x[i] xor y[i]
        _mm256_storeu_si256(x32,
                            _mm256_xor_si256(
                                _mm256_loadu_si256(x32),
                                _mm256_loadu_si256(y32)));

        bytes -= 32, ++x32, ++y32;
    }

    x16 = reinterpret_cast<GF256_M128*>(x32);
    y16 = reinterpret_cast<const GF256_M128*>(y32);
}

void gf256_add2_mem(const GF256_M128* GF256_RESTRICT& x16, const GF256_M128* GF256_RESTRICT& y16, GF256_M128* GF256_RESTRICT& z16, int& bytes)
{
    GF256_M256* GF256_RESTRICT z32 = reinterpret_cast<GF256_M256*>(z16);
    const GF256_M256* GF256_RESTRICT x32 = reinterpret_cast<const GF256_M256*>(x16);
    const GF256_M256* GF256_RESTRICT y32 = reinterpret_cast<const GF256_M256*>(y16);

    const unsigned count = bytes / 32;
    for (unsigned i = 0; i < count; ++i) {
        _mm256_storeu_si256(z32 + i,
                            _mm256_xor_si256(
                                _mm256_loadu_si256(z32 + i),
                                _mm256_xor_si256(
                                    _mm256_loadu_si256(x32 + i),
                                    _mm256_loadu_si256(y32 + i))));
    }

    bytes -= count * 32;
    z16 = reinterpret_cast<GF256_M128*>(z32 + count);
    x16 = reinterpret_cast<const GF256_M128*>(x32 + count);
    y16 = reinterpret_cast<const GF256_M128*>(y32 + count);
}

void gf256_addset_mem(const GF256_M128* GF256_RESTRICT& x16, const GF256_M128* GF256_RESTRICT& y16, GF256_M128* GF256_RESTRICT& z16, int& bytes)
{
    GF256_M256* GF256_RESTRICT z32 = reinterpret_cast<GF256_M256*>(z16);
    const GF256_M256* GF256_RESTRICT x32 = reinterpret_cast<const GF256_M256*>(x16);
    const GF256_M256* GF256_RESTRICT y32 = reinterpret_cast<const GF256_M256*>(y16);

    const unsigned count = bytes / 32;
    for (unsigned i = 0; i < count; ++i) {
        _mm256_storeu_si256(z32 + i,
                            _mm256_xor_si256(
                                _mm256_loadu_si256(x32 + i),
                                _mm256_loadu_si256(y32 + i)));
    }

    bytes -= count * 32;
    z16 = reinterpret_cast<GF256_M128*>(z32 + count);
    x16 = reinterpret_cast<const GF256_M128*>(x32 + count);
    y16 = reinterpret_cast<const GF256_M128*>(y32 + count);
}

void gf256_mul_mem(const GF256_M128* GF256_RESTRICT& x16, GF256_M128* GF256_RESTRICT& z16, uint8_t y, int& bytes)
{
    // Partial product tables; see above
    const GF256_M256 table_lo_y = _mm256_loadu_si256(TABLE_LO_Y + y);
    const GF256_M256 table_hi_y = _mm256_loadu_si256(TABLE_HI_Y + y);

    // clr_mask = 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
    const GF256_M256 clr_mask = _mm256_set1_epi8(0x0f);

    GF256_M256* GF256_RESTRICT z32 = reinterpret_cast<GF256_M256*>(z16);
    const GF256_M256* GF256_RESTRICT x32 = reinterpret_cast<const GF256_M256*>(x16);

    // Handle multiples of 32 bytes
    do {
        // See above comments for details
        GF256_M256 x0 = _mm256_loadu_si256(x32);
        GF256_M256 l0 = _mm256_and_si256(x0, clr_mask);
        x0 = _mm256_srli_epi64(x0, 4);
        GF256_M256 h0 = _mm256_and_si256(x0, clr_mask);
        l0 = _mm256_shuffle_epi8(table_lo_y, l0);
        h0 = _mm256_shuffle_epi8(table_hi_y, h0);
        _mm256_storeu_si256(z32, _mm256_xor_si256(l0, h0));

        bytes -= 32, ++x32, ++z32;
    } while (bytes >= 32);

    z16 = reinterpret_cast<GF256_M128*>(z32);
    x16 = reinterpret_cast<const GF256_M128*>(x32);
}

void gf256_muladd_mem(const GF256_M128* GF256_RESTRICT& x16, GF256_M128* GF256_RESTRICT& z16, uint8_t y, int& bytes)
{
    // Partial product tables; see above
    const GF256_M256 table_lo_y = _mm256_loadu_si256(TABLE_LO_Y + y);
    const GF256_M256 table_hi_y = _mm256_loadu_si256(TABLE_HI_Y + y);

    // clr_mask = 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
    const GF256_M256 clr_mask = _mm256_set1_epi8(0x0f);

    GF256_M256* GF256_RESTRICT z32 = reinterpret_cast<GF256_M256*>(z16);
    const GF256_M256* GF256_RESTRICT x32 = reinterpret_cast<const GF256_M256*>(x16);

    // On my Reed Solomon codec, the encoder unit test runs in 640 usec without and 550 usec with the optimization (86% of the original time)
    const unsigned count = bytes / 64;
    for (unsigned i = 0; i < count; ++i) {
        // See above comments for details
        GF256_M256 x0 = _mm256_loadu_si256(x32 + i * 2);
        GF256_M256 l0 = _mm256_and_si256(x0, clr_mask);
        x0 = _mm256_srli_epi64(x0, 4);
        const GF256_M256 z0 = _mm256_loadu_si256(z32 + i * 2);
        GF256_M256 h0 = _mm256_and_si256(x0, clr_mask);
        l0 = _mm256_shuffle_epi8(table_lo_y, l0);
        h0 = _mm256_shuffle_epi8(table_hi_y, h0);
        const GF256_M256 p0 = _mm256_xor_si256(l0, h0);
        _mm256_storeu_si256(z32 + i * 2, _mm256_xor_si256(p0, z0));

        GF256_M256 x1 = _mm256_loadu_si256(x32 + i * 2 + 1);
        GF256_M256 l1 = _mm256_and_si256(x1, clr_mask);
        x1 = _mm256_srli_epi64(x1, 4);
        const GF256_M256 z1 = _mm256_loadu_si256(z32 + i * 2 + 1);
        GF256_M256 h1 = _mm256_and_si256(x1, clr_mask);
        l1 = _mm256_shuffle_epi8(table_lo_y, l1);
        h1 = _mm256_shuffle_epi8(table_hi_y, h1);
        const GF256_M256 p1 = _mm256_xor_si256(l1, h1);
        _mm256_storeu_si256(z32 + i * 2 + 1, _mm256_xor_si256(p1, z1));
    }
    bytes -= count * 64;
    z32 += count * 2;
    x32 += count * 2;

    if (bytes >= 32) {
        GF256_M256 x0 = _mm256_loadu_si256(x32);
        GF256_M256 l0 = _mm256_and_si256(x0, clr_mask);
        x0 = _mm256_srli_epi64(x0, 4);
        GF256_M256 h0 = _mm256_and_si256(x0, clr_mask);
        l0 = _mm256_shuffle_epi8(table_lo_y, l0);
        h0 = _mm256_shuffle_epi8(table_hi_y, h0);
        const GF256_M256 p0 = _mm256_xor_si256(l0, h0);
        const GF256_M256 z0 = _mm256_loadu_si256(z32);
        _mm256_storeu_si256(z32, _mm256_xor_si256(p0, z0));

        bytes -= 32;
        z32++;
        x32++;
    }

    z16 = reinterpret_cast<GF256_M128*>(z32);
    x16 = reinterpret_cast<const GF256_M128*>(x32);
}

} // namespace gf256_avx2
#endif