#ifdef ENABLE_NEON
#include "gf256_neon.h"
#include <arm_neon.h>

namespace gf256_neon {

GF256_NEON_ALIGNED GF256_M128 TABLE_LO_Y[256];
GF256_NEON_ALIGNED GF256_M128 TABLE_HI_Y[256];

void gf256_mul_mem_init(uint8_t* lo, uint8_t* hi, int y)
{
    TABLE_LO_Y[y] = vld1q_u8(lo);
    TABLE_HI_Y[y] = vld1q_u8(hi);
}

void gf256_add_mem(GF256_M128* GF256_RESTRICT& x16,
                   const GF256_M128* GF256_RESTRICT& y16, int& bytes)
{
    while (bytes >= 64) {
        GF256_M128 x0 = vld1q_u8((uint8_t*)x16);
        GF256_M128 x1 = vld1q_u8((uint8_t*)(x16 + 1));
        GF256_M128 x2 = vld1q_u8((uint8_t*)(x16 + 2));
        GF256_M128 x3 = vld1q_u8((uint8_t*)(x16 + 3));
        GF256_M128 y0 = vld1q_u8((uint8_t*)y16);
        GF256_M128 y1 = vld1q_u8((uint8_t*)(y16 + 1));
        GF256_M128 y2 = vld1q_u8((uint8_t*)(y16 + 2));
        GF256_M128 y3 = vld1q_u8((uint8_t*)(y16 + 3));

        vst1q_u8((uint8_t*)x16, veorq_u8(x0, y0));
        vst1q_u8((uint8_t*)(x16 + 1), veorq_u8(x1, y1));
        vst1q_u8((uint8_t*)(x16 + 2), veorq_u8(x2, y2));
        vst1q_u8((uint8_t*)(x16 + 3), veorq_u8(x3, y3));

        bytes -= 64, x16 += 4, y16 += 4;
    }

    // Handle multiples of 16 bytes
    while (bytes >= 16) {
        GF256_M128 x0 = vld1q_u8((uint8_t*)x16);
        GF256_M128 y0 = vld1q_u8((uint8_t*)y16);

        vst1q_u8((uint8_t*)x16, veorq_u8(x0, y0));

        bytes -= 16, ++x16, ++y16;
    }
}

void gf256_add2_mem(const GF256_M128* GF256_RESTRICT& x16, const GF256_M128* GF256_RESTRICT& y16, GF256_M128* GF256_RESTRICT& z16, int& bytes)
{
    // Handle multiples of 16 bytes
    while (bytes >= 16) {
        // z[i] = z[i] xor x[i] xor y[i]
        vst1q_u8((uint8_t*)z16,
                 veorq_u8(
                     vld1q_u8((uint8_t*)z16),
                     veorq_u8(
                         vld1q_u8((uint8_t*)x16),
                         vld1q_u8((uint8_t*)y16))));

        bytes -= 16, ++x16, ++y16, ++z16;
    }
}

void gf256_addset_mem(const GF256_M128* GF256_RESTRICT& x16, const GF256_M128* GF256_RESTRICT& y16, GF256_M128* GF256_RESTRICT& z16, int& bytes)
{
    while (bytes >= 64) {
        GF256_M128 x0 = vld1q_u8((uint8_t*)x16);
        GF256_M128 x1 = vld1q_u8((uint8_t*)(x16 + 1));
        GF256_M128 x2 = vld1q_u8((uint8_t*)(x16 + 2));
        GF256_M128 x3 = vld1q_u8((uint8_t*)(x16 + 3));
        GF256_M128 y0 = vld1q_u8((uint8_t*)(y16));
        GF256_M128 y1 = vld1q_u8((uint8_t*)(y16 + 1));
        GF256_M128 y2 = vld1q_u8((uint8_t*)(y16 + 2));
        GF256_M128 y3 = vld1q_u8((uint8_t*)(y16 + 3));

        vst1q_u8((uint8_t*)z16, veorq_u8(x0, y0));
        vst1q_u8((uint8_t*)(z16 + 1), veorq_u8(x1, y1));
        vst1q_u8((uint8_t*)(z16 + 2), veorq_u8(x2, y2));
        vst1q_u8((uint8_t*)(z16 + 3), veorq_u8(x3, y3));

        bytes -= 64, x16 += 4, y16 += 4, z16 += 4;
    }

    // Handle multiples of 16 bytes
    while (bytes >= 16) {
        // z[i] = x[i] xor y[i]
        vst1q_u8((uint8_t*)z16,
                 veorq_u8(
                     vld1q_u8((uint8_t*)x16),
                     vld1q_u8((uint8_t*)y16)));

        bytes -= 16, ++x16, ++y16, ++z16;
    }
}

void gf256_mul_mem(const GF256_M128* GF256_RESTRICT& x16, GF256_M128* GF256_RESTRICT& z16, uint8_t y, int& bytes)
{
    // Partial product tables; see above
    const GF256_M128 table_lo_y = vld1q_u8((uint8_t*)(TABLE_LO_Y + y));
    const GF256_M128 table_hi_y = vld1q_u8((uint8_t*)(TABLE_HI_Y + y));

    // clr_mask = 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
    const GF256_M128 clr_mask = vdupq_n_u8(0x0f);

    // Handle multiples of 16 bytes
    do {
        // See above comments for details
        GF256_M128 x0 = vld1q_u8((uint8_t*)x16);
        GF256_M128 l0 = vandq_u8(x0, clr_mask);
        x0 = vshrq_n_u8(x0, 4);
        GF256_M128 h0 = vandq_u8(x0, clr_mask);
        l0 = vqtbl1q_u8(table_lo_y, l0);
        h0 = vqtbl1q_u8(table_hi_y, h0);
        vst1q_u8((uint8_t*)z16, veorq_u8(l0, h0));

        bytes -= 16, ++x16, ++z16;
    } while (bytes >= 16);
}

void gf256_muladd_mem(const GF256_M128* GF256_RESTRICT& x16, GF256_M128* GF256_RESTRICT& z16, uint8_t y, int& bytes)
{
    // Partial product tables; see above
    const GF256_M128 table_lo_y = vld1q_u8((uint8_t*)(TABLE_LO_Y + y));
    const GF256_M128 table_hi_y = vld1q_u8((uint8_t*)(TABLE_HI_Y + y));

    // clr_mask = 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
    const GF256_M128 clr_mask = vdupq_n_u8(0x0f);

    // Handle multiples of 16 bytes
    do {
        // See above comments for details
        GF256_M128 x0 = vld1q_u8((uint8_t*)x16);
        GF256_M128 l0 = vandq_u8(x0, clr_mask);

        // x0 = vshrq_n_u8(x0, 4);
        x0 = (GF256_M128)vshrq_n_u64((uint64x2_t)x0, 4);
        GF256_M128 h0 = vandq_u8(x0, clr_mask);
        l0 = vqtbl1q_u8(table_lo_y, l0);
        h0 = vqtbl1q_u8(table_hi_y, h0);
        const GF256_M128 p0 = veorq_u8(l0, h0);
        const GF256_M128 z0 = vld1q_u8((uint8_t*)z16);
        vst1q_u8((uint8_t*)z16, veorq_u8(p0, z0));
        bytes -= 16, ++x16, ++z16;
    } while (bytes >= 16);
}

} // namespace gf256_neon

#endif