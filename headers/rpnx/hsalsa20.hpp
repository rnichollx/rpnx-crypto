//
// Created by rnicholl on 12/16/20.
//

#ifndef RPNX_DJB_CRYPTO_HSALSA20_HPP
#define RPNX_DJB_CRYPTO_HSALSA20_HPP
#include <utility>
#include <cinttypes>
#include <tuple>
#include <cstddef>
#include "rpnx/crypto_common.hpp"

#include <stdint.h>
#include <stdlib.h>

namespace rpnx::djb_crypto
{
    template <std::size_t Rounds>
    void core_hsalsa(std::byte *out,
                         const std::byte *in,
                         const std::byte *k,
                         const std::byte *c)
    {
        static_assert(Rounds % 2 == 0);

        std::uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8,
                x9, x10, x11, x12, x13, x14,  x15;

        int      i;

        if (c == nullptr) {
            x0 = std::uint32_t(0x61707865);
            x5 = std::uint32_t(0x3320646e);
            x10 = std::uint32_t(0x79622d32);
            x15 = std::uint32_t(0x6b206574);
        } else {
            x0 = load_little_endian32(c + 0);
            x5 = load_little_endian32(c + 4);
            x10 = load_little_endian32(c + 8);
            x15 = load_little_endian32(c + 12);
        }
        x1 = load_little_endian32(k + 0);
        x2 = load_little_endian32(k + 4);
        x3 = load_little_endian32(k + 8);
        x4 = load_little_endian32(k + 12);
        x11 = load_little_endian32(k + 16);
        x12 = load_little_endian32(k + 20);
        x13 = load_little_endian32(k + 24);
        x14 = load_little_endian32(k + 28);
        x6 = load_little_endian32(in + 0);
        x7 = load_little_endian32(in + 4);
        x8 = load_little_endian32(in + 8);
        x9 = load_little_endian32(in + 12);

        for (i = Rounds; i > 0; i -= 2) {
            x4 ^= rotate_up_32(x0 + x12, 7);
            x8 ^= rotate_up_32(x4 + x0, 9);
            x12 ^= rotate_up_32(x8 + x4, 13);
            x0 ^= rotate_up_32(x12 + x8, 18);
            x9 ^= rotate_up_32(x5 + x1, 7);
            x13 ^= rotate_up_32(x9 + x5, 9);
            x1 ^= rotate_up_32(x13 + x9, 13);
            x5 ^= rotate_up_32(x1 + x13, 18);
            x14 ^= rotate_up_32(x10 + x6, 7);
            x2 ^= rotate_up_32(x14 + x10, 9);
            x6 ^= rotate_up_32(x2 + x14, 13);
            x10 ^= rotate_up_32(x6 + x2, 18);
            x3 ^= rotate_up_32(x15 + x11, 7);
            x7 ^= rotate_up_32(x3 + x15, 9);
            x11 ^= rotate_up_32(x7 + x3, 13);
            x15 ^= rotate_up_32(x11 + x7, 18);
            x1 ^= rotate_up_32(x0 + x3, 7);
            x2 ^= rotate_up_32(x1 + x0, 9);
            x3 ^= rotate_up_32(x2 + x1, 13);
            x0 ^= rotate_up_32(x3 + x2, 18);
            x6 ^= rotate_up_32(x5 + x4, 7);
            x7 ^= rotate_up_32(x6 + x5, 9);
            x4 ^= rotate_up_32(x7 + x6, 13);
            x5 ^= rotate_up_32(x4 + x7, 18);
            x11 ^= rotate_up_32(x10 + x9, 7);
            x8 ^= rotate_up_32(x11 + x10, 9);
            x9 ^= rotate_up_32(x8 + x11, 13);
            x10 ^= rotate_up_32(x9 + x8, 18);
            x12 ^= rotate_up_32(x15 + x14, 7);
            x13 ^= rotate_up_32(x12 + x15, 9);
            x14 ^= rotate_up_32(x13 + x12, 13);
            x15 ^= rotate_up_32(x14 + x13, 18);
        }

        store_little_endian32(out + 0, x0);
        store_little_endian32(out + 4, x5);
        store_little_endian32(out + 8, x10);
        store_little_endian32(out + 12, x15);
        store_little_endian32(out + 16, x6);
        store_little_endian32(out + 20, x7);
        store_little_endian32(out + 24, x8);
        store_little_endian32(out + 28, x9);
    }
}
#endif
