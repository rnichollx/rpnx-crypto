//
// Created by rnicholl on 12/16/20.
//

#ifndef RPNX_DJB_CRYPTO_SALSA20_HPP
#define RPNX_DJB_CRYPTO_SALSA20_HPP

#include <cstddef>
#include <cinttypes>
#include "rpnx/crypto_common.hpp"
#include <sodium.h>
#include <array>

namespace rpnx::djb_crypto
{
    template <std::size_t Rounds>
    void core_salsa(std::byte *out,
                     const std::byte *in,
                     const std::byte *k,
                     const std::byte *c)
    {
            uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14,
                    x15;
            uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14,
                    j15;
            int i;

            j0  = x0  = 0x61707865;
            j5  = x5  = 0x3320646e;
            j10 = x10 = 0x79622d32;
            j15 = x15 = 0x6b206574;
            if (c != NULL) {
                j0  = x0  = load_little_endian32(c + 0);
                j5  = x5  = load_little_endian32(c + 4);
                j10 = x10 = load_little_endian32(c + 8);
                j15 = x15 = load_little_endian32(c + 12);
            }
            j1  = x1  = load_little_endian32(k + 0);
            j2  = x2  = load_little_endian32(k + 4);
            j3  = x3  = load_little_endian32(k + 8);
            j4  = x4  = load_little_endian32(k + 12);
            j11 = x11 = load_little_endian32(k + 16);
            j12 = x12 = load_little_endian32(k + 20);
            j13 = x13 = load_little_endian32(k + 24);
            j14 = x14 = load_little_endian32(k + 28);

            j6  = x6  = load_little_endian32(in + 0);
            j7  = x7  = load_little_endian32(in + 4);
            j8  = x8  = load_little_endian32(in + 8);
            j9  = x9  = load_little_endian32(in + 12);

            for (i = 0; i < Rounds; i += 2) {
                x4  ^= rotate_up_32(x0  + x12, 7);
                x8  ^= rotate_up_32(x4  + x0, 9);
                x12 ^= rotate_up_32(x8  + x4, 13);
                x0  ^= rotate_up_32(x12 + x8, 18);
                x9  ^= rotate_up_32(x5  + x1, 7);
                x13 ^= rotate_up_32(x9  + x5, 9);
                x1  ^= rotate_up_32(x13 + x9, 13);
                x5  ^= rotate_up_32(x1  + x13, 18);
                x14 ^= rotate_up_32(x10 + x6, 7);
                x2  ^= rotate_up_32(x14 + x10, 9);
                x6  ^= rotate_up_32(x2  + x14, 13);
                x10 ^= rotate_up_32(x6  + x2, 18);
                x3  ^= rotate_up_32(x15 + x11, 7);
                x7  ^= rotate_up_32(x3  + x15, 9);
                x11 ^= rotate_up_32(x7  + x3, 13);
                x15 ^= rotate_up_32(x11 + x7, 18);
                x1  ^= rotate_up_32(x0  + x3, 7);
                x2  ^= rotate_up_32(x1  + x0, 9);
                x3  ^= rotate_up_32(x2  + x1, 13);
                x0  ^= rotate_up_32(x3  + x2, 18);
                x6  ^= rotate_up_32(x5  + x4, 7);
                x7  ^= rotate_up_32(x6  + x5, 9);
                x4  ^= rotate_up_32(x7  + x6, 13);
                x5  ^= rotate_up_32(x4  + x7, 18);
                x11 ^= rotate_up_32(x10 + x9, 7);
                x8  ^= rotate_up_32(x11 + x10, 9);
                x9  ^= rotate_up_32(x8  + x11, 13);
                x10 ^= rotate_up_32(x9  + x8, 18);
                x12 ^= rotate_up_32(x15 + x14, 7);
                x13 ^= rotate_up_32(x12 + x15, 9);
                x14 ^= rotate_up_32(x13 + x12, 13);
                x15 ^= rotate_up_32(x14 + x13, 18);
            }
            store_little_endian32(out + 0,  x0  + j0);
            store_little_endian32(out + 4,  x1  + j1);
            store_little_endian32(out + 8,  x2  + j2);
            store_little_endian32(out + 12, x3  + j3);
            store_little_endian32(out + 16, x4  + j4);
            store_little_endian32(out + 20, x5  + j5);
            store_little_endian32(out + 24, x6  + j6);
            store_little_endian32(out + 28, x7  + j7);
            store_little_endian32(out + 32, x8  + j8);
            store_little_endian32(out + 36, x9  + j9);
            store_little_endian32(out + 40, x10 + j10);
            store_little_endian32(out + 44, x11 + j11);
            store_little_endian32(out + 48, x12 + j12);
            store_little_endian32(out + 52, x13 + j13);
            store_little_endian32(out + 56, x14 + j14);
            store_little_endian32(out + 60, x15 + j15);
    }

    void stream_salsa20_xor_ic(std::byte *c, const std::byte *m,
                          std::uint64_t mlen,
                          const std::byte *n, uint64_t ic,
                          const std::byte *k)
                          {
        std::array<std::byte, 16> in{};
        std::array<std::byte, 64> block{};
        std::array<std::byte, 32> kcopy;
        std::uint32_t i;
        std::uint32_t u;


        if (!mlen) {
            return;
        }
        for (std::uint32_t i = 0; i < 32; i++) {
            kcopy[i] = k[i];
        }
        for (std::uint32_t i = 0; i < 8; i++) {
            in[i] = n[i];
        }
        for (std::uint32_t i = 8; i < 16; i++) {
            in[i] = (std::byte) (ic & 0xff);
            ic >>= 8;
        }
        while (mlen >= 64) {
            auto block_copy = block;
            core_salsa<20>(block.data(), (const std::byte*) in.data(), (const std::byte*) kcopy.data(), nullptr);
            crypto_core_salsa20(reinterpret_cast<unsigned char *>(block_copy.data()),
                                reinterpret_cast<const unsigned char *>(in.data()),
                                reinterpret_cast<const unsigned char *>(kcopy.data()), nullptr);

            assert(block == block_copy);

            for (int i = 0; i < 64; i++) {
                c[i] = m[i] ^ block[i];
            }
            std::uint32_t u = 1;
            for (int i = 8; i < 16; i++) {
                u += (unsigned int) (in[i]);
                in[i] = (std::byte)(u);
                u >>= 8;
            }
            mlen -= 64;
            c += 64;
            m += 64;
        }
        if (mlen) {
            auto block_copy = block;
            core_salsa<20>(block.data(), in.data(), kcopy.data(), nullptr);

            crypto_core_salsa20(reinterpret_cast<unsigned char *>(block_copy.data()),
                                reinterpret_cast<const unsigned char *>(in.data()),
                                reinterpret_cast<const unsigned char *>(kcopy.data()), nullptr);

            assert(block == block_copy);
            for (std::uint32_t i = 0; i < (std::uint32_t) mlen; i++) {
                c[i] = m[i] ^ block[i];
            }
        }

    }

    void stream_salsa20_xor_ic2(std::byte *c, const std::byte *m,
                               std::uint64_t mlen,
                               const std::byte *n, uint64_t ic,
                               const std::byte *k)
    {
        unsigned char in[16];
        unsigned char block[64];
        unsigned char kcopy[32];
        unsigned int  i;
        unsigned int  u;

        if (!mlen) {
            return;
        }
        for (i = 0; i < 32; i++) {
            kcopy[i] = (unsigned char) (k[i]);
        }
        for (i = 0; i < 8; i++) {
            in[i] = (unsigned char)(n[i]);
        }
        for (i = 8; i < 16; i++) {
            in[i] = (unsigned char) (ic & 0xff);
            ic >>= 8;
        }
        while (mlen >= 64) {
            crypto_core_salsa20(block, in, kcopy, NULL);
            for (i = 0; i < 64; i++) {
                c[i] = (std::byte)((unsigned char)(m[i]) ^ block[i]);
            }
            u = 1;
            for (i = 8; i < 16; i++) {
                u += (unsigned int) in[i];
                in[i] = u;
                u >>= 8;
            }
            mlen -= 64;
            c += 64;
            m += 64;
        }
        if (mlen) {
            crypto_core_salsa20(block, in, kcopy, NULL);
            for (i = 0; i < (unsigned int) mlen; i++) {
                c[i] = (std::byte)(unsigned char)((unsigned char)(m[i]) ^ (unsigned char)(block[i]));
            }
        }
       // sodium_memzero(block, sizeof block);
        //sodium_memzero(kcopy, sizeof kcopy);

        return;
    }
    
}
#endif //RPNX_DJB_CRYPTO_SALSA20_HPP
