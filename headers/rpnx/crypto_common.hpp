//
// Created by rnicholl on 12/16/20.
//

#ifndef RPNX_DJB_CRYPTO_CRYPTO_COMMON_HPP
#define RPNX_DJB_CRYPTO_CRYPTO_COMMON_HPP

#include <cstdint>
#include <cstddef>
#include <assert.h>

namespace rpnx
{
    template <typename It>
    inline constexpr std::uint32_t load_little_endian32(It it)
    {
        std::uint32_t output = 0;
        output |= (std::uint8_t)(*it++);
        output |= (std::uint8_t)(*it++) <<  8;
        output |= (std::uint8_t)(*it++) << 16;
        output |= (std::uint8_t)(*it++) << 24;
        return output;
    }

    template <typename It>
    inline void store_little_endian32(It x, std::uint32_t u)
    {
        *x++ = (std::byte) (u & 0xFF);
        *x++ = (std::byte) ((u >> 8) & 0xFF);
        *x++ = std::byte((u >> 16) & 0xFF);
        *x++ = std::byte((u >> 24) & 0xFF);
    }

    inline std::uint32_t rotate_up_32(std::uint32_t value, int amount)
    {
        assert(amount >= 0 && amount < 32);
        if (amount == 0) return value;
        return (value << amount) | (value >> (32 - amount));
    }

    inline std::uint32_t rotate_down_32(std::uint32_t value, int amount)
    {
        assert(amount >= 0 && amount < 32);
        if (amount == 0) return value;
        return rotate_up_32(value, 32 - amount);
    }



}

#endif //RPNX_DJB_CRYPTO_CRYPTO_COMMON_HPP
