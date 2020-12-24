//
// Created by rnicholl on 12/16/20.
//

#ifndef RPNX_DBJ_CRYPTO_XSALSA20_HPP
#define RPNX_DBJ_CRYPTO_XSALSA20_HPP

#include <utility>
#include <cinttypes>
#include <cstddef>
#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>

#include "rpnx/hsalsa.hpp"
#include "rpnx/salsa.hpp"

namespace rpnx::c_djb_crypto {
    template<std::size_t Rounds>
    void stream_xsalsa_xor_ic(std::byte *output, const std::byte *input,
                              std::uint64_t input_output_length, const std::byte *nonce,
                              std::uint64_t stream_position, const std::byte *key) {
        std::array<std::byte, 32> subkey;
        std::array<std::byte, 32> subkey_test;
        rpnx::c_djb_crypto::core_hsalsa<Rounds>(subkey.data(), nonce, key, nullptr);
        rpnx::c_djb_crypto::stream_salsa_xor_ic<Rounds>(output, input, input_output_length, nonce + 16, stream_position,
                                                      subkey.data());
    }
}

namespace rpnx::crypto
{
    template <std::size_t Rounds, typename InputIt, typename OutputIt, typename NonceIt, typename KeyIt>
    void xsalsa(InputIt input, InputIt inputEnd, OutputIt output, NonceIt nonce, KeyIt key, std::uint64_t stream_position = 0)
    {
        std::array<std::byte, 32> subkey;
        rpnx::crypto::core_hsalsa<Rounds>(subkey.data(), nonce, key);
        rpnx::crypto::stream_salsa_xor_ic<Rounds>(output, input, std::distance(input, inputEnd), nonce + 16, stream_position, subkey.data());
    }
}
#endif //RPNX_DBJ_CRYPTO_XSALSA20_HPP
