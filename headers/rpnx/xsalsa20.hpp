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

namespace rpnx::djb_crypto
{
    void stream_xsalsa20_xor_ic(std::byte *c, const std::byte *m,
                                std::uint64_t mlen, const std::byte *n,
                                uint64_t ic, const std::byte *k);
}
#endif //RPNX_DBJ_CRYPTO_XSALSA20_HPP
