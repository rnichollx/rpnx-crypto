#include "rpnx/xsalsa20.hpp"
#include "rpnx/salsa20.hpp"
#include "rpnx/hsalsa20.hpp"

#include <assert.h>
#include <vector>


void
rpnx::djb_crypto::stream_xsalsa20_xor_ic(std::byte *output,
                                         const std::byte *input,
                              std::uint64_t input_output_length,
                              const std::byte *nonce,
                              uint64_t stream_position,
                              const std::byte *key
                              )
{
    std::array<std::byte, 32> subkey;
    std::array<std::byte, 32> subkey_test;
    rpnx::djb_crypto::core_hsalsa<20>(subkey.data(), nonce, key, nullptr);


    std::vector<std::byte> output_copy;
    output_copy.resize(input_output_length);
    output_copy.assign(input, input + input_output_length);


    rpnx::djb_crypto::stream_salsa20_xor_ic2(output, input, input_output_length, nonce + 16, stream_position, subkey.data());


}
