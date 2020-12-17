#include "rpnx/xsalsa20.hpp"

#include <cstdio>
#include <iostream>
#include <sodium.h>
#include <vector>
#include <random>

class test_failure: public std::logic_error {
public:
    test_failure(char const * c)
            : std::logic_error(c)
    {}
};

#define REQUIRE(x) if (!(x)) { throw test_failure("Requirement failed: " # x ); }

int main()
{
    std::mt19937 prand(0);

    std::vector<std::byte> crypto_nonce;
    crypto_nonce.resize(crypto_stream_xsalsa20_NONCEBYTES);
    static_assert(crypto_stream_xsalsa20_NONCEBYTES == 24);


    std::vector<std::byte> crypto_key;
    crypto_key.resize(crypto_stream_xsalsa20_KEYBYTES);
    static_assert(crypto_stream_xsalsa20_KEYBYTES == 32);

    std::size_t data_len = 70;
    std::vector<std::byte> data_in(data_len);
    std::vector<std::byte> crypt_out_ref(data_len);
    std::vector<std::byte> crypt_out_impl(data_len);

    for (std::byte & x : crypto_nonce) x = (std::byte) (prand() & 0xFF);
    for (std::byte & x : crypto_key) x = (std::byte) (prand() & 0xFF);
    for (std::byte & x : data_in) x = (std::byte) 0;
    std::vector<std::byte> crypto_nonce_copy = crypto_nonce;

    REQUIRE(crypt_out_impl == crypt_out_impl);

    ::crypto_stream_xsalsa20_xor_ic(reinterpret_cast<unsigned char *>(crypt_out_ref.data()),
                                   reinterpret_cast<const unsigned char *>(crypt_out_ref.data()),
                                   crypt_out_ref.size(),
                                   reinterpret_cast<const unsigned char *>(crypto_nonce.data()),
                                   0,
                                   reinterpret_cast<const unsigned char *>(crypto_key.data()));

    std::cout << "hello world" << std::endl;

    rpnx::djb_crypto::stream_xsalsa20_xor_ic(crypt_out_impl.data(),
                                             crypt_out_impl.data(),
                                             crypt_out_impl.size(),
                                             crypto_nonce_copy.data(),
                                             0,
                                             crypto_key.data());

    for (std::byte c : crypt_out_impl)
    {
        std::cout << int((unsigned char)(c)) << " ";
    }
    std::cout << std::endl;

    for (std::byte c : crypt_out_ref)
    {
        std::cout << int((unsigned char)(c)) << " ";
    }

    std::cout << std::endl;

    try
    {
        REQUIRE(("2",crypt_out_ref == crypt_out_impl));
    }
    catch (test_failure const & err)
    {
        std::cerr << err.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}