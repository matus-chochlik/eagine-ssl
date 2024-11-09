/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
/// https://www.boost.org/LICENSE_1_0.txt
///
module;

#ifndef EAGINE_SSL_STATIC_FUNC
#define EAGINE_SSL_STATIC_FUNC(NAME) nullptr
#endif

export module eagine.sslplus:c_api;

import std;
import eagine.core.types;
import eagine.core.c_api;
import :config;
import :api_traits;
import :result;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
export template <typename ApiTraits>
struct basic_ssl_c_api {
private:
    ApiTraits& _traits;

public:
    using this_api = basic_ssl_c_api;
    using api_traits = ApiTraits;

    static constexpr bool has_api = ssl_types::has_api;
    using ui_method_type = ssl_types::ui_method_type;
    using dispatch_type = ssl_types::dispatch_type;
    using core_handle_type = ssl_types::core_handle_type;
    using lib_ctx_type = ssl_types::lib_ctx_type;
    using provider_type = ssl_types::provider_type;
    using engine_type = ssl_types::engine_type;
    using asn1_object_type = ssl_types::asn1_object_type;
    using asn1_string_type = ssl_types::asn1_string_type;
    using asn1_integer_type = ssl_types::asn1_integer_type;
    using bio_method_type = ssl_types::bio_method_type;
    using bio_type = ssl_types::bio_type;
    using evp_pkey_ctx_type = ssl_types::evp_pkey_ctx_type;
    using evp_pkey_type = ssl_types::evp_pkey_type;
    using evp_cipher_ctx_type = ssl_types::evp_cipher_ctx_type;
    using evp_cipher_type = ssl_types::evp_cipher_type;
    using evp_md_ctx_type = ssl_types::evp_md_ctx_type;
    using evp_md_type = ssl_types::evp_md_type;
    using x509_lookup_method_type = ssl_types::x509_lookup_method_type;
    using x509_lookup_type = ssl_types::x509_lookup_type;
    using x509_name_type = ssl_types::x509_name_type;
    using x509_name_entry_type = ssl_types::x509_name_entry_type;
    using x509_store_ctx_type = ssl_types::x509_store_ctx_type;
    using x509_store_type = ssl_types::x509_store_type;
    using x509_crl_type = ssl_types::x509_crl_type;
    using x509_type = ssl_types::x509_type;
    using x509_stack_type = ssl_types::x509_stack_type;

    using passwd_callback_type = int(char*, int, int, void*);

    using x509_store_ctx_verify_callback_type = int(int, x509_store_ctx_type*);

    template <typename Result, typename... U>
    constexpr auto check_result(Result res, U&&...) const noexcept {
        res.error_code(this->err_get_error());
        return res;
    }

    template <typename Result, typename Info, c_api::result_validity Validity>
    static constexpr auto collapse(
      c_api::result<Result, Info, Validity>&& r) noexcept {
        return r.collapsed(
          [](int value) { return value == 1; },
          [](auto& info) { info.set_unknown_error(); });
    }

    template <
      typename Signature,
      c_api::function_ptr<api_traits, nothing_t, Signature> Function>
    using ssl_api_function = c_api::
      opt_function<api_traits, nothing_t, Signature, Function, has_api, bool(Function)>;

    // error
    ssl_api_function<unsigned long(), EAGINE_SSL_STATIC_FUNC(ERR_get_error)>
      err_get_error{"ERR_get_error", *this};

    ssl_api_function<unsigned long(), EAGINE_SSL_STATIC_FUNC(ERR_peek_error)>
      err_peek_error{"ERR_peek_error", *this};

    ssl_api_function<
      void(unsigned long, char*, size_t),
      EAGINE_SSL_STATIC_FUNC(ERR_error_string_n)>
      err_error_string_n{"ERR_error_string_n", *this};

    // ui method
    ssl_api_function<const ui_method_type*(), EAGINE_SSL_STATIC_FUNC(UI_null)>
      ui_null{"UI_null", *this};

    ssl_api_function<ui_method_type*(), EAGINE_SSL_STATIC_FUNC(UI_OpenSSL)>
      ui_openssl{"UI_OpenSSL", *this};

    ssl_api_function<
      const ui_method_type*(),
      EAGINE_SSL_STATIC_FUNC(UI_get_default_method)>
      ui_get_default_method{"UI_get_default_method", *this};

    // lib_ctx
    ssl_api_function<lib_ctx_type*(), EAGINE_SSL_STATIC_FUNC(OSSL_LIB_CTX_new)>
      lib_ctx_new{"OSSL_LIB_CTX_new", *this};

    ssl_api_function<
      lib_ctx_type*(const core_handle_type*, const dispatch_type*),
      EAGINE_SSL_STATIC_FUNC(OSSL_LIB_CTX_new_from_dispatch)>
      lib_ctx_new_from_dispatch{"OSSL_LIB_CTX_new_from_dispatch", *this};

    ssl_api_function<
      lib_ctx_type*(const core_handle_type*, const dispatch_type*),
      EAGINE_SSL_STATIC_FUNC(OSSL_LIB_CTX_new_child)>
      lib_ctx_new_child{"OSSL_LIB_CTX_new_child", *this};

    ssl_api_function<
      int(lib_ctx_type*, const char*),
      EAGINE_SSL_STATIC_FUNC(OSSL_LIB_CTX_load_config)>
      lib_ctx_load_config{"OSSL_LIB_CTX_load_config", *this};

    ssl_api_function<
      lib_ctx_type*(),
      EAGINE_SSL_STATIC_FUNC(OSSL_LIB_CTX_get0_global_default)>
      lib_ctx_get_global_default{"OSSL_LIB_CTX_get0_global_default", *this};

    ssl_api_function<
      lib_ctx_type*(lib_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(OSSL_LIB_CTX_set0_default)>
      lib_ctx_set_default{"OSSL_LIB_CTX_set0_default", *this};

    ssl_api_function<void(lib_ctx_type*), EAGINE_SSL_STATIC_FUNC(OSSL_LIB_CTX_free)>
      lib_ctx_free{"OSSL_LIB_CTX_free", *this};

    // provider
    ssl_api_function<
      int(lib_ctx_type*, const char*),
      EAGINE_SSL_STATIC_FUNC(OSSL_PROVIDER_set_default_search_path)>
      provider_set_default_search_path{
        "OSSL_PROVIDER_set_default_search_path",
        *this};

    ssl_api_function<
      provider_type*(lib_ctx_type*, const char*),
      EAGINE_SSL_STATIC_FUNC(OSSL_PROVIDER_load)>
      provider_load{"OSSL_PROVIDER_load", *this};

    ssl_api_function<
      provider_type*(lib_ctx_type*, const char*, int),
      EAGINE_SSL_STATIC_FUNC(OSSL_PROVIDER_try_load)>
      provider_try_load{"OSSL_PROVIDER_try_load", *this};

    ssl_api_function<
      int(provider_type*),
      EAGINE_SSL_STATIC_FUNC(OSSL_PROVIDER_unload)>
      provider_unload{"OSSL_PROVIDER_unload", *this};

    ssl_api_function<
      const dispatch_type*(const provider_type*),
      EAGINE_SSL_STATIC_FUNC(OSSL_PROVIDER_get0_dispatch)>
      provider_get_dispatch{"OSSL_PROVIDER_get0_dispatch", *this};

    ssl_api_function<
      int(lib_ctx_type*, const char*),
      EAGINE_SSL_STATIC_FUNC(OSSL_PROVIDER_available)>
      provider_available{"OSSL_PROVIDER_available", *this};

    ssl_api_function<
      const char*(const provider_type*),
      EAGINE_SSL_STATIC_FUNC(OSSL_PROVIDER_get0_name)>
      provider_get_name{"OSSL_PROVIDER_get_name", *this};

    ssl_api_function<
      int(const provider_type*),
      EAGINE_SSL_STATIC_FUNC(OSSL_PROVIDER_self_test)>
      provider_self_test{"OSSL_PROVIDER_self_test", *this};

    // asn1
    ssl_api_function<
      int(const asn1_string_type*),
      EAGINE_SSL_STATIC_FUNC(ASN1_STRING_length)>
      asn1_string_length{"ASN1_STRING_length", *this};

    ssl_api_function<
      const unsigned char*(const asn1_string_type*),
      EAGINE_SSL_STATIC_FUNC(ASN1_STRING_get0_data)>
      asn1_string_get0_data{"ASN1_STRING_get0_data", *this};

    ssl_api_function<
      int(std::int64_t*, const asn1_integer_type*),
      EAGINE_SSL_STATIC_FUNC(ASN1_INTEGER_get_int64)>
      asn1_integer_get_int64{"ASN1_INTEGER_get_int64", *this};

    ssl_api_function<
      int(std::uint64_t*, const asn1_integer_type*),
      EAGINE_SSL_STATIC_FUNC(ASN1_INTEGER_get_uint64)>
      asn1_integer_get_uint64{"ASN1_INTEGER_get_uint64", *this};

    // obj
    ssl_api_function<
      int(char*, int, const asn1_object_type*, int),
      EAGINE_SSL_STATIC_FUNC(OBJ_obj2txt)>
      obj_obj2txt{"OBJ_obj2txt", *this};

    // bio
    ssl_api_function<
      bio_type*(const bio_method_type*),
      EAGINE_SSL_STATIC_FUNC(BIO_new)>
      bio_new{"BIO_new", *this};

    ssl_api_function<
      bio_type*(const void*, int),
      EAGINE_SSL_STATIC_FUNC(BIO_new_mem_buf)>
      bio_new_mem_buf{"BIO_new_mem_buf", *this};

    ssl_api_function<int(bio_type*), EAGINE_SSL_STATIC_FUNC(BIO_up_ref)> bio_up_ref{
      "BIO_up_ref",
      *this};

    ssl_api_function<int(bio_type*), EAGINE_SSL_STATIC_FUNC(BIO_free)> bio_free{
      "BIO_free",
      *this};

    ssl_api_function<void(bio_type*), EAGINE_SSL_STATIC_FUNC(BIO_free_all)>
      bio_free_all{"BIO_free_all", *this};

    // random
    ssl_api_function<int(unsigned char*, int num), EAGINE_SSL_STATIC_FUNC(RAND_bytes)>
      rand_bytes{"RAND_bytes", *this};

    // pkey
    ssl_api_function<evp_pkey_type*(), EAGINE_SSL_STATIC_FUNC(EVP_PKEY_new)>
      evp_pkey_new{"EVP_PKEY_new", *this};

    ssl_api_function<int(evp_pkey_type*), EAGINE_SSL_STATIC_FUNC(EVP_PKEY_up_ref)>
      evp_pkey_up_ref{"EVP_PKEY_up_ref", *this};

    ssl_api_function<void(evp_pkey_type*), EAGINE_SSL_STATIC_FUNC(EVP_PKEY_free)>
      evp_pkey_free{"EVP_PKEY_free", *this};

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_128_ctr)>
      evp_aes_128_ctr{"evp_aes_128_ctr", *this};

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_128_ccm)>
      evp_aes_128_ccm{"evp_aes_128_ccm", *this};

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_128_gcm)>
      evp_aes_128_gcm{"evp_aes_128_gcm", *this};

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_128_xts)>
      evp_aes_128_xts{"evp_aes_128_xts", *this};

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_192_ecb)>
      evp_aes_192_ecb{"evp_aes_192_ecb", *this};

    ssl_api_function<
      const evp_cipher_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_aes_192_cbc)>
      evp_aes_192_cbc{"evp_aes_192_cbc", *this};

    ssl_api_function<
      evp_cipher_ctx_type*(),
      EAGINE_SSL_STATIC_FUNC(EVP_CIPHER_CTX_new)>
      evp_cipher_ctx_new{"EVP_CIPHER_CTX_new", *this};

    ssl_api_function<
      int(evp_cipher_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_CIPHER_CTX_reset)>
      evp_cipher_ctx_reset{"EVP_CIPHER_CTX_reset", *this};

    ssl_api_function<
      void(evp_cipher_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_CIPHER_CTX_free)>
      evp_cipher_ctx_free{"EVP_CIPHER_CTX_free", *this};

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        const unsigned char*,
        const unsigned char*,
        int),
      EAGINE_SSL_STATIC_FUNC(EVP_CipherInit)>
      evp_cipher_init{"EVP_CipherInit", *this};

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        engine_type*,
        const unsigned char*,
        const unsigned char*,
        int),
      EAGINE_SSL_STATIC_FUNC(EVP_CipherInit_ex)>
      evp_cipher_init_ex{"EVP_CipherInit_ex", *this};

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*, const unsigned char*, int),
      EAGINE_SSL_STATIC_FUNC(EVP_CipherUpdate)>
      evp_cipher_update{"EVP_CipherUpdate", *this};

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_CipherFinal_ex)>
      evp_cipher_final{"EVP_CipherFinal", *this};

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_CipherFinal_ex)>
      evp_cipher_final_ex{"EVP_CipherFinal_ex", *this};

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        const unsigned char*,
        const unsigned char*),
      EAGINE_SSL_STATIC_FUNC(EVP_EncryptInit)>
      evp_encrypt_init{"EVP_EncryptInit", *this};

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        engine_type*,
        const unsigned char*,
        const unsigned char*),
      EAGINE_SSL_STATIC_FUNC(EVP_EncryptInit_ex)>
      evp_encrypt_init_ex{"EVP_EncryptInit_ex", *this};

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*, const unsigned char*, int),
      EAGINE_SSL_STATIC_FUNC(EVP_EncryptUpdate)>
      evp_encrypt_update{"EVP_EncryptUpdate", *this};

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_EncryptFinal_ex)>
      evp_encrypt_final{"EVP_EncryptFinal", *this};

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_EncryptFinal_ex)>
      evp_encrypt_final_ex{"EVP_EncryptFinal_ex", *this};

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        const unsigned char*,
        const unsigned char*),
      EAGINE_SSL_STATIC_FUNC(EVP_DecryptInit)>
      evp_decrypt_init{"EVP_DecryptInit", *this};

    ssl_api_function<
      int(
        evp_cipher_ctx_type*,
        const evp_cipher_type*,
        engine_type*,
        const unsigned char*,
        const unsigned char*),
      EAGINE_SSL_STATIC_FUNC(EVP_DecryptInit_ex)>
      evp_decrypt_init_ex{"EVP_DecryptInit_ex", *this};

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*, const unsigned char*, int),
      EAGINE_SSL_STATIC_FUNC(EVP_DecryptUpdate)>
      evp_decrypt_update{"EVP_DecryptUpdate", *this};

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_DecryptFinal_ex)>
      evp_decrypt_final{"EVP_DecryptFinal", *this};

    ssl_api_function<
      int(evp_cipher_ctx_type*, unsigned char*, int*),
      EAGINE_SSL_STATIC_FUNC(EVP_DecryptFinal_ex)>
      evp_decrypt_final_ex{"EVP_DecryptFinal_ex", *this};

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_md_null)>
      evp_md_null{"EVP_md_null", *this};

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_md5)> evp_md5{
      "EVP_md5",
      *this};

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_sha1)>
      evp_sha1{"EVP_sha1", *this};

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_sha224)>
      evp_sha224{"EVP_sha224", *this};

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_sha256)>
      evp_sha256{"EVP_sha256", *this};

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_sha384)>
      evp_sha384{"EVP_sha384", *this};

    ssl_api_function<const evp_md_type*(), EAGINE_SSL_STATIC_FUNC(EVP_sha512)>
      evp_sha512{"EVP_sha512", *this};

    ssl_api_function<
      const evp_md_type*(const char*),
      EAGINE_SSL_STATIC_FUNC(EVP_get_digestbyname)>
      evp_get_digest_by_name{"EVP_get_digestbyname", *this};

    ssl_api_function<int(const evp_md_type*), EAGINE_SSL_STATIC_FUNC(EVP_MD_size)>
      evp_md_size{"EVP_MD_size", *this};

    ssl_api_function<
      int(const evp_md_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_MD_block_size)>
      evp_md_block_size{"EVP_MD_block_size", *this};

    ssl_api_function<evp_md_ctx_type*(), EAGINE_SSL_STATIC_FUNC(EVP_MD_CTX_new)>
      evp_md_ctx_new{"EVP_MD_CTX_new", *this};

    ssl_api_function<int(evp_md_ctx_type*), EAGINE_SSL_STATIC_FUNC(EVP_MD_CTX_reset)>
      evp_md_ctx_reset{"EVP_MD_CTX_reset", *this};

    ssl_api_function<void(evp_md_ctx_type*), EAGINE_SSL_STATIC_FUNC(EVP_MD_CTX_free)>
      evp_md_ctx_free{"EVP_MD_CTX_free", *this};

    ssl_api_function<
      int(evp_md_ctx_type*, const evp_md_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestInit)>
      evp_digest_init{"EVP_DigestInit", *this};

    ssl_api_function<
      int(evp_md_ctx_type*, const evp_md_type*, engine_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestInit_ex)>
      evp_digest_init_ex{"EVP_DigestInit_ex", *this};

    ssl_api_function<
      int(evp_md_ctx_type*, const void*, size_t),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestUpdate)>
      evp_digest_update{"EVP_DigestUpdate", *this};

    ssl_api_function<
      int(evp_md_ctx_type*, unsigned char*, unsigned int*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestFinal_ex)>
      evp_digest_final{"EVP_DigestFinal", *this};

    ssl_api_function<
      int(evp_md_ctx_type*, unsigned char*, unsigned int*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestFinal_ex)>
      evp_digest_final_ex{"EVP_DigestFinal_ex", *this};

    ssl_api_function<
      int(
        evp_md_ctx_type*,
        evp_pkey_ctx_type**,
        const evp_md_type*,
        engine_type*,
        evp_pkey_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestSignInit)>
      evp_digest_sign_init{"EVP_DigestSignInit", *this};

    ssl_api_function<
      int(evp_md_ctx_type*, const void*, size_t),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestUpdate)>
      evp_digest_sign_update{"EVP_DigestSignUpdate", *this};

    ssl_api_function<
      int(evp_md_ctx_type*, unsigned char*, size_t*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestSignFinal)>
      evp_digest_sign_final{"EVP_DigestSignFinal", *this};

    ssl_api_function<
      int(
        evp_md_ctx_type*,
        evp_pkey_ctx_type**,
        const evp_md_type*,
        engine_type*,
        evp_pkey_type*),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestVerifyInit)>
      evp_digest_verify_init{"EVP_DigestVerifyInit", *this};

    ssl_api_function<
      int(evp_md_ctx_type*, const void*, size_t),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestUpdate)>
      evp_digest_verify_update{"EVP_DigestVerifyUpdate", *this};

    ssl_api_function<
      int(evp_md_ctx_type*, const unsigned char*, size_t),
      EAGINE_SSL_STATIC_FUNC(EVP_DigestVerifyFinal)>
      evp_digest_verify_final{"EVP_DigestVerifyFinal", *this};

    // x509 lookup
    ssl_api_function<
      x509_lookup_method_type*(),
      EAGINE_SSL_STATIC_FUNC(X509_LOOKUP_hash_dir)>
      x509_lookup_hash_dir{"X509_LOOKUP_hash_dir", *this};

    ssl_api_function<
      x509_lookup_method_type*(),
      EAGINE_SSL_STATIC_FUNC(X509_LOOKUP_file)>
      x509_lookup_file{"X509_LOOKUP_file", *this};

    // x509 store context
    ssl_api_function<
      x509_store_ctx_type*(),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_new)>
      x509_store_ctx_new{"X509_STORE_CTX_new", *this};

    ssl_api_function<
      int(x509_store_ctx_type*, x509_store_type*, x509_type*, x509_stack_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_init)>
      x509_store_ctx_init{"X509_STORE_CTX_init", *this};

    ssl_api_function<
      void(x509_store_ctx_type*, x509_stack_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_set0_trusted_stack)>
      x509_store_ctx_set0_trusted_stack{"X509_STORE_CTX_set0_trusted_stack", *this};

    ssl_api_function<
      void(x509_store_ctx_type*, x509_stack_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_set0_verified_chain)>
      x509_store_ctx_set0_verified_chain{
        "X509_STORE_CTX_set0_verified_chain",
        *this};

    ssl_api_function<
      void(x509_store_ctx_type*, x509_stack_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_set0_untrusted)>
      x509_store_ctx_set0_untrusted{"X509_STORE_CTX_set0_untrusted", *this};

    ssl_api_function<
      void(x509_store_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_cleanup)>
      x509_store_ctx_cleanup{"X509_STORE_CTX_cleanup", *this};

    ssl_api_function<
      void(x509_store_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_CTX_free)>
      x509_store_ctx_free{"X509_STORE_CTX_free", *this};

    ssl_api_function<
      int(x509_store_ctx_type*),
      EAGINE_SSL_STATIC_FUNC(X509_verify_cert)>
      x509_verify_cert{"X509_verify_cert", *this};

    // x509 store
    ssl_api_function<x509_store_type*(), EAGINE_SSL_STATIC_FUNC(X509_STORE_new)>
      x509_store_new{"X509_STORE_new", *this};

    ssl_api_function<int(x509_store_type*), EAGINE_SSL_STATIC_FUNC(X509_STORE_up_ref)>
      x509_store_up_ref{"X509_STORE_up_ref", *this};

    ssl_api_function<int(x509_store_type*), EAGINE_SSL_STATIC_FUNC(X509_STORE_lock)>
      x509_store_lock{"X509_STORE_lock", *this};

    ssl_api_function<int(x509_store_type*), EAGINE_SSL_STATIC_FUNC(X509_STORE_unlock)>
      x509_store_unlock{"X509_STORE_unlock", *this};

    ssl_api_function<void(x509_store_type*), EAGINE_SSL_STATIC_FUNC(X509_STORE_free)>
      x509_store_free{"X509_STORE_free", *this};

    ssl_api_function<
      int(x509_store_type*, x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_add_cert)>
      x509_store_add_cert{"X509_STORE_add_cert", *this};

    ssl_api_function<
      int(x509_store_type*, x509_crl_type*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_add_crl)>
      x509_store_add_crl{"X509_STORE_add_crl", *this};

    ssl_api_function<
      int(x509_store_type*, const char*, const char*),
      EAGINE_SSL_STATIC_FUNC(X509_STORE_load_locations)>
      x509_store_load_locations{"X509_STORE_load_locations", *this};

    // x509_crl
    ssl_api_function<x509_crl_type*(), EAGINE_SSL_STATIC_FUNC(X509_CRL_new)>
      x509_crl_new{"X509_crl_new", *this};

    ssl_api_function<void(x509_crl_type*), EAGINE_SSL_STATIC_FUNC(X509_CRL_free)>
      x509_crl_free{"X509_crl_free", *this};

    // x509
    ssl_api_function<x509_type*(), EAGINE_SSL_STATIC_FUNC(X509_new)> x509_new{
      "X509_new",
      *this};

    ssl_api_function<
      evp_pkey_type*(x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get_pubkey)>
      x509_get_pubkey{"X509_get_pubkey", *this};

    ssl_api_function<
      evp_pkey_type*(const x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get0_pubkey)>
      x509_get0_pubkey{"X509_get0_pubkey", *this};

    ssl_api_function<
      const asn1_integer_type*(const x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get0_serialNumber)>
      x509_get0_serial_number{"X509_get0_serialNumber", *this};

    ssl_api_function<
      x509_name_type*(const x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get_issuer_name)>
      x509_get_issuer_name{"X509_get_issuer_name", *this};

    ssl_api_function<
      x509_name_type*(const x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get_subject_name)>
      x509_get_subject_name{"X509_get_subject_name", *this};

    ssl_api_function<
      int(const x509_type*),
      EAGINE_SSL_STATIC_FUNC(X509_get_ext_count)>
      x509_get_ext_count{"X509_get_ext_count", *this};

    ssl_api_function<void(x509_type*), EAGINE_SSL_STATIC_FUNC(X509_free)> x509_free{
      "X509_free",
      *this};

    // x509 name (entry)
    ssl_api_function<
      int(const x509_name_type*),
      EAGINE_SSL_STATIC_FUNC(X509_NAME_entry_count)>
      x509_name_entry_count{"X509_NAME_entry_count", *this};

    ssl_api_function<
      x509_name_entry_type*(const x509_name_type*, int),
      EAGINE_SSL_STATIC_FUNC(X509_NAME_get_entry)>
      x509_name_get_entry{"X509_NAME_get_entry", *this};

    ssl_api_function<
      asn1_object_type*(const x509_name_entry_type*),
      EAGINE_SSL_STATIC_FUNC(X509_NAME_ENTRY_get_object)>
      x509_name_entry_get_object{"X509_NAME_ENTRY_get_object", *this};

    ssl_api_function<
      asn1_string_type*(const x509_name_entry_type*),
      EAGINE_SSL_STATIC_FUNC(X509_NAME_ENTRY_get_data)>
      x509_name_entry_get_data{"X509_NAME_ENTRY_get_data", *this};

    // pem
    ssl_api_function<
      evp_pkey_type*(bio_type*, evp_pkey_type**, passwd_callback_type*, void*),
      EAGINE_SSL_STATIC_FUNC(PEM_read_bio_PrivateKey)>
      pem_read_bio_private_key{"PEM_read_bio_PrivateKey", *this};

    ssl_api_function<
      evp_pkey_type*(bio_type*, evp_pkey_type**, passwd_callback_type*, void*),
      EAGINE_SSL_STATIC_FUNC(PEM_read_bio_PUBKEY)>
      pem_read_bio_pubkey{"PEM_read_bio_PUBKEY", *this};

    ssl_api_function<
      x509_crl_type*(bio_type*, x509_crl_type**, passwd_callback_type*, void*),
      EAGINE_SSL_STATIC_FUNC(PEM_read_bio_X509_CRL)>
      pem_read_bio_x509_crl{"PEM_read_bio_X509_CRL", *this};

    ssl_api_function<
      x509_type*(bio_type*, x509_type**, passwd_callback_type*, void*),
      EAGINE_SSL_STATIC_FUNC(PEM_read_bio_X509)>
      pem_read_bio_x509{"PEM_read_bio_X509", *this};

    basic_ssl_c_api(api_traits& traits)
      : _traits{traits} {}

    auto traits() noexcept -> api_traits& {
        return _traits;
    }
};
//------------------------------------------------------------------------------
using ssl_c_api = basic_ssl_c_api<ssl_api_traits>;
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
