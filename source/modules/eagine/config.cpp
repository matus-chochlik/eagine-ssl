/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
/// https://www.boost.org/LICENSE_1_0.txt
///
module;
#if __has_include(<openssl/evp.h>)
#define EAGINE_HAS_SSL 1
#else
#define EAGINE_HAS_SSL 0
#endif

export module eagine.sslplus:config;
import eagine.core.types;

extern "C" {
struct asn1_object_st;
struct asn1_string_st;
struct bio_st;
struct bio_method_st;
struct engine_st;
struct evp_cipher_ctx_st;
struct evp_cipher_st;
struct evp_md_st;
struct evp_md_ctx_st;
struct evp_pkey_ctx_st;
struct evp_pkey_st;
struct ossl_core_handle_st;
struct ossl_dispatch_st;
struct ossl_lib_ctx_st;
struct ossl_provider_st;
struct ui_st;
struct ui_method_st;
struct x509_st;
struct X509_crl_st;
struct x509_lookup_method_st;
struct x509_lookup_st;
struct X509_name_entry_st;
struct X509_name_st;
struct x509_store_ctx_st;
struct x509_store_st;
//
struct stack_st_X509;
}

namespace eagine::sslplus {
//------------------------------------------------------------------------------
export struct ssl_types {
#if EAGINE_HAS_SSL
    static constexpr bool has_api = true;
#else
    static constexpr bool has_api = false;
#endif
    using ui_method_type = ::ui_method_st;
    using dispatch_type = ::ossl_dispatch_st;
    using core_handle_type = ::ossl_core_handle_st;
    using lib_ctx_type = ::ossl_lib_ctx_st;
    using provider_type = ::ossl_provider_st;
    using engine_type = ::engine_st;
    using asn1_object_type = ::asn1_object_st;
    using asn1_string_type = ::asn1_string_st;
    using asn1_integer_type = ::asn1_string_st;
    using bio_method_type = ::bio_method_st;
    using bio_type = ::bio_st;
    using evp_pkey_ctx_type = ::evp_pkey_ctx_st;
    using evp_pkey_type = ::evp_pkey_st;
    using evp_cipher_ctx_type = ::evp_cipher_ctx_st;
    using evp_cipher_type = ::evp_cipher_st;
    using evp_md_ctx_type = ::evp_md_ctx_st;
    using evp_md_type = ::evp_md_st;
    using x509_crl_type = ::X509_crl_st;
    using x509_lookup_method_type = ::x509_lookup_method_st;
    using x509_lookup_type = ::x509_lookup_st;
    using x509_name_type = ::X509_name_st;
    using x509_name_entry_type = ::X509_name_entry_st;
    using x509_store_ctx_type = ::x509_store_ctx_st;
    using x509_store_type = ::x509_store_st;
    using x509_type = ::x509_st;
    using x509_stack_type = ::stack_st_X509;
};
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
