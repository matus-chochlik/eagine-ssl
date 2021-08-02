/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#ifndef EAGINE_SSLPLUS_API_API_HPP
#define EAGINE_SSLPLUS_API_API_HPP

#include "c_api.hpp"
#include "object_handle.hpp"
#include "object_stack.hpp"
#include <eagine/callable_ref.hpp>
#include <eagine/memory/split_block.hpp>
#include <eagine/scope_exit.hpp>
#include <eagine/string_list.hpp>

namespace eagine::sslplus {
//------------------------------------------------------------------------------
#define SSLPAFP(FUNC) decltype(c_api::FUNC), &c_api::FUNC
//------------------------------------------------------------------------------
class password_callback {
public:
    constexpr password_callback() noexcept = default;

    constexpr password_callback(
      callable_ref<bool(const string_span, const bool)> callback) noexcept
      : _callback{std::move(callback)} {}

    constexpr auto native_func() noexcept -> auto* {
        return _callback ? &_impl : nullptr;
    }

    constexpr auto native_data() noexcept -> auto* {
        return _callback ? static_cast<void*>(this) : nullptr;
    }

private:
    static auto _impl(char* dst, const int len, const int writing, void* ptr)
      -> int {
        if(auto* self = static_cast<password_callback*>(ptr)) {
            return self->_callback(
                     string_span(dst, span_size_t(len)), writing != 0)
                     ? 1
                     : 0;
        }
        return 0;
    }

    callable_ref<bool(const string_span, const bool)> _callback{};
};
//------------------------------------------------------------------------------
template <typename ApiTraits>
class basic_ssl_operations : public basic_ssl_c_api<ApiTraits> {

public:
    using api_traits = ApiTraits;
    using c_api = basic_ssl_c_api<ApiTraits>;

    template <typename W, W c_api::*F, typename Signature = typename W::signature>
    class func;

    template <typename W, W c_api::*F, typename RVC, typename... Params>
    class func<W, F, RVC(Params...)>
      : public wrapped_c_api_function<c_api, api_traits, nothing_t, W, F> {
        using base = wrapped_c_api_function<c_api, api_traits, nothing_t, W, F>;

    private:
        template <typename Res>
        constexpr auto _check(Res&& res) const noexcept {
            res.error_code(this->api().err_get_error());
            return std::forward<Res>(res);
        }

    protected:
        template <typename... Args>
        constexpr auto _chkcall(Args&&... args) const noexcept {
            return this->_check(this->_call(std::forward<Args>(args)...));
        }

        using base::_conv;

        template <typename Tag, typename Handle>
        static constexpr auto _conv(basic_handle<Tag, Handle> obj) noexcept {
            return static_cast<Handle>(obj);
        }

        template <typename Object>
        static constexpr auto _conv(const object_stack<Object>& stk) noexcept {
            return stk.native();
        }

        template <typename... Args>
        constexpr auto _cnvchkcall(Args&&... args) const noexcept {
            return this->_chkcall(_conv(args)...).cast_to(type_identity<RVC>{});
        }

    public:
        using base::base;

        constexpr auto operator()(Params... params) const noexcept {
            return this->_chkcall(_conv(params)...)
              .cast_to(type_identity<RVC>{});
        }

        constexpr auto fake() const noexcept {
            auto result{this->_fake(0)};
            result.set_unknown_error();
            return result;
        }
    };

    // null_ui
    struct : func<SSLPAFP(ui_null)> {
        using func<SSLPAFP(ui_null)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<ui_method>{});
        }
    } null_ui;

    // openssl_ui
    struct : func<SSLPAFP(ui_openssl)> {
        using func<SSLPAFP(ui_openssl)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<ui_method>{});
        }
    } openssl_ui;

    // load_builtin_engines
    struct : func<SSLPAFP(engine_load_builtin_engines)> {
        using func<SSLPAFP(engine_load_builtin_engines)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall();
        }
    } load_builtin_engines;

    // get_first_engine
    struct : func<SSLPAFP(engine_get_first)> {
        using func<SSLPAFP(engine_get_first)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<owned_engine>{});
        }
    } get_first_engine;

    // get_last_engine
    struct : func<SSLPAFP(engine_get_last)> {
        using func<SSLPAFP(engine_get_last)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<owned_engine>{});
        }
    } get_last_engine;

    // get_next_engine
    struct : func<SSLPAFP(engine_get_next)> {
        using func<SSLPAFP(engine_get_next)>::func;

        constexpr auto operator()(owned_engine& eng) const noexcept {
            return this->_cnvchkcall(eng.release())
              .cast_to(type_identity<owned_engine>{});
        }
    } get_next_engine;

    // get_prev_engine
    struct : func<SSLPAFP(engine_get_prev)> {
        using func<SSLPAFP(engine_get_prev)>::func;

        constexpr auto operator()(owned_engine& eng) const noexcept {
            return this->_cnvchkcall(eng.release())
              .cast_to(type_identity<owned_engine>{});
        }
    } get_prev_engine;

    // new_engine
    struct : func<SSLPAFP(engine_new)> {
        using func<SSLPAFP(engine_new)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<owned_engine>{});
        }
    } new_engine;

    // open_engine
    struct : func<SSLPAFP(engine_by_id)> {
        using func<SSLPAFP(engine_by_id)>::func;

        constexpr auto operator()(string_view id) const noexcept {
            return this->_cnvchkcall(id).cast_to(type_identity<owned_engine>{});
        }
    } open_engine;

    // copy_engine
    struct : func<SSLPAFP(engine_up_ref)> {
        using func<SSLPAFP(engine_up_ref)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return this->_cnvchkcall(eng).replaced_with(owned_engine(eng));
        }
    } copy_engine;

    // delete_engine
    struct : func<SSLPAFP(engine_free)> {
        using func<SSLPAFP(engine_free)>::func;

        constexpr auto operator()(owned_engine& eng) const noexcept {
            return this->_chkcall(eng.release());
        }

        auto raii(owned_engine& eng) const noexcept {
            return eagine::finally([this, &eng]() { (*this)(eng); });
        }

    } delete_engine;

    // init_engine
    struct : func<SSLPAFP(engine_init)> {
        using func<SSLPAFP(engine_init)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return collapse_bool(this->_cnvchkcall(eng));
        }
    } init_engine;

    // finish_engine
    struct : func<SSLPAFP(engine_finish)> {
        using func<SSLPAFP(engine_finish)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return collapse_bool(this->_cnvchkcall(eng));
        }

        auto raii(owned_engine& eng) const noexcept {
            return eagine::finally([this, &eng]() { (*this)(eng); });
        }
    } finish_engine;

    // get_engine_id
    struct : func<SSLPAFP(engine_get_id)> {
        using func<SSLPAFP(engine_get_id)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return this->_cnvchkcall(eng).cast_to(type_identity<string_view>{});
        }
    } get_engine_id;

    // get_engine_name
    struct : func<SSLPAFP(engine_get_name)> {
        using func<SSLPAFP(engine_get_name)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return this->_cnvchkcall(eng).cast_to(type_identity<string_view>{});
        }
    } get_engine_name;

    // set_default_rsa
    struct : func<SSLPAFP(engine_set_default_rsa)> {
        using func<SSLPAFP(engine_set_default_rsa)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return this->_cnvchkcall(eng);
        }
    } set_default_rsa;

    // set_default_dsa
    struct : func<SSLPAFP(engine_set_default_dsa)> {
        using func<SSLPAFP(engine_set_default_dsa)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return this->_cnvchkcall(eng);
        }
    } set_default_dsa;

    // set_default_dh
    struct : func<SSLPAFP(engine_set_default_dh)> {
        using func<SSLPAFP(engine_set_default_dh)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return this->_cnvchkcall(eng);
        }
    } set_default_dh;

    // set_default_rand
    struct : func<SSLPAFP(engine_set_default_rand)> {
        using func<SSLPAFP(engine_set_default_rand)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return this->_cnvchkcall(eng);
        }
    } set_default_rand;

    // set_default_ciphers
    struct : func<SSLPAFP(engine_set_default_ciphers)> {
        using func<SSLPAFP(engine_set_default_ciphers)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return this->_cnvchkcall(eng);
        }
    } set_default_ciphers;

    // set_default_digests
    struct : func<SSLPAFP(engine_set_default_digests)> {
        using func<SSLPAFP(engine_set_default_digests)>::func;

        constexpr auto operator()(engine eng) const noexcept {
            return this->_cnvchkcall(eng);
        }
    } set_default_digests;

    // load_engine_private_key
    struct : func<SSLPAFP(engine_load_private_key)> {
        using func<SSLPAFP(engine_load_private_key)>::func;

        constexpr auto operator()(engine eng, string_view key_id, ui_method uim)
          const noexcept {
            return this->_cnvchkcall(eng, key_id, uim, nullptr)
              .cast_to(type_identity<owned_pkey>{});
        }
    } load_engine_private_key;

    // load_engine_public_key
    struct : func<SSLPAFP(engine_load_public_key)> {
        using func<SSLPAFP(engine_load_public_key)>::func;

        constexpr auto operator()(engine eng, string_view key_id)
          const noexcept {
            return this->_cnvchkcall(eng, key_id, this->ui_openssl())
              .cast_to(type_identity<owned_pkey>{});
        }
    } load_engine_public_key;

    // ASN1
    // string
    struct : func<SSLPAFP(asn1_string_length)> {
        using func<SSLPAFP(asn1_string_length)>::func;

        constexpr auto operator()(asn1_string as) const noexcept {
            return this->_cnvchkcall(as).cast_to(type_identity<span_size_t>{});
        }
    } get_string_length;

    struct : func<SSLPAFP(asn1_string_get0_data)> {
        using func<SSLPAFP(asn1_string_get0_data)>::func;

        constexpr auto operator()(asn1_string as) const noexcept {
            return this->_cnvchkcall(as);
        }
    } get_string_data;

    auto get_string_block(asn1_string as) const noexcept
      -> memory::const_block {
        const auto data{get_string_data(as)};
        const auto size{get_string_length(as)};
        if(data && size) {
            return {extract(data), extract(size)};
        }
        return {};
    }

    auto get_string_view(asn1_string as) const noexcept {
        return as_chars(get_string_block(as));
    }

    // get_int64
    struct : func<SSLPAFP(asn1_integer_get_int64)> {
        using func<SSLPAFP(asn1_integer_get_int64)>::func;

        constexpr auto operator()(asn1_integer ai) const noexcept {
            std::int64_t result{};
            return this->_cnvchkcall(&result, ai).replaced_with(result);
        }
    } get_int64;

    // get_uint64
    struct : func<SSLPAFP(asn1_integer_get_uint64)> {
        using func<SSLPAFP(asn1_integer_get_uint64)>::func;

        constexpr auto operator()(asn1_integer ai) const noexcept {
            std::uint64_t result{};
            return this->_cnvchkcall(&result, ai).replaced_with(result);
        }
    } get_uint64;

    // object_to_text
    struct : func<SSLPAFP(obj_obj2txt)> {
        using func<SSLPAFP(obj_obj2txt)>::func;

        constexpr auto operator()(
          string_span dst,
          asn1_object obj,
          bool no_name = false) const noexcept {
            return head(
              dst,
              extract_or(
                this->_cnvchkcall(
                  dst.data(), limit_cast<int>(dst.size()), obj, no_name ? 1 : 0),
                0));
        }
    } object_to_text;

    // new_basic_io
    struct : func<SSLPAFP(bio_new)> {
        using func<SSLPAFP(bio_new)>::func;

        constexpr auto operator()(basic_io_method method) const noexcept {
            return this->_chkcall(method).cast_to(
              type_identity<owned_basic_io>{});
        }
    } new_basic_io;

    // new_block_basic_io
    struct : func<SSLPAFP(bio_new_mem_buf)> {
        using func<SSLPAFP(bio_new_mem_buf)>::func;

        constexpr auto operator()(memory::const_block blk) const noexcept {
            return this->_chkcall(blk.data(), limit_cast<int>(blk.size()))
              .cast_to(type_identity<owned_basic_io>{});
        }

    } new_block_basic_io;

    // delete_basic_io
    struct : func<SSLPAFP(bio_free)> {
        using func<SSLPAFP(bio_free)>::func;

        constexpr auto operator()(owned_basic_io& bio) const noexcept {
            return this->_chkcall(bio.release());
        }

        auto raii(owned_basic_io& bio) const noexcept {
            return eagine::finally([this, &bio]() { (*this)(bio); });
        }

    } delete_basic_io;

    // delete_all_basic_ios
    struct : func<SSLPAFP(bio_free_all)> {
        using func<SSLPAFP(bio_free_all)>::func;

        constexpr auto operator()(owned_basic_io& bio) const noexcept {
            return this->_chkcall(bio.release());
        }

        auto raii(owned_basic_io& bio) const noexcept {
            return eagine::finally([this, &bio]() { (*this)(bio); });
        }

    } delete_all_basic_ios;

    // random_bytes
    struct : func<SSLPAFP(rand_bytes)> {
        using func<SSLPAFP(rand_bytes)>::func;

        constexpr auto operator()(memory::block blk) const noexcept {
            return this->_cnvchkcall(blk.data(), limit_cast<int>(blk.size()));
        }

    } random_bytes;

    // copy_pkey
    struct : func<SSLPAFP(evp_pkey_up_ref)> {
        using func<SSLPAFP(evp_pkey_up_ref)>::func;

        constexpr auto operator()(pkey pky) const noexcept {
            return this->_cnvchkcall(pky).replaced_with(owned_pkey(pky));
        }
    } copy_pkey;

    // delete_pkey
    struct : func<SSLPAFP(evp_pkey_free)> {
        using func<SSLPAFP(evp_pkey_free)>::func;

        constexpr auto operator()(owned_pkey& pky) const noexcept {
            return this->_chkcall(pky.release());
        }

        auto raii(owned_pkey& pky) const noexcept {
            return eagine::finally([this, &pky]() { (*this)(pky); });
        }

    } delete_pkey;

    // cipher
    struct : func<SSLPAFP(evp_aes_128_ctr)> {
        using func<SSLPAFP(evp_aes_128_ctr)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<cipher_type>{});
        }
    } cipher_aes_128_ctr;

    struct : func<SSLPAFP(evp_aes_128_ccm)> {
        using func<SSLPAFP(evp_aes_128_ccm)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<cipher_type>{});
        }
    } cipher_aes_128_ccm;

    struct : func<SSLPAFP(evp_aes_128_gcm)> {
        using func<SSLPAFP(evp_aes_128_gcm)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<cipher_type>{});
        }
    } cipher_aes_128_gcm;

    struct : func<SSLPAFP(evp_aes_128_xts)> {
        using func<SSLPAFP(evp_aes_128_xts)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<cipher_type>{});
        }
    } cipher_aes_128_xts;

    struct : func<SSLPAFP(evp_aes_192_ecb)> {
        using func<SSLPAFP(evp_aes_192_ecb)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<cipher_type>{});
        }
    } cipher_aes_192_ecb;

    struct : func<SSLPAFP(evp_aes_192_cbc)> {
        using func<SSLPAFP(evp_aes_192_cbc)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<cipher_type>{});
        }
    } cipher_aes_192_cbc;

    // new_cipher
    struct : func<SSLPAFP(evp_cipher_ctx_new)> {
        using func<SSLPAFP(evp_cipher_ctx_new)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<owned_cipher>{});
        }
    } new_cipher;

    // delete_cipher
    struct : func<SSLPAFP(evp_cipher_ctx_free)> {
        using func<SSLPAFP(evp_cipher_ctx_free)>::func;

        constexpr auto operator()(owned_cipher& cyc) const noexcept {
            return this->_chkcall(cyc.release());
        }

        auto raii(owned_cipher& cyc) const noexcept {
            return eagine::finally([this, &cyc]() { (*this)(cyc); });
        }

    } delete_cipher;

    // cipher_reset
    struct : func<SSLPAFP(evp_cipher_ctx_reset)> {
        using func<SSLPAFP(evp_cipher_ctx_reset)>::func;

        constexpr auto operator()(cipher cyc) const noexcept {
            return this->_cnvchkcall(cyc);
        }

    } cipher_reset;

    // cipher_init
    struct : func<SSLPAFP(evp_cipher_init)> {
        using func<SSLPAFP(evp_cipher_init)>::func;

        constexpr auto operator()(
          cipher cyc,
          cipher_type cyt,
          memory::const_block key,
          memory::const_block iv,
          bool enc) const noexcept {
            return this->_cnvchkcall(
              cyc, cyt, key.data(), iv.data(), enc ? 1 : 0);
        }
    } cipher_init;

    // cipher_init_ex
    struct : func<SSLPAFP(evp_cipher_init_ex)> {
        using func<SSLPAFP(evp_cipher_init_ex)>::func;

        constexpr auto operator()(
          cipher cyc,
          cipher_type cyt,
          engine eng,
          memory::const_block key,
          memory::const_block iv,
          bool enc) const noexcept {
            return this->_cnvchkcall(
              cyc, cyt, eng, key.data(), iv.data(), enc ? 1 : 0);
        }
    } cipher_init_ex;

    // cipher_update
    struct : func<SSLPAFP(evp_cipher_update)> {
        using func<SSLPAFP(evp_cipher_update)>::func;

        constexpr auto operator()(
          cipher cyc,
          memory::split_block out,
          memory::const_block in) const noexcept {
            int outl{0};
            return this
              ->_cnvchkcall(
                cyc,
                out.tail().data(),
                &outl,
                in.data(),
                limit_cast<int>(in.size()))
              .replaced_with(out.advance(span_size(outl)));
        }

    } cipher_update;

    // cipher_final
    struct : func<SSLPAFP(evp_cipher_final)> {
        using func<SSLPAFP(evp_cipher_final)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } cipher_final;

    // cipher_final_ex
    struct : func<SSLPAFP(evp_cipher_final_ex)> {
        using func<SSLPAFP(evp_cipher_final_ex)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } cipher_final_ex;

    // encrypt_init
    struct : func<SSLPAFP(evp_encrypt_init)> {
        using func<SSLPAFP(evp_encrypt_init)>::func;

        constexpr auto operator()(
          cipher cyc,
          cipher_type cyt,
          memory::const_block key,
          memory::const_block iv,
          bool enc) const noexcept {
            return this->_cnvchkcall(
              cyc, cyt, key.data(), iv.data(), enc ? 1 : 0);
        }
    } encrypt_init;

    // encrypt_init_ex
    struct : func<SSLPAFP(evp_encrypt_init_ex)> {
        using func<SSLPAFP(evp_encrypt_init_ex)>::func;

        constexpr auto operator()(
          cipher cyc,
          cipher_type cyt,
          engine eng,
          memory::const_block key,
          memory::const_block iv,
          bool enc) const noexcept {
            return this->_cnvchkcall(
              cyc, cyt, eng, key.data(), iv.data(), enc ? 1 : 0);
        }
    } encrypt_init_ex;

    // encrypt_update
    struct : func<SSLPAFP(evp_encrypt_update)> {
        using func<SSLPAFP(evp_encrypt_update)>::func;

        constexpr auto operator()(
          cipher cyc,
          memory::split_block out,
          memory::const_block in) const noexcept {
            int outl{0};
            return this
              ->_cnvchkcall(
                cyc,
                out.tail().data(),
                &outl,
                in.data(),
                limit_cast<int>(in.size()))
              .replaced_with(out.advance(span_size(outl)));
        }

    } encrypt_update;

    // encrypt_final
    struct : func<SSLPAFP(evp_encrypt_final)> {
        using func<SSLPAFP(evp_encrypt_final)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } encrypt_final;

    // encrypt_final_ex
    struct : func<SSLPAFP(evp_encrypt_final_ex)> {
        using func<SSLPAFP(evp_encrypt_final_ex)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } encrypt_final_ex;

    // decrypt_init
    struct : func<SSLPAFP(evp_decrypt_init)> {
        using func<SSLPAFP(evp_decrypt_init)>::func;

        constexpr auto operator()(
          cipher cyc,
          cipher_type cyt,
          memory::const_block key,
          memory::const_block iv,
          bool enc) const noexcept {
            return this->_cnvchkcall(
              cyc, cyt, key.data(), iv.data(), enc ? 1 : 0);
        }
    } decrypt_init;

    // decrypt_init_ex
    struct : func<SSLPAFP(evp_decrypt_init_ex)> {
        using func<SSLPAFP(evp_decrypt_init_ex)>::func;

        constexpr auto operator()(
          cipher cyc,
          cipher_type cyt,
          engine eng,
          memory::const_block key,
          memory::const_block iv,
          bool enc) const noexcept {
            return this->_cnvchkcall(
              cyc, cyt, eng, key.data(), iv.data(), enc ? 1 : 0);
        }
    } decrypt_init_ex;

    // decrypt_update
    struct : func<SSLPAFP(evp_decrypt_update)> {
        using func<SSLPAFP(evp_decrypt_update)>::func;

        constexpr auto operator()(
          cipher cyc,
          memory::split_block out,
          memory::const_block in) const noexcept {
            int outl{0};
            return this
              ->_cnvchkcall(
                cyc,
                out.tail().data(),
                &outl,
                in.data(),
                limit_cast<int>(in.size()))
              .replaced_with(out.advance(span_size(outl)));
        }

    } decrypt_update;

    // decrypt_final
    struct : func<SSLPAFP(evp_decrypt_final)> {
        using func<SSLPAFP(evp_decrypt_final)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } decrypt_final;

    // decrypt_final_ex
    struct : func<SSLPAFP(evp_decrypt_final_ex)> {
        using func<SSLPAFP(evp_decrypt_final_ex)>::func;

        constexpr auto operator()(cipher cyc, memory::split_block out)
          const noexcept {
            int outl{0U};
            return this->_cnvchkcall(cyc, out.tail().data(), &outl)
              .replaced_with(out.advance(span_size(outl)));
        }
    } decrypt_final_ex;

    // message_digest
    struct : func<SSLPAFP(evp_md_null)> {
        using func<SSLPAFP(evp_md_null)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(
              type_identity<message_digest_type>{});
        }
    } message_digest_noop;

    struct : func<SSLPAFP(evp_md5)> {
        using func<SSLPAFP(evp_md5)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(
              type_identity<message_digest_type>{});
        }
    } message_digest_md5;

    struct : func<SSLPAFP(evp_sha1)> {
        using func<SSLPAFP(evp_sha1)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(
              type_identity<message_digest_type>{});
        }
    } message_digest_sha1;

    struct : func<SSLPAFP(evp_sha224)> {
        using func<SSLPAFP(evp_sha224)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(
              type_identity<message_digest_type>{});
        }
    } message_digest_sha224;

    struct : func<SSLPAFP(evp_sha256)> {
        using func<SSLPAFP(evp_sha256)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(
              type_identity<message_digest_type>{});
        }
    } message_digest_sha256;

    struct : func<SSLPAFP(evp_sha384)> {
        using func<SSLPAFP(evp_sha384)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(
              type_identity<message_digest_type>{});
        }
    } message_digest_sha384;

    struct : func<SSLPAFP(evp_sha512)> {
        using func<SSLPAFP(evp_sha512)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(
              type_identity<message_digest_type>{});
        }
    } message_digest_sha512;

    struct : func<SSLPAFP(evp_md_size)> {
        using func<SSLPAFP(evp_md_size)>::func;

        constexpr auto operator()(message_digest_type mdt) const noexcept {
            return this->_cnvchkcall(mdt);
        }
    } message_digest_size;

    // new_message_digest
    struct : func<SSLPAFP(evp_md_ctx_new)> {
        using func<SSLPAFP(evp_md_ctx_new)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(
              type_identity<owned_message_digest>{});
        }
    } new_message_digest;

    // delete_message_digest
    struct : func<SSLPAFP(evp_md_ctx_free)> {
        using func<SSLPAFP(evp_md_ctx_free)>::func;

        constexpr auto operator()(owned_message_digest& mdc) const noexcept {
            return this->_chkcall(mdc.release());
        }

        auto raii(owned_message_digest& mdc) const noexcept {
            return eagine::finally([this, &mdc]() { (*this)(mdc); });
        }

    } delete_message_digest;

    // message_digest_reset
    struct : func<SSLPAFP(evp_md_ctx_reset)> {
        using func<SSLPAFP(evp_md_ctx_reset)>::func;

        constexpr auto operator()(message_digest mdc) const noexcept {
            return this->_cnvchkcall(mdc);
        }

    } message_digest_reset;

    // message_digest_init
    struct : func<SSLPAFP(evp_digest_init)> {
        using func<SSLPAFP(evp_digest_init)>::func;

        constexpr auto operator()(message_digest mdc, message_digest_type mdt)
          const noexcept {
            return this->_cnvchkcall(mdc, mdt);
        }
    } message_digest_init;

    // message_digest_init_ex
    struct : func<SSLPAFP(evp_digest_init_ex)> {
        using func<SSLPAFP(evp_digest_init_ex)>::func;

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          engine eng) const noexcept {
            return this->_cnvchkcall(mdc, mdt, eng);
        }
    } message_digest_init_ex;

    // message_digest_update
    struct : func<SSLPAFP(evp_digest_update)> {
        using func<SSLPAFP(evp_digest_update)>::func;

        constexpr auto operator()(message_digest mdc, memory::const_block blk)
          const noexcept {
            return this->_cnvchkcall(mdc, blk.data(), std_size(blk.size()));
        }

    } message_digest_update;

    // message_digest_final
    struct : func<SSLPAFP(evp_digest_final)> {
        using func<SSLPAFP(evp_digest_final)>::func;

        constexpr auto operator()(message_digest mdc, memory::block blk)
          const noexcept {
            unsigned int size{0U};
            return this->_cnvchkcall(mdc, blk.data(), &size)
              .replaced_with(head(blk, span_size(size)));
        }
    } message_digest_final;

    // message_digest_final_ex
    struct : func<SSLPAFP(evp_digest_final_ex)> {
        using func<SSLPAFP(evp_digest_final_ex)>::func;

        constexpr auto operator()(message_digest mdc, memory::block blk)
          const noexcept {
            unsigned int size{0U};
            return this->_cnvchkcall(mdc, blk.data(), &size)
              .replaced_with(head(blk, span_size(size)));
        }
    } message_digest_final_ex;

    // message_digest_sign_init
    struct : func<SSLPAFP(evp_digest_sign_init)> {
        using func<SSLPAFP(evp_digest_sign_init)>::func;

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          pkey pky) const noexcept {
            return this->_cnvchkcall(mdc, nullptr, mdt, nullptr, pky);
        }

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          engine eng,
          pkey pky) const noexcept {
            return this->_cnvchkcall(mdc, nullptr, mdt, eng, pky);
        }
    } message_digest_sign_init;

    // message_digest_sign_update
    struct : func<SSLPAFP(evp_digest_sign_update)> {
        using func<SSLPAFP(evp_digest_sign_update)>::func;

        constexpr auto operator()(message_digest mdc, memory::const_block blk)
          const noexcept {
            return this->_cnvchkcall(mdc, blk.data(), std_size(blk.size()));
        }

    } message_digest_sign_update;

    // message_digest_sign_final
    struct : func<SSLPAFP(evp_digest_sign_final)> {
        using func<SSLPAFP(evp_digest_sign_final)>::func;

        constexpr auto required_size(message_digest mdc) const noexcept {
            size_t size{0U};
            return this->_cnvchkcall(mdc, nullptr, &size)
              .replaced_with(span_size(size));
        }

        constexpr auto operator()(message_digest mdc, memory::block blk)
          const noexcept {
            auto size = limit_cast<size_t>(blk.size());
            return this->_cnvchkcall(mdc, blk.data(), &size)
              .replaced_with(head(blk, span_size(size)));
        }
    } message_digest_sign_final;

    // message_digest_verify_init
    struct : func<SSLPAFP(evp_digest_verify_init)> {
        using func<SSLPAFP(evp_digest_verify_init)>::func;

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          pkey pky) const noexcept {
            return this->_cnvchkcall(mdc, nullptr, mdt, nullptr, pky);
        }

        constexpr auto operator()(
          message_digest mdc,
          message_digest_type mdt,
          engine eng,
          pkey pky) const noexcept {
            return this->_cnvchkcall(mdc, nullptr, mdt, eng, pky);
        }
    } message_digest_verify_init;

    // message_digest_verify_update
    struct : func<SSLPAFP(evp_digest_verify_update)> {
        using func<SSLPAFP(evp_digest_verify_update)>::func;

        constexpr auto operator()(message_digest mdc, memory::const_block blk)
          const noexcept {
            return this->_cnvchkcall(mdc, blk.data(), std_size(blk.size()));
        }

    } message_digest_verify_update;

    // message_digest_verify_final
    struct : func<SSLPAFP(evp_digest_verify_final)> {
        using func<SSLPAFP(evp_digest_verify_final)>::func;

        constexpr auto operator()(message_digest mdc, memory::const_block blk)
          const noexcept {
            return this->_cnvchkcall(mdc, blk.data(), std_size(blk.size()))
              .transformed([](int result) { return result == 1; });
        }
    } message_digest_verify_final;

    // new_x509_store_ctx
    struct : func<SSLPAFP(x509_store_ctx_new)> {
        using func<SSLPAFP(x509_store_ctx_new)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(
              type_identity<owned_x509_store_ctx>{});
        }
    } new_x509_store_ctx;

    // init_x509_store_ctx
    struct : func<SSLPAFP(x509_store_ctx_init)> {
        using func<SSLPAFP(x509_store_ctx_init)>::func;

        constexpr auto operator()(x509_store_ctx xsc, x509_store xst, x509 crt)
          const noexcept {
            return this->_cnvchkcall(xsc, xst, crt, nullptr);
        }

        constexpr auto operator()(
          x509_store_ctx xsc,
          x509_store xst,
          x509 crt,
          const object_stack<x509>& chain) const noexcept {
            return this->_cnvchkcall(xsc, xst, crt, chain);
        }

    } init_x509_store_ctx;

    // set_x509_store_trusted_stack
    struct : func<SSLPAFP(x509_store_ctx_set0_trusted_stack)> {
        using func<SSLPAFP(x509_store_ctx_set0_trusted_stack)>::func;

        constexpr auto operator()(
          x509_store_ctx xsc,
          const object_stack<x509>& stk) const noexcept {
            return this->_cnvchkcall(xsc, stk);
        }

    } set_x509_store_trusted_stack;

    // set_x509_store_verified_chain
    struct : func<SSLPAFP(x509_store_ctx_set0_verified_chain)> {
        using func<SSLPAFP(x509_store_ctx_set0_verified_chain)>::func;

        constexpr auto operator()(
          x509_store_ctx xsc,
          const object_stack<x509>& stk) const noexcept {
            return this->_cnvchkcall(xsc, stk);
        }

    } set_x509_store_verified_chain;

    // set_x509_store_untrusted
    struct : func<SSLPAFP(x509_store_ctx_set0_untrusted)> {
        using func<SSLPAFP(x509_store_ctx_set0_untrusted)>::func;

        constexpr auto operator()(
          x509_store_ctx xsc,
          const object_stack<x509>& stk) const noexcept {
            return this->_cnvchkcall(xsc, stk);
        }

    } set_x509_store_untrusted;

    // cleanup_x509_store_ctx
    struct : func<SSLPAFP(x509_store_ctx_cleanup)> {
        using func<SSLPAFP(x509_store_ctx_cleanup)>::func;

        constexpr auto operator()(x509_store_ctx xsc) const noexcept {
            return this->_chkcall(xsc);
        }

        auto raii(x509_store_ctx xsc) const noexcept {
            return eagine::finally([this, xsc]() { (*this)(xsc); });
        }

    } cleanup_x509_store_ctx;

    // delete_x509_store_ctx
    struct : func<SSLPAFP(x509_store_ctx_free)> {
        using func<SSLPAFP(x509_store_ctx_free)>::func;

        constexpr auto operator()(owned_x509_store_ctx& xsc) const noexcept {
            return this->_chkcall(xsc.release());
        }

        auto raii(owned_x509_store_ctx& xsc) const noexcept {
            return eagine::finally([this, &xsc]() { (*this)(xsc); });
        }

    } delete_x509_store_ctx;

    // x509_verify_certificate
    struct : func<SSLPAFP(x509_verify_cert)> {
        using func<SSLPAFP(x509_verify_cert)>::func;

        constexpr auto operator()(x509_store_ctx xsc) const noexcept {
            return collapse_bool(this->_cnvchkcall(xsc));
        }

    } x509_verify_certificate;

    // new_x509_store
    struct : func<SSLPAFP(x509_store_new)> {
        using func<SSLPAFP(x509_store_new)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<owned_x509_store>{});
        }
    } new_x509_store;

    // copy_x509_store
    struct : func<SSLPAFP(x509_store_up_ref)> {
        using func<SSLPAFP(x509_store_up_ref)>::func;

        constexpr auto operator()(x509_store xst) const noexcept {
            return this->_chkcall().replaced_with(owned_x509_store{xst});
        }
    } copy_x509_store;

    // delete_x509_store
    struct : func<SSLPAFP(x509_store_free)> {
        using func<SSLPAFP(x509_store_free)>::func;

        constexpr auto operator()(owned_x509_store& xst) const noexcept {
            return this->_chkcall(xst.release());
        }

        auto raii(owned_x509_store& xst) const noexcept {
            return eagine::finally([this, &xst]() { (*this)(xst); });
        }

    } delete_x509_store;

    // add_cert_into_x509_store
    struct : func<SSLPAFP(x509_store_add_cert)> {
        using func<SSLPAFP(x509_store_add_cert)>::func;

        constexpr auto operator()(x509_store xst, x509 crt) const noexcept {
            return this->_cnvchkcall(xst, crt);
        }

    } add_cert_into_x509_store;

    // add_crl_into_x509_store
    struct : func<SSLPAFP(x509_store_add_crl)> {
        using func<SSLPAFP(x509_store_add_crl)>::func;

        constexpr auto operator()(x509_store xst, x509_crl crl) const noexcept {
            return this->_cnvchkcall(xst, crl);
        }

    } add_crl_into_x509_store;

    // load_into_x509_store
    struct : func<SSLPAFP(x509_store_load_locations)> {
        using func<SSLPAFP(x509_store_load_locations)>::func;

        constexpr auto operator()(x509_store xst, string_view file_path)
          const noexcept {
            return this->_cnvchkcall(xst, file_path, nullptr);
        }

    } load_into_x509_store;

    // new_x509_crl
    struct : func<SSLPAFP(x509_crl_new)> {
        using func<SSLPAFP(x509_crl_new)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<owned_x509_crl>{});
        }
    } new_x509_crl;

    // delete_x509_crl
    struct : func<SSLPAFP(x509_crl_free)> {
        using func<SSLPAFP(x509_crl_free)>::func;

        constexpr auto operator()(owned_x509_crl& crl) const noexcept {
            return this->_chkcall(crl.release());
        }

        auto raii(owned_x509_crl& crl) const noexcept {
            return eagine::finally([this, &crl]() { (*this)(crl); });
        }

    } delete_x509_crl;

    // new_x509
    struct : func<SSLPAFP(x509_new)> {
        using func<SSLPAFP(x509_new)>::func;

        constexpr auto operator()() const noexcept {
            return this->_chkcall().cast_to(type_identity<owned_x509>{});
        }
    } new_x509;

    // get_x509_pubkey
    struct : func<SSLPAFP(x509_get_pubkey)> {
        using func<SSLPAFP(x509_get_pubkey)>::func;

        constexpr auto operator()(x509 crt) const noexcept {
            return this->_cnvchkcall(crt).cast_to(type_identity<owned_pkey>{});
        }
    } get_x509_pubkey;

    // get_x509_serial_number
    struct : func<SSLPAFP(x509_get0_serial_number)> {
        using func<SSLPAFP(x509_get0_serial_number)>::func;

        constexpr auto operator()(x509 crt) const noexcept {
            return this->_cnvchkcall(crt).cast_to(
              type_identity<asn1_integer>{});
        }
    } get_x509_serial_number;

    // get_x509_issuer_name
    struct : func<SSLPAFP(x509_get_issuer_name)> {
        using func<SSLPAFP(x509_get_issuer_name)>::func;

        constexpr auto operator()(x509 crt) const noexcept {
            return this->_cnvchkcall(crt).cast_to(type_identity<x509_name>{});
        }
    } get_x509_issuer_name;

    // get_x509_subject_name
    struct : func<SSLPAFP(x509_get_subject_name)> {
        using func<SSLPAFP(x509_get_subject_name)>::func;

        constexpr auto operator()(x509 crt) const noexcept {
            return this->_cnvchkcall(crt).cast_to(type_identity<x509_name>{});
        }
    } get_x509_subject_name;

    // delete_x509
    struct : func<SSLPAFP(x509_free)> {
        using func<SSLPAFP(x509_free)>::func;

        constexpr auto operator()(owned_x509& crt) const noexcept {
            return this->_chkcall(crt.release());
        }

        auto raii(owned_x509& crt) const noexcept {
            return eagine::finally([this, &crt]() { (*this)(crt); });
        }

    } delete_x509;

    // get_name_entry_count
    struct : func<SSLPAFP(x509_name_entry_count)> {
        using func<SSLPAFP(x509_name_entry_count)>::func;

        constexpr auto operator()(x509_name n) const noexcept {
            return this->_cnvchkcall(n).cast_to(type_identity<span_size_t>{});
        }
    } get_name_entry_count;

    // get_name_entry
    struct : func<SSLPAFP(x509_name_get_entry)> {
        using func<SSLPAFP(x509_name_get_entry)>::func;

        constexpr auto operator()(x509_name n, span_size_t i) const noexcept {
            return this->_cnvchkcall(n, limit_cast<int>(i))
              .cast_to(type_identity<x509_name_entry>{});
        }
    } get_name_entry;

    // get_name_entry_object
    struct : func<SSLPAFP(x509_name_entry_get_object)> {
        using func<SSLPAFP(x509_name_entry_get_object)>::func;

        constexpr auto operator()(x509_name_entry ne) const noexcept {
            return this->_cnvchkcall(ne).cast_to(type_identity<asn1_object>{});
        }
    } get_name_entry_object;

    // get_name_entry_data
    struct : func<SSLPAFP(x509_name_entry_get_data)> {
        using func<SSLPAFP(x509_name_entry_get_data)>::func;

        constexpr auto operator()(x509_name_entry ne) const noexcept {
            return this->_cnvchkcall(ne).cast_to(type_identity<asn1_string>{});
        }
    } get_name_entry_data;

    // read_bio_private_key
    struct : func<SSLPAFP(pem_read_bio_private_key)> {
        using func<SSLPAFP(pem_read_bio_private_key)>::func;

        constexpr auto operator()(basic_io bio) const noexcept {
            return this->_cnvchkcall(bio, nullptr, nullptr, nullptr)
              .cast_to(type_identity<owned_pkey>{});
        }

        constexpr auto operator()(basic_io bio, password_callback get_passwd)
          const noexcept {
            return this
              ->_cnvchkcall(
                bio, nullptr, get_passwd.native_func(), get_passwd.native_data())
              .cast_to(type_identity<owned_pkey>{});
        }

    } read_bio_private_key;

    // read_bio_public_key
    struct : func<SSLPAFP(pem_read_bio_pubkey)> {
        using func<SSLPAFP(pem_read_bio_pubkey)>::func;

        constexpr auto operator()(basic_io bio) const noexcept {
            return this->_cnvchkcall(bio, nullptr, nullptr, nullptr)
              .cast_to(type_identity<owned_pkey>{});
        }

        constexpr auto operator()(basic_io bio, password_callback get_passwd)
          const noexcept {
            return this
              ->_cnvchkcall(
                bio, nullptr, get_passwd.native_func(), get_passwd.native_data())
              .cast_to(type_identity<owned_pkey>{});
        }

    } read_bio_public_key;

    // read_bio_x509_crl
    struct : func<SSLPAFP(pem_read_bio_x509_crl)> {
        using func<SSLPAFP(pem_read_bio_x509_crl)>::func;

        constexpr auto operator()(basic_io bio) const noexcept {
            return this->_cnvchkcall(bio, nullptr, nullptr, nullptr)
              .cast_to(type_identity<owned_x509_crl>{});
        }

        constexpr auto operator()(basic_io bio, password_callback get_passwd)
          const noexcept {
            return this
              ->_cnvchkcall(
                bio, nullptr, get_passwd.native_func(), get_passwd.native_data())
              .cast_to(type_identity<owned_x509_crl>{});
        }

    } read_bio_x509_crl;

    // read_bio_x509
    struct : func<SSLPAFP(pem_read_bio_x509)> {
        using func<SSLPAFP(pem_read_bio_x509)>::func;

        constexpr auto operator()(basic_io bio) const noexcept {
            return this->_cnvchkcall(bio, nullptr, nullptr, nullptr)
              .cast_to(type_identity<owned_x509>{});
        }

        constexpr auto operator()(basic_io bio, password_callback get_passwd)
          const noexcept {
            return this
              ->_cnvchkcall(
                bio, nullptr, get_passwd.native_func(), get_passwd.native_data())
              .cast_to(type_identity<owned_x509>{});
        }

    } read_bio_x509;

    basic_ssl_operations(api_traits& traits);
};
//------------------------------------------------------------------------------
#undef SSLPAFP
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

#endif // EAGINE_SSLPLUS_API_API_HPP
