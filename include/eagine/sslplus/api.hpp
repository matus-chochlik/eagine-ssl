/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#ifndef EAGINE_SSLPLUS_API_HPP
#define EAGINE_SSLPLUS_API_HPP

#include "api/api.hpp"
#include "api/api_traits.hpp"
#include "api/constants.hpp"
#include "api_fwd.hpp"
#include <eagine/memory/block.hpp>

namespace eagine::sslplus {
//------------------------------------------------------------------------------
template <typename ApiTraits>
class basic_ssl_api
  : protected ApiTraits
  , public basic_ssl_operations<ApiTraits>
  , public basic_ssl_constants<ApiTraits> {
public:
    template <typename R>
    using combined_result = typename ApiTraits::template combined_result<R>;

    using evp_md_type = ssl_types::evp_md_type;

    basic_ssl_api(ApiTraits traits)
      : ApiTraits{std::move(traits)}
      , basic_ssl_operations<ApiTraits>{*static_cast<ApiTraits*>(this)}
      , basic_ssl_constants<ApiTraits>{
          *static_cast<ApiTraits*>(this),
          *static_cast<basic_ssl_operations<ApiTraits>*>(this)} {}

    basic_ssl_api()
      : basic_ssl_api{ApiTraits{}} {}

    template <typename Function>
    void for_each_engine(Function function) const {
        if(auto opt_eng = this->get_first_engine()) {
            owned_engine eng = std::move(extract(opt_eng));
            while(eng) {
                function(engine(eng));
                opt_eng = this->get_next_engine(eng);
                if(opt_eng) {
                    eng = std::move(extract(opt_eng));
                }
            }
        }
    }

    auto data_digest(
      memory::const_block data,
      memory::block dst,
      message_digest_type mdtype) const noexcept -> memory::block;

    template <typename OptMdt>
    auto do_data_digest(
      memory::const_block data,
      memory::block dst,
      OptMdt opt_mdtype) const noexcept -> memory::block {
        if(opt_mdtype) {
            return data_digest(data, dst, extract(opt_mdtype));
        }
        return {};
    }

    auto md5_digest(memory::const_block data, memory::block dst) const noexcept {
        return do_data_digest(data, dst, this->message_digest_md5());
    }

    auto
    sha1_digest(memory::const_block data, memory::block dst) const noexcept {
        return do_data_digest(data, dst, this->message_digest_sha1());
    }

    auto
    sha224_digest(memory::const_block data, memory::block dst) const noexcept {
        return do_data_digest(data, dst, this->message_digest_sha224());
    }

    auto
    sha256_digest(memory::const_block data, memory::block dst) const noexcept {
        return do_data_digest(data, dst, this->message_digest_sha256());
    }

    auto
    sha384_digest(memory::const_block data, memory::block dst) const noexcept {
        return do_data_digest(data, dst, this->message_digest_sha384());
    }

    auto
    sha512_digest(memory::const_block data, memory::block dst) const noexcept {
        return do_data_digest(data, dst, this->message_digest_sha512());
    }

    auto sign_data_digest(
      memory::const_block data,
      memory::block dst,
      message_digest_type mdtype,
      pkey pky) const noexcept -> memory::block;

    auto verify_data_digest(
      memory::const_block data,
      memory::const_block sig,
      message_digest_type mdtype,
      pkey pky) const noexcept -> bool;

    auto parse_private_key(
      memory::const_block blk,
      password_callback get_passwd = {}) const noexcept
      -> combined_result<owned_pkey>;

    auto parse_public_key(
      memory::const_block blk,
      password_callback get_passwd = {}) const noexcept
      -> combined_result<owned_pkey>;

    auto parse_x509(memory::const_block blk, password_callback get_passwd = {})
      const noexcept -> combined_result<owned_x509>;

    auto ca_verify_certificate(string_view ca_file_path, x509) const noexcept
      -> bool;

    auto ca_verify_certificate(x509 ca_cert, x509) const noexcept -> bool;
};
//------------------------------------------------------------------------------
template <std::size_t I, typename ApiTraits>
auto get(basic_ssl_api<ApiTraits>& x) noexcept ->
  typename std::tuple_element<I, basic_ssl_api<ApiTraits>>::type& {
    return x;
}

template <std::size_t I, typename ApiTraits>
auto get(const basic_ssl_api<ApiTraits>& x) noexcept -> const
  typename std::tuple_element<I, basic_ssl_api<ApiTraits>>::type& {
    return x;
}
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

#include <eagine/sslplus/api.inl>

// NOLINTNEXTLINE(cert-dcl58-cpp)
namespace std {
//------------------------------------------------------------------------------
template <typename ApiTraits>
struct tuple_size<eagine::sslplus::basic_ssl_api<ApiTraits>>
  : public std::integral_constant<std::size_t, 2> {};

template <typename ApiTraits>
struct tuple_element<0, eagine::sslplus::basic_ssl_api<ApiTraits>> {
    using type = eagine::sslplus::basic_ssl_operations<ApiTraits>;
};

template <typename ApiTraits>
struct tuple_element<1, eagine::sslplus::basic_ssl_api<ApiTraits>> {
    using type = eagine::sslplus::basic_ssl_constants<ApiTraits>;
};
//------------------------------------------------------------------------------
} // namespace std

#endif // EAGINE_SSLPLUS_API_HPP
