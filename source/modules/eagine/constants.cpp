/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
/// https://www.boost.org/LICENSE_1_0.txt
///
export module eagine.sslplus:constants;

import :c_api;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
export template <typename ApiTraits>
struct basic_ssl_constants {
public:
    basic_ssl_constants(ApiTraits&, basic_ssl_c_api<ApiTraits>&) {}
};
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
