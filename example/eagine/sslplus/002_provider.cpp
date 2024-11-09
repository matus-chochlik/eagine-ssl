/// @example eagine/sslplus/002_provider.cpp
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
/// https://www.boost.org/LICENSE_1_0.txt
///
import eagine.core;
import eagine.sslplus;

namespace eagine {
//------------------------------------------------------------------------------
auto main(main_ctx& ctx) -> int {
    const sslplus::ssl_api ssl{ctx};

    string_view provider_name{"default"};
    if(const auto arg{ctx.args().find("--provider").next()}) {
        provider_name = arg;
    }

    if(const ok provider{ssl.load_provider({}, provider_name)}) {
        ctx.log()
          .error("found provider '${name}'")
          .arg("name", ssl.get_provider_name(provider).or_default());
    } else {
        ctx.log()
          .error("failed to load provider '${name}'")
          .arg("name", provider_name);
    }

    return 0;
}
//------------------------------------------------------------------------------
} // namespace eagine

auto main(int argc, const char** argv) -> int {
    return eagine::default_main(argc, argv, eagine::main);
}
