/// @example eagine/sslplus/005_random_engine.cpp
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
/// https://www.boost.org/LICENSE_1_0.txt
///
import eagine.core;
import eagine.sslplus;
import std;

namespace eagine {
//------------------------------------------------------------------------------
auto main(main_ctx& ctx) -> int {

    const auto& log = ctx.log();
    const sslplus::ssl_api ssl{ctx};

    string_view engine_id("rdrand");

    ssl.load_builtin_engines();

    if(ok engine{ssl.open_engine(engine_id)}) {
        const auto del_eng = ssl.delete_engine.raii(engine);

        if(const auto init_result{ssl.init_engine(engine)}) {
            const auto fin_eng = ssl.finish_engine.raii(engine);

            if(const auto set_result{ssl.set_default_rand(engine)}) {
                std::array<byte, 256> temp{};
                if(const auto rand_result{ssl.random_bytes(cover(temp))}) {
                    ctx.cio()
                      .print(
                        identifier{"ssl"},
                        "got ${size} random bytes from engine ${id}")
                      .arg(identifier{"size"}, temp.size())
                      .arg(identifier{"id"}, engine_id)
                      .arg(identifier{"bytes"}, view(temp));
                } else {
                    log.error("failed to get random bytes from ${id}: ${reason}")
                      .arg(identifier{"id"}, engine_id)
                      .arg(identifier{"reason"}, rand_result.message());
                }
            } else {
                log.error("failed to set ${id} as random engine: ${reason}")
                  .arg(identifier{"id"}, engine_id)
                  .arg(identifier{"reason"}, set_result.message());
            }
        } else {
            log.error("failed to init ssl engine ${id}: ${reason}")
              .arg(identifier{"id"}, engine_id)
              .arg(identifier{"reason"}, init_result.message());
        }
    } else {
        log.error("failed to open ssl engine ${id}")
          .arg(identifier{"id"}, engine_id);
    }

    return 0;
}
//------------------------------------------------------------------------------
} // namespace eagine

auto main(int argc, const char** argv) -> int {
    return eagine::default_main(argc, argv, eagine::main);
}
