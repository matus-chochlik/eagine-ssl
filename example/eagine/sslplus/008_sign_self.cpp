/// @example eagine/sslplus/008_sign_self.cpp
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
    file_contents data(ctx.exe_path());
    std::array<byte, 1024> temp{};

    string_view engine_id("pkcs11");
    if(const auto arg{ctx.args().find("--engine").next()}) {
        engine_id = arg;
    }

    string_view key_id("pkcs11:token=user;object=user;");
    if(const auto arg{ctx.args().find("--key").next()}) {
        key_id = arg;
    }

    const sslplus::ssl_api ssl{ctx};

    ssl.load_builtin_engines();

    if(ok engine{ssl.open_engine(engine_id)}) {
        const auto del_eng{ssl.delete_engine.raii(engine)};

        if(auto init_result{ssl.init_engine(engine)}) {
            const auto fin_eng{ssl.finish_engine.raii(engine)};

            if(ok pkey{ssl.load_engine_private_key(
                 engine, key_id, ok{ssl.openssl_ui()})}) {
                const auto del_pkey{ssl.delete_pkey.raii(pkey)};

                if(ok md{ssl.message_digest_sha256()}) {

                    if(const auto sig{
                         ssl.sign_data_digest(data, cover(temp), md, pkey)}) {

                        ctx.cio()
                          .print(identifier{"ssl"}, "signature of self (${size})")
                          .arg(
                            identifier{"size"}, identifier{"ByseSize"}, sig.size())
                          .arg(identifier{"signature"}, memory::const_block{sig});

                        if(ssl.verify_data_digest(data, sig, md, pkey)) {
                            ctx.cio().print(
                              identifier{"ssl"}, "signature verified");
                        } else {
                            log.error("failed to verify data signature")
                              .arg(identifier{"keyId"}, key_id)
                              .arg(identifier{"engineId"}, engine_id);
                        }
                    } else {
                        log.error("failed to sign data")
                          .arg(identifier{"keyId"}, key_id)
                          .arg(identifier{"engineId"}, engine_id);
                    }
                } else {
                    log.error("failed to get message digest: ${reason}")
                      .arg(identifier{"engineId"}, engine_id)
                      .arg(identifier{"reason"}, (not md).message());
                }
            } else {
                log.error("failed to load key ${keyID} from engine: ${reason}")
                  .arg(identifier{"keyId"}, key_id)
                  .arg(identifier{"engineId"}, engine_id)
                  .arg(identifier{"reason"}, (not pkey).message());
            }

        } else {
            log.error("failed to init ssl engine ${engineId}: ${reason}")
              .arg(identifier{"engineId"}, engine_id)
              .arg(identifier{"reason"}, init_result.message());
        }
    } else {
        log.error("failed to open ssl engine ${engineId}")
          .arg(identifier{"engineId"}, engine_id);
    }

    return 0;
}
//------------------------------------------------------------------------------
} // namespace eagine

auto main(int argc, const char** argv) -> int {
    return eagine::default_main(argc, argv, eagine::main);
}
