/// @example eagine/sslplus/004_verify_cert.cpp
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

    string_view cert_path{"example.crt"};
    if(const auto arg{ctx.args().find("--cert").next()}) {
        cert_path = arg;
    }
    const memory::const_block ca_cert_pem{
      eagine::embed<"caCert">("example-ca.crt")};

    const sslplus::ssl_api ssl{ctx};

    if(ok ca_cert{ssl.parse_x509(ca_cert_pem, {})}) {
        const auto del_ca_cert{ssl.delete_x509.raii(ca_cert)};

        if(const auto subname{ssl.get_x509_subject_name(ca_cert)}) {
            const auto count{*ssl.get_name_entry_count(*subname)};
            const auto entry_cio{
              ctx.cio()
                .print(identifier{"ssl"}, "CA certificate common name entries:")
                .to_be_continued()};

            for(const auto index : integer_range(count)) {
                if(const auto entry{ssl.get_name_entry(*subname, index)}) {
                    const auto object{ssl.get_name_entry_object(*entry)};
                    const auto value{ssl.get_name_entry_data(*entry)};

                    std::array<char, 96> namebuf{};
                    const auto name{
                      ssl.get_object_text(cover(namebuf), *object, false)};

                    entry_cio.print("${index}: ${attribute}=${value}")
                      .arg(identifier{"index"}, index)
                      .arg(identifier{"attribute"}, name)
                      .arg(identifier{"value"}, ssl.get_string_view(*value));
                }
            }
        }

        file_contents cert_pem{cert_path};
        if(ok cert{ssl.parse_x509(cert_pem, {})}) {
            const auto del_cert{ssl.delete_x509.raii(cert)};

            if(ssl.ca_verify_certificate(ca_cert, cert)) {
                if(const auto subname{ssl.get_x509_subject_name(cert)}) {
                    const auto count{*ssl.get_name_entry_count(*subname)};
                    ctx.cio()
                      .print(
                        identifier{"ssl"},
                        "successfully verified certificate ${certPath}")
                      .arg(identifier{"certPath"}, identifier{"FsPath"}, cert_path)
                      .arg(identifier{"snEntCount"}, count);
                    const auto entry_cio{
                      ctx.cio()
                        .print(
                          identifier{"ssl"}, "certificate common name entries:")
                        .to_be_continued()};

                    for(const auto index : integer_range(count)) {
                        if(const auto entry{ssl.get_name_entry(*subname, index)}) {
                            const auto object{ssl.get_name_entry_object(*entry)};
                            const auto value{ssl.get_name_entry_data(*entry)};

                            std::array<char, 96> namebuf{};
                            const auto name{
                              ssl.get_object_text(cover(namebuf), *object, false)};

                            entry_cio.print("${index}: ${attribute}=${value}")
                              .arg(identifier{"index"}, index)
                              .arg(identifier{"attribute"}, name)
                              .arg(
                                identifier{"value"}, ssl.get_string_view(*value));
                        }
                    }
                } else {
                    ctx.log()
                      .error("failed to get certificate ${certPath} serial number")
                      .arg(identifier{"certPath"}, identifier{"FsPath"}, cert_path);
                }
            } else {
                ctx.log()
                  .error("failed to verify certificate ${certPath}")
                  .arg(identifier{"certPath"}, identifier{"FsPath"}, cert_path);
            }
        } else {
            ctx.log()
              .error("failed to load certificate ${certPath}")
              .arg(identifier{"certPath"}, identifier{"FsPath"}, cert_path);
        }
    }

    return 0;
}
//------------------------------------------------------------------------------
} // namespace eagine

auto main(int argc, const char** argv) -> int {
    return eagine::default_main(argc, argv, eagine::main);
}
