/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
/// https://www.boost.org/LICENSE_1_0.txt
///
export module eagine.sslplus:resources;
import eagine.core;

namespace eagine {
//------------------------------------------------------------------------------
export auto ca_certificate_pem(
  const memory::const_block embedded_blk,
  memory::buffer& buf,
  application_config& cfg,
  const logger& log) noexcept -> memory::const_block {
    return fetch_resource(
      string_view{"CA certificate"},
      string_view{"ca_cert_path"},
      embedded_blk,
      buf,
      cfg,
      log);
}
//------------------------------------------------------------------------------
export auto ca_certificate_pem(
  const memory::const_block embedded_blk,
  main_ctx& ctx) noexcept -> memory::const_block {
    return ca_certificate_pem(
      embedded_blk, ctx.scratch_space(), ctx.config(), ctx.log());
}
//------------------------------------------------------------------------------
} // namespace eagine
