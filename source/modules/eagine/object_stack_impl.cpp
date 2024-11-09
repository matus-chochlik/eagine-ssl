/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
/// https://www.boost.org/LICENSE_1_0.txt
///
module;

#if __has_include(<openssl/x509.h>)
#include <openssl/x509.h>

#define EAGINE_HAS_SSL 1
#else
#define EAGINE_HAS_SSL 0
#endif

module eagine.sslplus;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
auto stack_api<x509_tag>::unpack(x509 obj) const noexcept -> element_type* {
#if EAGINE_HAS_SSL
    return static_cast<element_type*>(obj);
#else
    return nullptr;
#endif
}
//------------------------------------------------------------------------------
auto stack_api<x509_tag>::new_null() const noexcept -> stack_type* {
#if EAGINE_HAS_SSL
    return sk_X509_new_null();
#else
    return nullptr;
#endif
}
//------------------------------------------------------------------------------
void stack_api<x509_tag>::free(stack_type* h) const noexcept {
#if EAGINE_HAS_SSL
    return OPENSSL_sk_free(reinterpret_cast<OPENSSL_STACK*>(h));
#endif
}
//------------------------------------------------------------------------------
auto stack_api<x509_tag>::num(stack_type* h) const noexcept -> int {
#if EAGINE_HAS_SSL
    return OPENSSL_sk_num(reinterpret_cast<const OPENSSL_STACK*>(h));
#else
    return 0;
#endif
}
//------------------------------------------------------------------------------
auto stack_api<x509_tag>::push(stack_type* h, element_type* e) const noexcept
  -> int {
#if EAGINE_HAS_SSL
    return OPENSSL_sk_push(reinterpret_cast<OPENSSL_STACK*>(h), e);
#else
    return 1;
#endif
}
//------------------------------------------------------------------------------
auto stack_api<x509_tag>::push_up_ref(stack_type* h, element_type* e) const noexcept
  -> int {
#if EAGINE_HAS_SSL
    X509_up_ref(e);
    return OPENSSL_sk_push(reinterpret_cast<OPENSSL_STACK*>(h), e);
#else
    return 1;
#endif
}
//------------------------------------------------------------------------------
auto stack_api<x509_tag>::pop(stack_type* h) const noexcept -> element_type* {
#if EAGINE_HAS_SSL
    return static_cast<element_type*>(
      OPENSSL_sk_pop(reinterpret_cast<OPENSSL_STACK*>(h)));
#else
    return nullptr;
#endif
}
//------------------------------------------------------------------------------
void stack_api<x509_tag>::pop_free(stack_type* h) const noexcept {
#if EAGINE_HAS_SSL
    OPENSSL_sk_pop_free(
      reinterpret_cast<OPENSSL_STACK*>(h),
      reinterpret_cast<void (*)(void*)>(&X509_free));
#endif
}
//------------------------------------------------------------------------------
auto stack_api<x509_tag>::set(stack_type* h, const int i, element_type* e)
  const noexcept -> element_type* {
#if EAGINE_HAS_SSL
    return static_cast<element_type*>(
      OPENSSL_sk_set(reinterpret_cast<OPENSSL_STACK*>(h), i, e));
#else
    return nullptr;
#endif
}
//------------------------------------------------------------------------------
auto stack_api<x509_tag>::value(stack_type* h, const int i) noexcept
  -> element_type* {
#if EAGINE_HAS_SSL
    return static_cast<element_type*>(
      OPENSSL_sk_value(reinterpret_cast<OPENSSL_STACK*>(h), i));
#else
    return nullptr;
#endif
}
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
