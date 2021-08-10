/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
///  http://www.boost.org/LICENSE_1_0.txt
///
#ifndef EAGINE_SSLPLUS_API_OBJECT_STACK_HPP
#define EAGINE_SSLPLUS_API_OBJECT_STACK_HPP

#include "object_handle.hpp"
#include <eagine/assert.hpp>
#include <utility>

namespace eagine::sslplus {
//------------------------------------------------------------------------------
template <typename Handle>
class object_stack;
//------------------------------------------------------------------------------
template <typename Tag>
class object_stack<basic_handle<Tag, nothing_t*, nullptr>> {
public:
    constexpr auto size() const noexcept -> int {
        return 0;
    }

    constexpr auto push(basic_handle<Tag, nothing_t*, nullptr>) -> auto& {
        return *this;
    }

    constexpr auto pop() -> auto& {
        return *this;
    }

    constexpr auto get(const int) -> basic_handle<Tag, nothing_t*, nullptr> {
        return {};
    }

    constexpr auto native() const noexcept -> nothing_t* {
        return nullptr;
    }
};
//------------------------------------------------------------------------------
#if EAGINE_HAS_SSL
//------------------------------------------------------------------------------
template <typename Tag>
struct stack_api;
//------------------------------------------------------------------------------
template <>
struct stack_api<x509_tag> {
    using stack_type = STACK_OF(X509);
    using element_type = ::X509;

    static auto unpack(x509 obj) noexcept -> auto* {
        return static_cast<::X509*>(obj);
    }

    static auto new_null() noexcept -> auto* {
        return sk_X509_new_null();
    }

    static auto free(stack_type* h) noexcept {
        return sk_X509_free(h);
    }

    static auto num(stack_type* h) noexcept {
        return sk_X509_num(h);
    }

    static auto push(stack_type* h, element_type* e) noexcept {
        return sk_X509_push(h, e);
    }

    static auto push_up_ref(stack_type* h, element_type* e) noexcept {
        X509_up_ref(e);
        return sk_X509_push(h, e);
    }

    static auto pop(stack_type* h) noexcept -> auto* {
        return sk_X509_pop(h);
    }

    static auto pop_free(stack_type* h) noexcept {
        return sk_X509_pop_free(h, &X509_free);
    }

    static auto set(stack_type* h, const int i, element_type* e) noexcept {
        return sk_X509_set(h, i, e);
    }

    static auto value(stack_type* h, const int i) noexcept -> auto* {
        return sk_X509_value(h, i);
    }
};
//------------------------------------------------------------------------------
// object_stack_base
//------------------------------------------------------------------------------
template <typename Handle>
class object_stack_base;

template <typename Tag, typename T>
class object_stack_base<basic_handle<Tag, T*, nullptr>> : stack_api<Tag> {
protected:
    typename stack_api<Tag>::stack_type* _top{nullptr};

    auto _api() const noexcept -> const stack_api<Tag>& {
        return *this;
    }

    object_stack_base(typename stack_api<Tag>::stack_type* top) noexcept
      : _top{top} {}

    auto _idx_ok(const int i) const noexcept -> bool {
        return (i >= 0) && (i < size());
    }

    ~object_stack_base() noexcept = default;

public:
    using wrapper = basic_handle<Tag, T*, nullptr>;

    object_stack_base(object_stack_base&& temp) noexcept
      : _top{temp._top} {
        temp._top = nullptr;
    }

    object_stack_base(const object_stack_base&) = delete;

    auto operator=(object_stack_base&& temp) noexcept -> object_stack_base& {
        using std::swap;
        swap(_top, temp._top);
        return *this;
    }

    auto operator=(const object_stack_base&) = delete;

    auto size() const noexcept -> int {
        return _api().num(_top);
    }

    auto get(const int pos) {
        EAGINE_ASSERT(_idx_ok(pos));
        return wrapper{_api().value(_top, pos)};
    }

    auto native() const noexcept -> auto* {
        return _top;
    }
};
//------------------------------------------------------------------------------
// object_stack
//------------------------------------------------------------------------------
template <typename Tag, typename T>
class object_stack<basic_handle<Tag, T*, nullptr>>
  : object_stack_base<basic_handle<Tag, T*, nullptr>> {

    using base = object_stack_base<basic_handle<Tag, T*, nullptr>>;
    using base::_api;
    using base::_idx_ok;

public:
    using wrapper = basic_handle<Tag, T*, nullptr>;

    object_stack() noexcept
      : base{_api().new_null()} {}

    object_stack(object_stack&&) noexcept = delete;
    object_stack(const object_stack&) = delete;
    auto operator=(object_stack&&) noexcept -> object_stack& = default;
    auto operator=(const object_stack&) = delete;

    ~object_stack() noexcept {
        _api.free()(this->_top);
    }

    auto push(wrapper obj) -> auto& {
        _api().push(this->_top, _api().unpack(obj));
        return *this;
    }

    auto pop() {
        return wrapper{_api().pop(this->_top)};
    }
};
//------------------------------------------------------------------------------
// object_stack owned
//------------------------------------------------------------------------------
template <typename Tag, typename T>
class object_stack<basic_owned_handle<Tag, T*, nullptr>>
  : object_stack_base<basic_handle<Tag, T*, nullptr>> {

    using base = object_stack_base<basic_handle<Tag, T*, nullptr>>;
    using base::_api;
    using base::_idx_ok;

public:
    using wrapper = basic_owned_handle<Tag, T*, nullptr>;

    object_stack() noexcept
      : base{_api().new_null()} {}

    object_stack(object_stack&&) noexcept = delete;
    object_stack(const object_stack&) = delete;
    auto operator=(object_stack&&) noexcept -> object_stack& = default;
    auto operator=(const object_stack&) = delete;

    ~object_stack() noexcept {
        _api.pop_free()(this->_top);
    }

    auto push(wrapper&& obj) -> auto& {
        _api().push_up_ref(this->_top, _api().unpack(obj.release()));
        return *this;
    }

    auto pop() {
        return wrapper{_api().pop(this->_top)};
    }
};
#endif
//------------------------------------------------------------------------------
} // namespace eagine::sslplus

#endif // EAGINE_SSLPLUS_API_OBJECT_STACK_HPP
