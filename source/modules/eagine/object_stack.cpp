/// @file
///
/// Copyright Matus Chochlik.
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE_1_0.txt or copy at
/// https://www.boost.org/LICENSE_1_0.txt
///
module;

#include <cassert>

export module eagine.sslplus:object_stack;

import std;
import eagine.core.types;
import eagine.core.c_api;
import :config;
import :object_handle;

namespace eagine::sslplus {
//------------------------------------------------------------------------------
export template <typename Handle>
class object_stack;
//------------------------------------------------------------------------------
export template <typename Tag>
class object_stack<c_api::basic_handle<Tag, nothing_t*, nullptr>> {
public:
    constexpr auto size() const noexcept -> int {
        return 0;
    }

    constexpr auto push(c_api::basic_handle<Tag, nothing_t*, nullptr>) noexcept
      -> auto& {
        return *this;
    }

    constexpr auto pop() noexcept -> auto& {
        return *this;
    }

    constexpr auto get(const int) noexcept
      -> c_api::basic_handle<Tag, nothing_t*, nullptr> {
        return {};
    }

    constexpr auto native() const noexcept -> nothing_t* {
        return nullptr;
    }
};
//------------------------------------------------------------------------------
export template <typename Tag>
struct stack_api;
//------------------------------------------------------------------------------
export template <>
struct stack_api<x509_tag> {
    using stack_type = ssl_types::x509_stack_type;
    using element_type = ssl_types::x509_type;

    auto unpack(x509 obj) const noexcept -> element_type*;

    auto new_null() const noexcept -> stack_type*;

    void free(stack_type* h) const noexcept;

    auto num(stack_type* h) const noexcept -> int;

    auto push(stack_type* h, element_type* e) const noexcept -> int;

    auto push_up_ref(stack_type* h, element_type* e) const noexcept -> int;

    auto pop(stack_type* h) const noexcept -> element_type*;

    void pop_free(stack_type* h) const noexcept;

    auto set(stack_type* h, const int i, element_type* e) const noexcept
      -> element_type*;

    auto value(stack_type* h, const int i) noexcept -> element_type*;
};
//------------------------------------------------------------------------------
// object_stack_base
//------------------------------------------------------------------------------
export template <typename Handle>
class object_stack_base;

export template <typename Tag, typename T>
class object_stack_base<c_api::basic_handle<Tag, T*, nullptr>> : stack_api<Tag> {
protected:
    typename stack_api<Tag>::stack_type* _top{nullptr};

    auto _api() const noexcept -> const stack_api<Tag>& {
        return *this;
    }

    object_stack_base(typename stack_api<Tag>::stack_type* top) noexcept
      : _top{top} {}

    auto _idx_ok(const int i) const noexcept -> bool {
        return (i >= 0) and (i < size());
    }

    ~object_stack_base() noexcept = default;

public:
    using wrapper = c_api::basic_handle<Tag, T*, nullptr>;

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

    auto get(const int pos) noexcept {
        assert(_idx_ok(pos));
        return wrapper{_api().value(_top, pos)};
    }

    auto native() const noexcept -> auto* {
        return _top;
    }
};
//------------------------------------------------------------------------------
// object_stack
//------------------------------------------------------------------------------
export template <typename Tag, typename T>
class object_stack<c_api::basic_handle<Tag, T*, nullptr>>
  : public object_stack_base<c_api::basic_handle<Tag, T*, nullptr>> {

    using base = object_stack_base<c_api::basic_handle<Tag, T*, nullptr>>;
    using base::_api;
    using base::_idx_ok;

public:
    using wrapper = c_api::basic_handle<Tag, T*, nullptr>;

    object_stack() noexcept
      : base{_api().new_null()} {}

    object_stack(object_stack&&) noexcept = delete;
    object_stack(const object_stack&) = delete;
    auto operator=(object_stack&&) noexcept -> object_stack& = default;
    auto operator=(const object_stack&) = delete;

    ~object_stack() noexcept {
        _api().free(this->_top);
    }

    auto push(wrapper obj) noexcept -> auto& {
        _api().push(this->_top, _api().unpack(obj));
        return *this;
    }

    auto pop() noexcept {
        return wrapper{_api().pop(this->_top)};
    }
};
//------------------------------------------------------------------------------
// object_stack owned
//------------------------------------------------------------------------------
export template <typename Tag, typename T>
class object_stack<c_api::basic_owned_handle<Tag, T*, nullptr>>
  : public object_stack_base<c_api::basic_handle<Tag, T*, nullptr>> {

    using base = object_stack_base<c_api::basic_handle<Tag, T*, nullptr>>;
    using base::_api;
    using base::_idx_ok;

public:
    using wrapper = c_api::basic_owned_handle<Tag, T*, nullptr>;

    object_stack() noexcept
      : base{_api().new_null()} {}

    object_stack(object_stack&&) noexcept = delete;
    object_stack(const object_stack&) = delete;
    auto operator=(object_stack&&) noexcept -> object_stack& = default;
    auto operator=(const object_stack&) = delete;

    ~object_stack() noexcept {
        _api.pop_free()(this->_top);
    }

    auto push(wrapper&& obj) noexcept -> auto& {
        _api().push_up_ref(this->_top, _api().unpack(obj.release()));
        return *this;
    }

    auto pop() noexcept {
        return wrapper{_api().pop(this->_top)};
    }
};
//------------------------------------------------------------------------------
} // namespace eagine::sslplus
namespace eagine::c_api {

export template <std::size_t I, typename Stack, typename Tag, typename T>
struct make_arg_map<
  I,
  I,
  Stack*,
  sslplus::object_stack<c_api::basic_handle<Tag, T*, nullptr>>> {
    template <typename... P>
    constexpr auto operator()(size_constant<I> i, P&&... p) const noexcept {
        return trivial_map{}(i, std::forward<P>(p)...).native();
    }
};

export template <std::size_t I, typename Stack, typename Tag, typename T>
struct make_arg_map<
  I,
  I,
  Stack*,
  sslplus::object_stack<c_api::basic_owned_handle<Tag, T*, nullptr>>> {
    template <typename... P>
    constexpr auto operator()(size_constant<I> i, P&&... p) const noexcept {
        return trivial_map{}(i, std::forward<P>(p)...).native();
    }
};
//------------------------------------------------------------------------------
} // namespace eagine::c_api
