#include "auth.h"

namespace vacban::network {

    void Auth::set_token(std::string_view token) {
        token_ = std::string{ token };
    }

    bool Auth::has_token() const noexcept {
        return !token_.empty();
    }

    std::string_view Auth::token() const noexcept {
        return token_;
    }

}