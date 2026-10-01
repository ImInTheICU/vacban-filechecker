#pragma once

#include <string>
#include <string_view>

namespace vacban::network {

    // placeholder
    class Auth {
    public:
        Auth() = default;

        void set_token(std::string_view token);

        [[nodiscard]] bool has_token() const noexcept;
        [[nodiscard]] std::string_view token() const noexcept;

    private:
        std::string token_;
    };

}