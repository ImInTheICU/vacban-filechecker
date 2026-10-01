#pragma once

#include "fingerprint.h"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace vacban::checker {

    class Checker {
    public:
        Checker() = default;

        [[nodiscard]] std::optional<FileFingerprint> fingerprint(const std::filesystem::path& path) const;

        [[nodiscard]] FileFingerprint fingerprint(std::span<const std::byte> data) const;
        [[nodiscard]] FileFingerprint fingerprint(std::string_view data) const;

        [[nodiscard]] int similarity(const FileFingerprint& a, const FileFingerprint& b) const;

    private:
        FingerprintEngine engine_;
    };

}