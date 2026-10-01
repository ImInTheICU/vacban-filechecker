#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vacban::checker {

    class FileFingerprint {
    public:
        static constexpr std::size_t kMaxSignatureLen = 64;
        static constexpr std::size_t kMinFileSize = 64;

        FileFingerprint() = default;

        explicit FileFingerprint(std::string signature);

        [[nodiscard]] bool empty() const noexcept { return signature_.empty(); }
        [[nodiscard]] const std::string& signature() const noexcept { return signature_; }
        [[nodiscard]] std::uint32_t block_size() const noexcept { return block_size_; }

        [[nodiscard]] int compare(const FileFingerprint& other) const;

        [[nodiscard]] std::string to_string() const;

        friend bool operator==(const FileFingerprint& a, const FileFingerprint& b) noexcept {
            return a.signature_ == b.signature_;
        }
        friend bool operator!=(const FileFingerprint& a, const FileFingerprint& b) noexcept {
            return !(a == b);
        }

    private:
        friend class FingerprintEngine;

        std::string signature_;
        std::uint32_t block_size_ = 0;
    };

    class FingerprintEngine {
    public:
        FingerprintEngine() = default;

        [[nodiscard]] std::optional<FileFingerprint> from_file(const std::filesystem::path& path) const;

        [[nodiscard]] FileFingerprint from_buffer(std::span<const std::byte> data) const;

        [[nodiscard]] FileFingerprint from_buffer(std::span<const std::uint8_t> data) const {
            return from_buffer(std::as_bytes(data));
        }
        [[nodiscard]] FileFingerprint from_buffer(std::string_view data) const {
            return from_buffer(std::as_bytes(std::span{ data }));
        }

    private:
        static constexpr std::size_t RollWindow = 7;
        static constexpr std::uint32_t MinBlockSize = 3;
        static constexpr std::string_view Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        struct RollingState {
            std::uint32_t h1 = 0;   // sum
            std::uint32_t h2 = 0;   // sum of sums
            std::uint32_t h3 = 0;   // rolling window product-ish
            std::uint8_t  window[RollWindow]{};
            std::size_t   idx = 0;
        };

        static void roll_hash(RollingState& rs, std::uint8_t byte) noexcept;
        static std::uint32_t roll_sum(const RollingState& rs) noexcept;

        static std::uint32_t block_hash(std::span<const std::byte> block) noexcept;

        static std::uint32_t choose_block_size(std::size_t file_size) noexcept;

        void compute(std::span<const std::byte> data,
            std::uint32_t block_size,
            std::string& part1,
            std::string& part2) const;
    };

}