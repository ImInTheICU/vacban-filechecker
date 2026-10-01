#include "fingerprint.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <fstream>
#include <iterator>
#include <limits>
#include <stdexcept>

namespace vacban::checker {

    FileFingerprint::FileFingerprint(std::string signature) : signature_(std::move(signature)) {
        const auto colon = signature_.find(':');
        if (colon != std::string::npos) {
            try {
                block_size_ = static_cast<std::uint32_t>(std::stoul(signature_.substr(0, colon)));
            }
            catch (...) {
                block_size_ = 0;
            }
        }
    }

    int FileFingerprint::compare(const FileFingerprint& other) const {
        if (empty() || other.empty()) return 0;

        const auto bs1 = block_size_;
        const auto bs2 = other.block_size_;
        if (bs1 == 0 || bs2 == 0) return 0;
        if (bs1 > bs2 * 4 || bs2 > bs1 * 4) return 0;

        auto extract_parts = [](std::string_view sig) -> std::pair<std::string_view, std::string_view> {
            const auto c1 = sig.find(':');
            if (c1 == std::string_view::npos) return {};
            const auto c2 = sig.find(':', c1 + 1);
            if (c2 == std::string_view::npos) return { sig.substr(c1 + 1), {} };
            return { sig.substr(c1 + 1, c2 - c1 - 1), sig.substr(c2 + 1) };
            };

        const auto [a1, a2] = extract_parts(signature_);
        const auto [b1, b2] = extract_parts(other.signature_);

        auto score_pair = [](std::string_view x, std::string_view y) -> int {
            if (x.empty() || y.empty()) return 0;
            if (x == y) return 100;

            const std::size_t m = x.size();
            const std::size_t n = y.size();
            if (m == 0 || n == 0) return 0;

            int hits = 0;
            int total = 0;

            for (std::size_t win : {3, 4, 5, 6, 7}) {
                if (m < win || n < win) continue;
                for (std::size_t i = 0; i + win <= m; ++i) {
                    ++total;
                    if (y.find(x.substr(i, win)) != std::string_view::npos) {
                        ++hits;
                    }
                }
            }

            if (total == 0) return 0;
            return std::clamp(hits * 100 / total, 0, 100);
            };

        int s = 0;
        s = std::max(s, score_pair(a1, b1));
        s = std::max(s, score_pair(a1, b2));
        s = std::max(s, score_pair(a2, b1));
        s = std::max(s, score_pair(a2, b2));
        return s;
    }

    std::string FileFingerprint::to_string() const {
        return signature_;
    }

    void FingerprintEngine::roll_hash(RollingState& rs, std::uint8_t byte) noexcept {
        // spamsum / ssdeep rolling hash
        rs.h2 -= rs.h1;
        rs.h2 += RollWindow * static_cast<std::uint32_t>(byte);

        rs.h1 += byte;
        rs.h1 -= rs.window[rs.idx % RollWindow];

        rs.window[rs.idx % RollWindow] = byte;
        ++rs.idx;

        rs.h3 <<= 5;
        rs.h3 ^= byte;
    }

    std::uint32_t FingerprintEngine::roll_sum(const RollingState& rs) noexcept {
        return rs.h1 + rs.h2 + rs.h3;
    }

    std::uint32_t FingerprintEngine::block_hash(std::span<const std::byte> block) noexcept {
        constexpr std::uint32_t FNV_OFFSET = 2166136261u;
        constexpr std::uint32_t FNV_PRIME = 16777619u;

        std::uint32_t h = FNV_OFFSET;
        for (const auto b : block) {
            h ^= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(b));
            h *= FNV_PRIME;
        }
        return h;
    }

    std::uint32_t FingerprintEngine::choose_block_size(std::size_t file_size) noexcept {
        std::uint32_t bs = MinBlockSize;
        const auto target = static_cast<std::uint64_t>(FileFingerprint::kMaxSignatureLen / 2);
        while (static_cast<std::uint64_t>(bs) * target < file_size) {
            bs *= 2;
            if (bs > (1u << 20))
                break;
        }

        if (bs > MinBlockSize * 2 && static_cast<std::uint64_t>(bs / 2) * target >= file_size / 2)
            bs /= 2;

        return bs;
    }

    void FingerprintEngine::compute(std::span<const std::byte> data,
        std::uint32_t block_size,
        std::string& part1,
        std::string& part2) const {
        part1.clear();
        part2.clear();
        part1.reserve(FileFingerprint::kMaxSignatureLen);
        part2.reserve(FileFingerprint::kMaxSignatureLen);

        if (data.size() < FileFingerprint::kMinFileSize) return;

        RollingState roll{};
        std::size_t block_start1 = 0;
        std::size_t block_start2 = 0;

        const std::uint32_t bs = block_size;
        const std::uint32_t bs2 = block_size * 2;

        auto emit = [&](std::string& dest, std::uint32_t h) {
            if (dest.size() < FileFingerprint::kMaxSignatureLen) {
                dest.push_back(Alphabet[h % Alphabet.size()]);
            }
            };

        for (std::size_t i = 0; i < data.size(); ++i) {
            const auto byte = static_cast<std::uint8_t>(std::to_integer<std::uint8_t>(data[i]));
            roll_hash(roll, byte);

            const auto r = roll_sum(roll);

            if ((r % bs) == (bs - 1) && part1.size() < FileFingerprint::kMaxSignatureLen) {
                const auto block = data.subspan(block_start1, i - block_start1 + 1);
                emit(part1, block_hash(block));
                block_start1 = i + 1;
            }

            if ((r % bs2) == (bs2 - 1) && part2.size() < FileFingerprint::kMaxSignatureLen) {
                const auto block = data.subspan(block_start2, i - block_start2 + 1);
                emit(part2, block_hash(block));
                block_start2 = i + 1;
            }
        }

        if (block_start1 < data.size() && part1.size() < FileFingerprint::kMaxSignatureLen) 
            emit(part1, block_hash(data.subspan(block_start1)));
        
        if (block_start2 < data.size() && part2.size() < FileFingerprint::kMaxSignatureLen) 
            emit(part2, block_hash(data.subspan(block_start2)));
        
        if (part2.empty() && !part1.empty()) 
            part2 = part1;
    }

    FileFingerprint FingerprintEngine::from_buffer(std::span<const std::byte> data) const {
        if (data.size() < FileFingerprint::kMinFileSize)
            return FileFingerprint{};
        
        const auto bs = choose_block_size(data.size());
        std::string p1, p2;
        compute(data, bs, p1, p2);

        std::string sig = std::to_string(bs) + " - " + p1 + " - " + p2;
        FileFingerprint fp(std::move(sig));
        return fp;
    }

    std::optional<FileFingerprint> FingerprintEngine::from_file(const std::filesystem::path& path) const {
        namespace fs = std::filesystem;

        std::error_code ec;
        const auto sz = fs::file_size(path, ec);
        if (ec || sz < FileFingerprint::kMinFileSize)
            return std::nullopt;

        constexpr std::uint64_t kMaxInMemory = 512ull * 1024 * 1024;
        if (sz > kMaxInMemory) 
            return std::nullopt;
        
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) 
            return std::nullopt;

        std::vector<std::byte> buffer(static_cast<std::size_t>(sz));
        ifs.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(sz));
        if (!ifs) 
            return std::nullopt;

        return from_buffer(buffer);
    }

}