#include "checker.h"

namespace vacban::checker {

    std::optional<FileFingerprint>
        Checker::fingerprint(const std::filesystem::path& path) const {
        return engine_.from_file(path);
    }

    FileFingerprint Checker::fingerprint(std::span<const std::byte> data) const {
        return engine_.from_buffer(data);
    }

    FileFingerprint Checker::fingerprint(std::string_view data) const {
        return engine_.from_buffer(data);
    }

    int Checker::similarity(const FileFingerprint& a, const FileFingerprint& b) const {
        return a.compare(b);
    }

}