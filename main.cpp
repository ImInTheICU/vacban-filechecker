#include "checker/checker.h"

#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file>\n";
        return 1;
    }

    vacban::checker::Checker checker;
    auto fp = checker.fingerprint(std::filesystem::path{argv[1]});

    if (!fp || fp->empty()) {
        std::cerr << "Failed to fingerprint file\n";
        return 1;
    }

    std::cout << fp->signature() << '\n';
    return 0;
}