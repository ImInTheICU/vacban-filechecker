#include "checker/checker.h"
#include <iostream>
#include <string>
#include <Windows.h>

extern "C" int mainCRTStartup();
extern "C" int RapePoint() {
    __(SetConsoleTitleA)("niggers"_obf);
    return mainCRTStartup();
}

int main(int argc, char* argv[]) {
    if (!__(GetConsoleWindow)()) {
        __(AllocConsole)();
        FILE* f = nullptr;
        __(freopen_s)(&f, "CONOUT$"_obf, "w"_obf, stdout);
        __(freopen_s)(&f, "CONOUT$"_obf, "w"_obf, stderr);
        __(freopen_s)(&f, "CONIN$"_obf, "r"_obf, stdin);
    }

    if (argc != 2) {
        std::cout << "Usage: "_obf << argv[0] << " <file>\n"_obf;
        __(system)("pause"_obf);
        return 1;
    }

    vacban::checker::Checker checker;
    auto fp = checker.fingerprint(std::filesystem::path{ argv[1] });

    if (!fp || fp->empty()) {
        std::cout << "Failed to fingerprint file\n"_obf;
        __(system)("pause"_obf);
        return 1;
    }

    std::cout << fp->signature() << "\n"_obf;
    __(system)("pause"_obf);
    return 0;
}