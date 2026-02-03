#pragma once
#include <vector>
#include <windows.h>

class ShellcodeRunner {
public:
    static void Run();
private:
    static std::vector<unsigned char> GetCalcShellcode();
};
