#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace Utils {
    // API Hashing (ROR13)
    constexpr DWORD HashStringKey = 13;
    
    __forceinline DWORD Ror13(DWORD d) {
        return _rotr(d, HashStringKey);
    }

    __forceinline DWORD HashString(const char* str) {
        DWORD hash = 0;
        while (*str) {
            hash = Ror13(hash);
            hash += *str;
            str++;
        }
        return hash;
    }

    __forceinline DWORD HashStringW(const wchar_t* str) {
        DWORD hash = 0;
        while (*str) {
            hash = Ror13(hash);
            hash += *str;
            str++;
        }
        return hash;
    }

    // Get Module Handle by Hash (PEB Walk)
    HMODULE GetModuleHandleH(DWORD moduleHash);
    
    // Get Proc Address by Hash (EAT Walk)
    FARPROC GetProcAddressH(HMODULE hModule, DWORD procHash);

    // Simple XOR String Deobfuscation (Runtime)
    // Key is simple byte for demo
    std::string Deobfuscate(const std::vector<unsigned char>& encrypted, unsigned char key);
}
