#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <map>

struct SyscallEntry {
    DWORD Hash;
    DWORD SSN;
    PVOID Address;
    bool IsHooked;
};

class SyscallSimulator {
public:
    static void Init();
    static DWORD GetSSN(DWORD funcHash);
    static void Simulate(DWORD ssn, const std::string& funcName, const std::vector<void*>& args);

private:
    static PVOID GetNtdllBase();
    static DWORD ResolveSSN_HellsGate(PVOID funcAddr);
    static DWORD ResolveSSN_HalosGate(PVOID funcAddr);
    
    static std::map<DWORD, SyscallEntry> cachedSyscalls;
};
