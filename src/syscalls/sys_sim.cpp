#include "sys_sim.h"
#include "../logger/logger.h"
#include "../utils/obfuscation.h"
#include <iostream>
#include <sstream>

// Standard syscall stub signature (Windows x64)
// mov r10, rcx; mov eax, <SSN>; syscall/int 2e
// 4c 8b d1 b8 <SSN> 0f 05 ... (or similar)

std::map<DWORD, SyscallEntry> SyscallSimulator::cachedSyscalls;

void SyscallSimulator::Init() {
    LOG_INFO("[SyscallEngine] Initializing. Enumerating NTDLL exports...");
    // We rely on lazy resolution in GetSSN usually, but we could pre-resolve.
}

PVOID SyscallSimulator::GetNtdllBase() {
    // Hash for "ntdll.dll"
    DWORD hash = 0;
    const wchar_t* name = L"ntdll.dll";
    while (*name) {
        wchar_t c = *name;
        if (c >= 'A' && c <= 'Z') c += 32;
        hash = _rotr(hash, 13);
        hash += c;
        name++;
    }
    return Utils::GetModuleHandleH(hash);
}

DWORD SyscallSimulator::GetSSN(DWORD funcHash) {
    if (cachedSyscalls.count(funcHash)) {
        return cachedSyscalls[funcHash].SSN;
    }

    PVOID ntdll = GetNtdllBase();
    if (!ntdll) {
        LOG_ERROR("[SyscallSimulator] Failed to find ntdll.dll base!");
        return -1;
    }

    FARPROC funcAddr = Utils::GetProcAddressH((HMODULE)ntdll, funcHash);
    if (!funcAddr) {
        LOG_ERROR("[SyscallSimulator] Failed to find function by hash.");
        return -1;
    }

    DWORD ssn = ResolveSSN_HellsGate(funcAddr);
    if (ssn == -1) {
        LOG_WARN("[SyscallSimulator] Function hooked! Attempting Halo's Gate...");
        ssn = ResolveSSN_HalosGate(funcAddr);
    }

    if (ssn != -1) {
        SyscallEntry entry = { funcHash, ssn, funcAddr, false }; // Hook status checked loosely
        cachedSyscalls[funcHash] = entry;
        LOG_SUCCESS("[SyscallEngine] Resolved SSN: 0x" + std::to_string(ssn));
    } else {
        LOG_ERROR("[SyscallSimulator] Failed to resolve SSN.");
    }
    
    return ssn;
}

DWORD SyscallSimulator::ResolveSSN_HellsGate(PVOID funcAddr) {
    BYTE* p = (BYTE*)funcAddr;
    
    // Check for "mov r10, rcx" (4c 8b d1)
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1) {
        // Check for "mov eax, <SSN>" (b8 <SSN>)
        if (p[3] == 0xB8) {
            DWORD ssn = 0;
            // SSN is u32 usually but low 16 bits mostly used.
            // p[4] is low byte, p[5] is high.
            ssn = ((DWORD)p[5] << 8) | p[4];
            return ssn;
        }
    }
    return -1;
}

DWORD SyscallSimulator::ResolveSSN_HalosGate(PVOID funcAddr) {
    BYTE* p = (BYTE*)funcAddr;
    
    // Check if hooked (e.g. jmp/0xE9)
    if (p[0] == 0xE9) {
        // Look up/down neighbors
        for (int i = 1; i < 500; i++) { // Search range
            // Down 32 bytes (size of stub approx 32)
            BYTE* neighbor = p + (i * 32); 
            DWORD ssn = ResolveSSN_HellsGate(neighbor);
            if (ssn != -1) {
                return ssn - i; // Each neighbor is usually SSN-1 (down) or +1 (up) ??
            
                // If neighbor (lower addr) has ssn X, our ssn is likely X+Delta.
                // NOTE: This is a research prototype, implementing the simplified assumption:
                // If we walk DOWN (higher memory address), SSN usually INCREASES.
                // If we walk UP (lower memory address), SSN usually DECREASES.
                // Wait: `p + (i*32)` is higher memory.
                // If higher memory has SSN `Y`, then ours `X` should be `Y - i`? 
                // Let's assume sequential exports.
                
                // which often checks bytes *before* the hook or *after*.
                // Actually Halo's Gate usually checks `p +/- i` for the byte signature.
            }
            
            // Checks UP (lower memory)
            neighbor = p - (i * 32);
            ssn = ResolveSSN_HellsGate(neighbor);
            if (ssn != -1) {
                return ssn + i; 
            }
        }
    }
    
    // As a fallback, try simply scanning for `mov eax, ssn` within the first 32 bytes
    // Sometimes hooks are placed 5-10 bytes in.
    for (int i=0; i<32; i++) {
        if (p[i] == 0xB8 && p[i+3] == 0x00 && p[i+4] == 0x00) { // Safety: high bytes 0
             return ((DWORD)p[i+2] << 8) | p[i+1];
        }
    }

    return -1;
}

void SyscallSimulator::Simulate(DWORD ssn, const std::string& funcName, const std::vector<void*>& args) {
    std::stringstream ss;
    ss << "SYSCALL EXECUTION [ " << funcName << " ]" << std::endl;
    ss << "    |-- SSN: 0x" << std::hex << ssn << std::dec << std::endl;
    ss << "    |-- Arguments (" << args.size() << "):" << std::endl;
    
    for (size_t i = 0; i < args.size(); i++) {
        ss << "        |-- Arg[" << i << "]: " << args[i] << std::endl;
    }
    
    LOG_INFO(ss.str());
    Logger::Log(LogLevel::TRACE, "--- [ KERNEL TRANSITION ] ---");
}
