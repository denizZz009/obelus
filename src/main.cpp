#include <windows.h>
#include "logger/logger.h"
#include "utils/obfuscation.h"
#include "syscalls/sys_sim.h"
#include "syscalls/native_syscalls.h"
#include "runner/shellcode_runner.h"
#include "loader/pe_loader.h"
#include "persistence/hijack_sim.h"
#include "bits/bits_sim.h"

// Helper to precompute hash for 'kernel32.dll' (lowercase)
// ROR13 of "kernel32.dll"

int main() {
    Logger::Log(LogLevel::INFO, "Obelus 2026 // Defensive Validator Initialized");
    Logger::Log(LogLevel::WARN, "[Init] Mode: ACTIVE // SYSTEM ANALYSIS");

    // Phase 1 verification: API Hashing
    LOG_INFO("[Init] Verifying Internal Obfuscation routines...");
    
    // Hash for "kernel32.dll"
    DWORD k32Hash = 0;
    const wchar_t* k32Name = L"kernel32.dll";
    const wchar_t* p = k32Name;
    while (*p) { 
        wchar_t c = *p; 
        if(c >= 'A' && c <= 'Z') c += 32; 
        k32Hash = _rotr(k32Hash, 13); 
        k32Hash += c; 
        p++; 
    }
    
    HMODULE hK32 = Utils::GetModuleHandleH(k32Hash);
    if (hK32) {
        Logger::Log(LogLevel::SUCCESS, "[API] Resolved kernel32.dll");
    } else {
        Logger::Log(LogLevel::ERR, "[API] Failed to resolve kernel32.dll");
    }

    // Hash for "Sleep"
    const char* sleepName = "Sleep";
    DWORD sleepHash = Utils::HashString(sleepName);
    
    FARPROC pSleep = Utils::GetProcAddressH(hK32, sleepHash);
    if (pSleep) {
        Logger::Log(LogLevel::SUCCESS, "[API] Resolved Sleep");
    }

    // Phase 1 verification: Obfuscation
    std::vector<unsigned char> secret = { 'S'^0xAA, 'E'^0xAA, 'C'^0xAA, 'R'^0xAA, 'E'^0xAA, 'T'^0xAA };
    std::string decrypted = Utils::Deobfuscate(secret, 0xAA);
    LOG_INFO("[OPSEC] Artifact Decrypted: " + decrypted);

    // Phase 2: Syscall Simulation
    LOG_INFO("\n[*] Initializing Syscall Engine...");
    SyscallSimulator::Init();
    
    DWORD ntAllocHash = Utils::HashString("NtAllocateVirtualMemory");
    DWORD ssn = SyscallSimulator::GetSSN(ntAllocHash);
    if (ssn != -1) {
        // Silent validation
    }
    LOG_SUCCESS("[*] Syscall Engine Ready.");

    // Phase 3: Shellcode Runner (Realtime)
    LOG_INFO("\n[*] Executing Payload Runner [Type: Shellcode/Notepad]...");
    NativeSyscalls::Init(); 
    ShellcodeRunner::Run();
    LOG_SUCCESS("[*] Payload Execution Flow Completed.");

    // Phase 4: Reflective PE Loader (Real-time Analysis)
    LOG_INFO("\n[*] Starting Real-time Reflective Module Analysis...");
    PELoader::RunReflectiveLoader((void*)GetModuleHandle(NULL));
    LOG_SUCCESS("[*] Module Analysis Completed.");

    // Phase 5: Persistence Analysis (DLL Hijacking)
    LOG_INFO("\n[*] Analyzing Persistence Vectors (DLL Hijacking)...");
    PersistenceSim::RunAnalysis();
    LOG_SUCCESS("[*] Persistence Analysis Completed.");

    // Phase 6: BITS Service Analysis
    LOG_INFO("\n[*] Analyzing BITS Service Artifacts...");
    BitsSimulator::RunAnalysis();
    LOG_SUCCESS("[*] BITS Analysis Completed.");

    LOG_INFO("\n[+] Operation Successful. Press Enter to Exit.");
    std::cin.get();

    return 0;
}
