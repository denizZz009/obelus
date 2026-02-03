.code

; Exported symbols
public SetCurrentSSN
public InvokeSyscall

.data
    wSystemCall DWORD 0

.code

; void SetCurrentSSN(DWORD ssn)
SetCurrentSSN proc
    mov wSystemCall, ecx
    ret
SetCurrentSSN endp

; NTSTATUS InvokeSyscall(RCX, RDX, R8, R9, ...)
; Arguments are already in registers for the function call constraint
; We need to move them to the registers expected by the syscall convention (Windows x64)
; Function Call: RCX, RDX, R8, R9...
; Syscall:       R10, RDX, R8, R9...  (Target Addr usually in RAX, but here logic is inside)
; Wait. The caller calls InvokeSyscall(Arg1, Arg2, Arg3...)
; Arg1 is in RCX. The Syscall expects Arg1 in R10.
; Arg2 is in RDX. Syscall expects Arg2 in RDX.
; Arg3 in R8 -> R8.
; So we just need to mov r10, rcx.
; AND we need to put the SSN in EAX.
InvokeSyscall proc
    mov r10, rcx
    mov eax, wSystemCall
    syscall
    ret
InvokeSyscall endp

end
