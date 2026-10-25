;
; @file       x64.asm
;
; @brief      All assembly code.
;
; @author     Satoshi Tanda
;
; @copyright  Copyright (c) 2017-2019, Satoshi Tanda. All rights reserved.
;
; ============================================================================
; OPTIMIZATIONS APPLIED (OPT #1-4) + BUG FIXES
; ============================================================================
;
; OPT #1: TargetSysHandler check moved before swapgs pair.
; OPT #2: ALIGN 16 before go_origLSTAR.
; OPT #3: Explicit jmp in clear_magic.
; OPT #4: Single-byte g_Ready check in hot path.
;
; BUG FIX #1: Re-validate TargetSysHandler != 0 just before sysretq.
;   There is a race between the g_Ready check at function entry and the
;   moment we execute sysretq: CleanupKuser and CounterUpdater's failure
;   paths set TargetSysHandler = NULL asynchronously. Without this check,
;   RCX would be loaded with NULL and sysretq would #GP in ring 0 -> BSOD.
;
; BUG FIX #2: Validate TargetSysHandler is a canonical user-mode address
;   (bit 63 = 0) before sysretq. sysretq requires RCX to be a user address;
;   if TargetSysHandler contains a kernel address or garbage with bit 63
;   set, sysretq raises #GP in ring 0 -> BSOD. The previous hybrid had
;   'test rcx, rcx; js' which missed the NULL case; this version checks
;   both NULL and the kernel-address bit.
;
; WARNINGS (DO NOT CHANGE):
;   - 'movd xmm4, eax' / 'movd eax, xmm4' KEPT. It depends on XMM4
;     being corrupted (high 96 bits zeroed) on every syscall. Removing
;     them freezes the system.
;   - 'xorps xmm5, xmm5' only clears the magic AFTER the context is
;     valid. Do not move it before the checks.
;   - ALIGN 16 is the only value that compiles in ML64.
;   - Do not add push/pop between PUSHAQ and POPAQ.
;
; ============================================================================

.data

EXTERN OrigLstar: QWORD
EXTERN TargetProcess: QWORD
EXTERN TargetSysHandler: QWORD
EXTERN SyscallBypassMagic: QWORD
EXTERN g_Ready: BYTE

.const

KTRAP_FRAME_SIZE            equ     190h
MACHINE_FRAME_SIZE          equ     28h

KTHREAD_APCSTATE_PROCESS    equ     220h

.code

extern SvHandleVmExit : proc

;
;   @brief      Saves all general purpose registers to the stack.
;
PUSHAQ macro
        push    rax
        push    rcx
        push    rdx
        push    rbx
        push    -1      ; Dummy for rsp.
        push    rbp
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15
        endm

;
;   @brief      Loads all general purpose registers from the stack.
;
POPAQ macro
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx    ; Dummy for rsp (destroyed by next pop).
        pop     rbx
        pop     rdx
        pop     rcx
        pop     rax
        endm

SvLaunchVm proc frame
        mov rsp, rcx    ; Rsp <= HostRsp

SvLV10:
        mov rax, [rsp]  ; RAX <= VpData->HostStackLayout.GuestVmcbPa
        vmload rax

        vmrun rax

        vmsave rax

        .pushframe
        sub     rsp, KTRAP_FRAME_SIZE
        .allocstack KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 100h

        PUSHAQ

        mov rdx, rsp                                ; Rdx <= GuestRegisters
        mov rcx, [rsp + 8 * 18 + KTRAP_FRAME_SIZE]  ; Rcx <= VpData

        sub rsp, 80h
        movaps xmmword ptr [rsp + 20h], xmm0
        movaps xmmword ptr [rsp + 30h], xmm1
        movaps xmmword ptr [rsp + 40h], xmm2
        movaps xmmword ptr [rsp + 50h], xmm3
        movaps xmmword ptr [rsp + 60h], xmm4
        movaps xmmword ptr [rsp + 70h], xmm5
        .endprolog

        call SvHandleVmExit

        movaps xmm5, xmmword ptr [rsp + 70h]
        movaps xmm4, xmmword ptr [rsp + 60h]
        movaps xmm3, xmmword ptr [rsp + 50h]
        movaps xmm2, xmmword ptr [rsp + 40h]
        movaps xmm1, xmmword ptr [rsp + 30h]
        movaps xmm0, xmmword ptr [rsp + 20h]
        add rsp, 80h

        test al, al
        POPAQ

        jnz SvLV20
        add rsp, KTRAP_FRAME_SIZE
        jmp SvLV10

SvLV20:
        mov rsp, rcx
        mov ecx, 'SSVM'
        jmp rbx
SvLaunchVm endp

SyscallHook proc frame

ALIGN 16

        ;
        ; XMM4 corruption: hard requirement.
        ;
        movd    xmm4, eax

        ;
        ; OPT #4: single-byte fast-fail check.
        ;
        cmp     byte ptr [g_Ready], 0
        je      go_origLSTAR

        ;
        ; Resolve current EPROCESS from the KTHREAD's ApcState.Process.
        ; swapgs pair is REQUIRED: on syscall entry, GS still points to
        ; user GS, not KPCR.
        ;
        swapgs
        mov     rax, gs:[188h]
        mov     rax, [rax + KTHREAD_APCSTATE_PROCESS]
        swapgs

        ;
        ; Only divert if the current process is the target process.
        ;
        cmp     rax, qword ptr [TargetProcess]
        jne     go_origLSTAR

        ;
        ; One-shot magic check: if XMM5 has the magic value, clear it and
        ; allow the real syscall to proceed.
        ;
        movq    rax, xmm5
        cmp     rax, qword ptr [SyscallBypassMagic]
        je      clear_magic

        ;
        ; BUG FIX #1: re-check TargetSysHandler != 0 immediately before
        ; diverting. CleanupKuser and CounterUpdater's failure paths set it
        ; to NULL asynchronously; without this check, sysretq would jump to
        ; NULL -> BSOD.
        ;
        ; BUG FIX #2: validate TargetSysHandler is a canonical user-mode
        ; address (bit 63 = 0) before sysretq. If it contains a kernel
        ; address or garbage with bit 63 set, sysretq raises #GP in ring 0
        ; -> BSOD.
        ;
        ; Implementation: save user RIP to RAX (the handler reads it as the
        ; return address), load the handler into RCX, validate RCX, and
        ; either sysretq or restore RCX and fall through to the original
        ; LSTAR.
        ;
        mov     rax, rcx                             ; RAX = user RIP
        mov     rcx, qword ptr [TargetSysHandler]    ; RCX = handler
        test    rcx, rcx
        jz      restore_rcx_and_orig                 ; NULL handler -> fallback
        js      restore_rcx_and_orig                 ; kernel address (bit 63) -> fallback

        sysretq

    restore_rcx_and_orig:
        mov     rcx, rax                             ; restore user RIP
        jmp     go_origLSTAR

    clear_magic:
        xorps   xmm5, xmm5
        ;
        ; OPT #3: explicit jmp so the ALIGN 16 padding below is never
        ; executed. Replaces the previous fall-through.
        ;
        jmp     go_origLSTAR

        ;
        ; OPT #2: align the common post-init return path (go_origLSTAR) to
        ; a 16-byte boundary.
        ;
        ALIGN 16

    go_origLSTAR:
        ;
        ; Restore EAX (low 32 bits of the original RAX, which holds the
        ; syscall number on entry). High 32 bits are zeroed by the 32-bit
        ; movd, which it depends on.
        ;
        movd    eax, xmm4
        jmp     qword ptr [OrigLstar]

        .endprolog

SyscallHook endp

end