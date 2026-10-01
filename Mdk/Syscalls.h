/**
 * @file Syscalls.h
 * @author Ky4meru (@ky4meru)
 * @brief Indirect syscall resolution via Hell's Hall and Tartarus Gate.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_SYSCALLS_H_
#define _MDK_SYSCALLS_H_

//#ifdef _MSC_VER
//#error Mdk does not support MSVC compiler, it only supports Clang for Windows.
//#endif // _MSC_VER

#ifndef _M_X64
#error Mdk does not support x86 architecture, it only supports x64 architecture.
#endif // _M_X64

#include "Hashes.h"
#include "Macros.h"

/// @private
MDK_TEXT_SEC(MDK) MDK_INLINE_ASSEMBLY static NTSTATUS MdkIndirectStub(_In_ LPVOID arg1, _In_ LPVOID arg2, _In_ LPVOID arg3, _In_ LPVOID arg4, _In_ LPVOID arg5, _In_ LPVOID arg6, _In_ LPVOID arg7, _In_ LPVOID arg8, _In_ LPVOID arg9, _In_ LPVOID arg10, _In_ LPVOID arg11, _In_ LPVOID arg12, _In_ DWORD ssn, _In_ LPVOID gate)
{
    __asm
    {
        mov r10, rcx
        mov eax, dword ptr [rsp + 0x68]
        jmp qword ptr [rsp + 0x70]
        ret
    }
}

/**
 * @brief Invokes a native syscall indirectly using the Hell's Hall and Tartarus Gate techniques.
 *
 * This function resolves a syscall stub in ntdll.dll by its hash, extracts its System Service Number (SSN) and
 * locates a legitimate syscall;ret gate to jump through. If the target stub is hooked (i.e. its prologue does not
 * match the expected mov r10, rcx / mov eax, SSN pattern), the function searches up to 500 neighboring stubs in
 * both directions to recover the SSN by calculating the offset from an unhooked neighbor.
 *
 * Unused arguments must be set to NULL.
 *
 * @param hash The compile-time or runtime hash of the syscall name (e.g. MDK_HASH_NtAllocateVirtualMemory).
 * @param arg1 The first argument to the syscall, or NULL if unused.
 * @param arg2 The second argument to the syscall, or NULL if unused.
 * @param arg3 The third argument to the syscall, or NULL if unused.
 * @param arg4 The fourth argument to the syscall, or NULL if unused.
 * @param arg5 The fifth argument to the syscall, or NULL if unused.
 * @param arg6 The sixth argument to the syscall, or NULL if unused.
 * @param arg7 The seventh argument to the syscall, or NULL if unused.
 * @param arg8 The eighth argument to the syscall, or NULL if unused.
 * @param arg9 The ninth argument to the syscall, or NULL if unused.
 * @param arg10 The tenth argument to the syscall, or NULL if unused.
 * @param arg11 The eleventh argument to the syscall, or NULL if unused.
 * @param arg12 The twelfth argument to the syscall, or NULL if unused.
 * @return The NTSTATUS returned by the syscall. Returns STATUS_UNSUCCESSFUL (0xC0000001) if the stub or the syscall gate could not be found.
 */
MDK_TEXT_SEC(MDK) static NTSTATUS MdkIndirectSyscall(_In_ DWORD hash, _In_ LPVOID arg1, _In_ LPVOID arg2, _In_ LPVOID arg3, _In_ LPVOID arg4, _In_ LPVOID arg5, _In_ LPVOID arg6, _In_ LPVOID arg7, _In_ LPVOID arg8, _In_ LPVOID arg9, _In_ LPVOID arg10, _In_ LPVOID arg11, _In_ LPVOID arg12)
{
    BYTE high = 0;
    BYTE low = 0;
    DWORD size = 32;
    DWORD ssn = 0;
    LPVOID gate = NULL;
    LPVOID ntd = NULL;
    LPVOID stub = NULL;
    PIMAGE_DATA_DIRECTORY dir = NULL;
    PIMAGE_DOS_HEADER hdr = NULL;
    PIMAGE_EXPORT_DIRECTORY	exp = NULL;
    PIMAGE_NT_HEADERS nth = NULL;
    PUINT16	aoo = NULL;
    PUINT32	aof = NULL;
    PUINT32	aon = NULL;

    MDK_DECL_DLL(Ntdll);

    ntd = MdkGetModuleHandleByHash(MDK_HASH_Ntdll);
    hdr = (PIMAGE_DOS_HEADER)ntd;
    nth = (PIMAGE_NT_HEADERS)(MDK_CAST_UPTR(hdr) + hdr->e_lfanew);
    dir = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (dir->VirtualAddress)
    {
        exp = (PIMAGE_EXPORT_DIRECTORY)(MDK_CAST_UPTR(hdr) + dir->VirtualAddress);
        aon = (PUINT32)(MDK_CAST_UPTR(hdr) + exp->AddressOfNames);
        aof = (PUINT32)(MDK_CAST_UPTR(hdr) + exp->AddressOfFunctions);
        aoo = (PUINT16)(MDK_CAST_UPTR(hdr) + exp->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exp->NumberOfNames; ++i)
        {
            if (MdkRunTimeHashString(MDK_CAST_VPTR(MDK_CAST_UPTR(hdr) + aon[i]), 0) == hash)
            {
                stub = MDK_CAST_VPTR(MDK_CAST_UPTR(hdr) + aof[aoo[i]]);
                break;
            }
        }
    }

    if (!stub)
    {
        return (NTSTATUS)0xC0000001;
    }

    if (*((PBYTE)stub) == 0x4c
        && *((PBYTE)stub + 1) == 0x8b
        && *((PBYTE)stub + 2) == 0xd1
        && *((PBYTE)stub + 3) == 0xb8
        && *((PBYTE)stub + 6) == 0x00
        && *((PBYTE)stub + 7) == 0x00)
    {
        low = *((PBYTE)stub + 4);
        high = *((PBYTE)stub + 5);
        ssn = (high << 8) | low;
    }
    else
    {
        for (DWORD i = 1; i <= 500; ++i)
        {
            if (((PBYTE)stub + i * size) < ((PBYTE)hdr + aof[aoo[exp->NumberOfFunctions - 1]]))
            {
                if (*((PBYTE)stub + i * size) == 0x4c
                    && *((PBYTE)stub + 1 + i * size) == 0x8b
                    && *((PBYTE)stub + 2 + i * size) == 0xd1
                    && *((PBYTE)stub + 3 + i * size) == 0xb8
                    && *((PBYTE)stub + 6 + i * size) == 0x00
                    && *((PBYTE)stub + 7 + i * size) == 0x00)
                {
                    high = *((PBYTE)stub + 5 + i * size);
                    low = *((PBYTE)stub + 4 + i * size);
                    ssn = ((high << 8) | low) - i;
                    stub = MDK_CAST_VPTR(MDK_CAST_UPTR(stub) + i * size);
                    break;
                }
            }

            if (((PBYTE)stub - i * size) > ((PBYTE)hdr + aof[aoo[0]]))
            {
                if (*((PBYTE)stub - i * size) == 0x4c
                    && *((PBYTE)stub + 1 - i * size) == 0x8b
                    && *((PBYTE)stub + 2 - i * size) == 0xd1
                    && *((PBYTE)stub + 3 - i * size) == 0xb8
                    && *((PBYTE)stub + 6 - i * size) == 0x00
                    && *((PBYTE)stub + 7 - i * size) == 0x00)
                {
                    high = *((PBYTE)stub + 5 - i * size);
                    low = *((PBYTE)stub + 4 - i * size);
                    ssn = ((high << 8) | low) + i;
                    stub = MDK_CAST_VPTR(MDK_CAST_UPTR(stub) - i * size);
                    break;
                }
            }
        }
    }

    for (DWORD i = 1; i < size; ++i)
    {
        if (*((PBYTE)stub + i) == 0x0f
            && *((PBYTE)stub + i + 1) == 0x05
            && *((PBYTE)stub + i + 2) == 0xc3)
        {
            gate = MDK_CAST_VPTR(MDK_CAST_UPTR(stub) + i);
            break;
        }
    }

    if (!gate)
    {
        return (NTSTATUS)0xC0000001;
    }

    return MdkIndirectStub(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, ssn, gate);
}

#endif // _MDK_SYSCALLS_H_
