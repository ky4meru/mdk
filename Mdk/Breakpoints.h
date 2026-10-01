/**
 * @file Breakpoints.h
 * @author Ky4meru (@ky4meru)
 * @brief Hardware breakpoint engine using Vectored Exception Handling.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_BREAKPOINTS_H_
#define _MDK_BREAKPOINTS_H_

#include "Macros.h"
#include "Internals.h"
#include "Wrappers.h"

/// @private
MDK_TEXT_SEC(MDK) static LPVOID MdkGlobalVehFunction;

/// @private
MDK_TEXT_SEC(MDK) static LPVOID MdkGlobalVehHooks[4];

/// @private
MDK_TEXT_SEC(MDK) static CRITICAL_SECTION MdkGlobalCriticalSection;

/**
 * @brief Sets a bit field in the DR7 debug control register value.
 *
 * @param dr7 The current DR7 register value.
 * @param pos The bit position of the field to set.
 * @param nb The number of bits in the field.
 * @param val The value to write into the field.
 * @return The updated DR7 register value.
 */
MDK_TEXT_SEC(MDK) static UINT_PTR MdkSetDr7(_In_ UINT_PTR dr7, _In_ DWORD pos, _In_ DWORD nb, _In_ UINT_PTR val)
{
    return (dr7 & ~(((1UL << nb) - 1UL) << pos)) | (val << pos);
}

/**
 * @brief Enters the global critical section used by the hardware breakpoints engine.
 */
MDK_TEXT_SEC(MDK) static VOID MdkEnterCriticalSection(VOID)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlEnterCriticalSection);

    NTSTATUS nts = 0;

    nts = MDK_CAST_SINT(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlEnterCriticalSection), &MdkGlobalCriticalSection));
    
    MdkSetLastError(nts);
}

/**
 * @brief Leaves the global critical section used by the hardware breakpoints engine.
 */
MDK_TEXT_SEC(MDK) static VOID MdkLeaveCriticalSection(VOID)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlLeaveCriticalSection);

    NTSTATUS nts = 0;

    nts = MDK_CAST_SINT(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlLeaveCriticalSection), &MdkGlobalCriticalSection));
    
    MdkSetLastError(nts);
}

/**
 * @brief Inserts a hardware breakpoint on a target address using a debug register.
 *
 * @param gate The address to set the hardware breakpoint on.
 * @param hook The address of the function to redirect execution to when the breakpoint is hit.
 * @param drx The debug register index to use (0 to 3).
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkInsertHardwareBreakpoint(_In_ LPVOID gate, _In_ LPVOID hook, _In_ DWORD drx)
{
    if (!gate || !hook || drx > 3 || !MdkGlobalVehFunction)
    {
        return FALSE;
    }

    BOOL ret = FALSE;
    CONTEXT ctx;

    MdkZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (MdkGetThreadContext(MdkCurrentThread(), &ctx))
    {
        switch (drx)
        {
        case 0: ctx.Dr0 = MDK_CAST_UPTR(gate); break;
        case 1: ctx.Dr1 = MDK_CAST_UPTR(gate); break;
        case 2: ctx.Dr2 = MDK_CAST_UPTR(gate); break;
        case 3: ctx.Dr3 = MDK_CAST_UPTR(gate); break;
        default: return FALSE;
        }

        MdkEnterCriticalSection();
        MdkGlobalVehHooks[drx] = hook;
        MdkLeaveCriticalSection();

        ctx.Dr6 = 0;
        ctx.Dr7 = MdkSetDr7(ctx.Dr7, drx * 2, 0x1, 0x1);

        if (MdkSetThreadContext(MdkCurrentThread(), &ctx))
        {
            ret = TRUE;
        }

        MdkZeroMemory(&ctx, sizeof(ctx));
    }

    return ret;
}

/**
 * @brief Removes a hardware breakpoint from a debug register.
 *
 * @param drx The debug register index to clear (0 to 3).
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkRemoveHardwareBreakpoint(_In_ DWORD drx)
{
    if (drx > 3 || !MdkGlobalVehFunction)
    {
        return FALSE;
    }

    BOOL ret = FALSE;
    CONTEXT ctx;

    MdkZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;

    if (MdkGetThreadContext(MdkCurrentThread(), &ctx))
    {
        switch (drx)
        {
        case 0: ctx.Dr0 = NULL; break;
        case 1: ctx.Dr1 = NULL; break;
        case 2: ctx.Dr2 = NULL; break;
        case 3: ctx.Dr3 = NULL; break;
        default: return FALSE;
        }

        MdkEnterCriticalSection();
        MdkGlobalVehHooks[drx] = NULL;
        MdkLeaveCriticalSection();
        
        ctx.Dr6 = 0;
        ctx.Dr7 = MdkSetDr7(ctx.Dr7, drx * 2, 0x1, 0x0);
        ctx.EFlags = 0;

        if (MdkSetThreadContext(MdkCurrentThread(), &ctx))
        {
            ret = TRUE;
        }

        MdkZeroMemory(&ctx, sizeof(ctx));
    }

    return ret;
}

/**
 * @brief Vectored exception handler that intercepts hardware breakpoint exceptions and redirects execution.
 * 
 * @param ptr The pointer to the exception information.
 * @return EXCEPTION_CONTINUE_EXECUTION if the exception was handled, EXCEPTION_CONTINUE_SEARCH otherwise.
 */
MDK_TEXT_SEC(MDK) static LONG WINAPI MdkVectoredExceptionHandler(PEXCEPTION_POINTERS ptr)
{
    if (!ptr || !ptr->ExceptionRecord)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD drx = 4;
    PCONTEXT ctx = NULL;
    UINT_PTR addr = NULL;
    
    if (ptr->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        addr = MDK_CAST_UPTR(ptr->ExceptionRecord->ExceptionAddress);

        if (addr == ptr->ContextRecord->Dr0 || addr == ptr->ContextRecord->Dr1 || addr == ptr->ContextRecord->Dr2 || addr == ptr->ContextRecord->Dr3)
        {
            MdkEnterCriticalSection();

            if (addr == ptr->ContextRecord->Dr0)
            {
                drx = 0;
            }
            else if (addr == ptr->ContextRecord->Dr1)
            {
                drx = 1;
            }
            else if (addr == ptr->ContextRecord->Dr2)
            {
                drx = 2;
            }
            else if (addr == ptr->ContextRecord->Dr3)
            {
                drx = 3;
            }

            ctx = ptr->ContextRecord;
            ctx->Rsp += sizeof(LPVOID);
            ctx->Rip = MDK_CAST_UPTR(MdkGlobalVehHooks[drx]);
            ctx->EFlags |= (1 << 16);

            MdkRemoveHardwareBreakpoint(drx);
            MdkLeaveCriticalSection();

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

/**
 * @brief Initializes the hardware breakpoints engine.
 *
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkStartHardwareBreakpointsEngine(VOID)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlAddVectoredExceptionHandler);
    MDK_DECL_PROC(RtlInitializeCriticalSection);

    MdkZeroMemory(&MdkGlobalCriticalSection, sizeof(MdkGlobalCriticalSection));

    if (!MDK_SUCCEEDED(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlInitializeCriticalSection), &MdkGlobalCriticalSection)))
    {
        return FALSE;
    }

    if (!MdkGlobalVehFunction)
    {
        if (!(MdkGlobalVehFunction = MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlAddVectoredExceptionHandler), 1, MdkVectoredExceptionHandler)))
        {
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * @brief Shuts down the hardware breakpoints engine.
 *
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkStopHardwareBreakpointsEngine(VOID)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlDeleteCriticalSection);
    MDK_DECL_PROC(RtlRemoveVectoredExceptionHandler);

    if (MdkGlobalCriticalSection.DebugInfo)
    {
        if (!MDK_SUCCEEDED(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlDeleteCriticalSection), &MdkGlobalCriticalSection)))
        {
            return FALSE;
        }

        MdkZeroMemory(&MdkGlobalCriticalSection, sizeof(MdkGlobalCriticalSection));
    }

    if (MdkGlobalVehFunction)
    {
        if (!MDK_SUCCEEDED(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlRemoveVectoredExceptionHandler), MdkGlobalVehFunction)))
        {
            return FALSE;
        }

        MdkGlobalVehFunction = NULL;
    }

    return TRUE;
}

#endif // _MDK_BREAKPOINTS_H_
