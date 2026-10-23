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
#include "Log.h"
#include "Wrappers.h"

/// @private
MDK_TEXT_SEC(MDK) static LPVOID MdkGlobalVehFunction;

/// @private
MDK_TEXT_SEC(MDK) static LPVOID MdkGlobalVehHooks[4];

/// @private
MDK_TEXT_SEC(MDK) static BOOL MdkGlobalVehPersistent[4];

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
    MDK_LOG_DEBUG("Calling with (dr7=0x%llx, pos=%lu, nb=%lu, val=0x%llx)", (unsigned long long)dr7, pos, nb, (unsigned long long)val);

    return (dr7 & ~(((1UL << nb) - 1UL) << pos)) | (val << pos);
}

/**
 * @brief Enters the global critical section used by the hardware breakpoints engine.
 */
MDK_TEXT_SEC(MDK) static VOID MdkEnterCriticalSection(VOID)
{
    MDK_LOG_DEBUG("Calling");

    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlEnterCriticalSection);

    NTSTATUS nts = 0;

    nts = MDK_CAST_SINT(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlEnterCriticalSection), &MdkGlobalCriticalSection));

    MdkSetLastError(nts);

    MDK_LOG_DEBUG("Finished with (nts=0x%lx)", nts);
}

/**
 * @brief Leaves the global critical section used by the hardware breakpoints engine.
 */
MDK_TEXT_SEC(MDK) static VOID MdkLeaveCriticalSection(VOID)
{
    MDK_LOG_DEBUG("Calling");

    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlLeaveCriticalSection);

    NTSTATUS nts = 0;

    nts = MDK_CAST_SINT(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlLeaveCriticalSection), &MdkGlobalCriticalSection));

    MdkSetLastError(nts);

    MDK_LOG_DEBUG("Finished with (nts=0x%lx)", nts);
}

/// @private
MDK_TEXT_SEC(MDK) static BOOL MdkModifyAllThreadsDr(_In_ HANDLE phd, _In_ DWORD drx, _In_ LPVOID gate, _In_ BOOL enable)
{
    MDK_DECL_PROC(NtQueryInformationProcess);
    MDK_DECL_PROC(NtQuerySystemInformation);
    MDK_DECL_PROC(NtSuspendThread);
    MDK_DECL_PROC(NtResumeThread);

    MDK_PROCESS_BASIC_INFORMATION pbi;
    MdkZeroMemory(&pbi, sizeof(pbi));

    if (!MDK_SUCCEEDED(MDK_INDIRECT_SYSCALL(NtQueryInformationProcess, phd, 0, &pbi, sizeof(pbi), NULL)))
    {
        return FALSE;
    }

    DWORD pid = MDK_CAST_UINT(MDK_CAST_UPTR(pbi.UniqueProcessId));
    DWORD ctid = MDK_CAST_UINT(MDK_CAST_UPTR(MdkCurrentTeb()->ClientId.UniqueThread));
    ULONG size = 0x10000;
    LPVOID buffer = NULL;
    NTSTATUS nts = 0;
    BOOL ret = FALSE;

    do
    {
        if (buffer) { MdkFree(buffer); }
        buffer = MdkMalloc(size);
        if (!buffer) { return FALSE; }
        nts = MDK_INDIRECT_SYSCALL(NtQuerySystemInformation, 5, buffer, size, &size);
        if (nts == (NTSTATUS)0xC0000004) { size *= 2; }
    } while (nts == (NTSTATUS)0xC0000004);

    if (!MDK_SUCCEEDED(nts))
    {
        MdkFree(buffer);
        return FALSE;
    }

    MDK_PSYSTEM_PROCESS_INFORMATION spi = (MDK_PSYSTEM_PROCESS_INFORMATION)buffer;

    while (TRUE)
    {
        if (MDK_CAST_UINT(MDK_CAST_UPTR(spi->UniqueProcessId)) == pid)
        {
            for (DWORD i = 0; i < spi->NumberOfThreads; ++i)
            {
                DWORD tid = MDK_CAST_UINT(MDK_CAST_UPTR(spi->Threads[i].ClientId.UniqueThread));
                HANDLE thd = NULL;
                CONTEXT ctx;

                if (tid == ctid)
                {
                    thd = MdkCurrentThread();
                }
                else
                {
                    thd = MdkOpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
                    if (!thd) { continue; }
                    MDK_INDIRECT_SYSCALL(NtSuspendThread, thd, NULL);
                }

                MdkZeroMemory(&ctx, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                if (MdkGetThreadContext(thd, &ctx))
                {
                    switch (drx)
                    {
                    case 0: ctx.Dr0 = MDK_CAST_UPTR(gate); break;
                    case 1: ctx.Dr1 = MDK_CAST_UPTR(gate); break;
                    case 2: ctx.Dr2 = MDK_CAST_UPTR(gate); break;
                    case 3: ctx.Dr3 = MDK_CAST_UPTR(gate); break;
                    }

                    ctx.Dr6 = 0;
                    ctx.Dr7 = MdkSetDr7(ctx.Dr7, drx * 2, 0x1, enable ? 0x1 : 0x0);

                    if (MdkSetThreadContext(thd, &ctx))
                    {
                        ret = TRUE;
                    }
                }

                MdkZeroMemory(&ctx, sizeof(ctx));

                if (tid != ctid)
                {
                    MDK_INDIRECT_SYSCALL(NtResumeThread, thd, NULL);
                    MdkCloseHandle(thd);
                }
            }

            break;
        }

        if (!spi->NextEntryOffset) { break; }
        spi = (MDK_PSYSTEM_PROCESS_INFORMATION)(MDK_CAST_UPTR(spi) + spi->NextEntryOffset);
    }

    MdkFree(buffer);
    MdkZeroMemory(&pbi, sizeof(pbi));

    return ret;
}

/**
 * @brief Inserts a hardware breakpoint on a target address using a debug register in all threads of a process.
 *
 * @param phd The handle to the process whose threads will receive the hardware breakpoint.
 * @param gate The address to set the hardware breakpoint on.
 * @param hook The address of the function to redirect execution to when the breakpoint is hit.
 * @param drx The debug register index to use (0 to 3).
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkInsertHardwareBreakpoint(_In_ HANDLE phd, _In_ LPVOID gate, _In_ LPVOID hook, _In_ DWORD drx)
{
    MDK_LOG_DEBUG("Calling with (phd=0x%p, gate=0x%p, hook=0x%p, drx=%lu)", phd, gate, hook, drx);

    if (!gate || !hook || drx > 3 || !MdkGlobalVehFunction)
    {
        MDK_LOG_DEBUG("Failed validation (gate=0x%p, hook=0x%p, drx=%lu, veh=0x%p)", gate, hook, drx, MdkGlobalVehFunction);
        return FALSE;
    }

    MdkEnterCriticalSection();
    MdkGlobalVehHooks[drx] = hook;
    MdkLeaveCriticalSection();

    if (!MdkModifyAllThreadsDr(phd, drx, gate, TRUE))
    {
        MDK_LOG_DEBUG("Failed to modify thread debug registers");
        MdkEnterCriticalSection();
        MdkGlobalVehHooks[drx] = NULL;
        MdkLeaveCriticalSection();
        return FALSE;
    }

    MDK_LOG_DEBUG("Successfully finished");

    return TRUE;
}

/**
 * @brief Inserts a persistent hardware breakpoint on a target address using a debug register in all threads of a process.
 *
 * Unlike MdkInsertHardwareBreakpoint, the breakpoint is not removed after being triggered.
 * It remains active and will fire on every subsequent call to the target function.
 * Use MdkRemoveHardwareBreakpoint to disable it.
 *
 * @param phd The handle to the process whose threads will receive the hardware breakpoint.
 * @param gate The address to set the hardware breakpoint on.
 * @param hook The address of the function to redirect execution to when the breakpoint is hit.
 * @param drx The debug register index to use (0 to 3).
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkInsertPersistentHardwareBreakpoint(_In_ HANDLE phd, _In_ LPVOID gate, _In_ LPVOID hook, _In_ DWORD drx)
{
    MDK_LOG_DEBUG("Calling with (phd=0x%p, gate=0x%p, hook=0x%p, drx=%lu)", phd, gate, hook, drx);

    if (drx > 3)
    {
        MDK_LOG_DEBUG("Failed validation (drx=%lu)", drx);
        return FALSE;
    }

    MdkEnterCriticalSection();
    MdkGlobalVehPersistent[drx] = TRUE;
    MdkLeaveCriticalSection();

    if (!MdkInsertHardwareBreakpoint(phd, gate, hook, drx))
    {
        MDK_LOG_DEBUG("Failed to insert hardware breakpoint");
        MdkEnterCriticalSection();
        MdkGlobalVehPersistent[drx] = FALSE;
        MdkLeaveCriticalSection();

        return FALSE;
    }

    MDK_LOG_DEBUG("Successfully finished");

    return TRUE;
}

/**
 * @brief Removes a hardware breakpoint from a debug register in all threads of a process.
 *
 * @param phd The handle to the process whose threads will have the hardware breakpoint removed.
 * @param drx The debug register index to clear (0 to 3).
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkRemoveHardwareBreakpoint(_In_ HANDLE phd, _In_ DWORD drx)
{
    MDK_LOG_DEBUG("Calling with (phd=0x%p, drx=%lu)", phd, drx);

    if (drx > 3 || !MdkGlobalVehFunction)
    {
        MDK_LOG_DEBUG("Failed validation (drx=%lu, veh=0x%p)", drx, MdkGlobalVehFunction);
        return FALSE;
    }

    BOOL ret = MdkModifyAllThreadsDr(phd, drx, NULL, FALSE);

    MdkEnterCriticalSection();
    MdkGlobalVehHooks[drx] = NULL;
    MdkGlobalVehPersistent[drx] = FALSE;
    MdkLeaveCriticalSection();

    MDK_LOG_DEBUG("Finished with (ret=%d)", ret);

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
    MDK_LOG_DEBUG("Calling with (ptr=0x%p)", ptr);

    if (!ptr || !ptr->ExceptionRecord)
    {
        MDK_LOG_DEBUG("Invalid exception pointers");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD drx = 4;
    PCONTEXT ctx = NULL;
    UINT_PTR addr = NULL;

    if (ptr->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        addr = MDK_CAST_UPTR(ptr->ExceptionRecord->ExceptionAddress);

        MDK_LOG_DEBUG("Single step at 0x%llx", (unsigned long long)addr);

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

            MDK_LOG_DEBUG("Redirecting Dr%lu to hook at 0x%llx", drx, (unsigned long long)ctx->Rip);

            if (!MdkGlobalVehPersistent[drx])
            {
                MDK_LOG_DEBUG("Non-persistent breakpoint, removing Dr%lu", drx);
                MdkRemoveHardwareBreakpoint(MdkCurrentProcess(), drx);
            }

            MdkLeaveCriticalSection();

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    MDK_LOG_DEBUG("Unhandled exception (code=0x%lx)", ptr->ExceptionRecord->ExceptionCode);

    return EXCEPTION_CONTINUE_SEARCH;
}

/**
 * @brief Initializes the hardware breakpoints engine.
 *
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkStartHardwareBreakpointsEngine(VOID)
{
    MDK_LOG_DEBUG("Calling");

    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlAddVectoredExceptionHandler);
    MDK_DECL_PROC(RtlInitializeCriticalSection);

    MdkZeroMemory(&MdkGlobalCriticalSection, sizeof(MdkGlobalCriticalSection));

    if (!MDK_SUCCEEDED(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlInitializeCriticalSection), &MdkGlobalCriticalSection)))
    {
        MDK_LOG_DEBUG("Failed to initialize critical section");
        return FALSE;
    }

    if (!MdkGlobalVehFunction)
    {
        if (!(MdkGlobalVehFunction = MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlAddVectoredExceptionHandler), 1, MdkVectoredExceptionHandler)))
        {
            MDK_LOG_DEBUG("Failed to add vectored exception handler");
            return FALSE;
        }
    }

    MDK_LOG_DEBUG("Successfully finished");

    return TRUE;
}

/**
 * @brief Shuts down the hardware breakpoints engine.
 *
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkStopHardwareBreakpointsEngine(VOID)
{
    MDK_LOG_DEBUG("Calling");

    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlDeleteCriticalSection);
    MDK_DECL_PROC(RtlRemoveVectoredExceptionHandler);

    if (MdkGlobalCriticalSection.DebugInfo)
    {
        if (!MDK_SUCCEEDED(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlDeleteCriticalSection), &MdkGlobalCriticalSection)))
        {
            MDK_LOG_DEBUG("Failed to delete critical section");
            return FALSE;
        }

        MdkZeroMemory(&MdkGlobalCriticalSection, sizeof(MdkGlobalCriticalSection));
    }

    if (MdkGlobalVehFunction)
    {
        if (!MDK_SUCCEEDED(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlRemoveVectoredExceptionHandler), MdkGlobalVehFunction)))
        {
            MDK_LOG_DEBUG("Failed to remove vectored exception handler");
            return FALSE;
        }

        MdkGlobalVehFunction = NULL;
    }

    MDK_LOG_DEBUG("Successfully finished");

    return TRUE;
}

#endif // _MDK_BREAKPOINTS_H_
