/**
 * @file Debug.h
 * @author Ky4meru (@ky4meru)
 * @brief Formatted debug output.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_DEBUG_H_
#define _MDK_DEBUG_H_

#include "Log.h"
#include "Internals.h"

/**
 * @brief Prints a formatted string to the standard output console.
 *
 * The function formats the message using ntdll's _vsnprintf and writes the result to the console using
 * kernel32's WriteConsoleA. The output buffer is limited to 1024 characters.
 *
 * @param format The printf-style format string.
 * @param ... The variable arguments matching the format specifiers.
 */
MDK_TEXT_SEC(MDK) static VOID MdkPrintf(_In_ LPCSTR format, ...)
{
    static volatile BOOL block = FALSE;

    if (block)
    {
        return;
    }

    block = TRUE;

    MDK_DECL_DLL(Ntdll);
    MDK_DECL_DLL(Kernel32);
    MDK_DECL_PROC(_vsnprintf);
    MDK_DECL_PROC(GetStdHandle);
    MDK_DECL_PROC(WriteConsoleA);

    char buf[1024];
    va_list va;
    int len = 0;

    va_start(va, format);
    len = MDK_CAST_SINT(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, _vsnprintf), buf, (SIZE_T)1024, format, va));
    va_end(va);

    if (len > 0)
    {
        MDK_CALL_PROC(MDK_GET_PROC(Kernel32, WriteConsoleA), MDK_CALL_PROC(MDK_GET_PROC(Kernel32, GetStdHandle), STD_OUTPUT_HANDLE), buf, (DWORD)len, NULL, NULL);
    }

    block = FALSE;
}

#ifdef _MDK_BOF

/// @private
MDK_TEXT_SEC(MDK) static VOID MdkBeaconPrintf(_In_ CHAR tag, _In_ LPCSTR format, ...)
{
    static volatile BOOL bLock = FALSE;

    if (bLock)
    {
        return;
    }

    bLock = TRUE;

    MDK_DECL_DLL(Ntdll);
    MDK_DECL_DLL(Kernel32);
    MDK_DECL_PROC(_snprintf);
    MDK_DECL_PROC(_vsnprintf);
    MDK_DECL_PROC(GetLocalTime);

    SYSTEMTIME st;
    char hdr[32];
    char msg[992];
    va_list va;

    MDK_CALL_PROC(MDK_GET_PROC(Kernel32, GetLocalTime), &st);

    MDK_CALL_PROC(MDK_GET_PROC(Ntdll, _snprintf), hdr, (SIZE_T)32, "[%02d/%02d %02d:%02d:%02d] [%c] ", (int)st.wMonth, (int)st.wDay, (int)st.wHour, (int)st.wMinute, (int)st.wSecond, (int)tag);

    va_start(va, format);
    MDK_CALL_PROC(MDK_GET_PROC(Ntdll, _vsnprintf), msg, (SIZE_T)992, format, va);
    va_end(va);

    BeaconPrintf(CALLBACK_OUTPUT, "%s%s", hdr, msg);

    bLock = FALSE;
}

#endif // _MDK_BOF

#endif // _MDK_DEBUG_H_
