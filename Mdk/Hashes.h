/**
 * @file Hashes.h
 * @author Ky4meru (@ky4meru)
 * @brief Compile-time and runtime string hashing for API resolution.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_HASHES_H_
#define _MDK_HASHES_H_

#include "Log.h"

#ifndef __cplusplus
extern "c++"
{
#endif // __cplusplus

/**
 * @brief Computes the hash of a string at compile time.
 *
 * @note Case folding only handles ASCII letters (a-z). Characters above 'z' (e.g. '{', '|', '~') are not affected
 * but would be if they fell in the folding range. Only use with ASCII alphanumeric strings (module names, proc names).
 *
 * @param str Pointer to the NULL terminated string to hash.
 * @return The hash of the string.
 */
MDK_TEXT_SEC(MDK) static constexpr DWORD MdkCompileTimeHashString(_In_ LPCSTR str)
{
    if (!str)
    {
        return 0;
    }

    DWORD hash = 0;
    UCHAR cur = 0;

    while (TRUE)
    {
        if (!*str)
        {
            break;
        }

        cur = *str;

        if (cur >= 'a')
        {
            cur -= 0x20;
        }

        hash = cur + (hash << 6) + (hash << 16) - hash;
        ++str;
    }

    return hash;
}

#ifndef __cplusplus
}
#endif // __cplusplus

/**
 * @brief Computes the hash of a string at runtime.
 *
 * @note Case folding only handles ASCII letters (a-z). Characters above 'z' (e.g. '{', '|', '~') are not affected
 * but would be if they fell in the folding range. Only use with ASCII alphanumeric strings (module names, proc names).
 *
 * @param str Pointer to the string to hash.
 * @param len Length of the string. If 0 is given, it is assumed that the string is NULL terminated.
 * @return The hash of the string.
 */
MDK_TEXT_SEC(MDK) static DWORD MdkRunTimeHashString(_In_ LPVOID str, _In_opt_ SIZE_T len)
{
    if (!str)
    {
        return 0;
    }

    DWORD hash = 0;
    PUCHAR ptr = (PUCHAR)str;
    UCHAR cur = 0;

    while (TRUE)
    {
        cur = *ptr;

        if (!len)
        {
            if (!*ptr)
            {
                break;
            }
        }
        else
        {
            if ((DWORD)(ptr - (PUCHAR)str) >= len)
            {
                break;
            };

            if (!*ptr)
            {
                ++ptr;
                continue;
            }
        }

        if (cur >= 'a')
        {
            cur -= 0x20;
        }

        hash = cur + (hash << 6) + (hash << 16) - hash;
        ++ptr;
    }

    return hash;
}

#endif // _MDK_HASHES_H_
