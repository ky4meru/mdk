/**
 * @file Strings.h
 * @author Ky4meru (@ky4meru)
 * @brief ANSI and Unicode string comparison and length functions.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_STRINGS_H_
#define _MDK_STRINGS_H_

#include "Log.h"

#pragma clang optimize off

/**
 * @brief Performs an ordinal comparison of two ANSI strings.
 *
 * @param lhs The first string to compare.
 * @param rhs The second string to compare.
 * @return An integer < 0 if lhs is less than rhs, an integer > 0 if lhs is greater that rhs, and 0 if the two strings are identical.
 */
MDK_TEXT_SEC(MDK) static INT MdkCompareString(_In_ LPCSTR lhs, _In_ LPCSTR rhs)
{
    MDK_LOG_DEBUG("Calling with (lhs=\"%s\", rhs=\"%s\")", lhs, rhs);

    while (*lhs && *lhs == *rhs)
    {
        ++lhs;
        ++rhs;
    }

    INT ret = (INT)(*lhs) - (INT)(*rhs);

    MDK_LOG_DEBUG("Returning %d", ret);

    return ret;
}

/**
 * @brief Performs an ordinal comparison of two ANSI strings without regard to case.
 *
 * @param lhs The first string to compare.
 * @param rhs The second string to compare.
 * @return An integer < 0 if lhs is less than rhs, an integer > 0 if lhs is greater that rhs, and 0 if the two strings are identical.
 */
MDK_TEXT_SEC(MDK) static INT MdkCompareInsensitiveString(_In_ LPCSTR lhs, _In_ LPCSTR rhs)
{
    MDK_LOG_DEBUG("Calling with (lhs=\"%s\", rhs=\"%s\")", lhs, rhs);

    CHAR l = 0;
    CHAR r = 0;

    while (*lhs && *rhs)
    {
        l = (*lhs >= 'A' && *lhs <= 'Z') ? *lhs + 0x20 : *lhs;
        r = (*rhs >= 'A' && *rhs <= 'Z') ? *rhs + 0x20 : *rhs;

        if (l != r)
        {
            INT ret = (INT)(l) - (INT)(r);
            MDK_LOG_DEBUG("Returning %d", ret);
            return ret;
        }

        ++lhs;
        ++rhs;
    }

    l = (*lhs >= 'A' && *lhs <= 'Z') ? *lhs + 0x20 : *lhs;
    r = (*rhs >= 'A' && *rhs <= 'Z') ? *rhs + 0x20 : *rhs;

    INT ret = (INT)(l) - (INT)(r);

    MDK_LOG_DEBUG("Returning %d", ret);

    return ret;
}

/**
 * @brief Performs an ordinal comparison of two UNICODE strings.
 *
 * @param lhs The first string to compare.
 * @param rhs The second string to compare.
 * @return An integer < 0 if lhs is less than rhs, an integer > 0 if lhs is greater that rhs, and 0 if the two strings are identical.
 */
MDK_TEXT_SEC(MDK) static INT MdkCompareWideString(_In_ LPCWSTR lhs, _In_ LPCWSTR rhs)
{
    MDK_LOG_DEBUG("Calling with (lhs=0x%p, rhs=0x%p)", lhs, rhs);

    while (*lhs && *lhs == *rhs)
    {
        ++lhs;
        ++rhs;
    }

    INT ret = (INT)(*lhs) - (INT)(*rhs);

    MDK_LOG_DEBUG("Returning %d", ret);

    return ret;
}

/**
 * @brief Performs an ordinal comparison of two UNICODE strings without regard to case.
 *
 * @param lhs The first string to compare.
 * @param rhs The second string to compare.
 * @return An integer < 0 if lhs is less than rhs, an integer > 0 if lhs is greater that rhs, and 0 if the two strings are identical.
 */
MDK_TEXT_SEC(MDK) static INT MdkCompareInsensitiveWideString(_In_ LPCWSTR lhs, _In_ LPCWSTR rhs)
{
    MDK_LOG_DEBUG("Calling with (lhs=0x%p, rhs=0x%p)", lhs, rhs);

    WCHAR l = 0;
    WCHAR r = 0;

    while (*lhs && *rhs)
    {
        l = (*lhs >= L'A' && *lhs <= L'Z') ? *lhs + 0x20 : *lhs;
        r = (*rhs >= L'A' && *rhs <= L'Z') ? *rhs + 0x20 : *rhs;

        if (l != r)
        {
            INT ret = (INT)(l) - (INT)(r);
            MDK_LOG_DEBUG("Returning %d", ret);
            return ret;
        }

        ++lhs;
        ++rhs;
    }

    l = (*lhs >= L'A' && *lhs <= L'Z') ? *lhs + 0x20 : *lhs;
    r = (*rhs >= L'A' && *rhs <= L'Z') ? *rhs + 0x20 : *rhs;

    INT ret = (INT)(l) - (INT)(r);

    MDK_LOG_DEBUG("Returning %d", ret);

    return ret;
}

/**
 * @brief Returns the length of a null-terminated ANSI string.
 *
 * @param str The null-terminated string whose length is to be determined.
 * @return The number of characters in the string.
 */
MDK_TEXT_SEC(MDK) static SIZE_T MdkStringLength(_In_ LPCSTR str)
{
    MDK_LOG_DEBUG("Calling with (str=\"%s\")", str);

    SIZE_T len = 0;

    while (str[len])
    {
        ++len;
    }

    MDK_LOG_DEBUG("Returning %zu", len);

    return len;
}

/**
 * @brief Returns the length of a null-terminated UNICODE string.
 *
 * @param str The null-terminated wide string whose length is to be determined.
 * @return The number of characters in the string.
 */
MDK_TEXT_SEC(MDK) static SIZE_T MdkWideStringLength(_In_ LPCWSTR str)
{
    MDK_LOG_DEBUG("Calling with (str=\"%ls\")", str);

    SIZE_T len = 0;

    while (str[len])
    {
        ++len;
    }

    MDK_LOG_DEBUG("Returning %zu", len);

    return len;
}

#pragma clang optimize on

#endif // _MDK_STRINGS_H_