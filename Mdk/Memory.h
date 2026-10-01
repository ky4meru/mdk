/**
 * @file Memory.h
 * @author Ky4meru (@ky4meru)
 * @brief Basic memory operations.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_MEMORY_H_
#define _MDK_MEMORY_H_

#include "Log.h"

#pragma clang optimize off

/**
 * @brief Compares two blocks of memory.
 *
 * @param lhs The first memory block.
 * @param rhs The second memory block.
 * @param count The number of bytes to compare.
 * @return An integer < 0 if lhs is less than rhs, an integer > 0 if lhs is greater that rhs, and 0 if the two memory blocks are identical.
 */
MDK_TEXT_SEC(MDK) static INT MdkCompareMemory(_In_ LPCVOID lhs, _In_ LPCVOID rhs, _In_ SIZE_T count)
{
    MDK_LOG_DEBUG("Calling with (lhs=0x%p, rhs=0x%p, count=%zu)", lhs, rhs, count);

    LPCBYTE p1 = (LPCBYTE)lhs;
    LPCBYTE p2 = (LPCBYTE)rhs;

    for (SIZE_T i = 0; i < count; ++i)
    {
        if (p1[i] < p2[i])
        {
            MDK_LOG_DEBUG("Returning -1");
            return -1;
        }
        else if (p1[i] > p2[i])
        {
            MDK_LOG_DEBUG("Returning 1");
            return 1;
        }
    }

    MDK_LOG_DEBUG("Returning 0");

    return 0;
}

/**
 * @brief Copies the contents of a source memory block to a destination memory block.
 *
 * @param dest The pointer to the destination memory block to copy the bytes to.
 * @param src The pointer to the source memory block to copy the bytes from.
 * @param count The number of bytes to copy from the source to the destination.
 * @return The pointer to destination memory block where bytes were copied to.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkCopyMemory(_Inout_ LPVOID dest, _In_ LPCVOID src, _In_ SIZE_T count)
{
    MDK_LOG_DEBUG("Calling with (dest=0x%p, src=0x%p, count=%zu)", dest, src, count);

    PCHAR cdest = (PCHAR)dest;
    PCHAR csrc = (PCHAR)src;

    while (count--)
    {
        *cdest++ = *csrc++;
    }

    MDK_LOG_DEBUG("Returning 0x%p", dest);

    return dest;
}

/**
 * @brief Securely fills a block of memory with a specific fill value, given a pointer to the block and the length, in bytes, to be filled.
 *
 * @param dest Pointer to the memory block to be filled.
 * @param fill Value to fill the destination memory block with. This value is copied to every byte in the memory block that is defined by dest and count.
 * @param count Number of bytes in the block of memory to be filled.
 */
MDK_TEXT_SEC(MDK) static VOID MdkFillMemory(_Inout_ LPVOID dest, _In_ SIZE_T count, _In_ INT fill)
{
    MDK_LOG_DEBUG("Calling with (dest=0x%p, count=%zu, fill=0x%02x)", dest, (unsigned long long)count, fill);

    volatile PCHAR cdest = (volatile PCHAR)dest;

    while (count--)
    {
        *cdest++ = fill;
    }
}

/**
 * @brief Fills a block of memory with zeros, given a pointer to the block and the length, in bytes, to be filled.
 *
 * @param dest Pointer to the memory block to be filled with zeros.
 * @param count Number of bytes to fill with zeros.
 * @return None.
 */
MDK_TEXT_SEC(MDK) static VOID MdkZeroMemory(_Inout_ LPVOID dest, _In_ SIZE_T count)
{
    MDK_LOG_DEBUG("Calling with (dest=0x%p, count=%zu)", dest, count);
    MdkFillMemory(dest, count, 0);
}

#pragma clang optimize on

/**
 * @brief Finds the first occurrence of a given pattern of bytes in a memory block.
 * 
 * @param buffer The memory block to search in.
 * @param bsize The size in bytes of the buffer.
 * @param pattern The series of bytes to look for.
 * @param psize The size in bytes of the pattern.
 * @return The pointer the the beginning of the pattern in the buffer, or NULL if it fails.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkFindPattern(_In_ LPBYTE buffer, _In_ SIZE_T bsize, _In_ LPBYTE pattern, _In_ SIZE_T psize)
{
    MDK_LOG_DEBUG("Calling with (buffer=0x%p, bsize=%zu, pattern=0x%p, psize=%zu)", buffer, bsize, pattern, psize);

    if (!buffer || !bsize || !pattern || !psize)
    {
        MDK_LOG_DEBUG("Invalid argument, returning NULL");
        return NULL;
    }

    if (bsize >= psize)
    {
        SIZE_T i = 0;
        SIZE_T count = bsize - psize + 1;

        for (i = 0; i < count; ++i)
        {
            if (MdkCompareMemory(buffer + i, pattern, psize) == 0)
            {
                MDK_LOG_DEBUG("Pattern found at 0x%p", buffer + i);
                return buffer + i;
            }
        }
    }

    MDK_LOG_DEBUG("Pattern not found, returning NULL");

    return NULL;
}

#endif // _MDK_MEMORY_H_
