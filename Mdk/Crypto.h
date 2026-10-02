/**
 * @file Crypto.h
 * @author Ky4meru (@ky4meru)
 * @brief Cryptographic primitives for evasion.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_CRYPTO_H_
#define _MDK_CRYPTO_H_

#include "Macros.h"
#include "Memory.h"

/**
 * @brief Rotates value's bits to the right.
 *
 * @param value The value to rotate.
 * @param shift The number of bits to rotate.
 * @return The rotated value. There is no error return.
 */
MDK_TEXT_SEC(MDK) static ULONGLONG MdkRotr64(_In_ ULONGLONG value, _In_ INT shift)
{
    return ((value >> shift) | (value << (0x40 - shift)));
}

/**
 * @brief Encodes the specified pointer with a system-specific value.
 *
 * @param ptr The pointer to encode.
 * @return The encoded pointer.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkEncodeSystemPointer(_In_ LPVOID ptr)
{
    ULONG msk = *(PULONG)0x7FFE0330;
    return MDK_CAST_VPTR(MdkRotr64(msk ^ MDK_CAST_UPTR(ptr), msk & 0x3F));
}

#pragma clang optimize off

/**
 * @brief Encrypts a buffer by XOR-ing it with a key.
 *
 * @param buffer The data to encrypt.
 * @param bsize The size of the buffer in bytes.
 * @param key The key to use for the encryption.
 * @param ksize The size of the key in bytes.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkXor(_In_ PBYTE buffer, _In_ SIZE_T bsize, _In_ PBYTE key, _In_ SIZE_T ksize)
{
    if (!buffer || !bsize || !key || !ksize)
    {
        return FALSE;
    }

    for (SIZE_T i = 0; i < bsize; ++i)
    {
        buffer[i] ^= key[i % ksize];
    }

    return TRUE;
}

/**
 * @brief Encrypts a buffer by RC4-ing it with a key.
 *
 * @param buffer The data to encrypt.
 * @param bsize The size of the buffer in bytes.
 * @param key The key to use for the encryption.
 * @param ksize The size of the key in bytes.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkRc4(_In_ PUCHAR buffer, _In_ DWORD bsize, _In_ PUCHAR key, _In_ DWORD ksize)
{
    if (!buffer || !bsize || !key || !ksize)
    {
        return FALSE;
    }

    UCHAR t = 0;
    UCHAR s[256];
    INT r = 0;
    DWORD n = 0;
    DWORD j = 0;
    DWORD i = 0;

    for (i = 0; i < 256; ++i)
    {
        s[i] = i;
    }

    for (i = 0, j = 0; i < 256; ++i)
    {
        j = (j + s[i] + key[i % ksize]) % 256;
        t = s[i];
        s[i] = s[j];
        s[j] = t;
    }

    for (i = 0, j = 0, n = 0; n < bsize; ++n)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        t = s[i];
        s[i] = s[j];
        s[j] = t;
        r = s[(s[i] + s[j]) % 256];
        buffer[n] = r ^ buffer[n];
    }

    return TRUE;
}

/**
 * @brief Encodes a raw buffer into Base64.
 *
 * @param buffer The raw buffer to encode.
 * @param length The length of the buffer in bytes.
 * @param output The output buffer in which the Base64 string is stored. It shall have at least ((length + 2) / 3) * 4 + 1 bytes allocated.
 * @return True if the function succeeds, false otherwise.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkEncodeBase64(_In_ PBYTE buffer, _In_ DWORD length, _Outptr_ PCHAR output)
{
    if (!buffer || !length || !output)
    {
        return FALSE;
    }

    DWORD i = 0;
    DWORD j = 0;
    CHAR alp[65];

    MdkZeroMemory(alp, sizeof(alp));

    DWORD map = 0;

    for (CHAR c = 'A'; c <= 'Z'; ++c)
    {
        alp[map++] = c;
    }

    for (CHAR c = 'a'; c <= 'z'; ++c)
    {
        alp[map++] = c;
    }

    for (CHAR c = '0'; c <= '9'; ++c)
    {
        alp[map++] = c;
    }

    alp[map++] = '+';
    alp[map++] = '/';

    for (i = 0; i + 2 < length; i += 3)
    {
        output[j++] = alp[(buffer[i] >> 2) & 0x3F];
        output[j++] = alp[((buffer[i] & 0x03) << 4) | ((buffer[i + 1] >> 4) & 0x0F)];
        output[j++] = alp[((buffer[i + 1] & 0x0F) << 2) | ((buffer[i + 2] >> 6) & 0x03)];
        output[j++] = alp[buffer[i + 2] & 0x3F];
    }

    if (i < length)
    {
        output[j++] = alp[(buffer[i] >> 2) & 0x3F];

        if (i + 1 < length)
        {
            output[j++] = alp[((buffer[i] & 0x03) << 4) | ((buffer[i + 1] >> 4) & 0x0F)];
            output[j++] = alp[((buffer[i + 1] & 0x0F) << 2)];
        }
        else
        {
            output[j++] = alp[((buffer[i] & 0x03) << 4)];
            output[j++] = '=';
        }

        output[j++] = '=';
    }

    output[j] = '\0';

    MdkZeroMemory(alp, sizeof(alp));

    return TRUE;
}

/**
 * @brief Decodes a Base64-encoded buffer.
 *
 * @param buffer The Base64-encoded buffer to decode.
 * @param length The length of the buffer.
 * @param output The output buffer in which decoded data is stored. It shall have at least (length / 4) * 3 bytes allocated.
 * @return True if the function succeeds, false otherwise.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkDecodeBase64(_In_ PCHAR buffer, _In_ DWORD length, _Outptr_ PCHAR output)
{
    if (!buffer || !length || !output)
    {
        return FALSE;
    }

    DWORD map = 0;
    CHAR tmp[4];
    CHAR idx = 0;
    CHAR enc = 0;
    CHAR alp[64];

    MdkZeroMemory(tmp, sizeof(tmp));
    MdkZeroMemory(alp, sizeof(alp));

    for (CHAR i = 'A'; i <= 'Z'; ++i)
    {
        alp[map++] = i;
    }

    for (CHAR i = 'a'; i <= 'z'; ++i)
    {
        alp[map++] = i;
    }

    for (CHAR i = '0'; i <= '9'; ++i)
    {
        alp[map++] = i;
    }

    alp[map++] = '+';
    alp[map++] = '/';

    for (DWORD i = 0; i < length; i++)
    {
        enc = 0;

        while (enc < 64 && alp[(INT)enc] != buffer[i])
        {
            ++enc;
        }

        tmp[(INT)idx++] = enc;

        if (idx == 4)
        {
            *output++ = (tmp[0] << 2) + (tmp[1] >> 4);

            if (tmp[2] != 64)
            {
                *output++ = (tmp[1] << 4) + (tmp[2] >> 2);
            }

            if (tmp[3] != 64)
            {
                *output++ = (tmp[2] << 6) + tmp[3];
            }

            idx = 0;
        }
    }

    MdkZeroMemory(tmp, sizeof(tmp));
    MdkZeroMemory(alp, sizeof(alp));

    return TRUE;
}

#pragma clang optimize on

#endif // _MDK_CRYPTO_H_
