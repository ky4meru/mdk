/**
 * @file Internals.h
 * @author Ky4meru (@ky4meru)
 * @brief PEB walking via hash resolution.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_INTERNALS_H_
#define _MDK_INTERNALS_H_

#include "Hashes.h"
#include "Macros.h"
#include "Types.h"

/**
 * @brief Gets a pointer to the Thread Environment Block (TEB) of the current thread. 
 * 
 * @return The pointer to the Thread Environment Block (PTEB) of the current thread.
 */
MDK_TEXT_SEC(MDK) static MDK_PTEB MdkCurrentTeb(VOID)
{
    return (MDK_PTEB)__readgsqword(0x30);
}

/**
 * @brief Gets a pointer to the Process Environment Block (PEB) of the current process.
 *
 * @return The pointer to the Process Environment Block (PPEB) of the current process.
 */
MDK_TEXT_SEC(MDK) static MDK_PPEB MdkCurrentPeb(VOID)
{
    return MdkCurrentTeb()->ProcessEnvironmentBlock;
}

/**
 * @brief Retrieves the calling thread's last-error code value. 
 *
 * @return The return value is the calling thread's last-error code.
 */
MDK_TEXT_SEC(MDK) static DWORD MdkGetLastError(VOID)
{
    return MdkCurrentTeb()->LastErrorValue;
}

/**
 * @brief Sets the last-error code for the calling thread.
 * 
 * @param code The last-error code for the thread.
 */
MDK_TEXT_SEC(MDK) static VOID MdkSetLastError(_In_ DWORD code)
{
    MdkCurrentTeb()->LastErrorValue = code;
}

/**
 * @brief Retrieves the KUSER_SHARED_DATA structure in-memory.
 * 
 * @return The pointer to the KUSER_SHARED_DATA structure.
 */
MDK_TEXT_SEC(MDK) static MDK_KUSER_SHARED_DATA CONST* MdkSharedUserData(VOID)
{
    return (MDK_KUSER_SHARED_DATA* CONST)0x7FFE0000;
}

/**
 * @brief Retrieves the number of milliseconds that have elapsed since the system was started.
 * 
 * @return The number of milliseconds. There is no error return.
 */
MDK_TEXT_SEC(MDK) static DWORD MdkGetTickCount(VOID)
{
    return MDK_CAST_UINT((MdkSharedUserData()->TickCountMultiplier * (ULONGLONG)MdkSharedUserData()->TickCount.LowPart) >> 0x18);
}

/**
 * @brief Gets the pointer to a module from its hash.
 *
 * @param hash The hash of the module.
 * @return The pointer to the module. Returns NULL if the module was not found or if the hash is NULL.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkGetModuleHandleByHash(_In_ DWORD hash)
{
    MDK_LOG_DEBUG("Calling with (hash=0x%08x)", hash);

    if (!hash)
    {
        MDK_LOG_DEBUG("Argument 'hash' is NULL, returning NULL");
        return NULL;
    }

    LPVOID module = NULL;
    MDK_PLDR_DATA_TABLE_ENTRY ldr = NULL;
    MDK_PPEB peb = MdkCurrentPeb();
    PLIST_ENTRY	hdr = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY ent = hdr->Flink;

    for (; hdr != ent; ent = ent->Flink)
    {
        ldr = (MDK_PLDR_DATA_TABLE_ENTRY)ent;

        if (MdkRunTimeHashString(ldr->BaseDllName.Buffer, ldr->BaseDllName.Length) == hash)
        {
            module = ldr->DllBase;
            MDK_LOG_DEBUG("Found module at 0x%p", module);
            break;
        }
    }

    if (!module)
    {
        MDK_LOG_DEBUG("Module not found, returning NULL");
    }

    return module;
}

/**
 * @brief Gets the pointer to a procedure (function or syscall) from its hash.
 *
 * @param module The pointer to the module where the procedure is stored.
 * @param hash The hash of the procedure.
 * @return The pointer to the procedure. Returns NULL if the procedure was not found, if module is NULL or if hash is NULL.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkGetProcAddressByHash(_In_ LPVOID module, _In_ DWORD hash)
{
    MDK_LOG_DEBUG("Calling with (module=0x%p, hash=0x%08x)", module, hash);

    if (!module || !hash)
    {
        MDK_LOG_DEBUG("Argument 'module' or 'hash' is NULL, returning NULL");
        return NULL;
    }

    LPVOID proc = NULL;
    PUINT16	aoo = NULL;
    PUINT32	aof = NULL;
    PUINT32	aon = NULL;
    PIMAGE_DOS_HEADER hdr = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)(MDK_CAST_UPTR(hdr) + hdr->e_lfanew);
    PIMAGE_DATA_DIRECTORY dir = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY	exp = NULL;

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
                proc = MDK_CAST_VPTR(MDK_CAST_UPTR(hdr) + aof[aoo[i]]);
                MDK_LOG_DEBUG("Found proc at 0x%p", proc);
                break;
            }
        }
    }

    if (!proc)
    {
        MDK_LOG_DEBUG("Proc not found, returning NULL");
    }

    return proc;
}

/**
 * @brief Gets the address of a PE section from its name hash.
 *
 * @param module The base address of the loaded module.
 * @param hash The hash of the section name to find.
 * @param size The pointer to a variable that receives the size of the section, in bytes.
 * @return The in-memory address of the section, or NULL if the section was not found or the PE headers are invalid.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkGetSectionAddressByHash(_In_ LPVOID module, _In_ DWORD hash, _Out_ PDWORD size)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)(MDK_CAST_UPTR(module) + dos->e_lfanew);

    if (nth->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);

    for (DWORD i = 0; i < nth->FileHeader.NumberOfSections; ++i)
    {
        if (MdkRunTimeHashString(sec[i].Name, 0) == hash)
        {
            *size = sec[i].SizeOfRawData;
            return MDK_CAST_VPTR(MDK_CAST_UPTR(module) + sec[i].VirtualAddress);
        }
    }

    return NULL;
}

#endif // _MDK_INTERNALS_H_
