/**
 * @file Wrappers.h
 * @author Ky4meru (@ky4meru)
 * @brief High-level wrappers around NT syscalls.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_WRAPPERS_H_
#define _MDK_WRAPPERS_H_

#include <windows.h>

#include "Internals.h"
#include "Memory.h"
#include "Syscalls.h"

/**
 * @brief Allocates a block of memory from the current process heap.
 *
 * @param size The size in bytes to allocate.
 * @return The pointer to the allocate memory block, or NULL if it fails.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkMalloc(_In_ SIZE_T size)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlAllocateHeap);

    return MDK_CALL_PROC(MDK_GET_SYSCALL(RtlAllocateHeap), MdkCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, size);
}

/**
 * @brief Reallocates a block of memory from the current process heap.
 *
 * @param ptr The pointer to previously allocated memory block (with MdkMalloc).
 * @param size The new size in bytes.
 * @return The pointer to the reallocate memory block, or NULL if it fails.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkRealloc(_In_ LPVOID ptr, _In_ SIZE_T size)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlReAllocateHeap);

    return MDK_CALL_PROC(MDK_GET_SYSCALL(RtlReAllocateHeap), MdkCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, ptr, size);
}

/**
 * @brief Frees a memory block allocated by MdkMalloc.
 *
 * @param ptr The pointer to the memory block to be freed.
 */
MDK_TEXT_SEC(MDK) static VOID MdkFree(_In_ LPVOID ptr)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlFreeHeap);

    MDK_CALL_PROC(MDK_GET_SYSCALL(RtlFreeHeap), MdkCurrentPeb()->ProcessHeap, NULL, ptr);
}

/**
 * @brief Suspends the execution of the current thread until the time-out interval elapses.
 *
 * @param ms The time interval for which execution is to be suspended, in milliseconds.
 */
MDK_TEXT_SEC(MDK) static VOID MdkSleep(_In_ DWORD ms)
{
    MDK_LOG_DEBUG("Calling with (ms=%lu)", ms);

    MDK_DECL_PROC(NtDelayExecution);

    LARGE_INTEGER del;
    NTSTATUS nts = 0;

    MdkZeroMemory(&del, sizeof(del));

    del.QuadPart = -10000LL * ms;
    nts = MDK_INDIRECT_SYSCALL(NtDelayExecution, FALSE, &del);

    MdkSetLastError(nts);
    MdkZeroMemory(&del, sizeof(del));

    MDK_LOG_DEBUG("Finished with status %ld", nts);
}

/**
 * @brief Waits until the specified object is in the signaled state or the time-out interval elapses.
 *
 * @param hd The handle to the object.
 * @param ms The time-out interval, in milliseconds.
 * @return If the function succeeds, the return value indicates the event that caused the function to return.
 */
MDK_TEXT_SEC(MDK) static DWORD MdkWaitForSingleObject(_In_ HANDLE hd, _In_ DWORD ms)
{
    MDK_LOG_DEBUG("Calling with (hd=0x%p, ms=%lu)", hd, ms);
    
    MDK_DECL_PROC(NtWaitForSingleObject);

    LARGE_INTEGER del;
    PLARGE_INTEGER timeout = NULL;
    NTSTATUS nts = 0;

    MdkZeroMemory(&del, sizeof(del));

    if (ms != INFINITE)
    {
        del.QuadPart = -10000LL * ms;
        timeout = &del;
    }

    nts = MDK_INDIRECT_SYSCALL(NtWaitForSingleObject, hd, FALSE, timeout);

    MdkSetLastError(nts);
    MdkZeroMemory(&del, sizeof(del));

    MDK_LOG_DEBUG("Finished with status %ld", nts);

    return MDK_CAST_UINT(nts);
}

/**
 * @brief Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero.
 *
 * @param phd The handle to a process. The function allocates memory within the virtual address space of this process.
 * @param addr The pointer that specifies a desired starting address for the region of pages that you want to allocate (optional).
 * @param size The size of the region of memory to allocate, in bytes.
 * @param type The type of memory allocation.
 * @param prot The memory protection for the region of pages to be allocated.
 * @return The base address of the allocated region of pages, or NULL if it fails.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkVirtualAllocEx(_In_ HANDLE phd, _In_opt_ LPVOID addr, _In_ SIZE_T size, _In_ DWORD type, _In_ DWORD prot)
{
    MDK_DECL_PROC(NtAllocateVirtualMemoryEx);
    MDK_DECL_PROC(NtAllocateVirtualMemory);
    
    LPVOID mem = addr;
    NTSTATUS nts = 0;
    SIZE_T tmp = size;
    MDK_MEM_EXTENDED_PARAMETER param;

    MdkZeroMemory(&param, sizeof(param));
    param.Type = 5;
    param.ULong64 = 0x1;

    nts = MDK_INDIRECT_SYSCALL(NtAllocateVirtualMemoryEx, phd, &mem, &tmp, type, prot, &param, 1);

    if (!MDK_SUCCEEDED(nts))
    {
        mem = addr;
        tmp = size;
        nts = MDK_INDIRECT_SYSCALL(NtAllocateVirtualMemory, phd, &mem, NULL, &tmp, type, prot);
    }

    if (!MDK_SUCCEEDED(nts))
    {
        mem = NULL;
    }

    MdkSetLastError(nts);

    return mem;
}

/**
 * @brief Changes the protection on a region of committed pages in the virtual address space of a specified process.
 *
 * @param phd The handle to the process whose memory protection is to be changed.
 * @param addr The pointer to the base address of the region of pages whose access protection attributes are to be changed.
 * @param size The size of the region whose access protection attributes are changed, in bytes.
 * @param prot The memory protection option.
 * @param old The pointer to a variable that receives the previous access protection of the first page in the specified region of pages.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkVirtualProtectEx(_In_ HANDLE phd, _In_ LPVOID addr, _In_ SIZE_T size, _In_ DWORD prot, _Out_ PDWORD old)
{
    MDK_DECL_PROC(NtProtectVirtualMemory);

    BOOL ret = TRUE;
    LPVOID mem = addr;
    NTSTATUS nts = 0;
    SIZE_T tmp = size;

    nts = MDK_INDIRECT_SYSCALL(NtProtectVirtualMemory, phd, &mem, &tmp, prot, old);

    if (!MDK_SUCCEEDED(nts))
    {
        ret = FALSE;
    }

    MdkSetLastError(nts);

    return ret;
}

/**
 * @brief Writes data to an area of memory in a specified process.
 *
 * @param phd The handle to the process memory to be modified.
 * @param addr The pointer to the base address in the specified process to which data is written.
 * @param buffer The pointer to the buffer that contains data to be written in the address space of the specified process.
 * @param size The number of bytes to be written to the specified process.
 * @param written The pointer to a variable that receives the number of bytes transferred into the specified process.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkWriteProcessMemory(_In_ HANDLE phd, _In_ LPVOID addr, _In_ LPCVOID buffer, _In_ SIZE_T size, _Out_ PSIZE_T written)
{
    MDK_DECL_PROC(NtWriteVirtualMemory);

    BOOL ret = TRUE;
    NTSTATUS nts = 0;

    nts = MDK_INDIRECT_SYSCALL(NtWriteVirtualMemory, phd, addr, buffer, size, written);

    if (!MDK_SUCCEEDED(nts))
    {
        ret = FALSE;
    }

    MdkSetLastError(nts);

    return ret;
}

/**
 * @brief Reads data from an area of memory in a specified process.
 *
 * @param phd The handle to the process with memory that is being read.
 * @param addr The pointer to the base address in the specified process from which to read.
 * @param buffer The pointer to a buffer that receives the contents from the address space of the specified process.
 * @param size The number of bytes to be read from the specified process.
 * @param read The pointer to a variable that receives the number of bytes transferred into the specified buffer.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkReadProcessMemory(_In_ HANDLE phd, _In_ LPCVOID addr, _Out_ LPVOID buffer, _In_ SIZE_T size, _Out_ PSIZE_T read)
{
    MDK_DECL_PROC(NtReadVirtualMemory);

    BOOL ret = TRUE;
    NTSTATUS nts = 0;

    nts = MDK_INDIRECT_SYSCALL(NtReadVirtualMemory, phd, addr, buffer, size, read);

    if (!MDK_SUCCEEDED(nts))
    {
        ret = FALSE;
    }

    MdkSetLastError(nts);

    return ret;
}

/**
 * @brief Retrieves the context of the specified thread.
 *
 * @param thd The handle to the thread whose context is to be retrieved.
 * @param ctx The pointer to a CONTEXT structure that receives the appropriate context of the specified thread.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkGetThreadContext(_In_ HANDLE thd, _Inout_ LPCONTEXT ctx)
{
    MDK_DECL_PROC(NtGetContextThread);

    BOOL ret = TRUE;
    NTSTATUS nts = 0;

    nts = MDK_INDIRECT_SYSCALL(NtGetContextThread, thd, ctx);

    if (!MDK_SUCCEEDED(nts))
    {
        ret = FALSE;
    }

    MdkSetLastError(nts);

    return ret;
}

/**
 * @brief Sets the context for the specified thread.
 *
 * @param thd The handle to the thread whose context is to be set.
 * @param ctx The pointer to a CONTEXT structure that contains the context to be set in the specified thread.
 * @return If the context was set, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkSetThreadContext(_In_ HANDLE thd, _In_ CONST LPCONTEXT ctx)
{
    MDK_DECL_PROC(NtSetContextThread);

    BOOL ret = TRUE;
    NTSTATUS nts = 0;

    nts = MDK_INDIRECT_SYSCALL(NtSetContextThread, thd, ctx);

    if (!MDK_SUCCEEDED(nts))
    {
        ret = FALSE;
    }

    MdkSetLastError(nts);

    return ret;
}

/**
 * @brief Computes a random number in a given range.
 *
 * @param min The range minimum.
 * @param max The range maximum.
 * @return The random value.
 */
MDK_TEXT_SEC(MDK) static DWORD MdkRandom(_In_ DWORD min, _In_ DWORD max)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(RtlRandomEx);

    DWORD tick = MdkGetTickCount();
    ULONGLONG rand = MDK_CAST_UPTR(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlRandomEx), &tick));
    ULONGLONG range = MDK_CAST_UPTR(max - min + 0x1);

    return min + MDK_CAST_UINT(rand % range);
}

/**
 * @brief Provides Control Flow Guard (CFG) with a valid indirect call target and specifies whether it should be marked valid or not.
 *
 * @param phd The handle to the target process.
 * @param addr The start of the virtual memory region whose call targets are being marked valid.
 * @param size The size of the virtual memory region.
 * @return TRUE if the operation was successful; otherwise, FALSE.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkSetProcessValidCallTargets(_In_ HANDLE phd, _In_ LPVOID addr, _In_ SIZE_T size)
{
    MDK_DECL_PROC(NtSetInformationVirtualMemory);
    MDK_DECL_PROC(NtQueryVirtualMemory);

    MEMORY_BASIC_INFORMATION mbi;
    MDK_MEMORY_RANGE_ENTRY mre;
    MDK_CFG_CALL_TARGET_LIST_INFORMATION ctl;
    CFG_CALL_TARGET_INFO cti;
    ULONG nbp = 0;
    NTSTATUS nts = 0;
    BOOL ret = FALSE;

    MdkZeroMemory(&cti, sizeof(cti));
    MdkZeroMemory(&ctl, sizeof(ctl));
    MdkZeroMemory(&mbi, sizeof(mbi));
    MdkZeroMemory(&mre, sizeof(mre));

    nts = MDK_INDIRECT_SYSCALL(NtQueryVirtualMemory, phd, addr, 0x0, &mbi, sizeof(mbi));

    if (MDK_SUCCEEDED(nts))
    {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
        {
            cti.Flags = CFG_CALL_TARGET_VALID;
            cti.Offset = MDK_CAST_UPTR(addr) - MDK_CAST_UPTR(mbi.BaseAddress);
            mre.VirtualAddress = mbi.BaseAddress;
            mre.NumberOfBytes = mbi.RegionSize;
            ctl.NumberOfEntries = 0x1;
            ctl.NumberOfEntriesProcessed = &nbp;
            ctl.CallTargetInfo = &cti;

            nts = MDK_INDIRECT_SYSCALL(NtSetInformationVirtualMemory, phd, 0x2, 0x1, &mre, &ctl, sizeof(ctl));

            if (MDK_SUCCEEDED(nts) || nts == 0xC0000045)
            {
                ret = TRUE;
            }
        }
    }

    MdkSetLastError(nts);

    MdkZeroMemory(&cti, sizeof(cti));
    MdkZeroMemory(&ctl, sizeof(ctl));
    MdkZeroMemory(&mbi, sizeof(mbi));
    MdkZeroMemory(&mre, sizeof(mre));

    return ret;
}

/**
 * @brief Creates or opens a file or I/O device.
 *
 * @param name The name of the file or device to be created or opened.
 * @param access The requested access to the file or device, which can be summarized as read, write, both or neither zero.
 * @param share The requested sharing mode of the file or device, which can be read, write, both, delete, all of these, or none.
 * @param sa A pointer to a SECURITY_ATTRIBUTES structure. If this parameter is NULL, the handle returned cannot be inherited by any child processes the application may create.
 * @param disp An action to take on a file or device that exists or does not exist.
 * @param flags The file or device attributes and flags, FILE_ATTRIBUTE_NORMAL being the most common default value for files.
 * @param tmpl A valid handle to a template file with the GENERIC_READ access right. This parameter can be NULL.
 * @return If the function succeeds, the return value is an open handle to the specified file, device, named pipe, or mail slot. If the function fails, the return value is INVALID_HANDLE_VALUE.
 */
MDK_TEXT_SEC(MDK) static HANDLE MdkCreateFileA(_In_ LPCSTR name, _In_ DWORD access, _In_ DWORD share, _In_opt_ LPSECURITY_ATTRIBUTES sa, _In_ DWORD disp, _In_ DWORD flags, _In_opt_ HANDLE tmpl)
{
    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(NtCreateFile);
    MDK_DECL_PROC(RtlDosPathNameToNtPathName_U);
    MDK_DECL_PROC(RtlFreeHeap);

    HANDLE hd = INVALID_HANDLE_VALUE;
    NTSTATUS nts = 0;
    MDK_IO_STATUS_BLOCK iosb;
    MDK_OBJECT_ATTRIBUTES oa;
    MDK_UNICODE_STRING ntp;
    ULONG cdp = 0;
    ULONG cop = 0x00000040;
    ULONG fat = 0;
    WCHAR wfn[MAX_PATH];

    MdkZeroMemory(&iosb, sizeof(iosb));
    MdkZeroMemory(&oa, sizeof(oa));
    MdkZeroMemory(&ntp, sizeof(ntp));
    MdkZeroMemory(wfn, sizeof(wfn));

    for (DWORD i = 0; name[i] && i < MAX_PATH - 1; ++i)
    {
        wfn[i] = (WCHAR)name[i];
    }

    if (!MDK_CAST_UPTR(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlDosPathNameToNtPathName_U), wfn, &ntp, NULL, NULL)))
    {
        MdkSetLastError(MDK_CAST_UINT(0xC0000039));
        MdkZeroMemory(wfn, sizeof(wfn));
        return INVALID_HANDLE_VALUE;
    }

    switch (disp)
    {
        case CREATE_NEW: cdp = 0x2; break;
        case CREATE_ALWAYS: cdp = 0x5; break;
        case OPEN_EXISTING: cdp = 0x1; break;
        case OPEN_ALWAYS: cdp = 0x3; break;
        case TRUNCATE_EXISTING: cdp = 0x4; break;
        default: cdp = 0x1; break;
    }

    fat = flags & 0x0000FFFF;

    if (!fat)
    {
        fat = FILE_ATTRIBUTE_NORMAL;
    }

    if (!(flags & FILE_FLAG_OVERLAPPED))
    {
        cop |= 0x00000020;
        access |= SYNCHRONIZE;
    }

    if (flags & FILE_FLAG_WRITE_THROUGH)
    {
        cop |= 0x00000002;
    }

    if (flags & FILE_FLAG_NO_BUFFERING)
    {
        cop |= 0x00000008;
    }

    if (flags & FILE_FLAG_RANDOM_ACCESS)
    {
        cop |= 0x00000800;
    }

    if (flags & FILE_FLAG_SEQUENTIAL_SCAN)
    {
        cop |= 0x00000004;
    }

    if (flags & FILE_FLAG_DELETE_ON_CLOSE)
    {
        cop |= 0x00001000;
    }

    if (flags & FILE_FLAG_BACKUP_SEMANTICS)
    {
        cop &= ~0x40u;
        cop |= 0x00004000;
    }

    if (flags & FILE_FLAG_OPEN_REPARSE_POINT)
    {
        cop |= 0x00200000;
    }

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &ntp;
    oa.Attributes = 0x00000040;
    oa.SecurityDescriptor = sa ? sa->lpSecurityDescriptor : NULL;
    oa.SecurityQualityOfService = NULL;

    nts = MDK_INDIRECT_SYSCALL(NtCreateFile, &hd, access, &oa, &iosb, NULL, fat, share, cdp, cop, NULL, NULL);

    MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlFreeHeap), MdkCurrentPeb()->ProcessHeap, NULL, ntp.Buffer);

    if (!MDK_SUCCEEDED(nts))
    {
        hd = INVALID_HANDLE_VALUE;
    }

    MdkSetLastError(nts);

    MdkZeroMemory(&iosb, sizeof(iosb));
    MdkZeroMemory(&oa, sizeof(oa));
    MdkZeroMemory(&ntp, sizeof(ntp));
    MdkZeroMemory(wfn, sizeof(wfn));

    return hd;
}

/**
 * @brief Opens an existing local process object.
 *
 * @param access The access to the process object. This access right is checked against the security descriptor for the process.
 * @param inherit If nonzero, processes created by this process will inherit the handle.
 * @param pid The identifier of the local process to be opened.
 * @return If the function succeeds, the return value is an open handle to the specified process. If the function fails, the return value is NULL.
 */
MDK_TEXT_SEC(MDK) static HANDLE MdkOpenProcess(_In_ DWORD access, _In_ BOOL inherit, _In_ DWORD pid)
{
    MDK_DECL_PROC(NtOpenProcess);

    HANDLE phd = NULL;
    NTSTATUS nts = 0;
    MDK_CLIENT_ID cid;
    MDK_OBJECT_ATTRIBUTES oa;

    MdkZeroMemory(&cid, sizeof(cid));
    MdkZeroMemory(&oa, sizeof(oa));

    oa.Length = sizeof(oa);

    if (inherit)
    {
        oa.Attributes = 0x2;
    }

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    nts = MDK_INDIRECT_SYSCALL(NtOpenProcess, &phd, access, &oa, &cid);

    if (!MDK_SUCCEEDED(nts))
    {
        phd = NULL;
    }

    MdkSetLastError(nts);

    MdkZeroMemory(&cid, sizeof(cid));
    MdkZeroMemory(&oa, sizeof(oa));

    return phd;
}

/**
 * @brief Opens an existing thread object.
 *
 * @param access The access to the thread object. This access right is checked against the security descriptor for the thread.
 * @param inherit If nonzero, processes created by this process will inherit the handle.
 * @param tid The identifier of the thread to be opened.
 * @return If the function succeeds, the return value is an open handle to the specified thread. If the function fails, the return value is NULL.
 */
MDK_TEXT_SEC(MDK) static HANDLE MdkOpenThread(_In_ DWORD access, _In_ BOOL inherit, _In_ DWORD tid)
{
    MDK_DECL_PROC(NtOpenThread);

    HANDLE thd = NULL;
    NTSTATUS nts = 0;
    MDK_CLIENT_ID cid;
    MDK_OBJECT_ATTRIBUTES oa;

    MdkZeroMemory(&cid, sizeof(cid));
    MdkZeroMemory(&oa, sizeof(oa));

    oa.Length = sizeof(oa);

    if (inherit)
    {
        oa.Attributes = 0x2;
    }

    cid.UniqueProcess = NULL;
    cid.UniqueThread = (HANDLE)(ULONG_PTR)tid;

    nts = MDK_INDIRECT_SYSCALL(NtOpenThread, &thd, access, &oa, &cid);

    if (!MDK_SUCCEEDED(nts))
    {
        thd = NULL;
    }

    MdkSetLastError(nts);

    MdkZeroMemory(&cid, sizeof(cid));
    MdkZeroMemory(&oa, sizeof(oa));

    return thd;
}

/**
 * @brief Closes an open object handle.
 *
 * @param hd The handle to an open object.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkCloseHandle(_In_ HANDLE hd)
{
    MDK_LOG_DEBUG("Calling with (hd=0x%p)", hd);

    MDK_DECL_PROC(NtClose);

    BOOL ret = TRUE;
    NTSTATUS nts = 0;

    nts = MDK_INDIRECT_SYSCALL(NtClose, hd);

    if (!MDK_SUCCEEDED(nts))
    {
        ret = FALSE;
    }

    MdkSetLastError(nts);

    MDK_LOG_DEBUG("Finished with status %ld", nts);

    return ret;
}

/**
 * @brief Loads the specified module into the address space of the specified process.
 * 
 * @param phd The handle to the process into which the module is to be loaded.
 * @param path The name of the module. This can be a full path or a relative file name.
 * @return If the function succeeds, the return value is a handle to the mapped module. If the function fails, the return value is NULL.
 */
MDK_TEXT_SEC(MDK) static HMODULE MdkLoadLibraryA(_In_ HANDLE phd, _In_ LPCSTR path)
{
    MDK_DECL_PROC(NtCreateSection);
    MDK_DECL_PROC(NtMapViewOfSection);

    HANDLE fhd = NULL;
    HANDLE shd = NULL;
    HMODULE module = NULL;
    NTSTATUS nts = 0;
    SIZE_T size = 0;

    if ((fhd = MdkCreateFileA(path, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
    {
        nts = MDK_INDIRECT_SYSCALL(NtCreateSection, &shd, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, fhd);

        if (MDK_SUCCEEDED(nts))
        {
            nts = MDK_INDIRECT_SYSCALL(NtMapViewOfSection, shd, phd, &module, NULL, NULL, NULL, &size, 0x1, NULL, PAGE_EXECUTE_READ);
            MdkCloseHandle(shd);
        }

       MdkCloseHandle(fhd);
    }

    MdkSetLastError(nts);

    return module;
}

#endif // _MDK_WRAPPERS_H_
