/**
 * @file Processes.h
 * @author Ky4meru (@ky4meru)
 * @brief Process and thread operations.
 * @version 0.4
 * @date 2026-09-15
 * @copyright Copyright (c) 2024-2026
 */

#ifndef _MDK_PROCESSES_H_
#define _MDK_PROCESSES_H_

#include "Macros.h"
#include "Strings.h"
#include "Wrappers.h"

/**
 * @brief Gets the pointer to a module from its hash in a remote process.
 *
 * @param phd The handle on the remote process.
 * @param hash The hash of the module.
 * @return The pointer to the module. Returns NULL if the module was not found, if the remote process handle is NULL or if the hash is NULL.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkGetRemoteModuleHandleByHash(_In_ HANDLE phd, _In_ DWORD hash)
{
    if (!phd || !hash)
    {
        return NULL;
    }

    MDK_DECL_PROC(NtQueryInformationProcess);

    LPVOID mod = NULL;
    NTSTATUS nts = 0;
    PBYTE head = NULL;
    PBYTE addr = NULL;
    PLIST_ENTRY cur = NULL;
    USHORT len = 0;
    WCHAR wn[MAX_PATH];
    MDK_LDR_DATA_TABLE_ENTRY_FULL ent;
    MDK_PEB peb;
    MDK_PEB_LDR_DATA ldr;
    MDK_PROCESS_BASIC_INFORMATION pbi;

    MdkZeroMemory(&ent, sizeof(ent));
    MdkZeroMemory(&peb, sizeof(peb));
    MdkZeroMemory(&pbi, sizeof(pbi));
    MdkZeroMemory(&ldr, sizeof(ldr));
    MdkZeroMemory(wn, sizeof(wn));

    nts = MDK_INDIRECT_SYSCALL(NtQueryInformationProcess, phd, 0, &pbi, sizeof(pbi), NULL);

    if (!MDK_SUCCEEDED(nts) || !pbi.PebBaseAddress)
    {
        return NULL;
    }

    if (!MdkReadProcessMemory(phd, pbi.PebBaseAddress, &peb, sizeof(peb), NULL) || !peb.Ldr)
    {
        return NULL;
    }

    if (!MdkReadProcessMemory(phd, peb.Ldr, &ldr, sizeof(ldr), NULL))
    {
        return NULL;
    }

    head = (PBYTE)peb.Ldr + offsetof(MDK_PEB_LDR_DATA, InMemoryOrderModuleList);
    cur = ldr.InMemoryOrderModuleList.Flink;

    for (DWORD i = 0; i < 1024 && (PBYTE)cur != head; ++i)
    {
        addr = (PBYTE)cur - offsetof(MDK_LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);

        if (!MdkReadProcessMemory(phd, addr, &ent, sizeof(ent), NULL))
        {
            break;
        }

        if (ent.BaseDllName.Buffer && ent.BaseDllName.Length)
        {
            len = ent.BaseDllName.Length;

            if (len > sizeof(wn) - sizeof(WCHAR))
            {
                len = sizeof(wn) - sizeof(WCHAR);
            }

            if (MdkReadProcessMemory(phd, ent.BaseDllName.Buffer, wn, len, NULL))
            {
                if (MdkRunTimeHashString(wn, len) == hash)
                {
                    mod = ent.DllBase;
                    break;
                }
            }

            MdkZeroMemory(wn, sizeof(wn));
        }

        cur = ent.InMemoryOrderLinks.Flink;
    }

    MdkZeroMemory(&ent, sizeof(ent));
    MdkZeroMemory(&peb, sizeof(peb));
    MdkZeroMemory(&pbi, sizeof(pbi));
    MdkZeroMemory(&ldr, sizeof(ldr));
    MdkZeroMemory(wn, sizeof(wn));

    return mod;
}

/**
 * @brief Gets the pointer to a procedure from its hash in a remote process.
 *
 * @param phd The handle on the remote process.
 * @param module The pointer to the module in which belongs the procedure.
 * @param hash The hash of the procedure.
 * @return The pointer to the procedure. Returns NULL if the procedure was not found, if the remote process handle is NULL, if the module is NULL or if the hash is NULL.
 */
MDK_TEXT_SEC(MDK) static LPVOID MdkGetRemoteProcAddressByHash(_In_ HANDLE phd, _In_ LPVOID module, _In_ DWORD hash)
{
    if (!phd || phd == INVALID_HANDLE_VALUE || !module || !hash)
    {
        return NULL;
    }

    DWORD foff = 0;
    DWORD off = 0;
    DWORD rva = 0;
    DWORD size = 0x1000;
    IMAGE_EXPORT_DIRECTORY exp;
    LPVOID buffer = NULL;
    LPVOID proc = NULL;
    PCHAR name = NULL;
    PIMAGE_DATA_DIRECTORY dir = NULL;
    PIMAGE_DOS_HEADER dos = NULL;
    PIMAGE_NT_HEADERS nth = NULL;
    WORD ord = NULL;

    MdkZeroMemory(&exp, sizeof(exp));

    if ((buffer = MdkMalloc(size)) == NULL)
    {
        return NULL;
    }

    if (!MdkReadProcessMemory(phd, module, buffer, size, NULL))
    {
        MdkFree(buffer);
        return NULL;
    }

    dos = (PIMAGE_DOS_HEADER)buffer;
    nth = (PIMAGE_NT_HEADERS)(MDK_CAST_UPTR(buffer) + dos->e_lfanew);
    dir = nth->OptionalHeader.DataDirectory;
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (!MdkReadProcessMemory(phd, MDK_CAST_VPTR(rva + MDK_CAST_UPTR(module)), &exp, sizeof(exp), NULL))
    {
        MdkFree(buffer);
        return NULL;
    }

    for (DWORD i = 0; i < exp.NumberOfFunctions; ++i)
    {
        if ((name = (PCHAR)MdkMalloc(MAX_PATH)) == NULL)
        {
            break;
        }

        if (!MdkReadProcessMemory(phd, MDK_CAST_VPTR(MDK_CAST_UPTR(module) + exp.AddressOfNames + i * sizeof(DWORD)), &off, sizeof(DWORD), NULL))
        {
            MdkFree(name);
            break;
        }

        if (!MdkReadProcessMemory(phd, MDK_CAST_VPTR(MDK_CAST_UPTR(module) + off), name, MAX_PATH, NULL))
        {
            MdkFree(name);
            break;
        }

        if (MdkRunTimeHashString(name, 0) == hash)
        {
            MdkFree(name);

            if (!MdkReadProcessMemory(phd, MDK_CAST_VPTR(MDK_CAST_UPTR(module) + exp.AddressOfNameOrdinals + i * sizeof(WORD)), &ord, sizeof(WORD), NULL))
            {
                break;
            }

            if (!MdkReadProcessMemory(phd, MDK_CAST_VPTR(MDK_CAST_UPTR(module) + exp.AddressOfFunctions + ord * sizeof(DWORD)), &foff, sizeof(DWORD), NULL))
            {
                break;
            }

            proc = MDK_CAST_VPTR(MDK_CAST_UPTR(module) + foff);
            break;
        }

        MdkFree(name);
        name = NULL;
    }

    MdkFree(buffer);

    return proc;
}

/**
 * @brief Retrieves the process identifier of a process by its image name.
 *
 * When multiple processes share the same name, the function identifies the broker process whose parent is not a member
 * of the matched set. If no broker can be determined, the first match is returned.
 *
 * @param name The image name of the process to find (e.g. "notepad.exe").
 * @return The process identifier, or 0 if the process was not found.
 */
MDK_TEXT_SEC(MDK) static DWORD MdkGetProcessIdByName(_In_ LPCSTR name)
{
    if (!name || !name[0])
    {
        return NULL;
    }

    MDK_DECL_PROC(NtQuerySystemInformation);

    BOOL ins = FALSE;
    BOOL done = FALSE;
    DWORD cap = 0;
    DWORD cnt = 0;
    DWORD len = 0;
    DWORD pid = 0;
    DWORD wch = 0;
    LPVOID buf = NULL;
    MDK_PSYSTEM_PROCESS_INFORMATION info = NULL;
    MDK_PSYSTEM_PROCESS_INFORMATION fst = NULL;
    MDK_PPROC_MATCH mch = NULL;
    NTSTATUS nts = 0;
    ULONG need = 0;
    ULONG size = 0x10000;
    WCHAR wn[MAX_PATH];

    MdkZeroMemory(wn, sizeof(wn));

    for (DWORD i = 0; name[i] && i < MAX_PATH - 1; ++i)
    {
        wn[i] = (WCHAR)name[i];
        wch++;
    }

    for (DWORD i = 0; i < 5; ++i)
    {
        need = 0;

        if ((buf = MdkMalloc(size)) == NULL)
        {
            MdkZeroMemory(wn, sizeof(wn));
            return 0;
        }

        nts = MDK_INDIRECT_SYSCALL(NtQuerySystemInformation, 5, buf, size, &need);

        if (MDK_SUCCEEDED(nts))
        {
            break;
        }

        MdkFree(buf);
        buf = NULL;
        size = need ? need + 0x1000 : size * 2;
    }

    if (buf != NULL)
    {
        fst = (MDK_PSYSTEM_PROCESS_INFORMATION)buf;

        info = fst;
        while (TRUE)
        {
            if (info->ImageName.Buffer && info->ImageName.Length)
            {
                len = info->ImageName.Length / sizeof(WCHAR);

                if (len == wch && MdkCompareInsensitiveWideString(info->ImageName.Buffer, wn) == 0)
                {
                    cnt++;
                }
            }

            if (info->NextEntryOffset == 0)
            {
                break;
            }

            info = (MDK_PSYSTEM_PROCESS_INFORMATION)(MDK_CAST_UPTR(info) + info->NextEntryOffset);
        }

        if (cnt == 1)
        {
            info = fst;
            while (TRUE)
            {
                if (info->ImageName.Buffer && info->ImageName.Length)
                {
                    len = info->ImageName.Length / sizeof(WCHAR);

                    if (len == wch && MdkCompareInsensitiveWideString(info->ImageName.Buffer, wn) == 0)
                    {
                        pid = MDK_CAST_UINT(info->UniqueProcessId);
                        break;
                    }
                }

                if (info->NextEntryOffset == 0)
                {
                    break;
                }

                info = (MDK_PSYSTEM_PROCESS_INFORMATION)(MDK_CAST_UPTR(info) + info->NextEntryOffset);
            }

            done = TRUE;
        }

        if (!done && cnt > 1)
        {
            mch = (MDK_PPROC_MATCH)MdkMalloc(cnt * sizeof(MDK_PROC_MATCH));
        }

        if (mch != NULL)
        {
            cap = cnt;
            cnt = 0;
            info = fst;

            while (TRUE)
            {
                if (info->ImageName.Buffer && info->ImageName.Length)
                {
                    len = info->ImageName.Length / sizeof(WCHAR);

                    if (len == wch && MdkCompareInsensitiveWideString(info->ImageName.Buffer, wn) == 0)
                    {
                        if (cnt < cap)
                        {
                            mch[cnt].Pid = MDK_CAST_UINT(info->UniqueProcessId);
                            mch[cnt].ParentPid = MDK_CAST_UINT(info->InheritedFromUniqueProcessId);
                            cnt++;
                        }
                    }
                }

                if (info->NextEntryOffset == 0)
                {
                    break;
                }

                info = (MDK_PSYSTEM_PROCESS_INFORMATION)(MDK_CAST_UPTR(info) + info->NextEntryOffset);
            }

            for (DWORD i = 0; i < cnt && pid == 0; ++i)
            {
                ins = FALSE;

                for (DWORD j = 0; j < cnt; ++j)
                {
                    if (mch[i].ParentPid == mch[j].Pid)
                    {
                        ins = TRUE;
                        break;
                    }
                }

                if (!ins)
                {
                    pid = mch[i].Pid;
                }
            }

            if (pid == 0 && cnt > 0)
            {
                pid = mch[0].Pid;
            }

            MdkFree(mch);
        }
    }

    MdkZeroMemory(wn, sizeof(wn));

    if (buf != NULL)
    {
        MdkFree(buf);
    }

    return pid;
}

/**
 * @brief Creates a new process in a suspended state and assigns it to a job object.
 * 
 * @param path The file path of the executable image to run.
 * @param phd The pointer to a variable that receives the handle to the new process.
 * @param thd The pointer to a variable that receives the handle to the initial thread of the new process.
 * @param job The handle to the job object to assign the new process to.
 * @return If the function succeeds, the return value is nonzero.
 */
MDK_TEXT_SEC(MDK) static BOOL MdkCreateSuspendedProcess(_In_ LPCSTR path, _Out_ PHANDLE phd, _Out_ PHANDLE thd, _In_ HANDLE job)
{
    if (!path || !phd || !thd || !job)
    {
        return FALSE;
    }

    MDK_DECL_DLL(Ntdll);
    MDK_DECL_PROC(NtCreateUserProcess);
    MDK_DECL_PROC(RtlCreateProcessParametersEx);
    MDK_DECL_PROC(RtlDestroyProcessParameters);
    MDK_DECL_PROC(RtlDosPathNameToNtPathName_U);
    MDK_DECL_PROC(RtlFreeHeap);

    BOOL ret = FALSE;
    NTSTATUS nts = 0;
    MDK_PPS_ATTRIBUTE_LIST atr = NULL;
    MDK_PRTL_USER_PROCESS_PARAMETERS prm = NULL;
    MDK_PS_CREATE_INFO inf;
    MDK_UNICODE_STRING ntp;
    SIZE_T tot = 0;
    WCHAR wfn[MAX_PATH];

    MdkZeroMemory(&inf, sizeof(inf));
    MdkZeroMemory(&ntp, sizeof(ntp));
    MdkZeroMemory(wfn, sizeof(wfn));

    *phd = NULL;
    *thd = NULL;

    for (DWORD i = 0; path[i] && i < MAX_PATH - 1; ++i)
    {
        wfn[i] = (WCHAR)path[i];
    }

    if (!MDK_CAST_UPTR(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlDosPathNameToNtPathName_U), wfn, &ntp, NULL, NULL)))
    {
        MdkZeroMemory(wfn, sizeof(wfn));
        return FALSE;
    }

    nts = (NTSTATUS)MDK_CAST_UPTR(MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlCreateProcessParametersEx), &prm, &ntp, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0x1));

    if (!MDK_SUCCEEDED(nts))
    {
        MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlFreeHeap), MdkCurrentPeb()->ProcessHeap, NULL, ntp.Buffer);
        MdkZeroMemory(&ntp, sizeof(ntp));
        MdkZeroMemory(wfn, sizeof(wfn));
        return FALSE;
    }

    inf.Size = sizeof(MDK_PS_CREATE_INFO);
    inf.State = MdkPsCreateInitialState;

    tot = FIELD_OFFSET(MDK_PS_ATTRIBUTE_LIST, Attributes) + 2 * sizeof(MDK_PS_ATTRIBUTE);
    atr = (MDK_PPS_ATTRIBUTE_LIST)MdkMalloc(tot);

    if (!atr)
    {
        MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlDestroyProcessParameters), prm);
        MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlFreeHeap), MdkCurrentPeb()->ProcessHeap, NULL, ntp.Buffer);
        MdkZeroMemory(&ntp, sizeof(ntp));
        MdkZeroMemory(wfn, sizeof(wfn));
        return FALSE;
    }

    atr->TotalLength = tot;

    atr->Attributes[0].Attribute = 0x20005;
    atr->Attributes[0].Size = ntp.Length;
    atr->Attributes[0].Value = MDK_CAST_UPTR(ntp.Buffer);

    atr->Attributes[1].Attribute = 0x00020013;
    atr->Attributes[1].Size = sizeof(HANDLE);
    atr->Attributes[1].Value = MDK_CAST_UPTR(&job);

    nts = MDK_INDIRECT_SYSCALL(NtCreateUserProcess, phd, thd, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, 0x1, prm, &inf, atr);

    if (MDK_SUCCEEDED(nts))
    {
        ret = TRUE;
    }

    MdkZeroMemory(atr, tot);
    MdkFree(atr);
    MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlDestroyProcessParameters), prm);
    MDK_CALL_PROC(MDK_GET_PROC(Ntdll, RtlFreeHeap), MdkCurrentPeb()->ProcessHeap, NULL, ntp.Buffer);
    MdkZeroMemory(&inf, sizeof(inf));
    MdkZeroMemory(&ntp, sizeof(ntp));
    MdkZeroMemory(wfn, sizeof(wfn));

    return ret;
}

#endif // _MDK_PROCESSES_H_