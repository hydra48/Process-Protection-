
#include "pch.h"
#include <detours.h>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <string>



typedef NTSTATUS(NTAPI* RealNTTerminateProces)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef NTSTATUS(NTAPI* RealNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId);
typedef NTSTATUS(NTAPI* RealNtDuplicateObject)(HANDLE SourceProcessHandle,HANDLE SourceHandle,HANDLE TargetProcessHandle,PHANDLE TargetHandle,ACCESS_MASK DesiredAccess,ULONG HandleAttributes,ULONG Options);

RealNtDuplicateObject NTNtDuplicateObject = nullptr;
RealNTTerminateProces NTTerminateProcess = nullptr;
RealNtOpenProcess NTOpenProcess = nullptr;

DWORD Getnotepadpid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32W structproc = { 0 };
    structproc.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(snap, &structproc)) {
        CloseHandle(snap);
        return 0;
    }
    do {
        if (_wcsicmp(L"notepad.exe", structproc.szExeFile) == 0) {
            DWORD pid = structproc.th32ProcessID;
            CloseHandle(snap);
            return pid;
        }
    } while (Process32NextW(snap, &structproc));
    CloseHandle(snap);
    return 0;
}
thread_local bool inOpenProcess = false;


NTSTATUS NTAPI HookedOpenProcess(
    PHANDLE processhandle,
    ACCESS_MASK desiredaccess,
    POBJECT_ATTRIBUTES objectattributes,CLIENT_ID * clientid)
{
    DWORD notepadpid = Getnotepadpid();
    DWORD pid = 0;

    if (clientid && clientid->UniqueProcess)
        pid = HandleToULong(clientid->UniqueProcess);



    if (pid == notepadpid)
    {
        desiredaccess &= ~PROCESS_TERMINATE;
        desiredaccess &= ~MAXIMUM_ALLOWED;

    }

    NTSTATUS status = NTOpenProcess(processhandle,desiredaccess,objectattributes,clientid );

    


    return status;
}


NTSTATUS NTAPI HookedNtDuplicateObject( HANDLE sourceprocessHandle, HANDLE sourcehandle, HANDLE targetprocessHandle, PHANDLE targethandle, ACCESS_MASK desiredaccess, ULONG handleattributes,ULONG Options)
{
    DWORD notepadpid = Getnotepadpid();
    DWORD pid = GetProcessId(sourcehandle);
    if (pid == notepadpid)
    {
        if (Options & DUPLICATE_SAME_ACCESS)
            return (NTSTATUS)0xC0000022L;
        desiredaccess &= ~PROCESS_TERMINATE;
        desiredaccess &= ~MAXIMUM_ALLOWED;
    }
    return NTNtDuplicateObject(sourceprocessHandle,sourcehandle,targetprocessHandle,targethandle,desiredaccess,handleattributes,Options);
}

NTSTATUS NTAPI HookedTerminatedProcess( HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    DWORD pid = GetProcessId(ProcessHandle);


    if (pid == Getnotepadpid()) {
        return 0xC0000022;
    }


    return NTTerminateProcess(ProcessHandle, ExitStatus);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
     

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        NTTerminateProcess = (RealNTTerminateProces)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTerminateProcess");
        NTOpenProcess= (RealNtOpenProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");
        NTNtDuplicateObject = (RealNtDuplicateObject)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach((PVOID*)&NTTerminateProcess, (PVOID)HookedTerminatedProcess);
        DetourAttach((PVOID*)&NTOpenProcess, (PVOID)HookedOpenProcess);
        DetourAttach((PVOID*)&NTNtDuplicateObject, (PVOID)HookedNtDuplicateObject);
        DetourTransactionCommit();
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach((PVOID*)&NTTerminateProcess, (PVOID)HookedTerminatedProcess);
        DetourDetach((PVOID*)&NTOpenProcess, (PVOID)HookedOpenProcess);
        DetourDetach((PVOID*)&NTNtDuplicateObject, (PVOID)HookedNtDuplicateObject);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}

