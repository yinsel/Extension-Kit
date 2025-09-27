#ifndef _BEACON_USER_DATA_H
#define _BEACON_USER_DATA_H

#include <windows.h>

#define DLL_BEACON_USER_DATA         0x0d
#define BEACON_USER_DATA_CUSTOM_SIZE 32

typedef struct
{
    PVOID fnAddr;
    PVOID jmpAddr;
    DWORD sysnum;
} SYSCALL_API_ENTRY;

typedef struct
{
    SYSCALL_API_ENTRY ntAllocateVirtualMemory;
    SYSCALL_API_ENTRY ntProtectVirtualMemory;
    SYSCALL_API_ENTRY ntFreeVirtualMemory;
    SYSCALL_API_ENTRY ntGetContextThread;
    SYSCALL_API_ENTRY ntSetContextThread;
    SYSCALL_API_ENTRY ntResumeThread;
    SYSCALL_API_ENTRY ntCreateThreadEx;
    SYSCALL_API_ENTRY ntOpenProcess;
    SYSCALL_API_ENTRY ntOpenThread;
    SYSCALL_API_ENTRY ntClose;
    SYSCALL_API_ENTRY ntCreateSection;
    SYSCALL_API_ENTRY ntMapViewOfSection;
    SYSCALL_API_ENTRY ntUnmapViewOfSection;
    SYSCALL_API_ENTRY ntQueryVirtualMemory;
    SYSCALL_API_ENTRY ntDuplicateObject;
    SYSCALL_API_ENTRY ntReadVirtualMemory;
    SYSCALL_API_ENTRY ntWriteVirtualMemory;
} SYSCALL_API;

typedef struct
{
    unsigned int version;
    SYSCALL_API* syscalls;
    char         custom[BEACON_USER_DATA_CUSTOM_SIZE];
} USER_DATA, *PUSER_DATA;

#endif
