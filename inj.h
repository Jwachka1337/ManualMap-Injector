#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include "skCrypt.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define SK_W(str) ((const wchar_t*)skCrypt(str))
#define SK_A(str) ((const char*)skCrypt(str))

// Путь к загружаемому модулю на диске
constexpr const wchar_t* kPayloadPath = L"Cheat.dll";

using pLoadLibraryA = HMODULE(__stdcall*)(LPCSTR);
using pGetProcAddress = FARPROC(__stdcall*)(HMODULE, LPCSTR);
using pRtlAddFunctionTable = BOOLEAN(__stdcall*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
using dllmain_t = INT(__stdcall*)(HMODULE, DWORD, LPVOID);
using fNtCreateThreadEx = NTSTATUS(NTAPI*)(
    OUT PHANDLE     ThreadHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  PVOID       ObjectAttributes,
    IN  HANDLE      ProcessHandle,
    IN  PVOID       StartRoutine,
    IN  PVOID       Argument         OPTIONAL,
    IN  ULONG       CreateFlags,
    IN  SIZE_T      ZeroBits         OPTIONAL,
    IN  SIZE_T      StackSize        OPTIONAL,
    IN  SIZE_T      MaximumStackSize OPTIONAL,
    IN  PVOID       AttributeList);


// NT структуры
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount;
    LARGE_INTEGER  WriteOperationCount;
    LARGE_INTEGER  OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount;
    LARGE_INTEGER  WriteTransferCount;
    LARGE_INTEGER  OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
} SYSTEM_INFORMATION_CLASS;


using pNtQuerySystemInformation = NTSTATUS(NTAPI*)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength);

using fNtQuerySystemInformation = NTSTATUS(NTAPI*)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength);


struct LoaderData {
    LPVOID                    ImageBase;
    PIMAGE_NT_HEADERS         NtHeaders;
    PIMAGE_BASE_RELOCATION    BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR  ImportDirectory;
    SIZE_T                    SizeOfImage;

    pLoadLibraryA             fnLoadLibraryA;
    pGetProcAddress           fnGetProcAddress;
    pRtlAddFunctionTable      fnRtlAddFunctionTable;
};


class SyscallStub {
public:
    SyscallStub(const SyscallStub&) = delete;
    SyscallStub& operator=(const SyscallStub&) = delete;

    SyscallStub() : m_ptr(nullptr) {}
    explicit SyscallStub(DWORD ssn);
    ~SyscallStub() { Free(); }

    SyscallStub(SyscallStub&& other) noexcept : m_ptr(other.m_ptr) { other.m_ptr = nullptr; }
    SyscallStub& operator=(SyscallStub&& other) noexcept {
        if (this != &other) { Free(); m_ptr = other.m_ptr; other.m_ptr = nullptr; }
        return *this;
    }

    bool Valid() const { return m_ptr != nullptr; }

    template<typename Fn>
    Fn As() const { return reinterpret_cast<Fn>(m_ptr); }

private:
    static constexpr SIZE_T kStubSize = 32;
    PVOID m_ptr;
    void Free() { if (m_ptr) { VirtualFree(m_ptr, 0, MEM_RELEASE); m_ptr = nullptr; } }
};

