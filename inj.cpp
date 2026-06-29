#include "inj.h"
#include <cstdio>
#include <iostream>

// SyscallStub
SyscallStub::SyscallStub(DWORD ssn) : m_ptr(nullptr) {
    m_ptr = VirtualAlloc(nullptr, kStubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!m_ptr) return;

    auto* code = static_cast<BYTE*>(m_ptr);
    // mov r10, rcx
    code[0] = 0x49; code[1] = 0x89; code[2] = 0xCA;
    // mov eax, <ssn>
    code[3] = 0xB8;
    *reinterpret_cast<DWORD*>(code + 4) = ssn;
    // syscall ; ret
    code[8] = 0x0F; code[9] = 0x05;
    code[10] = 0xC3;
}

// Hell's Gate
static DWORD HellsGate(const char* functionName) {
    HMODULE hNtdll = GetModuleHandleA(skCrypt("ntdll.dll"));
    if (!hNtdll) return 0xFFFFFFFF;

    auto* pb = reinterpret_cast<PBYTE>(GetProcAddress(hNtdll, functionName));
    if (!pb) return 0xFFFFFFFF;

    
    for (int i = 0; i < 48; i++) {
        if (pb[i] == 0x4C && pb[i + 1] == 0x8B && pb[i + 2] == 0xD1) {
            for (int j = i + 3; j < i + 12 && j < 64; j++) {
                if (pb[j] == 0xB8)
                    return *reinterpret_cast<DWORD*>(pb + j + 1);
            }
        }
    }

   
    for (int i = 0; i < 80; i++) {
        if (pb[i] == 0xB8) {
            for (int k = i + 5; k < i + 20 && k < 96; k++) {
                if (pb[k] == 0x0F && pb[k + 1] == 0x05)
                    return *reinterpret_cast<DWORD*>(pb + i + 1);
            }
        }
    }

    // fallback
    for (int i = 0; i < 64; i++)
        if (pb[i] == 0xB8)
            return *reinterpret_cast<DWORD*>(pb + i + 1);

    return 0xFFFFFFFF;
}


// Поиск PID 
static DWORD FindProcessId(const std::string& processName) {
    SyscallStub ntQuery(HellsGate(skCrypt("NtQuerySystemInformation")));
    if (!ntQuery.Valid()) return 0;

    ULONG    needed = 0;
    NTSTATUS status = ntQuery.As<fNtQuerySystemInformation>()(
        SystemProcessInformation, nullptr, 0, &needed);
    if (needed == 0) return 0;

    std::vector<BYTE> buf(static_cast<size_t>(needed) * 2);
    status = ntQuery.As<fNtQuerySystemInformation>()(
        SystemProcessInformation, buf.data(), static_cast<ULONG>(buf.size()), &needed);

    if (!NT_SUCCESS(status)) return 0;

    std::wstring target(processName.begin(), processName.end());
    auto* spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buf.data());

    for (;;) {
        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
            std::wstring current(spi->ImageName.Buffer, spi->ImageName.Length / sizeof(WCHAR));
            if (_wcsicmp(current.c_str(), target.c_str()) == 0)
                return static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->UniqueProcessId));
        }
        if (spi->NextEntryOffset == 0) break;
        spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<LPBYTE>(spi) + spi->NextEntryOffset);
    }
    return 0;
}


// Загрузка модуля
static PVOID LoadPayloadFromDisk(SIZE_T& outSize) {
    HANDLE hFile = CreateFileW(
        kPayloadPath,
        GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
        return nullptr;

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        return nullptr;
    }

    SIZE_T allocSize = static_cast<SIZE_T>(fileSize.QuadPart) + 65536;
    PVOID  buffer = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hFile);
        return nullptr;
    }

    DWORD  read = 0;
    BOOL   ok = ReadFile(hFile, buffer, static_cast<DWORD>(fileSize.QuadPart), &read, nullptr);
    CloseHandle(hFile);

    if (!ok || read != static_cast<DWORD>(fileSize.QuadPart)) {
        SecureZeroMemory(buffer, allocSize);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return nullptr;
    }

    outSize = static_cast<SIZE_T>(fileSize.QuadPart);
    return buffer;
}


static bool SetDebugPrivilege(bool enable) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid{};
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)
        && GetLastError() != ERROR_NOT_ALL_ASSIGNED;

    CloseHandle(hToken);
    return ok;
}


// Shellcode загрузчик

#pragma optimize("", off)
static DWORD __stdcall LibraryLoader(LPVOID memory) {
    auto* params = static_cast<LoaderData*>(memory);
    LPBYTE            base = static_cast<LPBYTE>(params->ImageBase);
    PIMAGE_NT_HEADERS ntHd = params->NtHeaders;
    LPBYTE            imageEnd = base + params->SizeOfImage;

    // Релокации
    if (params->BaseReloc) {
        auto* reloc = params->BaseReloc;
        UINT64 delta = reinterpret_cast<UINT64>(base) - ntHd->OptionalHeader.ImageBase;

        while (reloc->VirtualAddress) {
            if (reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

            int   count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD entry = reinterpret_cast<PWORD>(reloc + 1);

            for (int i = 0; i < count; i++) {
                if (!entry[i]) continue;
                WORD   type = entry[i] >> 12;
                DWORD  offset = entry[i] & 0xFFF;
                LPBYTE addr = base + reloc->VirtualAddress + offset;

                if (addr < base || addr >= imageEnd) continue;

                if (type == IMAGE_REL_BASED_DIR64)
                    *reinterpret_cast<UINT64*>(addr) += delta;
                else if (type == IMAGE_REL_BASED_HIGHLOW)
                    *reinterpret_cast<DWORD*>(addr) += static_cast<DWORD>(delta);
            }

            if (reloc->SizeOfBlock == 0) break;
            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<LPBYTE>(reloc) + reloc->SizeOfBlock);
        }
    }

    // Импорты
    if (params->ImportDirectory) {
        auto* iid = params->ImportDirectory;

        while (iid->Characteristics) {
            auto* origThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + iid->OriginalFirstThunk);
            auto* firstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + iid->FirstThunk);

            if (reinterpret_cast<LPBYTE>(origThunk) < base ||
                reinterpret_cast<LPBYTE>(firstThunk) >= imageEnd ||
                iid->Name == 0 || base + iid->Name >= imageEnd)
                break;

            HMODULE hMod = params->fnLoadLibraryA(reinterpret_cast<LPCSTR>(base + iid->Name));
            if (!hMod) return FALSE;

            while (origThunk->u1.AddressOfData) {
                FARPROC fn;
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    fn = params->fnGetProcAddress(hMod,
                        reinterpret_cast<LPCSTR>(origThunk->u1.Ordinal & 0xFFFF));
                else {
                    auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        base + origThunk->u1.AddressOfData);
                    fn = params->fnGetProcAddress(hMod, reinterpret_cast<LPCSTR>(ibn->Name));
                }
                if (!fn) return FALSE;
                firstThunk->u1.Function = reinterpret_cast<UINT64>(fn);
                ++origThunk; ++firstThunk;
            }
            ++iid;
        }
    }

    // SEH-таблица 
    auto& exDir = ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exDir.Size > 0 && params->fnRtlAddFunctionTable) {
        params->fnRtlAddFunctionTable(
            reinterpret_cast<PRUNTIME_FUNCTION>(base + exDir.VirtualAddress),
            exDir.Size / sizeof(RUNTIME_FUNCTION),
            reinterpret_cast<DWORD64>(base));
    }

    // TLS-колбэки
    auto& tlsDir = ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size > 0) {
        auto* tlsDirectory = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(base + tlsDir.VirtualAddress);
        auto* callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsDirectory->AddressOfCallBacks);
        if (callbacks)
            while (*callbacks) { (*callbacks)(base, DLL_PROCESS_ATTACH, nullptr); ++callbacks; }
    }

    // DllMain
    if (ntHd->OptionalHeader.AddressOfEntryPoint) {
        auto entry = reinterpret_cast<dllmain_t>(base + ntHd->OptionalHeader.AddressOfEntryPoint);
        return entry(reinterpret_cast<HMODULE>(base), DLL_PROCESS_ATTACH, nullptr);
    }
    return TRUE;
}
#pragma optimize("", on)


// Затирание PE заголовков/артефактов
static void ErasePeArtifacts(
    SyscallStub& ntWrite,
    HANDLE            hProcess,
    LPBYTE            imageBase,
    PIMAGE_NT_HEADERS ntHeaders,
    DWORD             e_lfanew)
{
    SIZE_T written = 0;
    BYTE   trash[0x1000];
    memset(trash, 0xCC, sizeof(trash));

    ntWrite.As<NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)>()(
        hProcess, imageBase, trash, sizeof(trash), &written);

    PVOID ntHeaderAddr = imageBase + e_lfanew;
    ntWrite.As<NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)>()(
        hProcess, ntHeaderAddr, trash, 0x400, &written);

    auto* sect = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        reinterpret_cast<LPBYTE>(&ntHeaders->OptionalHeader)
        + ntHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        BYTE  zero[8] = {};
        PVOID nameAddr = imageBase + sect[i].VirtualAddress - 8;
        ntWrite.As<NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)>()(
            hProcess, nameAddr, zero, sizeof(zero), &written);
    }

    PVOID rdataStart = imageBase
        + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (rdataStart)
        ntWrite.As<NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)>()(
            hProcess, rdataStart, trash, 0x200, &written);
}

// Установка прав секций
static void ApplySectionProtections(
    SyscallStub& ntProtect,
    HANDLE            hProcess,
    LPBYTE            imageBase,
    PIMAGE_NT_HEADERS ntHeaders)
{
    auto* sect = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        reinterpret_cast<LPBYTE>(&ntHeaders->OptionalHeader)
        + ntHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sect[i].VirtualAddress == 0) continue;

        DWORD ch = sect[i].Characteristics;
        ULONG prot = PAGE_READONLY;

        if (ch & IMAGE_SCN_MEM_EXECUTE)
            prot = (ch & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else
            prot = (ch & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;

        PVOID  base = imageBase + sect[i].VirtualAddress;
        SIZE_T sz = sect[i].Misc.VirtualSize;
        ULONG  old = 0;
        ntProtect.As<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)>()(
            hProcess, &base, &sz, prot, &old);
    }
}


int main() {
    SetConsoleTitleA("Nebulafox Injector by Jwachka1337");
    std::cout << "Starting injector..." << std::endl;

    if (!SetDebugPrivilege(true)) {
        std::cout << "!Failed to set Debug Privilege" << std::endl;
        return 1;
    }
    std::cout << "Debug Privilege enabled" << std::endl;

    // Загрузка модуля с диска
   
    SIZE_T fileSize = 0;
    PVOID  fileBuffer = LoadPayloadFromDisk(fileSize);
    if (!fileBuffer) {
        std::cout << "!Failed to load payload" << std::endl;
        return 1;
    }
    std::cout << "Payload loaded (" << fileSize << " bytes)" << std::endl;

    // Валидация 
    auto* dosHeader = static_cast<PIMAGE_DOS_HEADER>(fileBuffer);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "!Invalid DOS signature" << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return 1;
    }

    auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        static_cast<LPBYTE>(fileBuffer) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "!Invalid NT signature" << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return 1;
    }
    std::cout << "PE validation passed" << std::endl;

    const DWORD e_lfanew = dosHeader->e_lfanew;
    const DWORD sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    const DWORD relocRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    // Ожидание таргет процесса
    constexpr const char* kProcessName = "Game.exe";
    std::cout << "Waiting for process: " << kProcessName << std::endl;
    DWORD processId = 0;
    while (processId == 0) {
        processId = FindProcessId(kProcessName);
        if (processId == 0) Sleep(10);
    }
    std::cout << "Target process found! PID = " << processId << std::endl;
    Sleep(40);

    // Открытие процесса
    std::cout << "Opening target process..." << std::endl;
    SyscallStub ntOpenProcess(HellsGate(skCrypt("NtOpenProcess")));
    if (!ntOpenProcess.Valid()) {
        std::cout << "!Failed to create NtOpenProcess stub" << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return 1;
    }

    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    CLIENT_ID         clientId = { reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(processId)), nullptr };
    HANDLE            hProcess = nullptr;

    NTSTATUS openStatus = ntOpenProcess.As<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)>()(
        &hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);

    if (!NT_SUCCESS(openStatus) || !hProcess) {
        std::cout << "!Failed to open target process" << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return 1;
    }
    std::cout << "Process opened successfully" << std::endl;

    // Инициализация syscall-стабов
    std::cout << "Initializing syscall stubs..." << std::endl;
    SyscallStub ntAllocate(HellsGate(skCrypt("NtAllocateVirtualMemory")));
    SyscallStub ntWrite(HellsGate(skCrypt("NtWriteVirtualMemory")));
    SyscallStub ntCreateThreadEx(HellsGate(skCrypt("NtCreateThreadEx")));
    SyscallStub ntProtect(HellsGate(skCrypt("NtProtectVirtualMemory")));
    SyscallStub ntFree(HellsGate(skCrypt("NtFreeVirtualMemory")));
    SyscallStub ntQuerySys(HellsGate(skCrypt("NtQuerySystemInformation")));

    if (!ntAllocate.Valid() || !ntWrite.Valid() || !ntCreateThreadEx.Valid() ||
        !ntProtect.Valid() || !ntQuerySys.Valid()) {
        std::cout << "!Failed to create syscall stubs" << std::endl;
        CloseHandle(hProcess);
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return 1;
    }

    // Выделение памяти под образ
    std::cout << "Allocating memory in target process..." << std::endl;
    PVOID  executableImage = nullptr;
    SIZE_T regionSize = sizeOfImage;

    NTSTATUS allocStatus = ntAllocate.As<NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>()(
        hProcess, &executableImage, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(allocStatus) || !executableImage) {
        std::cout << "!Memory allocation failed" << std::endl;
        CloseHandle(hProcess);
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return 1;
    }
    std::cout << "Memory allocated at: 0x" << std::hex << (uintptr_t)executableImage << std::dec << std::endl;

    // Запись секций 
    std::cout << "Writing PE sections..." << std::endl;
    SIZE_T written = 0;
    ntWrite.As<NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)>()(
        hProcess, executableImage, fileBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, &written);

    auto* sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        reinterpret_cast<LPBYTE>(&ntHeaders->OptionalHeader)
        + ntHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;
        ntWrite.As<NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)>()(
            hProcess,
            static_cast<LPBYTE>(executableImage) + sections[i].VirtualAddress,
            static_cast<LPBYTE>(fileBuffer) + sections[i].PointerToRawData,
            sections[i].SizeOfRawData,
            &written);
    }

   
    IMAGE_NT_HEADERS ntHeadersCopy = *ntHeaders;
    const DWORD      numSections = ntHeaders->FileHeader.NumberOfSections;

    std::vector<IMAGE_SECTION_HEADER> sectionsCopy(numSections);
    auto* srcSections = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        reinterpret_cast<LPBYTE>(&ntHeaders->OptionalHeader)
        + ntHeaders->FileHeader.SizeOfOptionalHeader);
    memcpy(sectionsCopy.data(), srcSections, numSections * sizeof(IMAGE_SECTION_HEADER));

    SecureZeroMemory(fileBuffer, fileSize);
    VirtualFree(fileBuffer, 0, MEM_RELEASE);
    ntHeaders = nullptr;

    std::cout << "Preparing loader..." << std::endl;
    HMODULE hNtdll = GetModuleHandleA(skCrypt("ntdll.dll"));

    LoaderData loaderParams = {};
    loaderParams.ImageBase = executableImage;
    loaderParams.NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        static_cast<LPBYTE>(executableImage) + e_lfanew);
    loaderParams.BaseReloc = relocRVA ? reinterpret_cast<PIMAGE_BASE_RELOCATION>(
        static_cast<LPBYTE>(executableImage) + relocRVA) : nullptr;
    loaderParams.ImportDirectory = importRVA ? reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        static_cast<LPBYTE>(executableImage) + importRVA) : nullptr;
    loaderParams.SizeOfImage = sizeOfImage;
    loaderParams.fnLoadLibraryA = LoadLibraryA;
    loaderParams.fnGetProcAddress = GetProcAddress;
    loaderParams.fnRtlAddFunctionTable = reinterpret_cast<pRtlAddFunctionTable>(
        GetProcAddress(hNtdll, skCrypt("RtlAddFunctionTable")));

    constexpr SIZE_T kLoaderCodeSize = 8192;
    constexpr SIZE_T kLoaderRegion = sizeof(LoaderData) + kLoaderCodeSize + 64;

    PVOID  loaderMemory = nullptr;
    SIZE_T loaderRegionSize = kLoaderRegion;

    NTSTATUS loaderAllocStatus = ntAllocate.As<NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>()(
        hProcess, &loaderMemory, 0, &loaderRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(loaderAllocStatus) || !loaderMemory) {
        std::cout << "!Loader memory allocation failed" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Запись лоадера
    ntWrite.As<NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)>()(
        hProcess, loaderMemory, &loaderParams, sizeof(LoaderData), &written);

    PVOID loaderCode = static_cast<LPBYTE>(loaderMemory) + sizeof(LoaderData);
    ntWrite.As<NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)>()(
        hProcess, loaderCode, reinterpret_cast<PVOID>(LibraryLoader), kLoaderCodeSize, &written);

    std::cout << "Setting loader to PAGE_EXECUTE_READWRITE" << std::endl;
    {
        PVOID  protectBase = loaderMemory;
        SIZE_T protectSize = loaderRegionSize;
        ULONG  old = 0;
        ntProtect.As<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)>()(
            hProcess, &protectBase, &protectSize, PAGE_EXECUTE_READWRITE, &old);
    }

    // Временно RWX для образа для релокаций
    std::cout << "Temporarily enabling RWX for image..." << std::endl;
    {
        PVOID  tempBase = executableImage;
        SIZE_T tempSize = sizeOfImage;
        ULONG  old = 0;
        ntProtect.As<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)>()(
            hProcess, &tempBase, &tempSize, PAGE_EXECUTE_READWRITE, &old);
    }

    std::cout << "Creating remote thread..." << std::endl;
    HANDLE   hThread = nullptr;
    auto     NtCTEx = ntCreateThreadEx.As<fNtCreateThreadEx>();
    NTSTATUS threadStatus = NtCTEx(
        &hThread, THREAD_ALL_ACCESS, nullptr, hProcess,
        loaderCode, loaderMemory,
        0, 0, 0, 0, nullptr);

    if (NT_SUCCESS(threadStatus) && hThread) {
        std::cout << "Injection successful! Waiting for loader..." << std::endl;
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        ErasePeArtifacts(ntWrite, hProcess,
            static_cast<LPBYTE>(executableImage), &ntHeadersCopy, e_lfanew);
        ApplySectionProtections(ntProtect, hProcess,
            static_cast<LPBYTE>(executableImage), &ntHeadersCopy);

        if (ntFree.Valid()) {
            PVOID  freeBase = loaderMemory;
            SIZE_T freeSize = 0;
            ntFree.As<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG)>()(
                hProcess, &freeBase, &freeSize, MEM_RELEASE);
        }

        std::cout << "Cleanup completed" << std::endl;
        Sleep(4500 + (rand() % 6500));
    }
    else {
        std::cout << "!Failed to create remote thread" << std::endl;
    }

    CloseHandle(hProcess);
    std::cout << "Success!" << std::endl;
    return NT_SUCCESS(threadStatus) ? 0 : 1;
}