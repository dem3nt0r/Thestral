#include "ConsoleHelper.h"
#include "DllUnloader.h"
#include "ProcessHelper.h"
#include "Handle.h"
#include <cstdio>
#include <cwchar>

namespace Plimpy
{
    namespace
    {
        using CreateNativeThread = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
                                                ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    }

    bool UnloadDll(DWORD pid, const wchar_t* moduleNameOrPath)
    {
        Handle processHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
        if (!processHandle.IsValid())
        {
            ConsoleHelper::Print(L"[!]OpenProcess error %lu\n", GetLastError());
            return false;
        }
        const ProcessArchitecture architecture = GetProcessArchitecture(processHandle);
        if (architecture == ProcessArchitecture::Unknown ||
            architecture != GetScannerArchitecture())
        {
            ConsoleHelper::Error(L"[!] DLL unloading requires a matching x86 or x64 build.\n");
            return false;
        }
        MODULEENTRY32W selectedModule{};
        bool moduleFound = false;
        for (const MODULEENTRY32W& module : EnumerateModules(pid, architecture))
            if (!_wcsicmp(module.szModule, moduleNameOrPath) ||
                !_wcsicmp(module.szExePath, moduleNameOrPath))
            {
                selectedModule = module;
                moduleFound = true;
                break;
            }
        if (!moduleFound)
        {
            ConsoleHelper::Print(L"[!] Module not found in process\n");
            return false;
        }
        HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
        CreateNativeThread createNativeThread =
            reinterpret_cast<CreateNativeThread>(GetProcAddress(localNtdll, "NtCreateThreadEx"));
        FARPROC localUnloadAddress = GetProcAddress(localNtdll, "LdrUnloadDll");
        if (!createNativeThread || !localUnloadAddress)
        {
            ConsoleHelper::Print(L"[!]NtCreateThreadEx error\n");
            return false;
        }

        uintptr_t targetNtdllBase = 0;
        for (const MODULEENTRY32W& module : EnumerateModules(pid, architecture))
            if (!_wcsicmp(module.szModule, L"ntdll.dll"))
            {
                targetNtdllBase = reinterpret_cast<uintptr_t>(module.modBaseAddr);
                break;
            }
        if (!targetNtdllBase)
            return false;
        uintptr_t remoteUnloadAddress = targetNtdllBase +
                                        reinterpret_cast<uintptr_t>(localUnloadAddress) -
                                        reinterpret_cast<uintptr_t>(localNtdll);
        HANDLE rawThreadHandle = nullptr;
        LONG threadCreationStatus =
            createNativeThread(&rawThreadHandle, THREAD_ALL_ACCESS, nullptr, processHandle,
                               reinterpret_cast<void*>(remoteUnloadAddress),
                               selectedModule.modBaseAddr, 0, 0, 0, 0, nullptr);
        Handle threadHandle(rawThreadHandle);
        if (threadCreationStatus < 0 || !threadHandle.IsValid())
        {
            ConsoleHelper::Print(L"[!]ThreadHandle error\n");
            return false;
        }
        if (WaitForSingleObject(threadHandle, INFINITE) == WAIT_FAILED)
        {
            ConsoleHelper::Print(L"[!]WaitForSingleObject error\n");
            return false;
        }
        DWORD threadExitCode = 0;
        if (GetExitCodeThread(threadHandle, &threadExitCode))
        {
            if (!threadExitCode)
                ConsoleHelper::Print(L"[!]LdrUnloadDll success\n");
            else
                ConsoleHelper::Print(L"[!]LdrUnloadDll return fail %lX\n", threadExitCode);
        }
        return true;
    }
} // namespace Plimpy
