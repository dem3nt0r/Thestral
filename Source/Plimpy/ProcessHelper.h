#pragma once

#include "WindowsPlatform.h"
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdint>

namespace Plimpy
{
    enum class ProcessArchitecture
    {
        Unknown,
        X86,
        X64
    };

    ProcessArchitecture GetProcessArchitecture(HANDLE process);
    ProcessArchitecture GetScannerArchitecture();
    bool CanInspectArchitecture(ProcessArchitecture architecture);
    bool Is64BitWindows();
    std::wstring ResolveSystemPath(const std::wstring& path, ProcessArchitecture architecture);
    void EnableDebugPrivilege();
    std::wstring GetProcessPath(HANDLE process);
    std::wstring GetMappedImagePath(HANDLE process, LPCVOID address);
    std::vector<MODULEENTRY32W> EnumerateModules(DWORD pid, ProcessArchitecture architecture);
    int ClassifyAddress(const std::vector<MODULEENTRY32W>& moduleList, uintptr_t address);
} // namespace Plimpy
