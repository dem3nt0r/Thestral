#include "ProcessHelper.h"
#include "Handle.h"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>

#include <cstdint>
#include <string>
#include <vector>
#include <iterator>
#include <cwchar>

namespace Plimpy
{
    ProcessArchitecture GetScannerArchitecture()
    {
#ifdef _WIN64
        return ProcessArchitecture::X64;
#else
        return ProcessArchitecture::X86;
#endif
    }

    bool Is64BitWindows()
    {
        SYSTEM_INFO systemInfo{};
        GetNativeSystemInfo(&systemInfo);
        return systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
               systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
    }

    ProcessArchitecture GetProcessArchitecture(HANDLE process)
    {
        using QueryArchitecture = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
        QueryArchitecture queryArchitecture = reinterpret_cast<QueryArchitecture>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
        if (queryArchitecture)
        {
            USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (!queryArchitecture(process, &processMachine, &nativeMachine))
                return ProcessArchitecture::Unknown;
            const USHORT machine =
                processMachine == IMAGE_FILE_MACHINE_UNKNOWN ? nativeMachine : processMachine;
            if (machine == IMAGE_FILE_MACHINE_I386)
                return ProcessArchitecture::X86;
            if (machine == IMAGE_FILE_MACHINE_AMD64)
                return ProcessArchitecture::X64;
            return ProcessArchitecture::Unknown;
        }

        BOOL isWow64 = FALSE;
        if (!IsWow64Process(process, &isWow64))
            return ProcessArchitecture::Unknown;
        SYSTEM_INFO systemInfo{};
        GetNativeSystemInfo(&systemInfo);
        if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
            return ProcessArchitecture::X86;
        if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
            return isWow64 ? ProcessArchitecture::X86 : ProcessArchitecture::X64;
        return ProcessArchitecture::Unknown;
    }

    bool CanInspectArchitecture(ProcessArchitecture architecture)
    {
        return architecture == ProcessArchitecture::X86 ||
               (architecture == ProcessArchitecture::X64 &&
                GetScannerArchitecture() == ProcessArchitecture::X64);
    }

    std::wstring ResolveSystemPath(const std::wstring& path, ProcessArchitecture architecture)
    {
        if (!Is64BitWindows())
            return path;
        wchar_t windowsDirectory[32768]{};
        const UINT length =
            GetWindowsDirectoryW(windowsDirectory, static_cast<UINT>(std::size(windowsDirectory)));
        if (!length || length >= std::size(windowsDirectory))
            return path;
        std::wstring comparablePath = path;
        const std::wstring extendedPrefix = L"\\\\?\\";
        const bool isExtended =
            comparablePath.compare(0, extendedPrefix.size(), extendedPrefix) == 0;
        if (isExtended)
            comparablePath.erase(0, extendedPrefix.size());
        const std::wstring systemPrefix = std::wstring(windowsDirectory) + L"\\System32";
        if (comparablePath.size() < systemPrefix.size() ||
            _wcsnicmp(comparablePath.c_str(), systemPrefix.c_str(), systemPrefix.size()) != 0 ||
            (comparablePath.size() > systemPrefix.size() &&
             comparablePath[systemPrefix.size()] != L'\\'))
            return path;
        const std::wstring suffix = comparablePath.substr(systemPrefix.size());
        if (architecture == ProcessArchitecture::X86)
        {
            // These System32 subdirectories are not redirected by WOW64.
            const wchar_t* exceptions[] = {L"\\catroot",      L"\\catroot2", L"\\driverstore",
                                           L"\\drivers\\etc", L"\\logfiles", L"\\spool"};
            for (const wchar_t* exception : exceptions)
            {
                const size_t exceptionLength = wcslen(exception);
                if (_wcsnicmp(suffix.c_str(), exception, exceptionLength) == 0 &&
                    (suffix.size() == exceptionLength ||
                     (suffix.size() > exceptionLength && suffix[exceptionLength] == L'\\')))
                    return path;
            }
            wchar_t wow64Directory[32768]{};
            const UINT wow64Length = GetSystemWow64DirectoryW(
                wow64Directory, static_cast<UINT>(std::size(wow64Directory)));
            if (wow64Length && wow64Length < std::size(wow64Directory) && wow64Directory[0])
                return (isExtended ? extendedPrefix : L"") + std::wstring(wow64Directory) + suffix;
            return (isExtended ? extendedPrefix : L"") + std::wstring(windowsDirectory) +
                   L"\\SysWOW64" + suffix;
        }
        else if (architecture == ProcessArchitecture::X64 &&
                 GetScannerArchitecture() == ProcessArchitecture::X86)
        {
            // Sysnative addresses the native directory from an x86 scanner without
            // disabling redirection while WinTrust or another dependency loads DLLs.
            return (isExtended ? extendedPrefix : L"") + std::wstring(windowsDirectory) +
                   L"\\Sysnative" + suffix;
        }
        return path;
    }

    void EnableDebugPrivilege()
    {
        HANDLE rawToken = nullptr;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                              &rawToken))
        {
            return;
        }

        Handle token(rawToken);

        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;

        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid))
        {
            return;
        }

        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr))
        {
            return;
        }

        // AdjustTokenPrivileges can succeed even if the privilege
        // was not assigned to the token.
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
            return;
    }

    std::wstring GetProcessPath(HANDLE process)
    {
        wchar_t buffer[32768]{};

        DWORD length = static_cast<DWORD>(std::size(buffer));
        if (!QueryFullProcessImageNameW(process, 0, buffer, &length))
            return {};

        if (length == 0 || length >= std::size(buffer))
        {
            return {};
        }

        return std::wstring(buffer, length);
    }

    std::wstring GetMappedImagePath(HANDLE process, LPCVOID address)
    {
        wchar_t mappedPath[32768]{};
        const DWORD mappedLength =
            GetMappedFileNameW(process, const_cast<LPVOID>(address), mappedPath,
                               static_cast<DWORD>(std::size(mappedPath)));
        if (!mappedLength || mappedLength >= std::size(mappedPath))
            return {};
        wchar_t drives[512]{};
        const DWORD driveLength =
            GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives)), drives);
        if (!driveLength || driveLength >= std::size(drives))
            return {};
        for (const wchar_t* driveEntry = drives; *driveEntry; driveEntry += wcslen(driveEntry) + 1)
        {
            wchar_t drivePrefix[] = {driveEntry[0], L':', L'\0'};
            wchar_t devicePrefix[32768]{};
            if (!QueryDosDeviceW(drivePrefix, devicePrefix,
                                 static_cast<DWORD>(std::size(devicePrefix))))
                continue;
            const size_t prefixLength = wcslen(devicePrefix);
            if (_wcsnicmp(mappedPath, devicePrefix, prefixLength) == 0 &&
                (mappedPath[prefixLength] == L'\\' || mappedPath[prefixLength] == L'\0'))
            {
                // Mapped names identify physical files, even when module-list paths
                // retain a logical System32 path in a WOW64 process.
                return ResolveSystemPath(std::wstring(drivePrefix) + (mappedPath + prefixLength),
                                         ProcessArchitecture::X64);
            }
        }
        return {};
    }

    std::vector<MODULEENTRY32W> EnumerateModules(DWORD pid, ProcessArchitecture architecture)
    {
        std::vector<MODULEENTRY32W> result;

        if (!CanInspectArchitecture(architecture))
            return result;
        DWORD snapshotFlags = TH32CS_SNAPMODULE;
#ifdef _WIN64
        if (architecture == ProcessArchitecture::X86)
            snapshotFlags |= TH32CS_SNAPMODULE32;
#endif
        HANDLE rawSnapshot = INVALID_HANDLE_VALUE;
        for (unsigned attempt = 0; attempt < 3; ++attempt)
        {
            rawSnapshot = CreateToolhelp32Snapshot(snapshotFlags, pid);
            if (rawSnapshot != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH)
                break;
        }
        Handle snapshot(rawSnapshot);

        if (!snapshot.IsValid())
            return result;

        MODULEENTRY32W module{};
        module.dwSize = sizeof(module);

        if (!Module32FirstW(snapshot, &module))
            return result;

        do
        {
            result.push_back(module);
            module.dwSize = sizeof(module);
        } while (Module32NextW(snapshot, &module));

        return result;
    }

    int ClassifyAddress(const std::vector<MODULEENTRY32W>& moduleList, uintptr_t address)
    {
        if (address == 0 || moduleList.empty())
            return 1;

        for (const MODULEENTRY32W& module : moduleList)
        {
            const uintptr_t moduleBase = reinterpret_cast<uintptr_t>(module.modBaseAddr);

            const uintptr_t moduleSize = module.modBaseSize;

            // Avoid overflow when calculating the module's end.
            if (address < moduleBase || address - moduleBase >= moduleSize)
                continue;

            const wchar_t* extension = PathFindExtensionW(module.szExePath);

            return _wcsicmp(extension, L".exe") == 0 ? 2 : 1;
        }

        return 0;
    }
} // namespace Plimpy
