#include "ConsoleHelper.h"
#include "ComScanner.h"
#include "WindowsPlatform.h"
#include "SignatureVerifier.h"
#include "ProcessHelper.h"
#include <shlwapi.h>
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <utility>
#include <cstdio>

namespace Plimpy
{
    namespace
    {
        struct ComRegistration
        {
            std::wstring serverKeyPath;
            REGSAM registryView;
            ProcessArchitecture architecture;
        };

        class RegistryKeyOwner
        {
          public:
            explicit RegistryKeyOwner(HKEY key) : registryKey(key)
            {
            }
            ~RegistryKeyOwner()
            {
                RegCloseKey(registryKey);
            }
            RegistryKeyOwner(const RegistryKeyOwner&) = delete;
            RegistryKeyOwner& operator=(const RegistryKeyOwner&) = delete;

          private:
            HKEY registryKey;
        };

        std::vector<std::wstring> EnumerateSubkeys(HKEY root, const std::wstring& path,
                                                   REGSAM registryView)
        {
            HKEY registryKey = nullptr;
            std::vector<std::wstring> subkeyNames;
            if (RegOpenKeyExW(root, path.empty() ? nullptr : path.c_str(), 0,
                              KEY_READ | registryView, &registryKey) != ERROR_SUCCESS)
                return subkeyNames;
            RegistryKeyOwner keyOwner(registryKey);
            for (DWORD i = 0;; ++i)
            {
                wchar_t subkeyName[512]{};
                DWORD subkeyNameLength = 512;
                LSTATUS registryStatus =
                    RegEnumKeyExW(registryKey, i, subkeyName, &subkeyNameLength, nullptr, nullptr,
                                  nullptr, nullptr);
                if (registryStatus != ERROR_SUCCESS)
                    break;
                subkeyNames.emplace_back(subkeyName, subkeyNameLength);
            }
            return subkeyNames;
        }

        void CollectRegistrations(std::vector<ComRegistration>& registrations, REGSAM registryView,
                                  ProcessArchitecture architecture)
        {
            for (const std::wstring& sid : EnumerateSubkeys(HKEY_USERS, L"", registryView))
            {
                const std::wstring clsidRootPath = sid + L"\\SOFTWARE\\Classes\\CLSID";
                for (const std::wstring& clsid :
                     EnumerateSubkeys(HKEY_USERS, clsidRootPath, registryView))
                    registrations.push_back({clsidRootPath + L"\\" + clsid + L"\\InprocServer32",
                                             registryView, architecture});
            }
        }

        void CheckRegistration(ConsoleTable& table, const ComRegistration& registration,
                               std::set<std::pair<ProcessArchitecture, std::wstring>>& seenPaths,
                               std::mutex& seenPathsMutex)
        {
            const std::wstring& serverKeyPath = registration.serverKeyPath;
            const REGSAM registryView = registration.registryView;
            const ProcessArchitecture architecture = registration.architecture;
            HKEY registryKey = nullptr;
            if (RegOpenKeyExW(HKEY_USERS, serverKeyPath.c_str(), 0, KEY_READ | registryView,
                              &registryKey) != ERROR_SUCCESS)
                return;
            RegistryKeyOwner keyOwner(registryKey);
            DWORD valueType = 0, valueSizeBytes = 0;
            LSTATUS registryStatus = RegQueryValueExW(registryKey, nullptr, nullptr, &valueType,
                                                      nullptr, &valueSizeBytes);
            if (registryStatus == ERROR_SUCCESS &&
                (valueType == REG_SZ || valueType == REG_EXPAND_SZ) && valueSizeBytes < 1024 * 1024)
            {
                std::vector<wchar_t> valueBuffer(valueSizeBytes / 2 + 2, 0);
                if (RegQueryValueExW(registryKey, nullptr, nullptr, &valueType,
                                     reinterpret_cast<BYTE*>(valueBuffer.data()),
                                     &valueSizeBytes) == ERROR_SUCCESS)
                {
                    wchar_t expandedPath[32768]{};
                    DWORD expandedPathLength =
                        ExpandEnvironmentStringsW(valueBuffer.data(), expandedPath, 32768);
                    std::wstring path = (expandedPathLength && expandedPathLength <= 32768)
                                            ? expandedPath
                                            : valueBuffer.data();
                    if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"')
                        path = path.substr(1, path.size() - 2);
                    path = ResolveSystemPath(path, architecture);
                    if (PathIsRelativeW(path.c_str()))
                    {
                        wchar_t resolvedPath[32768]{};
                        wchar_t systemDirectory[32768]{};
                        const UINT systemLength = GetSystemDirectoryW(systemDirectory, 32768);
                        const std::wstring searchDirectory =
                            systemLength && systemLength < 32768
                                ? ResolveSystemPath(systemDirectory, architecture)
                                : L"";
                        DWORD resolvedPathLength =
                            SearchPathW(searchDirectory.empty() ? nullptr : searchDirectory.c_str(),
                                        path.c_str(), L".dll", 32768, resolvedPath, nullptr);
                        if (!resolvedPathLength)
                            resolvedPathLength = SearchPathW(nullptr, path.c_str(), L".dll", 32768,
                                                             resolvedPath, nullptr);
                        if (resolvedPathLength && resolvedPathLength < 32768)
                            path = ResolveSystemPath(resolvedPath, architecture);
                    }
                    bool firstPath = false;
                    {
                        std::lock_guard<std::mutex> lock(seenPathsMutex);
                        firstPath = seenPaths.insert({architecture, path}).second;
                    }
                    if (firstPath && !IsFileTrusted(path))
                        table.PrintRow({architecture == ProcessArchitecture::X86 ? L"x86" : L"x64",
                                        L"HKEY_USERS\\" + serverKeyPath, path});
                }
            }
        }

    } // namespace

    void ScanComRegistrations(unsigned workerCount)
    {
        ConsoleTable table(L"COM scan",
                           {{L"View", 5}, {L"Registry key", 52}, {L"Server path", 48}});
        std::vector<ComRegistration> registrations;
        CollectRegistrations(registrations, Is64BitWindows() ? KEY_WOW64_32KEY : 0,
                             ProcessArchitecture::X86);
        if (Is64BitWindows())
            CollectRegistrations(registrations, KEY_WOW64_64KEY, ProcessArchitecture::X64);
        std::set<std::pair<ProcessArchitecture, std::wstring>> seenPaths;
        std::mutex seenPathsMutex;
        const std::function<void(size_t)> inspectRegistration = [&](size_t registrationIndex)
        { CheckRegistration(table, registrations[registrationIndex], seenPaths, seenPathsMutex); };
        RunParallel(registrations.size(), workerCount, inspectRegistration);
    }
} // namespace Plimpy
