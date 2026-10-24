#include "ConsoleHelper.h"
#include "UnsignedScanner.h"
#include "ProcessHelper.h"
#include "PeImage.h"
#include "SignatureVerifier.h"
#include "FileMetadata.h"
#include "Handle.h"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <limits>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace Plimpy
{
    namespace
    {
        using DriveMapping = std::pair<std::wstring, std::wstring>;

        std::vector<DriveMapping> BuildDriveMappings()
        {
            std::vector<DriveMapping> mappings;
            wchar_t drives[512]{};

            if (!GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives)), drives))
                return mappings;

            for (const wchar_t* driveEntry = drives; *driveEntry;
                 driveEntry += wcslen(driveEntry) + 1)
            {
                wchar_t drivePrefix[] = {driveEntry[0], L':', L'\0'};
                wchar_t devicePrefix[32768]{};

                if (QueryDosDeviceW(drivePrefix, devicePrefix,
                                    static_cast<DWORD>(std::size(devicePrefix))))
                {
                    mappings.emplace_back(devicePrefix, drivePrefix);
                }
            }

            // Match the longest device prefix first.
            std::sort(mappings.begin(), mappings.end(),
                      [](const DriveMapping& lhs, const DriveMapping& rhs)
                      { return lhs.first.size() > rhs.first.size(); });

            return mappings;
        }

        std::wstring DeviceToDosPath(const wchar_t* devicePath,
                                     const std::vector<DriveMapping>& mappings)
        {
            if (!devicePath || !*devicePath)
                return {};

            for (const DriveMapping& mapping : mappings)
            {
                const std::wstring& devicePrefix = mapping.first;
                const std::wstring& drivePrefix = mapping.second;
                const size_t prefixLength = devicePrefix.size();

                if (_wcsnicmp(devicePath, devicePrefix.c_str(), prefixLength) == 0 &&
                    (devicePath[prefixLength] == L'\\' || devicePath[prefixLength] == L'\0'))
                {
                    return drivePrefix + (devicePath + prefixLength);
                }
            }

            // Keep the original device path if no DOS mapping is found.
            return devicePath;
        }

        void ReportUnsignedImage(ConsoleTable& table, DWORD pid, const std::wstring& processName,
                                 const std::wstring& path, std::set<std::wstring>& seenPaths,
                                 std::mutex& seenPathsMutex)
        {
            if (path.empty())
                return;
            {
                std::lock_guard<std::mutex> lock(seenPathsMutex);
                if (!seenPaths.insert(path).second)
                    return;
            }

            if (IsFileTrusted(path))
                return;

            WIN32_FILE_ATTRIBUTE_DATA attributes{};
            std::wstring creationTimeText;

            if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes))
            {
                creationTimeText = FormatFileTime(attributes.ftCreationTime);
            }

            const std::vector<BYTE> bytes = ReadFileBytes(path);

            PeInfo pe{};
            std::wstring peTimestampText;

            if (ReadPeInfo(bytes, pe))
            {
                ULARGE_INTEGER timestamp{};
                timestamp.QuadPart =
                    (static_cast<ULONGLONG>(pe.timeDateStamp) + 11644473600ULL) * 10000000ULL;

                FILETIME fileTime{timestamp.LowPart, timestamp.HighPart};

                peTimestampText = FormatFileTime(fileTime);
            }

            const std::wstring ownerName = GetFileOwner(path);
            const std::wstring md5 = HashFile(path, CALG_MD5);
            const std::wstring sha1 = HashFile(path, CALG_SHA1);
            const std::wstring sha256 = HashFile(path, CALG_SHA_256);

            table.PrintRow({std::to_wstring(pid), processName, creationTimeText, ownerName,
                            peTimestampText, md5, sha1, sha256, path});
        }
    } // namespace

    void ScanUnsignedImages(unsigned workerCount)
    {
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

        if (!snapshot.IsValid())
        {
            ConsoleHelper::Print(L"Failed to create a process snapshot. "
                                 L"Error code: %lu\n",
                                 GetLastError());
            return;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);

        if (!Process32FirstW(snapshot, &processEntry))
        {
            ConsoleHelper::Print(L"Failed to enumerate processes. "
                                 L"Error code: %lu\n",
                                 GetLastError());
            return;
        }

        ConsoleTable table(L"Signature scan", {{L"PID", 10},
                                               {L"Process", 24},
                                               {L"Created", 16},
                                               {L"Owner", 24},
                                               {L"PE timestamp", 16},
                                               {L"MD5", 32},
                                               {L"SHA-1", 40},
                                               {L"SHA-256", 64},
                                               {L"Path", 38}});
        std::set<std::wstring> seenPaths;
        std::mutex seenPathsMutex;
        const std::vector<DriveMapping> driveMappings = BuildDriveMappings();
        const DWORD currentPid = GetCurrentProcessId();

        std::vector<PROCESSENTRY32W> processes;
        do
        {
            processes.push_back(processEntry);
        } while (Process32NextW(snapshot, &processEntry));
        const std::function<void(size_t)> inspectProcess = [&](size_t processIndex)
        {
            const PROCESSENTRY32W& processEntry = processes[processIndex];
            const DWORD pid = processEntry.th32ProcessID;

            if (pid == currentPid)
                return;

            Handle processHandle(
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));

            if (!processHandle.IsValid())
                return;

            const ProcessArchitecture architecture = GetProcessArchitecture(processHandle);
            if (!CanInspectArchitecture(architecture))
            {
                ConsoleHelper::Error(L"[!] Skipping PID %lu: unsupported target architecture.\n",
                                     pid);
                return;
            }
            const std::wstring processPath =
                ResolveSystemPath(GetProcessPath(processHandle), ProcessArchitecture::X64);

            ReportUnsignedImage(table, pid, processEntry.szExeFile, processPath, seenPaths,
                                seenPathsMutex);

            uintptr_t address = 0;
            MEMORY_BASIC_INFORMATION region{};

            while (VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(address), &region,
                                  sizeof(region)) == sizeof(region))
            {
                if (region.Type == MEM_IMAGE)
                {
                    wchar_t devicePath[32768]{};

                    if (GetMappedFileNameW(processHandle, region.BaseAddress, devicePath,
                                           static_cast<DWORD>(std::size(devicePath))))
                    {
                        const std::wstring path = ResolveSystemPath(
                            DeviceToDosPath(devicePath, driveMappings), ProcessArchitecture::X64);

                        ReportUnsignedImage(table, pid, processEntry.szExeFile, path, seenPaths,
                                            seenPathsMutex);
                    }
                }

                const uintptr_t regionBase = reinterpret_cast<uintptr_t>(region.BaseAddress);

                if (!region.RegionSize ||
                    regionBase > std::numeric_limits<uintptr_t>::max() - region.RegionSize)
                {
                    break;
                }

                const uintptr_t nextAddress = regionBase + region.RegionSize;

                if (nextAddress <= address)
                    break;

                address = nextAddress;
            }
        };
        RunParallel(processes.size(), workerCount, inspectProcess);
    }
} // namespace Plimpy
