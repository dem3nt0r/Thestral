#include "ConsoleHelper.h"
#include "InjectionScanner.h"
#include "ProcessHelper.h"
#include "PeImage.h"
#include "Handle.h"
#include "ThreadStack.h"
#include <dbghelp.h>
#include <shlwapi.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <map>
#include <utility>

namespace Plimpy
{
    namespace
    {
        using QueryThread = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

        bool IsStackProtection(DWORD protection)
        {
            return protection == PAGE_READONLY || protection == PAGE_READWRITE ||
                   protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
                   protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
        }

        bool IsSuspiciousProtection(DWORD protection)
        {
            return protection == 0 || protection == PAGE_NOACCESS || protection == PAGE_READONLY ||
                   protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
                   protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
        }

        void PrintFinding(ConsoleTable& table, DWORD pid, DWORD tid, const std::wstring& path,
                          uintptr_t address, const wchar_t* kind)
        {
            wchar_t addressText[32]{};
            if (address)
                swprintf(addressText, 32, L"0x%llX", static_cast<unsigned long long>(address));
            table.PrintRow(
                {std::to_wstring(pid), tid ? std::to_wstring(tid) : L"-", addressText, kind, path});
        }

        bool IsSuspiciousAddress(HANDLE process, const std::vector<MODULEENTRY32W>& moduleList,
                                 uintptr_t address)
        {
            MEMORY_BASIC_INFORMATION memory{};
            return address && ClassifyAddress(moduleList, address) == 0 &&
                   VirtualQueryEx(process, reinterpret_cast<void*>(address), &memory,
                                  sizeof memory) == sizeof memory &&
                   IsStackProtection(memory.Protect);
        }

        void CheckStack(ConsoleTable& table, HANDLE process, DWORD pid, DWORD tid,
                        const std::wstring& path, const std::vector<MODULEENTRY32W>& moduleList,
                        ProcessArchitecture architecture)
        {
            std::vector<uintptr_t> addresses;
            if (!CaptureThreadStack(process, pid, tid, architecture, addresses))
                return;
            for (const uintptr_t address : addresses)
            {
                if (IsSuspiciousAddress(process, moduleList, address))
                {
                    PrintFinding(table, pid, tid, path, address, L"Suspicious memory");
                    break;
                }
            }
        }

        void CheckEntryPoints(ConsoleTable& table, HANDLE process, DWORD pid,
                              const std::vector<MODULEENTRY32W>& moduleList)
        {

            for (const MODULEENTRY32W& module : moduleList)
            {
                const std::wstring modulePath = GetMappedImagePath(process, module.modBaseAddr);
                if (modulePath.empty())
                    continue;
                std::vector<BYTE> diskBytes = ReadFileBytes(modulePath);
                PeInfo diskPeInfo, remotePeInfo;
                if (!ReadPeInfo(diskBytes, diskPeInfo))
                    continue;
                std::vector<BYTE> remoteHeaderBytes(4096);
                SIZE_T bytesRead = 0;
                if (!ReadProcessMemory(process, module.modBaseAddr, remoteHeaderBytes.data(),
                                       remoteHeaderBytes.size(), &bytesRead))
                    continue;
                remoteHeaderBytes.resize(bytesRead);
                const wchar_t* findingReason = nullptr;
                if (!ReadPeInfo(remoteHeaderBytes, remotePeInfo))
                    findingReason = L"Entry-point modification";
                else if (diskPeInfo.timeDateStamp != remotePeInfo.timeDateStamp)
                    findingReason = L"Possible hollowing or packing";
                else if (remotePeInfo.entryPointRva <= diskPeInfo.imageSize)
                {
                    size_t entryPointOffset = 0;
                    bool entrySectionFound = false;
                    for (unsigned i = 0; i < diskPeInfo.sectionCount; ++i)
                    {
                        size_t sectionHeaderOffset = diskPeInfo.ntHeaderOffset + 24 +
                                                     diskPeInfo.optionalHeaderSize +
                                                     i * sizeof(IMAGE_SECTION_HEADER);
                        if (sectionHeaderOffset > diskBytes.size() ||
                            diskBytes.size() - sectionHeaderOffset < sizeof(IMAGE_SECTION_HEADER))
                            break;
                        IMAGE_SECTION_HEADER sectionHeader{};
                        memcpy(&sectionHeader, diskBytes.data() + sectionHeaderOffset,
                               sizeof sectionHeader);
                        if (diskPeInfo.entryPointRva >= sectionHeader.VirtualAddress &&
                            diskPeInfo.entryPointRva - sectionHeader.VirtualAddress <
                                sectionHeader.SizeOfRawData)
                        {
                            entryPointOffset = static_cast<size_t>(sectionHeader.PointerToRawData) +
                                               diskPeInfo.entryPointRva -
                                               sectionHeader.VirtualAddress;
                            entrySectionFound = true;
                            break;
                        }
                    }
                    BYTE entryPointBytes[10]{};
                    if (entrySectionFound && entryPointOffset <= diskBytes.size() &&
                        diskBytes.size() - entryPointOffset >= 10 &&
                        ReadProcessMemory(process, module.modBaseAddr + remotePeInfo.entryPointRva,
                                          entryPointBytes, 10, &bytesRead) &&
                        bytesRead == 10)
                    {
                        unsigned matchingByteCount = 0;
                        for (unsigned i = 0; i < 10; ++i)
                            matchingByteCount +=
                                entryPointBytes[i] == diskBytes[entryPointOffset + i];
                        if (matchingByteCount < 7)
                            findingReason = L"Entry-point modification";
                    }
                }
                if (findingReason)
                    PrintFinding(table, pid, 0, module.szExePath, 0, findingReason);
            }
        }
    } // namespace

    void ScanInjection(unsigned workerCount)
    {

        QueryThread queryThreadInformation = reinterpret_cast<QueryThread>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
        Handle processSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        Handle threadSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        std::multimap<DWORD, DWORD> threadsByProcessId;
        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof threadEntry;
        if (threadSnapshot.IsValid() && Thread32First(threadSnapshot, &threadEntry))
            do
            {
                threadsByProcessId.emplace(threadEntry.th32OwnerProcessID,
                                           threadEntry.th32ThreadID);
            } while (Thread32Next(threadSnapshot, &threadEntry));
        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof processEntry;
        if (!processSnapshot.IsValid() || !Process32FirstW(processSnapshot, &processEntry))
            return;
        ConsoleTable table(
            L"Injection scan",
            {{L"PID", 10}, {L"TID", 10}, {L"Address", 18}, {L"Finding", 28}, {L"Path", 38}});
        std::vector<PROCESSENTRY32W> processes;
        do
        {
            processes.push_back(processEntry);
        } while (Process32NextW(processSnapshot, &processEntry));
        const std::function<void(size_t)> inspectProcess = [&](size_t processIndex)
        {
            const PROCESSENTRY32W& processEntry = processes[processIndex];
            Handle processHandle(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                                             processEntry.th32ProcessID));
            if (!processHandle.IsValid())
                return;
            if (processEntry.th32ProcessID == GetCurrentProcessId())
                return;
            const ProcessArchitecture architecture = GetProcessArchitecture(processHandle);
            if (!CanInspectArchitecture(architecture))
            {
                ConsoleHelper::Error(L"[!] Skipping PID %lu: unsupported target architecture.\n",
                                     processEntry.th32ProcessID);
                return;
            }
            std::wstring processPath =
                ResolveSystemPath(GetProcessPath(processHandle), ProcessArchitecture::X64);
            std::vector<MODULEENTRY32W> moduleList =
                EnumerateModules(processEntry.th32ProcessID, architecture);
            if (queryThreadInformation)
            {
                std::pair<std::multimap<DWORD, DWORD>::const_iterator,
                          std::multimap<DWORD, DWORD>::const_iterator>
                    threadRange = threadsByProcessId.equal_range(processEntry.th32ProcessID);
                for (std::multimap<DWORD, DWORD>::const_iterator threadIterator = threadRange.first;
                     threadIterator != threadRange.second; ++threadIterator)
                {
                    Handle threadHandle(
                        OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadIterator->second));
                    PVOID threadStartAddress = nullptr;
                    if (!threadHandle.IsValid() ||
                        queryThreadInformation(threadHandle, 9, &threadStartAddress,
                                               sizeof threadStartAddress, nullptr) != 0)
                        continue;
                    uintptr_t threadStartValue = reinterpret_cast<uintptr_t>(threadStartAddress);
                    int addressCategory = ClassifyAddress(moduleList, threadStartValue);
                    if (addressCategory == 0)
                    {
                        MEMORY_BASIC_INFORMATION memoryInfo{};
                        if (!VirtualQueryEx(processHandle, threadStartAddress, &memoryInfo,
                                            sizeof memoryInfo) ||
                            IsSuspiciousProtection(memoryInfo.Protect))
                        {
                            PrintFinding(table, processEntry.th32ProcessID, threadIterator->second,
                                         processPath, threadStartValue, L"Suspicious thread");
                            break;
                        }
                    }
                    else if (addressCategory == 2)
                        CheckStack(table, processHandle, processEntry.th32ProcessID,
                                   threadIterator->second, processPath, moduleList, architecture);
                }
            }

            bool hasExecutableModule = false;
            for (const MODULEENTRY32W& module : moduleList)
                if (_wcsicmp(PathFindExtensionW(module.szExePath), L".exe") == 0)
                {
                    hasExecutableModule = true;
                    break;
                }
            if (!moduleList.empty() && !hasExecutableModule)
                PrintFinding(table, processEntry.th32ProcessID, 0, processPath, 0,
                             L"Executable module not found");
            if (hasExecutableModule)
                CheckEntryPoints(table, processHandle, processEntry.th32ProcessID, moduleList);
        };
        RunParallel(processes.size(), workerCount, inspectProcess);
    }
} // namespace Plimpy
