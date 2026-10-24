#include "ThreadStack.h"
#include "Handle.h"
#include "ConsoleHelper.h"

#include <dbghelp.h>
#include <mutex>

namespace Plimpy
{
    namespace
    {
        std::mutex dbgHelpMutex;

        class SymbolSession
        {
          public:
            explicit SymbolSession(HANDLE process) : processHandle(process)
            {
                initialized = SymInitialize(processHandle, nullptr, TRUE) != FALSE;
            }

            ~SymbolSession()
            {
                if (initialized)
                    SymCleanup(processHandle);
            }

            bool IsValid() const
            {
                return initialized;
            }

            SymbolSession(const SymbolSession&) = delete;
            SymbolSession& operator=(const SymbolSession&) = delete;

          private:
            HANDLE processHandle;
            bool initialized = false;
        };

        class ThreadSuspension
        {
          public:
            ThreadSuspension(HANDLE thread, ProcessArchitecture architecture) : threadHandle(thread)
            {
#ifdef _WIN64
                if (architecture == ProcessArchitecture::X86)
                    suspended = Wow64SuspendThread(threadHandle) != static_cast<DWORD>(-1);
                else
#else
                (void)architecture;
#endif
                    suspended = SuspendThread(threadHandle) != static_cast<DWORD>(-1);
            }

            ~ThreadSuspension()
            {
                if (suspended)
                    Resume();
            }

            bool IsValid() const
            {
                return suspended;
            }

            bool Resume()
            {
                if (!suspended)
                    return false;
                if (ResumeThread(threadHandle) == static_cast<DWORD>(-1))
                {
                    const DWORD error = GetLastError();
                    ConsoleHelper::Error(L"[!] Failed to resume thread %lu: %lu\n",
                                         GetThreadId(threadHandle), error);
                    return false;
                }
                suspended = false;
                return true;
            }

            ThreadSuspension(const ThreadSuspension&) = delete;
            ThreadSuspension& operator=(const ThreadSuspension&) = delete;

          private:
            HANDLE threadHandle;
            bool suspended = false;
        };

        void WalkStack(HANDLE process, HANDLE thread, DWORD machineType, PVOID context,
                       DWORD64 instructionPointer, DWORD64 stackPointer, DWORD64 framePointer,
                       std::vector<uintptr_t>& addresses)
        {
            if (instructionPointer)
                addresses.push_back(static_cast<uintptr_t>(instructionPointer));
            STACKFRAME64 stackFrame{};
            stackFrame.AddrPC.Offset = instructionPointer;
            stackFrame.AddrPC.Mode = AddrModeFlat;
            stackFrame.AddrStack.Offset = stackPointer;
            stackFrame.AddrStack.Mode = AddrModeFlat;
            stackFrame.AddrFrame.Offset = framePointer;
            stackFrame.AddrFrame.Mode = AddrModeFlat;
            for (unsigned frameIndex = 0; frameIndex < 50; ++frameIndex)
            {
                if (!StackWalk64(machineType, process, thread, &stackFrame, context, nullptr,
                                 SymFunctionTableAccess64, SymGetModuleBase64, nullptr) ||
                    !stackFrame.AddrPC.Offset)
                    break;
                addresses.push_back(static_cast<uintptr_t>(stackFrame.AddrPC.Offset));
                if (!stackFrame.AddrReturn.Offset)
                    break;
            }
        }
    } // namespace

    bool CaptureThreadStack(HANDLE process, DWORD pid, DWORD tid, ProcessArchitecture architecture,
                            std::vector<uintptr_t>& addresses)
    {
        addresses.clear();
        if (pid == GetCurrentProcessId() || GetProcessId(process) != pid ||
            !CanInspectArchitecture(architecture) ||
            GetProcessArchitecture(process) != architecture)
            return false;

        Handle threadHandle(OpenThread(
            THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, tid));
        if (!threadHandle.IsValid() || GetProcessIdOfThread(threadHandle) != pid)
            return false;

        // DbgHelp is single threaded. Acquire the lock before suspending a target,
        // and retain it through SymCleanup. Other process checks can run in parallel.
        std::lock_guard<std::mutex> dbgHelpLock(dbgHelpMutex);
        SymbolSession symbols(process);
        if (!symbols.IsValid())
            return false;
        addresses.reserve(51);
        ThreadSuspension suspension(threadHandle, architecture);
        if (!suspension.IsValid())
            return false;

        bool contextCaptured = false;
#ifdef _WIN64
        if (architecture == ProcessArchitecture::X86)
        {
            WOW64_CONTEXT threadContext{};
            threadContext.ContextFlags = WOW64_CONTEXT_FULL;
            contextCaptured = Wow64GetThreadContext(threadHandle, &threadContext) != FALSE;
            if (contextCaptured)
                WalkStack(process, threadHandle, IMAGE_FILE_MACHINE_I386, &threadContext,
                          threadContext.Eip, threadContext.Esp, threadContext.Ebp, addresses);
        }
        else
        {
            CONTEXT threadContext{};
            threadContext.ContextFlags = CONTEXT_FULL;
            contextCaptured = GetThreadContext(threadHandle, &threadContext) != FALSE;
            if (contextCaptured)
                WalkStack(process, threadHandle, IMAGE_FILE_MACHINE_AMD64, &threadContext,
                          threadContext.Rip, threadContext.Rsp, threadContext.Rbp, addresses);
        }
#else
        CONTEXT threadContext{};
        threadContext.ContextFlags = CONTEXT_FULL;
        contextCaptured = GetThreadContext(threadHandle, &threadContext) != FALSE;
        if (contextCaptured)
            WalkStack(process, threadHandle, IMAGE_FILE_MACHINE_I386, &threadContext,
                      threadContext.Eip, threadContext.Esp, threadContext.Ebp, addresses);
#endif
        const bool resumed = suspension.Resume();
        return contextCaptured && resumed && !addresses.empty();
    }
} // namespace Plimpy
