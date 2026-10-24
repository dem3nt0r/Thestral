#pragma once

#include "ProcessHelper.h"

namespace Plimpy
{
    // Captures the target's application stack (the x86 stack for a WOW64 target).
    // The scanner's own process is excluded to avoid suspending threads it depends on.
    bool CaptureThreadStack(HANDLE process, DWORD pid, DWORD tid, ProcessArchitecture architecture,
                            std::vector<uintptr_t>& addresses);
} // namespace Plimpy
