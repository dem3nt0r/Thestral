#pragma once

#include "WindowsPlatform.h"

namespace Plimpy
{
    bool UnloadDll(DWORD pid, const wchar_t* moduleNameOrPath);
}
