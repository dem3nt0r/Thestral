#pragma once

#include "WindowsPlatform.h"
#include <wincrypt.h>
#include <string>

namespace Plimpy
{
    std::wstring HashFile(const std::wstring& path, ALG_ID algorithm);
    std::wstring FormatFileTime(const FILETIME& fileTime);
    std::wstring GetFileOwner(const std::wstring& path);
} // namespace Plimpy
