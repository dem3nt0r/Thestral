#pragma once

#include "WindowsPlatform.h"
#include <cstddef>
#include <string>
#include <vector>

namespace Plimpy
{
    struct PeInfo
    {
        WORD optionalHeaderMagic = 0;
        DWORD timeDateStamp = 0, entryPointRva = 0, imageSize = 0;
        size_t ntHeaderOffset = 0;
        WORD sectionCount = 0, optionalHeaderSize = 0;
    };
    bool ReadPeInfo(const std::vector<BYTE>& bytes, PeInfo& info);
    std::vector<BYTE> ReadFileBytes(const std::wstring& path);
    int GetImageBitness(const std::wstring& path);
} // namespace Plimpy
