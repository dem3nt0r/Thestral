#include "PeImage.h"
#include "Handle.h"
#include <cstring>

namespace Plimpy
{
    std::vector<BYTE> ReadFileBytes(const std::wstring& path)
    {
        Handle fileHandle(CreateFileW(path.c_str(), GENERIC_READ,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        LARGE_INTEGER fileSize{};
        if (!fileHandle.IsValid() || !GetFileSizeEx(fileHandle, &fileSize) ||
            fileSize.QuadPart <= 0 || fileSize.QuadPart > 512 * 1024 * 1024)
            return {};
        std::vector<BYTE> bytes(static_cast<size_t>(fileSize.QuadPart));
        DWORD bytesRead = 0;
        if (!ReadFile(fileHandle, bytes.data(), static_cast<DWORD>(bytes.size()), &bytesRead,
                      nullptr) ||
            bytesRead != bytes.size())
            return {};
        return bytes;
    }

    bool ReadPeInfo(const std::vector<BYTE>& bytes, PeInfo& info)
    {
        if (bytes.size() < sizeof(IMAGE_DOS_HEADER))
            return false;
        IMAGE_DOS_HEADER dosHeader{};
        memcpy(&dosHeader, bytes.data(), sizeof dosHeader);
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew < 0)
            return false;
        size_t ntHeaderOffset = static_cast<size_t>(dosHeader.e_lfanew);
        if (ntHeaderOffset > bytes.size() || bytes.size() - ntHeaderOffset < 24 + 60)
            return false;
        DWORD peSignature = 0;
        memcpy(&peSignature, bytes.data() + ntHeaderOffset, 4);
        if (peSignature != IMAGE_NT_SIGNATURE)
            return false;
        IMAGE_FILE_HEADER fileHeader{};
        memcpy(&fileHeader, bytes.data() + ntHeaderOffset + 4, sizeof fileHeader);
        memcpy(&info.optionalHeaderMagic, bytes.data() + ntHeaderOffset + 24, 2);
        if (info.optionalHeaderMagic != 0x10b && info.optionalHeaderMagic != 0x20b)
            return false;
        info.ntHeaderOffset = ntHeaderOffset;
        info.timeDateStamp = fileHeader.TimeDateStamp;
        info.sectionCount = fileHeader.NumberOfSections;
        info.optionalHeaderSize = fileHeader.SizeOfOptionalHeader;
        memcpy(&info.entryPointRva, bytes.data() + ntHeaderOffset + 40, 4);
        memcpy(&info.imageSize, bytes.data() + ntHeaderOffset + 80, 4);
        return true;
    }

    int GetImageBitness(const std::wstring& path)
    {
        PeInfo info;
        return ReadPeInfo(ReadFileBytes(path), info) ? (info.optionalHeaderMagic == 0x20b ? 2 : 1)
                                                     : 0;
    }
} // namespace Plimpy
