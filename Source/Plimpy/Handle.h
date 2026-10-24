#pragma once

#include "WindowsPlatform.h"

namespace Plimpy
{
    struct Handle
    {
        HANDLE value;
        explicit Handle(HANDLE handle = nullptr) : value(handle)
        {
        }
        ~Handle()
        {
            if (IsValid())
                CloseHandle(value);
        }
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        bool IsValid() const
        {
            return value && value != INVALID_HANDLE_VALUE;
        }
        operator HANDLE() const
        {
            return value;
        }
    };

} // namespace Plimpy
