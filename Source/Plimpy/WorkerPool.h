#pragma once

#include <cstddef>
#include <functional>

namespace Plimpy
{
    inline constexpr unsigned DefaultWorkerCount = 5;
    inline constexpr unsigned MaximumWorkerCount = 64;

    // On success, each item runs once. All started workers are joined before return or throw.
    void RunParallel(size_t itemCount, unsigned workerCount,
                     const std::function<void(size_t)>& processItem);
} // namespace Plimpy
