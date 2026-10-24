#include "WorkerPool.h"

#include <algorithm>
#include <atomic>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace Plimpy
{
    void RunParallel(size_t itemCount, unsigned workerCount,
                     const std::function<void(size_t)>& processItem)
    {
        if (!workerCount || workerCount > MaximumWorkerCount)
            throw std::invalid_argument("Worker count must be between 1 and 64.");
        if (!itemCount)
            return;

        const size_t threadCount = std::min(itemCount, static_cast<size_t>(workerCount));
        std::atomic<size_t> nextItem{0};
        std::atomic<bool> cancelled{false};
        std::exception_ptr failure;
        std::mutex failureMutex;
        std::vector<std::thread> workers;
        workers.reserve(threadCount);
        const std::function<void()> runWorker = [&]()
        {
            try
            {
                while (!cancelled.load())
                {
                    const size_t itemIndex = nextItem.fetch_add(1);
                    if (itemIndex >= itemCount)
                        break;
                    processItem(itemIndex);
                }
            }
            catch (...)
            {
                std::lock_guard<std::mutex> lock(failureMutex);
                if (!failure)
                    failure = std::current_exception();
                cancelled.store(true);
            }
        };

        try
        {
            for (size_t threadIndex = 0; threadIndex < threadCount; ++threadIndex)
                workers.emplace_back(runWorker);
        }
        catch (...)
        {
            cancelled.store(true);
            for (std::thread& worker : workers)
                worker.join();
            throw;
        }

        for (std::thread& worker : workers)
            worker.join();
        if (failure)
            std::rethrow_exception(failure);
    }
} // namespace Plimpy
