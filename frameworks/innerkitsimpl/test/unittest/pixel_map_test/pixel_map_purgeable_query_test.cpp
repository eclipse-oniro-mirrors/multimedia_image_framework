/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <utility>
#include <gtest/gtest.h>

#include "pixel_map.h"
#include "purgeable_mem_base.h"

#ifdef IMAGE_PURGEABLE_PIXELMAP
#include "image_purgeable_pixelmap_builder.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
class QueryablePurgeableMemory final : public PurgeableMem::PurgeableMemBase {
public:
    int GetPinStatus() const override
    {
        return status.load();
    }

    std::atomic<int> status {1};
};

class NoopPurgeableBuilder final : public PurgeableMem::PurgeableMemBuilder {
public:
    bool Build(void *, size_t) override
    {
        return true;
    }
};

class BlockingPurgeableMemory final : public PurgeableMem::PurgeableMemBase {
public:
    BlockingPurgeableMemory()
    {
        dataPtr_ = &data_;
        dataSizeInput_ = sizeof(data_);
        builder_ = std::make_unique<NoopPurgeableBuilder>();
        buildDataCount_ = 1;
    }

    int GetPinStatus() const override
    {
        return status.load();
    }

    bool Pin() override
    {
        status.fetch_add(1);
        if (onPin) {
            onPin();
        }
        return true;
    }

    bool Unpin() override
    {
        status.fetch_sub(1);
        return true;
    }

    bool IsPurged() override
    {
        return false;
    }

    std::atomic<int> status {1};
    std::function<void()> onPin;

private:
    uint8_t data_ = 0;
};

class CleanupRebuilder final : public PixelMapRebuilder {
public:
    explicit CleanupRebuilder(std::function<void()> cleanup) : cleanup_(std::move(cleanup)) {}

    ~CleanupRebuilder() override
    {
        if (cleanup_) {
            cleanup_();
        }
    }

    bool Rebuild(std::shared_ptr<PixelMap> &) override
    {
        return false;
    }

private:
    std::function<void()> cleanup_;
};

class CallbackRebuilder final : public PixelMapRebuilder {
public:
    explicit CallbackRebuilder(std::function<void()> callback) : callback_(std::move(callback)) {}

    bool Rebuild(std::shared_ptr<PixelMap> &) override
    {
        callback_();
        // These tests exercise callback execution, not pixel restoration or output-layout validation.
        return false;
    }

private:
    std::function<void()> callback_;
};

bool AllocateRebuildPixels(PixelMap &pixelMap)
{
    constexpr uint32_t size = 4;
    auto data = static_cast<uint8_t *>(std::malloc(size));
    if (data == nullptr) {
        return false;
    }
    pixelMap.SetPixelsAddr(data, nullptr, size, AllocatorType::HEAP_ALLOC, nullptr);
    return true;
}

constexpr auto QUERY_TIMEOUT = std::chrono::seconds(1);
} // namespace

class PixelMapPurgeableQueryTest : public testing::Test {};

/**
 * @tc.name: QueryDoesNotWaitForOperationLock
 * @tc.desc: query and backend snapshot do not acquire the operation lock held during a rebuild
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, QueryDoesNotWaitForOperationLock, TestSize.Level3)
{
    PixelMap pixelMap;
    auto memory = std::make_shared<QueryablePurgeableMemory>();
    pixelMap.SetPurgeableMemPtr(memory);
    const int statuses[] = {0, 1, 3, -1, -2};
    for (int status : statuses) {
        memory->status.store(status);
        std::unique_lock<std::mutex> operationLock(*pixelMap.unmapMutex_);
        auto query = std::async(std::launch::async, [&pixelMap]() {
            auto snapshot = pixelMap.GetPurgeableMemPtr();
            bool associated = true;
            bool success = pixelMap.GetPurgeableStatus(associated);
            return std::make_pair(success && snapshot != nullptr, associated);
        });
        const auto readiness = query.wait_for(QUERY_TIMEOUT);
        // Always release before joining, including when an old implementation blocks the query.
        operationLock.unlock();
        const auto result = query.get();
        EXPECT_EQ(readiness, std::future_status::ready);
        EXPECT_EQ(result.first, status >= -1);
        EXPECT_EQ(result.second, status >= 0);
        EXPECT_EQ(pixelMap.GetPurgeableMemPtr(), memory);
    }
    pixelMap.SetPurgeableMemPtr(nullptr);
}

/**
 * @tc.name: OrdinaryQueryDoesNotWaitForOperationLock
 * @tc.desc: an ordinary PixelMap can also be queried without the operation lock
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, OrdinaryQueryDoesNotWaitForOperationLock, TestSize.Level3)
{
    PixelMap pixelMap;
    std::unique_lock<std::mutex> operationLock(*pixelMap.unmapMutex_);
    auto query = std::async(std::launch::async, [&pixelMap]() {
        bool associated = true;
        bool success = pixelMap.GetPurgeableStatus(associated);
        return std::make_pair(success, associated);
    });
    const auto readiness = query.wait_for(QUERY_TIMEOUT);
    operationLock.unlock();
    const auto result = query.get();
    EXPECT_EQ(readiness, std::future_status::ready);
    EXPECT_TRUE(result.first);
    EXPECT_FALSE(result.second);
}

/**
 * @tc.name: QueryDoesNotWaitForLifecycleWriter
 * @tc.desc: queued writers and an exclusive lifecycle lock cannot delay an association query
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, QueryDoesNotWaitForLifecycleWriter, TestSize.Level3)
{
    PixelMap pixelMap;
    auto memory = std::make_shared<QueryablePurgeableMemory>();
    auto state = std::make_shared<PixelMapRebuildState>();
    pixelMap.SetPurgeableMemPtr(memory, state);
    std::unique_lock<std::shared_mutex> writer(state->purgeableMutex);
    auto query = std::async(std::launch::async, [&] { return pixelMap.IsPurgeable(); });
    const auto readiness = query.wait_for(QUERY_TIMEOUT);
    writer.unlock();
    EXPECT_EQ(readiness, std::future_status::ready);
    EXPECT_TRUE(query.get());
    pixelMap.SetPurgeableMemPtr(nullptr);
}

/**
 * @tc.name: PinSharesLifecycleLockAndRetirementWaits
 * @tc.desc: a blocked backend Pin retains only a shared lifecycle lock, while retirement waits for it
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, PinSharesLifecycleLockAndRetirementWaits, TestSize.Level3)
{
    PixelMap pixelMap;
    auto memory = std::make_shared<BlockingPurgeableMemory>();
    auto state = std::make_shared<PixelMapRebuildState>();
    std::weak_ptr<PixelMapRebuildState> lifetime = state;
    pixelMap.SetPurgeableMemPtr(memory, state);
    std::promise<void> entered;
    auto enteredFuture = entered.get_future();
    std::promise<void> release;
    auto releaseFuture = release.get_future().share();
    memory->onPin = [&] {
        entered.set_value();
        releaseFuture.wait();
    };
    auto pin = std::async(std::launch::async, [&] { return pixelMap.PinPurgeableMemory(); });
    const auto started = enteredFuture.wait_for(QUERY_TIMEOUT);
    auto reader = std::async(std::launch::async, [&] {
        std::shared_lock<std::shared_mutex> lock(state->purgeableMutex);
        return pixelMap.IsPurgeable();
    });
    const auto sharedReady = reader.wait_for(QUERY_TIMEOUT);
    // Finish the reader before queuing a writer: shared_mutex may prefer queued writers.
    release.set_value();
    EXPECT_TRUE(pin.get());
    EXPECT_TRUE(reader.get());
    EXPECT_EQ(started, std::future_status::ready);
    EXPECT_EQ(sharedReady, std::future_status::ready);

    std::promise<void> enteredAgain;
    auto enteredAgainFuture = enteredAgain.get_future();
    std::promise<void> releaseAgain;
    auto releaseAgainFuture = releaseAgain.get_future().share();
    memory->onPin = [&] {
        enteredAgain.set_value();
        releaseAgainFuture.wait();
    };
    auto nextPin = std::async(std::launch::async, [&] { return pixelMap.PinPurgeableMemory(); });
    const auto nextStarted = enteredAgainFuture.wait_for(QUERY_TIMEOUT);
    std::promise<void> retiring;
    auto retiringFuture = retiring.get_future();
    auto detach = std::async(std::launch::async, [&] {
        retiring.set_value();
        pixelMap.SetPurgeableMemPtr(nullptr);
    });
    const auto detachStarted = retiringFuture.wait_for(QUERY_TIMEOUT);
    const auto detachReadiness = detach.wait_for(std::chrono::milliseconds(50));
    auto query = std::async(std::launch::async, [&] { return pixelMap.IsPurgeable(); });
    const auto queryReadiness = query.wait_for(QUERY_TIMEOUT);
    releaseAgain.set_value();
    EXPECT_TRUE(nextPin.get());
    detach.get();
    EXPECT_TRUE(query.get());
    EXPECT_EQ(nextStarted, std::future_status::ready);
    EXPECT_EQ(detachStarted, std::future_status::ready);
    EXPECT_EQ(detachReadiness, std::future_status::timeout);
    EXPECT_EQ(queryReadiness, std::future_status::ready);
    EXPECT_EQ(std::atomic_load(&pixelMap.purgeableRebuildState_), nullptr);
    EXPECT_FALSE(lifetime.expired());
    state.reset();
    EXPECT_TRUE(lifetime.expired());
}

/**
 * @tc.name: OldCleanupCannotRetireNewAssociation
 * @tc.desc: an old operation's deferred cleanup must not detach a different privileged association
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, OldCleanupCannotRetireNewAssociation, TestSize.Level3)
{
    PixelMap pixelMap;
    auto first = std::make_shared<QueryablePurgeableMemory>();
    auto firstState = std::make_shared<PixelMapRebuildState>();
    pixelMap.SetPurgeableMemPtr(first, firstState);
    auto second = std::make_shared<QueryablePurgeableMemory>();
    auto secondState = std::make_shared<PixelMapRebuildState>();
    pixelMap.SetPurgeableMemPtr(second, secondState);
    pixelMap.ClearPurgeableResources(firstState, first);
    EXPECT_EQ(pixelMap.GetPurgeableMemPtr(), second);
    EXPECT_EQ(std::atomic_load(&pixelMap.purgeableRebuildState_), secondState);
    pixelMap.SetPurgeableMemPtr(nullptr);
}

/**
 * @tc.name: LiveBackendKeepsItsOriginalState
 * @tc.desc: setting the same backend cannot swap out the lock and state used by existing operations
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, LiveBackendKeepsItsOriginalState, TestSize.Level3)
{
    PixelMap pixelMap;
    auto memory = std::make_shared<QueryablePurgeableMemory>();
    auto original = std::make_shared<PixelMapRebuildState>();
    auto replacement = std::make_shared<PixelMapRebuildState>();
    pixelMap.SetPurgeableMemPtr(memory, original);
    pixelMap.SetPurgeableMemPtr(memory, replacement);
    EXPECT_EQ(std::atomic_load(&pixelMap.purgeableRebuildState_), original);
    pixelMap.SetPurgeableMemPtr(memory);
    EXPECT_EQ(std::atomic_load(&pixelMap.purgeableRebuildState_), original);
    pixelMap.SetPurgeableMemPtr(nullptr);
}

/**
 * @tc.name: RetirementWaitsForDirectBuildMutex
 * @tc.desc: a Build using only the state mutex is joined before current is cleared, without delaying queries
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, RetirementWaitsForDirectBuildMutex, TestSize.Level3)
{
    PixelMap pixelMap;
    auto memory = std::make_shared<QueryablePurgeableMemory>();
    auto state = std::make_shared<PixelMapRebuildState>();
    pixelMap.SetPurgeableMemPtr(memory, state);
    std::unique_lock<std::mutex> building(state->mutex);
    std::promise<void> entered;
    auto enteredFuture = entered.get_future();
    auto detach = std::async(std::launch::async, [&] {
        entered.set_value();
        pixelMap.SetPurgeableMemPtr(nullptr);
    });
    const auto started = enteredFuture.wait_for(QUERY_TIMEOUT);
    const auto waiting = detach.wait_for(std::chrono::milliseconds(50));
    auto query = std::async(std::launch::async, [&] { return pixelMap.IsPurgeable(); });
    const auto ready = query.wait_for(QUERY_TIMEOUT);
    building.unlock();
    detach.get();
    EXPECT_EQ(started, std::future_status::ready);
    EXPECT_EQ(waiting, std::future_status::timeout);
    EXPECT_EQ(ready, std::future_status::ready);
    EXPECT_TRUE(query.get());
    EXPECT_EQ(std::atomic_load(&pixelMap.purgeableRebuildState_), nullptr);
}

/**
 * @tc.name: SuppliedStateCanAdoptFirstRebuilder
 * @tc.desc: an explicitly supplied framework state preserves first-registration and state-identity semantics
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, SuppliedStateCanAdoptFirstRebuilder, TestSize.Level3)
{
    PixelMap pixelMap;
    auto memory = std::make_shared<BlockingPurgeableMemory>();
    auto state = std::make_shared<PixelMapRebuildState>();
    pixelMap.SetPurgeableMemPtr(memory, state);
    int cleanups = 0;
    bool unsupported = true;
    EXPECT_TRUE(pixelMap.SetPurgeableRebuilder(
        std::make_unique<CleanupRebuilder>([&] { ++cleanups; }), unsupported));
    EXPECT_FALSE(unsupported);
    EXPECT_EQ(memory->status.load(), 1);
    EXPECT_EQ(std::atomic_load(&pixelMap.purgeableRebuildState_), state);
    EXPECT_EQ(cleanups, 0);
    pixelMap.SetPurgeableMemPtr(nullptr);
    EXPECT_EQ(cleanups, 1);
}

/**
 * @tc.name: LockOnlyStateDoesNotEnableRebuilderRegistration
 * @tc.desc: allocating a lock for a one-argument backend must not make it support framework callbacks
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, LockOnlyStateDoesNotEnableRebuilderRegistration, TestSize.Level3)
{
    PixelMap pixelMap;
    auto memory = std::make_shared<BlockingPurgeableMemory>();
    pixelMap.SetPurgeableMemPtr(memory);
    int pins = 0;
    memory->onPin = [&] { ++pins; };
    bool unsupported = false;
    EXPECT_FALSE(pixelMap.SetPurgeableRebuilder(std::make_unique<CleanupRebuilder>(nullptr), unsupported));
    EXPECT_FALSE(unsupported);
    EXPECT_EQ(pins, 0);
    EXPECT_EQ(memory->status.load(), 1);
    pixelMap.SetPurgeableMemPtr(nullptr);
}

/**
 * @tc.name: RebuildReentryRejectsExecutionButAllowsQuery
 * @tc.desc: a real Build callback rejects same-map execution before locking, but still allows queries
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, RebuildReentryRejectsExecutionButAllowsQuery, TestSize.Level3)
{
    PixelMap pixelMap;
    ASSERT_TRUE(AllocateRebuildPixels(pixelMap));
    auto memory = std::make_shared<QueryablePurgeableMemory>();
    auto state = std::make_shared<PixelMapRebuildState>();
    int callbacks = 0;
    state->current = std::make_unique<CallbackRebuilder>([&] {
        ++callbacks;
        std::unique_lock<std::shared_mutex> writer(state->purgeableMutex);
        bool unsupported = true;
        EXPECT_FALSE(pixelMap.PinPurgeableMemory(unsupported));
        EXPECT_TRUE(unsupported);
        unsupported = false;
        EXPECT_FALSE(pixelMap.UnpinPurgeableMemory(unsupported));
        EXPECT_TRUE(unsupported);
        EXPECT_FALSE(pixelMap.DisablePurgeable());
        EXPECT_FALSE(pixelMap.SetPurgeableRebuilder(std::make_unique<CleanupRebuilder>(nullptr)));
        EXPECT_TRUE(pixelMap.IsPurgeable());
        EXPECT_FALSE(pixelMap.UnMap());
        EXPECT_FALSE(pixelMap.ReMap());
        pixelMap.SetPurgeableMemPtr(nullptr);
        pixelMap.FreePixelMap();
        EXPECT_EQ(pixelMap.GetPurgeableMemPtr(), memory);
    });
    pixelMap.SetPurgeableMemPtr(memory, state);
    PurgeablePixelMapBuilder builder(state, pixelMap);
    EXPECT_FALSE(builder.Build(pixelMap.GetWritablePixels(), pixelMap.GetAllocationByteCount()));
    EXPECT_EQ(callbacks, 1);
    pixelMap.SetPurgeableMemPtr(nullptr);
    EXPECT_EQ(pixelMap.GetPurgeableMemPtr(), nullptr);
}

/**
 * @tc.name: RebuildScopeRestoresOuterChainAndIsThreadLocal
 * @tc.desc: nested real Build callbacks preserve the outer guard without blocking another thread
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, RebuildScopeRestoresOuterChainAndIsThreadLocal, TestSize.Level3)
{
    PixelMap original;
    PixelMap temporary;
    ASSERT_TRUE(AllocateRebuildPixels(original));
    ASSERT_TRUE(AllocateRebuildPixels(temporary));
    auto originalMemory = std::make_shared<BlockingPurgeableMemory>();
    auto temporaryMemory = std::make_shared<BlockingPurgeableMemory>();
    auto originalState = std::make_shared<PixelMapRebuildState>();
    auto temporaryState = std::make_shared<PixelMapRebuildState>();
    PurgeablePixelMapBuilder outer(originalState, original);
    PurgeablePixelMapBuilder inner(temporaryState, temporary);
    int outerCallbacks = 0;
    int innerCallbacks = 0;
    temporaryState->current = std::make_unique<CallbackRebuilder>([&] {
        ++innerCallbacks;
        bool unsupported = false;
        EXPECT_FALSE(original.PinPurgeableMemory(unsupported));
        EXPECT_TRUE(unsupported);
        unsupported = false;
        EXPECT_FALSE(temporary.PinPurgeableMemory(unsupported));
        EXPECT_TRUE(unsupported);
        // A -> B -> A must fail before trying to take A's already-held rebuilder mutex.
        EXPECT_FALSE(outer.Build(original.GetWritablePixels(), original.GetAllocationByteCount()));
    });
    originalState->current = std::make_unique<CallbackRebuilder>([&] {
        ++outerCallbacks;
        auto otherThread = std::async(std::launch::async, [&] {
            bool unsupported = true;
            bool pinned = original.PinPurgeableMemory(unsupported);
            bool unpinned = pinned && original.UnpinPurgeableMemory();
            return pinned && unpinned && !unsupported;
        });
        EXPECT_TRUE(otherThread.get());
        EXPECT_FALSE(inner.Build(temporary.GetWritablePixels(), temporary.GetAllocationByteCount()));
        bool unsupported = false;
        EXPECT_FALSE(original.PinPurgeableMemory(unsupported));
        EXPECT_TRUE(unsupported);
        // Returning from B must clear B's guard while retaining A's guard.
        bool pinned = temporary.PinPurgeableMemory();
        EXPECT_TRUE(pinned);
        if (pinned) {
            EXPECT_TRUE(temporary.UnpinPurgeableMemory());
        }
    });
    original.SetPurgeableMemPtr(originalMemory, originalState);
    temporary.SetPurgeableMemPtr(temporaryMemory, temporaryState);
    EXPECT_FALSE(outer.Build(original.GetWritablePixels(), original.GetAllocationByteCount()));
    EXPECT_EQ(outerCallbacks, 1);
    EXPECT_EQ(innerCallbacks, 1);
    // Returning from A must also clear A's guard on the calling thread.
    bool pinned = original.PinPurgeableMemory();
    EXPECT_TRUE(pinned);
    if (pinned) {
        EXPECT_TRUE(original.UnpinPurgeableMemory());
    }
    EXPECT_EQ(originalMemory->status.load(), 1);
    EXPECT_EQ(temporaryMemory->status.load(), 1);
    original.SetPurgeableMemPtr(nullptr);
    temporary.SetPurgeableMemPtr(nullptr);
}

/**
 * @tc.name: RebuilderReleaseWaitsForOutermostScope
 * @tc.desc: nested retirement waits until the outer address replacement has completed
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, RebuilderReleaseWaitsForOutermostScope, TestSize.Level3)
{
    PixelMap pixelMap;
    auto first = static_cast<uint8_t *>(std::malloc(4));
    auto second = static_cast<uint8_t *>(std::malloc(4));
    if (first == nullptr || second == nullptr) {
        std::free(first);
        std::free(second);
        FAIL();
        return;
    }
    pixelMap.SetPixelsAddr(first, nullptr, 4, AllocatorType::HEAP_ALLOC, nullptr);
    auto memory = std::make_shared<QueryablePurgeableMemory>();
    auto state = std::make_shared<PixelMapRebuildState>();
    int cleanups = 0;
    bool replacementVisible = false;
    state->current = std::make_unique<CleanupRebuilder>([&]() {
        ++cleanups;
        replacementVisible = pixelMap.GetPixels() == second;
    });
    pixelMap.SetPurgeableMemPtr(memory, state);
    // FreePixelMap must pass retirement to the outer scope instead of destroying before address installation.
    pixelMap.SetPixelsAddr(second, nullptr, 4, AllocatorType::HEAP_ALLOC, false);
    EXPECT_EQ(cleanups, 1);
    EXPECT_TRUE(replacementVisible);
    EXPECT_EQ(pixelMap.GetPurgeableMemPtr(), nullptr);
    EXPECT_EQ(state->current, nullptr);
    EXPECT_EQ(pixelMap.GetPixels(), second);
}

/**
 * @tc.name: AddressReplacementDestroysRebuilderAfterPixelUnlock
 * @tc.desc: nested FreePixelMap must not invoke user cleanup under the outer pixel-data write lock
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, AddressReplacementDestroysRebuilderAfterPixelUnlock, TestSize.Level3)
{
    PixelMap pixelMap;
    auto first = static_cast<uint8_t *>(std::malloc(4));
    auto second = static_cast<uint8_t *>(std::malloc(4));
    if (first == nullptr || second == nullptr) {
        std::free(first);
        std::free(second);
        FAIL();
        return;
    }
    pixelMap.SetPixelsAddr(first, nullptr, 4, AllocatorType::HEAP_ALLOC, nullptr);
    auto memory = std::make_shared<QueryablePurgeableMemory>();
    auto state = std::make_shared<PixelMapRebuildState>();
    int cleanups = 0;
    bool pixelUnlocked = false;
    bool lifecycleUnlocked = false;
    bool rebuilderUnlocked = false;
    state->current = std::make_unique<CleanupRebuilder>([&] {
        ++cleanups;
        std::unique_lock<std::shared_mutex> pixelLock(*pixelMap.pixelDataMutex_, std::try_to_lock);
        std::unique_lock<std::shared_mutex> lifecycleLock(state->purgeableMutex, std::try_to_lock);
        std::unique_lock<std::mutex> rebuilderLock(state->mutex, std::try_to_lock);
        pixelUnlocked = pixelLock.owns_lock();
        lifecycleUnlocked = lifecycleLock.owns_lock();
        rebuilderUnlocked = rebuilderLock.owns_lock();
    });
    pixelMap.SetPurgeableMemPtr(memory, state);
    pixelMap.SetPixelsAddr(second, nullptr, 4, AllocatorType::HEAP_ALLOC, nullptr);
    EXPECT_EQ(cleanups, 1);
    EXPECT_TRUE(pixelUnlocked);
    EXPECT_TRUE(lifecycleUnlocked);
    EXPECT_TRUE(rebuilderUnlocked);
    EXPECT_EQ(pixelMap.GetPurgeableMemPtr(), nullptr);
    EXPECT_EQ(std::atomic_load(&pixelMap.purgeableRebuildState_), nullptr);
    EXPECT_EQ(pixelMap.GetPixels(), second);
}

/**
 * @tc.name: SnapshotRetainsBackendAfterDetach
 * @tc.desc: clearing the published association cannot destroy a backend retained by a reader
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, SnapshotRetainsBackendAfterDetach, TestSize.Level3)
{
    PixelMap pixelMap;
    auto memory = std::make_shared<QueryablePurgeableMemory>();
    std::weak_ptr<QueryablePurgeableMemory> lifetime = memory;
    pixelMap.SetPurgeableMemPtr(memory);
    auto snapshot = pixelMap.GetPurgeableMemPtr();
    memory.reset();
    pixelMap.SetPurgeableMemPtr(nullptr);
    EXPECT_EQ(pixelMap.GetPurgeableMemPtr(), nullptr);
    EXPECT_FALSE(lifetime.expired());
    EXPECT_EQ(snapshot->GetPinStatus(), 1);
    snapshot.reset();
    EXPECT_TRUE(lifetime.expired());
}

/**
 * @tc.name: ConcurrentAssociationPublicationAndQuery
 * @tc.desc: readers retain valid snapshots while a writer replaces and clears associations
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapPurgeableQueryTest, ConcurrentAssociationPublicationAndQuery, TestSize.Level3)
{
    PixelMap pixelMap;
    auto first = std::make_shared<QueryablePurgeableMemory>();
    auto second = std::make_shared<QueryablePurgeableMemory>();
    second->status.store(0);
    std::atomic<bool> done {false};
    auto query = std::async(std::launch::async, [&pixelMap, &done]() {
        uint32_t reads = 0;
        do {
            bool associated = false;
            if (!pixelMap.GetPurgeableStatus(associated)) {
                return false;
            }
            auto snapshot = pixelMap.GetPurgeableMemPtr();
            if (snapshot != nullptr && snapshot->GetPinStatus() < 0) {
                return false;
            }
            ++reads;
        } while (!done.load() || reads < 1000);
        return true;
    });
    for (uint32_t i = 0; i < 1000; ++i) {
        pixelMap.SetPurgeableMemPtr(first);
        pixelMap.SetPurgeableMemPtr(second);
        pixelMap.SetPurgeableMemPtr(nullptr);
    }
    done.store(true);
    EXPECT_TRUE(query.get());
}
} // namespace Media
} // namespace OHOS
#endif
