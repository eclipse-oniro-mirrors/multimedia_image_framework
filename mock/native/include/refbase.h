/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef MOCK_NATIVE_INCLUDE_REFBASE_H_
#define MOCK_NATIVE_INCLUDE_REFBASE_H_

#include <atomic>
#include <functional>

namespace OHOS {
#define INITIAL_PRIMARY_VALUE (1 << 28)

class RefBase;

class RefCounter {
public:
    using RefPtrCallback = std::function<void()>;
    friend class RefBase;

    RefCounter();

    explicit RefCounter(RefCounter *counter);

    RefCounter &operator=(const RefCounter &counter);

    virtual ~RefCounter();

    void SetCallback(const RefPtrCallback& callback);

    void RemoveCallback();

    int GetRefCount();

    void IncRefCount();

    void DecRefCount();

    bool IsRefPtrValid();

    int IncStrongRefCount(const void *objectId);

    int DecStrongRefCount(const void *objectId);

    int GetStrongRefCount();

    int IncWeakRefCount(const void *objectId);

    int DecWeakRefCount(const void *objectId);

    int GetWeakRefCount();

    void SetAttemptAcquire();

    bool IsAttemptAcquireSet();

    void ClearAttemptAcquire();

    bool AttemptIncStrongRef(const void *objectId, int &outCount);

    // Only for IPC use.
    bool AttemptIncStrong(const void *objectId);

    bool IsLifeTimeExtended();

    void ExtendObjectLifetime();

private:
    std::atomic<int> atomicStrong_;
    std::atomic<int> atomicWeak_;
    std::atomic<int> atomicRefCount_;
    std::atomic<unsigned int> atomicFlags_;
    std::atomic<int> atomicAttempt_;
    RefPtrCallback callback_ = nullptr;
    static constexpr unsigned int FLAG_EXTEND_LIFE_TIME = 0x00000002;
#ifdef DEBUG_REFBASE
    RefTracker* refTracker = nullptr;
    std::mutex trackerMutex;  // To ensure refTracker be thread-safe
    void GetNewTrace(const void* object);
    void PrintTracker();
#endif
};

class WeakRefCounter {
public:
    WeakRefCounter(RefCounter *base, void *cookie);

    virtual ~WeakRefCounter();

    void *GetRefPtr();

    void IncWeakRefCount(const void *objectId);

    void DecWeakRefCount(const void *objectId);

    bool AttemptIncStrongRef(const void *objectId);

private:
    std::atomic<int> atomicWeak_;
    RefCounter *refCounter_ = nullptr;
    void *cookie_ = nullptr;
};

class RefBase {
public:
    RefBase();

    RefBase(const RefBase &refbase);

    RefBase &operator=(const RefBase &refbase);

    RefBase(RefBase &&refbase) noexcept;

    RefBase &operator=(RefBase &&refbase) noexcept;

    virtual ~RefBase();

    virtual void RefPtrCallback();

    void ExtendObjectLifetime();

    void IncStrongRef(const void *objectId);

    void DecStrongRef(const void *objectId);

    int GetSptrRefCount();

    WeakRefCounter *CreateWeakRef(void *cookie);

    void IncWeakRef(const void *objectId);

    void DecWeakRef(const void *objectId);

    int GetWptrRefCount();

    bool AttemptAcquire(const void *objectId);

    bool AttemptIncStrongRef(const void *objectId);

    // Only for IPC use.
    bool AttemptIncStrong(const void *objectId);

    bool IsAttemptAcquireSet();

    bool IsExtendLifeTimeSet();

    virtual void OnFirstStrongRef(const void *objectId);

    virtual void OnLastStrongRef(const void *objectId);

    virtual void OnLastWeakRef(const void *objectId);

    virtual bool OnAttemptPromoted(const void *objectId);

private:
    RefCounter *refs_ = nullptr;
};
} // namespace OHOS

#endif // MOCK_NATIVE_INCLUDE_REFBASE_H_
