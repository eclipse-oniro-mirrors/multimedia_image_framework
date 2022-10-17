/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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


#ifndef MOCK_NATIVE_INCLUDE_PARCEL_H_
#define MOCK_NATIVE_INCLUDE_PARCEL_H_

#include <string>
#include <vector>
#include "nocopyable.h"
#include "refbase.h"

namespace OHOS {
class Parcel;

class Parcelable : public virtual RefBase {
public:
    virtual ~Parcelable() = default;

    Parcelable();
    explicit Parcelable(bool asRemote);

    // Write a parcelable object to the given parcel.
    // The object position is saved into Parcel if set asRemote_ to
    // true, and this intends to use in kernel data transaction.
    // Returns true being written on success or false if any error occur.
    virtual bool Marshalling(Parcel &parcel) const = 0;

    // NOTICE! A static Unmarshalling function must also be implemented, so
    // that you can get data from the given parcel into this parcelable object.
    // See "static TestParcelable *Unmarshalling(Parcel &parcel)" as an example.

    enum BehaviorFlag { IPC = 0x01, RPC = 0x02, HOLD_OBJECT = 0x10 };

    inline void SetBehavior(BehaviorFlag b) const
    {
        behavior_ |= static_cast<uint8_t>(b);
    }

    inline void ClearBehavior(BehaviorFlag b) const
    {
        behavior_ &= ~(static_cast<uint8_t>(b));
    }

    inline bool TestBehavior(BehaviorFlag b) const
    {
        return behavior_ & (static_cast<uint8_t>(b));
    }

public:
    bool asRemote_;
    mutable uint8_t behavior_;
};

class Allocator {
public:
    virtual ~Allocator() = default;

    virtual void *Realloc(void *data, size_t newSize) = 0;

    virtual void *Alloc(size_t size) = 0;

    virtual void Dealloc(void *data) = 0;
};

class Parcel {
public:
    Parcel();
    explicit Parcel(Allocator *allocator);

    virtual ~Parcel();

    size_t GetWritableBytes() const;

    size_t GetReadableBytes() const;

    size_t GetDataCapacity() const;

    bool SetDataCapacity(size_t newCapacity);

    bool SetDataSize(size_t dataSize);

    bool SetMaxCapacity(size_t maxCapacity);

    bool WriteInt32(int32_t value);

    bool WriteUint32(uint32_t value);

    bool WriteUnpadBuffer(const void *data, size_t size);

    bool WriteParcelable(const Parcelable *object);

    bool WriteRemoteObject(const Parcelable *object);

    bool ParseFrom(uintptr_t data, size_t size);

    int32_t ReadInt32();

    uint32_t ReadUint32();

    bool ReadInt32(int32_t &value);

    bool ReadUint32(uint32_t &value);

    const uint8_t *ReadBuffer(size_t length);

    const uint8_t *ReadUnpadBuffer(size_t length);

    size_t GetReadPosition();

    bool CheckOffsets();

    bool SetAllocator(Allocator *allocator);

private:
    DISALLOW_COPY_AND_MOVE(Parcel);
    template <typename T>
    bool Write(T value);

    template <typename T>
    bool Read(T &value);

    template <typename T>
    T Read();

    bool WriteDataBytes(const void *data, size_t size);

    void WritePadBytes(size_t padded);
};
} // namespace OHOS
#endif // MOCK_NATIVE_INCLUDE_PARCEL_H_
