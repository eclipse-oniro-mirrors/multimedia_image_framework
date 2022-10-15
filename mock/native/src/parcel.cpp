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

#include "parcel.h"

namespace OHOS {
Parcelable::Parcelable() : Parcelable(false)
{}

Parcelable::Parcelable(bool asRemote)
{}

Parcel::Parcel(Allocator *allocator)
{}

Parcel::~Parcel()
{}

size_t Parcel::GetWritableBytes() const
{
    return 0;
}

size_t Parcel::GetReadableBytes() const
{
    return 0;
}

size_t Parcel::GetDataCapacity() const
{
    return 0;
}

bool Parcel::SetMaxCapacity(size_t maxCapacity)
{
    (void) maxCapacity;
    return false;
}

bool Parcel::SetAllocator(Allocator *allocator)
{
    (void) allocator;
    return true;
}

bool Parcel::CheckOffsets()
{
    return false;
}

bool Parcel::SetDataCapacity(size_t newCapacity)
{
    (void) newCapacity;
    return false;
}

bool Parcel::SetDataSize(size_t dataSize)
{
    (void) dataSize;
    return true;
}

bool Parcel::WriteDataBytes(const void *data, size_t size)
{
    (void) data;
    (void) size;
    return true;
}

void Parcel::WritePadBytes(size_t padSize)
{
    (void) padSize;
}

bool Parcel::WriteUnpadBuffer(const void *data, size_t size)
{
    (void) data;
    (void) size;
    return false;
}

template <typename T>
bool Parcel::Write(T value)
{
    return false;
}

bool Parcel::WriteInt32(int32_t value)
{
    return Write<int32_t>(value);
}

bool Parcel::WriteUint32(uint32_t value)
{
    return Write<uint32_t>(value);
}

bool Parcel::WriteRemoteObject(const Parcelable *object)
{
    (void) object;
    return false;
}

bool Parcel::WriteParcelable(const Parcelable *object)
{
    (void) object;
    return false;
}


template <typename T>
bool Parcel::Read(T &value)
{
    return false;
}

template <typename T>
T Parcel::Read()
{
    T lvalue {};
    return Read<T>(lvalue) ? lvalue : 0;
}

bool Parcel::ParseFrom(uintptr_t data, size_t size)
{
    (void) data;
    (void) size;
    return false;
}

const uint8_t *Parcel::ReadBuffer(size_t length)
{
    (void) length;
    return nullptr;
}

const uint8_t *Parcel::ReadUnpadBuffer(size_t length)
{
    (void) length;
    return nullptr;
}

size_t Parcel::GetReadPosition()
{
    return 0;
}

int32_t Parcel::ReadInt32()
{
    return Read<int32_t>();
}

uint32_t Parcel::ReadUint32()
{
    return Read<uint32_t>();
}
}  // namespace OHOS
