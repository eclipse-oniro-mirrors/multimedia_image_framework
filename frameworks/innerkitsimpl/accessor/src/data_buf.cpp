/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <array>
#include <cctype>
#include <climits>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <utility>

#include "image_log.h"
#include "data_buf.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "DataBuffer"

namespace OHOS {
namespace Media {
const uint32_t BYTE_1_MASK = 0x000000ffU;
const uint32_t BYTE_2_MASK = 0x0000ff00U;
const uint32_t BYTE_3_MASK = 0x00ff0000U;
const uint32_t BYTE_4_MASK = 0xff000000U;

const uint32_t BYTE_1_SHIFT = 0;
const uint32_t BYTE_2_SHIFT = 8;
const uint32_t BYTE_3_SHIFT = 16;
const uint32_t BYTE_4_SHIFT = 24;

const uint32_t BYTE_1_POSITION = 0;
const uint32_t BYTE_2_POSITION = 1;
const uint32_t BYTE_3_POSITION = 2;
const uint32_t BYTE_4_POSITION = 3;

const size_t UINT32_SIZE = 4;

const uint16_t LOWER_BYTE_MASK = 0x00ffU;
const uint16_t UPPER_BYTE_MASK = 0xff00U;

DataBuf::DataBuf(size_t size) : pData_(size) {}

DataBuf::DataBuf(const byte *pData, size_t size) : pData_(size)
{
    std::copy_n(pData, size, pData_.begin());
}

void DataBuf::Resize(size_t size)
{
    pData_.resize(size);
}

void DataBuf::Reset()
{
    pData_.clear();
}

uint8_t DataBuf::ReadUInt8(size_t offset) const
{
    if (offset >= pData_.size()) {
        IMAGE_LOGE("Attempted to read beyond the buffer size while reading an 8-bit unsigned integer. "
            "Offset: %{public}zu, Buffer size: %{public}zu",
            offset, pData_.size());
        return 0;
    }
    return pData_[offset];
}

void DataBuf::WriteUInt8(size_t offset, uint8_t value)
{
    if (offset >= pData_.size()) {
        IMAGE_LOGE("Attempted to write beyond the buffer size while writing an 8-bit unsigned integer. "
            "Offset: %{public}zu, Buffer size: %{public}zu",
            offset, pData_.size());
        return;
    }
    pData_[offset] = value;
}

void DataBuf::WriteUInt32(size_t offset, uint32_t x, ByteOrder byteOrder)
{
    if (pData_.size() < UINT32_SIZE || offset > (pData_.size() - UINT32_SIZE)) {
        IMAGE_LOGE("Attempted to write beyond the buffer size while writing a 32-bit unsigned integer. "
            "Offset: %{public}zu, Buffer size: %{public}zu",
            offset, pData_.size());
        return;
    }
    UL2Data(&pData_[offset], x, byteOrder);
}

uint32_t DataBuf::ReadUInt32(size_t offset, ByteOrder byteOrder)
{
    if (pData_.size() < UINT32_SIZE || offset > (pData_.size() - UINT32_SIZE)) {
        IMAGE_LOGE("Attempted to read beyond the buffer size while reading a 32-bit unsigned integer. "
            "Offset: %{public}zu, Buffer size: %{public}zu",
            offset, pData_.size());
        return 0;
    }
    return GetULong(&pData_[offset], byteOrder);
}

int DataBuf::CmpBytes(size_t offset, const void *buf, size_t bufsize) const
{
    if (pData_.size() < bufsize || offset > pData_.size() - bufsize) {
        IMAGE_LOGE("Attempted to compare bytes beyond the buffer size. "
            "Offset: %{public}zu, Buffer size: %{public}zu, Compare size: %{public}zu",
            offset, pData_.size(), bufsize);
        return -1;
    }
    return memcmp(&pData_[offset], buf, bufsize);
}

byte *DataBuf::Data(size_t offset)
{
    return const_cast<byte *>(CData(offset));
}

const byte *DataBuf::CData(size_t offset) const
{
    if (pData_.empty() || offset == pData_.size()) {
        return nullptr;
    }
    if (offset > pData_.size()) {
        IMAGE_LOGE("Attempted to access beyond the buffer size. "
            "Offset: %{public}zu, Buffer size: %{public}zu",
            offset, pData_.size());
        return nullptr;
    }
    return &pData_[offset];
}

uint16_t GetUShort(const byte *buf, ByteOrder byteOrder)
{
    if (byteOrder == littleEndian) {
        return static_cast<byte>(buf[1]) << DATA_BUF_BYTE_SIZE | static_cast<byte>(buf[0]);
    }
    return static_cast<byte>(buf[0]) << DATA_BUF_BYTE_SIZE | static_cast<byte>(buf[1]);
}

void US2Data(byte *buf, uint16_t value, ByteOrder byteOrder)
{
    if (byteOrder == littleEndian) {
        buf[0] = static_cast<byte>(value & LOWER_BYTE_MASK);
        buf[1] = static_cast<byte>((value & UPPER_BYTE_MASK) >> DATA_BUF_BYTE_SIZE);
    } else {
        buf[0] = static_cast<byte>((value & UPPER_BYTE_MASK) >> DATA_BUF_BYTE_SIZE);
        buf[1] = static_cast<byte>(value & LOWER_BYTE_MASK);
    }
}

size_t UL2Data(byte *buf, uint32_t l, ByteOrder byteOrder)
{
    if (byteOrder == littleEndian) {
        buf[BYTE_1_POSITION] = static_cast<byte>(l & BYTE_1_MASK);
        buf[BYTE_2_POSITION] = static_cast<byte>((l & BYTE_2_MASK) >> BYTE_2_SHIFT);
        buf[BYTE_3_POSITION] = static_cast<byte>((l & BYTE_3_MASK) >> BYTE_3_SHIFT);
        buf[BYTE_4_POSITION] = static_cast<byte>((l & BYTE_4_MASK) >> BYTE_4_SHIFT);
    } else {
        buf[BYTE_1_POSITION] = static_cast<byte>((l & BYTE_4_MASK) >> BYTE_4_SHIFT);
        buf[BYTE_2_POSITION] = static_cast<byte>((l & BYTE_3_MASK) >> BYTE_3_SHIFT);
        buf[BYTE_3_POSITION] = static_cast<byte>((l & BYTE_2_MASK) >> BYTE_2_SHIFT);
        buf[BYTE_4_POSITION] = static_cast<byte>(l & BYTE_1_MASK);
    }
    return UINT32_SIZE;
}

uint32_t GetULong(const byte *buf, ByteOrder byteOrder)
{
    if (byteOrder == littleEndian) {
        return (buf[BYTE_4_POSITION] << BYTE_4_SHIFT) | (buf[BYTE_3_POSITION] << BYTE_3_SHIFT) |
            (buf[BYTE_2_POSITION] << BYTE_2_SHIFT) | (buf[BYTE_1_POSITION] << BYTE_1_SHIFT);
    }
    return (buf[BYTE_1_POSITION] << BYTE_4_SHIFT) | (buf[BYTE_2_POSITION] << BYTE_3_SHIFT) |
        (buf[BYTE_3_POSITION] << BYTE_2_SHIFT) | (buf[BYTE_4_POSITION] << BYTE_1_SHIFT);
}
} // namespace Media
} // namespace OHOS
