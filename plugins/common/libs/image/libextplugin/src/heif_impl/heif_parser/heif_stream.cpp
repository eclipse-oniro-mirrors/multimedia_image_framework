/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "heif_stream.h"
#include "heif_constant.h"
#include "securec.h"

#include <sstream>

const uint8_t BUFFER_INDEX_FOUR = 4;
const uint8_t BUFFER_INDEX_FIVE = 5;
const uint8_t BUFFER_INDEX_SIX = 6;
const uint8_t BUFFER_INDEX_SEVEN = 7;

namespace OHOS {
namespace ImagePlugin {
HeifBufferInputStream::HeifBufferInputStream(const uint8_t *data, size_t size, bool needCopy)
    : length_(size), pos_(0), copied_(needCopy)
{
    if (needCopy) {
        auto *copiedData = new uint8_t[length_];
        memcpy_s(copiedData, length_, data, length_);
        data_ = copiedData;
    } else {
        data_ = data;
    }
}

HeifBufferInputStream::~HeifBufferInputStream()
{
    if (copied_) {
        delete[] data_;
    }
}

int64_t HeifBufferInputStream::Tell() const
{
    return pos_;
}

bool HeifBufferInputStream::CheckSize(size_t target_size, int64_t end)
{
    auto posAfterRead = Tell() + static_cast<int64_t>(target_size);
    return (end < 0 || posAfterRead <= end) && static_cast<size_t>(posAfterRead) <= length_;
}

bool HeifBufferInputStream::Read(void *data, size_t size)
{
    auto end_pos = static_cast<int64_t>(pos_ + size);
    if (static_cast<size_t>(end_pos) > length_) {
        return false;
    }

    memcpy_s(data, size, &data_[pos_], size);
    pos_ = pos_ + static_cast<int64_t>(size);

    return true;
}

bool HeifBufferInputStream::Seek(int64_t position)
{
    if (static_cast<size_t>(position) > length_ || position < 0)
        return false;

    pos_ = position;
    return true;
}

HeifStreamReader::HeifStreamReader(std::shared_ptr<HeifInputStream> stream, int64_t start, size_t length)
    : inputStream_(std::move(stream)), start_(start)
{
    end_ = start_ + static_cast<int64_t>(length);
}

uint8_t HeifStreamReader::Read8()
{
    if (!CheckSize(UINT8_BYTES_NUM)) {
        return 0;
    }
    uint8_t buf;
    auto stream = GetStream();
    bool success = stream->Read(&buf, UINT8_BYTES_NUM);
    if (!success) {
        SetError(true);
        return 0;
    }
    return buf;
}

uint16_t HeifStreamReader::Read16()
{
    if (!CheckSize(UINT16_BYTES_NUM)) {
        return 0;
    }
    uint8_t buf[UINT16_BYTES_NUM];
    auto stream = GetStream();
    bool success = stream->Read(buf, UINT16_BYTES_NUM);
    if (!success) {
        SetError(true);
        return 0;
    }
    return static_cast<uint16_t>((buf[BUFFER_INDEX_ZERO] << ONE_BYTE_SHIFT) | (buf[BUFFER_INDEX_ONE]));
}

uint32_t HeifStreamReader::Read32()
{
    if (!CheckSize(UINT32_BYTES_NUM)) {
        return 0;
    }
    uint8_t buf[UINT32_BYTES_NUM];
    auto stream = GetStream();
    bool success = stream->Read(buf, UINT32_BYTES_NUM);
    if (!success) {
        SetError(true);
        return 0;
    }
    return static_cast<uint32_t>((buf[BUFFER_INDEX_ZERO] << THREE_BYTES_SHIFT) |
        (buf[BUFFER_INDEX_ONE] << TWO_BYTES_SHIFT) |
        (buf[BUFFER_INDEX_TWO] << ONE_BYTE_SHIFT) |
        (buf[BUFFER_INDEX_THREE]));
}

uint64_t HeifStreamReader::Read64()
{
    if (!CheckSize(UINT64_BYTES_NUM)) {
        return 0;
    }
    uint8_t buf[UINT64_BYTES_NUM];
    auto stream = GetStream();
    bool success = stream->Read(buf, UINT64_BYTES_NUM);
    if (!success) {
        SetError(true);
        return 0;
    }
    return static_cast<uint64_t>(((uint64_t)buf[BUFFER_INDEX_ZERO] << SEVEN_BYTES_SHIFT) |
        ((uint64_t)buf[BUFFER_INDEX_ONE] << SIX_BYTES_SHIFT) |
        ((uint64_t)buf[BUFFER_INDEX_TWO] << FIVE_BYTES_SHIFT) |
        ((uint64_t)buf[BUFFER_INDEX_THREE] << FOUR_BYTES_SHIFT) |
        ((uint64_t)buf[BUFFER_INDEX_FOUR] << THREE_BYTES_SHIFT) |
        ((uint64_t)buf[BUFFER_INDEX_FIVE] << TWO_BYTES_SHIFT) |
        ((uint64_t)buf[BUFFER_INDEX_SIX] << ONE_BYTE_SHIFT) |
        ((uint64_t)buf[BUFFER_INDEX_SEVEN]));
}

bool HeifStreamReader::ReadData(uint8_t *data, size_t size)
{
    if (!CheckSize(size)) {
        return false;
    }
    bool res = GetStream()->Read(data, size);
    if (!res) {
        SetError(true);
    }
    return res;
}

std::string HeifStreamReader::ReadString()
{
    if (IsAtEnd()) {
        return {};
    }
    std::stringstream strStream;
    auto stream = GetStream();
    char strChar = UINT8_BYTES_NUM;
    while (strChar != 0) {
        if (!CheckSize(UINT8_BYTES_NUM)) {
            return {};
        }
        bool res = stream->Read(&strChar, UINT8_BYTES_NUM);
        if (!res) {
            SetError(true);
            return {};
        }
        if (strChar != 0) {
            strStream << strChar;
        }
    }
    return strStream.str();
}

bool HeifStreamReader::CheckSize(size_t size)
{
    bool res = inputStream_->CheckSize(size, end_);
    if (!res) {
        SetError(true);
    }
    return res;
}

void HeifStreamWriter::CheckSize(size_t size)
{
    size_t posAfterMove = position_ + size;
    if (posAfterMove > data_.size()) {
        data_.resize(posAfterMove);
    }
}

void HeifStreamWriter::Write8(uint8_t value)
{
    if (position_ == data_.size()) {
        data_.push_back(value);
        position_++;
    } else {
        data_[position_++] = value;
    }
}

void HeifStreamWriter::Write16(uint16_t value)
{
    CheckSize(UINT16_BYTES_NUM);
    data_[position_++] = uint8_t((value >> ONE_BYTE_SHIFT) & 0xFF);
    data_[position_++] = uint8_t(value & 0xFF);
}

void HeifStreamWriter::Write32(uint32_t value)
{
    CheckSize(UINT32_BYTES_NUM);
    data_[position_++] = uint8_t((value >> THREE_BYTES_SHIFT) & 0xFF);
    data_[position_++] = uint8_t((value >> TWO_BYTES_SHIFT) & 0xFF);
    data_[position_++] = uint8_t((value >> ONE_BYTE_SHIFT) & 0xFF);
    data_[position_++] = uint8_t(value & 0xFF);
}

void HeifStreamWriter::Write64(uint64_t value)
{
    CheckSize(UINT64_BYTES_NUM);
    data_[position_++] = uint8_t((value >> SEVEN_BYTES_SHIFT) & 0xFF);
    data_[position_++] = uint8_t((value >> SIX_BYTES_SHIFT) & 0xFF);
    data_[position_++] = uint8_t((value >> FIVE_BYTES_SHIFT) & 0xFF);
    data_[position_++] = uint8_t((value >> FOUR_BYTES_SHIFT) & 0xFF);
    data_[position_++] = uint8_t((value >> THREE_BYTES_SHIFT) & 0xFF);
    data_[position_++] = uint8_t((value >> TWO_BYTES_SHIFT) & 0xFF);
    data_[position_++] = uint8_t((value >> ONE_BYTE_SHIFT) & 0xFF);
    data_[position_++] = uint8_t(value & 0xFF);
}

void HeifStreamWriter::Write(int size, uint64_t value)
{
    switch (size) {
        case UINT8_BYTES_NUM: {
            Write8((uint8_t) value);
            break;
        }
        case UINT16_BYTES_NUM: {
            Write16((uint16_t) value);
            break;
        }
        case UINT32_BYTES_NUM: {
            Write32((uint32_t) value);
            break;
        }
        case UINT64_BYTES_NUM:
            Write64((uint64_t) value);
            break;
        default:
            break;
    }
}

void HeifStreamWriter::Write(const std::string &str)
{
    CheckSize(str.size() + UINT8_BYTES_NUM);
    for (char ch : str) {
        data_[position_++] = ch;
    }
    data_[position_++] = 0;
}

void HeifStreamWriter::Write(const std::vector<uint8_t> &data)
{
    CheckSize(data.size());
    memcpy_s(data_.data() + position_, data_.size() - position_, data.data(), data.size());
    position_ += data.size();
}

void HeifStreamWriter::Skip(size_t skipSize)
{
    CheckSize(skipSize);
    position_ += skipSize;
}

void HeifStreamWriter::Insert(size_t insertSize)
{
    if (insertSize == 0) {
        return;
    }
    size_t sizeToMove = data_.size() - position_;
    void *pCurrent = data_.data() + position_;
    void *pAfterMove = (uint8_t *)pCurrent + insertSize;
    data_.resize(data_.size() + insertSize);
    memmove_s(pAfterMove, sizeToMove, pCurrent, sizeToMove);
}
} // namespace ImagePlugin
} // namespace OHOS
