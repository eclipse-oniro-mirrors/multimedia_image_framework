/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "image_log.h"
#include "xmp_buffer_IO.h"

#include <algorithm>
#include <cstring>
#include <securec.h>
#include <stdexcept>

namespace OHOS {
namespace Media {

XMPBuffer_IO::XMPBuffer_IO(const void* buffer, XMP_Uns32 size) : position_(0), readOnly_(true), derivedTemp_(nullptr)
{
    CHECK_ERROR_RETURN_LOG(buffer == nullptr || size == 0, "%{public}s invalid buffer or size", __func__);

    data_.resize(size);
    memcpy_s(data_.data(), size, buffer, size);
}

XMPBuffer_IO::XMPBuffer_IO() : position_(0), readOnly_(false), derivedTemp_(nullptr)
{
    data_.clear();
}

XMPBuffer_IO::~XMPBuffer_IO()
{
    if (derivedTemp_ != nullptr) {
        delete derivedTemp_;
        derivedTemp_ = nullptr;
    }
}

XMP_Uns32 XMPBuffer_IO::Read(void* buffer, XMP_Uns32 count, bool readAll)
{
    CHECK_ERROR_RETURN_RET_LOG(buffer == nullptr, XMP_UNS32_ERROR, "XMPBuffer_IO Read buffer is null");

    if (position_ >= static_cast<XMP_Int64>(data_.size())) {
        CHECK_ERROR_RETURN_RET_LOG(readAll, XMP_UNS32_ERROR, "XMPBuffer_IO Read data is not enough");
        return XMP_UNS32_ERROR;
    }

    XMP_Uns32 available = static_cast<XMP_Uns32>(data_.size() - position_);
    XMP_Uns32 toRead = (count > available) ? available : count;

    if (toRead == 0) {
        CHECK_ERROR_RETURN_RET_LOG(readAll, XMP_UNS32_ERROR, "XMPBuffer_IO Read data is not enough");
        return XMP_UNS32_ERROR;
    }

    memcpy_s(buffer, toRead, &data_[position_], toRead);
    position_ += toRead;
    return toRead;
}

void XMPBuffer_IO::Write(const void* buffer, XMP_Uns32 count)
{
    CHECK_ERROR_RETURN_LOG(readOnly_, "XMPBuffer_IO Write on read-only stream is not permitted");
    CHECK_ERROR_RETURN_LOG(buffer == nullptr, "XMPBuffer_IO Write buffer is null ");

    XMP_Int64 newSize = position_ + count;
    if (newSize > static_cast<XMP_Int64>(data_.size())) {
        data_.resize(static_cast<size_t>(newSize));
    }

    memcpy_s(&data_[position_], count, buffer, count);
    position_ += count;
}

XMP_Int64 XMPBuffer_IO::Seek(XMP_Int64 offset, SeekMode mode)
{
    XMP_Int64 newPosition = position_;

    switch (mode) {
        case kXMP_SeekFromStart:
            newPosition = offset;
            break;
        case kXMP_SeekFromCurrent:
            newPosition = position_ + offset;
            break;
        case kXMP_SeekFromEnd:
            newPosition = static_cast<XMP_Int64>(data_.size()) + offset;
            break;
        default:
            IMAGE_LOGE("XMPBuffer_IO Seek mode is invalid");
            return XMP_INT64_ERROR;
    }

    CHECK_ERROR_RETURN_RET_LOG(newPosition < 0, XMP_INT64_ERROR, "XMPBuffer_IO Seek position is negative");
    CHECK_ERROR_RETURN_RET_LOG(readOnly_ && newPosition > static_cast<XMP_Int64>(data_.size()), XMP_INT64_ERROR,
        "XMPBuffer_IO Seek beyond EOF is read-only");

    position_ = newPosition;
    return position_;
}

XMP_Int64 XMPBuffer_IO::Length()
{
    return static_cast<XMP_Int64>(data_.size());
}

void XMPBuffer_IO::Truncate(XMP_Int64 length)
{
    CHECK_ERROR_RETURN_LOG(readOnly_, "XMPBuffer_IO::Truncate not permitted on read-only stream");
    CHECK_ERROR_RETURN_LOG(length < 0 || length > static_cast<XMP_Int64>(data_.size()),
        "XMPBuffer_IO Truncate length is invalid");

    data_.resize(static_cast<size_t>(length));
    if (position_ > length) {
        position_ = length;
    }
}

XMP_IO* XMPBuffer_IO::DeriveTemp()
{
    CHECK_ERROR_RETURN_RET_LOG(readOnly_, nullptr, "XMPBuffer_IO DeriveTemp can't derive from read-only stream");

    if (derivedTemp_ != nullptr) {
        return derivedTemp_;
    }

    derivedTemp_ = new XMPBuffer_IO();
    return derivedTemp_;
}

void XMPBuffer_IO::AbsorbTemp()
{
    XMPBuffer_IO* temp = static_cast<XMPBuffer_IO*>(derivedTemp_);
    CHECK_ERROR_RETURN_LOG(temp == nullptr, "XMPBuffer_IO AbsorbTemp no temp to absorb")  ;

    data_ = temp->data_;
    position_ = temp->position_;

    delete temp;
    derivedTemp_ = nullptr;
}

void XMPBuffer_IO::DeleteTemp()
{
    if (derivedTemp_ != nullptr) {
        delete derivedTemp_;
        derivedTemp_ = nullptr;
    }
}

std::vector<XMP_Uns8> XMPBuffer_IO::GetData() const
{
    return data_;
}

const void* XMPBuffer_IO::GetDataPtr() const
{
    return data_.data();
}

XMP_Uns32 XMPBuffer_IO::GetDataSize() const
{
    return static_cast<XMP_Uns32>(data_.size());
}

} // namespace Media
} // namespace OHOS
