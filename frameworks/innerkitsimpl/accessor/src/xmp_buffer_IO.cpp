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
XMPBuffer_IO::XMPBuffer_IO(const void* buffer, XMP_Uns32 size, bool writable)
    : externalData_(static_cast<const XMP_Uns8*>(buffer)), dataSize_(size), position_(0), 
      readOnly_(!writable), isExternalData_(!writable), derivedTemp_(nullptr)
{
    CHECK_ERROR_RETURN_LOG(buffer == nullptr || size == 0, "%{public}s invalid buffer or size", __func__);

    // If writable, copy the data to internal storage
    if (writable) {
        data_.resize(size);
        memcpy_s(data_.data(), size, buffer, size);
        isExternalData_ = false;
    }
}

XMPBuffer_IO::XMPBuffer_IO()
    : externalData_(nullptr), dataSize_(0), position_(0), readOnly_(false), 
      isExternalData_(false), derivedTemp_(nullptr)
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

    XMP_Uns32 currentSize = GetCurrentSize();
    if (position_ >= static_cast<XMP_Int64>(currentSize)) {
        CHECK_ERROR_RETURN_RET_LOG(readAll, XMP_UNS32_ERROR, "XMPBuffer_IO Read data is not enough");
        return XMP_UNS32_ERROR;
    }

    XMP_Uns32 available = static_cast<XMP_Uns32>(currentSize - position_);
    XMP_Uns32 toRead = (count > available) ? available : count;

    if (toRead == 0) {
        CHECK_ERROR_RETURN_RET_LOG(readAll, XMP_UNS32_ERROR, "XMPBuffer_IO Read data is not enough");
        return XMP_UNS32_ERROR;
    }

    const XMP_Uns8* dataPtr = GetCurrentDataPtr();
    memcpy_s(buffer, toRead, &dataPtr[position_], toRead);
    position_ += toRead;
    return toRead;
}

void XMPBuffer_IO::Write(const void* buffer, XMP_Uns32 count)
{
    CHECK_ERROR_RETURN_LOG(readOnly_, "XMPBuffer_IO Write on read-only stream is not permitted");
    CHECK_ERROR_RETURN_LOG(buffer == nullptr, "XMPBuffer_IO Write buffer is null ");

    // Trigger COW to ensure data ownership
    EnsureOwnedData();

    XMP_Int64 newSize = position_ + count;
    if (newSize > static_cast<XMP_Int64>(data_.size())) {
        data_.resize(static_cast<size_t>(newSize));
        dataSize_ = static_cast<XMP_Uns32>(data_.size());
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
            newPosition = static_cast<XMP_Int64>(GetCurrentSize()) + offset;
            break;
        default:
            IMAGE_LOGE("XMPBuffer_IO Seek mode is invalid");
            return XMP_INT64_ERROR;
    }

    CHECK_ERROR_RETURN_RET_LOG(newPosition < 0, XMP_INT64_ERROR, "XMPBuffer_IO Seek position is negative");
    CHECK_ERROR_RETURN_RET_LOG(readOnly_ && newPosition > static_cast<XMP_Int64>(GetCurrentSize()), XMP_INT64_ERROR,
        "XMPBuffer_IO Seek beyond EOF is read-only");

    position_ = newPosition;
    return position_;
}

XMP_Int64 XMPBuffer_IO::Length()
{
    return static_cast<XMP_Int64>(GetCurrentSize());
}

void XMPBuffer_IO::Truncate(XMP_Int64 length)
{
    CHECK_ERROR_RETURN_LOG(readOnly_, "XMPBuffer_IO::Truncate not permitted on read-only stream");
    CHECK_ERROR_RETURN_LOG(length < 0 || length > static_cast<XMP_Int64>(GetCurrentSize()),
        "XMPBuffer_IO Truncate length is invalid");

    // Trigger COW to ensure data ownership
    EnsureOwnedData();
    
    data_.resize(static_cast<size_t>(length));
    dataSize_ = static_cast<XMP_Uns32>(data_.size());
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

const void* XMPBuffer_IO::GetDataPtr() const
{
    return GetCurrentDataPtr();
}

XMP_Uns32 XMPBuffer_IO::GetDataSize() const
{
    return GetCurrentSize();
}

void XMPBuffer_IO::EnsureOwnedData()
{
    if (isExternalData_) {
        // COW: Copy external data to internal storage
        data_.resize(dataSize_);
        memcpy_s(data_.data(), dataSize_, externalData_, dataSize_);
        isExternalData_ = false;
        externalData_ = nullptr;
    }
}

const XMP_Uns8* XMPBuffer_IO::GetCurrentDataPtr() const
{
    return isExternalData_ ? externalData_ : data_.data();
}

XMP_Uns32 XMPBuffer_IO::GetCurrentSize() const
{
    return isExternalData_ ? dataSize_ : static_cast<XMP_Uns32>(data_.size());
}

} // namespace Media
} // namespace OHOS
