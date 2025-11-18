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

// =================================================================================================
// XMPBuffer_IO::XMPBuffer_IO (read-only constructor)
// ==================================================

XMPBuffer_IO::XMPBuffer_IO(const void* buffer, XMP_Uns32 size)
    : position(0)
    , readOnly(true)
    , derivedTemp(nullptr)
{
    CHECK_ERROR_RETURN_LOG(buffer == nullptr || size == 0, "%{public}s invalid buffer or size", __func__);

    data.resize(size);
    memcpy_s(data.data(), size, buffer, size);
}

// =================================================================================================
// XMPBuffer_IO::XMPBuffer_IO (writable constructor)
// ================================================

XMPBuffer_IO::XMPBuffer_IO()
    : position(0)
    , readOnly(false)
    , derivedTemp(nullptr)
{
    // Initialize with empty data
    data.clear();
}

// =================================================================================================
// XMPBuffer_IO::~XMPBuffer_IO
// ===========================

XMPBuffer_IO::~XMPBuffer_IO()
{
    try {
        if (derivedTemp != nullptr) {
            delete derivedTemp;
            derivedTemp = nullptr;
        }
    } catch (...) {
        // All of the above is fail-safe cleanup, ignore problems.
    }
}

// =================================================================================================
// XMPBuffer_IO::Read
// ==================

XMP_Uns32 XMPBuffer_IO::Read(void* buffer, XMP_Uns32 count, bool readAll)
{
    if (buffer == nullptr) {
        throw std::invalid_argument("XMPBuffer_IO::Read: null buffer");
    }
    
    if (position >= static_cast<XMP_Int64>(data.size())) {
        if (readAll) {
            throw std::runtime_error("XMPBuffer_IO::Read: not enough data");
        }
        return 0;
    }

    XMP_Uns32 available = static_cast<XMP_Uns32>(data.size() - position);
    XMP_Uns32 toRead = (count > available) ? available : count;

    if (toRead == 0) {
        if (readAll) {
            throw std::runtime_error("XMPBuffer_IO::Read: not enough data");
        }
        return 0;
    }

    memcpy_s(buffer, toRead, &data[position], toRead);
    position += toRead;
    return toRead;
}

// =================================================================================================
// XMPBuffer_IO::Write
// ===================

void XMPBuffer_IO::Write(const void* buffer, XMP_Uns32 count)
{
    if (readOnly) {
        throw std::runtime_error("XMPBuffer_IO::Write: write not permitted on read-only stream");
    }
    
    if (buffer == nullptr) {
        throw std::invalid_argument("XMPBuffer_IO::Write: null buffer");
    }

    // If current position + write length exceeds current data size, extend data
    XMP_Int64 newSize = position + count;
    if (newSize > static_cast<XMP_Int64>(data.size())) {
        data.resize(static_cast<size_t>(newSize));
    }

    memcpy_s(&data[position], count, buffer, count);
    position += count;
}

// =================================================================================================
// XMPBuffer_IO::Seek
// ==================

XMP_Int64 XMPBuffer_IO::Seek(XMP_Int64 offset, SeekMode mode)
{
    XMP_Int64 newPosition = position;

    switch (mode) {
        case kXMP_SeekFromStart:
            newPosition = offset;
            break;
        case kXMP_SeekFromCurrent:
            newPosition = position + offset;
            break;
        case kXMP_SeekFromEnd:
            newPosition = static_cast<XMP_Int64>(data.size()) + offset;
            break;
        default:
            throw std::invalid_argument("XMPBuffer_IO::Seek: invalid seek mode");
    }

    if (newPosition < 0) {
        throw std::runtime_error("XMPBuffer_IO::Seek: negative position");
    }

    if (readOnly && newPosition > static_cast<XMP_Int64>(data.size())) {
        throw std::runtime_error("XMPBuffer_IO::Seek: read-only seek beyond EOF");
    }

    position = newPosition;
    return position;
}

// =================================================================================================
// XMPBuffer_IO::Length
// ====================

XMP_Int64 XMPBuffer_IO::Length()
{
    return static_cast<XMP_Int64>(data.size());
}

// =================================================================================================
// XMPBuffer_IO::Truncate
// ======================

void XMPBuffer_IO::Truncate(XMP_Int64 length)
{
    if (readOnly) {
        throw std::runtime_error("XMPBuffer_IO::Truncate: truncate not permitted on read-only stream");
    }

    if (length < 0 || length > static_cast<XMP_Int64>(data.size())) {
        throw std::invalid_argument("XMPBuffer_IO::Truncate: invalid length");
    }

    data.resize(static_cast<size_t>(length));
    if (position > length) {
        position = length;
    }
}

// =================================================================================================
// XMPBuffer_IO::DeriveTemp
// ========================

XMP_IO* XMPBuffer_IO::DeriveTemp()
{
    if (readOnly) {
        throw std::runtime_error("XMPBuffer_IO::DeriveTemp: can't derive from read-only stream");
    }
    
    if (derivedTemp != nullptr) {
        return derivedTemp;
    }

    // Create a new temporary memory stream
    derivedTemp = new XMPBuffer_IO();
    return derivedTemp;
}

// =================================================================================================
// XMPBuffer_IO::AbsorbTemp
// ========================

void XMPBuffer_IO::AbsorbTemp()
{
    XMPBuffer_IO* temp = static_cast<XMPBuffer_IO*>(derivedTemp);
    if (temp == nullptr) {
        throw std::runtime_error("XMPBuffer_IO::AbsorbTemp: no temp to absorb");
    }

    // Replace current data with temp data
    data = temp->data;
    position = temp->position;

    // Clean up temp
    delete temp;
    derivedTemp = nullptr;
}

// =================================================================================================
// XMPBuffer_IO::DeleteTemp
// ========================

void XMPBuffer_IO::DeleteTemp()
{
    if (derivedTemp != nullptr) {
        delete derivedTemp;
        derivedTemp = nullptr;
    }
}

// =================================================================================================
// XMPBuffer_IO::GetData
// =====================

std::vector<XMP_Uns8> XMPBuffer_IO::GetData() const
{
    return data;
}

// =================================================================================================
// XMPBuffer_IO::GetDataPtr
// ========================

const void* XMPBuffer_IO::GetDataPtr() const
{
    return data.data();
}

// =================================================================================================
// XMPBuffer_IO::GetDataSize
// =========================

XMP_Uns32 XMPBuffer_IO::GetDataSize() const
{
    return static_cast<XMP_Uns32>(data.size());
}

} // namespace Media
} // namespace OHOS
