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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_XMP_BUFFER_IO_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_XMP_BUFFER_IO_H

#include "XMP_Environment.h"    // ! XMP_Environment.h must be the first included header.
#include "XMP_Const.h"
#include "public/include/XMP_IO.hpp"

#include "nocopyable.h"

#include <string>
#include <vector>

namespace OHOS {
namespace Media {

// =================================================================================================
/// @brief XMPBuffer_IO - Memory buffer I/O implementation for XMP SDK
///
/// Implementation class for I/O using memory buffer data, allows XMP-Toolkit-SDK to work with
/// pre-loaded file data instead of file paths. This is useful when you have already read
/// file data into memory and want to parse XMP metadata from it.
// =================================================================================================
class XMPBuffer_IO : public XMP_IO {
public:
    /// @note When readOnly=true, the buffer pointer is stored directly without copying.
    ///       The caller must ensure the buffer remains valid for the lifetime of this object.
    XMPBuffer_IO(const void *buffer, XMP_Uns32 size, bool readOnly);
    XMPBuffer_IO();

    virtual ~XMPBuffer_IO();

    // XMP_IO interface implementation
    XMP_Uns32 Read(void *buffer, XMP_Uns32 count, bool readAll = false) override;
    void Write(const void *buffer, XMP_Uns32 count) override;
    XMP_Int64 Seek(XMP_Int64 offset, SeekMode mode) override;
    XMP_Int64 Length() override;
    void Truncate(XMP_Int64 length) override;
    XMP_IO *DeriveTemp() override;
    void AbsorbTemp() override;
    void DeleteTemp() override;
    const void *GetDataPtr() const;
    XMP_Uns32 GetDataSize() const { return GetCurrentSize(); }

private:
    std::vector<XMP_Uns8> data;     // Internal data storage
    const XMP_Uns8 *externalData;   // Zero-copy mode external data pointer
    XMP_Uns32 externalDataSize;     // Data size
    XMP_Int64 position;             // Current read/write position
    bool readOnly;                  // Whether this stream is read-only
    bool isExternalData;            // Flag to indicate whether external data is used (zero-copy)
    XMP_IO *derivedTemp;            // Associated temporary stream

    const XMP_Uns8 *GetCurrentDataPtr() const;     // Get current data pointer
    XMP_Uns32 GetCurrentSize() const;              // Get current data size

    XMPBuffer_IO &operator=(const XMP_IO &in) = delete;
    DISALLOW_COPY(XMPBuffer_IO);
};
}  // namespace Media
}  // namespace OHOS
#endif    // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_XMP_BUFFER_IO_H
