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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_BUFFER_IO_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_BUFFER_IO_H

#include <vector>
#include <string>
#include <cstring>
#include <memory>

#include "XMP_Environment.h"
#include "XMP_Const.h"
#include "XMP_IO.hpp"
#include "XMP.hpp"
#include "XMP.incl_cpp"

namespace OHOS {
namespace Media {

// =================================================================================================
/// @brief XMPBuffer_IO - Memory buffer I/O implementation for XMP SDK
///
/// This class implements the XMP_IO interface to allow XMP SDK to work with
/// pre-loaded file data instead of file paths. This enables reading and writing
/// XMP metadata from/to memory buffers.
// =================================================================================================

class XMPBuffer_IO : public XMP_IO {
public:
    // ---------------------------------------------------------------------------------------------
    /// @brief Constructor for read-only memory stream
    ///
    /// Creates a read-only XMPBuffer_IO object from existing memory data.
    ///
    /// @param buffer Pointer to the memory buffer containing file data
    /// @param size Size of the memory buffer in bytes

    XMPBuffer_IO(const void* buffer, XMP_Uns32 size);

    // ---------------------------------------------------------------------------------------------
    /// @brief Constructor for writable memory stream
    ///
    /// Creates a writable XMPBuffer_IO object that can be used for writing XMP data.

    XMPBuffer_IO();

    virtual ~XMPBuffer_IO();

    // XMP_IO interface implementation
    virtual XMP_Uns32 Read(void* buffer, XMP_Uns32 count, bool readAll = false) override;
    virtual void Write(const void* buffer, XMP_Uns32 count) override;
    virtual XMP_Int64 Seek(XMP_Int64 offset, SeekMode mode) override;
    virtual XMP_Int64 Length() override;
    virtual void Truncate(XMP_Int64 length) override;
    virtual XMP_IO* DeriveTemp() override;
    virtual void AbsorbTemp() override;
    virtual void DeleteTemp() override;

    // ---------------------------------------------------------------------------------------------
    /// @brief Get the current data as a vector
    ///
    /// Returns a copy of the current data in the stream.
    ///
    /// @return Vector containing the stream data

    std::vector<XMP_Uns8> GetData() const;

    // ---------------------------------------------------------------------------------------------
    /// @brief Get pointer to the data buffer
    ///
    /// Returns a pointer to the internal data buffer.
    ///
    /// @return Pointer to the data buffer

    const void* GetDataPtr() const;

    // ---------------------------------------------------------------------------------------------
    /// @brief Get the size of the data
    ///
    /// Returns the current size of the data in the stream.
    ///
    /// @return Size of the data in bytes

    XMP_Uns32 GetDataSize() const;

private:
    std::vector<XMP_Uns8>   data;           // Internal data storage
    XMP_Int64               position;       // Current read/write position
    bool                    readOnly;       // Whether this stream is read-only
    XMP_IO*                 derivedTemp;    // Associated temporary stream

    // The copy constructor and assignment operators are private to prevent client use
    XMPBuffer_IO(const XMPBuffer_IO& original);
    void operator=(const XMP_IO& in);
    void operator=(const XMPBuffer_IO& in);
};

} // namespace Media
} // namespace OHOS

#endif	// FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_BUFFER_IO_H
