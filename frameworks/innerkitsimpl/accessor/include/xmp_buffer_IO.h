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

namespace {
    static constexpr XMP_Uns32 XMP_UNS32_ERROR = 0;
    static constexpr XMP_Int64 XMP_INT64_ERROR = -1;
}

// =================================================================================================
/// @brief XMPBuffer_IO - Memory buffer I/O implementation for XMP SDK
///
/// This class implements the XMP_IO interface to allow XMP SDK to work with
/// pre-loaded file data instead of file paths. This enables reading and writing
/// XMP metadata from/to memory buffers.
// =================================================================================================

class XMPBuffer_IO : public XMP_IO {
public:
    XMPBuffer_IO(const void* buffer, XMP_Uns32 size);

    XMPBuffer_IO();

    virtual ~XMPBuffer_IO();

    virtual XMP_Uns32 Read(void* buffer, XMP_Uns32 count, bool readAll = false) override;
    virtual void Write(const void* buffer, XMP_Uns32 count) override;
    virtual XMP_Int64 Seek(XMP_Int64 offset, SeekMode mode) override;
    virtual XMP_Int64 Length() override;
    virtual void Truncate(XMP_Int64 length) override;
    virtual XMP_IO* DeriveTemp() override;
    virtual void AbsorbTemp() override;
    virtual void DeleteTemp() override;

    std::vector<XMP_Uns8> GetData() const;
    const void* GetDataPtr() const;
    XMP_Uns32 GetDataSize() const;

private:
    std::vector<XMP_Uns8> data_;
    XMP_Int64 position_;
    bool readOnly_;
    XMP_IO* derivedTemp_;

    XMPBuffer_IO(const XMPBuffer_IO& original);
    void operator=(const XMP_IO& in);
    void operator=(const XMPBuffer_IO& in);
};

} // namespace Media
} // namespace OHOS

#endif	// FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_BUFFER_IO_H
