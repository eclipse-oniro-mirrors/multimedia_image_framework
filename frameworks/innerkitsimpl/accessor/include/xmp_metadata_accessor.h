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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_METADATA_ACCESSOR_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_METADATA_ACCESSOR_H

#include "metadata_stream.h"
#include "xmp_metadata.h"
#include "XMP.hpp"
#include "XMP.incl_cpp"

namespace OHOS {
namespace Media {
class XMPBuffer_IO;

enum class XMPAccessMode {
    READ_ONLY_XMP,
    READ_FULL_METADATA,
    READ_WRITE_XMP,
    READ_WRITE_XMP_OPTIMIZED,
};

class XMPMetadataAccessor {
public:
    XMPMetadataAccessor(std::shared_ptr<MetadataStream> &stream, XMPAccessMode mode);
    ~XMPMetadataAccessor() = default;

    uint32_t Read();
    uint32_t Write();
    std::shared_ptr<XMPMetadata> Get();
    void Set(std::shared_ptr<XMPMetadata> &xmpMetadata);

private:
    uint32_t CheckXMPFiles();
    void InitializeFromStream();
    uint32_t UpdateData(const uint8_t *dataBlob, uint32_t size);

    struct XmpFileDeleter {
        void operator()(SXMPFiles *ptr) const
        {
            CHECK_ERROR_RETURN_LOG(ptr == nullptr, "XMPFiles delete failed because ptr is nullptr");
            ptr->CloseFile();
            delete ptr;
        }
    };

    std::unique_ptr<SXMPFiles, XmpFileDeleter> xmpFiles_ = nullptr;
    std::shared_ptr<XMPMetadata> xmpMetadata_ = nullptr;
    std::shared_ptr<XMPBuffer_IO> bufferIO_ = nullptr;
    std::shared_ptr<MetadataStream> imageStream_ = nullptr;  // Stream for file I/O
    XMPAccessMode accessMode_ = XMPAccessMode::READ_ONLY_XMP;  // Access mode for XMP operations
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_METADATA_ACCESSOR_H
