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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMPSDK_XMP_METADATA_ACCESSOR_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMPSDK_XMP_METADATA_ACCESSOR_H

#include <memory>
#include <mutex>
#include <string>

#include "image_log.h"
#include "xmp_helper.h"
#include "xmp_metadata_accessor.h"
#include "xmp_metadata.h"
#include "XMP.hpp"
#include "XMP.incl_cpp"

class XMPBuffer_IO;
class XMPFd_IO;

namespace OHOS {
namespace Media {

class XMPSdkXMPMetadataAccessor : public XMPMetadataAccessor {
public:
    XMPSdkXMPMetadataAccessor();
    ~XMPSdkXMPMetadataAccessor() override;

    static std::unique_ptr<XMPSdkXMPMetadataAccessor> Create(const uint8_t *data, uint32_t size, XMPAccessMode mode,
        const std::string &mimeType);
    static std::unique_ptr<XMPSdkXMPMetadataAccessor> Create(const std::string &filePath, XMPAccessMode mode,
        const std::string &mimeType);
    static std::unique_ptr<XMPSdkXMPMetadataAccessor> Create(int32_t fileDescriptor, XMPAccessMode mode,
        const std::string &mimeType);

    uint32_t Read() override;
    uint32_t Write() override;

private:
    uint32_t CheckXMPFiles();
    uint32_t InitializeFromBuffer(const uint8_t *data, uint32_t size, XMPAccessMode mode, const std::string &mimeType);
    uint32_t InitializeFromPath(const std::string &filePath, XMPAccessMode mode, const std::string &mimeType);
    uint32_t InitializeFromFd(int32_t fileDescriptor, XMPAccessMode mode, const std::string &mimeType);

    struct XmpFileDeleter {
        void operator()(SXMPFiles *ptr) const
        {
            CHECK_ERROR_RETURN_LOG(ptr == nullptr, "XMPFiles delete failed because ptr is nullptr");
            XMP_TRY();
            ptr->CloseFile();
            delete ptr;
            XMP_CATCH_NO_RETURN();
        }
    };

    static int32_t refCount_;
    static std::mutex initMutex_;
    bool isRefCounted_ = false;
    IOType ioType_ = IOType::UNKNOWN;
    std::unique_ptr<SXMPFiles, XmpFileDeleter> xmpFiles_ = nullptr;
    std::shared_ptr<XMPBuffer_IO> bufferIO_ = nullptr;
    std::shared_ptr<XMPFd_IO> fdIO_ = nullptr;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMPSDK_XMP_METADATA_ACCESSOR_H
