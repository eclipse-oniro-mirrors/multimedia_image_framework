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

#include "xmp_metadata_accessor_factory.h"

#include "image_log.h"
#include "image_mime_type.h"
#include "xmpsdk_xmp_metadata_accessor.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "XMPMetadataAccessorFactory"

namespace OHOS {
namespace Media {

namespace {
struct XMPSource {
    XMPMetadataAccessor::IOType ioType = XMPMetadataAccessor::IOType::UNKNOWN;
    const uint8_t *data = nullptr;
    uint32_t size = 0;
    std::string filePath;
    int32_t fd = -1;
};

static bool IsXMPSdkSupportedMimeType(const std::string &mimeType)
{
    return mimeType == IMAGE_JPEG_FORMAT || mimeType == IMAGE_PNG_FORMAT || mimeType == IMAGE_GIF_FORMAT ||
        mimeType == IMAGE_TIFF_FORMAT || mimeType == IMAGE_DNG_FORMAT;
}

static std::unique_ptr<XMPMetadataAccessor> CreateByMimeType(const XMPSource &source, XMPAccessMode mode,
    const std::string &mimeType)
{
    if (IsXMPSdkSupportedMimeType(mimeType)) {
        switch (source.ioType) {
            case XMPMetadataAccessor::IOType::XMP_BUFFER_IO:
                return XMPSdkXMPMetadataAccessor::Create(source.data, source.size, mode, mimeType);
            case XMPMetadataAccessor::IOType::XMP_FILE_PATH:
                return XMPSdkXMPMetadataAccessor::Create(source.filePath, mode, mimeType);
            case XMPMetadataAccessor::IOType::XMP_FD_IO:
                return XMPSdkXMPMetadataAccessor::Create(source.fd, mode, mimeType);
            default:
                return nullptr;
        }
    }

    IMAGE_LOGE("%{public}s unsupported mimeType=%{public}s", __func__, mimeType.c_str());
    return nullptr;
}
} // anonymous namespace

std::unique_ptr<XMPMetadataAccessor> XMPMetadataAccessorFactory::Create(const uint8_t *data, uint32_t size,
    XMPAccessMode mode, const std::string &mimeType)
{
    CHECK_ERROR_RETURN_RET_LOG(data == nullptr || size == 0, nullptr, "%{public}s invalid buffer input", __func__);

    XMPSource source;
    source.ioType = XMPMetadataAccessor::IOType::XMP_BUFFER_IO;
    source.data = data;
    source.size = size;
    return CreateByMimeType(source, mode, mimeType);
}

std::unique_ptr<XMPMetadataAccessor> XMPMetadataAccessorFactory::Create(const std::string &filePath,
    XMPAccessMode mode, const std::string &mimeType)
{
    CHECK_ERROR_RETURN_RET_LOG(filePath.empty(), nullptr, "%{public}s filePath is empty", __func__);

    XMPSource source;
    source.ioType = XMPMetadataAccessor::IOType::XMP_FILE_PATH;
    source.filePath = filePath;
    return CreateByMimeType(source, mode, mimeType);
}

std::unique_ptr<XMPMetadataAccessor> XMPMetadataAccessorFactory::Create(int32_t fileDescriptor, XMPAccessMode mode,
    const std::string &mimeType)
{
    CHECK_ERROR_RETURN_RET_LOG(fileDescriptor < 0, nullptr, "%{public}s fileDescriptor is invalid", __func__);

    XMPSource source;
    source.ioType = XMPMetadataAccessor::IOType::XMP_FD_IO;
    source.fd = fileDescriptor;
    return CreateByMimeType(source, mode, mimeType);
}
} // namespace Media
} // namespace OHOS
