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

#include <functional>

#include "image_log.h"
#include "image_mime_type.h"
#include "media_errors.h"
#include "xmpsdk_xmp_metadata_accessor.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "XMPMetadataAccessorFactory"

namespace OHOS {
namespace Media {

static bool IsXMPSdkSupportedMimeType(const std::string &mimeType)
{
    return mimeType == IMAGE_JPEG_FORMAT || mimeType == IMAGE_PNG_FORMAT || mimeType == IMAGE_GIF_FORMAT ||
        mimeType == IMAGE_TIFF_FORMAT || mimeType == IMAGE_DNG_FORMAT;
}

static std::unique_ptr<XMPMetadataAccessor> CreateXMPMetadataAccessor(const std::string &mimeType,
    const std::function<std::unique_ptr<XMPSdkXMPMetadataAccessor>()> &createFunc)
{
    CHECK_ERROR_RETURN_RET_LOG(!IsXMPSdkSupportedMimeType(mimeType), nullptr,
        "%{public}s unsupported mimeType=%{public}s", __func__, mimeType.c_str());

    auto sdkAccessor = createFunc();
    return std::unique_ptr<XMPMetadataAccessor>(sdkAccessor.release());
}

std::unique_ptr<XMPMetadataAccessor> XMPMetadataAccessorFactory::Create(const uint8_t *data, uint32_t size,
    XMPAccessMode mode, const std::string &mimeType)
{
    return CreateXMPMetadataAccessor(mimeType, [data, size, mode, mimeType]() {
        return XMPSdkXMPMetadataAccessor::Create(data, size, mode, mimeType);
    });
}

std::unique_ptr<XMPMetadataAccessor> XMPMetadataAccessorFactory::Create(const std::string &filePath,
    XMPAccessMode mode, const std::string &mimeType)
{
    return CreateXMPMetadataAccessor(mimeType, [filePath, mode, mimeType]() {
        return XMPSdkXMPMetadataAccessor::Create(filePath, mode, mimeType);
    });
}

std::unique_ptr<XMPMetadataAccessor> XMPMetadataAccessorFactory::Create(int32_t fileDescriptor, XMPAccessMode mode,
    const std::string &mimeType)
{
    return CreateXMPMetadataAccessor(mimeType, [fileDescriptor, mode, mimeType]() {
        return XMPSdkXMPMetadataAccessor::Create(fileDescriptor, mode, mimeType);
    });
}
} // namespace Media
} // namespace OHOS
