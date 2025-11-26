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
#include "xmp_metadata_accessor.h"
#include "xmp_metadata_impl.h"

namespace OHOS {
namespace Media {
XMPMetadataAccessor::XMPMetadataAccessor(const uint8_t *data, size_t size, XMPAccessMode mode)
{
    CHECK_ERROR_RETURN_LOG(!XMPMetadata::Initialize(), "%{public}s failed to init XMPMetadataAccessor", __func__);

    std::unique_ptr<XMPBuffer_IO> bufferIO = std::make_unique<XMPBuffer_IO>(data, static_cast<XMP_Uns32>(size));
    xmpFiles_ = std::unique_ptr<SXMPFiles, XmpFileDeleter>(new SXMPFiles());
    XMP_OptionBits openFlags = ConvertAccessModeToXMPOptions(mode);
    if (!xmpFiles_->OpenFile(bufferIO.get(), kXMP_UnknownFile, openFlags)) {
        IMAGE_LOGE("%{public}s failed to open file with XMPBuffer_IO", __func__);
        return;
    }

    auto impl = std::make_unique<XMPMetadataImpl>();
    CHECK_ERROR_RETURN_LOG(!impl->IsValid(), "%{public}s XMPMetadataImpl is invalid", __func__);
    if (!xmpFiles_->GetXMP(impl->GetRawPtr())) {
        IMAGE_LOGE("%{public}s GetXMP failed", __func__);
        return;
    }

    // Transfer ownership to XMPMetadata
    xmpMetadata_ = std::make_shared<XMPMetadata>(std::move(impl));
    IMAGE_LOGD("%{public}s successfully created XMPMetadataAccessor", __func__);
}

std::shared_ptr<XMPMetadata> XMPMetadataAccessor::Get()
{
    return xmpMetadata_;
}

void XMPMetadataAccessor::Set(std::shared_ptr<XMPMetadata> &xmpMetadata)
{
    xmpMetadata_ = xmpMetadata;
}

XMP_OptionBits XMPMetadataAccessor::ConvertAccessModeToXMPOptions(XMPAccessMode mode)
{
    switch (mode) {
        case XMPAccessMode::READ_ONLY_XMP:
            return kXMPFiles_OpenForRead | kXMPFiles_OpenOnlyXMP;
        case XMPAccessMode::READ_FULL_METADATA:
            return kXMPFiles_OpenForRead;
        case XMPAccessMode::READ_WRITE_XMP:
            return kXMPFiles_OpenForUpdate | kXMPFiles_OpenOnlyXMP;
        case XMPAccessMode::READ_WRITE_XMP_OPTIMIZED:
            return kXMPFiles_OpenForUpdate | kXMPFiles_OptimizeFileLayout;
        default:
            return kXMPFiles_OpenForRead | kXMPFiles_OpenOnlyXMP;
    }
}

} // namespace OHOS
} // namespace Media
