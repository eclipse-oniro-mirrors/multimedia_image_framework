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
#include "xmp_metadata.h"


namespace OHOS {
namespace Media {
bool XMPMetadata::xmpInitialized_ = false;

XMPMetadata::XMPMetadata()
{
    if (!Initialize()) {
        IMAGE_LOGE("%{public}s failed to initialize XMP Metadata", __func__);
        return;
    }

    xmpMeta_ = std::make_shared<SXMPMeta>();
}

XMPMetadata::XMPMetadata(std::shared_ptr<SXMPMeta> &xmpMeta)
{
    if (!Initialize()) {
        IMAGE_LOGE("%{public}s failed to initialize XMP Metadata", __func__);
        return;
    }

    xmpMeta_ = xmpMeta;
}

XMPMetadata::~XMPMetadata() {}

bool XMPMetadata::Initialize()
{
    if (xmpInitialized_) {
        return true;
    }
    CHECK_ERROR_RETURN_RET_LOG(!SXMPFiles::Initialize(kXMPFiles_IgnoreLocalText), false,
        "%{public}s failed to initialize XMPFiles", __func__);
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::Initialize(), false, "%{public}s failed to initialize XMPMeta", __func__);
    xmpInitialized_ = true;
    return true;
}

void XMPMetadata::Terminate()
{
    if (xmpInitialized_) {
        SXMPMeta::Terminate();
        SXMPFiles::Terminate();
        xmpInitialized_ = false;
    }
}

bool XMPMetadata::RegisterNamespacePrefix(const std::string& uri, const std::string& prefix)
{
    std::string placeholder;
    bool isURIRegistered = SXMPMeta::GetNamespacePrefix(uri.c_str(), &placeholder);
    if (isURIRegistered) {
        IMAGE_LOGI("%{public}s namespace already registered", __func__);
        return false;
    }

    bool isPrefixRegistered = SXMPMeta::GetNamespaceURI(prefix.c_str(), &placeholder);
    if (isPrefixRegistered) {
        IMAGE_LOGI("%{public}s prefix already registered", __func__);
        return false;
    }
    return SXMPMeta::RegisterNamespace(uri.c_str(), prefix.c_str(), &placeholder);
}

} // namespace Media
} // namespace OHOS