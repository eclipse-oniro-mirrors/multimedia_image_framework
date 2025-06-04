/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "metadata_impl.h"

#include "image_log.h"

namespace OHOS {
namespace Media {
MetadataImpl::MetadataImpl(std::shared_ptr<ImageMetadata> metadata)
{
    static std::atomic<uint32_t> currentId = 0;
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
    nativeMetadata_ = metadata;
}

MetadataImpl::~MetadataImpl()
{
    release();
}

void MetadataImpl::release()
{
    if (!isRelease) {
        nativeMetadata_ = nullptr;
        isRelease = true;
    }
}

std::vector<std::pair<std::string, std::string>> MetadataImpl::GetAllProperties(uint32_t* errCode)
{
    std::vector<std::pair<std::string, std::string>> propertiesArray;
    if (nativeMetadata_ == nullptr) {
        IMAGE_LOGE("Empty native rMetadata");
        return propertiesArray;
    }
    ImageMetadata::PropertyMapPtr allKey = nativeMetadata_->GetAllProperties();
    for (const auto& entry : *allKey) {
        propertiesArray.emplace_back(std::make_pair(entry.first, entry.second));
    }
    return propertiesArray;
}
} // namespace Media
} // namespace OHOS