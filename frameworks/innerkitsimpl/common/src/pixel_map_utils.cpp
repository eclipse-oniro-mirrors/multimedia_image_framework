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

#ifdef IMAGE_PURGEABLE_PIXELMAP

#include "pixel_map_utils.h"

#include <utility>

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelMap"

namespace OHOS {
namespace Media {
// One TLS definition per helper in image_native; consumers must not keep independent callback chains.
thread_local const PixelMapRebuildScope *PixelMapRebuildScope::current_ = nullptr;
thread_local RebuilderReleaseScope *RebuilderReleaseScope::current_ = nullptr;

PixelMapRebuildScope::PixelMapRebuildScope(const PixelMap *pixelMap) : pixelMap_(pixelMap), previous_(current_)
{
    current_ = this;
}

PixelMapRebuildScope::~PixelMapRebuildScope()
{
    current_ = previous_;
}

bool PixelMapRebuildScope::IsRebuilding(const PixelMap *pixelMap)
{
    for (auto scope = current_; scope != nullptr; scope = scope->previous_) {
        if (scope->pixelMap_ == pixelMap) {
            return true;
        }
    }
    return false;
}

RebuilderReleaseScope::RebuilderReleaseScope() : previous_(current_)
{
    current_ = this;
}

RebuilderReleaseScope::~RebuilderReleaseScope()
{
    current_ = previous_;
    if (previous_ != nullptr) {
        for (auto &rebuilder : retired_) {
            previous_->retired_.push_back(std::move(rebuilder));
        }
    }
}

void RebuilderReleaseScope::Retire(std::unique_ptr<PixelMapRebuilder> rebuilder)
{
    if (rebuilder != nullptr && current_ != nullptr) {
        current_->retired_.push_back(std::move(rebuilder));
    }
}

bool CheckPurgeableReentry(const PixelMap *pixelMap, const char *operation)
{
    if (!PixelMapRebuildScope::IsRebuilding(pixelMap)) {
        return false;
    }
    IMAGE_LOGE("%{public}s rejected during rebuild of the same PixelMap, id:%{public}u", operation,
        pixelMap->GetUniqueId());
    return true;
}
} // namespace Media
} // namespace OHOS

#endif // IMAGE_PURGEABLE_PIXELMAP
