/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "pixelmap_native_impl.h"

#include "pixel_map.h"

using namespace OHOS::Media;
#ifdef __cplusplus
extern "C" {
#endif

OH_PixelmapNative::OH_PixelmapNative(std::shared_ptr<PixelMap> pixelmap)
{
    if (pixelmap == nullptr) {
        pixelmap_ = nullptr;
        return;
    }
    pixelmap_ = pixelmap;
}

OH_PixelmapNative::OH_PixelmapNative(const uint32_t *colors, uint32_t colorLength, const InitializationOptions &opts)
{
    auto tmpPixelmap = PixelMap::Create(colors, colorLength, opts);
    pixelmap_ = std::move(tmpPixelmap);
}

OH_PixelmapNative::OH_PixelmapNative(const InitializationOptions &opts)
{
    auto tmpPixelmap = PixelMap::Create(opts);
    pixelmap_ = std::move(tmpPixelmap);
}

OH_PixelmapNative::OH_PixelmapNative(OH_PixelmapNative *OH_PixelmapNative, const InitializationOptions &opts)
{
    if (OH_PixelmapNative == nullptr) {
        pixelmap_ = nullptr;
        return;
    }
    auto pixelmapPtr = OH_PixelmapNative->GetInnerPixelmap().get();
    auto tmpPixelmap = PixelMap::Create(*pixelmapPtr, opts);
    pixelmap_ = std::move(tmpPixelmap);
}

std::shared_ptr<OHOS::Media::PixelMap> OH_PixelmapNative::GetInnerPixelmap()
{
    return pixelmap_;
}

OH_PixelmapNative::~OH_PixelmapNative()
{
    if (pixelmap_) {
        pixelmap_ = nullptr;
    }
}

#ifdef __cplusplus
};
#endif

// }
// }