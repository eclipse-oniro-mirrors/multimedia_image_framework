/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef IMAGE_PLUGIN_TYPE_H
#define IMAGE_PLUGIN_TYPE_H

#include <cstdint>
#include "image_type.h"

namespace OHOS {
namespace ImagePlugin {

struct PlImageInfo {
    OHOS::Media::Size size;
    OHOS::Media::PixelFormat pixelFormat = OHOS::Media::PixelFormat::UNKNOWN;
    OHOS::Media::ColorSpace colorSpace = OHOS::Media::ColorSpace::UNKNOWN;
    OHOS::Media::AlphaType alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    OHOS::Media::YUVDataInfo yuvDataInfo;
};

struct PlImageBuffer {
    void *buffer = nullptr;
    uint32_t bufferSize = 0;
    uint32_t dataSize = 0;
    void *context = nullptr;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // IMAGE_PLUGIN_TYPE_H
