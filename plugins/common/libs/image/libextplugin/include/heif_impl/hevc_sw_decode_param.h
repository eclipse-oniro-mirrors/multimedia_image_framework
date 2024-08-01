/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEVC_SW_DECODE_PARAM_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEVC_SW_DECODE_PARAM_H

#include "hardware/imagecodec/grid_info.h"
#include "image_type.h"

namespace OHOS {
namespace ImagePlugin {
struct HevcSoftDecodeParam {
    GridInfo gridInfo {};
    Media::PixelFormat dstPixFmt = Media::PixelFormat::UNKNOWN;
    uint8_t *dstBuffer = nullptr;
    uint32_t bufferSize = 0;
    uint32_t dstStride = 0;
    void *hwBuffer = nullptr;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif //PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEVC_SW_DECODE_PARAM_H
