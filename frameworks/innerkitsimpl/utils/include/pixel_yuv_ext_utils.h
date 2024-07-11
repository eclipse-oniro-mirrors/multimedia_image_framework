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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_PIXEL_YUV_EXT_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_PIXEL_YUV_EXT_UTILS_H

#include <cstdlib>
#include <cstdio>
#include <string>
#include "image_type.h"
#include "iosfwd"

#include "image_convert_tools.h"
#include "image_converter.h"
#include "pixel_yuv_utils.h"

namespace OHOS {
namespace Media {
class PixelYuvExtUtils {
public:
    static bool BGRAToYuv420(const uint8_t *src, uint8_t *dst, int srcW, int srcH, PixelFormat pixelFormat);
    static bool Yuv420ToBGRA(const uint8_t *sample, uint8_t *dst_argb, Size &size,
                             PixelFormat pixelFormat, YUVDataInfo &info);
    static bool Yuv420ToARGB(const uint8_t *sample, uint8_t *dst_argb, Size &size,
                             PixelFormat pixelFormat, YUVDataInfo &info);
    static bool YuvRotate(uint8_t *srcPixels, Size &size, int32_t degrees,
                          const PixelFormat &format, YUVDataInfo &info);
    static void ConvertYuvMode(OpenSourceLibyuv ::FilterMode &filterMode, const AntiAliasingOption &option);
    static void ScaleYuv420(float xAxis, float yAxis, const AntiAliasingOption &option,
                            YuvImageInfo &yuvInfo, uint8_t *src, uint8_t *dst, uint32_t dstYStride);
    static bool ReversalYuv(uint8_t *src, uint8_t *dst, Size &size, PixelFormat format, YUVDataInfo &info);
    static bool FlipYuv(uint8_t *src, uint8_t *dst, ImageInfo &imageinfo, bool isXaxis, YUVDataInfo &info);
};
} // namespace Media
} // namespace OHOS
#endif // RAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_PIXEL_YUV_EXT_UTILS_H
