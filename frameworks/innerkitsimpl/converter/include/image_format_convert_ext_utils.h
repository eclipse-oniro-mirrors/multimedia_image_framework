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

#ifndef FRAMEWORKS_INNERKITSIMPL_COMMON_INCLUDE_IMAGE_FORMAT_CONVERT_EXT_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_COMMON_INCLUDE_IMAGE_FORMAT_CONVERT_EXT_UTILS_H

#include <cinttypes>
#include <image_type.h>

namespace OHOS {
namespace Media {
struct I420Info {
    uint32_t width;
    uint32_t height;
    uint8_t *I420Y;
    uint32_t yStride;
    uint8_t *I420U;
    uint32_t uStride;
    uint8_t *I420V;
    uint32_t vStride;
    uint32_t uvHeight;
};

struct I010Info {
    uint32_t width;
    uint32_t height;
    uint16_t *I010Y;
    uint32_t yStride;
    uint16_t *I010U;
    uint32_t uStride;
    uint16_t *I010V;
    uint32_t vStride;
    uint32_t uvHeight;
};

class ImageFormatConvertExtUtils {
public:
    static bool RGB565ToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                                 [[maybe_unused]]ColorSpace colorSpace);
    static bool RGB565ToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                                 [[maybe_unused]]ColorSpace colorSpace);
    static bool RGBAToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool RGBAToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool BGRAToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool BGRAToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool RGBToNV12P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                              [[maybe_unused]]ColorSpace colorSpace);
    static bool RGBToNV21P010(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                              [[maybe_unused]]ColorSpace colorSpace);
    static bool RGBA1010102ToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                                  [[maybe_unused]]ColorSpace colorSpace);
    static bool RGBA1010102ToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                                  [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                  [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                  [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12ToNV12P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12ToNV21P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21ToNV12P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21ToNV21P010(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12P010ToNV12(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12P010ToNV21(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12P010ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                 [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12P010ToRGBA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                   [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12P010ToBGRA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                   [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12P010ToRGB888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                 [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21P010ToNV12(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21P010ToNV21(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                               [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12P010ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                      [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21P010ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                 [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21P010ToRGBA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                   [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21P010ToBGRA8888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                   [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21P010ToRGB888(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                 [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21P010ToRGBA1010102(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                                      [[maybe_unused]]ColorSpace colorSpace);
    static bool RGB565ToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                             [[maybe_unused]]ColorSpace colorSpace);
    static bool RGB565ToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                             [[maybe_unused]]ColorSpace colorSpace);
    static bool BGRAToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                           [[maybe_unused]]ColorSpace colorSpace);
    static bool RGBAToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                           [[maybe_unused]]ColorSpace colorSpace);
    static bool RGBAToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                           [[maybe_unused]]ColorSpace colorSpace);
    static bool RGBToNV21(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                          [[maybe_unused]]ColorSpace colorSpace);
    static bool RGBToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                          [[maybe_unused]]ColorSpace colorSpace);
    static bool BGRAToNV12(const uint8_t *srcBuffer, const RGBDataInfo &rgbInfo, DestConvertInfo &destInfo,
                           [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21ToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                          [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21ToRGBA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                           [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21ToBGRA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                           [[maybe_unused]]ColorSpace colorSpace);
    static bool NV21ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                             [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12ToRGB565(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                             [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12ToRGBA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                           [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12ToBGRA(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                           [[maybe_unused]]ColorSpace colorSpace);
    static bool NV12ToRGB(const uint8_t *srcBuffer, const YUVDataInfo &yDInfo, DestConvertInfo &destInfo,
                          [[maybe_unused]]ColorSpace colorSpace);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_COMMON_INCLUDE_IMAGE_FORMAT_CONVERT_EXT_UTILS_H