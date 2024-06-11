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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_PIXEL_YUV_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_PIXEL_YUV_UTILS_H

#include <cstdlib>
#include <cstdio>
#include <string>
#include "image_type.h"
#include "iosfwd"

#ifdef __cplusplus
extern "C" {
#endif
#include "libavfilter/avfilter.h"
#include "libavutil/avstring.h"
#include "libavfilter/buffersrc.h"
#include "libavfilter/buffersink.h"
#include "libavutil/frame.h"
#include "libavutil/imgutils.h"
#include "libavutil/pixfmt.h"
#include "libswscale/swscale.h"
#ifdef __cplusplus
}
#endif

namespace OHOS {
namespace Media {

struct XYaxis {
    float xAxis = 0;
    float yAxis = 0;
};

struct PixelSize {
    int32_t srcW = 0;
    int32_t srcH = 0;
    int32_t dstW = 0;
    int32_t dstH = 0;
};

struct YuvImageInfo {
    AVPixelFormat format = AVPixelFormat::AV_PIX_FMT_NONE;
    int32_t width;
    int32_t height;
    PixelFormat yuvFormat;
    YUVDataInfo yuvDataInfo;
};

class PixelYuvUtils {
public:
    static int32_t YuvConvertOption(const AntiAliasingOption &option);
    static bool WriteYuvConvert(const void *srcPixels, const ImageInfo &srcInfo, void *dstPixels,
        const Position &dstPos, const YUVDataInfo &yuvDataInfo);
    static bool ReadYuvConvert(const void *srcPixels, const Position &srcPos, YuvImageInfo &srcInfo,
        void *dstPixels, const ImageInfo &dstInfo);
    static void SetTranslateDataDefault(uint8_t *srcPixels, int32_t width, int32_t height);
    static uint8_t GetYuv420Y(uint32_t x, uint32_t y, YUVDataInfo &info, const uint8_t *in);
    static uint8_t GetYuv420U(uint32_t x, uint32_t y, YUVDataInfo &info, PixelFormat format,
        const uint8_t *in);
    static uint8_t GetYuv420V(uint32_t x, uint32_t y, YUVDataInfo &info, PixelFormat format,
        const uint8_t *in);
    static AVPixelFormat ConvertFormat(const PixelFormat &pixelFormat);
    static bool BGRAToYuv420(const uint8_t *src, YuvImageInfo &srcInfo, uint8_t *dst, YuvImageInfo &dstInfo);
    static bool Yuv420ToBGRA(const uint8_t *in, YuvImageInfo &srcInfo, uint8_t *out,
        YuvImageInfo &dstInfo);
    static bool Yuv420ToARGB(const uint8_t *in, YuvImageInfo &srcInfo, uint8_t *out, YuvImageInfo &dstInfo);
    static bool YuvTranslate(const uint8_t *srcPixels, YUVDataInfo &yuvInfo, uint8_t *dstPixels, XYaxis &xyAxis,
        ImageInfo &info);
    static bool Yuv420WritePixels(const YUVDataInfo &yuvInfo, uint8_t *srcPixels, ImageInfo &info,
        const uint32_t &color);
    static bool YuvWritePixel(uint8_t *srcPixels, const YUVDataInfo &yuvDataInfo, const PixelFormat &format,
        const Position &pos, const uint32_t &color);
    static bool YuvCrop(uint8_t *srcData, YuvImageInfo &srcInfo, uint8_t *dstData, const Rect &rect);
    static bool YuvRotate(uint8_t *srcData, YuvImageInfo &srcInfo,
        uint8_t *dstData, YuvImageInfo &dstInfo, int32_t degrees);
    static bool YuvFlip(uint8_t *srcData, YuvImageInfo &srcInfo, uint8_t *dstData, bool xAxis);
    static bool YuvReversal(uint8_t *srcData, YuvImageInfo &srcInfo, uint8_t *dstData, YuvImageInfo &dstInfo);
    static int32_t YuvScale(uint8_t *srcPixels, YuvImageInfo &srcInfo,
        uint8_t *dstPixels, YuvImageInfo &dstInfo, int32_t module);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_PIXEL_YUV_UTILS_H
