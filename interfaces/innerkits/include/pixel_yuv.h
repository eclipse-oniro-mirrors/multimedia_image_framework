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

#ifndef INTERFACES_INNERKITS_INCLUDE_PIXEL_YUV_H
#define INTERFACES_INNERKITS_INCLUDE_PIXEL_YUV_H

#include "image_converter.h"
#include "image_type.h"
#include "include/core/SkBitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkImage.h"
#include "memory_manager.h"
#include "pixel_map.h"

namespace OHOS {
namespace Media {

struct SkTransYuvInfo {
    SkRect r;
    SkImageInfo info;
    SkBitmap bitmap;
};

class PixelYuv : public PixelMap {
public:
    PixelYuv() {}
    virtual ~PixelYuv();
    NATIVEEXPORT const uint8_t *GetPixel8(int32_t x, int32_t y) override;
    NATIVEEXPORT const uint16_t *GetPixel16(int32_t x, int32_t y) override;
    NATIVEEXPORT const uint32_t *GetPixel32(int32_t x, int32_t y) override;
    NATIVEEXPORT bool GetARGB32Color(int32_t x, int32_t y, uint32_t &color) override;
    NATIVEEXPORT uint8_t GetARGB32ColorA(uint32_t color) override;
    NATIVEEXPORT uint8_t GetARGB32ColorR(uint32_t color) override;
    NATIVEEXPORT uint8_t GetARGB32ColorG(uint32_t color) override;
    NATIVEEXPORT uint8_t GetARGB32ColorB(uint32_t color) override;
    NATIVEEXPORT uint32_t SetAlpha(const float percent) override;
    NATIVEEXPORT uint32_t getPixelBytesNumber();
    NATIVEEXPORT int32_t GetByteCount() override;
    NATIVEEXPORT void rotate(float degrees) override;
    NATIVEEXPORT uint32_t crop(const Rect &rect) override;
    NATIVEEXPORT void scale(float xAxis, float yAxis) override;
    NATIVEEXPORT void scale(float xAxis, float yAxis, const AntiAliasingOption &option) override;
    NATIVEEXPORT bool resize(float xAxis, float yAxis) override;
    NATIVEEXPORT void flip(bool xAxis, bool yAxis) override;
    NATIVEEXPORT uint32_t WritePixels(const uint8_t *source, const uint64_t &bufferSize, const uint32_t &offset,
                                      const uint32_t &stride, const Rect &region) override;
    NATIVEEXPORT uint32_t ReadPixels(const uint64_t &bufferSize, const uint32_t &offset, const uint32_t &stride,
                                     const Rect &region, uint8_t *dst) override;
    NATIVEEXPORT void translate(float xAxis, float yAxis) override;
    NATIVEEXPORT uint32_t ReadPixel(const Position &pos, uint32_t &dst) override;
    NATIVEEXPORT bool WritePixels(const uint32_t &color) override;
    NATIVEEXPORT uint32_t WritePixel(const Position &pos, const uint32_t &color) override;
    ColorYuv420 GetYuv420Color(uint32_t x, uint32_t y);
    NATIVEEXPORT void SetPixelsAddr(void *addr, void *context, uint32_t size, AllocatorType type,
                                    CustomFreePixelMap func) override;
    bool YuvRotateConvert(Size &size, int32_t degrees, int32_t &dstWidth, int32_t &dstHeight,
        OpenSourceLibyuv::RotationMode &rotateNum);
protected:
    bool CheckPixelsInput(const uint8_t *dst, const uint64_t &bufferSize, const uint32_t &offset, const Rect &region);
    void SetRowDataSizeForImageInfo(ImageInfo info);
    static uint32_t GetImageSize(int32_t width, int32_t height, PixelFormat format);
    uint32_t SetColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace, SkTransYuvInfo &src,
        PixelFormat &format, uint64_t rowStride);
    std::unique_ptr<AbsMemory> CreateMemory(PixelFormat pixelFormat, std::string memoryTag,
        int32_t dstWidth, int32_t dstHeight, YUVStrideInfo &dstStrides);
#ifdef IMAGE_COLORSPACE_FLAG
    bool CheckColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace);
    int32_t ColorSpaceBGRAToYuv(uint8_t *bgraData, SkTransYuvInfo &dst, ImageInfo &imageInfo, PixelFormat &format,
        const OHOS::ColorManager::ColorSpace &grColorSpace);
    NATIVEEXPORT uint32_t ApplyColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace) override;
#endif
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERKITS_INCLUDE_PIXEL_YUV_H
