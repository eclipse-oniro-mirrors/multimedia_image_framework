/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_INCLUDE_PIXEL_ASTC_H
#define INTERFACES_INNERKITS_INCLUDE_PIXEL_ASTC_H

#include "pixel_map.h"

namespace OHOS {
namespace Media {
typedef struct {
    uint8_t magic[4];
    uint8_t blockdimX;
    uint8_t blockdimY;
    uint8_t blockdimZ;
    uint8_t xsize[3];
    uint8_t ysize[3];
    uint8_t zsize[3];
} AstcHeader;

class PixelAstc : public PixelMap {
public:
    PixelAstc()
    {
        astcId_ = currentId.fetch_add(1, std::memory_order_relaxed);
    }
    virtual ~PixelAstc();

    NATIVEEXPORT uint32_t SetAlpha(const float percent) override;
    NATIVEEXPORT bool SetAlphaType(const AlphaType &alphaType) override;
    NATIVEEXPORT void SetTransformered(bool isTransformered) override;
    NATIVEEXPORT void SetRowStride(uint32_t stride) override;

    NATIVEEXPORT const uint8_t *GetPixel8(int32_t x, int32_t y) override;
    NATIVEEXPORT const uint16_t *GetPixel16(int32_t x, int32_t y) override;
    NATIVEEXPORT const uint32_t *GetPixel32(int32_t x, int32_t y) override;
    NATIVEEXPORT bool GetARGB32Color(int32_t x, int32_t y, uint32_t &color) override;
    NATIVEEXPORT uint8_t GetARGB32ColorA(uint32_t color) override;
    NATIVEEXPORT uint8_t GetARGB32ColorR(uint32_t color) override;
    NATIVEEXPORT uint8_t GetARGB32ColorG(uint32_t color) override;
    NATIVEEXPORT uint8_t GetARGB32ColorB(uint32_t color) override;
    NATIVEEXPORT int32_t GetRowStride() override;
    NATIVEEXPORT void *GetWritablePixels() const override;
    NATIVEEXPORT uint32_t GetUniqueId() const override
    {
        return astcId_;
    }

    NATIVEEXPORT void scale(float xAxis, float yAxis) override;
    NATIVEEXPORT bool resize(float xAxis, float yAxis) override;
    NATIVEEXPORT void translate(float xAxis, float yAxis) override;
    NATIVEEXPORT void rotate(float degrees) override;
    NATIVEEXPORT void flip(bool xAxis, bool yAxis) override;
    NATIVEEXPORT uint32_t crop(const Rect &rect) override;

    // Config the pixel map parameter
    NATIVEEXPORT bool IsSameImage(const PixelMap &other) override;
    NATIVEEXPORT bool IsTransformered() override;
    // judgement whether create pixelmap use source as result
    NATIVEEXPORT bool IsSourceAsResponse() override;

    NATIVEEXPORT uint32_t ReadPixels(const uint64_t &bufferSize, const uint32_t &offset, const uint32_t &stride,
                                     const Rect &region, uint8_t *dst) override;
    NATIVEEXPORT uint32_t ReadPixels(const uint64_t &bufferSize, uint8_t *dst) override;
    NATIVEEXPORT uint32_t ReadPixel(const Position &pos, uint32_t &dst) override;
    NATIVEEXPORT uint32_t ResetConfig(const Size &size, const PixelFormat &format) override;
    NATIVEEXPORT uint32_t WritePixel(const Position &pos, const uint32_t &color) override;
    NATIVEEXPORT uint32_t WritePixels(const uint8_t *source, const uint64_t &bufferSize, const uint32_t &offset,
                         const uint32_t &stride, const Rect &region) override;
    NATIVEEXPORT uint32_t WritePixels(const uint8_t *source, const uint64_t &bufferSize) override;
    NATIVEEXPORT bool WritePixels(const uint32_t &color) override;

private:
    uint32_t astcId_ = 0;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERKITS_INCLUDE_PIXEL_ASTC_H