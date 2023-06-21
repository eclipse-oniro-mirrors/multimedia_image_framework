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
#include "ext_pixel_convert.h"
#include "media_errors.h"

namespace {
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_3 = 3;
    constexpr uint32_t NUM_4 = 4;
}

namespace OHOS {
namespace ImagePlugin {
using namespace Media;

template<typename T>
static T* Cast(uint8_t* buffer)
{
    void* tmp = buffer;
    return static_cast<T*>(tmp);
}

struct RGBxPixel {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t x;
};

struct RGBPixel {
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

void PixelCopy(RGBPixel* src, RGBxPixel* dst)
{
    dst->r = src->r;
    dst->g = src->g;
    dst->b = src->b;
    dst->x = NUM_0;
}

void PixelCopy(RGBxPixel* src, RGBPixel* dst)
{
    dst->r = src->r;
    dst->g = src->g;
    dst->b = src->b;
}

uint32_t ExtPixelConvert::RGBxToRGB(const ExtPixels &src, ExtPixels &dst)
{
    if (src.byteCount % NUM_4 != NUM_0) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    size_t srcPixelCount = src.byteCount / NUM_4;
    if (srcPixelCount * NUM_3 > dst.byteCount) {
        return ERR_IMAGE_TOO_LARGE;
    }
    RGBxPixel* srcPixel = Cast<RGBxPixel>(src.data);
    RGBPixel* dstPixel = Cast<RGBPixel>(dst.data);
    for (uint32_t i = NUM_0 ; i < srcPixelCount; i++) {
        PixelCopy(&srcPixel[i], &dstPixel[i]);
    }
    return SUCCESS;
}

uint32_t ExtPixelConvert::RGBToRGBx(const ExtPixels &src, ExtPixels &dst)
{
    if (src.byteCount % NUM_3 != NUM_0) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    size_t srcPixelCount = src.byteCount / NUM_3;
    if (srcPixelCount * NUM_4 > dst.byteCount) {
        return ERR_IMAGE_TOO_LARGE;
    }
    RGBPixel* srcPixel = Cast<RGBPixel>(src.data);
    RGBxPixel* dstPixel = Cast<RGBxPixel>(dst.data);
    for (uint32_t i = NUM_0 ; i < srcPixelCount; i++) {
        PixelCopy(&srcPixel[i], &dstPixel[i]);
    }
    return SUCCESS;
}
} // namespace ImagePlugin
} // namespace OHOS
