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

#include "pixel_astc.h"

#include "image_log.h"
#include "image_utils.h"
#include "image_trace.h"
#include "image_type_converter.h"
#include "memory_manager.h"
#include "include/core/SkBitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkImage.h"
#include "hitrace_meter.h"
#include "media_errors.h"
#include "pubdef.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelAstc"

namespace OHOS {
namespace Media {
using namespace std;

PixelAstc::~PixelAstc()
{
    IMAGE_LOGI("PixelAstc destory");
    FreePixelMap();
}

const uint8_t *PixelAstc::GetPixel8(int32_t x, int32_t y)
{
    IMAGE_LOGE("GetPixel8 is not support on pixelastc");
    return nullptr;
}

const uint16_t *PixelAstc::GetPixel16(int32_t x, int32_t y)
{
    IMAGE_LOGE("GetPixel16 is not support on pixelastc");
    return nullptr;
}

const uint32_t *PixelAstc::GetPixel32(int32_t x, int32_t y)
{
    IMAGE_LOGE("GetPixel32 is not support on pixelastc");
    return nullptr;
}

bool PixelAstc::GetARGB32Color(int32_t x, int32_t y, uint32_t &color)
{
    IMAGE_LOGE("GetARGB32Color is not support on pixelastc");
    return false;
}

void PixelAstc::scale(float xAxis, float yAxis)
{
    if (xAxis == 0 || yAxis == 0) {
        IMAGE_LOGE("scale param incorrect on pixelastc");
        return;
    } else {
        TransformData transformData;
        GetTransformData(transformData);
        transformData.scaleX *= xAxis;
        transformData.scaleY *= yAxis;
        SetTransformData(transformData);
        ImageInfo imageInfo;
        GetImageInfo(imageInfo);
        imageInfo.size.width *= abs(xAxis);
        imageInfo.size.height *= abs(yAxis);
        SetImageInfo(imageInfo, true);
    }
}

bool PixelAstc::resize(float xAxis, float yAxis)
{
    IMAGE_LOGE("resize is not support on pixelastc");
    return false;
}

void PixelAstc::translate(float xAxis, float yAxis)
{
    TransformData transformData;
    GetTransformData(transformData);
    transformData.translateX = xAxis;
    transformData.translateY = yAxis;
    SetTransformData(transformData);
}

void PixelAstc::rotate(float degrees)
{
    TransformData transformData;
    GetTransformData(transformData);
    transformData.rotateD = degrees;
    SetTransformData(transformData);
}

void PixelAstc::flip(bool xAxis, bool yAxis)
{
    TransformData transformData;
    GetTransformData(transformData);
    transformData.flipX = xAxis;
    transformData.flipY = yAxis;
    SetTransformData(transformData);
}

uint32_t PixelAstc::crop(const Rect &rect)
{
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);
    if (rect.left >= 0 && rect.top >= 0 && rect.width > 0 && rect.height > 0 &&
        rect.left + rect.width <= imageInfo.size.width &&
        rect.top + rect.height <= imageInfo.size.height) {
        TransformData transformData;
        GetTransformData(transformData);
        transformData.cropLeft = rect.left;
        transformData.cropTop = rect.top;
        transformData.cropWidth = rect.width;
        transformData.cropHeight = rect.height;
        SetTransformData(transformData);
        imageInfo.size.width = rect.width;
        imageInfo.size.height = rect.height;
        SetImageInfo(imageInfo, true);
    } else {
        IMAGE_LOGE("crop failed");
        return ERR_IMAGE_CROP;
    }
    return SUCCESS;
}

uint32_t PixelAstc::SetAlpha(const float percent)
{
    IMAGE_LOGE("SetAlpha is not support on pixelastc");
    return ERR_IMAGE_DATA_UNSUPPORT;
}

uint8_t PixelAstc::GetARGB32ColorA(uint32_t color)
{
    IMAGE_LOGE("GetARGB32ColorA is not support on pixelastc");
    return 0;
}

uint8_t PixelAstc::GetARGB32ColorR(uint32_t color)
{
    IMAGE_LOGE("GetARGB32ColorR is not support on pixelastc");
    return 0;
}

uint8_t PixelAstc::GetARGB32ColorG(uint32_t color)
{
    IMAGE_LOGE("GetARGB32ColorG is not support on pixelastc");
    return 0;
}

uint8_t PixelAstc::GetARGB32ColorB(uint32_t color)
{
    IMAGE_LOGE("GetARGB32ColorB is not support on pixelastc");
    return 0;
}

bool PixelAstc::IsSameImage(const PixelMap &other)
{
    IMAGE_LOGE("IsSameImage is not support on pixelastc");
    return false;
}

uint32_t PixelAstc::ReadPixels(const uint64_t &bufferSize, const uint32_t &offset, const uint32_t &stride,
                               const Rect &region, uint8_t *dst)
{
    IMAGE_LOGE("ReadPixels is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::ReadPixels(const uint64_t &bufferSize, uint8_t *dst)
{
    IMAGE_LOGE("ReadPixels is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::ReadPixel(const Position &pos, uint32_t &dst)
{
    IMAGE_LOGE("ReadPixel is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::ResetConfig(const Size &size, const PixelFormat &format)
{
    IMAGE_LOGE("ResetConfig is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

bool PixelAstc::SetAlphaType(const AlphaType &alphaType)
{
    IMAGE_LOGE("SetAlphaType is not support on pixelastc");
    return false;
}

uint32_t PixelAstc::WritePixel(const Position &pos, const uint32_t &color)
{
    IMAGE_LOGE("WritePixel is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::WritePixels(const uint8_t *source, const uint64_t &bufferSize, const uint32_t &offset,
                                const uint32_t &stride, const Rect &region)
{
    IMAGE_LOGE("WritePixels is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::WritePixels(const uint8_t *source, const uint64_t &bufferSize)
{
    IMAGE_LOGE("WritePixels is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

bool PixelAstc::WritePixels(const uint32_t &color)
{
    IMAGE_LOGE("WritePixels is not support on pixelastc");
    return false;
}

void PixelAstc::SetTransformered(bool isTransformered)
{
    IMAGE_LOGE("SetTransformered is not support on pixelastc");
}

bool PixelAstc::IsTransformered()
{
    IMAGE_LOGE("IsTransformered is not support on pixelastc");
    return false;
}

void PixelAstc::SetRowStride(uint32_t stride)
{
    IMAGE_LOGE("SetRowStride is not support on pixelastc");
}

int32_t PixelAstc::GetRowStride()
{
    IMAGE_LOGD("GetRowStride is not support on pixelastc");
    return 0;
}

bool PixelAstc::IsSourceAsResponse()
{
    IMAGE_LOGE("IsSourceAsResponse is not support on pixelastc");
    return false;
}

void* PixelAstc::GetWritablePixels() const
{
    IMAGE_LOGE("GetWritablePixels is not support on pixelastc");
    return nullptr;
}
} // namespace Media
} // namespace OHOS