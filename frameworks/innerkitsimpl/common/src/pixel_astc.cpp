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

#include "image_utils.h"
#include "image_trace.h"
#include "image_type_converter.h"
#include "memory_manager.h"
#include "include/core/SkBitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkImage.h"
#include "hilog/log.h"
#include "hitrace_meter.h"
#include "log_tags.h"
#include "media_errors.h"
#include "pubdef.h"

namespace OHOS {
namespace Media {
using namespace OHOS::HiviewDFX;
using namespace std;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "PixelAstc" };

PixelAstc::~PixelAstc()
{
    HiLog::Info(LABEL, "PixelAstc destory");
    FreePixelMap();
}

const uint8_t *PixelAstc::GetPixel8(int32_t x, int32_t y)
{
    HiLog::Error(LABEL, "GetPixel8 is not support on pixelastc");
    return nullptr;
}

const uint16_t *PixelAstc::GetPixel16(int32_t x, int32_t y)
{
    HiLog::Error(LABEL, "GetPixel16 is not support on pixelastc");
    return nullptr;
}

const uint32_t *PixelAstc::GetPixel32(int32_t x, int32_t y)
{
    HiLog::Error(LABEL, "GetPixel32 is not support on pixelastc");
    return nullptr;
}

bool PixelAstc::GetARGB32Color(int32_t x, int32_t y, uint32_t &color)
{
    HiLog::Error(LABEL, "GetARGB32Color is not support on pixelastc");
    return false;
}

void PixelAstc::scale(float xAxis, float yAxis)
{
    HiLog::Error(LABEL, "scale is not support on pixelastc");
}

bool PixelAstc::resize(float xAxis, float yAxis)
{
    HiLog::Error(LABEL, "resize is not support on pixelastc");
    return false;
}

void PixelAstc::translate(float xAxis, float yAxis)
{
    HiLog::Error(LABEL, "translate is not support on pixelastc");
}

void PixelAstc::rotate(float degrees)
{
    HiLog::Error(LABEL, "rotate is not support on pixelastc");
}

void PixelAstc::flip(bool xAxis, bool yAxis)
{
    HiLog::Error(LABEL, "flip is not support on pixelastc");
}

uint32_t PixelAstc::crop(const Rect &rect)
{
    HiLog::Error(LABEL, "crop is not support on pixelastc");
    return ERR_IMAGE_CROP;
}

uint32_t PixelAstc::SetAlpha(const float percent)
{
    HiLog::Error(LABEL, "SetAlpha is not support on pixelastc");
    return ERR_IMAGE_DATA_UNSUPPORT;
}

uint8_t PixelAstc::GetARGB32ColorA(uint32_t color)
{
    HiLog::Error(LABEL, "GetARGB32ColorA is not support on pixelastc");
    return 0;
}

uint8_t PixelAstc::GetARGB32ColorR(uint32_t color)
{
    HiLog::Error(LABEL, "GetARGB32ColorR is not support on pixelastc");
    return 0;
}

uint8_t PixelAstc::GetARGB32ColorG(uint32_t color)
{
    HiLog::Error(LABEL, "GetARGB32ColorG is not support on pixelastc");
    return 0;
}

uint8_t PixelAstc::GetARGB32ColorB(uint32_t color)
{
    HiLog::Error(LABEL, "GetARGB32ColorB is not support on pixelastc");
    return 0;
}

bool PixelAstc::IsSameImage(const PixelMap &other)
{
    HiLog::Error(LABEL, "IsSameImage is not support on pixelastc");
    return false;
}

uint32_t PixelAstc::ReadPixels(const uint64_t &bufferSize, const uint32_t &offset, const uint32_t &stride,
                               const Rect &region, uint8_t *dst)
{
    HiLog::Error(LABEL, "ReadPixels is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::ReadPixels(const uint64_t &bufferSize, uint8_t *dst)
{
    HiLog::Error(LABEL, "ReadPixels is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::ReadPixel(const Position &pos, uint32_t &dst)
{
    HiLog::Error(LABEL, "ReadPixel is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::ResetConfig(const Size &size, const PixelFormat &format)
{
    HiLog::Error(LABEL, "ResetConfig is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

bool PixelAstc::SetAlphaType(const AlphaType &alphaType)
{
    HiLog::Error(LABEL, "SetAlphaType is not support on pixelastc");
    return false;
}

uint32_t PixelAstc::WritePixel(const Position &pos, const uint32_t &color)
{
    HiLog::Error(LABEL, "WritePixel is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::WritePixels(const uint8_t *source, const uint64_t &bufferSize, const uint32_t &offset,
                                const uint32_t &stride, const Rect &region)
{
    HiLog::Error(LABEL, "WritePixels is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::WritePixels(const uint8_t *source, const uint64_t &bufferSize)
{
    HiLog::Error(LABEL, "WritePixels is not support on pixelastc");
    return ERR_IMAGE_INVALID_PARAMETER;
}

bool PixelAstc::WritePixels(const uint32_t &color)
{
    HiLog::Error(LABEL, "WritePixels is not support on pixelastc");
    return false;
}

void PixelAstc::SetTransformered(bool isTransformered)
{
    HiLog::Error(LABEL, "SetTransformered is not support on pixelastc");
}

bool PixelAstc::IsTransformered()
{
    HiLog::Error(LABEL, "IsTransformered is not support on pixelastc");
    return false;
}

void PixelAstc::SetRowStride(uint32_t stride)
{
    HiLog::Error(LABEL, "SetRowStride is not support on pixelastc");
}

int32_t PixelAstc::GetRowStride()
{
    HiLog::Error(LABEL, "GetRowStride is not support on pixelastc");
    return 0;
}

bool PixelAstc::IsSourceAsResponse()
{
    HiLog::Error(LABEL, "IsSourceAsResponse is not support on pixelastc");
    return false;
}

void* PixelAstc::GetWritablePixels() const
{
    HiLog::Error(LABEL, "GetWritablePixels is not support on pixelastc");
    return nullptr;
}
} // namespace Media
} // namespace OHOS