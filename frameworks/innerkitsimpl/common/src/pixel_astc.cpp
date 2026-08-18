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

#include <cmath>
#include <limits>

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

namespace {
constexpr double PI = 3.14159265358979323846;
constexpr double FULL_ROTATION_DEGREES = 360.0;

bool SafeCastToInt32(double value, int32_t &result)
{
    if (!std::isfinite(value) ||
        value < static_cast<double>(std::numeric_limits<int32_t>::min()) ||
        value > static_cast<double>(std::numeric_limits<int32_t>::max())) {
        return false;
    }
    result = static_cast<int32_t>(value);
    return true;
}

bool SafeRoundToInt32(double value, int32_t &result)
{
    if (!std::isfinite(value)) {
        return false;
    }
    return SafeCastToInt32(std::round(value), result);
}

bool SafeCastToFloat(double value, float &result)
{
    if (!std::isfinite(value) ||
        value < -static_cast<double>(std::numeric_limits<float>::max()) ||
        value > static_cast<double>(std::numeric_limits<float>::max())) {
        return false;
    }
    result = static_cast<float>(value);
    return true;
}

std::pair<double, double> CalculateRotatedDimensions(int32_t width, int32_t height, double rotationDegrees)
{
    double radians = rotationDegrees * PI / 180.0;
    double cosTheta = std::cos(radians);
    double sinTheta = std::sin(radians);
    double newWidth = std::abs(static_cast<double>(width) * cosTheta) +
        std::abs(static_cast<double>(height) * sinTheta);
    double newHeight = std::abs(static_cast<double>(width) * sinTheta) +
        std::abs(static_cast<double>(height) * cosTheta);
    return {newWidth, newHeight};
}
}

PixelAstc::~PixelAstc()
{
    IMAGE_LOGD("PixelAstc destory");
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
    Scale(xAxis, yAxis, AntiAliasingOption::NONE);
}

uint32_t PixelAstc::Scale(float xAxis, float yAxis, AntiAliasingOption option)
{
    std::lock_guard<std::mutex> lock(*translationMutex_);
    if (!std::isfinite(xAxis) || !std::isfinite(yAxis) || xAxis == 0.0f || yAxis == 0.0f) {
        IMAGE_LOGE("Invalid scale ratio");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    TransformData transformData;
    GetTransformData(transformData);
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);
    ImageInfo scaledImageInfo = imageInfo;
    double scaledWidth = std::abs(static_cast<double>(imageInfo.size.width) * xAxis);
    double scaledHeight = std::abs(static_cast<double>(imageInfo.size.height) * yAxis);
    if (!SafeRoundToInt32(scaledWidth, scaledImageInfo.size.width) ||
        !SafeRoundToInt32(scaledHeight, scaledImageInfo.size.height) ||
        scaledImageInfo.size.width <= 0 || scaledImageInfo.size.height <= 0 ||
        !SafeCastToFloat(static_cast<double>(transformData.scaleX) * xAxis, transformData.scaleX) ||
        !SafeCastToFloat(static_cast<double>(transformData.scaleY) * yAxis, transformData.scaleY)) {
        IMAGE_LOGE("Invalid scaled image or transform size");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint32_t ret = SetImageInfo(scaledImageInfo, true);
    if (ret != SUCCESS) {
        IMAGE_LOGE("PixelAstc scale SetImageInfo failed, ret: %{public}u", ret);
        uint32_t restoreRet = SetImageInfo(imageInfo, true);
        if (restoreRet != SUCCESS) {
            IMAGE_LOGE("PixelAstc scale restore ImageInfo failed, ret: %{public}u", restoreRet);
        }
        return ret;
    }
    SetTransformData(transformData);
    return SUCCESS;
}

bool PixelAstc::resize(float xAxis, float yAxis)
{
    IMAGE_LOGE("resize is not support on pixelastc");
    return false;
}

void PixelAstc::translate(float xAxis, float yAxis)
{
    Translate(xAxis, yAxis);
}

uint32_t PixelAstc::Translate(float xAxis, float yAxis)
{
    std::lock_guard<std::mutex> lock(*translationMutex_);
    if (!std::isfinite(xAxis) || !std::isfinite(yAxis)) {
        IMAGE_LOGE("Invalid translate distance");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    TransformData transformData;
    GetTransformData(transformData);
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);
    ImageInfo translatedImageInfo = imageInfo;
    int32_t translatedXAxis = 0;
    int32_t translatedYAxis = 0;
    if (!SafeCastToInt32(xAxis, translatedXAxis) ||
        !SafeCastToInt32(yAxis, translatedYAxis) ||
        !SafeCastToInt32(static_cast<double>(imageInfo.size.width) + translatedXAxis,
        translatedImageInfo.size.width) ||
        !SafeCastToInt32(static_cast<double>(imageInfo.size.height) + translatedYAxis,
        translatedImageInfo.size.height) ||
        translatedImageInfo.size.width <= 0 || translatedImageInfo.size.height <= 0 ||
        !SafeCastToFloat(static_cast<double>(transformData.translateX) + xAxis, transformData.translateX) ||
        !SafeCastToFloat(static_cast<double>(transformData.translateY) + yAxis, transformData.translateY)) {
        IMAGE_LOGE("PixelAstc translate failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint32_t ret = SetImageInfo(translatedImageInfo, true);
    if (ret != SUCCESS) {
        IMAGE_LOGE("PixelAstc translate SetImageInfo failed, ret: %{public}u", ret);
        uint32_t restoreRet = SetImageInfo(imageInfo, true);
        if (restoreRet != SUCCESS) {
            IMAGE_LOGE("PixelAstc translate restore ImageInfo failed, ret: %{public}u", restoreRet);
        }
        return ret;
    }
    SetTransformData(transformData);
    return SUCCESS;
}

void PixelAstc::rotate(float degrees)
{
    Rotate(degrees);
}

uint32_t PixelAstc::Rotate(float degrees)
{
    std::lock_guard<std::mutex> lock(*translationMutex_);
    if (!std::isfinite(degrees)) {
        IMAGE_LOGE("Invalid rotate degrees");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    TransformData transformData;
    GetTransformData(transformData);
    double normalizedDegrees = std::fmod(static_cast<double>(degrees), FULL_ROTATION_DEGREES);
    double accumulatedDegrees = std::fmod(
        static_cast<double>(transformData.rotateD) + normalizedDegrees, FULL_ROTATION_DEGREES);
    accumulatedDegrees = std::fmod(
        accumulatedDegrees + FULL_ROTATION_DEGREES, FULL_ROTATION_DEGREES);
    if (!SafeCastToFloat(accumulatedDegrees, transformData.rotateD)) {
        IMAGE_LOGE("Invalid accumulated rotate degrees");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);
    ImageInfo rotatedImageInfo = imageInfo;
    auto newDimensions = CalculateRotatedDimensions(
        imageInfo.size.width, imageInfo.size.height, normalizedDegrees);
    if (!SafeCastToInt32(newDimensions.first, rotatedImageInfo.size.width) ||
        !SafeCastToInt32(newDimensions.second, rotatedImageInfo.size.height) ||
        rotatedImageInfo.size.width <= 0 || rotatedImageInfo.size.height <= 0) {
        IMAGE_LOGE("Invalid rotated image size");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint32_t ret = SetImageInfo(rotatedImageInfo, true);
    if (ret != SUCCESS) {
        IMAGE_LOGE("PixelAstc rotate SetImageInfo failed, ret: %{public}u", ret);
        uint32_t restoreRet = SetImageInfo(imageInfo, true);
        if (restoreRet != SUCCESS) {
            IMAGE_LOGE("PixelAstc rotate restore ImageInfo failed, ret: %{public}u", restoreRet);
        }
        return ret;
    }
    SetTransformData(transformData);
    return SUCCESS;
}

void PixelAstc::flip(bool xAxis, bool yAxis)
{
    Flip(xAxis, yAxis);
}

uint32_t PixelAstc::Flip(bool xAxis, bool yAxis)
{
    std::lock_guard<std::mutex> lock(*translationMutex_);
    TransformData transformData;
    GetTransformData(transformData);
    transformData.flipX = xAxis;
    transformData.flipY = yAxis;
    SetTransformData(transformData);
    return SUCCESS;
}

uint32_t PixelAstc::crop(const Rect &rect)
{
    return Crop(rect);
}

uint32_t PixelAstc::Crop(const Rect &rect)
{
    std::lock_guard<std::mutex> lock(*translationMutex_);
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);
    if (rect.left >= 0 && rect.top >= 0 && rect.width > 0 && rect.height > 0 &&
        rect.left <= imageInfo.size.width && rect.top <= imageInfo.size.height &&
        rect.width <= imageInfo.size.width - rect.left &&
        rect.height <= imageInfo.size.height - rect.top) {
        TransformData transformData;
        GetTransformData(transformData);
        transformData.cropLeft = rect.left;
        transformData.cropTop = rect.top;
        transformData.cropWidth = rect.width;
        transformData.cropHeight = rect.height;
        ImageInfo croppedImageInfo = imageInfo;
        croppedImageInfo.size.width = rect.width;
        croppedImageInfo.size.height = rect.height;
        uint32_t ret = SetImageInfo(croppedImageInfo, true);
        if (ret != SUCCESS) {
            IMAGE_LOGE("PixelAstc crop SetImageInfo failed, ret: %{public}u", ret);
            uint32_t restoreRet = SetImageInfo(imageInfo, true);
            if (restoreRet != SUCCESS) {
                IMAGE_LOGE("PixelAstc crop restore ImageInfo failed, ret: %{public}u", restoreRet);
            }
            return ret;
        }
        SetTransformData(transformData);
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
    IMAGE_LOGE("%{public}d:ReadPixels is not support on pixelastc", uniqueId_);
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t PixelAstc::ReadPixels(const uint64_t &bufferSize, uint8_t *dst)
{
    IMAGE_LOGE("%{public}d:ReadPixels is not support on pixelastc", uniqueId_);
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
