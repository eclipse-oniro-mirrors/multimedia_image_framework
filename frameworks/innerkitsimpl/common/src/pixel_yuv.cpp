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

#include "pixel_yuv.h"

#include "image_utils.h"
#include "image_trace.h"
#include "image_type_converter.h"
#include "memory_manager.h"
#include "hitrace_meter.h"
#include "media_errors.h"
#include "pubdef.h"
#include "pixel_yuv_utils.h"
#include "securec.h"
#include "image_log.h"
#include "image_mdk_common.h"
#include "image_system_properties.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "surface_buffer.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelYuv"

namespace OHOS {
namespace Media {
using namespace std;

static const uint8_t NUM_2 = 2;
static const uint8_t NUM_3 = 3;
static const uint8_t NUM_4 = 4;
constexpr uint8_t Y_SHIFT = 16;
constexpr uint8_t U_SHIFT = 8;
constexpr uint8_t V_SHIFT = 0;
constexpr int32_t MAX_DIMENSION = INT32_MAX >> NUM_2;

struct TransInfos {
    SkMatrix matrix;
};

struct TransMemoryInfo {
    AllocatorType allocType;
    std::unique_ptr<AbsMemory> memory = nullptr;
};

static SkImageInfo ToSkImageInfo(ImageInfo &info, sk_sp<SkColorSpace> colorSpace)
{
    SkColorType colorType = ImageTypeConverter::ToSkColorType(info.pixelFormat);
    SkAlphaType alphaType = ImageTypeConverter::ToSkAlphaType(info.alphaType);
    IMAGE_LOGD("ToSkImageInfo w %{public}d, h %{public}d\n" \
        "ToSkImageInfo pf %{public}s, at %{public}s, skpf %{public}s, skat %{public}s",
        info.size.width, info.size.height,
        ImageTypeConverter::ToName(info.pixelFormat).c_str(),
        ImageTypeConverter::ToName(info.alphaType).c_str(),
        ImageTypeConverter::ToName(colorType).c_str(),
        ImageTypeConverter::ToName(alphaType).c_str());
    return SkImageInfo::Make(info.size.width, info.size.height, colorType, alphaType, colorSpace);
}

static sk_sp<SkColorSpace> ToSkColorSpace(PixelMap *pixelmap)
{
#ifdef IMAGE_COLORSPACE_FLAG
    if (pixelmap->InnerGetGrColorSpacePtr() == nullptr) {
        return nullptr;
    }
    return pixelmap->InnerGetGrColorSpacePtr()->ToSkColorSpace();
#else
    return nullptr;
#endif
}

static bool isSameColorSpace(const OHOS::ColorManager::ColorSpace &src,
    const OHOS::ColorManager::ColorSpace &dst)
{
    auto skSrc = src.ToSkColorSpace();
    auto skDst = dst.ToSkColorSpace();
    return SkColorSpace::Equals(skSrc.get(), skDst.get());
}

PixelYuv::~PixelYuv()
{
    FreePixelMap();
}

const uint8_t *PixelYuv::GetPixel8(int32_t x, int32_t y)
{
    IMAGE_LOGE("GetPixel8 is not support on PixelYuv");
    return nullptr;
}

const uint16_t *PixelYuv::GetPixel16(int32_t x, int32_t y)
{
    IMAGE_LOGE("GetPixel16 is not support on PixelYuv");
    return nullptr;
}

const uint32_t *PixelYuv::GetPixel32(int32_t x, int32_t y)
{
    IMAGE_LOGE("GetPixel32 is not support on PixelYuv");
    return nullptr;
}

bool PixelYuv::GetARGB32Color(int32_t x, int32_t y, uint32_t &color)
{
    IMAGE_LOGE("GetARGB32Color is not support on PixelYuv");
    return false;
}

uint8_t PixelYuv::GetARGB32ColorA(uint32_t color)
{
    IMAGE_LOGE("GetARGB32ColorA is not support on PixelYuv");
    return 0;
}

uint8_t PixelYuv::GetARGB32ColorR(uint32_t color)
{
    IMAGE_LOGE("GetARGB32ColorR is not support on PixelYuv");
    return 0;
}

uint8_t PixelYuv::GetARGB32ColorG(uint32_t color)
{
    IMAGE_LOGE("GetARGB32ColorG is not support on PixelYuv");
    return 0;
}

uint8_t PixelYuv::GetARGB32ColorB(uint32_t color)
{
    IMAGE_LOGE("GetARGB32ColorB is not support on PixelYuv");
    return 0;
}

uint32_t PixelYuv::SetAlpha(const float percent)
{
    IMAGE_LOGE("SetAlpha is not support on PixelYuv");
    return ERR_IMAGE_DATA_UNSUPPORT;
}

uint32_t PixelYuv::getPixelBytesNumber()
{
    IMAGE_LOGE("getPixelBytesNumber is not support on PixelYuv");
    return ERR_IMAGE_DATA_UNSUPPORT;
}

int32_t PixelYuv::GetByteCount()
{
    IMAGE_LOGE("GetByteCount is not support on PixelYuv");
    return ERR_IMAGE_DATA_UNSUPPORT;
}

static int32_t GetYSize(int32_t width, int32_t height)
{
    return width * height;
}

static int32_t GetUStride(int32_t width)
{
    return (width + 1) / NUM_2;
}

static int32_t GetUVHeight(int32_t height)
{
    return (height + 1) / NUM_2;
}

// Yuv420SP, u, v blend planer
static int32_t GetUVStride(int32_t width)
{
    return (width + 1) / NUM_2 * NUM_2;
}

void PixelYuv::rotate(float degrees)
{
    if (degrees == 0) {
        return;
    }
    uint32_t count = GetImageSize(imageInfo_.size.width, imageInfo_.size.height);
    Size desiredSize = {imageInfo_.size.width, imageInfo_.size.height};
    MemoryData memoryData = {nullptr, count, "Rotate ImageData", desiredSize};
    auto dstMemory = MemoryManager::CreateMemory(allocatorType_, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("rotate CreateMemory failed");
        return;
    }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType_ == AllocatorType::DMA_ALLOC) {
        if (dstMemory->extend.data == nullptr) {
            IMAGE_LOGE("GendstTransInfo get surfacebuffer failed");
        }
    }
#endif
    uint8_t *dst = reinterpret_cast<uint8_t *>(dstMemory->data.data);
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(imageInfo_.pixelFormat),
        imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, yuvDataInfo};
    YuvImageInfo dstInfo;
    if (!PixelYuvUtils::YuvRotate(data_, srcInfo, dst, dstInfo, degrees)) {
        IMAGE_LOGE("rotate failed");
        dstMemory->Release();
        return;
    }
    imageInfo_.size.width = dstInfo.width;
    imageInfo_.size.height = dstInfo.height;
    SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size, dstMemory->GetType(), nullptr);
    SetImageInfo(imageInfo_, true);
    AssignYuvDataOnType(imageInfo_.pixelFormat, imageInfo_.size.width, imageInfo_.size.height);
}

uint32_t PixelYuv::crop(const Rect &rect)
{
    int32_t rectSize = GetYSize(rect.width, rect.height);
    int32_t pixelSize = GetYSize(imageInfo_.size.width, imageInfo_.size.height);
    if (rect.top < 0 || rect.left < 0 || rectSize > pixelSize || rect.width <= 1 || rect.height <= 1) {
        IMAGE_LOGE("crop invalid param");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    Size desiredSize = {rect.width, rect.height};
    MemoryData memoryData = {nullptr, GetImageSize(rect.width, rect.height), "Trans ImageData", desiredSize};
    auto dstMemory = MemoryManager::CreateMemory(allocatorType_, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("crop CreateMemory failed");
        return ERR_IMAGE_CROP;
    }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType_ == AllocatorType::DMA_ALLOC) {
        if (dstMemory->extend.data == nullptr) {
            IMAGE_LOGE("GendstTransInfo get surfacebuffer failed");
        }
    }
#endif
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(imageInfo_.pixelFormat),
        imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, yuvDataInfo};
    if (!PixelYuvUtils::YuvCrop(data_, srcInfo, (uint8_t *)dstMemory->data.data, rect)) {
        dstMemory->Release();
        return ERR_IMAGE_CROP;
    }
    imageInfo_.size.height = rect.height;
    imageInfo_.size.width = rect.width;

    SetPixelsAddr(dstMemory->data.data, nullptr, GetImageSize(rect.width, rect.height), dstMemory->GetType(), nullptr);
    AssignYuvDataOnType(imageInfo_.pixelFormat, imageInfo_.size.width, imageInfo_.size.height);
    return SUCCESS;
}

void PixelYuv::scale(float xAxis, float yAxis)
{
    ImageTrace imageTrace("PixelMap scale");
    return scale(xAxis, yAxis, AntiAliasingOption::NONE);
}

bool PixelYuv::resize(float xAxis, float yAxis)
{
    ImageTrace imageTrace("PixelMap resize");
    scale(xAxis, yAxis, AntiAliasingOption::NONE);
    return true;
}

void PixelYuv::scale(float xAxis, float yAxis, const AntiAliasingOption &option)
{
    ImageTrace imageTrace("PixelMap scale");
    if (xAxis == 1 && yAxis == 1 && option == AntiAliasingOption::NONE) {
        return;
    }
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);
    int32_t dstW = imageInfo.size.width * xAxis;
    int32_t dstH = imageInfo.size.height * yAxis;
    Size desiredSize = {dstW, dstH};
    MemoryData memoryData = {nullptr, GetImageSize(dstW, dstH), "Trans ImageData", desiredSize};
    auto dstMemory = MemoryManager::CreateMemory(allocatorType_, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("scale CreateMemory failed");
        return;
    }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType_ == AllocatorType::DMA_ALLOC) {
        if (dstMemory->extend.data == nullptr) {
            IMAGE_LOGE("GendstTransInfo get surfacebuffer failed");
        }
    }
#endif
    uint8_t *yuvData = reinterpret_cast<uint8_t *>(dstMemory->data.data);
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(imageInfo.pixelFormat),
        imageInfo.size.width, imageInfo.size.height, imageInfo_.pixelFormat, yuvDataInfo};
    YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(imageInfo.pixelFormat),
        dstW, dstH, imageInfo_.pixelFormat, yuvDataInfo};
    if (PixelYuvUtils::YuvScale(data_, srcInfo, yuvData, dstInfo, PixelYuvUtils::YuvConvertOption(option)) != SUCCESS) {
        IMAGE_LOGE("ScaleYuv failed");
        return;
    }
    imageInfo.size.height = dstH;
    imageInfo.size.width = dstW;

    SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size, dstMemory->GetType(), nullptr);
    SetImageInfo(imageInfo, true);
    AssignYuvDataOnType(imageInfo.pixelFormat, imageInfo.size.width, imageInfo.size.height);
}

void PixelYuv::flip(bool xAxis, bool yAxis)
{
    if (xAxis == false && yAxis == false) {
        return;
    }
    int32_t srcW = imageInfo_.size.width;
    int32_t srcH = imageInfo_.size.height;
    PixelFormat format = imageInfo_.pixelFormat;
    const uint8_t *src = data_;
    Size desiredSize = {srcW, srcH};
    uint32_t pictureSize = GetImageSize(srcW, srcH);
    MemoryData memoryData = {nullptr, pictureSize, "flip ImageData", desiredSize};
    auto dstMemory = MemoryManager::CreateMemory(allocatorType_, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("flip CreateMemory failed");
        return;
    }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType_ == AllocatorType::DMA_ALLOC) {
        if (dstMemory->extend.data == nullptr) {
            IMAGE_LOGE("GendstTransInfo get surfacebuffer failed");
        }
    }
#endif
    uint8_t *dst = reinterpret_cast<uint8_t *>(dstMemory->data.data);
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(format), srcW, srcH, imageInfo_.pixelFormat, yuvDataInfo};
    YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(format), srcW, srcH, imageInfo_.pixelFormat, yuvDataInfo};
    if (xAxis && yAxis) {
        if (!PixelYuvUtils::YuvReversal(const_cast<uint8_t *>(src), srcInfo, dst, dstInfo)) {
            IMAGE_LOGE("flip yuv xAxis and yAxis failed");
            return;
        }
    } else {
        bool isXaxis = ((xAxis | yAxis) && xAxis) ? true : false;
        if (!PixelYuvUtils::YuvFlip(const_cast<uint8_t *>(src), srcInfo, dst, isXaxis)) {
            IMAGE_LOGE("flip yuv xAxis or yAxis failed");
            return;
        }
    }
    SetPixelsAddr(dst, dstMemory->extend.data, dstMemory->data.size, dstMemory->GetType(), nullptr);
    AssignYuvDataOnType(format, srcW, srcH);
}

uint32_t PixelYuv::WritePixels(const uint8_t *source, const uint64_t &bufferSize, const uint32_t &offset,
    const uint32_t &stride, const Rect &region)
{
    if (!CheckPixelsInput(source, bufferSize, offset, region)) {
        IMAGE_LOGE("write pixel by rect input parameter fail.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!IsEditable()) {
        IMAGE_LOGE("write pixel by rect PixelYuv data is not editable.");
        return ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY;
    }
    if (!ImageUtils::IsValidImageInfo(imageInfo_)) {
        IMAGE_LOGE("write pixel by rect current PixelYuv image info is invalid.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("write pixel by rect current pixel map data is null.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    uint32_t bytesPerPixel = ImageUtils::GetPixelBytes(imageInfo_.pixelFormat);
    if (bytesPerPixel == 0) {
        IMAGE_LOGE("write pixel by rect get bytes by per pixel fail.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    Position dstPosition{region.left, region.top};
    ImageInfo srcInfo;
    srcInfo.size.height = region.height;
    srcInfo.size.width = region.width;
    srcInfo.pixelFormat = imageInfo_.pixelFormat;
    if (!PixelYuvUtils::WriteYuvConvert(source + offset, srcInfo, data_, dstPosition, yuvDataInfo_)) {
        IMAGE_LOGE("write pixel by rect call WriteYuvConvert fail.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    return SUCCESS;
}

uint32_t PixelYuv::ReadPixels(const uint64_t &bufferSize, const uint32_t &offset, const uint32_t &stride,
    const Rect &region, uint8_t *dst)
{
    if (!CheckPixelsInput(dst, bufferSize, offset, region)) {
        IMAGE_LOGE("read pixels by rect input parameter fail.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    if (data_ == nullptr) {
        IMAGE_LOGE("read pixels by rect this pixel data is null.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    ImageInfo dstImageInfo;
    dstImageInfo.size.width = region.width;
    dstImageInfo.size.height = region.height;
    dstImageInfo.pixelFormat = imageInfo_.pixelFormat;

    Position srcPosition{region.left, region.top};
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    YuvImageInfo imageInfo = {PixelYuvUtils::ConvertFormat(imageInfo_.pixelFormat),
        imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, yuvDataInfo};
    if (!PixelYuvUtils::ReadYuvConvert((void *)data_, srcPosition, imageInfo, dst + offset, dstImageInfo)) {
        IMAGE_LOGE("read pixels by rect call ReadPixelsConvert fail.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return SUCCESS;
}

void PixelYuv::translate(float xAxis, float yAxis)
{
    if (xAxis == 0 && yAxis == 0) {
        return;
    }
    int32_t width = imageInfo_.size.width;
    int32_t height = imageInfo_.size.height;

    int32_t dstSize = GetImageSize(width, height);
    MemoryData memoryData = {nullptr, dstSize, "translate ImageData", {width, height}};
    auto dstMemory = MemoryManager::CreateMemory(allocatorType_, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("translate CreateMemory failed");
        return;
    }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType_ == AllocatorType::DMA_ALLOC) {
        if (dstMemory->extend.data == nullptr) {
            IMAGE_LOGE("GendstTransInfo get surfacebuffer failed");
        }
    }
#endif
    XYaxis xyAxis = {xAxis, yAxis};
    uint8_t *dst = reinterpret_cast<uint8_t *>(dstMemory->data.data);
    PixelYuvUtils::SetTranslateDataDefault(dst, width, height);
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    if (!PixelYuvUtils::YuvTranslate(data_, yuvDataInfo, dst, xyAxis, imageInfo_)) {
        dstMemory->Release();
        return;
    }
    imageInfo_.size.width = width;
    imageInfo_.size.height = height;

    SetPixelsAddr(dst, nullptr, dstSize, dstMemory->GetType(), nullptr);
    AssignYuvDataOnType(imageInfo_.pixelFormat, imageInfo_.size.width, imageInfo_.size.height);
}

uint32_t PixelYuv::ReadPixel(const Position &pos, uint32_t &dst)
{
    if (pos.x < 0 || pos.y < 0) {
        IMAGE_LOGE("read pixel by pos input invalid exception. [x(%{public}d), y(%{public}d)]", pos.x, pos.y);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("read pixel by pos source data is null.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    ColorYuv420 colorYuv = GetYuv420Color(abs(pos.x), abs(pos.y));
    dst = (colorYuv.colorY << Y_SHIFT) | (colorYuv.colorU << U_SHIFT) | (colorYuv.colorV << V_SHIFT);
    return SUCCESS;
}

bool PixelYuv::WritePixels(const uint32_t &color)
{
    if (data_ == nullptr) {
        IMAGE_LOGE("erase pixels by color current pixel map data is null.");
        return false;
    }

    return PixelYuvUtils::Yuv420WritePixels(yuvDataInfo_, data_, imageInfo_, color);
}

uint32_t PixelYuv::WritePixel(const Position &pos, const uint32_t &color)
{
    if (pos.x < 0 || pos.y < 0) {
        IMAGE_LOGE("write pixel by pos but input position is invalid. [x(%{public}d), y(%{public}d)]", pos.x, pos.y);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("write pixel by pos but current pixelmap data is nullptr.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    return PixelYuvUtils::YuvWritePixel(data_, yuvDataInfo_, imageInfo_.pixelFormat, pos, color);
}

ColorYuv420 PixelYuv::GetYuv420Color(uint32_t x, uint32_t y)
{
    ColorYuv420 colorYuv;
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);
    PixelFormat format = imageInfo.pixelFormat;
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    colorYuv.colorY = PixelYuvUtils::GetYuv420Y(x, y, yuvDataInfo, data_);
    colorYuv.colorU = PixelYuvUtils::GetYuv420U(x, y, yuvDataInfo, format, data_);
    colorYuv.colorV = PixelYuvUtils::GetYuv420V(x, y, yuvDataInfo, format, data_);
    return colorYuv;
}

void PixelYuv::SetPixelsAddr(void *addr, void *context, uint32_t size, AllocatorType type, CustomFreePixelMap func)
{
    if (data_ != nullptr) {
        IMAGE_LOGE("SetPixelsAddr release the existed data first");
        FreePixelMap();
    }
    if (type == AllocatorType::SHARE_MEM_ALLOC && context == nullptr) {
        IMAGE_LOGE("SetPixelsAddr error type %{public}d ", type);
    }
    data_ = static_cast<uint8_t *>(addr);
    context_ = context;
    pixelsSize_ = size;
    allocatorType_ = type;
    custFreePixelMap_ = func;
    if (type == AllocatorType::DMA_ALLOC && rowDataSize_ != 0) {
        SetImageInfo(imageInfo_, true);
    }
}

bool PixelYuv::CheckPixelsInput(const uint8_t *dst, const uint64_t &bufferSize, const uint32_t &offset,
    const Rect &region)
{
    if (dst == nullptr) {
        IMAGE_LOGE("CheckPixelsInput input dst address is null.");
        return false;
    }

    if (bufferSize == 0) {
        IMAGE_LOGE("CheckPixelsInput input buffer size is 0.");
        return false;
    }

    if (region.left < 0 || region.top < 0 || static_cast<uint64_t>(offset) > bufferSize) {
        IMAGE_LOGE("CheckPixelsInput left(%{public}d) or top(%{public}d) or offset(%{public}u) < 0.",
            region.left, region.top, offset);
        return false;
    }
    if (region.width <= 1 || region.height <= 1 || region.width > MAX_DIMENSION || region.height > MAX_DIMENSION) {
        IMAGE_LOGE("CheckPixelsInput width(%{public}d) or height(%{public}d) is < 0.", region.width,
            region.height);
        return false;
    }
    if (region.left > GetWidth() - region.width) {
        IMAGE_LOGE("CheckPixelsInput left(%{public}d) + width(%{public}d) is > PixelYuv width(%{public}d).",
            region.left, region.width, GetWidth());
        return false;
    }
    if (region.top > GetHeight() - region.height) {
        IMAGE_LOGE("CheckPixelsInput top(%{public}d) + height(%{public}d) is > PixelYuv height(%{public}d).",
            region.top, region.height, GetHeight());
        return false;
    }

    if (static_cast<uint64_t>(offset) > (bufferSize - NUM_3)) {
        IMAGE_LOGE(
            "CheckPixelsInput fail, height(%{public}d), width(%{public}d) "
            "offset(%{public}u), bufferSize:%{public}llu.",
            region.height, region.width, offset,
            static_cast<unsigned long long>(bufferSize));
        return false;
    }
    return true;
}

void PixelYuv::SetRowDataSizeForImageInfo(ImageInfo info)
{
    rowDataSize_ = info.size.width * NUM_3 / NUM_2;
    return;
}

uint32_t PixelYuv::GetImageSize(int32_t width, int32_t height)
{
    return width * height + ((width + 1) / NUM_2) * ((height + 1) / NUM_2) * NUM_2;
}

void PixelYuv::AssignYuvDataOnType(PixelFormat format, int32_t width, int32_t height)
{
    if (format == PixelFormat::NV12 || format == PixelFormat::NV21) {
        yuvDataInfo_.yWidth = width;
        yuvDataInfo_.yHeight = height;
        yuvDataInfo_.yStride = width;
        yuvDataInfo_.uvWidth = GetUStride(width);
        yuvDataInfo_.uvHeight = GetUVHeight(height);
        yuvDataInfo_.uvStride = GetUVStride(width);
        yuvDataInfo_.yOffset = 0;
        yuvDataInfo_.uvOffset =  yuvDataInfo_.yHeight * yuvDataInfo_.yStride;
    }
}

bool PixelYuv::IsYuvFormat(PixelFormat format)
{
    return format == PixelFormat::NV21 || format == PixelFormat::NV12;
}

#ifdef IMAGE_COLORSPACE_FLAG
uint32_t PixelYuv::SetColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace, SkTransYuvInfo &src,
    PixelFormat &format, uint64_t rowStride)
{
    int32_t width = yuvDataInfo_.yStride;
    int32_t height = yuvDataInfo_.yHeight;
    // Build sk target infomation
    SkTransYuvInfo dst;
    dst.info = ToSkImageInfo(imageInfo_, grColorSpace.ToSkColorSpace());
    MemoryData memoryData = {nullptr, width * height * NUM_4, "ApplyColorSpace ImageData",
        {dst.info.width(), dst.info.height()}};
    auto dstMemory = MemoryManager::CreateMemory(allocatorType_, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("applyColorSpace CreateMemory failed");
        return ERR_IMAGE_COLOR_CONVERT;
    }
    // Transfor pixels by readPixels
    if (!src.bitmap.readPixels(dst.info, dstMemory->data.data, rowStride, 0, 0)) {
        dstMemory->Release();
        IMAGE_LOGE("ReadPixels failed");
        return ERR_IMAGE_COLOR_CONVERT;
    }

    uint8_t *bgraData = reinterpret_cast<uint8_t *>(dstMemory->data.data);
    if (ColorSpaceBGRAToYuv(bgraData, dst, imageInfo_, format, grColorSpace) != SUCCESS) {
        dstMemory->Release();
        IMAGE_LOGE("ColorSpaceBGRAToYuv failed");
        return ERR_IMAGE_COLOR_CONVERT;
    }
    SetImageInfo(imageInfo_, true);
    return SUCCESS;
}

static void ToImageInfo(ImageInfo &info, SkImageInfo &skInfo, bool sizeOnly = true)
{
    info.size.width = skInfo.width();
    info.size.height = skInfo.height();
    if (!sizeOnly) {
        info.alphaType = ImageTypeConverter::ToAlphaType(skInfo.alphaType());
        info.pixelFormat = ImageTypeConverter::ToPixelFormat(skInfo.colorType());
    }
}

bool PixelYuv::CheckColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace)
{
    auto grName = grColorSpace.GetColorSpaceName();
    if (grColorSpace_ != nullptr && isSameColorSpace(*grColorSpace_, grColorSpace)) {
        if (grColorSpace_->GetColorSpaceName() != grName) {
            InnerSetColorSpace(grColorSpace);
            IMAGE_LOGI("applyColorSpace inner set");
        }
        return true;
    }
    return false;
}

int32_t PixelYuv::ColorSpaceBGRAToYuv(uint8_t *bgraData, SkTransYuvInfo &dst, ImageInfo &imageInfo,
    PixelFormat &format, const OHOS::ColorManager::ColorSpace &grColorSpace)
{
    int32_t dstWidth = dst.info.width();
    int32_t dstHeight = dst.info.height();
    uint32_t pictureSize = GetImageSize(dstWidth, dstHeight);
    MemoryData memoryYuvData = {nullptr, pictureSize, "Trans ImageData", {dstWidth, dstHeight}};
    auto yuvMemory = MemoryManager::CreateMemory(allocatorType_, memoryYuvData);
    if (yuvMemory == nullptr) {
        yuvMemory->Release();
        IMAGE_LOGE("applyColorSpace CreateYuvMemory failed");
        return ERR_IMAGE_COLOR_CONVERT;
    }
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(PixelFormat::BGRA_8888),
        imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, yuvDataInfo_};
    YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(format),
        imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, yuvDataInfo_};
    if (!PixelYuvUtils::BGRAToYuv420(bgraData, srcInfo, reinterpret_cast<uint8_t *>(yuvMemory->data.data), dstInfo)) {
        IMAGE_LOGE("applyColorSpace BGRAToYuv420 failed");
            return ERR_IMAGE_COLOR_CONVERT;
        }
    imageInfo.pixelFormat = format;
    dst.info = ToSkImageInfo(imageInfo, grColorSpace.ToSkColorSpace());
    ToImageInfo(imageInfo, dst.info);
    auto grName = grColorSpace.GetColorSpaceName();
    grColorSpace_ = std::make_shared<OHOS::ColorManager::ColorSpace>(dst.info.refColorSpace(), grName);
    SetPixelsAddr(reinterpret_cast<void *>(yuvMemory->data.data), nullptr, pictureSize, yuvMemory->GetType(), nullptr);
    return SUCCESS;
}

uint32_t PixelYuv::ApplyColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace)
{
    if (CheckColorSpace(grColorSpace)) {
        return SUCCESS;
    }
    PixelFormat format = imageInfo_.pixelFormat;
    imageInfo_.pixelFormat = PixelFormat::BGRA_8888;
    SkTransYuvInfo src;
    src.info = ToSkImageInfo(imageInfo_, ToSkColorSpace(this));
    uint64_t rowStride = src.info.minRowBytes();
    uint8_t *srcData = data_;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (GetAllocatorType() == AllocatorType::DMA_ALLOC && GetFd() != nullptr) {
        SurfaceBuffer *sbBuffer = reinterpret_cast<SurfaceBuffer *>(GetFd());
        rowStride = sbBuffer->GetStride();
    }
    srcData = static_cast<uint8_t *>(GetWritablePixels());
#endif

    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    int32_t width = yuvDataInfo.yStride;
    int32_t height = yuvDataInfo.yHeight;

    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(format),
        imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, yuvDataInfo};
    YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(PixelFormat::BGRA_8888),
        imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, yuvDataInfo};
    std::unique_ptr<uint8_t[]> RGBAdata = std::make_unique<uint8_t[]>(width * height * NUM_4);
    if (!PixelYuvUtils::Yuv420ToBGRA(srcData, srcInfo, RGBAdata.get(), dstInfo)) {
        IMAGE_LOGE("applyColorSpace Yuv420ToBGRA failed");
        return ERR_IMAGE_COLOR_CONVERT;
    }
    src.bitmap.installPixels(src.info, RGBAdata.get(), rowStride);
    return SetColorSpace(grColorSpace, src, format, rowStride);
}
#endif
} // namespace Media
} // namespace OHOS