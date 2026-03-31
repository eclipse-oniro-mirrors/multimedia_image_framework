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
#include <cmath>
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
#include "vpe_utils.h"
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
static const uint8_t RGBA_BIT_DEPTH = 4;
static const uint32_t TWO_SLICES = 2;
static const uint8_t YUV420_MIN_PIXEL_UINTBYTES = 4;
static const uint8_t YUV420P010_MIN_PIXEL_UINTBYTES = 8;
static const int32_t DEGREES90 = 90;
static const int32_t DEGREES180 = 180;
static const int32_t DEGREES270 = 270;
static const int32_t DEGREES360 = 360;
static const float ROUND_FLOAT_NUMBER = 0.5f;
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
    return PixelMap::GetByteCount();
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

bool PixelYuv::YuvRotateConvert(Size &size, int32_t degrees, int32_t &dstWidth, int32_t &dstHeight,
    OpenSourceLibyuv::RotationMode &rotateNum)
{
    switch (degrees) {
        case DEGREES90:
            dstWidth = size.height;
            dstHeight = size.width;
            rotateNum = OpenSourceLibyuv::RotationMode::kRotate90;
            return true;
        case DEGREES180:
            rotateNum = OpenSourceLibyuv::RotationMode::kRotate180;
            return true;
        case DEGREES270:
            dstWidth = size.height;
            dstHeight = size.width;
            rotateNum = OpenSourceLibyuv::RotationMode::kRotate270;
            return true;
        default:
            return false;
    }
}

bool PixelYuv::YuvRotateConvert(Size &srcSize, int32_t degrees, Size &dstSize,
                                OpenSourceLibyuv::RotationMode &rotateNum, YUVDataInfo yuvDataInfo)
{
    switch (degrees) {
        case DEGREES90:
            dstSize.width = srcSize.height;
            dstSize.height = std::max(static_cast<uint32_t>(srcSize.width), yuvDataInfo.yStride);
            rotateNum = OpenSourceLibyuv::RotationMode::kRotate90;
            return true;
        case DEGREES180:
            rotateNum = OpenSourceLibyuv::RotationMode::kRotate180;
            return true;
        case DEGREES270:
            dstSize.width = srcSize.height;
            dstSize.height = std::max(static_cast<uint32_t>(srcSize.width), yuvDataInfo.yStride);
            rotateNum = OpenSourceLibyuv::RotationMode::kRotate270;
            return true;
        default:
            return false;
    }
}

std::unique_ptr<AbsMemory> PixelYuv::CreateMemory(PixelFormat pixelFormat, std::string memoryTag, int32_t dstWidth,
    int32_t dstHeight, YUVStrideInfo &dstStrides)
{
    if (dstWidth <= 0 || dstHeight <= 0) {
        IMAGE_LOGE("CreateMemory invalid param, width:%{public}d, height:%{public}d", dstWidth, dstHeight);
        return nullptr;
    }
    if (dstHeight != 0 && dstWidth > (INT32_MAX / dstHeight)) {
        IMAGE_LOGE("CreateMemory invalid size (byte count) overflow");
        return nullptr;
    }
    uint32_t pictureSize = GetImageSize(dstWidth, dstHeight, pixelFormat);
    int32_t dst_yStride = dstWidth;
    int32_t dst_uvStride = (dstWidth + 1) / NUM_2 * NUM_2;
    int32_t dst_yOffset = 0;
    int32_t dst_uvOffset = dst_yStride * dstHeight;

    dstStrides = {dst_yStride, dst_uvStride, dst_yOffset, dst_uvOffset};
    MemoryData memoryData = {nullptr, pictureSize, memoryTag.c_str(), {dstWidth, dstHeight}, pixelFormat};
    memoryData.usage = GetNoPaddingUsage();
    auto m = MemoryManager::CreateMemory(allocatorType_, memoryData);
    if (m == nullptr) {
        IMAGE_LOGE("CreateMemory failed");
        return m;
    }
    IMAGE_LOGD("CreateMemory allocatorType: %{public}d", allocatorType_);
    #if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocatorType_ == AllocatorType::DMA_ALLOC) {
        if (m->extend.data == nullptr) {
            IMAGE_LOGE("CreateMemory get surfacebuffer failed");
            return m;
        }
        auto sb = reinterpret_cast<SurfaceBuffer*>(m->extend.data);
        OH_NativeBuffer_Planes *planes = nullptr;
        GSError retVal = sb->GetPlanesInfo(reinterpret_cast<void**>(&planes));
        if (retVal != OHOS::GSERROR_OK || planes == nullptr) {
            IMAGE_LOGE("CreateMemory Get planesInfo failed, retVal:%{public}d", retVal);
        } else if (planes->planeCount >= NUM_2) {
            int32_t pixelFmt = sb->GetFormat();
            ImageUtils::GetYUVStrideInfo(pixelFmt, planes, dstStrides);
        }
        sptr<SurfaceBuffer> sourceSurfaceBuffer(reinterpret_cast<SurfaceBuffer*>(GetFd()));
        sptr<SurfaceBuffer> dstSurfaceBuffer(reinterpret_cast<SurfaceBuffer*>(sb));
        VpeUtils::CopySurfaceBufferInfo(sourceSurfaceBuffer, dstSurfaceBuffer);
    }
    #endif
    return m;
}

void PixelYuv::rotate(float degrees)
{
    if (!IsYuvFormat() || degrees == 0) {
        return;
    }
    if (degrees < 0) {
        int n = abs(degrees / DEGREES360);
        degrees += DEGREES360 * (n + 1);
    }
    OpenSourceLibyuv::RotationMode rotateNum = OpenSourceLibyuv::RotationMode::kRotate0;
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    Size dstSize;
    dstSize.width = imageInfo_.size.width;
    dstSize.height = imageInfo_.size.height;
    if (!YuvRotateConvert(imageInfo_.size, degrees, dstSize, rotateNum, yuvDataInfo)) {
        IMAGE_LOGI("rotate degress is invalid, don't need rotate");
        return ;
    }
    YUVStrideInfo dstStrides;
    auto dstMemory = CreateMemory(imageInfo_.pixelFormat, "Rotate ImageData",
                                  dstSize.width, dstSize.height, dstStrides);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("rotate CreateMemory failed");
        return;
    }

    uint8_t *dst = reinterpret_cast<uint8_t *>(dstMemory->data.data);
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
    UpdateYUVDataInfo(imageInfo_.pixelFormat, imageInfo_.size.width, imageInfo_.size.height, dstStrides);
    ImageUtils::FlushSurfaceBuffer(this);
    AddVersionId();
}

uint32_t PixelYuv::crop(const Rect &rect)
{
    int32_t rectSize = GetYSize(rect.width, rect.height);
    int32_t pixelSize = GetYSize(imageInfo_.size.width, imageInfo_.size.height);
    if (rect.top < 0 || rect.left < 0 || rectSize > pixelSize || rect.width <= 1 || rect.height <= 1 ||
        !IsYuvFormat()) {
        IMAGE_LOGE("crop invalid param");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    YUVStrideInfo dstStrides;
    auto dstMemory = CreateMemory(imageInfo_.pixelFormat, "crop ImageData", rect.width, rect.height, dstStrides);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("crop CreateMemory failed");
        return ERR_IMAGE_CROP;
    }
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(imageInfo_.pixelFormat),
        imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, yuvDataInfo};
    if (!PixelYuvUtils::YuvCrop(data_, srcInfo, (uint8_t *)dstMemory->data.data, rect, dstStrides)) {
        dstMemory->Release();
        return ERR_IMAGE_CROP;
    }
    SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data,
        GetImageSize(rect.width, rect.height, imageInfo_.pixelFormat), dstMemory->GetType(), nullptr);
    imageInfo_.size.height = rect.height;
    imageInfo_.size.width = rect.width;
    SetImageInfo(imageInfo_, true);
    UpdateYUVDataInfo(imageInfo_.pixelFormat, rect.width, rect.height, dstStrides);
    AddVersionId();
    return SUCCESS;
}

void PixelYuv::scale(float xAxis, float yAxis)
{
    ImageTrace imageTrace("PixelMap scale");
    return scale(xAxis, yAxis, AntiAliasingOption::NONE);
}

void PixelYuv::scale(int32_t dstW, int32_t dstH)
{
    ImageTrace imageTrace("PixelMap scale");
    return scale(dstW, dstH, AntiAliasingOption::NONE);
}

bool PixelYuv::resize(int32_t dstW, int32_t dstH)
{
    ImageTrace imageTrace("PixelMap resize");
    scale(dstW, dstH, AntiAliasingOption::NONE);
    return true;
}

bool PixelYuv::resize(float xAxis, float yAxis)
{
    ImageTrace imageTrace("PixelMap resize");
    scale(xAxis, yAxis, AntiAliasingOption::NONE);
    return true;
}

bool PixelYuv::resizeForPicture(int32_t dstW, int32_t dstH)
{
    ImageTrace imageTrace("PixelMap resizeForPicture");
    int32_t rowSize = ImageUtils::GetRowDataSizeByPixelFormat(dstW, PixelFormat::NV21);
    if (dstH == 0) {
        return false;
    }
    bool cond = rowSize <= 0 || dstH <= 0 || rowSize > std::numeric_limits<int32_t>::max() / dstH;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s rowSize: %{public}d, height: %{public}d may overflowed",
        __func__, rowSize, dstH);
    uint32_t pictureSize = static_cast<uint32_t>(rowSize * dstH);
    CHECK_ERROR_RETURN_RET_LOG(SkImageInfo::ByteSizeOverflowed(pictureSize), false,
        "%{public}s too large byteCount: %{public}llu", __func__, static_cast<unsigned long long>(pictureSize));
    scale(dstW, dstH, AntiAliasingOption::NONE);
    return true;
}

void PixelYuv::scale(float xAxis, float yAxis, const AntiAliasingOption &option)
{
    if (!IsYuvFormat()) {
        return;
    }
    ImageTrace imageTrace("PixelMap scale");
    if (xAxis == 1 && yAxis == 1 && option == AntiAliasingOption::NONE) {
        return;
    }
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);
    int32_t dstW = (imageInfo.size.width * xAxis + ROUND_FLOAT_NUMBER);
    int32_t dstH = (imageInfo.size.height * yAxis + ROUND_FLOAT_NUMBER);
    YUVStrideInfo dstStrides;
    auto dstMemory = CreateMemory(imageInfo.pixelFormat, "scale ImageData", dstW, dstH, dstStrides);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("scale CreateMemory failed");
        return;
    }
    uint8_t *yuvData = reinterpret_cast<uint8_t *>(dstMemory->data.data);
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(imageInfo.pixelFormat),
        imageInfo.size.width, imageInfo.size.height, imageInfo_.pixelFormat, yuvDataInfo};
    YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(imageInfo.pixelFormat),
        dstW, dstH, imageInfo_.pixelFormat, yuvDataInfo};
    if (PixelYuvUtils::YuvScale(data_, srcInfo, yuvData, dstInfo, PixelYuvUtils::YuvConvertOption(option)) != SUCCESS) {
        IMAGE_LOGE("ScaleYuv failed");
        dstMemory->Release();
        return;
    }
    imageInfo.size.height = dstH;
    imageInfo.size.width = dstW;

    SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size, dstMemory->GetType(), nullptr);
    SetImageInfo(imageInfo, true);
    UpdateYUVDataInfo(imageInfo.pixelFormat, imageInfo.size.width, imageInfo.size.height, dstStrides);
    ImageUtils::FlushSurfaceBuffer(this);
    AddVersionId();
}

void PixelYuv::scale(int32_t dstW, int32_t dstH, const AntiAliasingOption &option)
{
    if (!IsYuvFormat()) {
        return;
    }
    ImageInfo imageInfo;
    GetImageInfo(imageInfo);
    ImageTrace imageTrace("PixelMap scale");
    if (imageInfo.size.width == dstW && imageInfo.size.height == dstH && option == AntiAliasingOption::NONE) {
        return;
    }
    YUVStrideInfo dstStrides;
    auto dstMemory = CreateMemory(imageInfo.pixelFormat, "scale ImageData", dstW, dstH, dstStrides);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("scale CreateMemory failed");
        return;
    }
    uint8_t *yuvData = reinterpret_cast<uint8_t *>(dstMemory->data.data);
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(imageInfo.pixelFormat),
        imageInfo.size.width, imageInfo.size.height, imageInfo_.pixelFormat, yuvDataInfo};
    YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(imageInfo.pixelFormat),
        dstW, dstH, imageInfo_.pixelFormat, yuvDataInfo};
    if (PixelYuvUtils::YuvScale(data_, srcInfo, yuvData, dstInfo, PixelYuvUtils::YuvConvertOption(option)) != SUCCESS) {
        IMAGE_LOGE("ScaleYuv failed");
        dstMemory->Release();
        return;
    }
    imageInfo.size.height = dstH;
    imageInfo.size.width = dstW;
    SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size, dstMemory->GetType(), nullptr);
    SetImageInfo(imageInfo, true);
    UpdateYUVDataInfo(imageInfo.pixelFormat, imageInfo.size.width, imageInfo.size.height, dstStrides);
    ImageUtils::FlushSurfaceBuffer(this);
    AddVersionId();
}

void PixelYuv::flip(bool xAxis, bool yAxis)
{
    if (!IsYuvFormat()) {
        return;
    }
    if (xAxis == false && yAxis == false) {
        return;
    }
    int32_t srcW = imageInfo_.size.width;
    int32_t srcH = imageInfo_.size.height;
    PixelFormat format = imageInfo_.pixelFormat;
    const uint8_t *src = data_;
    YUVStrideInfo dstStrides;
    auto dstMemory = CreateMemory(imageInfo_.pixelFormat, "flip ImageData", srcW, srcH, dstStrides);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("flip CreateMemory failed");
        return;
    }
    uint8_t *dst = reinterpret_cast<uint8_t *>(dstMemory->data.data);
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(format), srcW, srcH, imageInfo_.pixelFormat, yuvDataInfo};
    YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(format), srcW, srcH, imageInfo_.pixelFormat, yuvDataInfo};
    if (xAxis && yAxis) {
        if (!PixelYuvUtils::YuvReversal(const_cast<uint8_t *>(src), srcInfo, dst, dstInfo)) {
            IMAGE_LOGE("flip yuv xAxis and yAxis failed");
            dstMemory->Release();
            return;
        }
    } else {
        bool isXaxis = ((xAxis | yAxis) && xAxis) ? true : false;
        if (!PixelYuvUtils::YuvFlip(const_cast<uint8_t *>(src), srcInfo, dst, isXaxis)) {
            IMAGE_LOGE("flip yuv xAxis or yAxis failed");
            dstMemory->Release();
            return;
        }
    }
    SetPixelsAddr(dst, dstMemory->extend.data, dstMemory->data.size, dstMemory->GetType(), nullptr);
    UpdateYUVDataInfo(format, srcW, srcH, dstStrides);
    AddVersionId();
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
    int32_t bytesPerPixel = ImageUtils::GetPixelBytes(imageInfo_.pixelFormat);
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
    AddVersionId();
    return SUCCESS;
}

void PixelYuv::GetYUVInfoForCopyPixels(YUVDataInfo &yuvDataInfo)
{
    GetImageYUVInfo(yuvDataInfo);
    yuvDataInfo.imageSize = imageInfo_.size;
    yuvDataInfo.yWidth = static_cast<uint32_t>(imageInfo_.size.width);
    yuvDataInfo.yHeight = static_cast<uint32_t>(imageInfo_.size.height);
    yuvDataInfo.uvWidth = yuvDataInfo.uvWidth * NUM_2;
    if (IsP010Yuv()) {
        yuvDataInfo.yWidth = static_cast<uint32_t>(imageInfo_.size.width) * NUM_2;
        yuvDataInfo.uvWidth = yuvDataInfo.yWidth;
        yuvDataInfo.yOffset = yuvDataInfo.yOffset * NUM_2;
        yuvDataInfo.yStride = yuvDataInfo.yStride * NUM_2;
        yuvDataInfo.uvOffset = yuvDataInfo.uvOffset * NUM_2;
        yuvDataInfo.uvStride = yuvDataInfo.uvStride * NUM_2;
    }
}

uint32_t PixelYuv::WritePixels(const uint8_t *source, const uint64_t &bufferSize)
{
    if (!IsYuvFormat()) {
        IMAGE_LOGE("PixelYuv WritePixels Not YUV format");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    if (source == nullptr || data_ == nullptr) {
        IMAGE_LOGE("PixelYuv write pixels by buffer source or current pixelmap data is nullptr");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    auto requiredBufferSize = GetByteCount();
    if (bufferSize < requiredBufferSize) {
        IMAGE_LOGE("PixelYuv write pixels by buffer bufferSize error.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!IsEditable()) {
        IMAGE_LOGE("PixelYuv write pixels by buffer pixelmap data is not editable.");
        return ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY;
    }
    if (!ImageUtils::IsValidImageInfo(imageInfo_)) {
        IMAGE_LOGE("PixelYuv write pixels by buffer current pixelmap image info is invalid.");
        return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
    }
    YUVDataInfo yuvDataInfo;
    GetYUVInfoForCopyPixels(yuvDataInfo);
    auto srcY = source;
    auto srcUV = source + yuvDataInfo.yWidth * yuvDataInfo.yHeight;
    auto dstY = data_ + yuvDataInfo.yOffset;
    auto dstUV = data_ + yuvDataInfo.uvOffset;
    /* copy Y plane*/
    for (int32_t y = 0; y < static_cast<int32_t>(yuvDataInfo.yHeight); y++) {
        if (memcpy_s(dstY, yuvDataInfo.yWidth, srcY, yuvDataInfo.yWidth) != EOK) {
            IMAGE_LOGE("PixelYuv write pixels yInfo failed.");
            return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
        }
        dstY += yuvDataInfo.yStride;
        srcY += yuvDataInfo.yWidth;
    }
    /* copy UV plane*/
    for (int32_t y = 0; y < static_cast<int32_t>(yuvDataInfo.uvHeight); y++) {
        if (memcpy_s(dstUV, yuvDataInfo.uvWidth, srcUV, yuvDataInfo.uvWidth) != EOK) {
            IMAGE_LOGE("PixelYuv write pixels uvInfo failed.");
            return ERR_IMAGE_WRITE_PIXELMAP_FAILED;
        }
        dstUV += yuvDataInfo.uvStride;
        srcUV += yuvDataInfo.uvWidth;
    }
    AddVersionId();
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

bool PixelYuv::IsP010Yuv()
{
    if (imageInfo_.pixelFormat == PixelFormat::YCBCR_P010 || imageInfo_.pixelFormat == PixelFormat::YCRCB_P010) {
        return true;
    }
    return false;
}

uint32_t PixelYuv::ReadPixels(const uint64_t &bufferSize, uint8_t *dst)
{
    if (!IsYuvFormat()) {
        IMAGE_LOGE("PixelYuv ReadPixels Not YUV format");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    IMAGE_LOGD("PixelYuv ReadPixels by bufferSize");
    if (dst == nullptr) {
        IMAGE_LOGE("PixelYuv read pixels by buffer input dst address is null.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    if (data_ == nullptr) {
        IMAGE_LOGE("PixelYuv read pixels by buffer current PixelMap data is null.");
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    auto requiredBufferSize = GetByteCount();
    IMAGE_LOGD("PixelYuv requiredBufferSize: %{public}d", requiredBufferSize);

    if (bufferSize < static_cast<uint64_t>(requiredBufferSize)) {
        IMAGE_LOGE("PixelYuv read pixels dst buffer(%{public}llu) < current pixelmap size(%{public}u).",
            static_cast<unsigned long long>(bufferSize), requiredBufferSize);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    YUVDataInfo yuvDataInfo;
    GetYUVInfoForCopyPixels(yuvDataInfo);
    uint8_t *srcUVPixels = data_ + yuvDataInfo.uvOffset;
    uint8_t *srcYPixels = data_ + yuvDataInfo.yOffset;
    /* copy Y plane*/
    for (int32_t y = 0; y<static_cast<int32_t>(yuvDataInfo.yHeight); y++) {
        if (memcpy_s(dst, yuvDataInfo.yWidth, srcYPixels, yuvDataInfo.yWidth) != EOK) {
            IMAGE_LOGE("PixelYuv read pixels yInfo failed.");
            return ERR_IMAGE_INVALID_PARAMETER;
        }
        dst += yuvDataInfo.yWidth;
        srcYPixels += yuvDataInfo.yStride;
    }
    /* copy UV plane*/
    for (int32_t y = 0; y<static_cast<int32_t>(yuvDataInfo.uvHeight); y++) {
        if (memcpy_s(dst, yuvDataInfo.uvWidth, srcUVPixels, yuvDataInfo.uvWidth) != EOK) {
            IMAGE_LOGE("PixelYuv read pixels uvInfo failed.");
            return ERR_IMAGE_INVALID_PARAMETER;
        }
        dst += yuvDataInfo.uvWidth;
        srcUVPixels += yuvDataInfo.uvStride;
    }
    return SUCCESS;
}

void PixelYuv::translate(float xAxis, float yAxis)
{
    if (!IsYuvFormat()) {
        IMAGE_LOGE("translate not yuv format");
        return;
    }
    if (!PixelYuvUtils::IsLegalAxis(xAxis, yAxis, imageInfo_)) {
        return;
    }
    int32_t width = imageInfo_.size.width + xAxis;
    int32_t height = imageInfo_.size.height + yAxis;
    PixelFormat format = imageInfo_.pixelFormat;
    YUVStrideInfo dstStrides;
    auto dstMemory = CreateMemory(imageInfo_.pixelFormat, "translate ImageData", width, height, dstStrides);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("translate CreateMemory failed");
        return;
    }
    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    XYaxis xyAxis = {xAxis, yAxis};
    uint8_t *dst = reinterpret_cast<uint8_t *>(dstMemory->data.data);
    PixelYuvUtils::SetTranslateDataDefault(dst, width, height, format, dstStrides);

    if (!PixelYuvUtils::YuvTranslate(data_, yuvDataInfo, dst, xyAxis, imageInfo_, dstStrides)) {
        dstMemory->Release();
        return;
    }
    imageInfo_.size.width = width;
    imageInfo_.size.height = height;

    uint32_t dstSize = GetImageSize(width, height, format);
    SetPixelsAddr(dst, dstMemory->extend.data, dstSize, dstMemory->GetType(), nullptr);
    UpdateYUVDataInfo(imageInfo_.pixelFormat, width, height, dstStrides);
    AddVersionId();
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
    if (!IsYuvFormat() || data_ == nullptr) {
        IMAGE_LOGE("erase pixels by color current pixel map data is null.");
        return false;
    }

    return PixelYuvUtils::Yuv420WritePixels(yuvDataInfo_, data_, imageInfo_, color);
}

uint32_t PixelYuv::WritePixel(const Position &pos, const uint32_t &color)
{
    if (!IsYuvFormat() || (pos.x < 0 || pos.y < 0)) {
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
        IMAGE_LOGD("SetPixelsAddr release the existed data first");
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
    ImageUtils::FlushSurfaceBuffer(this);
}

static bool IsYUVP010Format(PixelFormat format)
{
    return format == PixelFormat::YCBCR_P010 || format == PixelFormat::YCRCB_P010;
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

    if (IsYUVP010Format(imageInfo_.pixelFormat)) {
        if ((static_cast<uint64_t>(offset) + YUV420P010_MIN_PIXEL_UINTBYTES) >= bufferSize) {
            IMAGE_LOGE(
                "CheckPixelsInput fail, height(%{public}d), width(%{public}d) "
                "offset(%{public}u), bufferSize:%{public}llu.",
                region.height, region.width, offset,
                static_cast<unsigned long long>(bufferSize));
            return false;
        }
    } else {
        if ((static_cast<uint64_t>(offset) + YUV420_MIN_PIXEL_UINTBYTES) >= bufferSize) {
            IMAGE_LOGE(
                "CheckPixelsInput fail, height(%{public}d), width(%{public}d) "
                "offset(%{public}u), bufferSize:%{public}llu.",
                region.height, region.width, offset,
                static_cast<unsigned long long>(bufferSize));
            return false;
        }
    }
    return true;
}

void PixelYuv::SetRowDataSizeForImageInfo(ImageInfo info)
{
    rowDataSize_ = info.size.width * NUM_3 / NUM_2;
    if (IsYUVP010Format(info.pixelFormat)) {
        rowDataSize_ *= NUM_2;
    }
    return;
}

uint32_t PixelYuv::GetImageSize(int32_t width, int32_t height, PixelFormat format)
{
    uint32_t size = static_cast<uint32_t>(GetYSize(width, height) +
                                          GetUStride(width) * GetUVHeight(height) * TWO_SLICES);
    if (IsYUVP010Format(format)) {
        size *= NUM_2;
    }
    return size;
}


#ifdef IMAGE_COLORSPACE_FLAG
uint32_t PixelYuv::SetColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace, SkTransYuvInfo &src,
    PixelFormat &format, uint64_t rowStride)
{
    int32_t width = static_cast<int32_t>(yuvDataInfo_.yStride);
    int32_t height = static_cast<int32_t>(yuvDataInfo_.yHeight);
    if (!PixelYuvUtils::CheckWidthAndHeightMult(width, height, RGBA_BIT_DEPTH)) {
        IMAGE_LOGE("SetColorSpace size overflow width(%{public}d), height(%{public}d)", width, height);
        return ERR_IMAGE_COLOR_CONVERT;
    }
    // Build sk target infomation
    SkTransYuvInfo dst;
    dst.info = ToSkImageInfo(imageInfo_, grColorSpace.ToSkColorSpace());
    MemoryData memoryData = {nullptr, width * height * NUM_4, "ApplyColorSpace ImageData",
        {dst.info.width(), dst.info.height()}};
    memoryData.usage = GetNoPaddingUsage();
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
    uint32_t pictureSize = GetImageSize(dstWidth, dstHeight, format);
    MemoryData memoryYuvData = {nullptr, pictureSize, "Trans ImageData", {dstWidth, dstHeight}};
    memoryYuvData.usage = GetNoPaddingUsage();
    auto yuvMemory = MemoryManager::CreateMemory(allocatorType_, memoryYuvData);
    if (yuvMemory == nullptr) {
        IMAGE_LOGE("applyColorSpace CreateYuvMemory failed");
        return ERR_IMAGE_COLOR_CONVERT;
    }
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(PixelFormat::BGRA_8888),
        imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, yuvDataInfo_};
    YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(format),
        imageInfo_.size.width, imageInfo_.size.height, imageInfo_.pixelFormat, yuvDataInfo_};
    if (!PixelYuvUtils::BGRAToYuv420(bgraData, srcInfo, reinterpret_cast<uint8_t *>(yuvMemory->data.data), dstInfo)) {
        IMAGE_LOGE("applyColorSpace BGRAToYuv420 failed");
        yuvMemory->Release();
        return ERR_IMAGE_COLOR_CONVERT;
    }
    imageInfo.pixelFormat = format;
    dst.info = ToSkImageInfo(imageInfo, grColorSpace.ToSkColorSpace());
    ToImageInfo(imageInfo, dst.info);
    auto grName = grColorSpace.GetColorSpaceName();
    grColorSpace_ = std::make_shared<OHOS::ColorManager::ColorSpace>(dst.info.refColorSpace(), grName);
    SetPixelsAddr(reinterpret_cast<void *>(yuvMemory->data.data), yuvMemory->extend.data, pictureSize,
        yuvMemory->GetType(), nullptr);
    AddVersionId();
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
        rowStride = static_cast<uint64_t>(sbBuffer->GetStride());
    }
    srcData = static_cast<uint8_t *>(GetWritablePixels());
#endif

    YUVDataInfo yuvDataInfo;
    GetImageYUVInfo(yuvDataInfo);
    int32_t width = static_cast<int32_t>(yuvDataInfo.yStride);
    int32_t height = static_cast<int32_t>(yuvDataInfo.yHeight);
    if (!PixelYuvUtils::CheckWidthAndHeightMult(width, height, RGBA_BIT_DEPTH)) {
        IMAGE_LOGE("ApplyColorSpace size overflow width(%{public}d), height(%{public}d)", width, height);
        return ERR_IMAGE_COLOR_CONVERT;
    }
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

static bool CopyYuvPlanes(PixelMap &source, PixelMap &dstPixelMap)
{
    ImageInfo srcInfo;
    ImageInfo dstInfo;
    source.GetImageInfo(srcInfo);
    dstPixelMap.GetImageInfo(dstInfo);
    bool cond = !ImageUtils::IsYuvFormat(srcInfo.pixelFormat) || srcInfo.pixelFormat != dstInfo.pixelFormat;
    CHECK_ERROR_RETURN_RET(cond, false);
    cond = (source.GetPixels() == nullptr || dstPixelMap.GetPixels() == nullptr);
    CHECK_ERROR_RETURN_RET(cond, false);
    cond = (srcInfo.size.width != dstInfo.size.width || srcInfo.size.height != dstInfo.size.height);
    CHECK_ERROR_RETURN_RET(cond, false);

    YUVDataInfo srcYuv {};
    YUVDataInfo dstYuv {};
    source.GetImageYUVInfo(srcYuv);
    dstPixelMap.GetImageYUVInfo(dstYuv);

    const bool isP010 = (srcInfo.pixelFormat == PixelFormat::YCBCR_P010 ||
        srcInfo.pixelFormat == PixelFormat::YCRCB_P010);
    const uint32_t bytesPerSample = isP010 ? 2 : 1;

    auto srcBase = const_cast<uint8_t *>(source.GetPixels());
    auto dstBase = const_cast<uint8_t *>(dstPixelMap.GetPixels());
    const uint32_t srcCapacity = source.GetCapacity();
    const uint32_t dstCapacity = dstPixelMap.GetCapacity();

    const uint64_t srcYStrideBytes = static_cast<uint64_t>(srcYuv.yStride) * bytesPerSample;
    const uint64_t srcUvStrideBytes = static_cast<uint64_t>(srcYuv.uvStride) * bytesPerSample;
    const uint64_t dstYStrideBytes = static_cast<uint64_t>(dstYuv.yStride) * bytesPerSample;
    const uint64_t dstUvStrideBytes = static_cast<uint64_t>(dstYuv.uvStride) * bytesPerSample;
    const uint64_t srcYOffsetBytes = static_cast<uint64_t>(srcYuv.yOffset) * bytesPerSample;
    const uint64_t srcUvOffsetBytes = static_cast<uint64_t>(srcYuv.uvOffset) * bytesPerSample;
    const uint64_t dstYOffsetBytes = static_cast<uint64_t>(dstYuv.yOffset) * bytesPerSample;
    const uint64_t dstUvOffsetBytes = static_cast<uint64_t>(dstYuv.uvOffset) * bytesPerSample;

    const uint64_t yRowBytes = static_cast<uint64_t>(srcInfo.size.width) * bytesPerSample;
    const uint64_t uvRowBytes = static_cast<uint64_t>(srcYuv.uvWidth) * 2ULL * bytesPerSample;
    const uint64_t yPlaneBytes = srcYStrideBytes * static_cast<uint64_t>(srcYuv.yHeight);
    const uint64_t uvPlaneBytes = srcUvStrideBytes * static_cast<uint64_t>(srcYuv.uvHeight);

    cond = (srcYOffsetBytes + yPlaneBytes > srcCapacity || srcUvOffsetBytes + uvPlaneBytes > srcCapacity);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CopyYuvPlanes source out of range, capacity=%{public}u", srcCapacity);

    cond = (dstYOffsetBytes + dstYStrideBytes * static_cast<uint64_t>(dstYuv.yHeight) > dstCapacity ||
        dstUvOffsetBytes + dstUvStrideBytes * static_cast<uint64_t>(dstYuv.uvHeight) > dstCapacity);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CopyYuvPlanes destination out of range, capacity=%{public}u", dstCapacity);
    
    cond = (yRowBytes > srcYStrideBytes || yRowBytes > dstYStrideBytes || uvRowBytes > srcUvStrideBytes ||
        uvRowBytes > dstUvStrideBytes);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CopyYuvPlanes invalid stride for yuv copy");

    for (uint32_t row = 0; row < srcYuv.yHeight; ++row) {
        const uint8_t *srcRow = srcBase + srcYOffsetBytes + row * srcYStrideBytes;
        uint8_t *dstRow = dstBase + dstYOffsetBytes + row * dstYStrideBytes;

        cond = (memcpy_s(dstRow, static_cast<size_t>(dstYStrideBytes), srcRow, static_cast<size_t>(yRowBytes)) != EOK);
        CHECK_ERROR_RETURN_RET_LOG(cond, false, "CopyYuvPlanes y plane copy failed");
    }

    for (uint32_t row = 0; row < srcYuv.uvHeight; ++row) {
        const uint8_t *srcRow = srcBase + srcUvOffsetBytes + row * srcUvStrideBytes;
        uint8_t *dstRow = dstBase + dstUvOffsetBytes + row * dstUvStrideBytes;
        
        cond = (memcpy_s(dstRow, static_cast<size_t>(dstUvStrideBytes), srcRow,
            static_cast<size_t>(uvRowBytes)) != EOK);
        CHECK_ERROR_RETURN_RET_LOG(cond, false, "CopyYuvPlanes uv plane copy failed");
    }

    ImageUtils::FlushSurfaceBuffer(&dstPixelMap);
    return true;
}

std::unique_ptr<PixelMap> PixelYuv::CloneYuvImpl(PixelMap &source, int32_t &errorCode)
{
    ImageInfo imageInfo;
    source.GetImageInfo(imageInfo);
    if (!ImageUtils::IsYuvFormat(imageInfo.pixelFormat)) {
        errorCode = ERR_IMAGE_READ_PIXELMAP_FAILED;
        return nullptr;
    }
    if (imageInfo.size.width <= 0 || imageInfo.size.height <= 0) {
        errorCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }

    InitializationOptions opts;
    opts.srcPixelFormat = imageInfo.pixelFormat;
    opts.pixelFormat = imageInfo.pixelFormat;
    opts.alphaType = imageInfo.alphaType;
    opts.size = imageInfo.size;
    opts.editable = source.IsEditable();
    opts.useDMA = (source.GetAllocatorType() == AllocatorType::DMA_ALLOC);
    auto dstPixelMap = PixelMap::Create(opts);
    if (dstPixelMap == nullptr) {
        errorCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }

    if (!CopyYuvPlanes(source, *dstPixelMap.get())) {
        errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
        return nullptr;
    }

    dstPixelMap->SetTransformered(source.IsTransformered());
    TransformData transformData;
    source.GetTransformData(transformData);
    dstPixelMap->SetTransformData(transformData);
    dstPixelMap->SetHdrType(source.GetHdrType());
    dstPixelMap->SetHdrMetadata(source.GetHdrMetadata());

#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace colorspace = source.InnerGetGrColorSpace();
    dstPixelMap->InnerSetColorSpace(colorspace);
#endif

    errorCode = SUCCESS;
    return dstPixelMap;
}

static void GetYuvDataInfo(PixelMap &source, YUVDataInfo &yuvDataInfo)
{
    // For DMA allocator, retrieve correct stride/offset from SurfaceBuffer planes.
    // The stride/offset returned by GetImageYUVInfo may be incomplete or incorrect for DMA buffers in some scenes.
    if (source.GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        SurfaceBuffer *sb = reinterpret_cast<SurfaceBuffer *>(source.GetFd());
        if (sb != nullptr) {
            OH_NativeBuffer_Planes *planes = nullptr;
            GSError retVal = sb->GetPlanesInfo(reinterpret_cast<void**>(&planes));
            if (retVal == OHOS::GSERROR_OK && planes != nullptr && planes->planeCount >= NUM_2) {
                int32_t pixelFmt = sb->GetFormat();
                YUVStrideInfo strideInfo;
                ImageUtils::GetYUVStrideInfo(pixelFmt, planes, strideInfo);
                if (strideInfo.yStride > 0 && strideInfo.uvStride > 0) {
                    yuvDataInfo.yStride = strideInfo.yStride;
                    yuvDataInfo.uvStride = strideInfo.uvStride;
                    yuvDataInfo.yOffset = strideInfo.yOffset;
                    yuvDataInfo.uvOffset = strideInfo.uvOffset;
                    IMAGE_LOGD("CreateThumbnailPixelMap use DMA stride: yStride=%{public}d, uvStride=%{public}d",
                        yuvDataInfo.yStride, yuvDataInfo.uvStride);
                }
            } else {
                IMAGE_LOGE("CreateThumbnailPixelMap GetPlanesInfo failed, retVal:%{public}d", retVal);
            }
        }
    }
}

static void SetDstYuvDataInfo(Size size, YUVStrideInfo dstStrides, YUVDataInfo &dstYuvDataInfo)
{
    dstYuvDataInfo.imageSize = {size.width, size.height};
    dstYuvDataInfo.yWidth = static_cast<uint32_t>(size.width);
    dstYuvDataInfo.yHeight = static_cast<uint32_t>(size.height);
    dstYuvDataInfo.uvWidth = static_cast<uint32_t>((size.width + 1) / NUM_2);
    dstYuvDataInfo.uvHeight = static_cast<uint32_t>(GetUVHeight(size.height));
    dstYuvDataInfo.yStride = dstStrides.yStride;
    dstYuvDataInfo.uvStride = dstStrides.uvStride;
    dstYuvDataInfo.yOffset = dstStrides.yOffset;
    dstYuvDataInfo.uvOffset = dstStrides.uvOffset;
}

std::unique_ptr<PixelMap> CreateDstPixelMap(PixelMap &source, Size targetSize, std::unique_ptr<AbsMemory> dstMemory,
    YUVStrideInfo dstStrides, int32_t &errorCode)
{
    ImageInfo imageInfo;
    source.GetImageInfo(imageInfo);
    InitializationOptions opts;
    opts.srcPixelFormat = imageInfo.pixelFormat;
    opts.pixelFormat = imageInfo.pixelFormat;
    opts.alphaType = imageInfo.alphaType;
    opts.size = {targetSize.width, targetSize.height};
    opts.editable = source.IsEditable();
    opts.useDMA = (source.GetAllocatorType() == AllocatorType::DMA_ALLOC);
    auto dstPixelMap = PixelMap::Create(opts);
    if (dstPixelMap == nullptr) {
        dstMemory->Release();
        errorCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }
 
    dstPixelMap->SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size,
        dstMemory->GetType(), nullptr);
    imageInfo.size.width = targetSize.width;
    imageInfo.size.height = targetSize.height;
    if (dstPixelMap->SetImageInfo(imageInfo, true) != SUCCESS) {
        dstMemory->Release();
        errorCode = ERR_IMAGE_DATA_ABNORMAL;
        return nullptr;
    }
    dstPixelMap->UpdateYUVDataInfo(imageInfo.pixelFormat, targetSize.width, targetSize.height, dstStrides);
    ImageUtils::FlushSurfaceBuffer(dstPixelMap.get());
 
    dstPixelMap->SetTransformered(source.IsTransformered());
    TransformData transformData;
    source.GetTransformData(transformData);
    dstPixelMap->SetTransformData(transformData);
    dstPixelMap->SetHdrType(ImageHdrType::SDR);
    dstPixelMap->SetHdrMetadata(nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace colorspace = source.InnerGetGrColorSpace();
    dstPixelMap->InnerSetColorSpace(colorspace);
#endif
 
    errorCode = SUCCESS;
    return dstPixelMap;
}

std::unique_ptr<PixelMap> PixelYuv::CreateThumbnailPixelMap(PixelMap &source, int32_t maxPixelSize, int32_t &errorCode)
{
    ImageInfo imageInfo;
    source.GetImageInfo(imageInfo);
    if (!ImageUtils::IsYuvFormat(imageInfo.pixelFormat) || imageInfo.size.width <= 0 || imageInfo.size.height <= 0) {
        errorCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }
    Size targetSize;
    float scale = 1.0f;
    errorCode = ImageUtils::GetThumbnailScaleTargetSize(imageInfo.size, maxPixelSize, targetSize, scale);
    CHECK_ERROR_RETURN_RET(errorCode != SUCCESS, nullptr);
    if (scale == 1.0f) {
        return CloneYuvImpl(source, errorCode);
    }
    targetSize.width = targetSize.width - (targetSize.width % NUM_2);
    targetSize.height = targetSize.height - (targetSize.height % NUM_2);
    YUVStrideInfo dstStrides;
    void *srcSurfaceBuffer = nullptr;
#if !defined(CROSS_PLATFORM)
    if (source.GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        srcSurfaceBuffer = reinterpret_cast<void *>(source.GetFd());
    }
#endif
    auto dstMemory = PixelYuvUtils::CreateYuvMemory(imageInfo.pixelFormat, "thumbnail ImageData", targetSize.width,
        targetSize.height, source.GetAllocatorType(), source.GetNoPaddingUsage(), srcSurfaceBuffer, dstStrides);
    if (dstMemory == nullptr || dstMemory->data.data == nullptr) {
        errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
        return nullptr;
    }
 
    YUVDataInfo yuvDataInfo;
    source.GetImageYUVInfo(yuvDataInfo);
#if !defined(CROSS_PLATFORM)
    GetYuvDataInfo(source, yuvDataInfo);
#endif
 
    YUVDataInfo dstYuvDataInfo = yuvDataInfo;
    SetDstYuvDataInfo(targetSize, dstStrides, dstYuvDataInfo);
 
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(imageInfo.pixelFormat),
        imageInfo.size.width, imageInfo.size.height, imageInfo.pixelFormat, yuvDataInfo};
    YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(imageInfo.pixelFormat),
        targetSize.width, targetSize.height, imageInfo.pixelFormat, dstYuvDataInfo};
 
    uint8_t *dstData = reinterpret_cast<uint8_t *>(dstMemory->data.data);
    int32_t ret = PixelYuvUtils::YuvScale(const_cast<uint8_t *>(source.GetPixels()), srcInfo, dstData, dstInfo,
        PixelYuvUtils::YuvConvertOption(AntiAliasingOption::HIGH));
    if (ret != SUCCESS) {
        dstMemory->Release();
        errorCode = ERR_IMAGE_DATA_ABNORMAL;
        return nullptr;
    }
    return CreateDstPixelMap(source, targetSize, std::move(dstMemory), dstStrides, errorCode);
}
} // namespace Media
} // namespace OHOS