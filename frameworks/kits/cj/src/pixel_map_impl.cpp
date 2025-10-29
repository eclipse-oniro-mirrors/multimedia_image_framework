/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "pixel_map_impl.h"

#include "image_format_convert.h"
#include "image_log.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include <charconv>
#include <regex>

#include "pixel_map_from_surface.h"
#include "sync_fence.h"
#include "transaction/rs_interfaces.h"
#endif
#include "image_utils.h"
#include "media_errors.h"
#include "message_sequence_impl.h"

namespace {
constexpr uint32_t NUM_2 = 2;
}

enum class FormatType : int8_t { UNKNOWN, YUV, RGB, ASTC };

namespace OHOS {
namespace Media {
std::shared_ptr<PixelMap> PixelMapImpl::GetRealPixelMap()
{
    return real_;
}

std::unique_ptr<PixelMap> PixelMapImpl::CreatePixelMap(const InitializationOptions& opts)
{
    if (opts.pixelFormat == PixelFormat::RGBA_1010102 || opts.pixelFormat == PixelFormat::YCBCR_P010 ||
        opts.pixelFormat == PixelFormat::YCRCB_P010) {
        return nullptr;
    }
    std::unique_ptr<PixelMap> ptr_ = PixelMap::Create(opts);
    if (ptr_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] instance init failed!");
    }
    return ptr_;
}

std::unique_ptr<PixelMap> PixelMapImpl::CreatePixelMap(
    uint32_t* colors, uint32_t& colorLength, InitializationOptions& opts)
{
    if (opts.pixelFormat == PixelFormat::RGBA_1010102 || opts.pixelFormat == PixelFormat::YCBCR_P010 ||
        opts.pixelFormat == PixelFormat::YCRCB_P010) {
        return nullptr;
    }
    std::unique_ptr<PixelMap> ptr_ = PixelMap::Create(colors, colorLength, opts);
    if (ptr_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] instance init failed!");
    }
    return ptr_;
}

std::unique_ptr<PixelMap> PixelMapImpl::CreateAlphaPixelMap(PixelMap& source, InitializationOptions& opts)
{
    std::unique_ptr<PixelMap> ptr_ = PixelMap::Create(source, opts);
    if (ptr_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] instance init failed!");
    }
    return ptr_;
}

uint32_t PixelMapImpl::CreatePremultipliedPixelMap(std::shared_ptr<PixelMap> src, std::shared_ptr<PixelMap> dst)
{
    if (src == nullptr || dst == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    } else {
        bool isPremul = true;
        if (dst->IsEditable()) {
            return src->ConvertAlphaFormat(*dst.get(), isPremul);
        } else {
            return ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY;
        }
    }
}

uint32_t PixelMapImpl::CreateUnpremultipliedPixelMap(std::shared_ptr<PixelMap> src, std::shared_ptr<PixelMap> dst)
{
    if (src == nullptr || dst == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    } else {
        bool isPremul = false;
        if (dst->IsEditable()) {
            return src->ConvertAlphaFormat(*dst.get(), isPremul);
        } else {
            return ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY;
        }
    }
}

PixelMapImpl::PixelMapImpl(std::shared_ptr<PixelMap> ptr_)
{
    real_ = ptr_;
}

uint32_t PixelMapImpl::ReadPixelsToBuffer(uint64_t& bufferSize, uint8_t* dst)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->ReadPixels(bufferSize, dst);
}

uint32_t PixelMapImpl::ReadPixels(uint64_t& bufferSize, uint32_t& offset, uint32_t& stride, Rect& region, uint8_t* dst)
{
    if (real_ == nullptr || dst == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->ReadPixels(bufferSize, offset, stride, region, dst);
}

uint32_t PixelMapImpl::WriteBufferToPixels(const uint8_t* source, uint64_t& bufferSize)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->WritePixels(source, bufferSize);
}

uint32_t PixelMapImpl::WritePixels(
    const uint8_t* source, uint64_t& bufferSize, uint32_t& offset, uint32_t& stride, Rect& region)
{
    if (real_ == nullptr || source == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->WritePixels(source, bufferSize, offset, stride, region);
}

void PixelMapImpl::GetImageInfo(ImageInfo& imageInfo)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return;
    }
    real_->GetImageInfo(imageInfo);
}

int32_t PixelMapImpl::GetDensity()
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return 0;
    }
    return real_->GetBaseDensity();
}

uint32_t PixelMapImpl::Opacity(float percent)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->SetAlpha(percent);
}

void PixelMapImpl::Scale(float xAxis, float yAxis)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return;
    }
    real_->scale(xAxis, yAxis);
}

void PixelMapImpl::Scale(float xAxis, float yAxis, AntiAliasingOption& option)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return;
    }
    real_->scale(xAxis, yAxis, option);
}

uint32_t PixelMapImpl::Crop(Rect& rect)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->crop(rect);
}

uint32_t PixelMapImpl::ToSdr()
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    if (!GetPixelMapImplEditable()) {
        IMAGE_LOGE("ToSdrExec pixelmap is not editable");
        return ERR_RESOURCE_UNAVAILABLE;
    }
    return real_->ToSdr();
}

void PixelMapImpl::Flip(bool xAxis, bool yAxis)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return;
    }
    real_->flip(xAxis, yAxis);
}

void PixelMapImpl::Rotate(float degrees)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return;
    }
    real_->rotate(degrees);
}

void PixelMapImpl::Translate(float xAxis, float yAxis)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return;
    }
    real_->translate(xAxis, yAxis);
}

uint32_t PixelMapImpl::GetPixelBytesNumber()
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return 0;
    }
    return real_->GetByteCount();
}

uint32_t PixelMapImpl::GetBytesNumberPerRow()
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return 0;
    }
    return real_->GetRowBytes();
}

bool PixelMapImpl::GetIsEditable()
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return false;
    }
    return real_->IsEditable();
}

bool PixelMapImpl::GetIsStrideAlignment()
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return false;
    }
    bool isDMA = real_->IsStrideAlignment();
    return isDMA;
}

uint32_t PixelMapImpl::SetColorSpace(std::shared_ptr<OHOS::ColorManager::ColorSpace> colorSpace)
{
#ifdef IMAGE_COLORSPACE_FLAG
    if (real_ == nullptr || colorSpace == nullptr) {
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }
    real_->InnerSetColorSpace(*colorSpace);
    return 0;
#else
    return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
#endif
}

std::shared_ptr<OHOS::ColorManager::ColorSpace> PixelMapImpl::GetColorSpace()
{
#ifdef IMAGE_COLORSPACE_FLAG
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] real_ is nullptr!");
        return nullptr;
    }
    auto colorSpace = real_->InnerGetGrColorSpacePtr();
    return colorSpace;
#else
    return nullptr;
#endif
}

uint32_t PixelMapImpl::ApplyColorSpace(std::shared_ptr<OHOS::ColorManager::ColorSpace> colorSpace)
{
    if (real_ == nullptr || colorSpace == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->ApplyColorSpace(*colorSpace);
}

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static bool GetSurfaceSize(size_t argc, Rect& region, std::string fd)
{
    if (argc == NUM_2 && (region.width <= 0 || region.height <= 0)) {
        IMAGE_LOGE("GetSurfaceSize invalid parameter argc = %{public}zu", argc);
        return false;
    }
    if (region.width <= 0 || region.height <= 0) {
        unsigned long numberFd = 0;
        auto res = std::from_chars(fd.c_str(), fd.c_str() + fd.size(), numberFd);
        if (res.ec != std::errc()) {
            IMAGE_LOGE("GetSurfaceSize invalid fd");
            return false;
        }
        sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(numberFd);
        if (surface == nullptr) {
            return false;
        }
        sptr<SyncFence> fence = SyncFence::InvalidFence();
        // a 4 * 4 idetity matrix
        float matrix[16] = { 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1 };
        sptr<SurfaceBuffer> surfaceBuffer = nullptr;
        GSError ret = surface->GetLastFlushedBuffer(surfaceBuffer, fence, matrix);
        if (ret != OHOS::GSERROR_OK || surfaceBuffer == nullptr) {
            IMAGE_LOGE("GetLastFlushedBuffer fail, ret = %{public}d", ret);
            return false;
        }
        region.width = surfaceBuffer->GetWidth();
        region.height = surfaceBuffer->GetHeight();
    }
    return true;
}
#endif

std::shared_ptr<PixelMap> PixelMapImpl::CreatePixelMapFromSurface(
    char* surfaceId, Rect region, size_t argc, uint32_t& errCode)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    errCode = ERR_IMAGE_PIXELMAP_CREATE_FAILED;
    return nullptr;
#else
    errCode = argc == NUM_2 ? ERR_IMAGE_INVALID_PARAMETER : COMMON_ERR_INVALID_PARAMETER;
    if (surfaceId == nullptr) {
        IMAGE_LOGE("surfaceId is nullptr!");
        return nullptr;
    }
    IMAGE_LOGD("CreatePixelMapFromSurface IN");
    IMAGE_LOGD("CreatePixelMapFromSurface id:%{public}s,area:%{public}d,%{public}d,%{public}d,%{public}d", surfaceId,
        region.left, region.top, region.height, region.width);
    if (!std::regex_match(surfaceId, std::regex("\\d+"))) {
        IMAGE_LOGE("CreatePixelMapFromSurface empty or invalid surfaceId");
        return nullptr;
    }
    if (!GetSurfaceSize(argc, region, surfaceId)) {
        return nullptr;
    }
    auto& rsClient = Rosen::RSInterfaces::GetInstance();
    OHOS::Rect r = {
        .x = region.left,
        .y = region.top,
        .w = region.width,
        .h = region.height,
    };
    unsigned long newSurfaceId = 0;
    auto res = std::from_chars(surfaceId, surfaceId + std::string(surfaceId).size(), newSurfaceId);
    if (res.ec != std::errc()) {
        IMAGE_LOGE("CreatePixelMapFromSurface invalid surfaceId");
        errCode = ERR_IMAGE_PIXELMAP_CREATE_FAILED;
        return nullptr;
    }
    std::shared_ptr<PixelMap> pixelMap = rsClient.CreatePixelMapFromSurfaceId(newSurfaceId, r);
#ifndef EXT_PIXEL
    if (pixelMap == nullptr) {
        res = std::from_chars(surfaceId, surfaceId + std::string(surfaceId).size(), newSurfaceId);
        if (res.ec != std::errc()) {
            IMAGE_LOGE("CreatePixelMapFromSurface invalid surfaceId");
            errCode = ERR_IMAGE_PIXELMAP_CREATE_FAILED;
            return nullptr;
        }
        pixelMap = CreatePixelMapFromSurfaceId(newSurfaceId, region);
    }
#endif
    errCode = SUCCESS;
    return pixelMap;
#endif
}

uint32_t PixelMapImpl::Marshalling(int64_t rpcId)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return ERR_IMAGE_INVALID_PARAMETER;
#else
    IMAGE_LOGD("Marshalling IN");
    if (real_ == nullptr) {
        IMAGE_LOGE("marshalling pixel map to parcel failed.");
        return ERR_IPC;
    }
    auto messageSequence = FFIData::GetData<MessageSequenceImpl>(rpcId);
    if (!messageSequence) {
        IMAGE_LOGE("[PixelMap] rpc not exist %{public}" PRId64, rpcId);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    auto messageParcel = messageSequence->GetMessageParcel();
    if (messageParcel == nullptr) {
        IMAGE_LOGE("marshalling pixel map to parcel failed.");
        return ERR_IPC;
    }
    bool st = real_->Marshalling(*messageParcel);
    if (!st) {
        IMAGE_LOGE("marshalling pixel map to parcel failed.");
        return ERR_IPC;
    }
    return SUCCESS;
#endif
}

std::shared_ptr<PixelMap> PixelMapImpl::Unmarshalling(int64_t rpcId, uint32_t& errCode)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    errCode = ERR_IMAGE_INVALID_PARAMETER;
    return nullptr;
#else
    IMAGE_LOGD("Unmarshalling IN");
    auto messageSequence = FFIData::GetData<MessageSequenceImpl>(rpcId);
    if (!messageSequence) {
        IMAGE_LOGE("[PixelMap] rpc not exist %{public}" PRId64, rpcId);
        errCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }
    auto messageParcel = messageSequence->GetMessageParcel();
    if (messageParcel == nullptr) {
        IMAGE_LOGE("UnmarshallingExec invalid parameter: messageParcel is null");
        errCode = ERR_IPC;
        return nullptr;
    }
    PIXEL_MAP_ERR error;
    auto pixelmap = PixelMap::Unmarshalling(*messageParcel, error);
    if (pixelmap == nullptr) {
        errCode = error.errorCode;
        return nullptr;
    }
    std::shared_ptr<PixelMap> pixelPtr(pixelmap);
    return pixelPtr;
#endif
}

std::shared_ptr<PixelMap> PixelMapImpl::CreatePixelMapFromParcel(int64_t rpcId, uint32_t& errCode)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    errCode = ERR_IMAGE_PIXELMAP_CREATE_FAILED;
    return nullptr;
#else
    IMAGE_LOGD("CreatePixelMapFromParcel IN");
    auto messageSequence = FFIData::GetData<MessageSequenceImpl>(rpcId);
    if (!messageSequence) {
        IMAGE_LOGE("[PixelMap] rpc not exist %{public}" PRId64, rpcId);
        errCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }
    auto messageParcel = messageSequence->GetMessageParcel();
    if (messageParcel == nullptr) {
        IMAGE_LOGE("get pacel failed");
        errCode = ERR_IPC;
        return nullptr;
    }
    PIXEL_MAP_ERR error;
    auto pixelmap = PixelMap::Unmarshalling(*messageParcel, error);
    if (pixelmap == nullptr) {
        errCode = error.errorCode;
        return nullptr;
    }
    std::shared_ptr<PixelMap> pixelPtr(pixelmap);
    return pixelPtr;
#endif
}

static FormatType TypeFormat(PixelFormat& pixelForamt)
{
    switch (pixelForamt) {
        case PixelFormat::ARGB_8888:
        case PixelFormat::RGB_565:
        case PixelFormat::RGBA_8888:
        case PixelFormat::BGRA_8888:
        case PixelFormat::RGB_888:
        case PixelFormat::RGBA_F16:
        case PixelFormat::RGBA_1010102: {
            return FormatType::RGB;
        }
        case PixelFormat::NV21:
        case PixelFormat::NV12:
        case PixelFormat::YCBCR_P010:
        case PixelFormat::YCRCB_P010: {
            return FormatType::YUV;
        }
        case PixelFormat::ASTC_4x4: {
            return FormatType::ASTC;
        }
        default:
            return FormatType::UNKNOWN;
    }
}

uint32_t PixelMapImpl::ConvertPixelMapFormat(PixelFormat& destFormat)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("pixelmap is nullptr");
        return ERR_IMAGE_PIXELMAP_CREATE_FAILED;
    }
    if (TypeFormat(destFormat) == FormatType::UNKNOWN) {
        IMAGE_LOGE("dstFormat is not support or invalid");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    FormatType srcFormatType = FormatType::UNKNOWN;
    if (real_->GetPixelFormat() == PixelFormat::ASTC_4x4) {
        srcFormatType = FormatType::ASTC;
    }
    FormatType dstFormatType = TypeFormat(destFormat);
    uint32_t result = SUCCESS;
    if (dstFormatType == FormatType::YUV &&
        (srcFormatType == FormatType::UNKNOWN || srcFormatType == FormatType::RGB)) {
        result = ImageFormatConvert::ConvertImageFormat(real_, destFormat);
    } else if ((dstFormatType == FormatType::RGB) &&
               (srcFormatType == FormatType::UNKNOWN || srcFormatType == FormatType::YUV)) {
        result = ImageFormatConvert::ConvertImageFormat(real_, destFormat);
    } else if ((dstFormatType == FormatType::RGB) && (srcFormatType == FormatType::ASTC)) {
        result = ImageFormatConvert::ConvertImageFormat(real_, destFormat);
    }
    if (result == SUCCESS) {
        ImageUtils::FlushSurfaceBuffer(const_cast<PixelMap*>(real_.get()));
    }
    return result;
}
} // namespace Media
} // namespace OHOS