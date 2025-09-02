/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "pixel_map_taihe.h"

#include "ani_color_space_object_convertor.h"
#include "image_format_convert.h"
#include "image_log.h"
#include "image_taihe_utils.h"
#include "image_utils.h"
#include "media_errors.h"
#include "message_parcel.h"
#include "pixel_map_taihe_ani.h"
#include "taihe/runtime.hpp"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include <regex>
#include "color_utils.h"
#include "pixel_map_from_surface.h"
#include "transaction/rs_interfaces.h"
#include "vpe_utils.h"
#endif

namespace ANI::Image {

constexpr uint32_t METADATA_RED_INDEX = 0;
constexpr uint32_t METADATA_GREEN_INDEX = 1;
constexpr uint32_t METADATA_BLUE_INDEX = 2;
constexpr uint32_t METADATA_CHANNEL_COUNT = 3;

enum class FormatType : int8_t {
    UNKNOWN,
    YUV,
    RGB,
    ASTC
};

Size MakeEmptySize()
{
    return {0, 0};
}

ImageInfo MakeEmptyImageInfo()
{
    return {MakeEmptySize(), 0, 0, PixelMapFormat(PixelMapFormat::key_t::UNKNOWN),
        AlphaType(AlphaType::key_t::UNKNOWN), "", false};
}

PixelMap CreatePixelMapByBufferAndOptionsSync(array_view<uint8_t> colors, InitializationOptions const& options)
{
    return make_holder<PixelMapImpl, PixelMap>(colors, options);
}

PixelMap CreatePixelMapByOptionsSync(InitializationOptions const& options)
{
    return make_holder<PixelMapImpl, PixelMap>(options);
}

PixelMap CreatePixelMapByPtr(int64_t ptr)
{
    return make_holder<PixelMapImpl, PixelMap>(ptr);
}

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static bool GetSurfaceSize(std::string const& surfaceId, Media::Rect& region)
{
    if (region.width <= 0 || region.height <= 0) {
        sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(std::stoull(surfaceId));
        if (surface == nullptr) {
            IMAGE_LOGE("[%{public}s] GetSurfaceSize: GetSurface failed", __func__);
            return false;
        }
        sptr<SyncFence> fence = SyncFence::InvalidFence();
        // 4 * 4 idetity matrix
        float matrix[16] = {
            1, 0, 0, 0,
            0, 1, 0, 0,
            0, 0, 1, 0,
            0, 0, 0, 1
        };
        sptr<SurfaceBuffer> surfaceBuffer = nullptr;
        GSError ret = surface->GetLastFlushedBuffer(surfaceBuffer, fence, matrix);
        if (ret != GSERROR_OK || surfaceBuffer == nullptr) {
            IMAGE_LOGE("[%{public}s] GetSurfaceSize: GetLastFlushedBuffer fail, ret = %{public}d", __func__, ret);
            return false;
        }
        region.width = surfaceBuffer->GetWidth();
        region.height = surfaceBuffer->GetHeight();
    }
    return true;
}

static PixelMap CreatePixelMapFromSurface(std::string const& surfaceId, Media::Rect& region)
{
    if (!std::regex_match(surfaceId, std::regex("\\d+"))) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Empty or invalid Surface ID");
        return make_holder<PixelMapImpl, PixelMap>();
    }
    if (!GetSurfaceSize(surfaceId, region)) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Get Surface size failed");
        return make_holder<PixelMapImpl, PixelMap>();
    }

    auto &rsClient = Rosen::RSInterfaces::GetInstance();
    OHOS::Rect r = {
        .x = region.left,
        .y = region.top,
        .w = region.width,
        .h = region.height,
    };
    std::shared_ptr<Media::PixelMap> pixelMap = rsClient.CreatePixelMapFromSurfaceId(std::stoull(surfaceId), r);
#ifndef EXT_PIXEL
    if (pixelMap == nullptr) {
        pixelMap = CreatePixelMapFromSurfaceId(std::stoull(surfaceId), region);
    }
#endif
    return make_holder<PixelMapImpl, PixelMap>(std::move(pixelMap));
}
#endif

PixelMap CreatePixelMapFromSurfaceByIdSync(string_view etsSurfaceId)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return make_holder<PixelMapImpl, PixelMap>();
#else
    std::string surfaceId(etsSurfaceId);
    Media::Rect region;
    IMAGE_LOGD("[%{public}s] surfaceId=%{public}s", __func__, surfaceId.c_str());
    return CreatePixelMapFromSurface(surfaceId, region);
#endif
}

PixelMap CreatePixelMapFromSurfaceByIdAndRegionSync(string_view etsSurfaceId,
    ohos::multimedia::image::image::Region const& etsRegion)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return make_holder<PixelMapImpl, PixelMap>();
#else
    std::string surfaceId(etsSurfaceId);
    Media::Rect region = {etsRegion.x, etsRegion.y, etsRegion.size.width, etsRegion.size.height};
    IMAGE_LOGD("[%{public}s] surfaceId=%{public}s, region=%{public}d,%{public}d,%{public}d,%{public}d",
        __func__, surfaceId.c_str(), region.left, region.top, region.width, region.height);
    if (region.width <= 0 || region.height <= 0) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Invalid region");
        return make_holder<PixelMapImpl, PixelMap>();
    }
    return CreatePixelMapFromSurface(surfaceId, region);
#endif
}

static PixelMap Unmarshalling(uintptr_t sequence)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return make_holder<PixelMapImpl, PixelMap>();
#else
    MessageParcel* messageParcel = ImageTaiheUtils::UnwrapMessageParcel(sequence);
    if (messageParcel == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IPC, "Get parcel failed");
        return make_holder<PixelMapImpl, PixelMap>();
    }

    Media::PIXEL_MAP_ERR error;
    auto pixelMap = Media::PixelMap::Unmarshalling(*messageParcel, error);
    if (pixelMap == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(error.errorCode, error.errorInfo);
        return make_holder<PixelMapImpl, PixelMap>();
    }
    std::shared_ptr<Media::PixelMap> pixelMapPtr(pixelMap);
    return make_holder<PixelMapImpl, PixelMap>(std::move(pixelMapPtr));
#endif
}

PixelMap CreatePixelMapFromParcel(uintptr_t sequence)
{
    return Unmarshalling(sequence);
}

static void ConvertPixelMapAlphaFormat(weak::PixelMap const& src, weak::PixelMap const& dst, bool isPremul)
{
    PixelMapImpl* rPixelMapImpl = reinterpret_cast<PixelMapImpl*>(src->GetImplPtr());
    PixelMapImpl* wPixelMapImpl = reinterpret_cast<PixelMapImpl*>(dst->GetImplPtr());
    if (rPixelMapImpl == nullptr || wPixelMapImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_READ_PIXELMAP_FAILED, "Unwrap PixelMap failed");
    }

    auto rPixelMap = rPixelMapImpl->GetNativePtr();
    auto wPixelMap = wPixelMapImpl->GetNativePtr();
    if (wPixelMap->IsEditable()) {
        rPixelMap->ConvertAlphaFormat(*(wPixelMap.get()), isPremul);
    } else {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY,
            "Target PixelMap is not editable");
    }
}

void CreatePremultipliedPixelMapSync(weak::PixelMap src, weak::PixelMap dst)
{
    ConvertPixelMapAlphaFormat(src, dst, true);
}

void CreateUnpremultipliedPixelMapSync(weak::PixelMap src, weak::PixelMap dst)
{
    ConvertPixelMapAlphaFormat(src, dst, false);
}

PixelMapImpl::PixelMapImpl() {}

PixelMapImpl::PixelMapImpl(array_view<uint8_t> const& colors, InitializationOptions const& etsOptions)
{
    Media::InitializationOptions options;
    ParseInitializationOptions(etsOptions, options);
    if (!Is10BitFormat(options.pixelFormat)) {
        nativePixelMap_ = Media::PixelMap::Create(reinterpret_cast<uint32_t*>(colors.data()),
            colors.size() / sizeof(uint32_t), options);
    }
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER,
            "Create PixelMap by buffer and options failed");
    } else {
        IMAGE_LOGD("[%{public}s] Created PixelMap with ID: %{public}d", __func__, nativePixelMap_->GetUniqueId());
    }
}

PixelMapImpl::PixelMapImpl(InitializationOptions const& etsOptions)
{
    Media::InitializationOptions options;
    ParseInitializationOptions(etsOptions, options);
    if (Is10BitFormat(options.pixelFormat)) {
        options.useDMA = true;
    }
    nativePixelMap_ = Media::PixelMap::Create(options);
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Create PixelMap by options failed");
    } else {
        IMAGE_LOGD("[%{public}s] Created PixelMap with ID: %{public}d", __func__, nativePixelMap_->GetUniqueId());
    }
}

PixelMapImpl::PixelMapImpl(std::shared_ptr<Media::PixelMap> pixelMap)
{
    nativePixelMap_ = pixelMap;
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Create PixelMap failed");
    } else {
        IMAGE_LOGD("[%{public}s] Transferred PixelMap with ID: %{public}d", __func__, nativePixelMap_->GetUniqueId());
    }
}

PixelMapImpl::PixelMapImpl(int64_t aniPtr)
{
    Media::PixelMapTaiheAni* pixelMapAni = reinterpret_cast<Media::PixelMapTaiheAni*>(aniPtr);
    nativePixelMap_ = pixelMapAni->nativePixelMap_;
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Create PixelMap failed");
    } else {
        IMAGE_LOGD("[%{public}s] Transferred PixelMap with ID: %{public}d", __func__, nativePixelMap_->GetUniqueId());
    }
}

PixelMapImpl::~PixelMapImpl()
{
    Release();
}

int64_t PixelMapImpl::GetImplPtr()
{
    return static_cast<int64_t>(reinterpret_cast<uintptr_t>(this));
}

std::shared_ptr<Media::PixelMap> PixelMapImpl::GetNativePtr()
{
    return nativePixelMap_;
}

std::shared_ptr<Media::PixelMap> PixelMapImpl::GetPixelMap(PixelMap etsPixelMap)
{
    PixelMapImpl *pixelMapImpl = reinterpret_cast<PixelMapImpl *>(etsPixelMap->GetImplPtr());
    if (pixelMapImpl == nullptr) {
        IMAGE_LOGE("[%{public}s] etsPixelMap is nullptr", __func__);
        return nullptr;
    }
    return pixelMapImpl->GetNativePtr();
}

PixelMap PixelMapImpl::CreatePixelMap(std::shared_ptr<Media::PixelMap> pixelMap)
{
    return make_holder<PixelMapImpl, PixelMap>(pixelMap);
}

ImageInfo PixelMapImpl::GetImageInfoSync()
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return MakeEmptyImageInfo();
    }

    Media::ImageInfo imageInfo;
    nativePixelMap_->GetImageInfo(imageInfo);
    ImageInfo result = ImageTaiheUtils::ToTaiheImageInfo(imageInfo, nativePixelMap_->IsHdr());
    result.density = imageInfo.baseDensity;
    result.stride = nativePixelMap_->GetRowStride();
    return result;
}

void PixelMapImpl::ReadPixelsToBufferSync(array_view<uint8_t> dst)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    uint32_t status = nativePixelMap_->ReadPixels(dst.size(), dst.data());
    if (status != Media::SUCCESS) {
        IMAGE_LOGE("[%{public}s] ReadPixels failed", __func__);
    }
}

void PixelMapImpl::ReadPixelsSync(weak::PositionArea area)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    ohos::multimedia::image::image::Region etsRegion = area->GetRegion();
    Media::Rect region = {etsRegion.x, etsRegion.y, etsRegion.size.width, etsRegion.size.height};
    array<uint8_t> etsPixels = area->GetPixels();
    uint32_t status = nativePixelMap_->ReadPixels(etsPixels.size(), area->GetOffset(), area->GetStride(), region,
        etsPixels.data());
    if (status == Media::SUCCESS) {
        area->SetPixels(etsPixels);
    } else {
        IMAGE_LOGE("[%{public}s] ReadPixels by region failed", __func__);
    }
}

void PixelMapImpl::WriteBufferToPixelsSync(array_view<uint8_t> src)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    uint32_t status = nativePixelMap_->WritePixels(src.data(), src.size());
    if (status != Media::SUCCESS) {
        IMAGE_LOGE("[%{public}s] WritePixels failed", __func__);
    }
}

void PixelMapImpl::WritePixelsSync(weak::PositionArea area)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    ohos::multimedia::image::image::Region etsRegion = area->GetRegion();
    Media::Rect region = {etsRegion.x, etsRegion.y, etsRegion.size.width, etsRegion.size.height};
    array<uint8_t> etsPixels = area->GetPixels();
    uint32_t status = nativePixelMap_->WritePixels(etsPixels.data(), etsPixels.size(), area->GetOffset(),
        area->GetStride(), region);
    if (status != Media::SUCCESS) {
        IMAGE_LOGE("[%{public}s] WritePixels by region failed", __func__);
    }
}

PixelMap PixelMapImpl::CreateAlphaPixelmapSync()
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return make_holder<PixelMapImpl, PixelMap>();
    }

    Media::InitializationOptions options;
    options.pixelFormat = Media::PixelFormat::ALPHA_8;
    auto alphaPixelMap = Media::PixelMap::Create(*nativePixelMap_, options);
    return make_holder<PixelMapImpl, PixelMap>(std::move(alphaPixelMap));
}

int32_t PixelMapImpl::GetBytesNumberPerRow()
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return 0;
    }

    return nativePixelMap_->GetRowBytes();
}

int32_t PixelMapImpl::GetPixelBytesNumber()
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return 0;
    }

    return nativePixelMap_->GetByteCount();
}

int32_t PixelMapImpl::GetDensity()
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return 0;
    }

    return nativePixelMap_->GetBaseDensity();
}

void PixelMapImpl::ScaleSync(double x, double y)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    nativePixelMap_->scale(static_cast<float>(x), static_cast<float>(y));
}

void PixelMapImpl::ScaleWithAntiAliasingSync(double x, double y, AntiAliasingLevel level)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    nativePixelMap_->scale(static_cast<float>(x), static_cast<float>(y), Media::AntiAliasingOption(level.get_value()));
}

PixelMap PixelMapImpl::CreateScaledPixelMapSync(double x, double y, optional_view<AntiAliasingLevel> level)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Native PixelMap is nullptr");
        return make_holder<PixelMapImpl, PixelMap>();
    }

    Media::InitializationOptions opts;
    std::unique_ptr<Media::PixelMap> clonedPixelMap = Media::PixelMap::Create(*nativePixelMap_, opts);
    if (clonedPixelMap == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Clone PixelMap failed");
        return make_holder<PixelMapImpl, PixelMap>();
    }

    if (level.has_value()) {
        clonedPixelMap->scale(static_cast<float>(x), static_cast<float>(y),
            Media::AntiAliasingOption(level.value().get_value()));
    } else {
        clonedPixelMap->scale(static_cast<float>(x), static_cast<float>(y));
    }
    return make_holder<PixelMapImpl, PixelMap>(std::move(clonedPixelMap));
}

PixelMap PixelMapImpl::CloneSync()
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_INIT_ABNORMAL, "Native PixelMap is nullptr");
        return make_holder<PixelMapImpl, PixelMap>();
    }

    int32_t errorCode = Media::SUCCESS;
    auto clonedPixelMap = nativePixelMap_->Clone(errorCode);
    if (clonedPixelMap == nullptr) {
        if (errorCode == Media::ERR_IMAGE_INIT_ABNORMAL) {
            ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_INIT_ABNORMAL, "Initialize empty PixelMap failed");
        } else if (errorCode == Media::ERR_IMAGE_MALLOC_ABNORMAL) {
            ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_MALLOC_ABNORMAL, "Copy PixelMap data failed");
        } else if (errorCode == Media::ERR_IMAGE_DATA_UNSUPPORT) {
            ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_DATA_UNSUPPORT,
                "PixelMap type does not support clone");
        } else if (errorCode == Media::ERR_IMAGE_TOO_LARGE) {
            ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_TOO_LARGE, "PixelMap size (bytes) out of range");
        } else {
            ImageTaiheUtils::ThrowExceptionError(errorCode, "Clone PixelMap failed");
        }
        return make_holder<PixelMapImpl, PixelMap>();
    }
    return make_holder<PixelMapImpl, PixelMap>(std::move(clonedPixelMap));
}

void PixelMapImpl::TranslateSync(double x, double y)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_INIT_ABNORMAL, "Native PixelMap is nullptr");
        return;
    }

    nativePixelMap_->translate(static_cast<float>(x), static_cast<float>(y));
}

void PixelMapImpl::CropSync(ohos::multimedia::image::image::Region const& region)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    Media::Rect rect = {region.x, region.y, region.size.width, region.size.height};
    uint32_t status = nativePixelMap_->crop(rect);
    if (status != Media::SUCCESS) {
        IMAGE_LOGE("[%{public}s] crop failed", __func__);
    }
}

void PixelMapImpl::RotateSync(double angle)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    nativePixelMap_->rotate(static_cast<float>(angle));
}

void PixelMapImpl::FlipSync(bool horizontal, bool vertical)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    nativePixelMap_->flip(horizontal, vertical);
}

void PixelMapImpl::OpacitySync(double rate)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    uint32_t status = nativePixelMap_->SetAlpha(static_cast<float>(rate));
    if (status != Media::SUCCESS) {
        IMAGE_LOGE("[%{public}s] SetAlpha failed", __func__);
    }
}

void PixelMapImpl::SetMemoryNameSync(string_view name)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    uint32_t status = nativePixelMap_->SetMemoryName(std::string(name));
    if (status == Media::ERR_MEMORY_NOT_SUPPORT) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEMORY_NOT_SUPPORT, "Set memory name not supported");
    } else if (status == Media::COMMON_ERR_INVALID_PARAMETER) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Memory name size out of range");
    }
}

void PixelMapImpl::SetTransferDetached(bool detached)
{
    IMAGE_LOGD("[%{public}s] This method is no longer useful or necessary", __func__);
}

static FormatType FormatTypeOf(Media::PixelFormat pixelForamt)
{
    switch (pixelForamt) {
        case Media::PixelFormat::ARGB_8888:
        case Media::PixelFormat::RGB_565:
        case Media::PixelFormat::RGBA_8888:
        case Media::PixelFormat::BGRA_8888:
        case Media::PixelFormat::RGB_888:
        case Media::PixelFormat::RGBA_F16:
        case Media::PixelFormat::RGBA_1010102:
            return FormatType::RGB;
        case Media::PixelFormat::NV21:
        case Media::PixelFormat::NV12:
        case Media::PixelFormat::YCBCR_P010:
        case Media::PixelFormat::YCRCB_P010:
            return FormatType::YUV;
        case Media::PixelFormat::ASTC_4x4:
            return FormatType::ASTC;
        default:
            return FormatType::UNKNOWN;
    }
}

void PixelMapImpl::ConvertPixelFormatSync(PixelMapFormat targetPixelFormat)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    Media::PixelFormat srcFormat = nativePixelMap_->GetPixelFormat();
    Media::PixelFormat dstFormat = Media::PixelFormat(targetPixelFormat.get_value());
    if (FormatTypeOf(srcFormat) == FormatType::UNKNOWN || FormatTypeOf(dstFormat) == FormatType::UNKNOWN) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_INVALID_PARAMETER,
            "Source or target pixel format is not supported or invalid");
        return;
    }

    uint32_t status = Media::ImageFormatConvert::ConvertImageFormat(nativePixelMap_, dstFormat);
    if (status == Media::SUCCESS) {
        Media::ImageUtils::FlushSurfaceBuffer(nativePixelMap_.get());
    } else if (status == Media::ERR_IMAGE_INVALID_PARAMETER) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_INVALID_PARAMETER, "Invalid parameter");
    } else if (status == Media::ERR_IMAGE_SOURCE_DATA_INCOMPLETE) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_SOURCE_DATA_INCOMPLETE,
            "Image source data is incomplete");
    } else if (status == Media::IMAGE_RESULT_CREATE_FORMAT_CONVERT_FAILED) {
        ImageTaiheUtils::ThrowExceptionError(Media::IMAGE_RESULT_CREATE_FORMAT_CONVERT_FAILED, "Conversion failed");
    } else if (status == Media::ERR_MEDIA_FORMAT_UNSUPPORT) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEDIA_FORMAT_UNSUPPORT,
            "The target pixel format to be converted is not supported");
    } else if (status == Media::ERR_IMAGE_PIXELMAP_CREATE_FAILED) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_PIXELMAP_CREATE_FAILED, "Failed to create PixelMap");
    }
}

uintptr_t PixelMapImpl::GetColorSpace()
{
#ifdef IMAGE_COLORSPACE_FLAG
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_DATA_ABNORMAL, "Invalid native PixelMap");
        return 0;
    }

    auto grColorSpace = nativePixelMap_->InnerGetGrColorSpacePtr();
    if (grColorSpace == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_DATA_UNSUPPORT, "No color space in PixelMap");
        return 0;
    }
    return reinterpret_cast<uintptr_t>(ColorManager::CreateAniColorSpaceObject(get_env(), grColorSpace));
#else
    ImageTaiheUtils::ThrowExceptionError(Media::ERR_INVALID_OPERATION, "Unsupported operation");
    return 0;
#endif
}

void PixelMapImpl::SetColorSpace(uintptr_t colorSpace)
{
#ifdef IMAGE_COLORSPACE_FLAG
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    auto grColorSpace = ColorManager::GetColorSpaceByAniObject(get_env(), reinterpret_cast<ani_object>(colorSpace));
    if (grColorSpace == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_INVALID_PARAMETER, "Color space mismatch");
        return;
    }
    nativePixelMap_->InnerSetColorSpace(*grColorSpace);
#else
    ImageTaiheUtils::ThrowExceptionError(Media::ERR_INVALID_OPERATION, "Unsupported operation");
#endif
}

void PixelMapImpl::Marshalling(uintptr_t sequence)
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return;
    }

    MessageParcel* messageParcel = ImageTaiheUtils::UnwrapMessageParcel(sequence);
    if (messageParcel == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IPC,
            "Marshalling PixelMap to parcel failed, parcel is nullptr");
        return;
    }
    bool st = nativePixelMap_->Marshalling(*messageParcel);
    if (!st) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IPC, "Marshalling PixelMap to parcel failed");
    }
}

PixelMap PixelMapImpl::UnmarshallingSync(uintptr_t sequence)
{
    return Unmarshalling(sequence);
}

void PixelMapImpl::ToSdrSync()
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEDIA_INVALID_OPERATION, "Internal error.");
        return;
    }

    uint32_t status = nativePixelMap_->ToSdr();
    if (status != Media::SUCCESS) {
        if (status == Media::ERR_MEDIA_INVALID_OPERATION) {
            ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEDIA_INVALID_OPERATION, "The pixelmap is not hdr.");
        } else if (status == Media::IMAGE_RESULT_GET_SURFAC_FAILED) {
            ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEDIA_INVALID_OPERATION, "Alloc new memory failed.");
        } else if (status == Media::ERR_RESOURCE_UNAVAILABLE) {
            ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEDIA_INVALID_OPERATION, "Pixelmap is not editable");
        } else {
            ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEDIA_INVALID_OPERATION, "Internal error.");
        }
    }
}

static uint32_t ParseColorSpace(std::shared_ptr<OHOS::ColorManager::ColorSpace> &colorSpace,
    uintptr_t targetColorSpace)
{
#ifdef IMAGE_COLORSPACE_FLAG
    ani_object obj = reinterpret_cast<ani_object>(targetColorSpace);
    colorSpace = OHOS::ColorManager::GetColorSpaceByAniObject(get_env(), obj);
    if (colorSpace == nullptr) {
        return Media::ERR_IMAGE_INVALID_PARAMETER;
    }
    return Media::SUCCESS;
#else
    return Media::ERR_IMAGE_DATA_UNSUPPORT;
#endif
}

void PixelMapImpl::ApplyColorSpaceSync(uintptr_t targetColorSpace)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_INIT_ABNORMAL, "Internal error.");
        return;
    }

    std::shared_ptr<OHOS::ColorManager::ColorSpace> colorSpace;
    uint32_t status = ParseColorSpace(colorSpace, targetColorSpace);
    if (status != Media::SUCCESS) {
        ImageTaiheUtils::ThrowExceptionError(status, "ParseColorSpace failed");
        return;
    }

    if (colorSpace == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_INIT_ABNORMAL, "ApplyColorSpace Null native ref");
        return;
    }
    status = nativePixelMap_->ApplyColorSpace(*colorSpace);
    if (status != Media::SUCCESS) {
        ImageTaiheUtils::ThrowExceptionError(status, "ApplyColorSpace has failed!");
        return;
    }
}

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static std::map<HdrMetadataType::key_t, HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type> EtsMetadataMap = {
    {HdrMetadataType::key_t::NONE, HDI::Display::Graphic::Common::V1_0::CM_METADATA_NONE},
    {HdrMetadataType::key_t::BASE, HDI::Display::Graphic::Common::V1_0::CM_IMAGE_HDR_VIVID_DUAL},
    {HdrMetadataType::key_t::GAINMAP, HDI::Display::Graphic::Common::V1_0::CM_METADATA_NONE},
    {HdrMetadataType::key_t::ALTERNATE, HDI::Display::Graphic::Common::V1_0::CM_IMAGE_HDR_VIVID_SINGLE},
};

static std::map<HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type, HdrMetadataType::key_t> MetadataEtsMap = {
    {HDI::Display::Graphic::Common::V1_0::CM_METADATA_NONE, HdrMetadataType::key_t::NONE},
    {HDI::Display::Graphic::Common::V1_0::CM_IMAGE_HDR_VIVID_DUAL, HdrMetadataType::key_t::BASE},
    {HDI::Display::Graphic::Common::V1_0::CM_IMAGE_HDR_VIVID_SINGLE, HdrMetadataType::key_t::ALTERNATE},
};

static HdrStaticMetadata BuildHdrStaticMetadata(
    HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata const& srcStaticMetadata)
{
    HdrStaticMetadata dstMetadata{};
    dstMetadata.displayPrimariesX = {
        srcStaticMetadata.smpte2086.displayPrimaryRed.x,
        srcStaticMetadata.smpte2086.displayPrimaryGreen.x,
        srcStaticMetadata.smpte2086.displayPrimaryBlue.x
    };
    dstMetadata.displayPrimariesY = {
        srcStaticMetadata.smpte2086.displayPrimaryRed.y,
        srcStaticMetadata.smpte2086.displayPrimaryGreen.y,
        srcStaticMetadata.smpte2086.displayPrimaryBlue.y
    };
    dstMetadata.whitePointX = srcStaticMetadata.smpte2086.whitePoint.x;
    dstMetadata.whitePointY = srcStaticMetadata.smpte2086.whitePoint.y;
    dstMetadata.maxLuminance = srcStaticMetadata.smpte2086.maxLuminance;
    dstMetadata.minLuminance = srcStaticMetadata.smpte2086.minLuminance;
    dstMetadata.maxContentLightLevel = srcStaticMetadata.cta861.maxContentLightLevel;
    dstMetadata.maxFrameAverageLightLevel = srcStaticMetadata.cta861.maxFrameAverageLightLevel;
    return dstMetadata;
}

static HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata ParseHdrStaticMetadata(
    HdrStaticMetadata const& srcStaticMetadata)
{
    HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata dstMetadata{};
    dstMetadata.smpte2086.displayPrimaryRed.x = srcStaticMetadata.displayPrimariesX[METADATA_RED_INDEX];
    dstMetadata.smpte2086.displayPrimaryGreen.x = srcStaticMetadata.displayPrimariesX[METADATA_GREEN_INDEX];
    dstMetadata.smpte2086.displayPrimaryBlue.x = srcStaticMetadata.displayPrimariesX[METADATA_BLUE_INDEX];
    dstMetadata.smpte2086.displayPrimaryRed.y = srcStaticMetadata.displayPrimariesY[METADATA_RED_INDEX];
    dstMetadata.smpte2086.displayPrimaryGreen.y = srcStaticMetadata.displayPrimariesY[METADATA_GREEN_INDEX];
    dstMetadata.smpte2086.displayPrimaryBlue.y = srcStaticMetadata.displayPrimariesY[METADATA_BLUE_INDEX];
    dstMetadata.smpte2086.whitePoint.x = srcStaticMetadata.whitePointX;
    dstMetadata.smpte2086.whitePoint.y = srcStaticMetadata.whitePointY;
    dstMetadata.smpte2086.maxLuminance = srcStaticMetadata.maxLuminance;
    dstMetadata.smpte2086.minLuminance = srcStaticMetadata.minLuminance;
    dstMetadata.cta861.maxContentLightLevel = srcStaticMetadata.maxContentLightLevel;
    dstMetadata.cta861.maxFrameAverageLightLevel = srcStaticMetadata.maxFrameAverageLightLevel;
    return dstMetadata;
}

static HdrGainmapMetadata BuildHdrGainmapMetadata(Media::HDRVividExtendMetadata const& srcGainmapMetadata)
{
    HdrGainmapMetadata dstMetadata{};
    dstMetadata.writerVersion = static_cast<int32_t>(srcGainmapMetadata.metaISO.writeVersion);
    dstMetadata.miniVersion = static_cast<int32_t>(srcGainmapMetadata.metaISO.miniVersion);
    dstMetadata.gainmapChannelCount = static_cast<int32_t>(srcGainmapMetadata.metaISO.gainmapChannelNum);
    dstMetadata.useBaseColorFlag = static_cast<bool>(srcGainmapMetadata.metaISO.useBaseColorFlag);
    dstMetadata.baseHeadroom = srcGainmapMetadata.metaISO.baseHeadroom;
    dstMetadata.alternateHeadroom = srcGainmapMetadata.metaISO.alternateHeadroom;
    dstMetadata.channels = array<GainmapChannel>::make(METADATA_CHANNEL_COUNT);
    for (uint32_t i = 0; i < METADATA_CHANNEL_COUNT; ++i) {
        dstMetadata.channels[i] = {
            srcGainmapMetadata.metaISO.enhanceClippedThreholdMaxGainmap[i],
            srcGainmapMetadata.metaISO.enhanceClippedThreholdMinGainmap[i],
            srcGainmapMetadata.metaISO.enhanceMappingGamma[i],
            srcGainmapMetadata.metaISO.enhanceMappingBaselineOffset[i],
            srcGainmapMetadata.metaISO.enhanceMappingAlternateOffset[i]
        };
    }
    return dstMetadata;
}

static void ParseHdrGainmapMetadata(HdrGainmapMetadata const& srcGainmapMetadata,
    Media::HDRVividExtendMetadata &dstMetadata)
{
    dstMetadata.metaISO.writeVersion = static_cast<unsigned short>(srcGainmapMetadata.writerVersion);
    dstMetadata.metaISO.miniVersion = static_cast<unsigned short>(srcGainmapMetadata.miniVersion);
    dstMetadata.metaISO.gainmapChannelNum = static_cast<unsigned char>(srcGainmapMetadata.gainmapChannelCount);
    dstMetadata.metaISO.useBaseColorFlag = static_cast<unsigned char>(srcGainmapMetadata.useBaseColorFlag);
    dstMetadata.metaISO.baseHeadroom = srcGainmapMetadata.baseHeadroom;
    dstMetadata.metaISO.alternateHeadroom = srcGainmapMetadata.alternateHeadroom;
    for (uint32_t i = 0; i < METADATA_CHANNEL_COUNT; ++i) {
        dstMetadata.metaISO.enhanceClippedThreholdMaxGainmap[i] = srcGainmapMetadata.channels[i].gainmapMax;
        dstMetadata.metaISO.enhanceClippedThreholdMinGainmap[i] = srcGainmapMetadata.channels[i].gainmapMin;
        dstMetadata.metaISO.enhanceMappingGamma[i] = srcGainmapMetadata.channels[i].gamma;
        dstMetadata.metaISO.enhanceMappingBaselineOffset[i] = srcGainmapMetadata.channels[i].baseOffset;
        dstMetadata.metaISO.enhanceMappingAlternateOffset[i] = srcGainmapMetadata.channels[i].alternateOffset;
    }
}

static bool GetMetadataType(sptr<SurfaceBuffer> const& surfaceBuffer, HdrMetadataValue &metadataValue)
{
    HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type type;
    Media::VpeUtils::GetSbMetadataType(surfaceBuffer, type);
    if (MetadataEtsMap.find(type) != MetadataEtsMap.end()) {
        std::vector<uint8_t> gainmapDataVec;
        if (type == HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type::CM_METADATA_NONE &&
            Media::VpeUtils::GetSbDynamicMetadata(surfaceBuffer, gainmapDataVec) &&
            gainmapDataVec.size() == sizeof(Media::HDRVividExtendMetadata)) {
            metadataValue = HdrMetadataValue::make_hdrMetadataType(HdrMetadataType::key_t::GAINMAP);
        } else {
            metadataValue = HdrMetadataValue::make_hdrMetadataType(MetadataEtsMap[type]);
        }
        return true;
    } else {
        IMAGE_LOGE("[%{public}s] GetMetadataType failed", __func__);
        return false;
    }
}

static bool SetMetadataType(sptr<SurfaceBuffer> &surfaceBuffer, HdrMetadataValue const& metadataValue)
{
    if (!metadataValue.holds_hdrMetadataType()) {
        IMAGE_LOGE("[%{public}s] Key and value types are inconsistent", __func__);
        return false;
    }

    HdrMetadataType metadataType = metadataValue.get_hdrMetadataType_ref();
    if (EtsMetadataMap.find(metadataType.get_key()) != EtsMetadataMap.end()) {
        Media::VpeUtils::SetSbMetadataType(surfaceBuffer, EtsMetadataMap[metadataType.get_key()]);
        return true;
    } else {
        IMAGE_LOGE("[%{public}s] SetMetadataType failed", __func__);
        return false;
    }
}

static bool GetStaticMetadata(sptr<SurfaceBuffer> const& surfaceBuffer, HdrMetadataValue &metadataValue)
{
    HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata staticMetadata;
    uint32_t vecSize = sizeof(HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata);
    std::vector<uint8_t> staticDataVec;
    if (!Media::VpeUtils::GetSbStaticMetadata(surfaceBuffer, staticDataVec) || staticDataVec.size() != vecSize) {
        IMAGE_LOGE("[%{public}s] GetSbStaticMetadata failed", __func__);
        return false;
    }
    if (memcpy_s(&staticMetadata, vecSize, staticDataVec.data(), staticDataVec.size()) != EOK) {
        IMAGE_LOGE("[%{public}s] memcpy failed", __func__);
        return false;
    }
    metadataValue = HdrMetadataValue::make_hdrStaticMetadata(BuildHdrStaticMetadata(staticMetadata));
    return true;
}

static bool SetStaticMetadata(sptr<SurfaceBuffer> &surfaceBuffer, HdrMetadataValue const& metadataValue)
{
    if (!metadataValue.holds_hdrStaticMetadata()) {
        IMAGE_LOGE("[%{public}s] Key and value types are inconsistent", __func__);
        return false;
    }

    auto staticMetadata = ParseHdrStaticMetadata(metadataValue.get_hdrStaticMetadata_ref());
    uint32_t vecSize = sizeof(HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata);
    std::vector<uint8_t> staticDataVec(vecSize);
    if (memcpy_s(staticDataVec.data(), vecSize, &staticMetadata, vecSize) != EOK) {
        IMAGE_LOGE("[%{public}s] memcpy failed", __func__);
        return false;
    }
    if (!Media::VpeUtils::SetSbStaticMetadata(surfaceBuffer, staticDataVec)) {
        IMAGE_LOGE("[%{public}s] SetSbStaticMetadata failed", __func__);
        return false;
    }
    return true;
}

static bool GetDynamicMetadata(sptr<SurfaceBuffer> const& surfaceBuffer, HdrMetadataValue &metadataValue)
{
    std::vector<uint8_t> dynamicDataVec;
    if (Media::VpeUtils::GetSbDynamicMetadata(surfaceBuffer, dynamicDataVec) && dynamicDataVec.size() > 0) {
        array<uint8_t> dataArr(dynamicDataVec);
        metadataValue = HdrMetadataValue::make_arrayBuffer(dataArr);
        return true;
    } else {
        IMAGE_LOGE("[%{public}s] GetSbDynamicMetadata failed", __func__);
        return false;
    }
}

static bool SetDynamicMetadata(sptr<SurfaceBuffer> &surfaceBuffer, HdrMetadataValue const& metadataValue)
{
    if (!metadataValue.holds_arrayBuffer()) {
        IMAGE_LOGE("[%{public}s] Key and value types are inconsistent", __func__);
        return false;
    }

    std::vector<uint8_t> dynamicDataVec;
    array<uint8_t> metadataArr = metadataValue.get_arrayBuffer_ref();
    dynamicDataVec.resize(metadataArr.size());
    if (memcpy_s(dynamicDataVec.data(), dynamicDataVec.size(), metadataArr.data(), metadataArr.size()) != EOK) {
        IMAGE_LOGE("[%{public}s] memcpy failed", __func__);
        return false;
    }
    if (!Media::VpeUtils::SetSbDynamicMetadata(surfaceBuffer, dynamicDataVec)) {
        IMAGE_LOGE("[%{public}s] SetSbDynamicMetadata failed", __func__);
        return false;
    }
    return true;
}

static bool GetGainmapMetadata(sptr<SurfaceBuffer> const& surfaceBuffer, HdrMetadataValue &metadataValue)
{
    std::vector<uint8_t> gainmapDataVec;
    if (Media::VpeUtils::GetSbDynamicMetadata(surfaceBuffer, gainmapDataVec) &&
        gainmapDataVec.size() == sizeof(Media::HDRVividExtendMetadata)) {
        Media::HDRVividExtendMetadata &gainmapMetadata =
            *(reinterpret_cast<Media::HDRVividExtendMetadata*>(gainmapDataVec.data()));
        metadataValue = HdrMetadataValue::make_hdrGainmapMetadata(BuildHdrGainmapMetadata(gainmapMetadata));
        return true;
    } else {
        IMAGE_LOGE("[%{public}s] GetSbDynamicMetadata failed", __func__);
        return false;
    }
}

static bool SetGainmapMetadata(sptr<SurfaceBuffer> &surfaceBuffer, Media::PixelMap &pixelMap,
    HdrMetadataValue const& metadataValue)
{
    if (!metadataValue.holds_hdrGainmapMetadata()) {
        IMAGE_LOGE("[%{public}s] Key and value types are inconsistent", __func__);
        return false;
    }

    uint32_t vecSize = sizeof(Media::HDRVividExtendMetadata);
    std::vector<uint8_t> gainmapDataVec(vecSize);
    Media::HDRVividExtendMetadata extendMetadata;
#ifdef IMAGE_COLORSPACE_FLAG
    ColorManager::ColorSpace colorSpace = pixelMap.InnerGetGrColorSpace();
    uint16_t primary = Media::ColorUtils::GetPrimaries(colorSpace.GetColorSpaceName());
#else
    uint16_t primary = 0;
#endif
    extendMetadata.baseColorMeta.baseColorPrimary = primary;

    HdrGainmapMetadata gainmapMetadata = metadataValue.get_hdrGainmapMetadata_ref();
    extendMetadata.gainmapColorMeta.combineColorPrimary =
        gainmapMetadata.useBaseColorFlag ? primary : static_cast<uint8_t>(Media::CM_BT2020_HLG_FULL);
    extendMetadata.gainmapColorMeta.enhanceDataColorModel =
        gainmapMetadata.useBaseColorFlag ? primary : static_cast<uint8_t>(Media::CM_BT2020_HLG_FULL);
    extendMetadata.gainmapColorMeta.alternateColorPrimary = static_cast<uint8_t>(Media::CM_BT2020_HLG_FULL);

    ParseHdrGainmapMetadata(gainmapMetadata, extendMetadata);
    
    if (memcpy_s(gainmapDataVec.data(), vecSize, &extendMetadata, vecSize) != EOK) {
        IMAGE_LOGE("[%{public}s] memcpy failed", __func__);
        return false;
    }
    if (!Media::VpeUtils::SetSbDynamicMetadata(surfaceBuffer, gainmapDataVec)) {
        IMAGE_LOGE("[%{public}s] SetSbDynamicMetadata failed", __func__);
        return false;
    }
    return true;
}

HdrMetadataValue PixelMapImpl::GetMetadata(HdrMetadataKey key)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Native PixelMap is nullptr");
        return HdrMetadataValue::make_hdrMetadataType(HdrMetadataType::key_t::NONE);
    }
    if (nativePixelMap_->GetAllocatorType() != Media::AllocatorType::DMA_ALLOC) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_DMA_NOT_EXIST, "PixelMap memory type is not DMA memory");
        return HdrMetadataValue::make_hdrMetadataType(HdrMetadataType::key_t::NONE);
    }

    bool success = false;
    HdrMetadataValue metadataValue = HdrMetadataValue::make_hdrMetadataType(HdrMetadataType::key_t::NONE);
    sptr<SurfaceBuffer> surfaceBuffer(reinterpret_cast<SurfaceBuffer*>(nativePixelMap_->GetFd()));
    switch (key.get_key()) {
        case HdrMetadataKey::key_t::HDR_METADATA_TYPE:
            success = GetMetadataType(surfaceBuffer, metadataValue);
            break;
        case HdrMetadataKey::key_t::HDR_STATIC_METADATA:
            success = GetStaticMetadata(surfaceBuffer, metadataValue);
            break;
        case HdrMetadataKey::key_t::HDR_DYNAMIC_METADATA:
            success = GetDynamicMetadata(surfaceBuffer, metadataValue);
            break;
        case HdrMetadataKey::key_t::HDR_GAINMAP_METADATA:
            success = GetGainmapMetadata(surfaceBuffer, metadataValue);
            break;
        default:
            success = false;
    }

    if (!success) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEMORY_COPY_FAILED, "Get metadata failed");
        return HdrMetadataValue::make_hdrMetadataType(HdrMetadataType::key_t::NONE);
    }
    return metadataValue;
}

void PixelMapImpl::SetMetadataSync(HdrMetadataKey key, HdrMetadataValue const& value)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_IMAGE_INVALID_PARAMETER, "Native PixelMap is nullptr");
        return;
    }
    if (nativePixelMap_->GetAllocatorType() != Media::AllocatorType::DMA_ALLOC) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_DMA_NOT_EXIST, "PixelMap memory type is not DMA memory");
        return;
    }

    bool success = false;
    sptr<SurfaceBuffer> surfaceBuffer(reinterpret_cast<SurfaceBuffer*>(nativePixelMap_->GetFd()));
    switch (key.get_key()) {
        case HdrMetadataKey::key_t::HDR_METADATA_TYPE:
            success = SetMetadataType(surfaceBuffer, value);
            break;
        case HdrMetadataKey::key_t::HDR_STATIC_METADATA:
            success = SetStaticMetadata(surfaceBuffer, value);
            break;
        case HdrMetadataKey::key_t::HDR_DYNAMIC_METADATA:
            success = SetDynamicMetadata(surfaceBuffer, value);
            break;
        case HdrMetadataKey::key_t::HDR_GAINMAP_METADATA:
            success = SetGainmapMetadata(surfaceBuffer, *(nativePixelMap_.get()), value);
            break;
        default:
            success = false;
    }

    if (!success) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEMORY_COPY_FAILED, "Set metadata failed");
    }
}
#else
HdrMetadataValue PixelMapImpl::GetMetadata(HdrMetadataKey key)
{
    return HdrMetadataValue::make_hdrMetadataType(HdrMetadataType::key_t::NONE);
}

void PixelMapImpl::SetMetadataSync(HdrMetadataKey key, HdrMetadataValue const& value)
{
    return;
}
#endif

void PixelMapImpl::ReleaseSync()
{
    if (nativePixelMap_ != nullptr) {
        if (!nativePixelMap_->IsModifiable()) {
            ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Unable to release the PixelMap "
                "because it's locked or unmodifiable");
        } else {
            IMAGE_LOGD("[%{public}s] Attempt to release PixelMap with ID: %{public}d",
                __func__, nativePixelMap_->GetUniqueId());
            nativePixelMap_.reset();
        }
    }
}

bool PixelMapImpl::GetIsEditable()
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return false;
    }

    return nativePixelMap_->IsEditable();
}

bool PixelMapImpl::GetIsStrideAlignment()
{
    if (nativePixelMap_ == nullptr) {
        IMAGE_LOGE("[%{public}s] Native PixelMap is nullptr", __func__);
        return false;
    }

    return nativePixelMap_->IsStrideAlignment();
}

void PixelMapImpl::SetCaptureId(int32_t captureId)
{
    captureId_ = captureId;
}

int32_t PixelMapImpl::GetCaptureId()
{
    return captureId_;
}

void PixelMapImpl::SetTimestamp(int64_t timestamp)
{
    timestamp_ = timestamp;
}

int64_t PixelMapImpl::GetTimestamp()
{
    return timestamp_;
}

bool PixelMapImpl::Is10BitFormat(Media::PixelFormat format)
{
    return format == Media::PixelFormat::RGBA_1010102 || format == Media::PixelFormat::YCBCR_P010 ||
        format == Media::PixelFormat::YCRCB_P010;
}

void PixelMapImpl::ParseInitializationOptions(InitializationOptions const& etsOptions,
    Media::InitializationOptions &options)
{
    options.size = {etsOptions.size.width, etsOptions.size.height};
    if (etsOptions.srcPixelFormat) {
        options.srcPixelFormat = Media::PixelFormat(etsOptions.srcPixelFormat->get_value());
    }
    if (etsOptions.pixelFormat) {
        options.pixelFormat = Media::PixelFormat(etsOptions.pixelFormat->get_value());
    }
    if (etsOptions.editable) {
        options.editable = *etsOptions.editable;
    }
    if (etsOptions.alphaType) {
        options.alphaType = Media::AlphaType(etsOptions.alphaType->get_value());
    }
    if (etsOptions.scaleMode) {
        options.scaleMode = Media::ScaleMode(etsOptions.scaleMode->get_value());
    }
}

void PixelMapImpl::Release()
{
    if (nativePixelMap_ != nullptr) {
        IMAGE_LOGD("[%{public}s] Attempt to release PixelMap with ID: %{public}d",
            __func__, nativePixelMap_->GetUniqueId());
        nativePixelMap_.reset();
    }
}

} // namespace ANI::Image

TH_EXPORT_CPP_API_MakeEmptySize(ANI::Image::MakeEmptySize);
TH_EXPORT_CPP_API_MakeEmptyImageInfo(ANI::Image::MakeEmptyImageInfo);
TH_EXPORT_CPP_API_CreatePixelMapByBufferAndOptionsSync(ANI::Image::CreatePixelMapByBufferAndOptionsSync);
TH_EXPORT_CPP_API_CreatePixelMapByOptionsSync(ANI::Image::CreatePixelMapByOptionsSync);
TH_EXPORT_CPP_API_CreatePixelMapByPtr(ANI::Image::CreatePixelMapByPtr);
TH_EXPORT_CPP_API_CreatePixelMapFromSurfaceByIdSync(ANI::Image::CreatePixelMapFromSurfaceByIdSync);
TH_EXPORT_CPP_API_CreatePixelMapFromSurfaceByIdAndRegionSync(ANI::Image::CreatePixelMapFromSurfaceByIdAndRegionSync);
TH_EXPORT_CPP_API_CreatePixelMapFromParcel(ANI::Image::CreatePixelMapFromParcel);
TH_EXPORT_CPP_API_CreatePremultipliedPixelMapSync(ANI::Image::CreatePremultipliedPixelMapSync);
TH_EXPORT_CPP_API_CreateUnpremultipliedPixelMapSync(ANI::Image::CreateUnpremultipliedPixelMapSync);