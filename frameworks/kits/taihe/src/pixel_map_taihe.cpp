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

#include "ani_color_space_object_convertor.h"
#include "image_log.h"
#include "image_taihe_utils.h"
#include "media_errors.h"
#include "pixel_map_taihe_ani.h"
#include "pixel_map_taihe.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include <regex>
#include "pixel_map_from_surface.h"
#include "sync_fence.h"
#include "transaction/rs_interfaces.h"
#endif

namespace ANI::Image {

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
            IMAGE_LOGE("[PixelMap ANI] GetSurfaceSize: GetSurface failed");
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
            IMAGE_LOGE("[PixelMap ANI] GetSurfaceSize: GetLastFlushedBuffer fail, ret = %{public}d", ret);
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
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Empty or invalid surfaceId");
        return make_holder<PixelMapImpl, PixelMap>();
    }
    if (!GetSurfaceSize(surfaceId, region)) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Get surface size failed");
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
    IMAGE_LOGD("[PixelMap ANI] createPixelMapFromSurfaceByIdSync: id=%{public}s", surfaceId.c_str());
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
    IMAGE_LOGD("[PixelMap ANI] createPixelMapFromSurfaceByIdAndRegionSync: id=%{public}s, area=%{public}d,%{public}d,"
        "%{public}d,%{public}d", surfaceId.c_str(), region.left, region.top, region.width, region.height);
    if (region.width <= 0 || region.height <= 0) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Invalid region");
        return make_holder<PixelMapImpl, PixelMap>();
    }
    return CreatePixelMapFromSurface(surfaceId, region);
#endif
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
    }
}

PixelMapImpl::PixelMapImpl(std::shared_ptr<Media::PixelMap> pixelMap)
{
    nativePixelMap_ = pixelMap;
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Create PixelMap failed");
    }
}

PixelMapImpl::PixelMapImpl(int64_t aniPtr)
{
    Media::PixelMapTaiheAni* pixelMapAni = reinterpret_cast<Media::PixelMapTaiheAni*>(aniPtr);
    nativePixelMap_ = pixelMapAni->nativePixelMap_;
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Create PixelMap failed");
    }
}

PixelMapImpl::~PixelMapImpl()
{
    Release();
}

int64_t PixelMapImpl::GetImplPtr()
{
    return reinterpret_cast<uintptr_t>(this);
}

std::shared_ptr<Media::PixelMap> PixelMapImpl::GetNativePtr()
{
    return nativePixelMap_;
}

std::shared_ptr<Media::PixelMap> PixelMapImpl::GetPixelMap(PixelMap etsPixelMap)
{
    PixelMapImpl *pixelMapImpl = reinterpret_cast<PixelMapImpl *>(etsPixelMap->GetImplPtr());
    if (pixelMapImpl == nullptr) {
        IMAGE_LOGE("%{public}s etsPixelMap is nullptr", __func__);
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
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return MakeEmptyImageInfo();
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
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
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return;
    }

    uint32_t status = nativePixelMap_->ReadPixels(dst.size(), dst.data());
    if (status != Media::SUCCESS) {
        IMAGE_LOGE("[PixelMap ANI] ReadPixels failed");
    }
}

void PixelMapImpl::ReadPixelsSync(weak::PositionArea area)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
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
        IMAGE_LOGE("[PixelMap ANI] ReadPixels by region failed");
    }
}

void PixelMapImpl::WriteBufferToPixelsSync(array_view<uint8_t> src)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return;
    }

    uint32_t status = nativePixelMap_->WritePixels(src.data(), src.size());
    if (status != Media::SUCCESS) {
        IMAGE_LOGE("[PixelMap ANI] WritePixels failed");
    }
}

PixelMap PixelMapImpl::CreateAlphaPixelmapSync()
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return make_holder<PixelMapImpl, PixelMap>();
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
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
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return 0;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return 0;
    }

    return nativePixelMap_->GetRowBytes();
}

int32_t PixelMapImpl::GetPixelBytesNumber()
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return 0;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return 0;
    }

    return nativePixelMap_->GetByteCount();
}

void PixelMapImpl::ScaleSync(float x, float y)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return;
    }

    nativePixelMap_->scale(x, y);
}

void PixelMapImpl::ScaleWithAntiAliasingSync(float x, float y, AntiAliasingLevel level)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return;
    }

    nativePixelMap_->scale(x, y, Media::AntiAliasingOption(level.get_value()));
}

void PixelMapImpl::CropSync(ohos::multimedia::image::image::Region const& region)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return;
    }

    Media::Rect rect = {region.x, region.y, region.size.width, region.size.height};
    uint32_t status = nativePixelMap_->crop(rect);
    if (status != Media::SUCCESS) {
        IMAGE_LOGE("[PixelMap ANI] crop failed");
    }
}

void PixelMapImpl::RotateSync(float angle)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return;
    }

    nativePixelMap_->rotate(angle);
}

void PixelMapImpl::FlipSync(bool horizontal, bool vertical)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return;
    }

    nativePixelMap_->flip(horizontal, vertical);
}

void PixelMapImpl::OpacitySync(float rate)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return;
    }

    uint32_t status = nativePixelMap_->SetAlpha(rate);
    if (status != Media::SUCCESS) {
        IMAGE_LOGE("[PixelMap ANI] SetAlpha failed");
    }
}

void PixelMapImpl::SetMemoryNameSync(string_view name)
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
        return;
    }
    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "PixelMap has crossed threads");
        return;
    }

    uint32_t status = nativePixelMap_->SetMemoryName(std::string(name));
    if (status == Media::ERR_MEMORY_NOT_SUPPORT) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEMORY_NOT_SUPPORT, "Set memory name not supported");
    } else if (status == Media::COMMON_ERR_INVALID_PARAMETER) {
        ImageTaiheUtils::ThrowExceptionError(Media::COMMON_ERR_INVALID_PARAMETER, "Memory name size out of range");
    }
}

void PixelMapImpl::ToSdrSync()
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEDIA_INVALID_OPERATION, "Internal error.");
        return;
    }

    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_MEDIA_INVALID_OPERATION, "Pixelmap is not editable");
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

    if (!aniEditable_) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Pixelmap is not editable");
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

void PixelMapImpl::ReleaseSync()
{
    if (nativePixelMap_ != nullptr) {
        if (!nativePixelMap_->IsModifiable()) {
            ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Unable to release the PixelMap "
                "because it's locked or unmodifiable");
        } else {
            IMAGE_LOGD("[PixelMap ANI] Releasing PixelMap with ID: %{public}d", nativePixelMap_->GetUniqueId());
            nativePixelMap_.reset();
        }
    }
}

bool PixelMapImpl::GetIsStrideAlignment()
{
    if (nativePixelMap_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(Media::ERR_RESOURCE_UNAVAILABLE, "Native PixelMap is nullptr");
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