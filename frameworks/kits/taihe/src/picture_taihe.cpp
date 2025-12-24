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

#include "auxiliary_picture_taihe.h"
#include "image_common.h"
#include "image_log.h"
#include "image_taihe_utils.h"
#include "image_type.h"
#include "picture_taihe.h"
#include "picture_taihe_ani.h"
#include "pixel_map_taihe.h"
#include "media_errors.h"
#include "message_parcel.h"
#include "metadata_taihe.h"

using namespace ANI::Image;

namespace ANI::Image {

PictureImpl::PictureImpl() : nativePicture_(nullptr), isRelease(false) {}

PictureImpl::PictureImpl(std::shared_ptr<OHOS::Media::Picture> picture)
{
    nativePicture_ = picture;
    if (nativePicture_ == nullptr) {
        IMAGE_LOGE("Failed to set nativePicture_ with null. Maybe a reentrancy error");
    }
}

PictureImpl::PictureImpl(int64_t aniPtr)
{
    OHOS::Media::PictureTaiheAni *pictureAni = reinterpret_cast<OHOS::Media::PictureTaiheAni *>(aniPtr);
    if (pictureAni != nullptr && pictureAni->nativePicture_ != nullptr) {
        nativePicture_ = pictureAni->nativePicture_;
    } else {
        ImageTaiheUtils::ThrowExceptionError("aniPtr is invalid or nativePicture_ is nullptr");
    }
}

PictureImpl::~PictureImpl()
{
    Release();
}

int64_t PictureImpl::GetImplPtr()
{
    return static_cast<int64_t>(reinterpret_cast<uintptr_t>(this));
}

std::shared_ptr<OHOS::Media::Picture> PictureImpl::GetNativePtr()
{
    return nativePicture_;
}

Picture PictureImpl::CreatePicture(std::shared_ptr<OHOS::Media::Picture> picture)
{
    return make_holder<PictureImpl, Picture>(picture);
}

optional<PixelMap> PictureImpl::GetMainPixelmap()
{
    if (nativePicture_ == nullptr) {
        IMAGE_LOGE("Native picture is nullptr!");
        return optional<PixelMap>(std::nullopt);
    }
    auto pixelmap = nativePicture_->GetMainPixel();
    if (pixelmap == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Get main pixelmap failed, pixelmap is nullptr!");
        return optional<PixelMap>(std::nullopt);
    }
    auto res = PixelMapImpl::CreatePixelMap(pixelmap);
    return optional<PixelMap>(std::in_place, res);
}

optional<PixelMap> PictureImpl::GetHdrComposedPixelmapSync()
{
    IMAGE_LOGD("GetHdrComposedPixelMap IN");
    if (nativePicture_ == nullptr) {
        IMAGE_LOGE("Empty native pixelmap");
        return optional<PixelMap>(std::nullopt);
    }
    if (nativePicture_->GetAuxiliaryPicture(OHOS::Media::AuxiliaryPictureType::GAINMAP) == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_UNSUPPORTED_OPERATION, "There is no GAINMAP");
        return optional<PixelMap>(std::nullopt);
    }
    if (nativePicture_->GetMainPixel()->GetAllocatorType() != OHOS::Media::AllocatorType::DMA_ALLOC) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_UNSUPPORTED_OPERATION, "Unsupported operations");
        return optional<PixelMap>(std::nullopt);
    }

    auto tmpixel = nativePicture_->GetHdrComposedPixelMap();
    if (tmpixel == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERROR, "Get hdr composed pixelMap failed");
        return optional<PixelMap>(std::nullopt);
    }
    auto res = PixelMapImpl::CreatePixelMap(std::move(tmpixel));
    return optional<PixelMap>(std::in_place, res);
}

NullablePixelMap PictureImpl::GetGainmapPixelmap()
{
    IMAGE_LOGD("GetGainmapPixelmap");
    if (nativePicture_ != nullptr) {
        auto gainpixelmap = nativePicture_->GetGainmapPixelMap();
        if (gainpixelmap != nullptr) {
            return NullablePixelMap::make_type_pixelMap(PixelMapImpl::CreatePixelMap(gainpixelmap));
        } else {
            return NullablePixelMap::make_type_null();
        }
    } else {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_MEDIA_UNKNOWN, "Picture is a null pointer");
        return NullablePixelMap::make_type_null();
    }
}

NullablePixelMap PictureImpl::GetThumbnailPixelmap()
{
    IMAGE_LOGD("GetThumbnailPixelmap");
    if (nativePicture_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Picture is a null pointer");
        return NullablePixelMap::make_type_null();
    }

    auto thumbnailPixelmap = nativePicture_->GetThumbnailPixelMap();
    if (thumbnailPixelmap == nullptr) {
        IMAGE_LOGE("%{public}s Get thumbnail pixelmap failed, thumbnail pixelmap is nullptr", __func__);
        return NullablePixelMap::make_type_null();
    }
    return NullablePixelMap::make_type_pixelMap(PixelMapImpl::CreatePixelMap(thumbnailPixelmap));
}

void PictureImpl::SetThumbnailPixelmap(PixelMap thumbnailPixelmap)
{
    IMAGE_LOGD("SetThumbnailPixelmap IN");
    if (nativePicture_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Picture is a null pointer");
        return;
    }

    std::shared_ptr<OHOS::Media::PixelMap> nativeThumbnailPixelmap = PixelMapImpl::GetPixelMap(thumbnailPixelmap);
    if (nativeThumbnailPixelmap == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "native thumbnail pixelmap is nullptr");
        return;
    }
    nativePicture_->SetThumbnailPixelMap(nativeThumbnailPixelmap);
}

static OHOS::Media::AuxiliaryPictureType ParseAuxiliaryPictureType(int32_t val)
{
    if (!ImageTaiheUtils::GetTaiheSupportedAuxTypes().count(static_cast<OHOS::Media::AuxiliaryPictureType>(val))) {
        IMAGE_LOGE("%{public}s auxiliary picture type is not supported: %{public}d", __func__, val);
        return OHOS::Media::AuxiliaryPictureType::NONE;
    }
    return OHOS::Media::AuxiliaryPictureType(val);
}

void PictureImpl::SetAuxiliaryPicture(AuxiliaryPictureType type, weak::AuxiliaryPicture auxiliaryPicture)
{
    IMAGE_LOGD("SetAuxiliaryPictureSync IN");

    OHOS::Media::AuxiliaryPictureType auxType = ParseAuxiliaryPictureType(type.get_value());
    if (auxType == OHOS::Media::AuxiliaryPictureType::NONE) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER,
            "The type does not match the auxiliary picture type!");
            return;
    }

    AuxiliaryPictureImpl* auxiliaryPictureImpl =
        reinterpret_cast<AuxiliaryPictureImpl*>(auxiliaryPicture->GetImplPtr());
    if (auxiliaryPictureImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Fail to unwrap AuxiliaryPictureImpl!");
        return;
    }

    if (nativePicture_ != nullptr) {
        auto auxiliaryPicturePtr = auxiliaryPictureImpl->GetNativeAuxiliaryPic();
        if (auxiliaryPicturePtr != nullptr) {
            if (auxType != auxiliaryPicturePtr->GetAuxiliaryPictureInfo().auxiliaryPictureType) {
                ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER,
                    "The type does not match the auxiliary picture type!");
            } else {
                nativePicture_->SetAuxiliaryPicture(auxiliaryPicturePtr);
            }
        } else {
            ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER,
                "Native auxiliary picture is nullptr!");
        }
    } else {
        ImageTaiheUtils::ThrowExceptionError("native picture is nullptr!");
    }
}

AuxPicture PictureImpl::GetAuxiliaryPicture(AuxiliaryPictureType type)
{
    AuxPicture result = AuxPicture::make_type_null();

    IMAGE_LOGD("GetAuxiliaryPicture IN");
    OHOS::Media::AuxiliaryPictureType auxType = ParseAuxiliaryPictureType(type.get_value());
    if (auxType == OHOS::Media::AuxiliaryPictureType::NONE) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER,
            "The type does not match the auxiliary picture type!");
        return result;
    }

    if (nativePicture_ != nullptr) {
        auto auxiliaryPic = nativePicture_->GetAuxiliaryPicture(auxType);
        if (auxiliaryPic != nullptr) {
            result = AuxPicture::make_type_auxPicture(
                make_holder<AuxiliaryPictureImpl, AuxiliaryPicture>(std::move(auxiliaryPic)));
        } else {
            IMAGE_LOGE("native auxiliary picture is nullptr!");
        }
    } else {
        IMAGE_LOGE("native picture is nullptr!");
    }

    return result;
}

void PictureImpl::DropAuxiliaryPicture(AuxiliaryPictureType type)
{
    IMAGE_LOGD("DropAuxiliaryPicture IN");
    OHOS::Media::AuxiliaryPictureType auxType = ParseAuxiliaryPictureType(type.get_value());
    if (auxType == OHOS::Media::AuxiliaryPictureType::NONE) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER,
            "The type does not match the auxiliary picture type!");
    }

    if (nativePicture_ == nullptr) {
        IMAGE_LOGE("native picture is nullptr!");
        return;
    }
    nativePicture_->DropAuxiliaryPicture(auxType);
    IMAGE_LOGD("DropAuxiliaryPicture OUT");
}

void PictureImpl::SetMetadataSync(MetadataType metadataType, weak::Metadata metadata)
{
    IMAGE_LOGD("SetMetadata IN");
    if (nativePicture_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Empty native picture");
        return;
    }

    OHOS::Media::MetadataType type;
    int32_t typeValue = metadataType.get_value();
    if (OHOS::Media::Picture::IsValidPictureMetadataType(static_cast<OHOS::Media::MetadataType>(typeValue))) {
        type = OHOS::Media::MetadataType(typeValue);
    } else {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_UNSUPPORTED_METADATA, "Unsupport MetadataType");
        return;
    }

    MetadataImpl* metadataImpl = reinterpret_cast<MetadataImpl*>(metadata->GetImplPtr());
    if (metadataImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Fail to unwrap MetadataImpl.");
        return;
    }
    std::shared_ptr<OHOS::Media::ImageMetadata> imageMetadata = metadataImpl->GetNativeMetadata();

    int32_t status = static_cast<int32_t>(nativePicture_->SetMetadata(type, imageMetadata));
    if (status != OHOS::Media::SUCCESS) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERROR, "Set Metadata failed!");
    }
}

optional<Metadata> PictureImpl::GetMetadataSync(MetadataType metadataType)
{
    IMAGE_LOGD("GetMetadata IN");
    if (nativePicture_ == nullptr) {
        IMAGE_LOGE("Empty native picture");
        return optional<Metadata>(std::nullopt);
    }

    int32_t typeValue = metadataType.get_value();
    if (!OHOS::Media::Picture::IsValidPictureMetadataType(static_cast<OHOS::Media::MetadataType>(typeValue))) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_UNSUPPORTED_METADATA, "Unsupport MetadataType");
        return optional<Metadata>(std::nullopt);
    }

    auto imageMetadata = nativePicture_->GetMetadata(static_cast<OHOS::Media::MetadataType>(typeValue));
    if (imageMetadata == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERROR, "Get Metadata failed!");
        return optional<Metadata>(std::nullopt);
    }
    auto res = make_holder<MetadataImpl, Metadata>(imageMetadata);
    return optional<Metadata>(std::in_place, res);
}

static OHOS::MessageParcel* UnwarpMessageParcel(uintptr_t sequence)
{
    ani_env* env = taihe::get_env();
    CHECK_ERROR_RETURN_RET_LOG(env == nullptr, nullptr, "get_env failed");
    ani_long messageParcel {};
    ani_status status = env->Object_CallMethodByName_Long(reinterpret_cast<ani_object>(sequence), "getNativePtr",
        nullptr, &messageParcel);
    if (status != ANI_OK) {
        IMAGE_LOGE("UnwarpMessageParcel failed. status: %{public}d", status);
        return nullptr;
    }
    return reinterpret_cast<OHOS::MessageParcel*>(messageParcel);
}

void PictureImpl::Marshalling(uintptr_t sequence)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    OHOS::MessageParcel* messageParcel = UnwarpMessageParcel(sequence);
    if (messageParcel == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IPC, "Marshalling picture to parcel failed.");
        return;
    }
    bool st = nativePicture_->Marshalling(*messageParcel);
    if (!st) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IPC, "Marshalling picture to parcel failed.");
    }
#endif
}

void PictureImpl::Release()
{
    if (!isRelease) {
        if (nativePicture_ != nullptr) {
            nativePicture_ = nullptr;
        }
        isRelease = true;
    }
}

Picture CreatePictureByPixelMap(weak::PixelMap mainPixelmap)
{
    IMAGE_LOGI("CreatePicture IN");
    PixelMapImpl* pixelMapImpl = reinterpret_cast<PixelMapImpl*>(mainPixelmap->GetImplPtr());
    if (pixelMapImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Pixelmap instance is nullptr!");
        return make_holder<PictureImpl, Picture>();
    }
    auto nativePixelMap = pixelMapImpl->GetNativePtr();
    if (nativePixelMap == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Get native pixelmap failed!");
        return make_holder<PictureImpl, Picture>();
    }
    auto picture = OHOS::Media::Picture::Create(nativePixelMap);
    if (picture == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERROR, "Create picture failed!");
        return make_holder<PictureImpl, Picture>();
    }
    IMAGE_LOGI("CreatePicture OUT");
    return make_holder<PictureImpl, Picture>(std::move(picture));
}

Picture CreatePictureFromParcel(uintptr_t sequence)
{
    IMAGE_LOGD("Call CreatePictureFromParcel");

    OHOS::MessageParcel* messageParcel = UnwarpMessageParcel(sequence);
    if (messageParcel == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IPC, "Get parcel failed");
        return make_holder<PictureImpl, Picture>();
    }

    OHOS::Media::PICTURE_ERR error;
    auto picture = OHOS::Media::Picture::Unmarshalling(*messageParcel, error);
    if (picture == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IPC, "Unmarshalling picture failed");
        return make_holder<PictureImpl, Picture>();
    }
    std::shared_ptr<OHOS::Media::Picture> picturePtr(picture);
    return make_holder<PictureImpl, Picture>(std::move(picturePtr));
}

Picture CreatePictureByPtr(int64_t aniPtr)
{
    return make_holder<PictureImpl, Picture>(aniPtr);
}

Picture CreatePictureByHdrAndSdrPixelMapSync(weak::PixelMap hdrPixelMap, weak::PixelMap sdrPixelMap)
{
    IMAGE_LOGD("CreatePictureByHdrAndSdrPixelMap IN");
    if (hdrPixelMap.is_error()) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Get arg hdr Pixelmap failed");
        return make_holder<PictureImpl, Picture>();
    }
    if (sdrPixelMap.is_error()) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Get arg sdr Pixelmap failed");
        return make_holder<PictureImpl, Picture>();
    }

    PixelMapImpl* hdrPixelMapImpl = reinterpret_cast<PixelMapImpl*>(hdrPixelMap->GetImplPtr());
    PixelMapImpl* sdrPixelMapImpl = reinterpret_cast<PixelMapImpl*>(sdrPixelMap->GetImplPtr());
    if (hdrPixelMapImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Get arg hdr Pixelmap failed");
        return make_holder<PictureImpl, Picture>();
    }
    if (sdrPixelMapImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Get arg sdr Pixelmap failed");
        return make_holder<PictureImpl, Picture>();
    }

    auto nativeHdrPixelMap = hdrPixelMapImpl->GetNativePtr();
    auto nativeSdrPixelMap = sdrPixelMapImpl->GetNativePtr();
    auto picture = OHOS::Media::Picture::CreatePictureByHdrAndSdrPixelMap(nativeHdrPixelMap, nativeSdrPixelMap);
    if (picture == nullptr) {
        IMAGE_LOGE("fail to create picture sync");
        return make_holder<PictureImpl, Picture>();
    }
    IMAGE_LOGD("CreatePictureByHdrAndSdrPixelMap OUT");
    return make_holder<PictureImpl, Picture>(std::move(picture));
}
} // namespace ANI::Image

TH_EXPORT_CPP_API_CreatePictureByPixelMap(CreatePictureByPixelMap);
TH_EXPORT_CPP_API_CreatePictureFromParcel(CreatePictureFromParcel);
TH_EXPORT_CPP_API_CreatePictureByPtr(CreatePictureByPtr);
TH_EXPORT_CPP_API_CreatePictureByHdrAndSdrPixelMapSync(CreatePictureByHdrAndSdrPixelMapSync);