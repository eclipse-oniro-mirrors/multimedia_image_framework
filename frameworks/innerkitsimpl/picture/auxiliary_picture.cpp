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

#include "picture.h"
#include "auxiliary_picture.h"
#include "media_errors.h"
#include "image_log.h"
#include "image_utils.h"
#include "exif_metadata.h"
#include "fragment_metadata.h"

namespace OHOS {
namespace Media {

const static uint64_t MAX_PICTURE_META_TYPE_COUNT = 64;
const static uint64_t MAX_JPEG_TAG_NAME_LENGTH = 100;
AuxiliaryPicture::~AuxiliaryPicture() {}

std::unique_ptr<AuxiliaryPicture> AuxiliaryPicture::Create(std::shared_ptr<PixelMap> &content,
                                                           AuxiliaryPictureType type, Size size)
{
    if (content == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AuxiliaryPicture> dstAuxPicture = std::make_unique<AuxiliaryPicture>();
    dstAuxPicture->content_ = content;
    dstAuxPicture->SetType(type);
    dstAuxPicture->SetSize(size);
    dstAuxPicture->UpdateAuxiliaryPictureInfo();
    return dstAuxPicture;
}

void AuxiliaryPicture::UpdateAuxiliaryPictureInfo()
{
    if (content_ == nullptr) {
        IMAGE_LOGE("%{public}s content_ is nullptr", __func__);
        return;
    }
    ImageInfo imageInfo;
    content_->GetImageInfo(imageInfo);

    auxiliaryPictureInfo_.size = imageInfo.size;
    auxiliaryPictureInfo_.rowStride = static_cast<uint32_t>(content_->GetRowStride());
    auxiliaryPictureInfo_.colorSpace = imageInfo.colorSpace;
    auxiliaryPictureInfo_.pixelFormat = imageInfo.pixelFormat;
}

std::unique_ptr<AuxiliaryPicture> AuxiliaryPicture::Create(sptr<SurfaceBuffer> &surfaceBuffer,
                                                           AuxiliaryPictureType type, Size size)
{
    std::shared_ptr<PixelMap> pixelMap = Picture::SurfaceBuffer2PixelMap(surfaceBuffer);
    return Create(pixelMap, type, size);
}

AuxiliaryPictureType AuxiliaryPicture::GetType()
{
    return auxiliaryPictureInfo_.auxiliaryPictureType;
}

void AuxiliaryPicture::SetType(AuxiliaryPictureType type)
{
    auxiliaryPictureInfo_.auxiliaryPictureType = type;
}

Size AuxiliaryPicture::GetSize()
{
    return auxiliaryPictureInfo_.size;
}

void AuxiliaryPicture::SetSize(Size size)
{
    auxiliaryPictureInfo_.size = size;
}

std::shared_ptr<PixelMap> AuxiliaryPicture::GetContentPixel()
{
    return content_;
}

void AuxiliaryPicture::SetContentPixel(std::shared_ptr<PixelMap> content)
{
    content_ = content;
    UpdateAuxiliaryPictureInfo();
}

uint32_t AuxiliaryPicture::ReadPixels(const uint64_t &bufferSize, uint8_t *dst)
{
    if (content_ == nullptr) {
        return ERR_MEDIA_NULL_POINTER;
    }
    return content_->ReadPixels(bufferSize, dst);
}

uint32_t AuxiliaryPicture::WritePixels(const uint8_t *source, const uint64_t &bufferSize)
{
    if (content_ == nullptr) {
        return ERR_MEDIA_NULL_POINTER;
    }
    return content_->WritePixels(source, bufferSize);
}

std::shared_ptr<ImageMetadata> AuxiliaryPicture::GetMetadata(MetadataType type)
{
    auto iter = metadatas_.find(type);
    if (iter == metadatas_.end()) {
        return nullptr;
    }
    return iter->second;
}

void AuxiliaryPicture::SetMetadata(MetadataType type, std::shared_ptr<ImageMetadata> metadata)
{
    CHECK_ERROR_RETURN_LOG(metadatas_.size() >= MAX_PICTURE_META_TYPE_COUNT,
        "Failed to set metadata, the size of metadata exceeds the maximum limit %{public}llu.",
        static_cast<unsigned long long>(MAX_PICTURE_META_TYPE_COUNT));
    if (metadata != nullptr) {
        metadatas_[type] = metadata;
    }
}

bool AuxiliaryPicture::HasMetadata(MetadataType type)
{
    auto item = metadatas_.find(type);
    return item != metadatas_.end() && item->second != nullptr;
}

bool AuxiliaryPicture::WriteAuxPictureInfoToParcel(Parcel &data) const
{
    CHECK_ERROR_RETURN_RET_LOG(!data.WriteInt32(static_cast<int32_t>(auxiliaryPictureInfo_.auxiliaryPictureType)),
        false, "Failed to write type of auxiliary pictures.");

    CHECK_ERROR_RETURN_RET_LOG(!data.WriteInt32(static_cast<int32_t>(auxiliaryPictureInfo_.colorSpace)),
        false, "Failed to write color space of auxiliary pictures.");

    CHECK_ERROR_RETURN_RET_LOG(!data.WriteInt32(static_cast<int32_t>(auxiliaryPictureInfo_.pixelFormat)),
        false, "Failed to write pixel format of auxiliary pictures.");

    CHECK_ERROR_RETURN_RET_LOG(!data.WriteUint32(auxiliaryPictureInfo_.rowStride),
        false, "Failed to write row stride of auxiliary pictures.");

    CHECK_ERROR_RETURN_RET_LOG(
        !data.WriteInt32(auxiliaryPictureInfo_.size.height) || !data.WriteInt32(auxiliaryPictureInfo_.size.width),
        false, "Failed to write size of auxiliary pictures.");

    CHECK_ERROR_RETURN_RET_LOG(auxiliaryPictureInfo_.jpegTagName.length() > MAX_JPEG_TAG_NAME_LENGTH,
        false, "The length of jpeg tag name exceeds the maximum limit.");

    CHECK_ERROR_RETURN_RET_LOG(!data.WriteString(auxiliaryPictureInfo_.jpegTagName),
        false, "Failed to write jpegTagName of auxiliary pictures.");

    return true;
}

bool AuxiliaryPicture::Marshalling(Parcel &data) const
{
    CHECK_ERROR_RETURN_RET_LOG(content_ == nullptr, false, "Auxiliary picture is null.");

    CHECK_ERROR_RETURN_RET_LOG(!content_->Marshalling(data), false, "Failed to marshal auxiliary picture.");

    CHECK_ERROR_RETURN_RET_LOG(!WriteAuxPictureInfoToParcel(data), false,
        "write auxiliary picture info to parcel failed.");

    CHECK_ERROR_RETURN_RET_LOG(metadatas_.size() > MAX_PICTURE_META_TYPE_COUNT, false,
        "The number of metadatas exceeds the maximum limit.");

    CHECK_ERROR_RETURN_RET(!data.WriteUint64(static_cast<uint64_t>(metadatas_.size())), false);

    for (const auto &[type, metadata] : metadatas_) {
        int32_t typeInt32 = static_cast<int32_t>(type);
        CHECK_ERROR_RETURN_RET_LOG(metadata == nullptr, false, "Metadata %{public}d is nullptr.", typeInt32);

        CHECK_ERROR_RETURN_RET_LOG(!(data.WriteInt32(typeInt32) && metadata->Marshalling(data)),
            false, "Failed to marshal metadatas.");
    }

    return true;
}

AuxiliaryPicture *AuxiliaryPicture::Unmarshalling(Parcel &data)
{
    PICTURE_ERR error;
    AuxiliaryPicture* dstAuxiliaryPicture = AuxiliaryPicture::Unmarshalling(data, error);
    bool cond = dstAuxiliaryPicture == nullptr || error.errorCode != SUCCESS;
    if (cond) {
        IMAGE_LOGE("unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
            error.errorCode, error.errorInfo.c_str());
    }
    return dstAuxiliaryPicture;
}

AuxiliaryPicture *AuxiliaryPicture::Unmarshalling(Parcel &parcel, PICTURE_ERR &error)
{
    std::unique_ptr<AuxiliaryPicture> auxPtr = std::make_unique<AuxiliaryPicture>();

    std::shared_ptr<PixelMap> contentPtr(PixelMap::Unmarshalling(parcel));
    if (!contentPtr) {
        return nullptr;
    }
    auxPtr->SetContentPixel(contentPtr);
    AuxiliaryPictureInfo auxiliaryPictureInfo;
    auxiliaryPictureInfo.auxiliaryPictureType = static_cast<AuxiliaryPictureType>(parcel.ReadInt32());
    auxiliaryPictureInfo.colorSpace = static_cast<ColorSpace>(parcel.ReadInt32());
    auxiliaryPictureInfo.pixelFormat = static_cast<PixelFormat>(parcel.ReadInt32());
    auxiliaryPictureInfo.rowStride = parcel.ReadUint32();
    auxiliaryPictureInfo.size.height = parcel.ReadInt32();
    auxiliaryPictureInfo.size.width = parcel.ReadInt32();
    auxiliaryPictureInfo.jpegTagName = parcel.ReadString();
    auxPtr->SetAuxiliaryPictureInfo(auxiliaryPictureInfo);

    std::map<MetadataType, std::shared_ptr<ImageMetadata>> metadatas;
    
    uint64_t size = parcel.ReadUint64();
    CHECK_ERROR_RETURN_RET(size > MAX_PICTURE_META_TYPE_COUNT, nullptr);
    for (size_t i = 0; i < size; ++i) {
        MetadataType type = static_cast<MetadataType>(parcel.ReadInt32());
        std::shared_ptr<ImageMetadata> imagedataPtr(nullptr);

        if (type == MetadataType::EXIF) {
            imagedataPtr.reset(ExifMetadata::Unmarshalling(parcel));
            CHECK_ERROR_RETURN_RET(!imagedataPtr, nullptr);
        } else if (type == MetadataType::FRAGMENT) {
            imagedataPtr.reset(FragmentMetadata::Unmarshalling(parcel));
            CHECK_ERROR_RETURN_RET(!imagedataPtr, nullptr);
        } else {
            IMAGE_LOGE("Unsupported metadata type.");
            return nullptr;
        }
        auxPtr->SetMetadata(type, imagedataPtr);
    }

    return auxPtr.release();
}

AuxiliaryPictureInfo AuxiliaryPicture::GetAuxiliaryPictureInfo()
{
    return auxiliaryPictureInfo_;
}

uint32_t AuxiliaryPicture::SetAuxiliaryPictureInfo(const AuxiliaryPictureInfo &auxiliaryPictureInfo)
{
    int32_t apiVersion = ImageUtils::GetAPIVersion();
    IMAGE_LOGD("%{public}s current apiVersion: %{public}d", __func__, apiVersion);
    if (apiVersion > APIVERSION_13) {
        bool cond = content_ == nullptr;
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_MEDIA_NULL_POINTER, "%{public}s pixelmap is nullptr", __func__);
        cond = !ImageUtils::IsValidAuxiliaryInfo(content_, auxiliaryPictureInfo);
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
                                   "%{public}s invalid auxiliary picture info", __func__);
        ImageInfo imageInfo;
        content_->GetImageInfo(imageInfo);
        imageInfo.size = auxiliaryPictureInfo.size;
        imageInfo.pixelFormat = auxiliaryPictureInfo.pixelFormat;
        imageInfo.colorSpace = auxiliaryPictureInfo.colorSpace;
        uint32_t err = content_->SetImageInfo(imageInfo, true);
        cond = err != SUCCESS;
        CHECK_ERROR_RETURN_RET_LOG(cond, err, "%{public}s sync info to pixelmap failed", __func__);
    }
    auxiliaryPictureInfo_ = auxiliaryPictureInfo;
    return SUCCESS;
}

} // namespace Media
} // namespace OHOS