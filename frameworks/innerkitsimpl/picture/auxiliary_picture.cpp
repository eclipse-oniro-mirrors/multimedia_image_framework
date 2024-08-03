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
#include "exif_metadata.h"
#include "fragment_metadata.h"

namespace OHOS {
namespace Media {
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
    return dstAuxPicture;
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
    metadatas_[type] = metadata;
}

bool AuxiliaryPicture::HasMetadata(MetadataType type)
{
    return metadatas_.find(type) != metadatas_.end();
}

bool AuxiliaryPicture::Marshalling(Parcel &data) const
{
    if (content_ == nullptr) {
        IMAGE_LOGE("Auxiliary picture is null.");
        return false;
    }

    if (!content_->Marshalling(data)) {
        IMAGE_LOGE("Failed to marshal auxiliary picture.");
        return false;
    }

    if (!data.WriteInt32(static_cast<int32_t>(auxiliaryPictureInfo_.auxiliaryPictureType))) {
        IMAGE_LOGE("Failed to write type of auxiliary pictures.");
        return false;
    }

    if (!data.WriteInt32(static_cast<int32_t>(auxiliaryPictureInfo_.colorSpace))) {
        IMAGE_LOGE("Failed to write color space of auxiliary pictures.");
        return false;
    }

    if (!data.WriteInt32(static_cast<int32_t>(auxiliaryPictureInfo_.pixelFormat))) {
        IMAGE_LOGE("Failed to write pixel format of auxiliary pictures.");
        return false;
    }

    if (!data.WriteInt32(auxiliaryPictureInfo_.rowStride)) {
        IMAGE_LOGE("Failed to write row stride of auxiliary pictures.");
        return false;
    }

    if (!data.WriteInt32(auxiliaryPictureInfo_.size.height) || !data.WriteInt32(auxiliaryPictureInfo_.size.width)) {
        IMAGE_LOGE("Failed to write size of auxiliary pictures.");
        return false;
    }

    if (!data.WriteUint64(static_cast<uint64_t>(metadatas_.size()))) {
        return false;
    }
    
    for (const auto &metadata : metadatas_) {
        if (!(data.WriteInt32(static_cast<int32_t>(metadata.first)) && metadata.second->Marshalling(data))) {
            IMAGE_LOGE("Failed to marshal metadatas.");
            return false;
        }
    }

    return true;
}

AuxiliaryPicture *AuxiliaryPicture::Unmarshalling(Parcel &data)
{
    PICTURE_ERR error;
    AuxiliaryPicture* dstAuxiliaryPicture = AuxiliaryPicture::Unmarshalling(data, error);
    if (dstAuxiliaryPicture == nullptr || error.errorCode != SUCCESS) {
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
    auxiliaryPictureInfo.rowStride = parcel.ReadInt32();
    auxiliaryPictureInfo.size.height = parcel.ReadInt32();
    auxiliaryPictureInfo.size.width = parcel.ReadInt32();
    auxPtr->SetAuxiliaryPictureInfo(auxiliaryPictureInfo);

    std::map<MetadataType, std::shared_ptr<ImageMetadata>> metadatas;
    
    uint64_t size = parcel.ReadUint64();
    
    for (size_t i = 0; i < size; ++i) {
        MetadataType type = static_cast<MetadataType>(parcel.ReadInt32());
        std::shared_ptr<ImageMetadata> imagedataPtr(nullptr);

        if (type == MetadataType::EXIF) {
            imagedataPtr.reset(ExifMetadata::Unmarshalling(parcel));
            if (!imagedataPtr) {
                return nullptr;
            }
        } else if (type == MetadataType::FRAGMENT) {
            imagedataPtr.reset(FragmentMetadata::Unmarshalling(parcel));
            if (!imagedataPtr) {
                return nullptr;
            }
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

void AuxiliaryPicture::SetAuxiliaryPictureInfo(const AuxiliaryPictureInfo &auxiliaryPictureInfo)
{
    auxiliaryPictureInfo_ = auxiliaryPictureInfo;
}

} // namespace Media
} // namespace OHOS