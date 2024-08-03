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
#include "common_utils.h"
#include "exif_metadata.h"
#include "image_common.h"
#include "image_common_impl.h"
#include "image_log.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "picture_native.h"
#include "picture_native_impl.h"
#include "pixelmap_native_impl.h"
#ifdef __cplusplus
extern "C" {
#endif

static Image_AuxiliaryPictureType AuxTypeInnerToNative(OHOS::Media::AuxiliaryPictureType type)
{
    return static_cast<Image_AuxiliaryPictureType>(static_cast<int>(type));
}

static OHOS::Media::AuxiliaryPictureType AuxTypeNativeToInner(Image_AuxiliaryPictureType type)
{
    return static_cast<OHOS::Media::AuxiliaryPictureType>(static_cast<int>(type));
}

static OHOS::Media::MetadataType MetaDataTypeNativeToInner(Image_MetadataType metadataType)
{
    return static_cast<OHOS::Media::MetadataType>(static_cast<int>(metadataType));
}

MIDK_EXPORT
Image_ErrorCode OH_PictureNative_CreatePicture(OH_PixelmapNative *mainPixelmap, OH_PictureNative **picture)
{
    if (mainPixelmap == nullptr || picture == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    auto innerPixelMap = mainPixelmap->GetInnerPixelmap();
    auto pictureTmp = std::make_unique<OH_PictureNative>(innerPixelMap);
    if (!pictureTmp || !pictureTmp->GetInnerPicture()) {
        return IMAGE_ALLOC_FAILED;
    }
    *picture = pictureTmp.release();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PictureNative_GetMainPixelmap(OH_PictureNative *picture, OH_PixelmapNative **mainPixelmap)
{
    if (mainPixelmap == nullptr || picture == nullptr ||
        !picture->GetInnerPicture() || !picture->GetInnerPicture()->GetMainPixel()) {
        return IMAGE_BAD_PARAMETER;
    }
    auto mainPixelmapTmp = std::make_unique<OH_PixelmapNative>(picture->GetInnerPicture()->GetMainPixel());
    if (!mainPixelmapTmp || !mainPixelmapTmp->GetInnerPixelmap()) {
        return IMAGE_ALLOC_FAILED;
    }
    *mainPixelmap = mainPixelmapTmp.release();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PictureNative_GetHdrComposedPixelmap(OH_PictureNative *picture, OH_PixelmapNative **mainPixelmap)
{
    if (mainPixelmap == nullptr || picture == nullptr || !picture->GetInnerPicture()) {
        return IMAGE_BAD_PARAMETER;
    }

    auto pixelPtrTmp = picture->GetInnerPicture()->GetHdrComposedPixelMap();
    auto mainPixelmapNative = std::make_unique<OH_PixelmapNative>(std::move(pixelPtrTmp));
    if (!mainPixelmapNative || !mainPixelmapNative->GetInnerPixelmap()) {
        return IMAGE_ALLOC_FAILED;
    }
    *mainPixelmap = mainPixelmapNative.release();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PictureNative_GetGainmapPixelmap(OH_PictureNative *picture, OH_PixelmapNative **gainmapPixelmap)
{
    if (gainmapPixelmap == nullptr || picture == nullptr || !picture->GetInnerPicture()) {
        return IMAGE_BAD_PARAMETER;
    }

    auto gainMainPixelmapTmp = std::make_unique<OH_PixelmapNative>(picture->GetInnerPicture()->GetGainmapPixelMap());
    if (!gainMainPixelmapTmp || !gainMainPixelmapTmp->GetInnerPixelmap()) {
        return IMAGE_ALLOC_FAILED;
    }
    *gainmapPixelmap = gainMainPixelmapTmp.release();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PictureNative_SetAuxiliaryPicture(OH_PictureNative *picture, Image_AuxiliaryPictureType type,
    OH_AuxiliaryPictureNative *auxiliaryPicture)
{
    if (picture == nullptr || auxiliaryPicture == nullptr || !picture->GetInnerPicture() ||
        !auxiliaryPicture->GetInnerAuxiliaryPicture()) {
        return IMAGE_BAD_PARAMETER;
    }

    auto auxPicTypeUser = AuxTypeNativeToInner(type);
    if (!OHOS::Media::ImageUtils::IsAuxiliaryPictureTypeSupported(auxPicTypeUser)) {
        return IMAGE_BAD_PARAMETER;
    }

    auto innerAuxiliaryPicture = auxiliaryPicture->GetInnerAuxiliaryPicture();
    OHOS::Media::AuxiliaryPictureType auxPicTypeInner = innerAuxiliaryPicture->GetType();
    if (auxPicTypeUser != auxPicTypeInner) {
        return IMAGE_BAD_PARAMETER;
    }
    picture->GetInnerPicture()->SetAuxiliaryPicture(innerAuxiliaryPicture);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PictureNative_GetAuxiliaryPicture(OH_PictureNative *picture, Image_AuxiliaryPictureType type,
    OH_AuxiliaryPictureNative **auxiliaryPicture)
{
    if (picture == nullptr || auxiliaryPicture == nullptr || !picture->GetInnerPicture()) {
        return IMAGE_BAD_PARAMETER;
    }

    auto auxPicTypeInner = AuxTypeNativeToInner(type);
    if (!OHOS::Media::ImageUtils::IsAuxiliaryPictureTypeSupported(auxPicTypeInner)) {
        return IMAGE_BAD_PARAMETER;
    }

    auto auxiliaryPictureTmp = picture->GetInnerPicture()->GetAuxiliaryPicture(auxPicTypeInner);
    if (!auxiliaryPictureTmp) {
        return IMAGE_BAD_PARAMETER;
    }
    auto auxNativeTmp =  std::make_unique<OH_AuxiliaryPictureNative>(auxiliaryPictureTmp);
    if (!auxNativeTmp || !auxNativeTmp->GetInnerAuxiliaryPicture()) {
        return IMAGE_ALLOC_FAILED;
    }
    *auxiliaryPicture = auxNativeTmp.release();
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_PictureNative_GetMetadata(OH_PictureNative *picture, Image_MetadataType metadataType,
    OH_PictureMetadata **metadata)
{
    if (picture == nullptr || metadata == nullptr || !picture->GetInnerPicture()) {
        return IMAGE_BAD_PARAMETER;
    }
    std::shared_ptr<OHOS::Media::ImageMetadata> metadataTmp = nullptr;
    if (metadataType == EXIF_METADATA) {
        metadataTmp = picture->GetInnerPicture()->GetExifMetadata();
    }
    if (metadataTmp == nullptr) {
        return IMAGE_UNSUPPORTED_METADATA;
    }
    auto matadataNativeTmp = std::make_unique<OH_PictureMetadata>(metadataTmp);
    if (!matadataNativeTmp || !matadataNativeTmp->GetInnerAuxiliaryMetadata()) {
        return IMAGE_UNSUPPORTED_METADATA;
    }
    *metadata = matadataNativeTmp.release();
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_PictureNative_SetMetadata(OH_PictureNative *picture, Image_MetadataType metadataType,
    OH_PictureMetadata *metadata)
{
    if (picture == nullptr || metadata == nullptr || !picture->GetInnerPicture() ||
        !metadata->GetInnerAuxiliaryMetadata()) {
        return IMAGE_BAD_PARAMETER;
    }
    if (metadataType == EXIF_METADATA) {
        auto metadataInner = metadata->GetInnerAuxiliaryMetadata();
        auto exifMetadata = std::static_pointer_cast<OHOS::Media::ExifMetadata>(metadataInner);
        auto errorCode = picture->GetInnerPicture()->SetExifMetadata(exifMetadata);
        if (errorCode != OHOS::Media::SUCCESS) {
            return IMAGE_UNSUPPORTED_METADATA;
        }
    } else {
        return IMAGE_UNSUPPORTED_METADATA;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PictureNative_Release(OH_PictureNative *picture)
{
    if (picture == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete picture;
    picture = nullptr;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureNative_Create(uint8_t *data, size_t dataLength, Image_Size *size,
    Image_AuxiliaryPictureType type, OH_AuxiliaryPictureNative **auxiliaryPicture)
{
    if (data == nullptr || dataLength <= 0 || auxiliaryPicture == nullptr || size == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    auto auxPicTypeInner = AuxTypeNativeToInner(type);
    if (!OHOS::Media::ImageUtils::IsAuxiliaryPictureTypeSupported(auxPicTypeInner)) {
        return IMAGE_BAD_PARAMETER;
    }

    OHOS::Media::InitializationOptions initializationOptions;
    initializationOptions.size.width = size->width;
    initializationOptions.size.height = size->height;
    initializationOptions.editable = true;
    auto dataTmp = reinterpret_cast<uint32_t*>(data);
    auto dataLengthTmp = static_cast<uint32_t>(dataLength);

    auto pixelMap = OHOS::Media::PixelMap::Create(dataTmp, dataLengthTmp, initializationOptions);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMapPtr = std::move(pixelMap);
    if (!pixelMapPtr) {
        return IMAGE_UNKNOWN_ERROR;
    }
    auto auxiliaryPictureTmp = std::make_unique<OH_AuxiliaryPictureNative>(pixelMapPtr, auxPicTypeInner,
                                                                           initializationOptions.size);
    if (!auxiliaryPictureTmp || !auxiliaryPictureTmp->GetInnerAuxiliaryPicture()) {
        return IMAGE_ALLOC_FAILED;
    }
    *auxiliaryPicture = auxiliaryPictureTmp.release();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureNative_WritePixels(OH_AuxiliaryPictureNative *auxiliaryPicture,
    uint8_t *source, size_t bufferSize)
{
    if (auxiliaryPicture == nullptr || source == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    auto innerAuxiliaryPicture = auxiliaryPicture->GetInnerAuxiliaryPicture();
    if (!innerAuxiliaryPicture) {
        return IMAGE_BAD_PARAMETER;
    }
    uint32_t ret = innerAuxiliaryPicture->WritePixels(source, static_cast<uint64_t>(bufferSize));
    if (ret != OHOS::Media::SUCCESS) {
        return IMAGE_UNKNOWN_ERROR;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureNative_ReadPixels(OH_AuxiliaryPictureNative *auxiliaryPicture, uint8_t *destination,
    size_t *bufferSize)
{
    if (auxiliaryPicture == nullptr || destination == nullptr || bufferSize == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    auto innerAuxiliaryPicture = auxiliaryPicture->GetInnerAuxiliaryPicture();
    if (!innerAuxiliaryPicture) {
        return IMAGE_BAD_PARAMETER;
    }
    auto size = static_cast<uint64_t>(*bufferSize);
    if (innerAuxiliaryPicture->ReadPixels(size, reinterpret_cast<uint8_t*>(destination)) != IMAGE_SUCCESS) {
        return IMAGE_UNKNOWN_ERROR;
    }
    *bufferSize = static_cast<size_t>(size);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureNative_GetType(OH_AuxiliaryPictureNative *auxiliaryPicture,
    Image_AuxiliaryPictureType *type)
{
    if (auxiliaryPicture == nullptr  || type == nullptr || !auxiliaryPicture->GetInnerAuxiliaryPicture()) {
        return IMAGE_BAD_PARAMETER;
    }

    auto auxiliaryPictureType = auxiliaryPicture->GetInnerAuxiliaryPicture()->GetType();
    Image_AuxiliaryPictureType auxiliaryPictureTypeTmp = AuxTypeInnerToNative(auxiliaryPictureType);
    *type = auxiliaryPictureTypeTmp;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureNative_GetInfo(OH_AuxiliaryPictureNative *auxiliaryPicture,
    OH_AuxiliaryPictureInfo **info)
{
    if (auxiliaryPicture == nullptr || !auxiliaryPicture->GetInnerAuxiliaryPicture() || info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    auto auxInfo = auxiliaryPicture->GetInnerAuxiliaryPicture()->GetAuxiliaryPictureInfo();
    *info = new OH_AuxiliaryPictureInfo(auxInfo);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureNative_SetInfo(OH_AuxiliaryPictureNative *auxiliaryPicture,
    OH_AuxiliaryPictureInfo *info)
{
    if (auxiliaryPicture == nullptr || !auxiliaryPicture->GetInnerAuxiliaryPicture() || info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    auto tempInfo = *(info->GetInnerAuxiliaryPictureInfo().get());
    auxiliaryPicture->GetInnerAuxiliaryPicture()->SetAuxiliaryPictureInfo(tempInfo);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureNative_GetMetadata(OH_AuxiliaryPictureNative *auxiliaryPicture, Image_MetadataType
    metadataType, OH_PictureMetadata **metadata)
{
    if (auxiliaryPicture == nullptr || metadata == nullptr || !auxiliaryPicture->GetInnerAuxiliaryPicture()) {
        return IMAGE_BAD_PARAMETER;
    }

    auto metadataTypeInner = MetaDataTypeNativeToInner(metadataType);
    if (!OHOS::Media::ImageUtils::IsMetadataTypeSupported(metadataTypeInner)) {
        return IMAGE_BAD_PARAMETER;
    }

    auto metadataPtr = auxiliaryPicture->GetInnerAuxiliaryPicture()->GetMetadata(metadataTypeInner);
    *metadata = new OH_PictureMetadata(metadataPtr);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureNative_SetMetadata(OH_AuxiliaryPictureNative *auxiliaryPicture,
    Image_MetadataType metadataType,  OH_PictureMetadata *metadata)
{
    if (auxiliaryPicture == nullptr || !auxiliaryPicture->GetInnerAuxiliaryPicture() || metadata == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    auto metadataTypeInner = MetaDataTypeNativeToInner(metadataType);
    if (!OHOS::Media::ImageUtils::IsMetadataTypeSupported(metadataTypeInner)) {
        return IMAGE_BAD_PARAMETER;
    }

    auto metadataPtr = metadata->GetInnerAuxiliaryMetadata();
    if (!metadataPtr) {
        return IMAGE_BAD_PARAMETER;
    }
    auxiliaryPicture->GetInnerAuxiliaryPicture()->SetMetadata(metadataTypeInner, metadataPtr);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureNative_Release(OH_AuxiliaryPictureNative *picture)
{
    if (picture == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete picture;
    picture = nullptr;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureInfo_Create(OH_AuxiliaryPictureInfo **info)
{
    if (info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *info = new OH_AuxiliaryPictureInfo();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureInfo_GetType(OH_AuxiliaryPictureInfo *info, Image_AuxiliaryPictureType *type)
{
    if (info == nullptr || type == nullptr || !info->GetInnerAuxiliaryPictureInfo()) {
        return IMAGE_BAD_PARAMETER;
    }
    auto typeTmpInner = info->GetInnerAuxiliaryPictureInfo()->auxiliaryPictureType;
    auto typeTmpNative = AuxTypeInnerToNative(typeTmpInner);
    *type = typeTmpNative;
    return  IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureInfo_SetType(OH_AuxiliaryPictureInfo *info, Image_AuxiliaryPictureType type)
{
    if (info == nullptr || !info->GetInnerAuxiliaryPictureInfo()) {
        return IMAGE_BAD_PARAMETER;
    }

    auto auxPicTypeInner = AuxTypeNativeToInner(type);
    if (!OHOS::Media::ImageUtils::IsAuxiliaryPictureTypeSupported(auxPicTypeInner)) {
        return IMAGE_BAD_PARAMETER;
    }

    info->GetInnerAuxiliaryPictureInfo()->auxiliaryPictureType = auxPicTypeInner;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureInfo_GetSize(OH_AuxiliaryPictureInfo *info, Image_Size *size)
{
    if (info == nullptr || size == nullptr || !info->GetInnerAuxiliaryPictureInfo()) {
        return IMAGE_BAD_PARAMETER;
    }
    auto sizeIner = info->GetInnerAuxiliaryPictureInfo()->size;
    Image_Size sizeTmp = Image_Size();
    sizeTmp.height = sizeIner.height;
    sizeTmp.width = sizeIner.width;
    *size = sizeTmp;
    return  IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureInfo_SetSize(OH_AuxiliaryPictureInfo *info, Image_Size *size)
{
    if (info == nullptr || !info->GetInnerAuxiliaryPictureInfo() || size == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    OHOS::Media::Size sizeTmp = OHOS::Media::Size();
    sizeTmp.height = size->height;
    sizeTmp.width = size->width;
    info->GetInnerAuxiliaryPictureInfo()->size = sizeTmp;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureInfo_GetRowStride(OH_AuxiliaryPictureInfo *info, uint32_t *rowStride)
{
    if (info == nullptr || rowStride == nullptr  || !info->GetInnerAuxiliaryPictureInfo()) {
        return IMAGE_BAD_PARAMETER;
    }
    *rowStride = info->GetInnerAuxiliaryPictureInfo()->rowStride;
    return  IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureInfo_SetRowStride(OH_AuxiliaryPictureInfo *info, uint32_t rowStride)
{
    if (info == nullptr || !info->GetInnerAuxiliaryPictureInfo()) {
        return IMAGE_BAD_PARAMETER;
    }
    info->GetInnerAuxiliaryPictureInfo()->rowStride = rowStride;
    return  IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureInfo_GetPixelFormat(OH_AuxiliaryPictureInfo *info, PIXEL_FORMAT *pixelFormat)
{
    if (info == nullptr || !info->GetInnerAuxiliaryPictureInfo() || pixelFormat == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    auto pixelFormatTpm = info->GetInnerAuxiliaryPictureInfo()->pixelFormat;
    *pixelFormat = static_cast<PIXEL_FORMAT>(pixelFormatTpm);
    return  IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureInfo_SetPixelFormat(OH_AuxiliaryPictureInfo *info, PIXEL_FORMAT pixelFormat)
{
    if (info == nullptr || !info->GetInnerAuxiliaryPictureInfo()) {
        return IMAGE_BAD_PARAMETER;
    }
    info->GetInnerAuxiliaryPictureInfo()->pixelFormat = static_cast<OHOS::Media::PixelFormat>(pixelFormat);
    return  IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_AuxiliaryPictureInfo_Release(OH_AuxiliaryPictureInfo *info)
{
    if (info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete info;
    info = nullptr;
    return  IMAGE_SUCCESS;
}

#ifdef __cplusplus
};
#endif
