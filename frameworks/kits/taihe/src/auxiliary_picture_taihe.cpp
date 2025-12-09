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

#include <memory.h>

#include "ani_color_space_object_convertor.h"
#include "auxiliary_picture_taihe.h"
#include "image_common.h"
#include "image_log.h"
#include "image_taihe_utils.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "metadata_taihe.h"
#include "pixel_map.h"
using namespace ANI::Image;

namespace ANI::Image {

struct AuxiliaryPictureTaiheContext {
    uint32_t status;
    AuxiliaryPictureImpl *nConstructor;
    std::shared_ptr<OHOS::Media::PixelMap> rPixelmap;
    std::shared_ptr<OHOS::Media::AuxiliaryPicture> auxPicture;
    void *arrayBuffer;
    size_t arrayBufferSize;
    std::shared_ptr<OHOS::Media::AuxiliaryPicture> rAuxiliaryPicture;
    OHOS::Media::AuxiliaryPictureInfo auxiliaryPictureInfo;
    std::shared_ptr<OHOS::Media::ImageMetadata> imageMetadata;
    OHOS::Media::MetadataType metadataType = OHOS::Media::MetadataType::EXIF;
    std::shared_ptr<OHOS::ColorManager::ColorSpace> AuxColorSpace = nullptr;
};

AuxiliaryPictureImpl::AuxiliaryPictureImpl() {}

AuxiliaryPictureImpl::AuxiliaryPictureImpl(std::shared_ptr<OHOS::Media::AuxiliaryPicture> auxiliaryPicture)
{
    nativeAuxiliaryPicture_ = auxiliaryPicture;
}

AuxiliaryPictureImpl::~AuxiliaryPictureImpl()
{
    Release();
}

int64_t AuxiliaryPictureImpl::GetImplPtr()
{
    return static_cast<int64_t>(reinterpret_cast<uintptr_t>(this));
}

void AuxiliaryPictureImpl::WritePixelsFromBufferSync(array_view<uint8_t> data)
{
    std::unique_ptr<AuxiliaryPictureTaiheContext> taiheContext = std::make_unique<AuxiliaryPictureTaiheContext>();
    taiheContext->rAuxiliaryPicture = nativeAuxiliaryPicture_;
    if (taiheContext->rAuxiliaryPicture == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Empty native auxiliary picture.");
        return;
    }
    taiheContext->arrayBuffer = static_cast<void *>(data.data());
    taiheContext->arrayBufferSize = data.size();
    if (taiheContext->arrayBuffer == nullptr || taiheContext->arrayBufferSize == 0) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Invalid args.");
        IMAGE_LOGE("Fail to get buffer info");
    }
    taiheContext->rAuxiliaryPicture->WritePixels(
        static_cast<uint8_t*>(taiheContext->arrayBuffer), taiheContext->arrayBufferSize);
}

static bool ReadPixelsToBufferSyncExecute(std::unique_ptr<AuxiliaryPictureTaiheContext> &context)
{
    OHOS::Media::AuxiliaryPictureInfo info = context->rAuxiliaryPicture->GetAuxiliaryPictureInfo();
    context->arrayBufferSize = static_cast<size_t>(info.size.width * info.size.height *
        OHOS::Media::ImageUtils::GetPixelBytes(info.pixelFormat));
    context->arrayBuffer = new uint8_t[context->arrayBufferSize];
    if (context->arrayBuffer != nullptr) {
        context->status = context->rAuxiliaryPicture->ReadPixels(
            context->arrayBufferSize, static_cast<uint8_t *>(context->arrayBuffer));
    } else {
        context->status = OHOS::Media::ERR_MEDIA_MALLOC_FAILED;
        ImageTaiheUtils::ThrowExceptionError(IMAGE_ALLOC_FAILED, "Memory alloc failed.");
        return false;
    }
    return true;
}

static optional<array<uint8_t>> ReadPixelsToBufferSyncComplete(std::unique_ptr<AuxiliaryPictureTaiheContext> &context)
{
    optional<array<uint8_t>> result = optional<array<uint8_t>>(std::nullopt);
    if (context->status == OHOS::Media::SUCCESS) {
        array<uint8_t> array = ImageTaiheUtils::CreateTaiheArrayBuffer(static_cast<uint8_t *>(context->arrayBuffer),
            context->arrayBufferSize);
        result = optional<taihe::array<uint8_t>>(std::in_place, array);
    } else {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERROR, "Fail to create taihe arraybuffer!");
    }

    delete[] static_cast<uint8_t *>(context->arrayBuffer);
    context->arrayBuffer = nullptr;
    context->arrayBufferSize = 0;
    return result;
}

optional<AuxiliaryPictureType> AuxiliaryPictureImpl::GetType()
{
    IMAGE_LOGD("Call GetType");
    if (nativeAuxiliaryPicture_ == nullptr) {
        IMAGE_LOGE("Native auxiliary picture is nullptr!");
        return optional<AuxiliaryPictureType>(std::nullopt);
    }
    AuxiliaryPictureType::key_t auxPictureTypeKey;
    auto auxType = nativeAuxiliaryPicture_->GetType();
    IMAGE_LOGD("AuxiliaryPictureImpl::GetType %{public}d", auxType);
    if (static_cast<int32_t>(auxType) >= 0 && auxType <= OHOS::Media::AuxiliaryPictureType::FRAGMENT_MAP) {
        if (ImageTaiheUtils::GetEnumKeyByValue<AuxiliaryPictureType>(static_cast<int32_t>(auxType),
            auxPictureTypeKey)) {
            return optional<AuxiliaryPictureType>(std::in_place, AuxiliaryPictureType(auxPictureTypeKey));
        } else {
            IMAGE_LOGE("Get auxiliary picture type failed");
        }
    }
    return optional<AuxiliaryPictureType>(std::nullopt);
}

static bool CheckMetadataType(std::unique_ptr<AuxiliaryPictureTaiheContext> const& context)
{
    if (context == nullptr || context->rAuxiliaryPicture == nullptr) {
        IMAGE_LOGE("Auxiliary picture is null");
        return false;
    }
    return !(context->rAuxiliaryPicture->GetType() != OHOS::Media::AuxiliaryPictureType::FRAGMENT_MAP &&
        context->metadataType == OHOS::Media::MetadataType::FRAGMENT);
}

void AuxiliaryPictureImpl::SetMetadataSync(MetadataType metadataType, weak::Metadata metadata)
{
    std::unique_ptr<AuxiliaryPictureTaiheContext> context = std::make_unique<AuxiliaryPictureTaiheContext>();
    context->rAuxiliaryPicture = nativeAuxiliaryPicture_;
    if (context->rAuxiliaryPicture == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Empty native auxiliary picture.");
        return;
    }
    if (metadataType >= static_cast<int32_t>(OHOS::Media::MetadataType::EXIF)
        && metadataType <= static_cast<int32_t>(OHOS::Media::MetadataType::FRAGMENT)) {
        context->metadataType = OHOS::Media::MetadataType(metadataType.get_value());
    } else {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Invalid args metadata type.");
        return;
    }
    if (!CheckMetadataType(context)) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_UNSUPPORTED_METADATA, "Unsupported metadata");
        return;
    }
    MetadataImpl* metadataImpl = reinterpret_cast<MetadataImpl*>(metadata->GetImplPtr());
    if (metadataImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Failed to unwrap MetadataImpl");
        return;
    }
    context->imageMetadata = metadataImpl->GetNativeMetadata();
    if (context->imageMetadata == nullptr) {
        IMAGE_LOGE("Empty native metadata");
    }
    context->rAuxiliaryPicture->SetMetadata(context->metadataType, context->imageMetadata);
    IMAGE_LOGD("[AuxiliaryPicture]SetMetadata OUT");
}

optional<Metadata> AuxiliaryPictureImpl::GetMetadataSync(MetadataType metadataType)
{
    std::unique_ptr<AuxiliaryPictureTaiheContext> context = std::make_unique<AuxiliaryPictureTaiheContext>();
    context->rAuxiliaryPicture = nativeAuxiliaryPicture_;
    if (context->rAuxiliaryPicture == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Empty native auxiliary picture.");
        return optional<Metadata>(std::nullopt);
    }
    if (metadataType >= static_cast<int32_t>(OHOS::Media::MetadataType::EXIF)
        && metadataType <= static_cast<int32_t>(OHOS::Media::MetadataType::FRAGMENT)) {
        context->metadataType = OHOS::Media::MetadataType(metadataType.get_value());
    } else {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Invalid args metadata type.");
        return optional<Metadata>(std::nullopt);
    }
    if (!CheckMetadataType(context) || context->metadataType == OHOS::Media::MetadataType::EXIF) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_UNSUPPORTED_METADATA, "Unsupported metadata");
        return optional<Metadata>(std::nullopt);
    }
    context->imageMetadata = context->rAuxiliaryPicture->GetMetadata(context->metadataType);
    if (context->imageMetadata == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Get Metadata failed!");
        return optional<Metadata>(std::nullopt);
    }
    IMAGE_LOGD("[AuxiliaryPicture]GetMetadata OUT");
    auto res = make_holder<MetadataImpl, Metadata>(std::move(context->imageMetadata));
    return optional<Metadata>(std::in_place, res);
}

optional<array<uint8_t>> AuxiliaryPictureImpl::ReadPixelsToBufferSync()
{
    std::unique_ptr<AuxiliaryPictureTaiheContext> taiheContext = std::make_unique<AuxiliaryPictureTaiheContext>();
    taiheContext->rAuxiliaryPicture = nativeAuxiliaryPicture_;
    if (taiheContext->rAuxiliaryPicture == nullptr) {
        IMAGE_LOGE("Empty native auxiliary picture.");
        return optional<array<uint8_t>>(std::nullopt);
    }
    if (!ReadPixelsToBufferSyncExecute(taiheContext)) {
        return optional<array<uint8_t>>(std::nullopt);
    }
    return ReadPixelsToBufferSyncComplete(taiheContext);
}

AuxiliaryPictureInfo MakeEmptyAuxiliaryPictureInfo()
{
    return {AuxiliaryPictureType(static_cast<AuxiliaryPictureType::key_t>(OHOS::Media::AuxiliaryPictureType::NONE)),
        {0, 0}, 0, PixelMapFormat(PixelMapFormat::key_t::UNKNOWN), 0};
}

static optional<AuxiliaryPictureInfo> ToTaiheAuxiliaryPictureInfo(const OHOS::Media::AuxiliaryPictureInfo &src,
    std::shared_ptr<OHOS::Media::AuxiliaryPicture> &auxiliaryPicture)
{
    AuxiliaryPictureInfo result = MakeEmptyAuxiliaryPictureInfo();
    AuxiliaryPictureType::key_t auxiliaryPictureTypeKey;
    ImageTaiheUtils::GetEnumKeyByValue<AuxiliaryPictureType>(static_cast<int32_t>(src.auxiliaryPictureType),
        auxiliaryPictureTypeKey);
    result.auxiliaryPictureType = AuxiliaryPictureType(auxiliaryPictureTypeKey);

    Size size {
        .width = src.size.width,
        .height = src.size.height,
    };
    result.size = size;
    result.rowStride = static_cast<int32_t>(src.rowStride);

    PixelMapFormat::key_t pixelFormatKey;
    ImageTaiheUtils::GetEnumKeyByValue<PixelMapFormat>(static_cast<int32_t>(src.pixelFormat), pixelFormatKey);
    result.pixelFormat = PixelMapFormat(pixelFormatKey);

    if (auxiliaryPicture->GetContentPixel() == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_DATA_ABNORMAL, "Invalid pixelmap");
        return optional<AuxiliaryPictureInfo>(std::nullopt);
    }

    auto grCS = auxiliaryPicture->GetContentPixel()->InnerGetGrColorSpacePtr();
    if (grCS == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_DATA_UNSUPPORT, "No colorspace in pixelmap");
        return optional<AuxiliaryPictureInfo>(std::nullopt);
    }
    ani_object colorSpaceObj = OHOS::ColorManager::CreateAniColorSpaceObject(get_env(), grCS);
    result.colorSpace = reinterpret_cast<uintptr_t>(colorSpaceObj);
    return optional<AuxiliaryPictureInfo>(std::in_place, result);
}

optional<AuxiliaryPictureInfo> AuxiliaryPictureImpl::GetAuxiliaryPictureInfo()
{
    if (nativeAuxiliaryPicture_ != nullptr) {
        return ToTaiheAuxiliaryPictureInfo(
            nativeAuxiliaryPicture_->GetAuxiliaryPictureInfo(), nativeAuxiliaryPicture_);
    } else {
        IMAGE_LOGE("Native auxiliarypicture is nullptr!");
        return optional<AuxiliaryPictureInfo>(std::nullopt);
    }
}

static OHOS::Media::AuxiliaryPictureType ParseAuxiliaryPictureType(int32_t val)
{
    if (val >= static_cast<int32_t>(OHOS::Media::AuxiliaryPictureType::GAINMAP)
        && val <= static_cast<int32_t>(OHOS::Media::AuxiliaryPictureType::FRAGMENT_MAP)) {
        return OHOS::Media::AuxiliaryPictureType(val);
    }
    return OHOS::Media::AuxiliaryPictureType::NONE;
}

static bool ParseSize(Size const& size)
{
    if (size.width <= 0 || size.height <= 0) {
        return false;
    }
    return true;
}

static OHOS::Media::PixelFormat ParsePixelFormat(int32_t val)
{
    if (val >= static_cast<int32_t>(OHOS::Media::PixelFormat::ARGB_8888) &&
        val <= static_cast<int32_t>(OHOS::Media::PixelFormat::CMYK)) {
        return OHOS::Media::PixelFormat(val);
    }
    return OHOS::Media::PixelFormat::UNKNOWN;
}

static bool ParseColorSpace(uintptr_t val, AuxiliaryPictureTaiheContext* taiheContext)
{
#ifdef IMAGE_COLORSPACE_FLAG
    ani_object obj = reinterpret_cast<ani_object>(val);
    taiheContext->AuxColorSpace = OHOS::ColorManager::GetColorSpaceByAniObject(get_env(), obj);
    if (taiheContext->AuxColorSpace == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_INVALID_PARAMETER, "ColorSpace mismatch");
        return false;
    }
    taiheContext->rPixelmap->InnerSetColorSpace(*(taiheContext->AuxColorSpace));
    return true;
#else
    ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_INVALID_OPERATION, "Unsupported operation");
#endif
    return false;
}

static bool ParseAuxiliaryPictureInfo(AuxiliaryPictureInfo const& info, AuxiliaryPictureTaiheContext* taiheContext)
{
    taiheContext->auxiliaryPictureInfo.auxiliaryPictureType = ParseAuxiliaryPictureType(info.auxiliaryPictureType);
    if (!ParseSize(info.size)) {
        IMAGE_LOGE("Invalid size in auxiliaryPictureInfo");
        return false;
    }
    taiheContext->auxiliaryPictureInfo.size.width = info.size.width;
    taiheContext->auxiliaryPictureInfo.size.height = info.size.height;
    if (info.rowStride < 0) {
        IMAGE_LOGE("Invalid rowStride in auxiliaryPictureInfo");
        return false;
    }
    taiheContext->auxiliaryPictureInfo.rowStride = info.rowStride;
    taiheContext->auxiliaryPictureInfo.pixelFormat = ParsePixelFormat(info.pixelFormat);

    taiheContext->rPixelmap = taiheContext->auxPicture->GetContentPixel();
    ParseColorSpace(info.colorSpace, taiheContext);
    return true;
}

void AuxiliaryPictureImpl::SetAuxiliaryPictureInfo(AuxiliaryPictureInfo const& info)
{
    std::unique_ptr<AuxiliaryPictureTaiheContext> context = std::make_unique<AuxiliaryPictureTaiheContext>();
    if (nativeAuxiliaryPicture_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Empty native auxiliarypicture");
        return;
    }
    context->auxPicture = nativeAuxiliaryPicture_;
    if (!ParseAuxiliaryPictureInfo(info, context.get())) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Parameter error.");
        IMAGE_LOGE("AuxiliaryPictureInfo mismatch");
        return;
    }

    uint32_t res = context->auxPicture->SetAuxiliaryPictureInfo(context->auxiliaryPictureInfo);
    if (res != OHOS::Media::SUCCESS) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Set auxiliary picture info failed.");
    }
}

void AuxiliaryPictureImpl::Release()
{
    if (!isRelease) {
        if (nativeAuxiliaryPicture_ != nullptr) {
            nativeAuxiliaryPicture_ = nullptr;
        }
        isRelease = true;
    }
}

static std::unique_ptr<OHOS::Media::AuxiliaryPicture> CreateAuxiliaryPictureExec(array_view<uint8_t> buffer,
    OHOS::Media::Size size, OHOS::Media::AuxiliaryPictureType type)
{
    OHOS::Media::InitializationOptions opts;
    opts.size = size;
    opts.editable = true;
    opts.useDMA = true;
    auto colors = reinterpret_cast<uint32_t*>(buffer.data());
    if (colors == nullptr) {
        return nullptr;
    }
    auto tmpPixelmap = OHOS::Media::PixelMap::Create(colors, buffer.size(), opts);
    std::shared_ptr<OHOS::Media::PixelMap> pixelmap = std::move(tmpPixelmap);
    auto picture = OHOS::Media::AuxiliaryPicture::Create(pixelmap, type, size);
    return picture;
}

AuxiliaryPicture CreateAuxiliaryPicture(array_view<uint8_t> buffer, const Size &size, AuxiliaryPictureType type)
{
    if (buffer.empty()) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Invalid arraybuffer.");
        return make_holder<AuxiliaryPictureImpl, AuxiliaryPicture>();
    }
    OHOS::Media::Size ohSize = {size.width, size.height};
    if (size.width <= 0 || size.height <= 0) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Invalid size.");
        return make_holder<AuxiliaryPictureImpl, AuxiliaryPicture>();
    }
    OHOS::Media::AuxiliaryPictureType ohType = ParseAuxiliaryPictureType(type.get_value());
    if (ohType == OHOS::Media::AuxiliaryPictureType::NONE) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Invalid auxiliary picture type.");
        return make_holder<AuxiliaryPictureImpl, AuxiliaryPicture>();
    }
    auto auxiliaryPicture = CreateAuxiliaryPictureExec(buffer, ohSize, ohType);
    if (auxiliaryPicture == nullptr) {
        IMAGE_LOGE("Fail to create auxiliary picture.");
        return make_holder<AuxiliaryPictureImpl, AuxiliaryPicture>();
    }
    return make_holder<AuxiliaryPictureImpl, AuxiliaryPicture>(std::move(auxiliaryPicture));
}

} // namespace ANI::Image

TH_EXPORT_CPP_API_CreateAuxiliaryPicture(CreateAuxiliaryPicture);