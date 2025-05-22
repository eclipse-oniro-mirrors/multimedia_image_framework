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

static bool ReadPixelsToBufferSyncExecute(std::unique_ptr<AuxiliaryPictureTaiheContext> &context)
{
    OHOS::Media::AuxiliaryPictureInfo info = context->rAuxiliaryPicture->GetAuxiliaryPictureInfo();
    context->arrayBufferSize =
        info.size.width * info.size.height * OHOS::Media::ImageUtils::GetPixelBytes(info.pixelFormat);
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

static array<uint8_t> ReadPixelsToBufferSyncComplete(std::unique_ptr<AuxiliaryPictureTaiheContext> &context)
{
    array<uint8_t> result = array<uint8_t>(nullptr, 0);
    if (context->status == OHOS::Media::SUCCESS) {
        result = ImageTaiheUtils::CreateTaiheArrayBuffer(static_cast<uint8_t *>(context->arrayBuffer),
            context->arrayBufferSize);
    } else {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERROR, "Fail to create taihe arraybuffer!");
        return array<uint8_t>(nullptr, 0);
    }

    delete[] static_cast<uint8_t *>(context->arrayBuffer);
    context->arrayBuffer = nullptr;
    context->arrayBufferSize = 0;
    return result;
}

array<uint8_t> AuxiliaryPictureImpl::ReadPixelsToBufferSync()
{
    std::unique_ptr<AuxiliaryPictureTaiheContext> taiheContext = std::make_unique<AuxiliaryPictureTaiheContext>();
    taiheContext->rAuxiliaryPicture = nativeAuxiliaryPicture_;
    if (taiheContext->rAuxiliaryPicture == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Empty native auxiliary picture.");
        return array<uint8_t>(nullptr, 0);
    }
    if (!ReadPixelsToBufferSyncExecute(taiheContext)) {
        return array<uint8_t>(nullptr, 0);
    }
    return ReadPixelsToBufferSyncComplete(taiheContext);
}

AuxiliaryPictureInfo MakeEmptyAuxiliaryPictureInfo()
{
    return {AuxiliaryPictureType(static_cast<AuxiliaryPictureType::key_t>(OHOS::Media::AuxiliaryPictureType::NONE)),
        {0, 0}, 0, PixelMapFormat(PixelMapFormat::key_t::UNKNOWN), 0};
}

static AuxiliaryPictureInfo ToTaiheAuxiliaryPictureInfo(const OHOS::Media::AuxiliaryPictureInfo &src)
{
    AuxiliaryPictureType::key_t auxiliaryPictureTypeKey;
    ImageTaiheUtils::GetEnumKeyByValue<AuxiliaryPictureType>(static_cast<int32_t>(src.auxiliaryPictureType),
        auxiliaryPictureTypeKey);

    Size size {
        .width = src.size.width,
        .height = src.size.height,
    };

    PixelMapFormat::key_t pixelFormatKey;
    ImageTaiheUtils::GetEnumKeyByValue<PixelMapFormat>(static_cast<int32_t>(src.pixelFormat), pixelFormatKey);

    AuxiliaryPictureInfo result {
        .auxiliaryPictureType = AuxiliaryPictureType(auxiliaryPictureTypeKey),
        .size = size,
        .rowStride = static_cast<int32_t>(src.rowStride),
        .pixelFormat = PixelMapFormat(pixelFormatKey),
    };
    return result;
}

AuxiliaryPictureInfo AuxiliaryPictureImpl::GetAuxiliaryPictureInfo()
{
    if (nativeAuxiliaryPicture_ != nullptr) {
        AuxiliaryPictureInfo info = ToTaiheAuxiliaryPictureInfo(nativeAuxiliaryPicture_->GetAuxiliaryPictureInfo());
        return info;
    } else {
        ImageTaiheUtils::ThrowExceptionError("Native auxiliarypicture is nullptr!");
        return MakeEmptyAuxiliaryPictureInfo();
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