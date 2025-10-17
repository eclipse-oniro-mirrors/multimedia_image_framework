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

#include "image_common.h"
#include "image_log.h"
#include "image_packer.h"
#include "image_packer_taihe.h"
#include "image_source_taihe.h"
#include "image_taihe_utils.h"
#include "image_trace.h"
#include "picture_taihe.h"
#include "pixel_map_taihe.h"
#include "media_errors.h"

using namespace ANI::Image;

namespace {
    constexpr int32_t INVALID_FD = -1;
    constexpr int32_t SIZE_256 = 256;
    constexpr int32_t SIZE_512 = 512;
    constexpr int32_t SIZE_1024 = 1024;
    constexpr int32_t SIZE_1440 = 1440;
    constexpr int32_t SIZE_1920 = 1920;
    constexpr int64_t FILE_SIZE_300K = 300 * 1024;
    constexpr int64_t FILE_SIZE_1M = 1 * 1024 * 1024;
    constexpr int64_t FILE_SIZE_4M = 4 * 1024 * 1024;
    constexpr int64_t FILE_SIZE_10M = 10 * 1024 * 1024;
}

namespace ANI::Image {
const uint8_t BYTE_FULL = 0xFF;
const int32_t SIZE = 100;
const int32_t TYPE_IMAGE_SOURCE = 1;
const int32_t TYPE_PIXEL_MAP = 2;
const int32_t TYPE_PICTURE = 3;
const int32_t TYPE_ARRAY = 4;
const int64_t DEFAULT_BUFFER_SIZE = 25 * 1024 * 1024; // 25M is the maximum default packedSize
const int MASK_3 = 0x3;
const int MASK_16 = 0xffff;

struct ImagePackerTaiheContext {
    OHOS::Media::PackOption packOption;
    std::shared_ptr<OHOS::Media::ImagePacker> rImagePacker;
    std::shared_ptr<OHOS::Media::ImageSource> rImageSource;
    std::shared_ptr<OHOS::Media::PixelMap> rPixelMap;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    std::shared_ptr<OHOS::Media::Picture> rPicture;
#endif
    std::shared_ptr<std::vector<std::shared_ptr<OHOS::Media::PixelMap>>> rPixelMaps;
    std::unique_ptr<uint8_t[]> resultBuffer;
    int32_t packType = TYPE_IMAGE_SOURCE;
    int64_t resultBufferSize = 0;
    int64_t packedSize = 0;
    int fd = INVALID_FD;
    bool needReturnErrorCode = true;
    uint32_t frameCount;
};

ImagePackerImpl::ImagePackerImpl() : nativeImagePacker_(nullptr) {}

ImagePackerImpl::ImagePackerImpl(std::shared_ptr<OHOS::Media::ImagePacker> imagePacker)
{
    nativeImagePacker_ = imagePacker;
}

ImagePackerImpl::~ImagePackerImpl()
{
    ReleaseSync();
}

int64_t ImagePackerImpl::GetImplPtr()
{
    return static_cast<int64_t>(reinterpret_cast<uintptr_t>(this));
}

std::shared_ptr<OHOS::Media::ImagePacker> ImagePackerImpl::GetNativeImagePacker()
{
    return nativeImagePacker_;
}

static int64_t GetDefaultBufferSize(int32_t width, int32_t height)
{
    if (width <= SIZE_256 && height <= SIZE_256) {
        return FILE_SIZE_300K;
    }
    if (width <= SIZE_512 && height <= SIZE_512) {
        return FILE_SIZE_1M;
    }
    if (width <= SIZE_1024 && height <= SIZE_1024) {
        return FILE_SIZE_4M;
    }
    if (width <= SIZE_1440 && height <= SIZE_1920) {
        return FILE_SIZE_10M;
    }
    return DEFAULT_BUFFER_SIZE;
}

static int64_t GetDefaultBufferSize(std::unique_ptr<ImagePackerTaiheContext> &context)
{
    if (context == nullptr) {
        return DEFAULT_BUFFER_SIZE;
    }
    OHOS::Media::ImageInfo imageInfo {};
    if (context->packType == TYPE_IMAGE_SOURCE) {
        if (context->rImageSource == nullptr) {
            return DEFAULT_BUFFER_SIZE;
        }
        context->rImageSource->GetImageInfo(imageInfo);
    } else if (context->packType == TYPE_PIXEL_MAP) {
        if (context->rPixelMap == nullptr) {
            return DEFAULT_BUFFER_SIZE;
        }
        context->rPixelMap->GetImageInfo(imageInfo);
    }
    if (imageInfo.size.width <= 0 || imageInfo.size.height <= 0) {
        return DEFAULT_BUFFER_SIZE;
    }
    return GetDefaultBufferSize(imageInfo.size.width, imageInfo.size.height);
}

static OHOS::Media::EncodeDynamicRange ParseDynamicRange(PackingOption const& options)
{
    uint32_t tmpNumber = 0;
    if (!options.desiredDynamicRange.has_value()) {
        return OHOS::Media::EncodeDynamicRange::SDR;
    } else {
        tmpNumber = static_cast<uint32_t>(options.desiredDynamicRange->get_value());
    }
    if (tmpNumber <= static_cast<uint32_t>(OHOS::Media::EncodeDynamicRange::SDR)) {
        return OHOS::Media::EncodeDynamicRange(tmpNumber);
    }
    return OHOS::Media::EncodeDynamicRange::SDR;
}

static bool ParseNeedsPackProperties(PackingOption const& options)
{
    if (!options.needsPackProperties.has_value()) {
        IMAGE_LOGD("No needsPackProperties in pack option");
        return false;
    }
    return options.needsPackProperties.value();
}

static int64_t ParseBufferSize(std::unique_ptr<ImagePackerTaiheContext> &context, PackingOption const& options)
{
    int64_t defaultSize = GetDefaultBufferSize(context);
    if (!options.bufferSize.has_value()) {
        IMAGE_LOGI("No bufferSize, Using default");
        return defaultSize;
    }
    int64_t tmpNumber = options.bufferSize.value();
    IMAGE_LOGD("BufferSize is %{public}" PRId64, tmpNumber);
    if (tmpNumber < 0) {
        return defaultSize;
    }
    return tmpNumber;
}

static bool HandlePixelMapList(std::unique_ptr<ImagePackerTaiheContext>& context)
{
    if (context->frameCount == 0) {
        IMAGE_LOGE("Parameter input error, invalid frameCount");
        return false;
    }
    if (context->rPixelMaps == nullptr || context->rPixelMaps->empty()) {
        IMAGE_LOGE("Parameter input error, pixelmaplist is empty");
        return false;
    }
    uint32_t pixelMapListLength = context->rPixelMaps->size();
    if (pixelMapListLength > context->frameCount) {
        for (uint32_t i = pixelMapListLength; i > context->frameCount; i--) {
            context->rPixelMaps->pop_back();
        }
    } else if (pixelMapListLength < context->frameCount) {
        for (uint32_t i = pixelMapListLength; i < context->frameCount; i++) {
            context->rPixelMaps->push_back((*context->rPixelMaps)[pixelMapListLength - 1]);
        }
    }
    return true;
}

static bool ParsePackOptionOfDelayTimes(std::unique_ptr<ImagePackerTaiheContext>& context,
    PackingOptionsForSequence const& options)
{
    int32_t num;
    uint32_t len = options.delayTimeList.size();
    for (size_t i = 0; i < len; i++) {
        num = options.delayTimeList[i];
        if (num <= 0 || num > MASK_16) {
            IMAGE_LOGE("Invalid delayTime, out of range");
            return false;
        }
        context->packOption.delayTimes.push_back(static_cast<uint16_t>(num) & static_cast<uint16_t>(MASK_16));
    }
    if (len < context->frameCount) {
        for (uint32_t i = len; i < context->frameCount; i++) {
            context->packOption.delayTimes.push_back(static_cast<uint16_t>(num) & static_cast<uint16_t>(MASK_16));
        }
    }
    return true;
}

static bool ParsePackOptionOfFrameCount(std::unique_ptr<ImagePackerTaiheContext>& context,
    PackingOptionsForSequence const& options)
{
    context->frameCount = options.frameCount;
    if (!HandlePixelMapList(context)) {
        return false;
    }
    return ParsePackOptionOfDelayTimes(context, options);
}

static bool ParsePackOptionOfDisposalTypes(std::unique_ptr<ImagePackerTaiheContext>& context,
    PackingOptionsForSequence const& options, OHOS::Media::PackOption* opts)
{
    if (options.disposalTypes.has_value()) {
        int32_t num;
        uint32_t len = options.disposalTypes.value().size();
        for (size_t i = 0; i < len; i++) {
            num = options.disposalTypes.value()[i];
            if (num < 0 || num > MASK_3) {
                IMAGE_LOGE("Invalid disposalTypes, out of range");
                return false;
            }
            opts->disposalTypes.push_back(static_cast<uint8_t>(num) & static_cast<uint8_t>(MASK_3));
        }
    }
    return true;
}

static bool ParsePackOptionOfLoop(std::unique_ptr<ImagePackerTaiheContext>& context,
    PackingOptionsForSequence const& options)
{
    context->packOption.format = "image/gif";
    int32_t tmpNumber = 0;
    if (options.loopCount.has_value()) {
        tmpNumber = options.loopCount.value();
    } else {
        tmpNumber = 1;
    }
    if (tmpNumber < 0 || tmpNumber > MASK_16) {
        IMAGE_LOGE("Invalid loopCount");
        return false;
    }
    context->packOption.loop = static_cast<uint16_t>(tmpNumber) & static_cast<uint16_t>(MASK_16);
    return ParsePackOptionOfFrameCount(context, options);
}

static uint8_t ParsePackOptionOfQuality(PackingOption const& options)
{
    uint32_t tmpNumber = options.quality;
    if (tmpNumber > SIZE) {
        IMAGE_LOGE("Invalid quality");
        return BYTE_FULL;
    } else {
        return static_cast<uint8_t>(tmpNumber & 0xff);
    }
}

static OHOS::Media::PackOption ParsePackOptions(PackingOption const& options)
{
    OHOS::Media::PackOption packOption;
    packOption.format = std::string(options.format);
    packOption.quality = ParsePackOptionOfQuality(options);
    packOption.desiredDynamicRange = ParseDynamicRange(options);
    IMAGE_LOGI("ParsePackOptions format:[%{public}s]", packOption.format.c_str());
    packOption.needsPackProperties = ParseNeedsPackProperties(options);
    return packOption;
}

static std::shared_ptr<OHOS::Media::ImageSource> GetImageSourceFromTaihe(int64_t source)
{
    ImageSourceImpl* imageSourceImpl = reinterpret_cast<ImageSourceImpl*>(source);
    if (imageSourceImpl == nullptr) {
        IMAGE_LOGE("GetImageSourceFromTaihe imageSourceImpl is nullptr");
        ImageTaiheUtils::ThrowExceptionError("Fail to unwrap imageSourceImpl.");
        return nullptr;
    }
    return imageSourceImpl->nativeImgSrc;
}

static std::shared_ptr<OHOS::Media::PixelMap> GetPixelMap(int64_t source)
{
    PixelMapImpl* pixelMapImpl = reinterpret_cast<PixelMapImpl*>(source);
    if (pixelMapImpl == nullptr) {
        IMAGE_LOGE("GetPixelMap pixelMapImpl is nullptr");
        ImageTaiheUtils::ThrowExceptionError("Fail to unwrap pixelMapImpl.");
        return nullptr;
    }
    return pixelMapImpl->GetNativePtr();
}

static std::shared_ptr<OHOS::Media::Picture> GetPicture(int64_t source)
{
    PictureImpl* pictureImpl = reinterpret_cast<PictureImpl*>(source);
    if (pictureImpl == nullptr) {
        IMAGE_LOGE("GetPicture pictureImpl is nullptr");
        ImageTaiheUtils::ThrowExceptionError("Fail to unwrap pictureImpl.");
        return nullptr;
    }
    return pictureImpl->GetNativePtr();
}

static std::shared_ptr<std::vector<std::shared_ptr<OHOS::Media::PixelMap>>> GetPixelMaps(
    array_view<PixelMap> pixelmapSequence)
{
    auto PixelMaps = std::make_shared<std::vector<std::shared_ptr<OHOS::Media::PixelMap>>>();
    for (uint32_t i = 0; i < pixelmapSequence.size(); ++i) {
        std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
        if (ImageTaiheUtils::IsValidPtr<weak::PixelMap>(pixelmapSequence[i])) {
            pixelMap = GetPixelMap(pixelmapSequence[i]->GetImplPtr());
        }
        PixelMaps->push_back(pixelMap);
    }
    return PixelMaps;
}

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
bool SetPicture(std::unique_ptr<ImagePackerTaiheContext> &context)
{
    IMAGE_LOGD("ImagePacker set picture");
    if (context->rPicture == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "Picture is nullptr");
        return false;
    }
    context->rImagePacker->AddPicture(*(context->rPicture));
    return true;
}
#endif

bool SetArrayPixel(std::unique_ptr<ImagePackerTaiheContext> &context)
{
    IMAGE_LOGD("ImagePacker set pixelmap array");
    if (!context->rPixelMaps) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "PixelmapList is nullptr");
        return false;
    }
    for (auto &pixelMap : *context->rPixelMaps.get()) {
        context->rImagePacker->AddImage(*(pixelMap.get()));
    }
    return true;
}

static bool FinalizePackToFile(std::unique_ptr<ImagePackerTaiheContext> &context)
{
    int64_t packedSize = 0;
    auto packRes = context->rImagePacker->FinalizePacking(packedSize);
    IMAGE_LOGD("packRes=%{public}d packedSize=%{public}" PRId64, packRes, packedSize);
    if (packRes == OHOS::Media::SUCCESS && packedSize > 0) {
        context->packedSize = packedSize;
        return true;
    } else {
        if (context->packType == TYPE_PICTURE) {
            ImageTaiheUtils::ThrowExceptionError(packRes == OHOS::Media::ERR_IMAGE_INVALID_PARAMETER ?
                IMAGE_BAD_PARAMETER : IMAGE_ENCODE_FAILED, "PackToFile picture failed");
        }
        ImageTaiheUtils::ThrowExceptionError(packRes, "PackedSize outside size");
        IMAGE_LOGE("Packing failed, packedSize outside size.");
        return false;
    }
}

static bool PackToFileExec(std::unique_ptr<ImagePackerTaiheContext> &context)
{
    auto startRes = context->rImagePacker->StartPacking(context->fd, context->packOption);
    if (startRes != OHOS::Media::SUCCESS) {
        if (context->packType == TYPE_PICTURE) {
            ImageTaiheUtils::ThrowExceptionError(startRes == OHOS::Media::ERR_IMAGE_INVALID_PARAMETER ?
                IMAGE_BAD_PARAMETER : IMAGE_ENCODE_FAILED, "PackToFile start packing failed");
            return false;
        }
        ImageTaiheUtils::ThrowExceptionError(startRes, "Start packing failed");
        return false;
    }
    if (context->packType == TYPE_IMAGE_SOURCE) {
        IMAGE_LOGI("ImagePacker set image source");
        if (!context->rImageSource) {
            ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_INVALID_PARAMETER, "ImageSource is nullptr");
            return false;
        }
        context->rImagePacker->AddImage(*(context->rImageSource));
    } else if (context->packType == TYPE_PIXEL_MAP) {
        IMAGE_LOGD("ImagePacker set pixelmap");
        if (!context->rPixelMap) {
            ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_INVALID_PARAMETER, "Pixelmap is nullptr");
            return false;
        }
        context->rImagePacker->AddImage(*(context->rPixelMap));
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    } else if (context->packType == TYPE_PICTURE) {
        if (!SetPicture(context)) {
            return false;
        }
#endif
    } else if (context->packType == TYPE_ARRAY) {
        if (!SetArrayPixel(context)) {
            return false;
        }
    }
    return FinalizePackToFile(context);
}

static bool ParserPackToFileArguments(int32_t packType, int64_t source, int32_t fd, PackingOption const& options,
    std::unique_ptr<ImagePackerTaiheContext>& context)
{
    context->packType = packType;
    if (context->packType == TYPE_IMAGE_SOURCE) {
        context->rImageSource = GetImageSourceFromTaihe(source);
        if (context->rImageSource == nullptr) {
            ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_INVALID_PARAMETER, "ImageSource mismatch");
            return false;
        }
    } else if (context->packType == TYPE_PIXEL_MAP) {
        context->rPixelMap = GetPixelMap(source);
        if (context->rPixelMap == nullptr) {
            ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_INVALID_PARAMETER, "Pixelmap is released");
            return false;
        }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    } else if (context->packType == TYPE_PICTURE) {
        context->rPicture = GetPicture(source);
        if (context->rPicture == nullptr) {
            ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "Picture mismatch");
            return false;
        }
#endif
    }

    uint32_t errorCode = context->packType == TYPE_PICTURE ?
        IMAGE_BAD_PARAMETER : OHOS::Media::ERR_IMAGE_INVALID_PARAMETER;
    context->fd = fd;
    if (context->fd <= INVALID_FD) {
        ImageTaiheUtils::ThrowExceptionError(errorCode, "fd mismatch");
        return false;
    }
    context->packOption = ParsePackOptions(options);
    return true;
}

static bool ParserPackToFileArgumentsArray(array_view<PixelMap> pixelmapSequence, int32_t fd,
    PackingOptionsForSequence const& options, std::unique_ptr<ImagePackerTaiheContext>& context)
{
    context->rPixelMaps = GetPixelMaps(pixelmapSequence);
    if (context->rPixelMaps == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "PixelMap mismatch");
        return false;
    }
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    context->fd = fd;
    if (context->fd <= INVALID_FD) {
        ImageTaiheUtils::ThrowExceptionError(errorCode, "fd mismatch");
        return false;
    }
    if (!ParsePackOptionOfLoop(context, options)) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "PackOptions mismatch");
        return false;
    }
    if (!ParsePackOptionOfDisposalTypes(context, options, &(context->packOption))) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "PackOptions mismatch");
        return false;
    }
    return true;
}

void ImagePackerImpl::PackToFile(int32_t packType, int64_t source, int32_t fd, PackingOption const& options)
{
    OHOS::Media::ImageTrace imageTrace("ImagePackerTaihe::PackToFile");

    std::unique_ptr<ImagePackerTaiheContext> context = std::make_unique<ImagePackerTaiheContext>();
    context->rImagePacker = nativeImagePacker_;
    if (!ParserPackToFileArguments(packType, source, fd, options, context)) {
        IMAGE_LOGE("ParserPackToFileArguments Failed");
        return;
    }

    ImageTaiheUtils::HicheckerReport();

    if (!PackToFileExec(context)) {
        IMAGE_LOGE("PackToFileExec Failed");
    }
}

void ImagePackerImpl::PackImageSourceToFileSync(weak::ImageSource source, int32_t fd, PackingOption const& options)
{
    if (!ImageTaiheUtils::IsValidPtr(source)) {
        ImageTaiheUtils::ThrowExceptionError("fail to unwrap taihe ImageSource");
        return;
    }
    PackToFile(TYPE_IMAGE_SOURCE, source->GetImplPtr(), fd, options);
}

void ImagePackerImpl::PackPixelMapToFileSync(weak::PixelMap source, int32_t fd, PackingOption const& options)
{
    if (!ImageTaiheUtils::IsValidPtr(source)) {
        ImageTaiheUtils::ThrowExceptionError("fail to unwrap taihe PixelMap");
        return;
    }
    PackToFile(TYPE_PIXEL_MAP, source->GetImplPtr(), fd, options);
}

void ImagePackerImpl::PackToFileFromPixelmapSequenceSync(array_view<PixelMap> pixelmapSequence, int32_t fd,
    PackingOptionsForSequence const& options)
{
    OHOS::Media::ImageTrace imageTrace("ImagePackerTaihe::PackImageSourceToFile");

    std::unique_ptr<ImagePackerTaiheContext> context = std::make_unique<ImagePackerTaiheContext>();
    context->rImagePacker = nativeImagePacker_;
    context->packType = TYPE_ARRAY;
    if (!ParserPackToFileArgumentsArray(pixelmapSequence, fd, options, context)) {
        IMAGE_LOGE("ParserPackToFileArguments Failed");
        return;
    }

    ImageTaiheUtils::HicheckerReport();

    if (!PackToFileExec(context)) {
        IMAGE_LOGE("PackToFileExec Failed");
    }
}

void ImagePackerImpl::PackPictureToFileSync(weak::Picture picture, int32_t fd, PackingOption const& options)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (!ImageTaiheUtils::IsValidPtr(picture)) {
        ImageTaiheUtils::ThrowExceptionError("fail to unwrap taihe Picture");
        return;
    }
    PackToFile(TYPE_PICTURE, picture->GetImplPtr(), fd, options);
#endif
}

static void ThrowPackingError(std::unique_ptr<ImagePackerTaiheContext> &ctx, int32_t errorCode, const std::string msg)
{
    if (ctx == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImagePacker taihe context is nullptr");
        return;
    }
    if (ctx->needReturnErrorCode) {
        ImageTaiheUtils::ThrowExceptionError(errorCode, msg);
    } else {
        ImageTaiheUtils::ThrowExceptionError(msg);
    }
}

static bool FinalizePacking(std::unique_ptr<ImagePackerTaiheContext> &context, int32_t innerEncodeErrorCode)
{
    int64_t packedSize = 0;
    auto packRes = context->rImagePacker->FinalizePacking(packedSize);
    IMAGE_LOGD("packedSize=%{public}" PRId64, packedSize);
    if (packRes == OHOS::Media::SUCCESS) {
        context->packedSize = packedSize;
        return true;
    } else if (packedSize == context->resultBufferSize) {
        if (context->packType == TYPE_PICTURE) {
            ThrowPackingError(context, IMAGE_ENCODE_FAILED, "output buffer is not enough");
        } else {
            ThrowPackingError(context, OHOS::Media::ERR_IMAGE_TOO_LARGE, "output buffer is not enough");
        }
        IMAGE_LOGE("output buffer is not enough.");
        return false;
    } else {
        IMAGE_LOGE("Packing failed, packedSize outside size.");
        ThrowPackingError(context, packRes == OHOS::Media::ERR_IMAGE_INVALID_PARAMETER ?
            OHOS::Media::COMMON_ERR_INVALID_PARAMETER : innerEncodeErrorCode, "Packing failed");
        return false;
    }
}

static bool PackingExec(std::unique_ptr<ImagePackerTaiheContext> &context)
{
    IMAGE_LOGD("ImagePacker BufferSize %{public}" PRId64, context->resultBufferSize);
    context->resultBuffer = std::make_unique<uint8_t[]>(
        (context->resultBufferSize <= 0) ? GetDefaultBufferSize(context) : context->resultBufferSize);
    int32_t innerEncodeErrorCode = static_cast<int32_t>(
        context->packType == TYPE_PICTURE ? IMAGE_ENCODE_FAILED : OHOS::Media::ERR_IMAGE_ENCODE_FAILED);
    if (context->resultBuffer == nullptr) {
        ThrowPackingError(context, innerEncodeErrorCode, "ImagePacker buffer alloc error");
        return false;
    }
    auto startRes = context->rImagePacker->StartPacking(context->resultBuffer.get(),
    context->resultBufferSize, context->packOption);
    if (startRes != OHOS::Media::SUCCESS) {
        ThrowPackingError(context, startRes == OHOS::Media::ERR_IMAGE_INVALID_PARAMETER ?
            OHOS::Media::COMMON_ERR_INVALID_PARAMETER : innerEncodeErrorCode, "Packing start packing failed");
        return false;
    }
    if (context->packType == TYPE_IMAGE_SOURCE) {
        IMAGE_LOGI("ImagePacker set image source");
        if (context->rImageSource == nullptr) {
            ThrowPackingError(context, OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "ImageSource is nullptr");
            return false;
        }
        context->rImagePacker->AddImage(*(context->rImageSource));
    } else if (context->packType == TYPE_PIXEL_MAP) {
        IMAGE_LOGD("ImagePacker set pixelmap");
        if (context->rPixelMap == nullptr) {
            ThrowPackingError(context, OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "Pixelmap is nullptr");
            return false;
        }
        context->rImagePacker->AddImage(*(context->rPixelMap));
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    } else if (context->packType == TYPE_PICTURE) {
        if (!SetPicture(context)) {
            return false;
        }
#endif
    } else if (context->packType == TYPE_ARRAY) {
        if (!SetArrayPixel(context)) {
            return false;
        }
    }
    return FinalizePacking(context, innerEncodeErrorCode);
}

static array<uint8_t> PackingComplete(std::unique_ptr<ImagePackerTaiheContext> &context)
{
    if (context == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("PackingComplete context is nullptr!");
        return array<uint8_t>(0);
    }

    array<uint8_t> arrayBuffer = ImageTaiheUtils::CreateTaiheArrayBuffer(context->resultBuffer.get(),
        context->packedSize);
    if (arrayBuffer.empty()) {
        ImageTaiheUtils::ThrowExceptionError("CreateTaiheArrayBuffer failed!");
    }

    context->resultBuffer = nullptr;
    context->resultBufferSize = 0;
    return arrayBuffer;
}

static bool ParserPackingArguments(int32_t packType, int64_t source, PackingOption const& options,
    std::unique_ptr<ImagePackerTaiheContext>& context)
{
    context->packType = packType;
    if (context->packType == TYPE_PICTURE) {
        context->needReturnErrorCode = true;
    }
    if (context->packType == TYPE_IMAGE_SOURCE) {
        context->rImageSource = GetImageSourceFromTaihe(source);
        if (context->rImageSource == nullptr) {
            ThrowPackingError(context, OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "ImageSource mismatch");
            return false;
        }
    } else if (context->packType == TYPE_PIXEL_MAP) {
        context->rPixelMap = GetPixelMap(source);
        if (context->rPixelMap == nullptr) {
            ThrowPackingError(context, OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "Pixelmap is released");
            return false;
        }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    } else if (context->packType == TYPE_PICTURE) {
        context->rPicture = GetPicture(source);
        if (context->rPicture == nullptr) {
            ThrowPackingError(context, OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "Picture mismatch");
            return false;
        }
    }
#endif
    context->packOption = ParsePackOptions(options);
    context->resultBufferSize = ParseBufferSize(context, options);
    return true;
}

static bool ParserPackingArgumentsArray(array_view<PixelMap> pixelmapSequence,
    PackingOptionsForSequence const& options, std::unique_ptr<ImagePackerTaiheContext>& context)
{
    context->rPixelMaps = GetPixelMaps(pixelmapSequence);
    if (context->rPixelMaps == nullptr) {
        ThrowPackingError(context, OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "PixelMaps mismatch");
        return false;
    }

    if (!ParsePackOptionOfLoop(context, options)) {
        ThrowPackingError(context, OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "PackOptions mismatch");
        return false;
    }
    context->resultBufferSize = DEFAULT_BUFFER_SIZE;
    if (!ParsePackOptionOfDisposalTypes(context, options, &(context->packOption))) {
        ThrowPackingError(context, OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "PackOptions mismatch");
        return false;
    }
    return true;
}

array<uint8_t> ImagePackerImpl::Packing(int32_t packType, int64_t source, PackingOption const& options,
    bool needReturnError)
{
    OHOS::Media::ImageTrace imageTrace("ImagePackerTaihe::Packing");
    IMAGE_LOGI("PackingFromTaihe IN");

    std::unique_ptr<ImagePackerTaiheContext> context = std::make_unique<ImagePackerTaiheContext>();
    context->needReturnErrorCode = needReturnError;
    context->rImagePacker = nativeImagePacker_;
    if (!ParserPackingArguments(packType, source, options, context)) {
        IMAGE_LOGE("ParserPackingArguments Failed");
        return array<uint8_t>(0);
    }

    ImageTaiheUtils::HicheckerReport();

    if (!PackingExec(context)) {
        IMAGE_LOGE("PackingExec Failed");
        return array<uint8_t>(0);
    }
    return PackingComplete(context);
}

array<uint8_t> ImagePackerImpl::PackingPictureSync(weak::Picture picture, PackingOption const& options)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (!ImageTaiheUtils::IsValidPtr(picture)) {
        ImageTaiheUtils::ThrowExceptionError("fail to unwrap taihe Picture");
        return array<uint8_t>(0);
    }
    return Packing(TYPE_PICTURE, picture->GetImplPtr(), options, true);
#else
    ImageTaiheUtils::ThrowExceptionError("Invalid type!");
#endif
}

array<uint8_t> ImagePackerImpl::PackImageSourceToDataSync(weak::ImageSource source, PackingOption const& options)
{
    if (!ImageTaiheUtils::IsValidPtr(source)) {
        ImageTaiheUtils::ThrowExceptionError("fail to unwrap taihe ImageSource");
        return array<uint8_t>(0);
    }
    return Packing(TYPE_IMAGE_SOURCE, source->GetImplPtr(), options, true);
}

array<uint8_t> ImagePackerImpl::PackPixelMapToDataSync(weak::PixelMap source, PackingOption const& options)
{
    if (!ImageTaiheUtils::IsValidPtr(source)) {
        ImageTaiheUtils::ThrowExceptionError("fail to unwrap taihe PixelMap");
        return array<uint8_t>(0);
    }
    return Packing(TYPE_PIXEL_MAP, source->GetImplPtr(), options, true);
}

array<uint8_t> ImagePackerImpl::PackToDataFromPixelmapSequenceSync(array_view<PixelMap> pixelmapSequence,
    PackingOptionsForSequence const& options)
{
    OHOS::Media::ImageTrace imageTrace("ImagePackerTaihe::PackToDataFromPixelmapSequenceSync");
    IMAGE_LOGI("PackToDataFromPixelmapSequenceSync IN");

    std::unique_ptr<ImagePackerTaiheContext> context = std::make_unique<ImagePackerTaiheContext>();
    context->needReturnErrorCode = true;
    context->rImagePacker = nativeImagePacker_;
    context->packType = TYPE_ARRAY;
    if (!ParserPackingArgumentsArray(pixelmapSequence, options, context)) {
        IMAGE_LOGE("ParserPackingArguments Failed");
        return array<uint8_t>(0);
    }

    ImageTaiheUtils::HicheckerReport();

    if (!PackingExec(context)) {
        IMAGE_LOGE("PackingExec Failed");
        return array<uint8_t>(0);
    }
    return PackingComplete(context);
}

void ImagePackerImpl::ReleaseSync()
{
    if (!isRelease) {
        nativeImagePacker_ = nullptr;
        isRelease = true;
    }
}

array<string> ImagePackerImpl::GetSupportedFormats()
{
    std::set<std::string> formats;
    nativeImagePacker_->GetSupportedFormats(formats);
    std::vector<std::string> vec(formats.begin(), formats.end());
    return ImageTaiheUtils::ToTaiheArrayString(vec);
}

ImagePacker CreateImagePacker()
{
    OHOS::Media::ImageTrace imageTrace("ImagePackerTaihe::CreateImagePacker");
    std::shared_ptr<OHOS::Media::ImagePacker> imagePacker = std::make_shared<OHOS::Media::ImagePacker>();
    return make_holder<ImagePackerImpl, ImagePacker>(imagePacker);
}

array<string> GetImagePackerSupportedFormats()
{
    std::set<std::string> formats;
    uint32_t ret = OHOS::Media::ImagePacker::GetSupportedFormats(formats);
    if (ret != OHOS::Media::SUCCESS) {
        IMAGE_LOGE("Fail to get decode supported formats");
    }
    return ImageTaiheUtils::ToTaiheArrayString(std::vector(formats.begin(), formats.end()));
}
} // namespace ANI::Image

TH_EXPORT_CPP_API_CreateImagePacker(CreateImagePacker);
TH_EXPORT_CPP_API_GetImagePackerSupportedFormats(GetImagePackerSupportedFormats);