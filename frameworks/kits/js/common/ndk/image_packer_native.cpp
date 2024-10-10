/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "image_packer_native.h"

#include "common_utils.h"
#include "image_packer.h"
#include "image_packer_native_impl.h"
#include "image_source_native_impl.h"
#include "pixelmap_native_impl.h"
#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif

using namespace OHOS;
using namespace Media;
#ifdef __cplusplus
extern "C" {
#endif

constexpr size_t SIZE_ZERO = 0;
constexpr int32_t IMAGE_BASE = 62980096;
static constexpr int32_t IMAGE_BASE_19 = 19;
static constexpr int32_t IMAGE_BASE_16 = 16;
static constexpr int32_t IMAGE_BASE_17 = 17;
static constexpr int32_t IMAGE_BASE_26 = 26;
static constexpr int32_t IMAGE_BASE_31 = 31;
static constexpr int32_t IMAGE_BASE_152 = 152;
static constexpr int32_t IMAGE_BASE_27 = 27;
static constexpr int32_t IMAGE_BASE_12 = 12;
static constexpr int32_t IMAGE_BASE_13 = 13;
static constexpr int32_t IMAGE_BASE_6 = 6;
static constexpr int32_t IMAGE_BASE_14 = 14;
static constexpr int32_t IMAGE_BASE_4 = 4;
static constexpr int32_t IMAGE_BASE_9 = 9;
static constexpr int32_t IMAGE_BASE_20 = 20;
static constexpr int32_t IMAGE_BASE_22 = 22;
static constexpr int32_t IMAGE_BASE_23 = 23;

struct OH_PackingOptions {
    Image_MimeType mimeType;
    int quality;
    int32_t desiredDynamicRange = IMAGE_PACKER_DYNAMIC_RANGE_SDR;
    uint16_t loop;
    uint16_t* delayTimes;
    uint32_t delayTimesSize;
    uint16_t* disposalTypes;
    uint32_t disposalTypesSize;
    bool needsPackProperties = false;
};

static Image_ErrorCode ToNewErrorCode(int code)
{
    switch (code) {
        case 0:
            return IMAGE_SUCCESS;
        case IMAGE_BASE + IMAGE_BASE_19:
            return IMAGE_BAD_PARAMETER;
        case IMAGE_BASE + IMAGE_BASE_16:
        case IMAGE_BASE + IMAGE_BASE_17:
        case IMAGE_BASE + IMAGE_BASE_26:
            return IMAGE_UNKNOWN_MIME_TYPE;
        case IMAGE_BASE + IMAGE_BASE_31:
            return IMAGE_TOO_LARGE;
        case IMAGE_BASE + IMAGE_BASE_152:
            return IMAGE_UNSUPPORTED_OPERATION;
        case IMAGE_BASE + IMAGE_BASE_27:
            return IMAGE_UNSUPPORTED_METADATA;
        case IMAGE_BASE + IMAGE_BASE_12:
            return IMAGE_UNSUPPORTED_CONVERSION;
        case IMAGE_BASE + IMAGE_BASE_13:
            return IMAGE_INVALID_REGION;
        case IMAGE_BASE + IMAGE_BASE_6:
            return IMAGE_ALLOC_FAILED;
        case IMAGE_BASE + IMAGE_BASE_14:
            return IMAGE_BAD_SOURCE;
        case IMAGE_BASE + IMAGE_BASE_4:
        case IMAGE_BASE + IMAGE_BASE_9:
        case IMAGE_BASE + IMAGE_BASE_20:
        case IMAGE_BASE + IMAGE_BASE_22:
            return IMAGE_DECODE_FAILED;
        case IMAGE_BASE + IMAGE_BASE_23:
            return IMAGE_ENCODE_FAILED;
        default:
            return IMAGE_UNKNOWN_ERROR;
    }
};

static EncodeDynamicRange ParseDynamicRange(int32_t val)
{
    if (val <= static_cast<int32_t>(EncodeDynamicRange::SDR)) {
        return EncodeDynamicRange(val);
    }

    return EncodeDynamicRange::SDR;
}

static Image_ErrorCode CopyPackingOptions(const OH_PackingOptions *options, PackOption &packOption)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    std::string format(options->mimeType.data, options->mimeType.size);
    if (format.empty()) {
        return IMAGE_BAD_PARAMETER;
    }
    packOption.format = format;
    packOption.quality = options->quality;
    packOption.needsPackProperties = options->needsPackProperties;
    packOption.desiredDynamicRange = ParseDynamicRange(options->desiredDynamicRange);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_Create(OH_PackingOptions **options)
{
    *options = new OH_PackingOptions();
    if (*options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_GetMimeType(OH_PackingOptions *options,
    Image_MimeType *format)
{
    if (options == nullptr || format == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    if (format->size != SIZE_ZERO && format->size < options->mimeType.size) {
        return IMAGE_BAD_PARAMETER;
    }

    format->size = (format->size == SIZE_ZERO) ? options->mimeType.size : format->size;
    format->data = static_cast<char *>(malloc(format->size));
    if (format->data == nullptr) {
        return IMAGE_ALLOC_FAILED;
    }

    if (memcpy_s(format->data, format->size, options->mimeType.data, options->mimeType.size) != 0) {
        free(format->data);
        format->data = nullptr;
        format->size = 0;
        return IMAGE_COPY_FAILED;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_SetMimeType(OH_PackingOptions *options,
    Image_MimeType *format)
{
    if (options == nullptr || format->data == nullptr || format->size == 0) {
        return IMAGE_BAD_PARAMETER;
    }
    if (options->mimeType.data != nullptr) {
        free(options->mimeType.data);
        options->mimeType.data = nullptr;
    }
    options->mimeType.size = format->size;
    options->mimeType.data = static_cast<char *>(malloc(options->mimeType.size));
    if (options->mimeType.data == nullptr) {
        return IMAGE_ALLOC_FAILED;
    }
    if (memcpy_s(options->mimeType.data, options->mimeType.size, format->data, format->size) != 0) {
        free(options->mimeType.data);
        options->mimeType.data = nullptr;
        options->mimeType.size = 0;
        return IMAGE_COPY_FAILED;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_GetQuality(OH_PackingOptions *options, uint32_t *quality)
{
    if (options == nullptr || quality == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *quality = options->quality;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_SetQuality(OH_PackingOptions *options, uint32_t quality)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->quality = static_cast<int>(quality);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_GetNeedsPackProperties(OH_PackingOptions *options, bool *needsPackProperties)
{
    if (options == nullptr || needsPackProperties == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *needsPackProperties = options->needsPackProperties;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_SetNeedsPackProperties(OH_PackingOptions *options, bool needsPackProperties)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->needsPackProperties = needsPackProperties;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_GetDesiredDynamicRange(OH_PackingOptions *options, int32_t* desiredDynamicRange)
{
    if (options == nullptr || desiredDynamicRange == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *desiredDynamicRange = options->desiredDynamicRange;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_SetDesiredDynamicRange(OH_PackingOptions *options, int32_t desiredDynamicRange)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->desiredDynamicRange = desiredDynamicRange;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_SetLoop(OH_PackingOptions *options, uint16_t loop)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->loop = loop;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_GetLoop(OH_PackingOptions *options, uint16_t* loop)
{
    if (options == nullptr || loop == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *loop = options->loop;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_SetDelayTimes(OH_PackingOptions *options, uint16_t* delayTimes,
    uint32_t delayTimesSize)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->delayTimes = delayTimes;
    options->delayTimesSize = delayTimesSize;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_GetDelayTimes(OH_PackingOptions *options, uint16_t* delayTimes,
    uint32_t* delayTimesSize)
{
    if (options == nullptr || delayTimes == nullptr || delayTimesSize == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delayTimes = options->delayTimes;
    *delayTimesSize = options->delayTimesSize;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_SetDisposalTypes(OH_PackingOptions *options, uint16_t* disposalTypes,
    uint32_t disposalTypesSize)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->disposalTypes = disposalTypes;
    options->disposalTypesSize = disposalTypesSize;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_GetDisposalTypes(OH_PackingOptions *options, uint16_t* disposalTypes,
    uint32_t* disposalTypesSize)
{
    if (options == nullptr || disposalTypes == nullptr || disposalTypesSize == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    disposalTypes = options->disposalTypes;
    *disposalTypesSize = options->disposalTypesSize;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PackingOptions_Release(OH_PackingOptions *options)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    if (options->mimeType.data) {
        free(options->mimeType.data);
        options->mimeType.data = nullptr;
    }
    delete options;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImagePackerNative_Create(OH_ImagePackerNative **imagePacker)
{
    auto imagePacker2 = new OH_ImagePackerNative();
    if (imagePacker2 == nullptr || imagePacker2->GetInnerImagePacker() == nullptr) {
        if (imagePacker2) {
            delete imagePacker2;
        }
        return IMAGE_BAD_PARAMETER;
    }
    *imagePacker = imagePacker2;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImagePackerNative_PackToDataFromImageSource(OH_ImagePackerNative *imagePacker,
    OH_PackingOptions *options, OH_ImageSourceNative *imageSource, uint8_t *outData, size_t *size)
{
    if (imagePacker == nullptr || options == nullptr || imageSource == nullptr || outData == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    PackOption packOption;
    Image_ErrorCode errorCode = CopyPackingOptions(options, packOption);
    if (errorCode != IMAGE_SUCCESS) {
        return errorCode;
    }
    return ToNewErrorCode(imagePacker->PackingFromImageSource(&packOption, imageSource,
        outData, reinterpret_cast<int64_t*>(size)));
}

MIDK_EXPORT
Image_ErrorCode OH_ImagePackerNative_PackToDataFromPixelmap(OH_ImagePackerNative *imagePacker,
    OH_PackingOptions *options, OH_PixelmapNative *pixelmap, uint8_t *outData, size_t *size)
{
    if (imagePacker == nullptr || options == nullptr || pixelmap == nullptr || outData == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    PackOption packOption;
    Image_ErrorCode errorCode = CopyPackingOptions(options, packOption);
    if (errorCode != IMAGE_SUCCESS) {
        return errorCode;
    }
    return ToNewErrorCode(imagePacker->PackingFromPixelmap(&packOption, pixelmap, outData,
        reinterpret_cast<int64_t*>(size)));
}

MIDK_EXPORT
Image_ErrorCode OH_ImagePacker_PackToDataMultiFrames(OH_ImagePackerNative *imagePacker, OH_PackingOptions *options,
    OH_PixelmapNative **pixelmaps, int32_t mapSize, uint8_t* outData, size_t* outDataSize)
{
    if (imagePacker == nullptr || options == nullptr || pixelmaps == nullptr || outData == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    std::vector<OH_PixelmapNative*> pixelmap;
    PackOption packOption;
    std::string format(options->mimeType.data, options->mimeType.size);
    packOption.format = format;
    packOption.quality = options->quality;
    packOption.desiredDynamicRange = ParseDynamicRange(options->desiredDynamicRange);
    packOption.loop = options->loop;
    
    for (uint32_t i = 0; i < options->delayTimesSize; i++) {
        packOption.delayTimes.push_back(options->delayTimes[i]);
    }
    for (uint32_t i = 0; i < options->disposalTypesSize; i++) {
        packOption.disposalTypes.push_back(options->disposalTypes[i]);
    }
    for (int i = 0; i < mapSize; i++) {
        pixelmap.push_back(pixelmaps[i]);
    }
    return ToNewErrorCode(imagePacker->PackToDataMultiFrames(&packOption, pixelmap, outData,
        reinterpret_cast<int64_t*>(outDataSize)));
}

MIDK_EXPORT
Image_ErrorCode OH_ImagePackerNative_PackToDataFromPicture(OH_ImagePackerNative *imagePacker,
    OH_PackingOptions *options, OH_PictureNative *picture, uint8_t *outData, size_t *size)
{
    if (imagePacker == nullptr || options == nullptr || picture == nullptr || outData == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    PackOption packOption;
    Image_ErrorCode errorCode = CopyPackingOptions(options, packOption);
    if (errorCode != IMAGE_SUCCESS) {
        return errorCode;
    }
    return ToNewErrorCode(imagePacker->PackToDataFromPicture(&packOption, picture, outData,
        reinterpret_cast<int64_t*>(size)));
}

MIDK_EXPORT
Image_ErrorCode OH_ImagePackerNative_PackToFileFromImageSource(OH_ImagePackerNative *imagePacker,
    OH_PackingOptions *options, OH_ImageSourceNative *imageSource, int32_t fd)
{
    if (imagePacker == nullptr || options == nullptr || imageSource == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    PackOption packOption;
    Image_ErrorCode errorCode = CopyPackingOptions(options, packOption);
    if (errorCode != IMAGE_SUCCESS) {
        return errorCode;
    }
    return ToNewErrorCode(imagePacker->PackToFileFromImageSource(&packOption, imageSource, fd));
}

MIDK_EXPORT
Image_ErrorCode OH_ImagePackerNative_PackToFileFromPixelmap(OH_ImagePackerNative *imagePacker,
    OH_PackingOptions *options, OH_PixelmapNative *pixelmap, int32_t fd)
{
    if (imagePacker == nullptr || options == nullptr || pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    PackOption packOption;
    Image_ErrorCode errorCode = CopyPackingOptions(options, packOption);
    if (errorCode != IMAGE_SUCCESS) {
        return errorCode;
    }
    return ToNewErrorCode(imagePacker->PackToFileFromPixelmap(&packOption, pixelmap, fd));
}

MIDK_EXPORT
Image_ErrorCode OH_ImagePacker_PackToFileMultiFrames(OH_ImagePackerNative *imagePacker, OH_PackingOptions *options,
    OH_PixelmapNative **pixelmaps, int32_t mapSize, int32_t fd)
{
    if (imagePacker == nullptr || options == nullptr || pixelmaps == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    std::vector<OH_PixelmapNative*> pixelmap;
    PackOption packOption;
    std::string format(options->mimeType.data, options->mimeType.size);
    packOption.format = format;
    packOption.quality = options->quality;
    packOption.desiredDynamicRange = ParseDynamicRange(options->desiredDynamicRange);
    packOption.loop = options->loop;

    for (uint32_t i = 0; i < options->delayTimesSize; i++) {
        packOption.delayTimes.push_back(options->delayTimes[i]);
    }
    for (uint32_t i = 0; i < options->disposalTypesSize; i++) {
        packOption.disposalTypes.push_back(options->disposalTypes[i]);
    }
    for (int i = 0; i < mapSize; i++) {
        pixelmap.push_back(pixelmaps[i]);
    }
    return ToNewErrorCode(imagePacker->PackToFileMultiFrames(&packOption, pixelmap, fd));
}

MIDK_EXPORT
Image_ErrorCode OH_ImagePackerNative_PackToFileFromPicture(OH_ImagePackerNative *imagePacker,
    OH_PackingOptions *options, OH_PictureNative *picture, int32_t fd)
{
    if (imagePacker == nullptr || options == nullptr || picture == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    PackOption packOption;
    Image_ErrorCode errorCode = CopyPackingOptions(options, packOption);
    if (errorCode != IMAGE_SUCCESS) {
        return errorCode;
    }
    return ToNewErrorCode(imagePacker->PackToFileFromPicture(&packOption, picture, fd));
}

MIDK_EXPORT
Image_ErrorCode OH_ImagePackerNative_Release(OH_ImagePackerNative *imagePacker)
{
    if (imagePacker == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete imagePacker;
    return IMAGE_SUCCESS;
}

#ifdef __cplusplus
};
#endif