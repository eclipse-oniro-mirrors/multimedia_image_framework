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

#include "image_source_native.h"
#include "jpeg_decoder_yuv.h"
#include "picture_native_impl.h"
#include "common_utils.h"
#include "image_source.h"
#include "image_source_native_impl.h"
#include "image_utils.h"
#include "pixelmap_native_impl.h"
#include "picture_native.h"
#include "media_errors.h"
#include "image_log.h"
#include "native_color_space_manager.h"
#include "ndk_color_space.h"

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

const uint32_t DEFAULT_INDEX = 0;
constexpr size_t SIZE_ZERO = 0;
constexpr uint32_t INVALID_SAMPLE_SIZE = 0;
const int32_t INVALID_FD = -1;
static constexpr int32_t FORMAT_0 = 0;
static constexpr int32_t FORMAT_2 = 2;
static constexpr int32_t FORMAT_3 = 3;
static constexpr int32_t FORMAT_4 = 4;
static constexpr int32_t FORMAT_5 = 5;
static constexpr int32_t FORMAT_6 = 6;
static constexpr int32_t FORMAT_7 = 7;
static constexpr int32_t FORMAT_8 = 8;
static constexpr int32_t FORMAT_9 = 9;
using JpegYuvDecodeError = OHOS::ImagePlugin::JpegYuvDecodeError;
static Image_MimeType *IMAGE_SOURCE_SUPPORTED_FORMATS = nullptr;
static size_t SUPPORTED_FORMATS_SIZE = 0;

struct OH_DecodingOptions {
    int32_t pixelFormat;
    uint32_t index;
    uint32_t sampleSize = INVALID_SAMPLE_SIZE;
    uint32_t rotate;
    struct Image_Size desiredSize;
    struct Image_Region desiredRegion;
    int32_t desiredDynamicRange = IMAGE_DYNAMIC_RANGE_SDR;
    int32_t cropAndScaleStrategy;
    int32_t desiredColorSpace = 0;
    struct Image_Region cropRegion;
    bool isCropRegionSet = false;
};

struct OH_ImageSource_Info {
    /** Image width, in pixels. */
    int32_t width;
    /** Image height, in pixels. */
    int32_t height;
    /** Image dynamicRange*/
    bool isHdr;
    /** Image mime type. */
    Image_MimeType mimeType;
};

static const std::map<int32_t, Image_ErrorCode> ERROR_CODE_MAP = {
    {ERR_IMAGE_INVALID_PARAMETER, Image_ErrorCode::IMAGE_BAD_PARAMETER},
    {COMMON_ERR_INVALID_PARAMETER, Image_ErrorCode::IMAGE_BAD_PARAMETER},
    {JpegYuvDecodeError::JpegYuvDecodeError_InvalidParameter, Image_ErrorCode::IMAGE_BAD_PARAMETER},
    {ERR_IMAGE_SOURCE_DATA, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {ERR_IMAGE_SOURCE_DATA_INCOMPLETE, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {ERR_IMAGE_GET_DATA_ABNORMAL, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {ERR_IMAGE_DATA_ABNORMAL, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {ERROR, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {JpegYuvDecodeError::JpegYuvDecodeError_BadImage, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {ERR_IMAGE_MISMATCHED_FORMAT, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_MIMETYPE},
    {ERR_IMAGE_UNKNOWN_FORMAT, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_MIMETYPE},
    {ERR_IMAGE_DECODE_HEAD_ABNORMAL, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_MIMETYPE},
    {ERR_IMAGE_TOO_LARGE, Image_ErrorCode::IMAGE_SOURCE_TOO_LARGE},
    {ERR_MEDIA_INVALID_OPERATION, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE},
    {IMAGE_RESULT_FORMAT_CONVERT_FAILED, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS},
    {ERR_MEDIA_FORMAT_UNSUPPORT, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS},
    {ERR_IMAGE_PIXELMAP_CREATE_FAILED, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS},
    {JpegYuvDecodeError::JpegYuvDecodeError_ConvertError, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS},
    {ERR_IMAGE_CROP, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS},
    {ERR_IMAGE_DECODE_FAILED, Image_ErrorCode::IMAGE_DECODE_FAILED},
    {ERR_IMAGE_DECODE_ABNORMAL, Image_ErrorCode::IMAGE_DECODE_FAILED},
    {ERR_IMAGE_PLUGIN_CREATE_FAILED, Image_ErrorCode::IMAGE_DECODE_FAILED},
    {JpegYuvDecodeError::JpegYuvDecodeError_DecodeFailed, Image_ErrorCode::IMAGE_DECODE_FAILED},
    {JpegYuvDecodeError::JpegYuvDecodeError_MemoryNotEnoughToSaveResult, Image_ErrorCode::IMAGE_DECODE_FAILED},
    {ERR_IMAGE_MALLOC_ABNORMAL, Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED},
    {ERR_IMAGE_DATA_UNSUPPORT, Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED},
    {ERR_DMA_NOT_EXIST, Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED},
    {ERR_DMA_DATA_ABNORMAL, Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED},
    {ERR_SHAMEM_DATA_ABNORMAL, Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED}
};
static Image_ErrorCode ConvertToErrorCode(int32_t errorCode)
{
    Image_ErrorCode apiErrorCode = Image_ErrorCode::IMAGE_DECODE_FAILED;
    auto iter = ERROR_CODE_MAP.find(errorCode);
    if (iter != ERROR_CODE_MAP.end()) {
        apiErrorCode = iter->second;
    }
    return apiErrorCode;
}

static Image_AuxiliaryPictureType AuxTypeInnerToNative(OHOS::Media::AuxiliaryPictureType type)
{
    return static_cast<Image_AuxiliaryPictureType>(static_cast<int>(type));
}

static OHOS::Media::AuxiliaryPictureType AuxTypeNativeToInner(Image_AuxiliaryPictureType type)
{
    return static_cast<OHOS::Media::AuxiliaryPictureType>(static_cast<int>(type));
}

static DecodeDynamicRange ParseImageDynamicRange(int32_t val)
{
    if (val <= static_cast<int32_t>(DecodeDynamicRange::HDR)) {
        return DecodeDynamicRange(val);
    }

    return DecodeDynamicRange::SDR;
}

static void releaseMimeType(Image_MimeType *mimeType)
{
    if (mimeType->data != nullptr) {
        free(mimeType->data);
        mimeType->data = nullptr;
    }
    mimeType->size = 0;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_Create(OH_DecodingOptions **options)
{
    *options = new OH_DecodingOptions();
    if (*options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_GetPixelFormat(OH_DecodingOptions *options,
    int32_t *pixelFormat)
{
    if (options == nullptr || pixelFormat == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *pixelFormat = options->pixelFormat;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_SetPixelFormat(OH_DecodingOptions *options,
    int32_t pixelFormat)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->pixelFormat = pixelFormat;
    return IMAGE_SUCCESS;
}

static inline bool IsCropStrategyValid(int32_t strategy)
{
    return strategy >= static_cast<int32_t>(CropAndScaleStrategy::SCALE_FIRST) &&
        strategy <= static_cast<int32_t>(CropAndScaleStrategy::CROP_FIRST);
}

Image_ErrorCode OH_DecodingOptions_GetCropAndScaleStrategy(OH_DecodingOptions *options,
    int32_t *cropAndScaleStrategy)
{
    if (options == nullptr || cropAndScaleStrategy == nullptr) {
        IMAGE_LOGE("options or cropAndScaleStrategy is nullptr");
        return IMAGE_BAD_PARAMETER;
    }
    if (!IsCropStrategyValid(options->cropAndScaleStrategy)) {
        IMAGE_LOGE("SetCropAndScaleStrategy was not called or the method call failed");
        return IMAGE_BAD_PARAMETER;
    }
    *cropAndScaleStrategy = options->cropAndScaleStrategy;
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_DecodingOptions_SetCropAndScaleStrategy(OH_DecodingOptions *options,
    int32_t cropAndScaleStrategy)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    if (!IsCropStrategyValid(cropAndScaleStrategy)) {
        IMAGE_LOGE("cropAndScaleStrategy:%{public}d is invalid", cropAndScaleStrategy);
        return IMAGE_BAD_PARAMETER;
    }
    options->cropAndScaleStrategy = cropAndScaleStrategy;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_GetIndex(OH_DecodingOptions *options, uint32_t *index)
{
    if (options == nullptr || index == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *index = options->index;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_SetIndex(OH_DecodingOptions *options, uint32_t index)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->index = index;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_GetRotate(OH_DecodingOptions *options, float *rotate)
{
    if (options == nullptr || rotate == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *rotate = options->rotate;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_SetRotate(OH_DecodingOptions *options, float rotate)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->rotate = rotate;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_GetDesiredSize(OH_DecodingOptions *options,
    Image_Size *desiredSize)
{
    if (options == nullptr || desiredSize == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    desiredSize->width = options->desiredSize.width;
    desiredSize->height = options->desiredSize.height;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_SetDesiredSize(OH_DecodingOptions *options,
    Image_Size *desiredSize)
{
    if (options == nullptr || desiredSize == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->desiredSize.width = desiredSize->width;
    options->desiredSize.height = desiredSize->height;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_GetDesiredRegion(OH_DecodingOptions *options,
    Image_Region *desiredRegion)
{
    if (options == nullptr || desiredRegion == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    desiredRegion->x = options->desiredRegion.x;
    desiredRegion->y = options->desiredRegion.y;
    desiredRegion->width = options->desiredRegion.width;
    desiredRegion->height = options->desiredRegion.height;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_SetDesiredRegion(OH_DecodingOptions *options,
    Image_Region *desiredRegion)
{
    if (options == nullptr || desiredRegion == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->desiredRegion.x = desiredRegion->x;
    options->desiredRegion.y = desiredRegion->y;
    options->desiredRegion.width = desiredRegion->width;
    options->desiredRegion.height = desiredRegion->height;
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_DecodingOptions_GetCropRegion(OH_DecodingOptions *options, Image_Region *cropRegion)
{
    if (options == nullptr || cropRegion == nullptr) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }
    cropRegion->x = options->cropRegion.x;
    cropRegion->y = options->cropRegion.y;
    cropRegion->width = options->cropRegion.width;
    cropRegion->height = options->cropRegion.height;
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_DecodingOptions_SetCropRegion(OH_DecodingOptions *options, Image_Region *cropRegion)
{
    if (options == nullptr || cropRegion == nullptr) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }
    options->cropRegion.x = cropRegion->x;
    options->cropRegion.y = cropRegion->y;
    options->cropRegion.width = cropRegion->width;
    options->cropRegion.height = cropRegion->height;
    options->isCropRegionSet = true;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_GetDesiredDynamicRange(OH_DecodingOptions *options,
    int32_t *desiredDynamicRange)
{
    if (options == nullptr || desiredDynamicRange == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *desiredDynamicRange = options->desiredDynamicRange;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_SetDesiredDynamicRange(OH_DecodingOptions *options,
    int32_t desiredDynamicRange)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->desiredDynamicRange = desiredDynamicRange;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_GetDesiredColorSpace(OH_DecodingOptions *options, int32_t *colorSpace)
{
    if (options == nullptr || colorSpace == nullptr) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }
    *colorSpace = options->desiredColorSpace;
    return IMAGE_SUCCESS;
}

inline static bool IsColorSpaceInvalid(int32_t colorSpace)
{
    return colorSpace <= static_cast<int32_t>(ColorSpaceName::NONE) ||
        colorSpace > static_cast<int32_t>(ColorSpaceName::LINEAR_BT2020) ||
        colorSpace == static_cast<int32_t>(ColorSpaceName::CUSTOM);
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_SetDesiredColorSpace(OH_DecodingOptions *options, int32_t colorSpace)
{
    if (options == nullptr || IsColorSpaceInvalid(colorSpace) ||
        colorSpace == static_cast<int32_t>(ColorSpaceName::CUSTOM)) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }
    options->desiredColorSpace = colorSpace;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptions_Release(OH_DecodingOptions *options)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete options;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceInfo_Create(OH_ImageSource_Info **info)
{
    *info = new OH_ImageSource_Info();
    if (*info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceInfo_GetWidth(OH_ImageSource_Info *info, uint32_t *width)
{
    if (info == nullptr || width == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *width = info->width;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceInfo_GetHeight(OH_ImageSource_Info *info, uint32_t *height)
{
    if (info == nullptr || height == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *height = info->height;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceInfo_GetDynamicRange(OH_ImageSource_Info *info, bool *isHdr)
{
    if (info == nullptr || isHdr == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *isHdr = info->isHdr;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceInfo_GetMimeType(OH_ImageSource_Info *info, Image_MimeType *mimeType)
{
    if (info == nullptr || mimeType == nullptr) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }
    *mimeType = info->mimeType;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceInfo_Release(OH_ImageSource_Info *info)
{
    if (info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    releaseMimeType(&info->mimeType);
    delete info;
    info = nullptr;
    return IMAGE_SUCCESS;
}


std::string OH_ImageSourceNative::UrlToPath(const std::string &path)
{
    const std::string filePrefix = "file://";
    if (path.size() > filePrefix.size() &&
        (path.compare(0, filePrefix.size(), filePrefix) == 0)) {
        return path.substr(filePrefix.size());
    }
    return path;
}

static void ParseDecodingOps(DecodeOptions &decOps, struct OH_DecodingOptions *ops)
{
    if (ops->sampleSize != INVALID_SAMPLE_SIZE) {
        decOps.sampleSize = ops->sampleSize;
    }
    decOps.rotateNewDegrees = ops->rotate;
    decOps.desiredSize.width = static_cast<int32_t>(ops->desiredSize.width);
    decOps.desiredSize.height = static_cast<int32_t>(ops->desiredSize.height);
    if (ops->isCropRegionSet) {
        decOps.CropRect.left = static_cast<int32_t>(ops->cropRegion.x);
        decOps.CropRect.top = static_cast<int32_t>(ops->cropRegion.y);
        decOps.CropRect.width = static_cast<int32_t>(ops->cropRegion.width);
        decOps.CropRect.height = static_cast<int32_t>(ops->cropRegion.height);
    } else if (IsCropStrategyValid(ops->cropAndScaleStrategy)) {
        decOps.CropRect.left = static_cast<int32_t>(ops->desiredRegion.x);
        decOps.CropRect.top = static_cast<int32_t>(ops->desiredRegion.y);
        decOps.CropRect.width = static_cast<int32_t>(ops->desiredRegion.width);
        decOps.CropRect.height = static_cast<int32_t>(ops->desiredRegion.height);
    } else {
        decOps.desiredRegion.left = static_cast<int32_t>(ops->desiredRegion.x);
        decOps.desiredRegion.top = static_cast<int32_t>(ops->desiredRegion.y);
        decOps.desiredRegion.width = static_cast<int32_t>(ops->desiredRegion.width);
        decOps.desiredRegion.height = static_cast<int32_t>(ops->desiredRegion.height);
    }
    decOps.desiredDynamicRange = ParseImageDynamicRange(ops->desiredDynamicRange);
    switch (static_cast<int32_t>(ops->pixelFormat)) {
        case FORMAT_0:
        case FORMAT_2:
        case FORMAT_3:
        case FORMAT_4:
        case FORMAT_5:
        case FORMAT_6:
        case FORMAT_7:
        case FORMAT_8:
        case FORMAT_9:
            decOps.desiredPixelFormat = PixelFormat(ops->pixelFormat);
            break;
        default:
            decOps.desiredPixelFormat = PixelFormat::UNKNOWN;
    }
    if (IsCropStrategyValid(ops->cropAndScaleStrategy)) {
        decOps.cropAndScaleStrategy = static_cast<OHOS::Media::CropAndScaleStrategy>(ops->cropAndScaleStrategy);
    }
    OH_NativeColorSpaceManager* colorSpaceNative =
        OH_NativeColorSpaceManager_CreateFromName(ColorSpaceName(ops->desiredColorSpace));
    if (colorSpaceNative != nullptr) {
        ColorManager::ColorSpace nativeColorspace =
            reinterpret_cast<NativeColorSpaceManager*>(colorSpaceNative)->GetInnerColorSpace();
        decOps.desiredColorSpaceInfo = std::make_shared<OHOS::ColorManager::ColorSpace>(nativeColorspace);
        OH_NativeColorSpaceManager_Destroy(colorSpaceNative);
    } else {
        IMAGE_LOGD("no colorSpace");
    }
}

static void ParseImageSourceInfo(struct OH_ImageSource_Info *source, const ImageInfo &info)
{
    if (source == nullptr) {
        return;
    }
    source->width = info.size.width;
    source->height = info.size.height;
    if (source->mimeType.data != nullptr) {
        return;
    }
    if (info.encodedFormat.empty()) {
        std::string unknownStr = "unknown";
        source->mimeType.data = strdup(unknownStr.c_str());
        source->mimeType.size = unknownStr.size();
        return;
    }
    source->mimeType.size = info.encodedFormat.size();
    source->mimeType.data = static_cast<char *>(malloc(source->mimeType.size));
    if (source->mimeType.data == nullptr) {
        return;
    }
    if (memcpy_s(source->mimeType.data, source->mimeType.size, info.encodedFormat.c_str(),
        info.encodedFormat.size()) != 0) {
        releaseMimeType(&source->mimeType);
    }
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_CreateFromUri(char *uri, size_t uriSize, OH_ImageSourceNative **res)
{
    if (uri == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    SourceOptions options;
    auto imageSource = new OH_ImageSourceNative(uri, uriSize, options);
    if (imageSource == nullptr || imageSource->GetInnerImageSource() == nullptr) {
        if (imageSource) {
            delete imageSource;
        }
        *res = nullptr;
        return IMAGE_BAD_PARAMETER;
    }
    std::string tmp(uri, uriSize);
    if (tmp.empty()) {
        delete imageSource;
        return IMAGE_BAD_PARAMETER;
    }
    imageSource->filePath_ = tmp;
    *res = imageSource;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_CreateFromFd(int32_t fd, OH_ImageSourceNative **res)
{
    SourceOptions options;
    auto imageSource = new OH_ImageSourceNative(fd, options);
    if (imageSource == nullptr || imageSource->GetInnerImageSource() == nullptr) {
        if (imageSource) {
            delete imageSource;
        }
        *res = nullptr;
        return IMAGE_BAD_PARAMETER;
    }
    imageSource->fileDescriptor_ = fd;
    *res = imageSource;
    return IMAGE_SUCCESS;
}

Image_ErrorCode CreateFromDataInternal(uint8_t *data, size_t dataSize, OH_ImageSourceNative **res, bool isUserBuffer)
{
    if (data == nullptr) {
        return isUserBuffer ? IMAGE_SOURCE_INVALID_PARAMETER : IMAGE_BAD_PARAMETER;
    }
    SourceOptions options;
    auto imageSource = new OH_ImageSourceNative(data, dataSize, options, isUserBuffer);
    if (imageSource == nullptr || imageSource->GetInnerImageSource() == nullptr) {
        if (imageSource) {
            delete imageSource;
        }
        *res = nullptr;
        return isUserBuffer ? IMAGE_SOURCE_INVALID_PARAMETER : IMAGE_BAD_PARAMETER;
    }
    imageSource->fileBuffer_ = reinterpret_cast<void*>(data);
    imageSource->fileBufferSize_ = dataSize;
    *res = imageSource;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_CreateFromData(uint8_t *data, size_t dataSize, OH_ImageSourceNative **res)
{
    return CreateFromDataInternal(data, dataSize, res, false);
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_CreateFromDataWithUserBuffer(uint8_t *data, size_t datalength,
                                                                  OH_ImageSourceNative **imageSource)
{
    return CreateFromDataInternal(data, datalength, imageSource, true);
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_CreateFromRawFile(RawFileDescriptor *rawFile, OH_ImageSourceNative **res)
{
    if (rawFile == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    SourceOptions options;
    auto imageSource = new OH_ImageSourceNative(*rawFile, options);
    if (imageSource == nullptr || imageSource->GetInnerImageSource() == nullptr) {
        if (imageSource) {
            delete imageSource;
        }
        *res = nullptr;
        return IMAGE_BAD_PARAMETER;
    }
    *res = imageSource;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_CreatePixelmap(OH_ImageSourceNative *source, OH_DecodingOptions *ops,
    OH_PixelmapNative **pixelmap)
{
    if (source == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    DecodeOptions decOps;
    uint32_t index = DEFAULT_INDEX;
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    if (ops != nullptr) {
        ParseDecodingOps(decOps, ops);
        index = ops->index;
    } else {
        OH_DecodingOptions localOps{};
        ParseDecodingOps(decOps, &localOps);
    }
    std::unique_ptr<PixelMap> tmpPixelmap = source->GetInnerImageSource()->CreatePixelMapEx(index, decOps, errorCode);
    if (tmpPixelmap == nullptr || errorCode != IMAGE_SUCCESS) {
        return IMAGE_UNSUPPORTED_OPERATION;
    }
    std::shared_ptr<PixelMap> nativePixelmap = std::move(tmpPixelmap);
    OH_PixelmapNative *stPixMap = new OH_PixelmapNative(nativePixelmap);
    *pixelmap = stPixMap;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_CreatePixelmapUsingAllocator(OH_ImageSourceNative *source, OH_DecodingOptions *ops,
    IMAGE_ALLOCATOR_TYPE allocator, OH_PixelmapNative **pixelmap)
{
    if (source == nullptr || ops == nullptr || pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    DecodeOptions decOps;
    uint32_t index = DEFAULT_INDEX;
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    ParseDecodingOps(decOps, ops);
    index = ops->index;
    if (source->GetInnerImageSource() == nullptr) {
        return IMAGE_BAD_SOURCE;
    }
    if (!source->GetInnerImageSource()->IsSupportAllocatorType(decOps, static_cast<int32_t>(allocator))) {
        return IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE;
    }
    std::unique_ptr<PixelMap> tmpPixelmap = source->GetInnerImageSource()->CreatePixelMapEx(index, decOps, errorCode);
    if (tmpPixelmap == nullptr || errorCode != IMAGE_SUCCESS) {
        return ConvertToErrorCode(errorCode);
    }
    std::shared_ptr<PixelMap> nativePixelmap = std::move(tmpPixelmap);
    OH_PixelmapNative *stPixMap = new OH_PixelmapNative(nativePixelmap);
    *pixelmap = stPixMap;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_CreatePixelmapList(OH_ImageSourceNative *source, OH_DecodingOptions *ops,
    OH_PixelmapNative *resVecPixMap[], size_t outSize)
{
    if (source == nullptr || ops == nullptr || resVecPixMap == nullptr || outSize == SIZE_ZERO) {
        return IMAGE_BAD_PARAMETER;
    }
    DecodeOptions decOps;
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    ParseDecodingOps(decOps, ops);

    auto pixelmapList = source->GetInnerImageSource()->CreatePixelMapList(decOps, errorCode);
    if (pixelmapList == nullptr || errorCode != IMAGE_SUCCESS) {
        return IMAGE_BAD_PARAMETER;
    }
    if (outSize < (*pixelmapList).size()) {
        return IMAGE_BAD_PARAMETER;
    }
    size_t index = 0;
    for (auto &item : *pixelmapList) {
        std::shared_ptr<PixelMap> tempPixMap = std::move(item);
        OH_PixelmapNative *stPixMap = new OH_PixelmapNative(tempPixMap);
        resVecPixMap[index] = stPixMap;
        index ++;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_CreatePicture(OH_ImageSourceNative *source, OH_DecodingOptionsForPicture *options,
    OH_PictureNative **picture)
{
    if (source == nullptr || !source->GetInnerImageSource() || options == nullptr
        || picture == nullptr || !options->GetInnerDecodingOptForPicture()) {
        return IMAGE_BAD_PARAMETER;
    }

    auto innerDecodingOptionsForPicture = options->GetInnerDecodingOptForPicture().get();
    uint32_t errorCode;
    auto pictureTemp = source->GetInnerImageSource()->CreatePicture(*innerDecodingOptionsForPicture, errorCode);
    if (errorCode != SUCCESS) {
        return IMAGE_DECODE_FAILED;
    }
    
    auto pictureNative  = new OH_PictureNative(std::move(pictureTemp));
    *picture = pictureNative;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_GetDelayTimeList(OH_ImageSourceNative *source, int32_t *delayTimeList, size_t size)
{
    if (source == nullptr || delayTimeList == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    uint32_t errorCode = IMAGE_SUCCESS;
    auto delayTimes = source->GetInnerImageSource()->GetDelayTime(errorCode);
    if (delayTimes == nullptr || errorCode != IMAGE_SUCCESS) {
        return IMAGE_BAD_PARAMETER;
    }
    size_t actCount = (*delayTimes).size();
    if (size < actCount) {
        return IMAGE_BAD_PARAMETER;
    }
    for (size_t i = SIZE_ZERO; i < actCount; i++) {
        delayTimeList[i] = (*delayTimes)[i];
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_GetImageInfo(OH_ImageSourceNative *source, int32_t index,
    struct OH_ImageSource_Info *info)
{
    if (source == nullptr || info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    ImageInfo imageInfo;
    uint32_t errorCode = source->GetInnerImageSource()->GetImageInfo(index, imageInfo);
    if (errorCode != IMAGE_SUCCESS) {
        return IMAGE_BAD_PARAMETER;
    }
    ParseImageSourceInfo(info, imageInfo);
    info->isHdr = source->GetInnerImageSource()->IsHdrImage();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_GetImageProperty(OH_ImageSourceNative *source, Image_String *key,
    Image_String *value)
{
    if (source == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    if (key == nullptr || key->data == nullptr || key->size == SIZE_ZERO) {
        return IMAGE_BAD_PARAMETER;
    }
    if (value == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    std::string keyString(key->data, key->size);
    if (keyString.empty()) {
        return IMAGE_BAD_PARAMETER;
    }
    std::string val;
    uint32_t errorCode = source->GetInnerImageSource()->GetImagePropertyString(DEFAULT_INDEX, keyString, val);
    if (errorCode != IMAGE_SUCCESS || val.empty()) {
        return IMAGE_BAD_PARAMETER;
    }

    if (value->size != SIZE_ZERO && value->size < val.size()) {
        return IMAGE_BAD_PARAMETER;
    }
    value->size = (value->size == SIZE_ZERO) ? val.size() : value->size;
    value->data = static_cast<char *>(malloc(value->size));
    if (value->data == nullptr) {
        return IMAGE_ALLOC_FAILED;
    }
    if (EOK != memcpy_s(value->data, value->size, val.c_str(), val.size())) {
        return IMAGE_COPY_FAILED;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_GetImagePropertyWithNull(OH_ImageSourceNative *source, Image_String *key,
    Image_String *value)
{
    if (source == nullptr || key == nullptr || key->data == nullptr || key->size == SIZE_ZERO || value == nullptr) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }

    std::string keyString(key->data, key->size);
    if (keyString.empty()) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }

    std::string val;
    uint32_t errorCode = source->GetInnerImageSource()->GetImagePropertyString(DEFAULT_INDEX, keyString, val);
    if (errorCode != IMAGE_SUCCESS || val.empty()) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }

    if (value->size != SIZE_ZERO && value->size < val.size()) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }

    size_t allocSize = val.size() + 1;
    char* buffer = static_cast<char*>(malloc(allocSize));
    if (buffer == nullptr) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }

    if (EOK != memcpy_s(buffer, allocSize, val.c_str(), val.size())) {
        free(buffer);
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }
    buffer[val.size()] = '\0';

    value->data = buffer;
    value->size = val.size();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_ModifyImageProperty(OH_ImageSourceNative *source, Image_String *key,
    Image_String *value)
{
    if (source == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    if (key == nullptr || key->data == nullptr || key->size == SIZE_ZERO) {
        return IMAGE_BAD_PARAMETER;
    }
    if (value == nullptr || value->data == nullptr || value->size == SIZE_ZERO) {
        return IMAGE_BAD_PARAMETER;
    }

    std::string keyStr(key->data, key->size);
    if (keyStr.empty()) {
        return IMAGE_BAD_PARAMETER;
    }
    std::string val(value->data, value->size);
    if (val.empty()) {
        return IMAGE_BAD_PARAMETER;
    }
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    if (!(source->filePath_.empty())) {
        errorCode = source->GetInnerImageSource()->ModifyImageProperty(DEFAULT_INDEX, keyStr, val, source->filePath_);
    } else if (source->fileDescriptor_ != INVALID_FD) {
        errorCode = source->GetInnerImageSource()->ModifyImageProperty(DEFAULT_INDEX, keyStr, val,
            source->fileDescriptor_);
    } else if (source->fileBuffer_ != nullptr && source->fileBufferSize_ != 0) {
        errorCode = source->GetInnerImageSource()->ModifyImageProperty(DEFAULT_INDEX, keyStr, val,
            static_cast<uint8_t *>(source->fileBuffer_), source->fileBufferSize_);
    } else {
        return IMAGE_BAD_PARAMETER;
    }
    if (errorCode == IMAGE_SUCCESS) {
        return IMAGE_SUCCESS;
    }
    return IMAGE_BAD_PARAMETER;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_GetFrameCount(OH_ImageSourceNative *source, uint32_t *frameCount)
{
    if (source == nullptr || frameCount == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    *frameCount = source->GetInnerImageSource()->GetFrameCount(errorCode);
    if (errorCode != IMAGE_SUCCESS) {
        return IMAGE_BAD_PARAMETER;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_Release(OH_ImageSourceNative *source)
{
    if (source == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    source->~OH_ImageSourceNative();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptionsForPicture_Create(OH_DecodingOptionsForPicture **options)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    auto decodingOptionsForPicture = std::make_shared<OHOS::Media::DecodingOptionsForPicture>();
    *options = new OH_DecodingOptionsForPicture(decodingOptionsForPicture);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptionsForPicture_GetDesiredAuxiliaryPictures(OH_DecodingOptionsForPicture *options,
    Image_AuxiliaryPictureType **desiredAuxiliaryPictures, size_t *length)
{
    if (options == nullptr || !options->GetInnerDecodingOptForPicture() ||
        desiredAuxiliaryPictures == nullptr || length == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    auto innerDecodingSet = options->GetInnerDecodingOptForPicture()->desireAuxiliaryPictures;
    if (innerDecodingSet.size() == 0) {
        return IMAGE_BAD_PARAMETER;
    }
    auto lenTmp = innerDecodingSet.size();
    auto auxTypeArrayUniptr = std::make_unique<Image_AuxiliaryPictureType[]>(lenTmp);
    int index = 0;
    for (auto innerDecoding : innerDecodingSet) {
        auxTypeArrayUniptr[index++] = AuxTypeInnerToNative(innerDecoding);
    }
    *desiredAuxiliaryPictures = auxTypeArrayUniptr.release();
    *length = lenTmp;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptionsForPicture_SetDesiredAuxiliaryPictures(OH_DecodingOptionsForPicture *options,
    Image_AuxiliaryPictureType *desiredAuxiliaryPictures, size_t length)
{
    if (options == nullptr || !options->GetInnerDecodingOptForPicture() ||
        desiredAuxiliaryPictures == nullptr || length <= 0) {
        return IMAGE_BAD_PARAMETER;
    }
    std::set<AuxiliaryPictureType> tmpDesireSet;
    auto innerDecodingOptionsForPicture = options->GetInnerDecodingOptForPicture().get();
    for (size_t index = 0; index < length; index++) {
        auto auxTypeTmp = AuxTypeNativeToInner(desiredAuxiliaryPictures[index]);
        if (!OHOS::Media::ImageUtils::IsAuxiliaryPictureTypeSupported(auxTypeTmp)) {
            return IMAGE_BAD_PARAMETER;
        }
        tmpDesireSet.insert(auxTypeTmp);
    }
    innerDecodingOptionsForPicture->desireAuxiliaryPictures.insert(tmpDesireSet.begin(), tmpDesireSet.end());
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_DecodingOptionsForPicture_Release(OH_DecodingOptionsForPicture *options)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete options;
    options = nullptr;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_GetSupportedFormats(Image_MimeType** supportedFormat, size_t* length)
{
    if (supportedFormat == nullptr || length == nullptr) {
        return IMAGE_SOURCE_INVALID_PARAMETER;
    }
    if (IMAGE_SOURCE_SUPPORTED_FORMATS != nullptr || SUPPORTED_FORMATS_SIZE != 0) {
        *supportedFormat = IMAGE_SOURCE_SUPPORTED_FORMATS;
        *length = SUPPORTED_FORMATS_SIZE;
        return IMAGE_SUCCESS;
    }
    std::set<std::string> formats;
    ImageSource::GetSupportedFormats(formats);
    *length = formats.size();
    *supportedFormat = new Image_MimeType[*length];
    size_t count = 0;
    for (const auto& str : formats) {
        (*supportedFormat)[count].data = strdup(str.c_str());
        if ((*supportedFormat)[count].data == nullptr) {
            IMAGE_LOGE("ImageSource strdup failed");
            continue;
        }
        (*supportedFormat)[count].size = str.size();
        count++;
    }
    IMAGE_SOURCE_SUPPORTED_FORMATS = *supportedFormat;
    SUPPORTED_FORMATS_SIZE = *length;
    return IMAGE_SUCCESS;
}

#ifdef __cplusplus
};
#endif