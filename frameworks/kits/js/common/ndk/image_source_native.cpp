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

#include "common_utils.h"
#include "image_source.h"
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

struct OH_DecodingOptions {
    int32_t pixelFormat;
    uint32_t index;
    uint32_t sampleSize;
    uint32_t rotate;
    struct Image_Size desiredSize;
    struct Image_Region desiredRegion;
    int32_t desiredDynamicRange = IMAGE_DYNAMIC_RANGE_SDR;
};

struct OH_ImageSource_Info {
    /** Image width, in pixels. */
    int32_t width;
    /** Image height, in pixels. */
    int32_t height;
    /** Image dynamicRange*/
    bool isHdr;
};

static DecodeDynamicRange ParseImageDynamicRange(int32_t val)
{
    if (val <= static_cast<int32_t>(DecodeDynamicRange::HDR)) {
        return DecodeDynamicRange(val);
    }

    return DecodeDynamicRange::SDR;
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
Image_ErrorCode OH_ImageSourceInfo_Release(OH_ImageSource_Info *info)
{
    if (info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete info;
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
    decOps.desiredRegion.left = static_cast<int32_t>(ops->desiredRegion.x);
    decOps.desiredRegion.top = static_cast<int32_t>(ops->desiredRegion.y);
    decOps.desiredRegion.width = static_cast<int32_t>(ops->desiredRegion.width);
    decOps.desiredRegion.height = static_cast<int32_t>(ops->desiredRegion.height);
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
}

static void ParseImageSourceInfo(struct OH_ImageSource_Info *source, ImageInfo &info)
{
    source->width = info.size.width;
    source->height = info.size.height;
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

MIDK_EXPORT
Image_ErrorCode OH_ImageSourceNative_CreateFromData(uint8_t *data, size_t dataSize, OH_ImageSourceNative **res)
{
    if (data == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    SourceOptions options;
    auto imageSource = new OH_ImageSourceNative(data, dataSize, options);
    if (imageSource == nullptr || imageSource->GetInnerImageSource() == nullptr) {
        if (imageSource) {
            delete imageSource;
        }
        *res = nullptr;
        return IMAGE_BAD_PARAMETER;
    }
    imageSource->fileBuffer_ = (void*)data;
    imageSource->fileBufferSize_ = dataSize;
    *res = imageSource;
    return IMAGE_SUCCESS;
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
    if (source == nullptr || ops == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    DecodeOptions decOps;
    uint32_t index = DEFAULT_INDEX;
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    ParseDecodingOps(decOps, ops);
    index = ops->index;
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
Image_ErrorCode OH_ImageSourceNative_CreatePixelmapList(OH_ImageSourceNative *source, OH_DecodingOptions *ops,
    OH_PixelmapNative *resVecPixMap[], size_t outSize)
{
    if (source == nullptr || ops == nullptr || resVecPixMap == nullptr || outSize <= SIZE_ZERO) {
        return IMAGE_BAD_PARAMETER;
    }
    DecodeOptions decOps;
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    if (ops != nullptr) {
        ParseDecodingOps(decOps, ops);
    }
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
    memcpy_s(value->data, value->size, val.c_str(), val.size());
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
#ifdef __cplusplus
};
#endif