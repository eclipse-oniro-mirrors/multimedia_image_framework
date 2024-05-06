/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "image_source_mdk_kits.h"
#include <map>
#include "image_log.h"
#include "media_errors.h"
#include "securec.h"
#include "image_dfx.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSourceMdk"

namespace {
    constexpr size_t SIZE_ZERO = 0;
    constexpr int32_t INVALID_FD = -1;
    constexpr uint32_t DEFAULT_INDEX = 0;
    constexpr uint32_t INVALID_SAMPLE_SIZE = 0;
    constexpr int8_t INT8_TRUE = 1;
}

namespace OHOS {
namespace Media {
using ImageSourceNapiFunc = int32_t (*)(struct ImageSourceArgs* args);
#ifdef __cplusplus
extern "C" {
#endif

static ImageSource* GetNativeImageSource(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->napi == nullptr || args->napi->nativeImgSrc == nullptr) {
        return nullptr;
    }
    return args->napi->nativeImgSrc.get();
}

static void ParseImageSourceOps(SourceOptions &opts, struct OhosImageSourceOps* ops)
{
    opts.baseDensity = ops->density;
    opts.pixelFormat = static_cast<PixelFormat>(ops->pixelFormat);
    opts.size.width = ops->size.width;
    opts.size.height = ops->size.height;
}

static void ParseDecodingOps(DecodeOptions &decOps, struct OhosImageDecodingOps* ops)
{
    if (ops->sampleSize != INVALID_SAMPLE_SIZE) {
        decOps.sampleSize = ops->sampleSize;
    }
    decOps.rotateNewDegrees = ops->rotate;
    decOps.editable = (ops->editable == INT8_TRUE);
    decOps.desiredSize.width = ops->size.width;
    decOps.desiredSize.height = ops->size.height;
    decOps.desiredRegion.left = ops->region.x;
    decOps.desiredRegion.top = ops->region.y;
    decOps.desiredRegion.width = ops->region.width;
    decOps.desiredRegion.height = ops->region.height;
    if (ops->pixelFormat <= static_cast<int32_t>(PixelFormat::CMYK)) {
        decOps.desiredPixelFormat = PixelFormat(ops->pixelFormat);
    }
    decOps.fitDensity = ops->fitDensity;
}

static void ParseImageSourceInfo(struct OhosImageSourceInfo* source, ImageInfo &info)
{
    source->alphaType = static_cast<int32_t>(info.alphaType);
    source->colorSpace = static_cast<int32_t>(info.colorSpace);
    source->density = info.baseDensity;
    source->pixelFormat = static_cast<int32_t>(info.pixelFormat);
    source->size.width = info.size.width;
    source->size.height = info.size.height;
}

static std::string UrlToPath(const std::string &path)
{
    const std::string filePrefix = "file://";
    if (path.size() > filePrefix.size() &&
        (path.compare(0, filePrefix.size(), filePrefix) == 0)) {
        return path.substr(filePrefix.size());
    }
    return path;
}

static ImageSourceNapi* UnwrapNativeObject(napi_env env, napi_value value)
{
    napi_valuetype valueType;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_object) {
        IMAGE_LOGE("UnwrapNativeObject value not a object");
        return nullptr;
    }
    std::unique_ptr<ImageSourceNapi> napi = nullptr;
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&napi));
    if ((status == napi_ok) && napi != nullptr) {
        return napi.release();
    }
    IMAGE_LOGE("UnwrapNativeObject unwrap error");
    return nullptr;
}

static int32_t ImageSourceNativeCreate(struct OhosImageSource* source,
    struct OhosImageSourceOps* ops, std::shared_ptr<ImageSource> &result, ImageResource &resource)
{
    if (source == nullptr) {
        IMAGE_LOGE("ImageSourceNativeCreate source nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    SourceOptions opts;
    if (ops != nullptr) {
        ParseImageSourceOps(opts, ops);
    }
    std::unique_ptr<ImageSource> nativeImageSource = nullptr;
    if (source->uri != nullptr && source->uriSize != SIZE_ZERO) {
        IMAGE_LOGD("ImageSourceNativeCreate by path");
        std::string url(source->uri, source->uriSize);
        IMAGE_LOGD("ImageSourceNativeCreate by path %{public}s", url.c_str());
        auto path = UrlToPath(url);
        nativeImageSource = ImageSource::CreateImageSource(path, opts, errorCode);
        resource.type = ImageResourceType::IMAGE_RESOURCE_PATH;
        resource.path = path;
    } else if (source->fd != INVALID_FD) {
        IMAGE_LOGD("ImageSourceNativeCreate by fd");
        nativeImageSource = ImageSource::CreateImageSource(source->fd, opts, errorCode);
        resource.type = ImageResourceType::IMAGE_RESOURCE_FD;
        resource.fd = source->fd;
    } else if (source->buffer != nullptr && source->bufferSize != SIZE_ZERO) {
        IMAGE_LOGD("ImageSourceNativeCreate by buffer");
        nativeImageSource = ImageSource::CreateImageSource(source->buffer,
            source->bufferSize, opts, errorCode);
        resource.type = ImageResourceType::IMAGE_RESOURCE_BUFFER;
        resource.buffer = source->buffer;
        resource.bufferSize = source->bufferSize;
    }
    if (nativeImageSource != nullptr) {
        result = std::move(nativeImageSource);
        IMAGE_LOGD("ImageSourceNativeCreate success");
        return IMAGE_RESULT_SUCCESS;
    }
    IMAGE_LOGE("ImageSourceNativeCreate no match source");
    return IMAGE_RESULT_BAD_PARAMETER;
}

static int32_t ImageSourceCreateNapi(napi_env env, napi_value* res,
    std::shared_ptr<ImageSource> imageSource,
    std::shared_ptr<IncrementalPixelMap> incrementalPixelMap, ImageResource* resource)
{
    if (ImageSourceNapi::CreateImageSourceNapi(env, res) != SUCCESS) {
        IMAGE_LOGE("ImageSourceCreateNapi napi create failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    auto napi = UnwrapNativeObject(env, *(res));
    if (napi == nullptr) {
        IMAGE_LOGE("ImageSourceCreateNapi napi unwrap check failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }

    if (imageSource != nullptr) {
        napi->SetNativeImageSource(imageSource);
    }
    if (incrementalPixelMap != nullptr) {
        napi->SetIncrementalPixelMap(incrementalPixelMap);
    }
    if (resource != nullptr) {
        napi->SetImageResource(*resource);
    }
    IMAGE_LOGD("ImageSourceCreateNapi success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreate(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    std::shared_ptr<ImageSource> imageSource = nullptr;
    ImageResource resource;
    ImageSourceNativeCreate(args->source, args->sourceOps, imageSource, resource);
    if (imageSource == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreate native create failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (ImageSourceCreateNapi(args->inEnv, args->outVal, imageSource, nullptr, &resource) != SUCCESS) {
        IMAGE_LOGE("ImageSourceNapiCreate napi create failed");
        args->outVal = nullptr;
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    IMAGE_LOGD("ImageSourceNapiCreate success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreateFromUri(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr || args->uri.empty()) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    SourceOptions opts;
    if (args->sourceOps != nullptr) {
        ParseImageSourceOps(opts, args->sourceOps);
    }
    IMAGE_LOGD("ImageSourceNapiCreateFromUri by path %{public}s", args->uri.c_str());
    auto path = UrlToPath(args->uri);
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    std::unique_ptr<ImageSource> nativeImageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    if (nativeImageSource == nullptr) {
        IMAGE_LOGD("ImageSourceNapiCreateFromUri create failed:%{public}d", errorCode);
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageResource resource;
    resource.type = ImageResourceType::IMAGE_RESOURCE_PATH;
    resource.path = path;
    std::shared_ptr<ImageSource> imageSource = std::move(nativeImageSource);
    if (imageSource == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreateFromUri native create failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (ImageSourceCreateNapi(args->inEnv, args->outVal, imageSource, nullptr, &resource) != SUCCESS) {
        IMAGE_LOGE("ImageSourceNapiCreateFromUri napi create failed");
        args->outVal = nullptr;
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    IMAGE_LOGD("ImageSourceNapiCreateFromUri success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreateFromFd(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr || args->fd == INVALID_FD) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    SourceOptions opts;
    if (args->sourceOps != nullptr) {
        ParseImageSourceOps(opts, args->sourceOps);
    }
    IMAGE_LOGD("ImageSourceNapiCreateFromFd");
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    std::unique_ptr<ImageSource> nativeImageSource = ImageSource::CreateImageSource(args->fd, opts, errorCode);
    if (nativeImageSource == nullptr) {
        IMAGE_LOGD("ImageSourceNapiCreateFromFd create failed:%{public}d", errorCode);
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageResource resource;
    resource.type = ImageResourceType::IMAGE_RESOURCE_FD;
    resource.fd = args->fd;
    std::shared_ptr<ImageSource> imageSource = std::move(nativeImageSource);
    if (imageSource == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreateFromFd native create failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (ImageSourceCreateNapi(args->inEnv, args->outVal, imageSource, nullptr, &resource) != SUCCESS) {
        IMAGE_LOGE("ImageSourceNapiCreateFromFd napi create failed");
        args->outVal = nullptr;
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    IMAGE_LOGD("ImageSourceNapiCreateFromFd success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreateFromData(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr ||
        args->dataArray.data == nullptr || args->dataArray.dataSize == SIZE_ZERO) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    SourceOptions opts;
    if (args->sourceOps != nullptr) {
        ParseImageSourceOps(opts, args->sourceOps);
    }
    IMAGE_LOGD("ImageSourceNapiCreateFromData");
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    std::unique_ptr<ImageSource> nativeImageSource = ImageSource::CreateImageSource(
        args->dataArray.data, args->dataArray.dataSize, opts, errorCode);
    if (nativeImageSource == nullptr) {
        IMAGE_LOGD("ImageSourceNapiCreateFromData create failed:%{public}d", errorCode);
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageResource resource;
    resource.type = ImageResourceType::IMAGE_RESOURCE_BUFFER;
    resource.buffer = args->dataArray.data;
    resource.bufferSize = args->dataArray.dataSize;
    std::shared_ptr<ImageSource> imageSource = std::move(nativeImageSource);
    if (imageSource == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreateFromData native create failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (ImageSourceCreateNapi(args->inEnv, args->outVal, imageSource, nullptr, &resource) != SUCCESS) {
        IMAGE_LOGE("ImageSourceNapiCreateFromData napi create failed");
        args->outVal = nullptr;
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    IMAGE_LOGD("ImageSourceNapiCreateFromData success");
    return IMAGE_RESULT_SUCCESS;
}

static bool isValidRawFile(RawFileDescriptor &rawFile)
{
    return rawFile.fd != INVALID_FD && rawFile.start >= static_cast<long>(SIZE_ZERO) &&
        rawFile.length > static_cast<long>(SIZE_ZERO);
}

static int32_t ImageSourceNapiCreateFromRawFile(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr || !isValidRawFile(args->rawFile)) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    SourceOptions opts;
    if (args->sourceOps != nullptr) {
        ParseImageSourceOps(opts, args->sourceOps);
    }
    RawFileDescriptor rawFile = args->rawFile;
    IMAGE_LOGD("ImageSourceNapiCreateFromRawFile");
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    int32_t rawFileLength = rawFile.start + rawFile.length;
    std::unique_ptr<ImageSource> nativeImageSource = ImageSource::CreateImageSource(
        rawFile.fd, rawFile.start, rawFileLength, opts, errorCode);
    if (nativeImageSource == nullptr) {
        IMAGE_LOGD("ImageSourceNapiCreateFromRawFile create failed:%{public}d", errorCode);
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageResource resource;
    resource.type = ImageResourceType::IMAGE_RESOURCE_RAW_FILE;
    resource.fd = rawFile.fd;
    resource.fileStart = rawFile.start;
    resource.fileLength = rawFileLength;
    std::shared_ptr<ImageSource> imageSource = std::move(nativeImageSource);
    if (imageSource == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreateFromRawFile native create failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (ImageSourceCreateNapi(args->inEnv, args->outVal, imageSource, nullptr, &resource) != SUCCESS) {
        IMAGE_LOGE("ImageSourceNapiCreateFromRawFile napi create failed");
        args->outVal = nullptr;
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    IMAGE_LOGD("ImageSourceNapiCreateFromRawFile success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreateIncremental(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreateIncremental args or env is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    IncrementalSourceOptions incOpts;
    if (args->sourceOps != nullptr) {
        IMAGE_LOGD("ImageSourceNapiCreate ParseImageSourceOps");
        ParseImageSourceOps(incOpts.sourceOptions, args->sourceOps);
    }
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreateIncremental native imagesource failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (args->dataArray.data != nullptr && args->dataArray.dataSize > SIZE_ZERO) {
        IMAGE_LOGD("ImageSourceNapiCreateIncremental update dataArray");
        imageSource->UpdateData(args->dataArray.data, args->dataArray.dataSize, false);
    }
    DecodeOptions decodeOpts;
    uint32_t index = DEFAULT_INDEX;
    if (args->decodingOps != nullptr) {
        ParseDecodingOps(decodeOpts, args->decodingOps);
        index = args->decodingOps->index;
    }
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(
        index, decodeOpts, errorCode);
    if (incPixelMap == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreateIncremental native incremental pixelmap failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (ImageSourceCreateNapi(args->inEnv, args->outVal,
        std::move(imageSource), std::move(incPixelMap), nullptr) != SUCCESS) {
        IMAGE_LOGE("ImageSourceNapiCreateIncremental napi create failed");
        args->outVal = nullptr;
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    IMAGE_LOGD("ImageSourceNapiCreateIncremental success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiGetSupportedFormats(struct ImageSourceArgs* args)
{
    if (args == nullptr) {
        IMAGE_LOGE("ImageSourceNapiGetSupportedFormats args is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    auto formats = args->outFormats;
    if (formats == nullptr) {
        IMAGE_LOGE("ImageSourceNapiGetSupportedFormats args or napi is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    std::set<std::string> formatSet;
    uint32_t errorCode = ImageSource::GetSupportedFormats(formatSet);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("ImageSourceNapiGetSupportedFormats native failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }

    size_t formatCount = formatSet.size();
    if (formats->supportedFormatList == nullptr) {
        formats->size = formatCount;
        IMAGE_LOGD("ImageSourceNapiGetSupportedFormats get count only Success");
        return IMAGE_RESULT_SUCCESS;
    } else {
        formatCount = formats->size;
    }

    auto formatList = formats->supportedFormatList;
    size_t i = 0;
    for (const std::string& formatStr: formatSet) {
        if (i >= formatCount) {
            break;
        }
        if (formatList[i] == nullptr || formatList[i]->format == nullptr) {
            IMAGE_LOGD("ImageSourceNapiGetSupportedFormats nullptr format out buffer");
            return IMAGE_RESULT_BAD_PARAMETER;
        }
        memcpy_s(formatList[i]->format, formatList[i]->size, formatStr.c_str(), formatStr.size());
        if (formatList[i]->size > formatStr.size()) {
            formatList[i]->size = formatStr.size();
        }
        i++;
    }
    IMAGE_LOGD("ImageSourceNapiGetSupportedFormats Success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiUnwrap(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr || args->inVal == nullptr) {
        IMAGE_LOGE("ImageSourceNapiUnwrap args or env is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    args->napi = UnwrapNativeObject(args->inEnv, args->inVal);
    if (args->napi == nullptr) {
        IMAGE_LOGE("ImageSourceNapiUnwrap UnwrapNativeObject failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreatePixelmap(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr || args->inEnv == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreatePixelmap args or napi is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    std::shared_ptr<PixelMap> nativePixelMap = args->napi->GetIncrementalPixelMap();
    if (nativePixelMap == nullptr) {
        DecodeOptions decOps;
        uint32_t index = DEFAULT_INDEX;
        uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
        if (args->decodingOps != nullptr) {
            ParseDecodingOps(decOps, args->decodingOps);
            index = args->decodingOps->index;
        }
        decOps.desiredDynamicRange = DecodeDynamicRange::SDR;
        IMAGE_LOGD("ImageSourceNapiCreatePixelmap CreatePixelMapEx");
        decOps.invokeType = C_INTERFACE;
        auto tmpPixelmap = native->CreatePixelMapEx(index, decOps, errorCode);
        if (tmpPixelmap != nullptr) {
            nativePixelMap = std::move(tmpPixelmap);
        }
    }
    if (nativePixelMap == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreatePixelmap native failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    *(args->outVal) = PixelMapNapi::CreatePixelMap(args->inEnv, nativePixelMap);
    if (*(args->outVal) == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreatePixelmap create pixelmap failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    IMAGE_LOGD("ImageSourceNapiCreatePixelmap Success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreatePixelmapList(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr || args->inEnv == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreatePixelmapList args or napi is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    DecodeOptions decOps;
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    if (args->decodingOps != nullptr) {
        ParseDecodingOps(decOps, args->decodingOps);
    }
    decOps.desiredDynamicRange = DecodeDynamicRange::SDR;
    decOps.invokeType = C_INTERFACE;
    auto pixelMapList = native->CreatePixelMapList(decOps, errorCode);
    if (pixelMapList == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreatePixelmapList CreatePixelMapList failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    napi_create_array(args->inEnv, args->outVal);
    size_t i = DEFAULT_INDEX;
    for (auto &item : *pixelMapList) {
        auto napiPixelMap = PixelMapNapi::CreatePixelMap(args->inEnv, std::move(item));
        napi_set_element(args->inEnv, *(args->outVal), i, napiPixelMap);
        i++;
    }
    IMAGE_LOGD("ImageSourceNapiCreatePixelmapList Success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiGetDelayTime(struct ImageSourceArgs* args) __attribute__((no_sanitize("cfi")))
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr || args->outDelayTimes == nullptr) {
        IMAGE_LOGE("ImageSourceNapiGetDelayTime native image or out is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    auto outDelayTimes = args->outDelayTimes;
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    auto delayTimes = native->GetDelayTime(errorCode);
    if (delayTimes == nullptr) {
        IMAGE_LOGE("ImageSourceNapiGetDelayTime native failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    size_t actCount = (*delayTimes).size();
    if (outDelayTimes->delayTimeList == nullptr) {
        IMAGE_LOGE("ImageSourceNapiGetDelayTime get times count only");
        outDelayTimes->size = actCount;
        return IMAGE_RESULT_SUCCESS;
    }
    if (actCount > outDelayTimes->size) {
        actCount = outDelayTimes->size;
    }
    for (size_t i = SIZE_ZERO; i < actCount; i++) {
        outDelayTimes->delayTimeList[i] = (*delayTimes)[i];
    }
    IMAGE_LOGD("ImageSourceNapiGetDelayTime Success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiGetFrameCount(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr || args->outUint32 == nullptr) {
        IMAGE_LOGE("ImageSourceNapiGetFrameCount native image or out is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    *(args->outUint32) = native->GetFrameCount(errorCode);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("ImageSourceNapiGetFrameCount native failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    IMAGE_LOGD("ImageSourceNapiGetFrameCount Success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiGetImageInfo(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr) {
        IMAGE_LOGE("ImageSourceNapiGetImageInfo native image is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    auto imageSourceInfo = args->outInfo;
    if (imageSourceInfo == nullptr) {
        IMAGE_LOGE("ImageSourceNapiGetImageInfo image info is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageInfo imageInfo;
    uint32_t errorCode = native->GetImageInfo(args->inInt32, imageInfo);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("ImageSourceNapiGetImageInfo native failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ParseImageSourceInfo(imageSourceInfo, imageInfo);
    IMAGE_LOGD("ImageSourceNapiGetImageInfo Success");
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiGetImageProperty(
    struct ImageSourceArgs* args) __attribute__((no_sanitize("cfi")))
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr) {
        IMAGE_LOGE("ImageSourceNapiGetImageProperty native image is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    auto propertyKey = args->inPropertyKey;
    auto propertyVal = args->propertyVal;
    if (propertyKey == nullptr || propertyKey->value == nullptr || propertyKey->size == SIZE_ZERO) {
        IMAGE_LOGE("ImageSourceNapiGetImageProperty key is empty");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (propertyVal == nullptr) {
        IMAGE_LOGE("ImageSourceNapiGetImageProperty out val is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    std::string key(propertyKey->value, propertyKey->size);
    std::string val;
    uint32_t errorCode = native->GetImagePropertyString(DEFAULT_INDEX, key, val);
    if (errorCode != SUCCESS || val.empty()) {
        IMAGE_LOGE("ImageSourceNapiGetImageProperty native failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (propertyVal->value == nullptr) {
        IMAGE_LOGD("ImageSourceNapiGetImageProperty return size only");
        propertyVal->size = val.size();
        return IMAGE_RESULT_SUCCESS;
    }
    memcpy_s(propertyVal->value, propertyVal->size, val.c_str(), val.size());
    if (propertyVal->size > val.size()) {
        propertyVal->size = val.size();
    }
    IMAGE_LOGD("ImageSourceNapiGetImageProperty Success");
    return IMAGE_RESULT_SUCCESS;
}

static uint32_t NativePropertyModify(ImageSource* native, ImageResource &imageResource,
    std::string &key, std::string &val)
{
    auto type = imageResource.type;
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    if (type == ImageResourceType::IMAGE_RESOURCE_INVAILD) {
        IMAGE_LOGE("NativePropertyModify resource is invaild");
        return IMAGE_RESULT_BAD_PARAMETER;
    } else if (type == ImageResourceType::IMAGE_RESOURCE_FD && imageResource.fd != INVALID_FD) {
        IMAGE_LOGD("NativePropertyModify fd resource");
        errorCode = native->ModifyImageProperty(DEFAULT_INDEX, key, val, imageResource.fd);
    } else if (type == ImageResourceType::IMAGE_RESOURCE_PATH && !imageResource.path.empty()) {
        IMAGE_LOGD("NativePropertyModify path resource");
        errorCode = native->ModifyImageProperty(DEFAULT_INDEX, key, val, imageResource.path);
    } else if (type == ImageResourceType::IMAGE_RESOURCE_BUFFER &&
        imageResource.buffer != nullptr && imageResource.bufferSize > SIZE_ZERO) {
        IMAGE_LOGD("NativePropertyModify buffer resource");
        errorCode = native->ModifyImageProperty(DEFAULT_INDEX, key, val,
            imageResource.buffer, imageResource.bufferSize);
    } else {
        IMAGE_LOGE("NativePropertyModify %{public}d resource error", type);
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (errorCode == SUCCESS) {
        IMAGE_LOGD("NativePropertyModify Success");
        return IMAGE_RESULT_SUCCESS;
    }
    IMAGE_LOGE("NativePropertyModify native failed");
    return IMAGE_RESULT_BAD_PARAMETER;
}

static int32_t ImageSourceNapiModifyImageProperty(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr) {
        IMAGE_LOGE("ImageSourceNapiModifyImageProperty native image is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    auto propertyKey = args->inPropertyKey;
    auto propertyVal = args->propertyVal;
    if (propertyKey == nullptr || propertyKey->value == nullptr || propertyKey->size == SIZE_ZERO) {
        IMAGE_LOGE("ImageSourceNapiModifyImageProperty key is empty");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    if (propertyVal == nullptr || propertyVal->value == nullptr || propertyVal->size == SIZE_ZERO) {
        IMAGE_LOGE("ImageSourceNapiModifyImageProperty val is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    std::string key(propertyKey->value, propertyKey->size);
    std::string val(propertyVal->value, propertyVal->size);
    auto imageResource = args->napi->GetImageResource();
    auto res = NativePropertyModify(native, imageResource, key, val);
    return res;
}

static int32_t ProcessIncrementalPixelMap(struct ImageSourceArgs* args, bool completed)
{
    auto incPixelMap = args->napi->GetIncrementalPixelMap();
    if (incPixelMap == nullptr) {
        IMAGE_LOGE("ProcessIncrementalPixelMap incremental pixelmap is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    uint8_t tmpProgress = 0;
    uint32_t errCode = incPixelMap->PromoteDecoding(tmpProgress);
    if (completed) {
        incPixelMap->DetachFromDecoding();
    }
    if (errCode != SUCCESS || (errCode == ERR_IMAGE_SOURCE_DATA_INCOMPLETE && !completed)) {
        IMAGE_LOGE("ProcessIncrementalPixelMap promote decoding failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return IMAGE_RESULT_SUCCESS;
}

static uint32_t MathMin(uint32_t a, uint32_t b)
{
    if (a < b) {
        return a;
    }
    return b;
}

static int32_t ImageSourceNapiUpdateData(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr) {
        IMAGE_LOGE("ImageSourceNapiUpdateData native image is nullptr");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    auto data = args->inUpdateData;
    if (data == nullptr || data->buffer == nullptr || data->bufferSize == SIZE_ZERO ||
        data->offset >= data->bufferSize) {
        IMAGE_LOGE("ImageSourceNapiUpdateData update data is empty");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    uint32_t actSize = MathMin((data->bufferSize - data->offset), data->updateLength);
    bool completed = data->isCompleted == INT8_TRUE;
    uint32_t errCode = native->UpdateData((data->buffer + data->offset), actSize, completed);
    if (errCode != SUCCESS) {
        IMAGE_LOGE("ImageSourceNapiUpdateData update native failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return ProcessIncrementalPixelMap(args, completed);
}

static const std::map<int32_t, ImageSourceNapiFunc> g_Functions = {
    {ENV_FUNC_IMAGE_SOURCE_CREATE, ImageSourceNapiCreate},
    {ENV_FUNC_IMAGE_SOURCE_CREATE_FROM_URI, ImageSourceNapiCreateFromUri},
    {ENV_FUNC_IMAGE_SOURCE_CREATE_FROM_FD, ImageSourceNapiCreateFromFd},
    {ENV_FUNC_IMAGE_SOURCE_CREATE_FROM_DATA, ImageSourceNapiCreateFromData},
    {ENV_FUNC_IMAGE_SOURCE_CREATE_FROM_RAW_FILE, ImageSourceNapiCreateFromRawFile},
    {ENV_FUNC_IMAGE_SOURCE_CREATE_INCREMENTAL, ImageSourceNapiCreateIncremental},
    {ENV_FUNC_IMAGE_SOURCE_UNWRAP, ImageSourceNapiUnwrap},
    {STA_FUNC_IMAGE_SOURCE_GET_SUPPORTED_FORMATS, ImageSourceNapiGetSupportedFormats},
    {CTX_FUNC_IMAGE_SOURCE_CREATE_PIXELMAP, ImageSourceNapiCreatePixelmap},
    {CTX_FUNC_IMAGE_SOURCE_CREATE_PIXELMAP_LIST, ImageSourceNapiCreatePixelmapList},
    {CTX_FUNC_IMAGE_SOURCE_GET_DELAY_TIME, ImageSourceNapiGetDelayTime},
    {CTX_FUNC_IMAGE_SOURCE_GET_FRAME_COUNT, ImageSourceNapiGetFrameCount},
    {CTX_FUNC_IMAGE_SOURCE_GET_IMAGE_INFO, ImageSourceNapiGetImageInfo},
    {CTX_FUNC_IMAGE_SOURCE_GET_IMAGE_PROPERTY, ImageSourceNapiGetImageProperty},
    {CTX_FUNC_IMAGE_SOURCE_MODIFY_IMAGE_PROPERTY, ImageSourceNapiModifyImageProperty},
    {CTX_FUNC_IMAGE_SOURCE_UPDATE_DATA, ImageSourceNapiUpdateData}
};

MIDK_EXPORT
int32_t ImageSourceNativeCall(int32_t mode, struct ImageSourceArgs* args)
{
    auto funcSearch = g_Functions.find(mode);
    if (funcSearch == g_Functions.end()) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return funcSearch->second(args);
}
#ifdef __cplusplus
};
#endif
}  // namespace Media
}  // namespace OHOS