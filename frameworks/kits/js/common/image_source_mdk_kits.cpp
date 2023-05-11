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
#include "hilog/log.h"
#include "media_errors.h"
#include "securec.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "ImageSourceMdk"};
    constexpr size_t SIZE_ZERO = 0;
    constexpr int32_t INVALID_FD = -1;
    constexpr uint32_t DEFAULT_INDEX = 0;
    constexpr uint32_t INVALID_SAMPLE_SIZE = 0;
    constexpr int8_t INT8_TRUE = 1;
}

namespace OHOS {
namespace Media {
using OHOS::HiviewDFX::HiLog;
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
        HiLog::Error(LABEL, "UnwrapNativeObject value not a object");
        return nullptr;
    }
    std::unique_ptr<ImageSourceNapi> napi = nullptr;
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&napi));
    if ((status == napi_ok) && napi != nullptr) {
        return napi.release();
    }
    HiLog::Error(LABEL, "UnwrapNativeObject unwrap error");
    return nullptr;
}

static int32_t ImageSourceNativeCreate(struct OhosImageSource* source,
    struct OhosImageSourceOps* ops, std::shared_ptr<ImageSource> &result, ImageResource &resource)
{
    if (source == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNativeCreate source nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    SourceOptions opts;
    if (ops != nullptr) {
        ParseImageSourceOps(opts, ops);
    }
    std::unique_ptr<ImageSource> nativeImageSource = nullptr;
    if (source->uri != nullptr && source->uriSize != SIZE_ZERO) {
        HiLog::Debug(LABEL, "ImageSourceNativeCreate by path");
        std::string url(source->uri, source->uriSize);
        HiLog::Debug(LABEL, "ImageSourceNativeCreate by path %{public}s", url.c_str());
        auto path = UrlToPath(url);
        nativeImageSource = ImageSource::CreateImageSource(path, opts, errorCode);
        resource.type = ImageResourceType::IMAGE_RESOURCE_PATH;
        resource.path = path;
    } else if (source->fd != INVALID_FD) {
        HiLog::Debug(LABEL, "ImageSourceNativeCreate by fd");
        nativeImageSource = ImageSource::CreateImageSource(source->fd, opts, errorCode);
        resource.type = ImageResourceType::IMAGE_RESOURCE_FD;
        resource.fd = source->fd;
    } else if (source->buffer != nullptr && source->bufferSize != SIZE_ZERO) {
        HiLog::Debug(LABEL, "ImageSourceNativeCreate by buffer");
        nativeImageSource = ImageSource::CreateImageSource(source->buffer,
            source->bufferSize, opts, errorCode);
        resource.type = ImageResourceType::IMAGE_RESOURCE_BUFFER;
        resource.buffer = source->buffer;
        resource.bufferSize = source->bufferSize;
    }
    if (nativeImageSource != nullptr) {
        result = std::move(nativeImageSource);
        HiLog::Debug(LABEL, "ImageSourceNativeCreate success");
        return OHOS_IMAGE_RESULT_SUCCESS;
    }
    HiLog::Error(LABEL, "ImageSourceNativeCreate no match source");
    return OHOS_IMAGE_RESULT_BAD_PARAMETER;
}

static int32_t ImageSourceCreateNapi(napi_env env, napi_value* res,
    std::shared_ptr<ImageSource> imageSource,
    std::shared_ptr<IncrementalPixelMap> incrementalPixelMap, ImageResource* resource)
{
    if (ImageSourceNapi::CreateImageSourceNapi(env, res) != SUCCESS) {
        HiLog::Error(LABEL, "ImageSourceCreateNapi napi create failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    auto napi = UnwrapNativeObject(env, *(res));
    if (napi == nullptr) {
        HiLog::Error(LABEL, "ImageSourceCreateNapi napi unwrap check failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
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
    HiLog::Debug(LABEL, "ImageSourceCreateNapi success");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreate(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    std::shared_ptr<ImageSource> imageSource = nullptr;
    ImageResource resource;
    ImageSourceNativeCreate(args->source, args->sourceOps, imageSource, resource);
    if (imageSource == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiCreate native create failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    if (ImageSourceCreateNapi(args->inEnv, args->outVal, imageSource, nullptr, &resource) != SUCCESS) {
        HiLog::Error(LABEL, "ImageSourceNapiCreate napi create failed");
        args->outVal = nullptr;
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    HiLog::Debug(LABEL, "ImageSourceNapiCreate success");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreateIncremental(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiCreateIncremental args or env is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    IncrementalSourceOptions incOpts;
    if (args->sourceOps != nullptr) {
        HiLog::Debug(LABEL, "ImageSourceNapiCreate ParseImageSourceOps");
        ParseImageSourceOps(incOpts.sourceOptions, args->sourceOps);
    }
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    if (imageSource == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiCreateIncremental native imagesource failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
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
        HiLog::Error(LABEL, "ImageSourceNapiCreateIncremental native incremental pixelmap failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    if (ImageSourceCreateNapi(args->inEnv, args->outVal,
        std::move(imageSource), std::move(incPixelMap), nullptr) != SUCCESS) {
        HiLog::Error(LABEL, "ImageSourceNapiCreateIncremental napi create failed");
        args->outVal = nullptr;
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    HiLog::Debug(LABEL, "ImageSourceNapiCreateIncremental success");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiGetSupportedFormats(struct ImageSourceArgs* args)
{
    if (args == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetSupportedFormats args is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    auto formats = args->outFormats;
    if (formats == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetSupportedFormats args or napi is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    std::set<std::string> formatSet;
    uint32_t errorCode = ImageSource::GetSupportedFormats(formatSet);
    if (errorCode != SUCCESS) {
        HiLog::Error(LABEL, "ImageSourceNapiGetSupportedFormats native failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    size_t formatCount = formatSet.size();
    if (formats->supportedFormatList == nullptr) {
        formats->size = formatCount;
        HiLog::Debug(LABEL, "ImageSourceNapiGetSupportedFormats get count only Success");
        return OHOS_IMAGE_RESULT_SUCCESS;
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
            HiLog::Debug(LABEL, "ImageSourceNapiGetSupportedFormats nullptr format out buffer");
            return OHOS_IMAGE_RESULT_BAD_PARAMETER;
        }
        memcpy_s(formatList[i]->format, formatList[i]->size, formatStr.c_str(), formatStr.size());
        if (formatList[i]->size > formatStr.size()) {
            formatList[i]->size = formatStr.size();
        }
        i++;
    }
    HiLog::Debug(LABEL, "ImageSourceNapiGetSupportedFormats Success");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiUnwrap(struct ImageSourceArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr || args->inVal == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiUnwrap args or env is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    args->napi = UnwrapNativeObject(args->inEnv, args->inVal);
    if (args->napi == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiUnwrap UnwrapNativeObject failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreatePixelmap(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr || args->inEnv == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiCreatePixelmap args or napi is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
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
        HiLog::Debug(LABEL, "ImageSourceNapiCreatePixelmap CreatePixelMapEx");
        auto tmpPixelmap = native->CreatePixelMapEx(index, decOps, errorCode);
        if (tmpPixelmap != nullptr) {
            nativePixelMap = std::move(tmpPixelmap);
        }
    }
    if (nativePixelMap == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiCreatePixelmap native failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    *(args->outVal) = PixelMapNapi::CreatePixelMap(args->inEnv, nativePixelMap);
    if (*(args->outVal) == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiCreatePixelmap create pixelmap failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    HiLog::Debug(LABEL, "ImageSourceNapiCreatePixelmap Success");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiCreatePixelmapList(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr || args->inEnv == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiCreatePixelmapList args or napi is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    DecodeOptions decOps;
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    if (args->decodingOps != nullptr) {
        ParseDecodingOps(decOps, args->decodingOps);
    }
    auto pixelMapList = native->CreatePixelMapList(decOps, errorCode);
    if (pixelMapList == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiCreatePixelmapList CreatePixelMapList failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    napi_create_array(args->inEnv, args->outVal);
    size_t i = DEFAULT_INDEX;
    for (auto &item : *pixelMapList) {
        auto napiPixelMap = PixelMapNapi::CreatePixelMap(args->inEnv, std::move(item));
        napi_set_element(args->inEnv, *(args->outVal), i, napiPixelMap);
        i++;
    }
    HiLog::Debug(LABEL, "ImageSourceNapiCreatePixelmapList Success");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiGetDelayTime(struct ImageSourceArgs* args) __attribute__((no_sanitize("cfi")))
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr || args->outDelayTimes == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetDelayTime native image or out is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    auto outDelayTimes = args->outDelayTimes;
    if (outDelayTimes == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetDelayTime out delay times is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    auto delayTimes = native->GetDelayTime(errorCode);
    if (delayTimes == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetDelayTime native failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    size_t actCount = (*delayTimes).size();
    if (outDelayTimes->delayTimeList == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetDelayTime get times count only");
        outDelayTimes->size = actCount;
        return OHOS_IMAGE_RESULT_SUCCESS;
    }
    if (actCount > outDelayTimes->size) {
        actCount = outDelayTimes->size;
    }
    for (size_t i = SIZE_ZERO; i < actCount; i++) {
        outDelayTimes->delayTimeList[i] = (*delayTimes)[i];
    }
    HiLog::Debug(LABEL, "ImageSourceNapiGetDelayTime Success");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiGetFrameCount(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr || args->outUint32 == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetFrameCount native image or out is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    *(args->outUint32) = native->GetFrameCount(errorCode);
    if (errorCode != SUCCESS) {
        HiLog::Error(LABEL, "ImageSourceNapiGetFrameCount native failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    HiLog::Debug(LABEL, "ImageSourceNapiGetFrameCount Success");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiGetImageInfo(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetImageInfo native image is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    auto imageSourceInfo = args->outInfo;
    if (imageSourceInfo == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetImageInfo image info is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageInfo imageInfo;
    uint32_t errorCode = native->GetImageInfo(args->inInt32, imageInfo);
    if (errorCode != SUCCESS) {
        HiLog::Error(LABEL, "ImageSourceNapiGetImageInfo native failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    ParseImageSourceInfo(imageSourceInfo, imageInfo);
    HiLog::Debug(LABEL, "ImageSourceNapiGetImageInfo Success");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static int32_t ImageSourceNapiGetImageProperty(
    struct ImageSourceArgs* args) __attribute__((no_sanitize("cfi")))
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetImageProperty native image is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    auto propertyKey = args->inPropertyKey;
    auto propertyVal = args->propertyVal;
    if (propertyKey == nullptr || propertyKey->value == nullptr || propertyKey->size == SIZE_ZERO) {
        HiLog::Error(LABEL, "ImageSourceNapiGetImageProperty key is empty");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    if (propertyVal == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiGetImageProperty out val is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    std::string key(propertyKey->value, propertyKey->size);
    std::string val;
    uint32_t errorCode = native->GetImagePropertyString(DEFAULT_INDEX, key, val);
    if (errorCode != SUCCESS || val.empty()) {
        HiLog::Error(LABEL, "ImageSourceNapiGetImageProperty native failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    if (propertyVal->value == nullptr) {
        HiLog::Debug(LABEL, "ImageSourceNapiGetImageProperty return size only");
        propertyVal->size = val.size();
        return OHOS_IMAGE_RESULT_SUCCESS;
    }
    memcpy_s(propertyVal->value, propertyVal->size, val.c_str(), val.size());
    if (propertyVal->size > val.size()) {
        propertyVal->size = val.size();
    }
    HiLog::Debug(LABEL, "ImageSourceNapiGetImageProperty Success");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

static uint32_t NativePropertyModify(ImageSource* native, ImageResource &imageResource,
    std::string &key, std::string &val)
{
    auto type = imageResource.type;
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    if (type == ImageResourceType::IMAGE_RESOURCE_INVAILD) {
        HiLog::Error(LABEL, "NativePropertyModify resource is invaild");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    } else if (type == ImageResourceType::IMAGE_RESOURCE_FD && imageResource.fd != INVALID_FD) {
        HiLog::Debug(LABEL, "NativePropertyModify fd resource");
        errorCode = native->ModifyImageProperty(DEFAULT_INDEX, key, val, imageResource.fd);
    } else if (type == ImageResourceType::IMAGE_RESOURCE_PATH && !imageResource.path.empty()) {
        HiLog::Debug(LABEL, "NativePropertyModify path resource");
        errorCode = native->ModifyImageProperty(DEFAULT_INDEX, key, val, imageResource.path);
    } else if (type == ImageResourceType::IMAGE_RESOURCE_BUFFER &&
        imageResource.buffer != nullptr && imageResource.bufferSize > SIZE_ZERO) {
        HiLog::Debug(LABEL, "NativePropertyModify buffer resource");
        errorCode = native->ModifyImageProperty(DEFAULT_INDEX, key, val,
            imageResource.buffer, imageResource.bufferSize);
    } else {
        HiLog::Error(LABEL, "NativePropertyModify %{public}d resource error", type);
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    if (errorCode == SUCCESS) {
        HiLog::Debug(LABEL, "NativePropertyModify Success");
        return OHOS_IMAGE_RESULT_SUCCESS;
    }
    HiLog::Error(LABEL, "NativePropertyModify native failed");
    return OHOS_IMAGE_RESULT_BAD_PARAMETER;
}

static int32_t ImageSourceNapiModifyImageProperty(struct ImageSourceArgs* args)
{
    auto native = GetNativeImageSource(args);
    if (native == nullptr) {
        HiLog::Error(LABEL, "ImageSourceNapiModifyImageProperty native image is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    auto propertyKey = args->inPropertyKey;
    auto propertyVal = args->propertyVal;
    if (propertyKey == nullptr || propertyKey->value == nullptr || propertyKey->size == SIZE_ZERO) {
        HiLog::Error(LABEL, "ImageSourceNapiModifyImageProperty key is empty");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    if (propertyVal == nullptr || propertyVal->value == nullptr || propertyVal->size == SIZE_ZERO) {
        HiLog::Error(LABEL, "ImageSourceNapiModifyImageProperty val is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
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
        HiLog::Error(LABEL, "ProcessIncrementalPixelMap incremental pixelmap is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    uint8_t tmpProgress = 0;
    uint32_t errCode = incPixelMap->PromoteDecoding(tmpProgress);
    if (completed) {
        incPixelMap->DetachFromDecoding();
    }
    if (errCode != SUCCESS || (errCode == ERR_IMAGE_SOURCE_DATA_INCOMPLETE && !completed)) {
        HiLog::Error(LABEL, "ProcessIncrementalPixelMap promote decoding failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    return OHOS_IMAGE_RESULT_SUCCESS;
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
        HiLog::Error(LABEL, "ImageSourceNapiUpdateData native image is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    auto data = args->inUpdateData;
    if (data == nullptr || data->buffer == nullptr || data->bufferSize == SIZE_ZERO ||
        data->offset >= data->bufferSize) {
        HiLog::Error(LABEL, "ImageSourceNapiUpdateData update data is empty");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    uint32_t actSize = MathMin((data->bufferSize - data->offset), data->updateLength);
    bool completed = data->isCompleted == INT8_TRUE;
    uint32_t errCode = native->UpdateData((data->buffer + data->offset), actSize, completed);
    if (errCode != SUCCESS) {
        HiLog::Error(LABEL, "ImageSourceNapiUpdateData update native failed");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    return ProcessIncrementalPixelMap(args, completed);
}

static const std::map<int32_t, ImageSourceNapiFunc> g_Functions = {
    {ENV_FUNC_IMAGE_SOURCE_CREATE, ImageSourceNapiCreate},
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
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    return funcSearch->second(args);
}
#ifdef __cplusplus
};
#endif
}  // namespace Media
}  // namespace OHOS