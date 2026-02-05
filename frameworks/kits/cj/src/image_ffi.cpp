/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "image_ffi.h"

#include <cstdint>

#include "cj_color_manager.h"
#include "cj_lambda.h"
#include "image_common.h"
#include "image_creator_impl.h"
#include "image_log.h"
#include "image_packer_impl.h"
#include "image_receiver_impl.h"
#include "image_source_impl.h"
#include "image_type.h"
#include "media_errors.h"
#include "metadata_impl.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Media {
extern "C" {
//--------------------- ImageSource ------------------------------------------------------------------------
static const std::string FILE_URL_PREFIX = "file://";
static std::string FileUrlToRawPath(const std::string& path)
{
    if (path.size() > FILE_URL_PREFIX.size() && (path.compare(0, FILE_URL_PREFIX.size(), FILE_URL_PREFIX) == 0)) {
        return path.substr(FILE_URL_PREFIX.size());
    }
    return path;
}

FFI_EXPORT int64_t FfiOHOSCreateImageSourceByPath(char* uri, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByPath start");
    std::string path = FileUrlToRawPath(uri);
    std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSource(path, *errCode);
    if (*errCode != SUCCESS_CODE) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByPath failed");
        return INIT_FAILED;
    }
    auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
    if (!nativeImage) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByPath failed");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    nativeImage->SetPathName(path);
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByPath success");
    return nativeImage->GetID();
}

static SourceOptions ParseCSourceOptions(CSourceOptions opts)
{
    SourceOptions options;
    options.baseDensity = opts.baseDensity;
    options.pixelFormat = PixelFormat(opts.pixelFormat);
    options.size.height = opts.height;
    options.size.width = opts.width;
    IMAGE_LOGD("[ImageSource] SourceOptions height is %{public}d, width is %{public}d", options.size.height,
        options.size.width);
    return options;
}

FFI_EXPORT int64_t FfiOHOSCreateImageSourceByPathWithOption(char* uri, CSourceOptions opts, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByPathWithOption start");
    std::string path = FileUrlToRawPath(uri);
    SourceOptions options = ParseCSourceOptions(opts);
    std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSourceWithOption(path, options, *errCode);
    if (*errCode != SUCCESS_CODE) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByPathWithOption failed");
        return INIT_FAILED;
    }
    auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
    if (!nativeImage) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByPathWithOption failed");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    nativeImage->SetPathName(path);
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByPathWithOption success");
    return nativeImage->GetID();
}

FFI_EXPORT int64_t FfiOHOSCreateImageSourceByFd(int fd, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByFd start");
    std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSource(fd, *errCode);
    if (*errCode != SUCCESS_CODE) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByFd failed");
        return INIT_FAILED;
    }
    auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
    if (!nativeImage) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByFd failed");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    nativeImage->SetFd(fd);
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByFd success");
    return nativeImage->GetID();
}

FFI_EXPORT int64_t FfiOHOSCreateImageSourceByFdWithOption(int fd, CSourceOptions opts, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByFdWithOption start");
    SourceOptions options = ParseCSourceOptions(opts);
    std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSourceWithOption(fd, options, *errCode);
    if (*errCode != SUCCESS_CODE) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByFdWithOption failed");
        return INIT_FAILED;
    }
    auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
    if (!nativeImage) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByFdWithOption failed");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    nativeImage->SetFd(fd);
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByFdWithOption success");
    return nativeImage->GetID();
}

FFI_EXPORT int64_t FfiOHOSCreateImageSourceByBuffer(uint8_t* data, uint32_t size, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByBuffer start");
    std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSource(data, size, *errCode);
    if (*errCode != SUCCESS_CODE) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByBuffer failed");
        return INIT_FAILED;
    }
    auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
    if (!nativeImage) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByBuffer failed");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    nativeImage->SetBuffer(data, size);
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByBuffer success");
    return nativeImage->GetID();
}

FFI_EXPORT int64_t FfiOHOSCreateImageSourceByBufferWithOption(
    uint8_t* data, uint32_t size, CSourceOptions opts, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByBufferWithOption start");
    SourceOptions options = ParseCSourceOptions(opts);
    std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSourceWithOption(data, size, options, *errCode);
    if (*errCode != SUCCESS_CODE) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByBufferWithOption failed");
        return INIT_FAILED;
    }
    auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
    if (!nativeImage) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByBufferWithOption failed");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    nativeImage->SetBuffer(data, size);
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByBufferWithOption success");
    return nativeImage->GetID();
}

FFI_EXPORT int64_t FfiOHOSCreateImageSourceByRawFile(
    int fd, int32_t offset, int32_t length, CSourceOptions opts, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByRawFile start");
    SourceOptions options = ParseCSourceOptions(opts);
    std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSource(fd, offset, length, options, *errCode);
    if (*errCode != SUCCESS_CODE) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByRawFile failed");
        return INIT_FAILED;
    }
    auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
    if (!nativeImage) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByRawFile failed");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByRawFile success");
    return nativeImage->GetID();
}

FFI_EXPORT int64_t FfiOHOSCreateIncrementalSource(
    const uint8_t* data, uint32_t size, CSourceOptions opts, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateIncrementalSource start");
    SourceOptions options = ParseCSourceOptions(opts);
    auto ptr = ImageSourceImpl::CreateIncrementalSource(data, size, options, *errCode);
    if (*errCode != SUCCESS_CODE) {
        return INIT_FAILED;
    }
    auto nativeImage = FFIData::Create<ImageSourceImpl>(move(std::get<0>(ptr)), move(std::get<1>(ptr)));
    if (!nativeImage) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateIncrementalSource failed");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    IMAGE_LOGD("[ImageSource] FfiOHOSCreateIncrementalSource success");

    return nativeImage->GetID();
}

FFI_EXPORT CImageInfo FfiOHOSImageSourceGetImageInfo(int64_t id, uint32_t index, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceGetImageInfo start");
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    CImageInfo ret = {};
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    ImageInfo info;
    *errCode = instance->GetImageInfo(index, info);
    if (*errCode != 0) {
        return ret;
    }
    ret.height = info.size.height;
    ret.width = info.size.width;
    ret.density = info.baseDensity;
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceGetImageInfo success");
    return ret;
}

static CImageInfoV2 ParseImageSourceImageInfo(ImageInfo info, ImageSource* imageSource)
{
    CImageInfoV2 ret = {};
    ret.height = info.size.height;
    ret.width = info.size.width;
    ret.density = info.baseDensity;
    ret.pixelFormat = static_cast<int32_t>(info.pixelFormat);
    ret.alphaType = static_cast<int32_t>(info.alphaType);
    ret.mimeType = Utils::MallocCString(info.encodedFormat);
    ret.isHdr = imageSource->IsHdrImage();
    return ret;
}

FFI_EXPORT CImageInfoV2 FfiOHOSImageSourceGetImageInfoV2(int64_t id, uint32_t index, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceGetImageInfoV2 start");
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    CImageInfoV2 ret = {};
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    ImageInfo info;
    *errCode = instance->GetImageInfo(index, info);
    if (*errCode != 0) {
        return ret;
    }
    ret = ParseImageSourceImageInfo(info, instance->nativeImgSrc.get());
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceGetImageInfoV2 success");
    return ret;
}

void FreeArrayPtr(char** ptr, int count)
{
    for (int i = 0; i < count; i++) {
        free(ptr[i]);
    }
}

FFI_EXPORT CArrString FfiOHOSGetSupportedFormats(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSGetSupportedFormats start");
    CArrString ret = { .head = nullptr, .size = 0 };
    *errCode = ERR_IMAGE_INIT_ABNORMAL;
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        return ret;
    }
    std::set<std::string> formats;
    *errCode = instance->GetSupportedFormats(formats);
    if (*errCode == SUCCESS_CODE) {
        size_t size = formats.size();
        if (size == 0) {
            IMAGE_LOGE("[ImageSource] FfiOHOSGetSupportedFormats size cannot be equal to 0.");
            *errCode = ERR_IMAGE_MALLOC_ABNORMAL;
            return ret;
        }

        auto arr = static_cast<char**>(malloc(sizeof(char*) * size));
        if (!arr) {
            IMAGE_LOGE("[ImageSource] FfiOHOSGetSupportedFormats failed to malloc arr.");
            *errCode = ERR_IMAGE_MALLOC_ABNORMAL;
            return ret;
        }

        int32_t i = 0;
        for (const std::string& str : formats) {
            auto temp = Utils::MallocCString(str);
            if (!temp) {
                IMAGE_LOGE("[ImageSource] FfiOHOSGetSupportedFormats failed to copy string.");
                FreeArrayPtr(arr, i);
                free(arr);
                *errCode = ERR_IMAGE_MALLOC_ABNORMAL;
                return ret;
            }
            arr[i] = temp;
            i++;
        }
        ret.head = arr;
        ret.size = static_cast<int64_t>(size);
    }
    IMAGE_LOGD("[ImageSource] FfiOHOSGetSupportedFormats success");
    return ret;
}

FFI_EXPORT char* FfiOHOSGetImageProperty(int64_t id, char* key, uint32_t index, char* defaultValue, uint32_t* errCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSGetImageProperty start");
    char* ret = nullptr;
    *errCode = ERR_IMAGE_INIT_ABNORMAL;
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        return ret;
    }
    std::string skey = key;
    std::string value = defaultValue;
    *errCode = instance->GetImageProperty(skey, index, value);
    if (*errCode != SUCCESS_CODE) {
        return ret;
    }
    ret = Utils::MallocCString(value);
    IMAGE_LOGD("[ImageSource] FfiOHOSGetImageProperty success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSModifyImageProperty(int64_t id, char* key, char* value)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSModifyImageProperty start");
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t ret = instance->ModifyImageProperty(key, value);
    IMAGE_LOGD("[ImageSource] FfiOHOSModifyImageProperty success");
    return ret;
}

FFI_EXPORT RetDataUI32 FfiOHOSGetFrameCount(int64_t id)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSGetFrameCount start");
    RetDataUI32 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = 0 };
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        return ret;
    }
    ret.data = instance->GetFrameCount(ret.code);
    IMAGE_LOGD("[ImageSource] FfiOHOSGetFrameCount success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSUpdateData(int64_t id, UpdateDataInfo info)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSUpdateData start");
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint8_t* buffer = info.data;
    if (info.offset < info.arrSize) {
        buffer = buffer + info.offset;
    }
    uint32_t lastSize = info.arrSize - info.offset;
    uint32_t size = info.updateLen < lastSize ? info.updateLen : lastSize;
    uint32_t ret = instance->UpdateData(buffer, size, info.isCompleted);
    if (ret == 0) {
        auto incPixelMap = instance->GetIncrementalPixelMap();
        if (incPixelMap != nullptr) {
            uint8_t decodeProgress = 0;
            uint32_t err = incPixelMap->PromoteDecoding(decodeProgress);
            if (!(err == SUCCESS_CODE || (err == ERR_IMAGE_SOURCE_DATA_INCOMPLETE && !info.isCompleted))) {
                IMAGE_LOGE("UpdateData PromoteDecoding error");
            }
            if (info.isCompleted) {
                incPixelMap->DetachFromDecoding();
            }
        }
    }

    IMAGE_LOGD("[ImageSource] FfiOHOSUpdateData success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSRelease(int64_t id)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSRelease start");
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->Release();
    IMAGE_LOGD("[ImageSource] FfiOHOSRelease success");
    return SUCCESS_CODE;
}

static DecodeOptions ParseCDecodingOptions(CDecodingOptions& opts)
{
    DecodeOptions decodeOpts = {};
    decodeOpts.fitDensity = opts.fitDensity;
    decodeOpts.desiredSize.height = opts.desiredSize.height;
    decodeOpts.desiredSize.width = opts.desiredSize.width;
    IMAGE_LOGD("[ImageSource] desiredSize height is %{public}d, width is %{public}d", decodeOpts.desiredSize.height,
        decodeOpts.desiredSize.width);
    decodeOpts.desiredRegion.height = opts.desiredRegion.size.height;
    decodeOpts.desiredRegion.width = opts.desiredRegion.size.width;
    decodeOpts.desiredRegion.left = opts.desiredRegion.x;
    decodeOpts.desiredRegion.top = opts.desiredRegion.y;
    IMAGE_LOGD("[ImageSource] desiredRegion height is %{public}d, width is %{public}d,"
               "left is %{public}d, top is %{public}d",
        decodeOpts.desiredRegion.height, decodeOpts.desiredRegion.width, decodeOpts.desiredRegion.left,
        decodeOpts.desiredRegion.top);
    decodeOpts.rotateDegrees = opts.rotateDegrees;
    decodeOpts.sampleSize = opts.sampleSize;
    decodeOpts.desiredPixelFormat = PixelFormat(opts.desiredPixelFormat);
    decodeOpts.editable = opts.editable;
    if (opts.desiredColorSpace != 0) {
        auto colorSpace = FFIData::GetData<ColorManager::CjColorManager>(opts.desiredColorSpace);
        if (colorSpace != nullptr) {
            decodeOpts.desiredColorSpaceInfo = colorSpace->GetColorSpaceToken();
        }
    }
    return decodeOpts;
}

static DecodeOptions ParseCDecodingOptionsV2(CDecodingOptionsV2& opts)
{
    DecodeOptions decodeOpts = {};
    decodeOpts.fitDensity = opts.fitDensity;
    decodeOpts.desiredSize.height = opts.desiredSize.height;
    decodeOpts.desiredSize.width = opts.desiredSize.width;
    IMAGE_LOGD("[ImageSource] desiredSize height is %{public}d, width is %{public}d", decodeOpts.desiredSize.height,
        decodeOpts.desiredSize.width);
    decodeOpts.desiredRegion.height = opts.desiredRegion.size.height;
    decodeOpts.desiredRegion.width = opts.desiredRegion.size.width;
    decodeOpts.desiredRegion.left = opts.desiredRegion.x;
    decodeOpts.desiredRegion.top = opts.desiredRegion.y;
    IMAGE_LOGD("[ImageSource] desiredRegion height is %{public}d, width is %{public}d,"
               "left is %{public}d, top is %{public}d",
        decodeOpts.desiredRegion.height, decodeOpts.desiredRegion.width, decodeOpts.desiredRegion.left,
        decodeOpts.desiredRegion.top);
    decodeOpts.rotateDegrees = opts.rotateDegrees;
    decodeOpts.sampleSize = opts.sampleSize;
    decodeOpts.desiredPixelFormat = PixelFormat(opts.desiredPixelFormat);
    decodeOpts.editable = opts.editable;
    if (opts.desiredColorSpace != 0) {
        auto colorSpace = FFIData::GetData<ColorManager::CjColorManager>(opts.desiredColorSpace);
        if (colorSpace != nullptr) {
            decodeOpts.desiredColorSpaceInfo = colorSpace->GetColorSpaceToken();
        }
    }
    decodeOpts.desiredDynamicRange = DecodeDynamicRange(opts.desiredDynamicRange);
    return decodeOpts;
}

FFI_EXPORT CArrI64 FfiOHOSImageSourceCreatePixelMapList(
    int64_t id, uint32_t index, CDecodingOptions opts, uint32_t* errorCode)
{
    IMAGE_LOGD("[ImageSource] CreatePixelMapList start");
    CArrI64 ret = { .head = nullptr, .size = 0 };
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        *errorCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    DecodeOptions decodeOpts = ParseCDecodingOptions(opts);
    std::vector<int64_t> data = instance->CreatePixelMapList(index, decodeOpts, *errorCode);
    if (*errorCode == SUCCESS_CODE) {
        auto size = data.size();
        if (size == 0) {
            *errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
            IMAGE_LOGE("[ImageSource] FfiOHOSImageSourceCreatePixelMapList size error.");
            return ret;
        }

        auto arr = static_cast<int64_t*>(malloc(sizeof(int64_t) * size));
        if (!arr) {
            IMAGE_LOGE("[ImageSource] FfiOHOSImageSourceCreatePixelMapList failed to malloc arr.");
            *errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
            return ret;
        }
        for (int i = 0; i < static_cast<int>(size); ++i) {
            arr[i] = data[i];
        }
        ret.head = arr;
        ret.size = static_cast<int64_t>(data.size());
    }
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceCreatePixelMapList success");
    return ret;
}

FFI_EXPORT CArrI64 FfiOHOSImageSourceCreatePixelMapListV2(
    int64_t id, uint32_t index, CDecodingOptionsV2 opts, uint32_t* errorCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceCreatePixelMapListV2 start");
    CArrI64 ret = { .head = nullptr, .size = 0 };
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        *errorCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    DecodeOptions decodeOpts = ParseCDecodingOptionsV2(opts);
    std::vector<int64_t> data = instance->CreatePixelMapList(index, decodeOpts, *errorCode);
    if (*errorCode == SUCCESS_CODE) {
        auto size = data.size();
        if (size > 0) {
            auto arr = static_cast<int64_t*>(malloc(sizeof(int64_t) * size));
            if (!arr) {
                IMAGE_LOGE("[ImageSource] FfiOHOSImageSourceCreatePixelMapListV2 failed to malloc arr.");
                *errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
                return ret;
            }
            for (int i = 0; i < static_cast<int>(size); ++i) {
                arr[i] = data[i];
            }
            ret.head = arr;
            ret.size = static_cast<int64_t>(data.size());
        } else {
            *errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
            IMAGE_LOGE("[ImageSource] FfiOHOSImageSourceCreatePixelMapListV2 size error.");
            return ret;
        }
    }
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceCreatePixelMapListV2 success");
    return ret;
}

FFI_EXPORT CArrI32 FfiOHOSImageSourceGetDelayTime(int64_t id, uint32_t* errorCode)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceGetDelayTime start");
    CArrI32 ret = { .head = nullptr, .size = 0 };
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        *errorCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    auto data = instance->GetDelayTime(*errorCode);
    if (*errorCode == SUCCESS_CODE) {
        auto size = data->size();
        if (size <= 0) {
            IMAGE_LOGE("[ImageSource] FfiOHOSImageSourceGetDelayTime size cannot be less than or equal to 0.");
            *errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
            return ret;
        }
        auto arr = static_cast<int32_t*>(malloc(sizeof(int32_t) * size));
        if (!arr) {
            IMAGE_LOGE("[ImageSource] FfiOHOSImageSourceGetDelayTime failed to malloc arr.");
            *errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
            return ret;
        }
        for (int i = 0; i < static_cast<int>(size); ++i) {
            arr[i] = data->operator[](i);
        }
        ret.head = arr;
        ret.size = static_cast<int64_t>(data->size());
    }
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceGetDelayTime success");
    return ret;
}

FFI_EXPORT CArrI32 FfiImageImageSourceImplGetDisposalTypeList(int64_t id, uint32_t* errorCode)
{
    IMAGE_LOGD("[ImageSource] FfiImageImageSourceImplGetDisposalTypeList start");
    CArrI32 ret = { .head = nullptr, .size = 0 };
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        *errorCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    std::unique_ptr<std::vector<int32_t>> data = instance->GetDisposalTypeList(*errorCode);
    if (*errorCode == SUCCESS_CODE && data != nullptr) {
        auto size = data->size();
        if (size <= 0) {
            return ret;
        }
        int32_t* arr = static_cast<int32_t*>(malloc(sizeof(int32_t) * size));
        if (!arr) {
            IMAGE_LOGE("[ImageSource] FfiImageImageSourceImplGetDisposalTypeList failed to malloc arr.");
            *errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
            return ret;
        }
        for (int i = 0; i < static_cast<int>(size); ++i) {
            arr[i] = data->operator[](i);
        }
        ret.head = arr;
        ret.size = static_cast<int64_t>(data->size());
    }
    IMAGE_LOGD("[ImageSource] FfiImageImageSourceImplGetDisposalTypeList success");
    return ret;
}

FFI_EXPORT uint32_t FfiImageImageSourceImplGetImageProperties(int64_t id, CArrString key, char** value)
{
    IMAGE_LOGD("[ImageSource] FfiImageImageSourceImplGetImageProperties start");
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    std::vector<std::string> keyStrArray;
    for (int64_t i = 0; i < key.size; i++) {
        keyStrArray.push_back(key.head[i]);
    }
    std::vector<std::string> valueStrArray;
    uint32_t errCode = instance->GetImageProperties(keyStrArray, valueStrArray);
    if (errCode != SUCCESS) {
        return errCode;
    }
    for (size_t i = 0; i < valueStrArray.size(); i++) {
        value[i] = Utils::MallocCString(valueStrArray[i]);
    }
    IMAGE_LOGD("[ImageSource] FfiImageImageSourceImplGetImageProperties success");
    return errCode;
}

FFI_EXPORT ErrorInfo FfiImageImageSourceImplGetImagePropertiesV2(int64_t id, CArrString key, char** value)
{
    IMAGE_LOGD("[ImageSource] FfiImageImageSourceImplGetImagePropertiesV2 start");
    ErrorInfo errorInfo = { .code = SUCCESS, .message = nullptr };
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        errorInfo.code = ERR_IMAGE_INIT_ABNORMAL;
        return errorInfo;
    }
    std::vector<std::string> keyStrArray;
    for (int64_t i = 0; i < key.size; i++) {
        keyStrArray.emplace_back(key.head[i]);
    }
    std::vector<std::string> valueStrArray;
    std::set<std::string> exifUnsupportKeys;
    uint32_t status = instance->GetImagePropertiesV2(keyStrArray, valueStrArray, exifUnsupportKeys);
    if (status != SUCCESS) {
        errorInfo.code = status;
        std::string errMsg = "Failed to get keys:";
        for (auto& key : exifUnsupportKeys) {
            errMsg.append(" ").append(key);
        }
        errorInfo.message = Utils::MallocCString(errMsg);
        return errorInfo;
    }
    if (valueStrArray.size() != key.size) {
        errorInfo.code = IMAGE_UNSUPPORTED_METADATA;
        return errorInfo;
    }
    for (size_t i = 0; i < valueStrArray.size(); i++) {
        value[i] = Utils::MallocCString(valueStrArray[i]);
    }
    IMAGE_LOGD("[ImageSource] FfiImageImageSourceImplGetImageProperties success");
    return errorInfo;
}

FFI_EXPORT uint32_t FfiImageImageSourceImplModifyImageProperties(int64_t id, CArrString key, CArrString value)
{
    IMAGE_LOGD("[ImageSource] FfiImageImageSourceImplModifyImageProperties start");
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    std::vector<std::string> keyStrArray;
    for (int64_t i = 0; i < key.size; i++) {
        keyStrArray.push_back(key.head[i]);
    }
    std::vector<std::string> valueStrArray;
    for (int64_t i = 0; i < value.size; i++) {
        valueStrArray.push_back(value.head[i]);
    }
    IMAGE_LOGD("[ImageSource] FfiImageImageSourceImplModifyImageProperties success");
    return instance->ModifyImageProperties(keyStrArray, valueStrArray);
}

FFI_EXPORT RetDataI64U32 FfiOHOSImageSourceCreatePixelMap(int64_t id, uint32_t index, CDecodingOptions opts)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceCreatePixelMap start");
    RetDataI64U32 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = 0 };
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        return ret;
    }
    DecodeOptions decodeOpts = ParseCDecodingOptions(opts);
    ret.data = instance->CreatePixelMap(index, decodeOpts, ret.code);
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceCreatePixelMap success");
    return ret;
}

FFI_EXPORT RetDataI64U32 FfiOHOSImageSourceCreatePixelMapV2(int64_t id, uint32_t index, CDecodingOptionsV2 opts)
{
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceCreatePixelMapV2 start");
    RetDataI64U32 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = 0 };
    auto instance = FFIData::GetData<ImageSourceImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
        return ret;
    }
    DecodeOptions decodeOpts = ParseCDecodingOptionsV2(opts);
    ret.data = instance->CreatePixelMap(index, decodeOpts, ret.code);
    IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceCreatePixelMapV2 success");
    return ret;
}

//--------------------- ImageReceiver ------------------------------------------------------------------------

FFI_EXPORT uint32_t FfiOHOSReceiverGetSize(int64_t id, CSize* retVal)
{
    IMAGE_LOGD("FfiOHOSReceiverGetSize start");
    auto instance = FFIData::GetData<ImageReceiverImpl>(id);
    if (!instance) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t retCode = instance->GetSize(retVal);
    IMAGE_LOGD("FfiOHOSReceiverGetSize success");
    return retCode;
}

FFI_EXPORT uint32_t FfiOHOSReceiverGetCapacity(int64_t id, int32_t* retVal)
{
    IMAGE_LOGD("FfiOHOSReceiverGetCapacity start");
    auto instance = FFIData::GetData<ImageReceiverImpl>(id);
    if (!instance) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t retCode = instance->GetCapacity(retVal);
    IMAGE_LOGD("FfiOHOSReceiverGetCapacity success");
    return retCode;
}

FFI_EXPORT uint32_t FfiOHOSReceiverGetFormat(int64_t id, int32_t* retVal)
{
    IMAGE_LOGD("FfiOHOSReceiverGetFormat start");
    auto instance = FFIData::GetData<ImageReceiverImpl>(id);
    if (!instance) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t retCode = instance->GetFormat(retVal);
    IMAGE_LOGD("FfiOHOSReceiverGetFormat success");
    return retCode;
}

FFI_EXPORT int64_t FfiOHOSCreateImageReceiver(int32_t width, int32_t height, int32_t format, int32_t capacity)
{
    IMAGE_LOGD("FfiOHOSCreateImageReceiver start");
    auto id = ImageReceiverImpl::CreateImageReceiver(width, height, format, capacity);
    IMAGE_LOGD("FfiOHOSCreateImageReceiver success");
    return id;
}

FFI_EXPORT char* FfiOHOSGetReceivingSurfaceId(int64_t id)
{
    IMAGE_LOGD("FfiOHOSGetReceivingSurfaceId start");
    auto instance = FFIData::GetData<ImageReceiverImpl>(id);
    if (!instance) {
        IMAGE_LOGE("ImageReceiver instance not exist %{public}" PRId64, id);
        return nullptr;
    }
    char* ret = instance->GetReceivingSurfaceId();
    IMAGE_LOGD("FfiOHOSGetReceivingSurfaceId success");
    return ret;
}

FFI_EXPORT int64_t FfiOHOSReadNextImage(int64_t id)
{
    IMAGE_LOGD("FfiOHOSReadNextImage start");
    auto instance = FFIData::GetData<ImageReceiverImpl>(id);
    if (!instance) {
        IMAGE_LOGE("ImageReceiver instance not exist %{public}" PRId64, id);
        return INIT_FAILED;
    }
    auto image = instance->ReadNextImage();
    if (!image) {
        IMAGE_LOGE("ImageImpl Create is nullptr.");
        return INIT_FAILED;
    }
    IMAGE_LOGD("FfiOHOSReadNextImage success");
    return image->GetID();
}

FFI_EXPORT int64_t FfiOHOSReadLatestImage(int64_t id)
{
    IMAGE_LOGD("FfiOHOSReadLatestImage start.");
    auto instance = FFIData::GetData<ImageReceiverImpl>(id);
    if (!instance) {
        IMAGE_LOGE("ImageReceiver instance not exist %{public}" PRId64, id);
        return INIT_FAILED;
    }
    auto image = instance->ReadLatestImage();
    if (!image) {
        IMAGE_LOGE("ImageImpl Create is nullptr.");
        return INIT_FAILED;
    }

    IMAGE_LOGD("FfiOHOSReadLatestImage success.");
    return image->GetID();
}

FFI_EXPORT void FfiOHOSReceiverRelease(int64_t id)
{
    IMAGE_LOGD("FfiOHOSReceiverRelease start");
    auto instance = FFIData::GetData<ImageReceiverImpl>(id);
    if (!instance) {
        IMAGE_LOGE("ImageReceiver instance not exist %{public}" PRId64, id);
        return;
    }
    instance->Release();
    IMAGE_LOGD("FfiOHOSReceiverRelease success");
}

FFI_EXPORT uint32_t FfiOHOSImageGetClipRect(int64_t id, CRegion* retVal)
{
    IMAGE_LOGD("FfiOHOSImageGetClipRect start");
    auto instance = FFIData::GetData<ImageImpl>(id);
    if (!instance) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    int64_t retCode = instance->GetClipRect(*retVal);
    IMAGE_LOGD("FfiOHOSImageGetClipRect success");
    return retCode;
}

FFI_EXPORT uint32_t FfiOHOSImageGetSize(int64_t id, CSize* retVal)
{
    IMAGE_LOGD("FfiOHOSImageGetSize start");
    auto instance = FFIData::GetData<ImageImpl>(id);
    if (!instance) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t retCode = instance->GetSize(*retVal);
    IMAGE_LOGD("FfiOHOSImageGetSize success");
    return retCode;
}

FFI_EXPORT uint32_t FfiOHOSImageGetFormat(int64_t id, int32_t* retVal)
{
    IMAGE_LOGD("FfiOHOSImageGetFormat start");
    auto instance = FFIData::GetData<ImageImpl>(id);
    if (!instance) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t retCode = instance->GetFormat(*retVal);
    IMAGE_LOGD("FfiOHOSImageGetFormat success");
    return retCode;
}

FFI_EXPORT uint32_t FfiOHOSGetComponent(int64_t id, int32_t componentType, CRetComponent* ptr)
{
    IMAGE_LOGD("FfiOHOSGetComponent start");
    auto instance = FFIData::GetData<ImageImpl>(id);
    if (!instance) {
        IMAGE_LOGE("ImageImpl instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t errCode = instance->GetComponent(componentType, *ptr);
    IMAGE_LOGD("FfiOHOSGetComponent success");
    return errCode;
}

FFI_EXPORT int64_t FfiImageImageImplGetTimestamp(int64_t id)
{
    IMAGE_LOGD("FfiImageImageImplGetTimestamp start");
    auto instance = FFIData::GetData<ImageImpl>(id);
    if (!instance) {
        IMAGE_LOGE("ImageImpl instance not exist %{public}" PRId64, id);
        return 0;
    }
    IMAGE_LOGD("FfiImageImageImplGetTimestamp success");
    return instance->GetTimestamp();
}

FFI_EXPORT void FfiOHOSImageRelease(int64_t id)
{
    IMAGE_LOGD("FfiOHOSImageRelease start");
    auto instance = FFIData::GetData<ImageImpl>(id);
    if (!instance) {
        IMAGE_LOGE("ImageImpl instance not exist %{public}" PRId64, id);
        return;
    }
    instance->Release();
    IMAGE_LOGD("FfiOHOSImageRelease success");
}

FFI_EXPORT uint32_t FfiImageReceiverImplOn(int64_t id, char* name, int64_t callbackId)
{
    IMAGE_LOGD("FfiImageReceiverImplOn start");
    auto instance = FFIData::GetData<ImageReceiverImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageReceiver] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    auto cFunc = reinterpret_cast<void (*)()>(callbackId);
    std::function<void()> func = CJLambda::Create(cFunc);
    return instance->CjOn(name, func);
}

FFI_EXPORT uint32_t FfiImageReceiverImplOff(int64_t id, char* name)
{
    (void)name;
    IMAGE_LOGD("FfiImageReceiverImplOff start");
    auto instance = FFIData::GetData<ImageReceiverImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageReceiver] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    return instance->CjOff();
}

//--------------------- ImagePacker ---------------------------------------------------------------------------
FFI_EXPORT int64_t FFiOHOSImagePackerConstructor()
{
    auto ret = FFIData::Create<ImagePackerImpl>();
    if (!ret) {
        return INIT_FAILED;
    }
    return ret->GetID();
}

static PackOption ParseCPackOption(CPackingOptionV2 option)
{
    PackOption packOption = {
        .format = option.format,
        .quality = option.quality,
        .desiredDynamicRange = EncodeDynamicRange(option.desiredDynamicRange),
        .needsPackProperties = option.needsPackProperties,
    };
    return packOption;
}

FFI_EXPORT RetDataCArrUI8 FfiOHOSImagePackerPackingPixelMap(int64_t id, int64_t source, CPackingOption option)
{
    CArrUI8 data = { .head = nullptr, .size = 0 };
    RetDataCArrUI8 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = data };
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ret;
    }

    auto pixelMapImpl = FFIData::GetData<PixelMapImpl>(source);
    if (pixelMapImpl != nullptr) {
        auto pixelMap = pixelMapImpl->GetRealPixelMap();
        if (!pixelMap) {
            return ret;
        }
        PackOption packOption = { .format = option.format, .quality = option.quality };
        auto [code, head, size] = imagePackerImpl->Packing(*pixelMap, packOption, option.bufferSize);
        if (code != SUCCESS_CODE) {
            IMAGE_LOGE("Packing failed, error code is %{public}d", code);
        }
        data.head = head;
        data.size = size;
        ret.code = code;
        ret.data = data;
        return ret;
    }

    IMAGE_LOGE("Packing failed, invalid id of PixelMapImpl");
    return ret;
}

FFI_EXPORT RetDataCArrUI8 FfiOHOSImagePackerPackingPixelMapV2(int64_t id, int64_t source, CPackingOptionV2 option)
{
    CArrUI8 data = { .head = nullptr, .size = 0 };
    RetDataCArrUI8 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = data };
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ret;
    }

    auto pixelMapImpl = FFIData::GetData<PixelMapImpl>(source);
    if (pixelMapImpl != nullptr) {
        auto pixelMap = pixelMapImpl->GetRealPixelMap();
        if (!pixelMap) {
            return ret;
        }
        PackOption packOption = { .format = option.format, .quality = option.quality };
        auto [code, head, size] = imagePackerImpl->Packing(*pixelMap, packOption, option.bufferSize);
        if (code != SUCCESS_CODE) {
            IMAGE_LOGE("Packing failed, error code is %{public}d", code);
        }
        data.head = head;
        data.size = size;
        ret.code = code;
        ret.data = data;
        return ret;
    }

    IMAGE_LOGE("Packing failed, invalid id of PixelMapImpl");
    return ret;
}

FFI_EXPORT RetDataCArrUI8 FfiOHOSImagePackerPackingImageSource(int64_t id, int64_t source, CPackingOption option)
{
    CArrUI8 data = { .head = nullptr, .size = 0 };
    RetDataCArrUI8 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = data };
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ret;
    }

    auto imageSourceImpl = FFIData::GetData<ImageSourceImpl>(source);
    if (imageSourceImpl != nullptr) {
        PackOption packOption = { .format = option.format, .quality = option.quality };
        auto imageSource = imageSourceImpl->nativeImgSrc;
        if (!imageSource) {
            return ret;
        }
        auto [code, head, size] = imagePackerImpl->Packing(*imageSource, packOption, option.bufferSize);
        if (code != SUCCESS_CODE) {
            IMAGE_LOGE("Packing failed, error code is %{public}d", code);
        }
        data.head = head;
        data.size = size;
        ret.code = code;
        ret.data = data;
        return ret;
    }

    IMAGE_LOGE("Packing failed, invalid id of ImageSourceImpl");
    return ret;
}

FFI_EXPORT RetDataCArrUI8 FfiOHOSImagePackerPackingImageSourceV2(int64_t id, int64_t source, CPackingOptionV2 option)
{
    CArrUI8 data = { .head = nullptr, .size = 0 };
    RetDataCArrUI8 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = data };
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ret;
    }

    auto imageSourceImpl = FFIData::GetData<ImageSourceImpl>(source);
    if (imageSourceImpl != nullptr) {
        PackOption packOption = ParseCPackOption(option);
        auto imageSource = imageSourceImpl->nativeImgSrc;
        if (!imageSource) {
            return ret;
        }
        auto [code, head, size] = imagePackerImpl->Packing(*imageSource, packOption, option.bufferSize);
        if (code != SUCCESS_CODE) {
            IMAGE_LOGE("Packing failed, error code is %{public}d", code);
        }
        data.head = head;
        data.size = size;
        ret.code = code;
        ret.data = data;
        return ret;
    }

    IMAGE_LOGE("Packing failed, invalid id of ImageSourceImpl");
    return ret;
}

FFI_EXPORT RetDataCArrUI8 FfiImageImagePackerImplPackToDataPixelMap(int64_t id, int64_t source, CPackingOptionV2 option)
{
    IMAGE_LOGD("[ImagePacker] FfiImageImagePackerImplPackToDataPixelMap in");
    CArrUI8 data = { .head = nullptr, .size = 0 };
    RetDataCArrUI8 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = data };
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ret;
    }

    auto pixelMapImpl = FFIData::GetData<PixelMapImpl>(source);
    if (pixelMapImpl != nullptr) {
        PackOption packOption = ParseCPackOption(option);
        auto pixelMap = pixelMapImpl->GetRealPixelMap();
        if (!pixelMap) {
            return ret;
        }
        auto [code, head, size] = imagePackerImpl->PackToData(pixelMap, packOption, option.bufferSize);
        if (code != SUCCESS_CODE) {
            IMAGE_LOGE("Packing failed, error code is %{public}d", code);
        }
        data.head = head;
        data.size = size;
        ret.code = code;
        ret.data = data;
        IMAGE_LOGD("[ImagePacker] FfiImageImagePackerImplPackToDataPixelMap in");
        return ret;
    }

    IMAGE_LOGE("Packing failed, invalid id of pixelMapImpl");
    return ret;
}

FFI_EXPORT RetDataCArrUI8 FfiImageImagePackerImplPackToDataImageSource(
    int64_t id, int64_t source, CPackingOptionV2 option)
{
    {
        IMAGE_LOGD("[ImagePacker] FfiImageImagePackerImplPackToDataImageSource in");
        CArrUI8 data = { .head = nullptr, .size = 0 };
        RetDataCArrUI8 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = data };
        auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
        if (!imagePackerImpl) {
            IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
            return ret;
        }

        auto imageSourceImpl = FFIData::GetData<ImageSourceImpl>(source);
        if (imageSourceImpl != nullptr) {
            PackOption packOption = ParseCPackOption(option);
            auto imageSource = imageSourceImpl->nativeImgSrc;
            if (!imageSource) {
                return ret;
            }
            auto [code, head, size] = imagePackerImpl->PackToData(imageSource, packOption, option.bufferSize);
            if (code != SUCCESS_CODE) {
                IMAGE_LOGE("Packing failed, error code is %{public}d", code);
            }
            data.head = head;
            data.size = size;
            ret.code = code;
            ret.data = data;
            IMAGE_LOGD("[ImagePacker] FfiImageImagePackerImplPackToDataImageSource in");
            return ret;
        }

        IMAGE_LOGE("Packing failed, invalid id of imageSourceImpl");
        return ret;
    }
}

FFI_EXPORT RetDataCArrUI8 FfiImageImagePackerImplPackingPicture(int64_t id, int64_t source, CPackingOptionV2 option)
{
    IMAGE_LOGD("[ImagePacker] FfiImageImagePackerImplPackingPicture in");
    CArrUI8 data = { .head = nullptr, .size = 0 };
    RetDataCArrUI8 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = data };
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ret;
    }

    auto pictureImpl = FFIData::GetData<PictureImpl>(source);
    if (pictureImpl != nullptr) {
        PackOption packOption = ParseCPackOption(option);
        auto picture = pictureImpl->GetPicture();
        if (!picture) {
            return ret;
        }
        auto [code, head, size] = imagePackerImpl->PackToData(picture, packOption, option.bufferSize);
        if (code != SUCCESS_CODE) {
            IMAGE_LOGE("Packing failed, error code is %{public}d", code);
        }
        data.head = head;
        data.size = size;
        ret.code = code;
        ret.data = data;
        IMAGE_LOGD("[ImagePacker] FfiImageImagePackerImplPackingPicture in");
        return ret;
    }

    IMAGE_LOGE("Packing failed, invalid id of pictureImpl");
    return ret;
}

FFI_EXPORT RetDataCArrString FfiOHOSImagePackerGetSupportedFormats(int64_t id)
{
    RetDataCArrString ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = { .head = nullptr, .size = 0 } };
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ret;
    }

    auto imagePacker = imagePackerImpl->GetImagePacker();
    if (!imagePacker) {
        IMAGE_LOGE("fail to get ImagePacker");
        return ret;
    }

    std::set<std::string> formats;
    uint32_t formatsRet = imagePacker->GetSupportedFormats(formats);
    if (formatsRet != SUCCESS_CODE) {
        IMAGE_LOGE("fail to get supported formats");
        return ret;
    }

    CArrString arrInfo { .head = nullptr, .size = 0 };
    auto size = formats.size();
    if (size == 0) {
        IMAGE_LOGE("[ImageSource] FfiOHOSImagePackerGetSupportedFormats size cannot be equal to 0.");
        ret.code = ERR_SHAMEM_NOT_EXIST;
        return ret;
    }
    auto arr = static_cast<char**>(malloc(sizeof(char*) * size));
    if (!arr) {
        IMAGE_LOGE("[ImageSource] FfiOHOSImagePackerGetSupportedFormats failed to malloc arr.");
        ret.code = ERR_SHAMEM_NOT_EXIST;
        return ret;
    }

    uint32_t i = 0;
    for (const auto& format : formats) {
        auto temp = ::Utils::MallocCString(format);
        if (!temp) {
            FreeArrayPtr(arr, i);
            free(arr);
            ret.code = ERR_SHAMEM_NOT_EXIST;
            return ret;
        }
        arr[i++] = temp;
    }

    arrInfo.head = arr;
    arrInfo.size = static_cast<int64_t>(formats.size());
    ret.code = SUCCESS_CODE;
    ret.data = arrInfo;

    return ret;
}

FFI_EXPORT uint32_t FfiOHOSImagePackerPackPixelMapToFile(int64_t id, int64_t source, int fd, CPackingOption option)
{
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    auto pixelMapImpl = FFIData::GetData<PixelMapImpl>(source);
    if (pixelMapImpl != nullptr) {
        auto pixelMap = pixelMapImpl->GetRealPixelMap();
        if (!pixelMap) {
            return ERR_IMAGE_INIT_ABNORMAL;
        }

        PackOption packOption = { .format = option.format, .quality = option.quality };
        uint32_t ret = imagePackerImpl->PackToFile(pixelMap, fd, packOption);
        return ret;
    }
    return ERR_IMAGE_INIT_ABNORMAL;
}

FFI_EXPORT uint32_t FfiOHOSImagePackerPackPixelMapToFileV2(int64_t id, int64_t source, int fd, CPackingOptionV2 option)
{
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    auto pixelMapImpl = FFIData::GetData<PixelMapImpl>(source);
    if (pixelMapImpl != nullptr) {
        auto pixelMap = pixelMapImpl->GetRealPixelMap();
        if (!pixelMap) {
            return ERR_IMAGE_INIT_ABNORMAL;
        }

        PackOption packOption = ParseCPackOption(option);
        uint32_t ret = imagePackerImpl->PackToFile(pixelMap, fd, packOption);
        return ret;
    }
    return ERR_IMAGE_INIT_ABNORMAL;
}

FFI_EXPORT uint32_t FfiOHOSImagePackerImageSourcePackToFile(int64_t id, int64_t source, int fd, CPackingOption option)
{
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    auto imageSourceImpl = FFIData::GetData<ImageSourceImpl>(source);
    if (imageSourceImpl != nullptr) {
        PackOption packOption = { .format = option.format, .quality = option.quality };
        auto imageSource = imageSourceImpl->nativeImgSrc;
        if (!imageSource) {
            return ERR_IMAGE_INIT_ABNORMAL;
        }

        uint32_t ret = imagePackerImpl->PackToFile(imageSource, fd, packOption);
        return ret;
    }
    return ERR_IMAGE_INIT_ABNORMAL;
}

FFI_EXPORT uint32_t FfiOHOSImagePackerImageSourcePackToFileV2(
    int64_t id, int64_t source, int fd, CPackingOptionV2 option)
{
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    auto imageSourceImpl = FFIData::GetData<ImageSourceImpl>(source);
    if (imageSourceImpl != nullptr) {
        PackOption packOption = ParseCPackOption(option);
        auto imageSource = imageSourceImpl->nativeImgSrc;
        if (!imageSource) {
            return ERR_IMAGE_INIT_ABNORMAL;
        }

        uint32_t ret = imagePackerImpl->PackToFile(imageSource, fd, packOption);
        return ret;
    }
    return ERR_IMAGE_INIT_ABNORMAL;
}

FFI_EXPORT uint32_t FfiImageImagePackerImplPackToFilePicture(
    int64_t id, int64_t source, int fd, CPackingOptionV2 option)
{
    IMAGE_LOGD("[ImagePacker] FfiImageImagePackerImplPackToFilePicture in");
    auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
    if (!imagePackerImpl) {
        IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    auto pictureImpl = FFIData::GetData<PictureImpl>(source);
    if (pictureImpl != nullptr) {
        PackOption packOption = ParseCPackOption(option);
        auto picture = pictureImpl->GetPicture();
        if (!picture) {
            return ERR_IMAGE_INIT_ABNORMAL;
        }

        uint32_t ret = imagePackerImpl->PackToFile(picture, fd, packOption);
        IMAGE_LOGD("[ImagePacker] FfiImageImagePackerImplPackToFilePicture in");
        return ret;
    }
    return ERR_IMAGE_INIT_ABNORMAL;
}

FFI_EXPORT uint64_t FfiOHOSGetPackOptionSize()
{
    return sizeof(PackOption);
}

FFI_EXPORT void FFiOHOSImagePackerRelease(int64_t id)
{
    IMAGE_LOGD("FFiOHOSImagePackerRelease start");
    auto instance = FFIData::GetData<ImagePackerImpl>(id);
    if (!instance) {
        return;
    }
    instance->Release();
    IMAGE_LOGD("FFiOHOSImagePackerRelease success");
}

//--------------------- ImageCreator ---------------------------------------------------------------------------
FFI_EXPORT int64_t FFiOHOSImageCreatorConstructor(int32_t width, int32_t height, int32_t format, int32_t capacity)
{
    auto ret = FFIData::Create<ImageCreatorImpl>(width, height, format, capacity);
    if (!ret) {
        return INIT_FAILED;
    }
    return ret->GetID();
}

FFI_EXPORT RetDataI32 FFiOHOSImageCreatorGetCapacity(int64_t id)
{
    IMAGE_LOGD("FFiOHOSImageCreatorGetCapacity start");
    RetDataI32 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = 0 };
    auto instance = FFIData::GetData<ImageCreatorImpl>(id);
    if (!instance) {
        IMAGE_LOGE("FFiOHOSImageCreatorGetCapacity instance not exist %{public}" PRId64, id);
        return ret;
    }

    std::shared_ptr<ImageCreator> imageCreator = instance->GetImageCreator();
    if (!imageCreator) {
        IMAGE_LOGE("FFiOHOSImageCreatorGetCapacity imageCreator is nullptr.");
        return ret;
    }

    std::shared_ptr<ImageCreatorContext> context = imageCreator->iraContext_;
    if (!context) {
        IMAGE_LOGE("FFiOHOSImageCreatorGetCapacity context is nullptr.");
        return ret;
    }

    ret.data = context->GetCapicity();
    ret.code = SUCCESS_CODE;
    IMAGE_LOGD("FFiOHOSImageCreatorGetCapacity success");
    return ret;
}

FFI_EXPORT RetDataI32 FFiOHOSImageCreatorGetformat(int64_t id)
{
    IMAGE_LOGD("FFiOHOSImageCreatorGetformat start");
    RetDataI32 ret = { .code = ERR_IMAGE_INIT_ABNORMAL, .data = 0 };
    auto instance = FFIData::GetData<ImageCreatorImpl>(id);
    if (!instance) {
        IMAGE_LOGE("FFiOHOSImageCreatorGetformat instance not exist %{public}" PRId64, id);
        return ret;
    }

    std::shared_ptr<ImageCreator> imageCreator = instance->GetImageCreator();
    if (!imageCreator) {
        IMAGE_LOGE("FFiOHOSImageCreatorGetformat imageCreator is nullptr.");
        return ret;
    }

    std::shared_ptr<ImageCreatorContext> context = imageCreator->iraContext_;
    if (!context) {
        IMAGE_LOGE("FFiOHOSImageCreatorGetformat context is nullptr.");
        return ret;
    }

    ret.data = context->GetFormat();
    ret.code = SUCCESS_CODE;
    IMAGE_LOGD("FFiOHOSImageCreatorGetformat success");
    return ret;
}

FFI_EXPORT int64_t FFiOHOSImageCreatorDequeueImage(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("FFiOHOSImageCreatorDequeueImage start");
    auto instance = FFIData::GetData<ImageCreatorImpl>(id);
    if (!instance) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }

    std::shared_ptr<ImageCreator> imageCreator = instance->GetImageCreator();
    if (!imageCreator) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    std::shared_ptr<NativeImage> nativeImageRes = imageCreator->DequeueNativeImage();
    if (!nativeImageRes) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    auto ret = FFIData::Create<ImageImpl>(nativeImageRes);
    if (!ret) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return INIT_FAILED;
    }
    *errCode = SUCCESS_CODE;
    return ret->GetID();
}

FFI_EXPORT void FFiOHOSImageCreatorQueueImage(int64_t id, int64_t imageId)
{
    IMAGE_LOGD("FFiOHOSImageCreatorQueueImage start");
    auto instance = FFIData::GetData<ImageCreatorImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageCreator] instance not exist %{public}" PRId64, id);
        return;
    }
    auto imageInstance = FFIData::GetData<ImageImpl>(imageId);
    if (!imageInstance) {
        IMAGE_LOGE("[ImageCreator] imageInstance not exist %{public}" PRId64, imageId);
        return;
    }
    std::shared_ptr<ImageCreator> imageCreator = instance->GetImageCreator();
    if (!imageCreator) {
        IMAGE_LOGE("[ImageCreator] imageCreator can not be nullptr");
        return;
    }
    imageCreator->QueueNativeImage(imageInstance->GetNativeImage());
    IMAGE_LOGD("FFiOHOSImageCreatorQueueImage success");
}

FFI_EXPORT void FFiOHOSImageCreatorRelease(int64_t id)
{
    IMAGE_LOGD("FFiOHOSImageCreatorRelease start");
    auto instance = FFIData::GetData<ImageCreatorImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageCreator] instance not exist %{public}" PRId64, id);
        return;
    }
    instance->Release();
    IMAGE_LOGD("FFiOHOSImageCreatorRelease success");
}

FFI_EXPORT uint32_t FfiImageImageCreatorImplOn(int64_t id, char* name, int64_t callbackId)
{
    IMAGE_LOGD("FfiImageImageCreatorImplOn start");
    auto instance = FFIData::GetData<ImageCreatorImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[ImageCreator] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    auto cFunc = reinterpret_cast<void (*)()>(callbackId);
    std::function<void()> func = CJLambda::Create(cFunc);
    return instance->CjOn(name, func);
}

//  Picture
FFI_EXPORT int64_t FfiImagePictureImplCreatePicture(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[Picture] FfiImagePictureImplCreatePicture in");
    auto pixelMapImpl = FFIData::GetData<PixelMapImpl>(id);
    if (!pixelMapImpl) {
        IMAGE_LOGE("[Picture] pixelMapImpl not exist %{public}" PRId64, id);
        return IMAGE_BAD_PARAMETER;
    }
    auto pixelMap = pixelMapImpl->GetRealPixelMap();
    if (!pixelMap) {
        IMAGE_LOGE("[Picture] pixelMap is nullptr");
        return IMAGE_BAD_PARAMETER;
    }
    auto picture = Picture::Create(pixelMap);
    if (!picture) {
        IMAGE_LOGE("[Picture] picture is nullptr");
        return IMAGE_BAD_PARAMETER;
    }
    auto native = FFIData::Create<PictureImpl>(move(picture));
    if (!native) {
        IMAGE_LOGE("[Picture] native is nullptr");
        return IMAGE_BAD_PARAMETER;
    }
    IMAGE_LOGD("[Picture] FfiImagePictureImplCreatePicture out");
    return native->GetID();
}

FFI_EXPORT uint32_t FfiImagePictureImplSetMetadata(int64_t id, int32_t metadataType, int64_t metadataId)
{
    IMAGE_LOGD("[Picture] FfiImagePictureImplSetMetadata in");
    if (metadataType != static_cast<int32_t>(MetadataType::EXIF)) {
        IMAGE_LOGE("Unsupport MetadataType");
        return IMAGE_UNSUPPORTED_METADATA;
    }
    auto picture = FFIData::GetData<PictureImpl>(id);
    if (!picture) {
        IMAGE_LOGE("[Picture] picture not exist %{public}" PRId64, id);
        return IMAGE_BAD_PARAMETER;
    }
    auto metadata = FFIData::GetData<MetadataImpl>(metadataId);
    if (!metadata) {
        IMAGE_LOGE("[Picture] metadata not exist %{public}" PRId64, metadataId);
        return IMAGE_BAD_PARAMETER;
    }
    IMAGE_LOGD("[Picture] FfiImagePictureImplSetMetadata out");
    return picture->SetMetadata(MetadataType(metadataType), metadata->GetNativeMetadata());
}

FFI_EXPORT int64_t FfiImagePictureImplGetMetadata(int64_t id, int32_t metadataType, uint32_t* errCode)
{
    IMAGE_LOGD("[Picture] FfiImagePictureImplGetMetadata in");
    if (metadataType != static_cast<int32_t>(MetadataType::EXIF)) {
        IMAGE_LOGE("Unsupport MetadataType");
        *errCode = IMAGE_UNSUPPORTED_METADATA;
        return 0;
    }
    auto picture = FFIData::GetData<PictureImpl>(id);
    if (!picture) {
        IMAGE_LOGE("[Picture] picture not exist %{public}" PRId64, id);
        *errCode = IMAGE_BAD_PARAMETER;
        return 0;
    }
    auto metadata = picture->GetMetadata(MetadataType(metadataType), errCode);
    if (!metadata) {
        IMAGE_LOGE("[Picture] metadata is nullptr");
        *errCode = IMAGE_BAD_PARAMETER;
        return 0;
    }
    auto native = FFIData::Create<MetadataImpl>(metadata);
    if (!native) {
        IMAGE_LOGE("[Picture] native is nullptr");
        *errCode = IMAGE_BAD_PARAMETER;
        return 0;
    }
    IMAGE_LOGD("[Picture] FfiImagePictureImplGetMetadata out");
    return native->GetID();
}

// Metadata
FFI_EXPORT CjProperties FfiImageMetadataImplGetAllProperties(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[Metadata] FfiImageMetadataImplGetAllProperties in");
    CjProperties res = { 0 };
    auto metadata = FFIData::GetData<MetadataImpl>(id);
    if (!metadata) {
        IMAGE_LOGE("[Metadata] metadata is nullptr");
        *errCode = IMAGE_BAD_PARAMETER;
        return res;
    }
    std::vector<std::pair<std::string, std::string>> vec = metadata->GetAllProperties(errCode);
    if (*errCode != SUCCESS) {
        return res;
    }
    size_t size = vec.size();
    if (size < 0) {
        *errCode = IMAGE_BAD_PARAMETER;
        return res;
    }
    if (size == 0) {
        return res;
    }
    char** keyArr = static_cast<char**>(malloc(sizeof(char*) * size));
    if (keyArr == nullptr) {
        IMAGE_LOGE("[Metadata] keyArr is nullptr");
        *errCode = IMAGE_BAD_PARAMETER;
        return res;
    }
    char** valueArr = static_cast<char**>(malloc(sizeof(char*) * size));
    if (valueArr == nullptr) {
        IMAGE_LOGE("[Metadata] valueArr is nullptr");
        free(keyArr);
        *errCode = IMAGE_BAD_PARAMETER;
        return res;
    }
    size_t index = 0;
    for (const auto& p : vec) {
        keyArr[index] = Utils::MallocCString(p.first);
        valueArr[index] = Utils::MallocCString(p.second);
        index++;
    }
    res.key = keyArr;
    res.value = valueArr;
    res.size = static_cast<int64_t>(size);
    IMAGE_LOGD("[Metadata] FfiImageMetadataImplGetAllProperties out");
    return res;
}

FFI_EXPORT void FfiImageMetadataImplReleaseProperties(CjProperties* properties)
{
    if (properties != nullptr) {
        if (properties->key != nullptr) {
            for (int64_t i = 0; i < properties->size; i++) {
                free(properties->key[i]);
            }
        }
        free(properties->key);
        properties->key = nullptr;
        if (properties->value != nullptr) {
            for (int64_t i = 0; i < properties->size; i++) {
                free(properties->value[i]);
            }
        }
        free(properties->value);
        properties->value = nullptr;
    }
}
}
} // namespace Media
} // namespace OHOS