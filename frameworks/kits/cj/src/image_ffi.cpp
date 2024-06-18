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
#include "image_log.h"
#include "image_source_impl.h"
#include <cstdint>
#include "media_errors.h"
#include "pixel_map_impl.h"
#include "image_receiver_impl.h"
#include "image_creator_impl.h"
#include "image_packer_impl.h"
#include "cj_color_manager.h"
#include "image_type.h"
 
using namespace OHOS::FFI;
 
namespace OHOS {
namespace Media {
extern "C"
{
    static Rect ParseCRegion(CRegion region)
    {
        Rect rt = {
            .left = region.x,
            .top = region.y,
            .width = region.size.width,
            .height = region.size.height,
        };
        return rt;
    }

    //--------------------- ImageSource ------------------------------------------------------------------------
    static const std::string FILE_URL_PREFIX = "file://";
    static std::string FileUrlToRawPath(const std::string &path)
    {
        if (path.size() > FILE_URL_PREFIX.size() &&
            (path.compare(0, FILE_URL_PREFIX.size(), FILE_URL_PREFIX) == 0)) {
            return path.substr(FILE_URL_PREFIX.size());
        }
        return path;
    }

    int64_t FfiOHOSCreateImageSourceByPath(char *uri, uint32_t* errCode)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByPath start");
        std::string path = FileUrlToRawPath(uri);
        std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSource(path, errCode);
        if (*errCode != SUCCESS_CODE) {
            IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByPath failed");
            return INIT_FAILED;
        }
        auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
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
        IMAGE_LOGD("[ImageSource] SourceOptions height is %{public}d, width is %{public}d",
            options.size.height, options.size.width);
        return options;
    }

    int64_t FfiOHOSCreateImageSourceByPathWithOption(char* uri, CSourceOptions opts, uint32_t* errCode)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByPathWithOption start");
        std::string path = FileUrlToRawPath(uri);
        SourceOptions options = ParseCSourceOptions(opts);
        std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSourceWithOption(path, options, errCode);
        if (*errCode != SUCCESS_CODE) {
            IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByPathWithOption failed");
            return INIT_FAILED;
        }
        auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
        nativeImage->SetPathName(path);
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByPathWithOption success");
        return nativeImage->GetID();
    }

    int64_t FfiOHOSCreateImageSourceByFd(int fd, uint32_t* errCode)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByFd start");
        std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSource(fd, errCode);
        if (*errCode != SUCCESS_CODE) {
            IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByFd failed");
            return INIT_FAILED;
        }
        auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
        nativeImage->SetFd(fd);
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByFd success");
        return nativeImage->GetID();
    }

    int64_t FfiOHOSCreateImageSourceByFdWithOption(int fd, CSourceOptions opts, uint32_t* errCode)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByFdWithOption start");
        SourceOptions options = ParseCSourceOptions(opts);
        std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSourceWithOption(fd, options, errCode);
        if (*errCode != SUCCESS_CODE) {
            IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByFdWithOption failed");
            return INIT_FAILED;
        }
        auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
        nativeImage->SetFd(fd);
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByFdWithOption success");
        return nativeImage->GetID();
    }

    int64_t FfiOHOSCreateImageSourceByBuffer(uint8_t *data, uint32_t size, uint32_t* errCode)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByBuffer start");
        std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSource(data, size, errCode);
        if (*errCode != SUCCESS_CODE) {
            IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByBuffer failed");
            return INIT_FAILED;
        }
        auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
        nativeImage->SetBuffer(data, size);
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByBuffer success");
        return nativeImage->GetID();
    }

    int64_t FfiOHOSCreateImageSourceByBufferWithOption(uint8_t *data, uint32_t size, CSourceOptions opts,
        uint32_t* errCode)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByBufferWithOption start");
        SourceOptions options = ParseCSourceOptions(opts);
        std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSourceWithOption(data, size, options, errCode);
        if (*errCode != SUCCESS_CODE) {
            IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByBufferWithOption failed");
            return INIT_FAILED;
        }
        auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
        nativeImage->SetBuffer(data, size);
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByBufferWithOption success");
        return nativeImage->GetID();
    }

    int64_t FfiOHOSCreateImageSourceByRawFile(int fd, int32_t offset,
        int32_t length, CSourceOptions opts, uint32_t* errCode)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByRawFile start");
        SourceOptions options = ParseCSourceOptions(opts);
        std::unique_ptr<ImageSource> ptr_ = ImageSourceImpl::CreateImageSource(fd, offset, length, options, *errCode);
        if (*errCode != SUCCESS_CODE) {
            IMAGE_LOGE("[ImageSource] FfiOHOSCreateImageSourceByRawFile failed");
            return INIT_FAILED;
        }
        auto nativeImage = FFIData::Create<ImageSourceImpl>(move(ptr_));
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateImageSourceByRawFile success");
        return nativeImage->GetID();
    }

    int64_t FfiOHOSCreateIncrementalSource(const uint8_t *data, uint32_t size, CSourceOptions opts, uint32_t* errCode)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateIncrementalSource start");
        SourceOptions options = ParseCSourceOptions(opts);
        auto ptr = ImageSourceImpl::CreateIncrementalSource(data, size, options, *errCode);
        if (*errCode != SUCCESS_CODE) {
            return INIT_FAILED;
        }
        auto nativeImage = FFIData::Create<ImageSourceImpl>(move(std::get<0>(ptr)), move(std::get<1>(ptr)));
        IMAGE_LOGD("[ImageSource] FfiOHOSCreateIncrementalSource success");
        
        return nativeImage->GetID();
    }

    CImageInfo FfiOHOSImageSourceGetImageInfo(int64_t id, uint32_t index, uint32_t* errCode)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSImageSourceGetImageInfo start");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        auto instance = FFIData::GetData<ImageSourceImpl>(id);
        CImageInfo ret;
        if (!instance) {
            IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
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

    void FreeArrayPtr(char** ptr, int count)
    {
        for (int i = 0; i < count; i++) {
            free(ptr[i]);
        }
    }

    CArrString FfiOHOSGetSupportedFormats(int64_t id, uint32_t* errCode)
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
            size_t size =  formats.size();
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
            for (const std::string& str: formats) {
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

    char* FfiOHOSGetImageProperty(int64_t id, char* key, uint32_t index, char* defaultValue, uint32_t* errCode)
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
        ret = Utils::MallocCString(value);
        IMAGE_LOGD("[ImageSource] FfiOHOSGetImageProperty success");
        return ret;
    }

    uint32_t FfiOHOSModifyImageProperty(int64_t id, char* key, char* value)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSModifyImageProperty start");
        auto instance = FFIData::GetData<ImageSourceImpl>(id);
        if (!instance) {
            IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        uint32_t ret =  instance->ModifyImageProperty(key, value);
        IMAGE_LOGD("[ImageSource] FfiOHOSModifyImageProperty success");
        return ret;
    }

    RetDataUI32 FfiOHOSGetFrameCount(int64_t id)
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

    uint32_t FfiOHOSUpdateData(int64_t id, UpdateDataInfo info)
    {
        IMAGE_LOGD("[ImageSource] FfiOHOSUpdateData start");
        auto instance = FFIData::GetData<ImageSourceImpl>(id);
        if (!instance) {
            IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        uint8_t *buffer = info.data;
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

    uint32_t FfiOHOSRelease(int64_t id)
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

    static DecodeOptions ParseCDecodingOptions(CDecodingOptions &opts)
    {
        DecodeOptions decodeOpts;
        decodeOpts.fitDensity = opts.fitDensity;
        decodeOpts.desiredSize.height = opts.desiredSize.height;
        decodeOpts.desiredSize.width = opts.desiredSize.width;
        IMAGE_LOGD("[ImageSource] desiredSize height is %{public}d, width is %{public}d",
            decodeOpts.desiredSize.height, decodeOpts.desiredSize.width);
        decodeOpts.desiredRegion.height = opts.desiredRegion.size.height;
        decodeOpts.desiredRegion.width = opts.desiredRegion.size.width;
        decodeOpts.desiredRegion.left = opts.desiredRegion.x;
        decodeOpts.desiredRegion.top = opts.desiredRegion.y;
        IMAGE_LOGD("[ImageSource] desiredRegion height is %{public}d, width is %{public}d," \
            "left is %{public}d, top is %{public}d",
            decodeOpts.desiredRegion.height, decodeOpts.desiredRegion.width,
            decodeOpts.desiredRegion.left, decodeOpts.desiredRegion.top);
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

    CArrI64 FfiOHOSImageSourceCreatePixelMapList(int64_t id, uint32_t index, CDecodingOptions opts,
        uint32_t* errorCode)
    {
        IMAGE_LOGD("[ImageSource] CreatePixelMapList start");
        CArrI64 ret = {.head = nullptr, .size = 0 };
        auto instance = FFIData::GetData<ImageSourceImpl>(id);
        if (!instance) {
            IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
            *errorCode = ERR_IMAGE_INIT_ABNORMAL;
            return ret;
        }
        DecodeOptions decodeOpts = ParseCDecodingOptions(opts);
        std::vector<int64_t> data = instance->CreatePixelMapList(index, decodeOpts, errorCode);
        if (*errorCode == SUCCESS_CODE) {
            auto size = data.size();
            if (size == 0) {
                *errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
                IMAGE_LOGE("[ImageSource] CreatePixelMapList size error.");
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
        IMAGE_LOGD("[ImageSource] CreatePixelMapList success");
        return ret;
    }

    CArrI32 FfiOHOSImageSourceGetDelayTime(int64_t id, uint32_t* errorCode)
    {
        IMAGE_LOGD("[ImageSource] GetDelayTime start");
        CArrI32 ret = {.head = nullptr, .size = 0 };
        auto instance = FFIData::GetData<ImageSourceImpl>(id);
        if (!instance) {
            IMAGE_LOGE("[ImageSource] instance not exist %{public}" PRId64, id);
            *errorCode = ERR_IMAGE_INIT_ABNORMAL;
            return ret;
        }
        auto data = instance->GetDelayTime(errorCode);
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
        IMAGE_LOGD("[ImageSource] GetDelayTime success");
        return ret;
    }

    RetDataI64U32 FfiOHOSImageSourceCreatePixelMap(int64_t id, uint32_t index, CDecodingOptions &opts)
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

    //--------------------- PixelMap ---------------------------------------------------------------------------

    int64_t FfiOHOSCreatePixelMap(uint8_t *colors, uint32_t colorLength, CInitializationOptions opts)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSCreatePixelMap start");
        InitializationOptions option;
        option.alphaType = AlphaType(opts.alphaType);
        option.editable = opts.editable;
        option.pixelFormat = PixelFormat(opts.pixelFormat);
        option.scaleMode = ScaleMode(opts.scaleMode);
        option.size.height = opts.height;
        option.size.width = opts.width;
        std::unique_ptr<PixelMap> ptr_ =
            PixelMapImpl::CreatePixelMap(reinterpret_cast<uint32_t*>(colors), colorLength, option);
        if (!ptr_) {
            return INIT_FAILED;
        }
        auto nativeImage = FFIData::Create<PixelMapImpl>(move(ptr_));
        IMAGE_LOGD("[PixelMap] FfiOHOSCreatePixelMap success");
        return nativeImage->GetID();
    }

    uint32_t FfiOHOSPixelMapRelease(int64_t id)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSRelease start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        std::shared_ptr<PixelMap> ptr_ = instance->GetRealPixelMap();
        ptr_.reset();
        IMAGE_LOGD("[PixelMap] FfiOHOSRelease success");
        return SUCCESS_CODE;
    }

    int64_t FfiOHOSCreateAlphaPixelMap(int64_t id, uint32_t* errCode)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSCreateAlphaPixelMap start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance) {
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return 0;
        }
        std::shared_ptr<PixelMap> ptr_ = instance->GetRealPixelMap();
        if (!ptr_) {
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            IMAGE_LOGE("[PixelMap] ptr is nullptr!");
            return 0;
        }
        InitializationOptions opts;
        opts.pixelFormat = PixelFormat::ALPHA_8;
        auto tmpPixelMap = PixelMapImpl::CreateAlphaPixelMap(*ptr_, opts);
        if (!tmpPixelMap) {
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            IMAGE_LOGE("[PixelMap] tmpPixelMap is nullptr!");
            return 0;
        }
        auto nativeImage = FFIData::Create<PixelMapImpl>(move(tmpPixelMap));
        IMAGE_LOGD("[PixelMap] FfiOHOSCreateAlphaPixelMap success");
        *errCode = SUCCESS_CODE;
        return nativeImage->GetID();
    }

    uint32_t FfiOHOSReadPixelsToBuffer(int64_t id, uint64_t bufferSize, uint8_t *dst)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSReadPixelsToBuffer start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        uint32_t ret = instance->ReadPixelsToBuffer(bufferSize, dst);
        IMAGE_LOGD("[PixelMap] FfiOHOSReadPixelsToBuffer success");
        return ret;
    }

    uint32_t FfiOHOSWriteBufferToPixels(int64_t id, uint8_t *source, uint64_t bufferSize)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSWriteBufferToPixels start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        uint32_t ret = instance->WriteBufferToPixels(source, bufferSize);
        IMAGE_LOGD("[PixelMap] FfiOHOSWriteBufferToPixels success");
        return ret;
    }

    int32_t FfiOHOSGetDensity(int64_t id, uint32_t* errCode)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSGetDensity start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            return 0;
        }
        int32_t ret = instance->GetDensity();
        *errCode = SUCCESS_CODE;
        IMAGE_LOGD("[PixelMap] FfiOHOSGetDensity success");
        return ret;
    }

    uint32_t FfiOHOSOpacity(int64_t id, float percent)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSOpacity start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        uint32_t ret = instance->Opacity(percent);
        IMAGE_LOGD("[PixelMap] FfiOHOSOpacity success");
        return ret;
    }

    uint32_t FfiOHOSCrop(int64_t id, CRegion rect)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSCrop start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        Rect rt;
        rt.left = rect.x;
        rt.top = rect.y;
        rt.width = rect.size.width;
        rt.height = rect.size.height;
        uint32_t ret = instance->Crop(rt);
        IMAGE_LOGD("[PixelMap] FfiOHOSCrop success");
        return ret;
    }

    uint32_t FfiOHOSGetPixelBytesNumber(int64_t id, uint32_t* errCode)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSGetPixelBytesNumber start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            return 0;
        }
        uint32_t ret = instance->GetPixelBytesNumber();
        *errCode = SUCCESS_CODE;
        IMAGE_LOGD("[PixelMap] FfiOHOSGetPixelBytesNumber success");
        return ret;
    }

    uint32_t FfiOHOSGetBytesNumberPerRow(int64_t id, uint32_t* errCode)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSGetBytesNumberPerRow start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            return 0;
        }
        uint32_t ret = instance->GetBytesNumberPerRow();
        *errCode = SUCCESS_CODE;
        IMAGE_LOGD("[PixelMap] FfiOHOSGetBytesNumberPerRow success");
        return ret;
    }

    CImageInfo FfiOHOSGetImageInfo(int64_t id, uint32_t* errCode)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSGetImageInfo start");
        CImageInfo ret;
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ret;
        }
        ImageInfo info;
        instance->GetImageInfo(info);
        ret.height = info.size.height;
        ret.width = info.size.width;
        ret.density = info.baseDensity;
        *errCode = SUCCESS_CODE;
        IMAGE_LOGD("[PixelMap] FfiOHOSGetImageInfo success");
        return ret;
    }

    uint32_t FfiOHOSScale(int64_t id, float xAxis, float yAxis)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSScale start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        instance->Scale(xAxis, yAxis);
        IMAGE_LOGD("[PixelMap] FfiOHOSScale success");
        return SUCCESS_CODE;
    }

    uint32_t FfiOHOSFlip(int64_t id, bool xAxis, bool yAxis)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSFlip start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        instance->Flip(xAxis, yAxis);
        IMAGE_LOGD("[PixelMap] FfiOHOSFlip success");
        return SUCCESS_CODE;
    }

    uint32_t FfiOHOSRotate(int64_t id, float degrees)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSRotate start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        instance->Rotate(degrees);
        IMAGE_LOGD("[PixelMap] FfiOHOSRotate success");
        return SUCCESS_CODE;
    }

    uint32_t FfiOHOSTranslate(int64_t id, float xAxis, float yAxis)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSTranslate start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        instance->Translate(xAxis, yAxis);
        IMAGE_LOGD("[PixelMap] FfiOHOSTranslate success");
        return SUCCESS_CODE;
    }

    uint32_t FfiOHOSReadPixels(int64_t id, CPositionArea area)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSReadPixels start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        Rect rt = ParseCRegion(area.region);
        uint32_t ret = instance->ReadPixels(area.bufferSize, area.offset, area.stride, rt, area.dst);
        IMAGE_LOGD("[PixelMap] FfiOHOSReadPixels success");
        return ret;
    }

    uint32_t FfiOHOSWritePixels(int64_t id, CPositionArea area)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSWritePixels start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        Rect rt = ParseCRegion(area.region);
        uint32_t ret = instance->WritePixels(area.dst, area.bufferSize, area.offset, area.stride, rt);
        IMAGE_LOGD("[PixelMap] FfiOHOSWritePixels success");
        return ret;
    }

    bool FfiOHOSGetIsEditable(int64_t id, uint32_t* errCode)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSGetIsEditable start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        bool ret = false;
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            return ret;
        }
        ret = instance->GetIsEditable();
        *errCode = SUCCESS_CODE;
        IMAGE_LOGD("[PixelMap] FfiOHOSGetIsEditable success");
        return ret;
    }

    bool FfiOHOSGetIsStrideAlignment(int64_t id, uint32_t* errCode)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSGetIsStrideAlignment start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        bool ret = false;
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            return ret;
        }
        ret = instance->GetIsStrideAlignment();
        *errCode = SUCCESS_CODE;
        IMAGE_LOGD("[PixelMap] FfiOHOSGetIsStrideAlignment success");
        return ret;
    }

    uint32_t FfiOHOSPixelMapSetColorSpace(int64_t id, int64_t colorSpaceId)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapSetColorSpace start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] PixelMapImpl instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        auto colorSpace = FFIData::GetData<ColorManager::CjColorManager>(colorSpaceId);
        if (!colorSpace) {
            IMAGE_LOGE("[PixelMap] CjColorManager instance not exist %{public}" PRId64, colorSpaceId);
            return ERR_IMAGE_INVALID_PARAMETER;
        }
        uint32_t ret = instance->SetColorSpace(colorSpace->GetColorSpaceToken());
        IMAGE_LOGD("[PixelMap] FFfiOHOSPixelMapSetColorSpace success");
        return ret;
    }

    int64_t FfiOHOSPixelMapGetColorSpace(int64_t id, int32_t* errCode)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapGetColorSpace start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            *errCode = ERR_IMAGE_DATA_ABNORMAL;
            return 0;
        }
        auto colorSpace = instance->GetColorSpace();
        if (!colorSpace) {
            *errCode = ERR_IMAGE_DATA_UNSUPPORT;
            return 0;
        }
        auto native = FFIData::Create<ColorManager::CjColorManager>(colorSpace);
        if (!native) {
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            return 0;
        }
        
        IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapGetColorSpace success");
        *errCode = SUCCESS_CODE;
        return native->GetID();
    }

    uint32_t FfiOHOSPixelMapApplyColorSpace(int64_t id, int64_t colorSpaceId)
    {
        IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapApplyColorSpace start");
        auto instance = FFIData::GetData<PixelMapImpl>(id);
        if (!instance || !instance->GetRealPixelMap()) {
            IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        auto colorSpace = FFIData::GetData<ColorManager::CjColorManager>(colorSpaceId);
        if (!colorSpace) {
            IMAGE_LOGE("[PixelMap] CjColorManager instance not exist %{public}" PRId64, colorSpaceId);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        uint32_t ret = instance->ApplyColorSpace(colorSpace->GetColorSpaceToken());
        IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapApplyColorSpace success");
        return ret;
    }

    //--------------------- ImageReceiver ------------------------------------------------------------------------

    uint32_t FfiOHOSReceiverGetSize(int64_t id, CSize *retVal)
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

    uint32_t FfiOHOSReceiverGetCapacity(int64_t id, int32_t *retVal)
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

    uint32_t FfiOHOSReceiverGetFormat(int64_t id, int32_t *retVal)
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

    int64_t FfiOHOSCreateImageReceiver(int32_t width, int32_t height, int32_t format, int32_t capacity)
    {
        IMAGE_LOGD("FfiOHOSCreateImageReceiver start");
        auto id = ImageReceiverImpl::CreateImageReceiver(width, height, format, capacity);
        IMAGE_LOGD("FfiOHOSCreateImageReceiver success");
        return id;
    }

    char* FfiOHOSGetReceivingSurfaceId(int64_t id)
    {
        IMAGE_LOGD("FfiOHOSGetReceivingSurfaceId start");
        auto instance = FFIData::GetData<ImageReceiverImpl>(id);
        if (!instance) {
            IMAGE_LOGE("ImageReceiver instance not exist %{public}" PRId64, id);
            return nullptr;
        }
        char *ret = instance->GetReceivingSurfaceId();
        IMAGE_LOGD("FfiOHOSGetReceivingSurfaceId success");
        return ret;
    }

    int64_t FfiOHOSReadNextImage(int64_t id)
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

    int64_t FfiOHOSReadLatestImage(int64_t id)
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

    void FfiOHOSReceiverRelease(int64_t id)
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

    uint32_t FfiOHOSImageGetClipRect(int64_t id, CRegion *retVal)
    {
        IMAGE_LOGD("FfiOHOSImageGetClipRect start");
        auto instance = FFIData::GetData<ImageImpl>(id);
        if (!instance) {
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        int64_t retCode = instance->GetClipRect(retVal);
        IMAGE_LOGD("FfiOHOSImageGetClipRect success");
        return retCode;
    }

    uint32_t FfiOHOSImageGetSize(int64_t id, CSize *retVal)
    {
        IMAGE_LOGD("FfiOHOSImageGetSize start");
        auto instance = FFIData::GetData<ImageImpl>(id);
        if (!instance) {
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        uint32_t retCode = instance->GetSize(retVal);
        IMAGE_LOGD("FfiOHOSImageGetSize success");
        return retCode;
    }

    uint32_t FfiOHOSImageGetFormat(int64_t id, int32_t *retVal)
    {
        IMAGE_LOGD("FfiOHOSImageGetFormat start");
        auto instance = FFIData::GetData<ImageImpl>(id);
        if (!instance) {
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        uint32_t retCode = instance->GetFormat(retVal);
        IMAGE_LOGD("FfiOHOSImageGetFormat success");
        return retCode;
    }

    uint32_t FfiOHOSGetComponent(int64_t id, int32_t componentType, CRetComponent *ptr)
    {
        IMAGE_LOGD("FfiOHOSGetComponent start");
        auto instance = FFIData::GetData<ImageImpl>(id);
        if (!instance) {
            IMAGE_LOGE("ImageImpl instance not exist %{public}" PRId64, id);
            return ERR_IMAGE_INIT_ABNORMAL;
        }
        uint32_t errCode = instance->GetComponent(componentType, ptr);
        IMAGE_LOGD("FfiOHOSGetComponent success");
        return errCode;
    }

    void FfiOHOSImageRelease(int64_t id)
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

    //--------------------- ImagePacker ---------------------------------------------------------------------------
    int64_t FFiOHOSImagePackerConstructor()
    {
        auto ret = FFIData::Create<ImagePackerImpl>();
        return ret->GetID();
    }

    RetDataCArrUI8 FfiOHOSImagePackerPackingPixelMap(int64_t id, int64_t source, CPackingOption option)
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
            PackOption packOption = { .format = option.format, .quality = option.quality};
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

    RetDataCArrUI8 FfiOHOSImagePackerPackingImageSource(int64_t id, int64_t source, CPackingOption option)
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
            PackOption packOption = { .format = option.format, .quality = option.quality};
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

    RetDataCArrString FfiOHOSImagePackerGetSupportedFormats(int64_t id)
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

    uint32_t FfiOHOSImagePackerPackPixelMapToFile(int64_t id, int64_t source, int fd, CPackingOption option)
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
            
            PackOption packOption = { .format = option.format, .quality = option.quality};
            uint32_t ret = imagePackerImpl->PackToFile(*pixelMap, fd, packOption);
            return ret;
        }
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    uint32_t FfiOHOSImagePackerImageSourcePackToFile(int64_t id, int64_t source, int fd, CPackingOption option)
    {
        auto imagePackerImpl = FFIData::GetData<ImagePackerImpl>(id);
        if (!imagePackerImpl) {
            IMAGE_LOGE("Packing failed, invalid id of ImagePackerImpl");
            return ERR_IMAGE_INIT_ABNORMAL;
        }

        auto imageSourceImpl = FFIData::GetData<ImageSourceImpl>(source);
        if (imageSourceImpl != nullptr) {
            PackOption packOption = { .format = option.format, .quality = option.quality};
            auto imageSource = imageSourceImpl->nativeImgSrc;
            if (!imageSource) {
                return ERR_IMAGE_INIT_ABNORMAL;
            }
            
            uint32_t ret = imagePackerImpl->PackToFile(*imageSource, fd, packOption);
            return ret;
        }
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    uint64_t FfiOHOSGetPackOptionSize()
    {
        return sizeof(PackOption);
    }

    void FFiOHOSImagePackerRelease(int64_t id)
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
    int64_t FFiOHOSImageCreatorConstructor(int32_t width, int32_t height, int32_t format, int32_t capacity)
    {
        auto ret = FFIData::Create<ImageCreatorImpl>(width, height, format, capacity);
        return ret->GetID();
    }

    RetDataI32 FFiOHOSImageCreatorGetCapacity(int64_t id)
    {
        IMAGE_LOGD("FFiOHOSImageCreatorGetCapacity start");
        RetDataI32 ret = {.code = ERR_IMAGE_INIT_ABNORMAL, .data = 0};
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

    RetDataI32 FFiOHOSImageCreatorGetformat(int64_t id)
    {
        IMAGE_LOGD("FFiOHOSImageCreatorGetformat start");
        RetDataI32 ret = {.code = ERR_IMAGE_INIT_ABNORMAL, .data = 0};
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

        ret.data = context->GetFormat();
        ret.code = SUCCESS_CODE;
        IMAGE_LOGD("FFiOHOSImageCreatorGetformat success");
        return ret;
    }

    int64_t FFiOHOSImageCreatorDequeueImage(int64_t id, uint32_t* errCode)
    {
        IMAGE_LOGD("FFiOHOSImageCreatorDequeueImage start");
        auto instance = FFIData::GetData<ImageCreatorImpl>(id);
        if (!instance) {
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            return -1;
        }
        
        std::shared_ptr<ImageCreator> imageCreator = instance->GetImageCreator();
        if (!imageCreator) {
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            return -1;
        }
        std::shared_ptr<NativeImage> nativeImageRes = imageCreator->DequeueNativeImage();
        if (!nativeImageRes) {
            *errCode = ERR_IMAGE_INIT_ABNORMAL;
            return -1;
        }
        auto ret = FFIData::Create<ImageImpl>(nativeImageRes);
        *errCode = SUCCESS_CODE;
        return ret->GetID();
    }

    void FFiOHOSImageCreatorQueueImage(int64_t id, int64_t imageId)
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

    void FFiOHOSImageCreatorRelease(int64_t id)
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
}
}
}