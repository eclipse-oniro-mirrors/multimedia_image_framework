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
#include "image_source_impl.h"
#include "image_log.h"
#include "file_source_stream.h"
#include "image_source.h"
#include "media_errors.h"
#include "string_ex.h"
#include "pixel_map_impl.h"
#include "image_ffi.h"
 
namespace OHOS {
namespace Media {
const uint32_t NUM_2 = 2;
const uint32_t NUM_3 = 3;
const long int NUM_8 = 8;
const int DECIMAL_BASE = 10;


std::unique_ptr<ImageSource> ImageSourceImpl::CreateImageSource(std::string uri, uint32_t* errCode)
{
    SourceOptions opts;
    std::unique_ptr<ImageSource> ptr_ = ImageSource::CreateImageSource(uri, opts, *errCode);
    return ptr_;
}

std::unique_ptr<ImageSource> ImageSourceImpl::CreateImageSourceWithOption(std::string uri, SourceOptions &opts,
    uint32_t* errCode)
{
    std::unique_ptr<ImageSource> ptr_ = ImageSource::CreateImageSource(uri, opts, *errCode);
    return ptr_;
}

std::unique_ptr<ImageSource> ImageSourceImpl::CreateImageSource(int fd, uint32_t* errCode)
{
    SourceOptions opts;
    std::unique_ptr<ImageSource> ptr_ = ImageSource::CreateImageSource(fd, opts, *errCode);
    return ptr_;
}

std::unique_ptr<ImageSource> ImageSourceImpl::CreateImageSourceWithOption(int fd, SourceOptions &opts,
    uint32_t* errCode)
{
    std::unique_ptr<ImageSource> ptr_ = ImageSource::CreateImageSource(fd, opts, *errCode);
    return ptr_;
}

std::unique_ptr<ImageSource> ImageSourceImpl::CreateImageSource(uint8_t *data, uint32_t size, uint32_t* errCode)
{
    SourceOptions opts;
    std::unique_ptr<ImageSource> ptr_ = ImageSource::CreateImageSource(data, size, opts, *errCode);
    return ptr_;
}

std::unique_ptr<ImageSource> ImageSourceImpl::CreateImageSourceWithOption(uint8_t *data, uint32_t size,
    SourceOptions &opts, uint32_t* errCode)
{
    std::unique_ptr<ImageSource> ptr_ = ImageSource::CreateImageSource(data, size, opts, *errCode);
    return ptr_;
}

std::unique_ptr<ImageSource> ImageSourceImpl::CreateImageSource(const int fd, int32_t offset,
    int32_t length, const SourceOptions &opts, uint32_t &errorCode)
{
    int32_t fileSize = offset + length;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(fd,
        offset, fileSize, opts, errorCode);
    return imageSource;
}

std::tuple<std::unique_ptr<ImageSource>, std::unique_ptr<IncrementalPixelMap>> ImageSourceImpl::CreateIncrementalSource(
    const uint8_t *data, uint32_t size, SourceOptions &opts, uint32_t &errorCode)
{
    IncrementalSourceOptions incOpts;
    incOpts.sourceOptions = opts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    
    DecodeOptions decodeOpts;
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(0, decodeOpts,
        errorCode);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("CreateIncrementalImageSource error.");
        return std::make_tuple(nullptr, nullptr);
    }
    return std::make_tuple(move(imageSource), move(incPixelMap));
}

ImageSourceImpl::ImageSourceImpl(std::unique_ptr<ImageSource> imageSource)
{
    nativeImgSrc = move(imageSource);
}

ImageSourceImpl::ImageSourceImpl(std::unique_ptr<ImageSource> imageSource,
    std::unique_ptr<IncrementalPixelMap> pixelMap)
{
    nativeImgSrc = move(imageSource);
    navIncPixelMap_ = move(pixelMap);
}

uint32_t ImageSourceImpl::GetImageInfo(uint32_t index, ImageInfo &imageInfo)
{
    if (nativeImgSrc == nullptr) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    IMAGE_LOGI("[ImageSourceImpl] GetImageInfo start.");
    return nativeImgSrc->GetImageInfo(index, imageInfo);
}

uint32_t ImageSourceImpl::GetSupportedFormats(std::set<std::string> &formats)
{
    if (nativeImgSrc == nullptr) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    IMAGE_LOGI("[ImageSourceImpl] GetSupportedFormats start.");
    return nativeImgSrc->GetSupportedFormats(formats);
}

uint32_t ImageSourceImpl::GetImageProperty(std::string key, uint32_t index, std::string &defaultValue)
{
    if (nativeImgSrc == nullptr) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    IMAGE_LOGI("[ImageSourceImpl] GetImageProperty start.");
    index_ = index;
    return nativeImgSrc->GetImagePropertyString(index, key, defaultValue);
}

static bool CheckExifDataValue(const std::string &value)
{
    std::vector<std::string> bitsVec;
    SplitStr(value, ",", bitsVec);
    if (bitsVec.size() > NUM_3) {
        return false;
    }
    for (size_t i = 0; i < bitsVec.size(); i++) {
        if (!IsNumericStr(bitsVec[i])) {
            return false;
        }
    }
    return true;
}

static bool CheckOrientation(const std::string &value)
{
    long int num;
    char *endptr;
    num = strtol(value.c_str(), &endptr, DECIMAL_BASE);
    if (*endptr != '\0') {
        return false;
    }
    if (!IsNumericStr(value) || num < 1 || num > NUM_8) {
        return false;
    }
    return true;
}

static bool CheckGPS(const std::string &value)
{
    std::vector<std::string> gpsVec;
    SplitStr(value, ",", gpsVec);
    if (gpsVec.size() != NUM_2) {
        return false;
    }

    for (size_t i = 0; i < gpsVec.size(); i++) {
        if (!IsNumericStr(gpsVec[i])) {
            return false;
        }
    }
    return true;
}

static bool CheckExifDataValue(const std::string &key, const std::string &value)
{
    if (IsSameTextStr(key, "BitsPerSample")) {
        return CheckExifDataValue(value);
    } else if (IsSameTextStr(key, "Orientation")) {
        return CheckOrientation(value);
    } else if (IsSameTextStr(key, "ImageLength") || IsSameTextStr(key, "ImageWidth")) {
        if (!IsNumericStr(value)) {
            return false;
        }
    } else if (IsSameTextStr(key, "GPSLatitude") || IsSameTextStr(key, "GPSLongitude")) {
        return CheckGPS(value);
    } else if (IsSameTextStr(key, "GPSLatitudeRef")) {
        if (!IsSameTextStr(value, "N") && !IsSameTextStr(value, "S")) {
            return false;
        }
    } else if (IsSameTextStr(key, "GPSLongitudeRef")) {
        if (!IsSameTextStr(value, "W") && !IsSameTextStr(value, "E")) {
            return false;
        }
    }
    return true;
}

uint32_t ImageSourceImpl::ModifyImageProperty(std::string key, std::string value)
{
    if (nativeImgSrc == nullptr) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    IMAGE_LOGI("[ImageSourceImpl] ModifyImageProperty start.");
    uint32_t ret = ERR_MEDIA_INVALID_VALUE;
    if (!CheckExifDataValue(key, value)) {
        IMAGE_LOGE("There is invalid exif data parameter");
        ret = ERR_MEDIA_VALUE_INVALID;
        return ret;
    }
    if (!IsSameTextStr(pathName_, "")) {
        ret = nativeImgSrc->ModifyImageProperty(index_, key, value, pathName_);
    } else if (fd_ != -1) {
        ret = nativeImgSrc->ModifyImageProperty(index_, key, value, fd_);
    } else if (buffer_ != nullptr) {
        ret = nativeImgSrc->ModifyImageProperty(index_, key, value, buffer_, bufferSize_);
    } else {
        IMAGE_LOGE("[ImageSourceImpl] There is no image source!");
    }
    return ret;
}

uint32_t ImageSourceImpl::GetFrameCount(uint32_t &errorCode)
{
    if (nativeImgSrc == nullptr) {
        errorCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    IMAGE_LOGI("[ImageSourceImpl] GetFrameCount start.");
    return nativeImgSrc->GetFrameCount(errorCode);
}

uint32_t ImageSourceImpl::UpdateData(uint8_t *data, uint32_t size, bool isCompleted)
{
    if (nativeImgSrc == nullptr) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    IMAGE_LOGI("[ImageSourceImpl] UpdateData start.");
    return nativeImgSrc->UpdateData(data, size, isCompleted);
}

int64_t ImageSourceImpl::CreatePixelMap(uint32_t index, DecodeOptions &opts, uint32_t &errorCode)
{
    if (nativeImgSrc == nullptr) {
        errorCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    IMAGE_LOGI("[ImageSourceImpl] CreatePixelMap start.");
    std::shared_ptr<PixelMap> incPixelMap;
    incPixelMap = GetIncrementalPixelMap();
    if (incPixelMap != nullptr) {
        errorCode = 0;
        IMAGE_LOGI("Get Incremental PixelMap!!!");
    } else {
        IMAGE_LOGI("Create PixelMap!!!");
        incPixelMap = nativeImgSrc->CreatePixelMapEx(index, opts, errorCode);
        if (incPixelMap == nullptr) {
            IMAGE_LOGE("[ImageSourceImpl] Create PixelMap error.");
        }
    }
    
    auto nativeImage = FFIData::Create<PixelMapImpl>(move(incPixelMap));
    IMAGE_LOGI("[ImageSourceImpl] CreatePixelMap success.");
    return nativeImage->GetID();
}

std::vector<int64_t> ImageSourceImpl::CreatePixelMapList(uint32_t index, DecodeOptions opts, uint32_t* errorCode)
{
    std::vector<int64_t> ret;
    if (nativeImgSrc == nullptr) {
        *errorCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    IMAGE_LOGI("[ImageSourceImpl] CreatePixelMapList start.");
    uint32_t frameCount = nativeImgSrc->GetFrameCount(*errorCode);
    
    std::unique_ptr<std::vector<std::unique_ptr<PixelMap>>> pixelMaps;
    if ((*errorCode == SUCCESS) && (index >= 0) && (index < frameCount)) {
        pixelMaps = nativeImgSrc->CreatePixelMapList(opts, *errorCode);
    }
    for (size_t i = 0; i < pixelMaps->size(); i++) {
        std::unique_ptr<PixelMap> pixelmap = move(pixelMaps->operator[](i));
        auto nativeImage = FFIData::Create<PixelMapImpl>(move(pixelmap));
        ret.push_back(nativeImage->GetID());
    }
    IMAGE_LOGI("[ImageSourceImpl] CreatePixelMapList success.");
    return ret;
}

std::unique_ptr<std::vector<int32_t>> ImageSourceImpl::GetDelayTime(uint32_t* errorCode)
{
    std::unique_ptr<std::vector<int32_t>> delayTimes;
    if (nativeImgSrc == nullptr) {
        *errorCode = ERR_IMAGE_INIT_ABNORMAL;
        return delayTimes;
    }
    IMAGE_LOGI("[ImageSourceImpl] GetDelayTime start.");
    delayTimes = nativeImgSrc->GetDelayTime(*errorCode);
    IMAGE_LOGI("[ImageSourceImpl] GetDelayTime success.");
    return delayTimes;
}

void ImageSourceImpl::SetPathName(std::string pathName)
{
    pathName_ = pathName;
}

void ImageSourceImpl::SetFd(int fd)
{
    fd_ = fd;
}

void ImageSourceImpl::SetBuffer(uint8_t *data, uint32_t size)
{
    buffer_ = data;
    bufferSize_ = size;
}
}
}