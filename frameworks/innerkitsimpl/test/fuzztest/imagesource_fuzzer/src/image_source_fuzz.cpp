/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "image_source_fuzz.h"

#define private public
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>

#include "securec.h"
#include "image_source.h"

namespace OHOS {
namespace Media {
void ImageSourceFuncTest001(std::unique_ptr<ImageSource>& imageSource)
{
    std::set<std::string> formats;
    imageSource->GetSupportedFormats(formats);
    imageSource->GetDecodeEvent();
    std::string key = "ImageWidth";
    std::string value = "500";
    int32_t valueInt = 0;
    uint32_t errCode = 0;
    imageSource->ModifyImageProperty(key, value);
    imageSource->ModifyImageProperty(nullptr, key, value);
    imageSource->ModifyImageProperty(0, key, value, "");
    imageSource->ModifyImageProperty(0, key, value, 0);
    imageSource->ModifyImageProperty(0, key, value, nullptr, 0);
    imageSource->GetImagePropertyCommon(0, key, value);
    imageSource->GetImagePropertyInt(0, key, valueInt);
    imageSource->GetImagePropertyString(0, key, value);
    imageSource->GetSourceInfo(errCode);
    imageSource->RegisterListener(nullptr);
    imageSource->UnRegisterListener(nullptr);
    imageSource->AddDecodeListener(nullptr);
    imageSource->RemoveDecodeListener(nullptr);
    imageSource->IsStreamCompleted();
    auto agentIter = imageSource->formatAgentMap_.begin();
    imageSource->CheckEncodedFormat(*(agentIter->second));
    imageSource->CheckFormatHint(key, agentIter);
    imageSource->DecodeSourceInfo(false);
    imageSource->DecodeSourceInfo(true);
    imageSource->CreateDecoder(errCode);
    DecodeOptions opts;
    DecodeOptions procOpts;
    PixelMap pixelMap;
    imageSource->CopyOptionsToProcOpts(opts, procOpts, pixelMap);
    MemoryUsagePreference preference = MemoryUsagePreference::LOW_RAM;
    imageSource->SetMemoryUsagePreference(preference);
    imageSource->ImageSizeChange(1, 1, 1, 1);
    Rect cropRect;
    ImageInfo imageInfo;
    imageSource->ImageConverChange(cropRect, imageInfo, imageInfo);
    imageSource->CreatePixelMapForYUV(errCode);
    imageSource->CreatePixelMapList(opts, errCode);
    imageSource->GetDelayTime(errCode);
    imageSource->GetDisposalType(errCode);
    imageSource->GetFrameCount(errCode);
}

void CreateImageSourceByDataFuzz(const uint8_t* data, size_t size)
{
    uint8_t dest[size + 1];
    int ret = memcpy_s(dest, sizeof(dest), data, size);
    if (ret != 0) {
        return;
    }
    dest[sizeof(dest) - 1] = '\0';
    Media::SourceOptions opts;
    uint32_t errorCode;
    auto imagesource = Media::ImageSource::CreateImageSource(dest, sizeof(dest), opts, errorCode);
    ImageSourceFuncTest001(imagesource);
    Media::DecodeOptions dopts;
    imagesource->CreatePixelMap(dopts, errorCode);
    imagesource->Reset();
}

void CreateImageSourceByFDEXFuzz(const uint8_t* data, size_t size)
{
    Media::SourceOptions opts;
    uint32_t errorCode;
    uint32_t offset = 0;
    uint32_t length = 1;
    std::string pathName = "/data/local/tmp/test2.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        return;
    }
    auto imagesource = Media::ImageSource::CreateImageSource(fd, offset, length, opts, errorCode);
    Media ::DecodeOptions dopts;
    imagesource->CreatePixelMap(dopts, errorCode);
    close(fd);
}

void CreateImageSourceByIstreamFuzz(const uint8_t* data, size_t size)
{
    std::string pathName = "/data/local/tmp/test1.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return;
    }
    std::unique_ptr<std::istream> is = std::make_unique<std::ifstream>(pathName.c_str());
    Media::SourceOptions opts;
    uint32_t errorCode;
    Media ::DecodeOptions dopts;
    auto imagesource = Media::ImageSource::CreateImageSource(std::move(is), opts, errorCode);
    if (imagesource != nullptr) {
        imagesource->CreatePixelMap(dopts, errorCode);
    }
    close(fd);
}

void CreateImageSourceByPathNameFuzz(const uint8_t* data, size_t size)
{
    std::string pathName = "/data/local/tmp/test4.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        return;
    }
    Media::SourceOptions opts;
    uint32_t errorCode;
    Media ::DecodeOptions dopts;
    auto imagesource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imagesource != nullptr) {
        imagesource->CreatePixelMap(dopts, errorCode);
    }
    close(fd);
}

void CreateIncrementalPixelMapFuzz(const uint8_t* data, size_t size)
{
    std::string pathName = "/data/local/tmp/test5.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return;
    }
    Media::SourceOptions opts;
    uint32_t errorCode;
    auto imagesource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    Media ::DecodeOptions dopts;
    uint32_t index = 1;
    if (imagesource != nullptr) {
        imagesource->CreateIncrementalPixelMap(index, dopts, errorCode);
    }
    close(fd);
}

static inline std::string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

void CreateImageSourceByPathname(const uint8_t* data, size_t size)
{
    uint32_t errCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(FuzzString(data, size), opts, errCode);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::CreateImageSourceByDataFuzz(data, size);
    OHOS::Media::CreateImageSourceByFDEXFuzz(data, size);
    OHOS::Media::CreateImageSourceByIstreamFuzz(data, size);
    OHOS::Media::CreateImageSourceByPathNameFuzz(data, size);
    OHOS::Media::CreateIncrementalPixelMapFuzz(data, size);
    OHOS::Media::CreateImageSourceByPathname(data, size);
    return 0;
}