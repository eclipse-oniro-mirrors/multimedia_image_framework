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

#include "image_fwk_image_source_fuzzer.h"

#define private public
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include "common_fuzztest_function.h"

#include "image_log.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_utils.h"
#include "media_errors.h"

static const std::string JPEG_FORMAT = "image/jpeg";
static const std::string HEIF_FORMAT = "image/heif";
static const std::string WEBP_FORMAT = "image/webp";
static const std::string GIF_FORMAT = "image/gif";
static const std::string PNG_FORMAT = "image/png";
static const std::string IMAGE_ENCODE_DEST = "/data/local/tmp/test_out.dat";

namespace OHOS {
namespace Media {
void ImageSourceFuncTest002(std::unique_ptr<ImageSource>& imageSource, DecodeOptions& opts, PixelMap& pixelMap)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    uint32_t errCode = 0;
    Rect cropRect;
    ImageInfo imageInfo;
    imageSource->ImageConverChange(cropRect, imageInfo, imageInfo);
    imageSource->CreatePixelMapForYUV(errCode);
    imageSource->CreatePixelMapList(opts, errCode);
    imageSource->GetDelayTime(errCode);
    imageSource->GetDisposalType(errCode);
    imageSource->GetFrameCount(errCode);
    imageSource->GetLoopCount(errCode);
    auto exifMeta = imageSource->GetExifMetadata();
    imageSource->SetExifMetadata(exifMeta);
    imageSource->GetFinalOutputStep(opts, pixelMap, false);
    imageSource->SetIncrementalSource(false);
    auto incrementalRecordIter = imageSource->incDecodingMap_.find(&pixelMap);
    imageSource->AddIncrementalContext(pixelMap, incrementalRecordIter);
    imageSource->GetImageInfoFromExif(0, imageInfo);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void ImageSourceFuncTest001(std::unique_ptr<ImageSource>& imageSource)
{
    IMAGE_LOGI("%{public}s IN", __func__);
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
    ImageSourceFuncTest002(imageSource, opts, pixelMap);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void CreateImageSourceByPathFuzz(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    Media::SourceOptions opts;
    uint32_t errorCode;
    auto imageSource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    ImageSourceFuncTest001(imageSource);
    Media::DecodeOptions dopts;
    imageSource->CreatePixelMap(dopts, errorCode);
    imageSource->Reset();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void CreateImageSourceByFDEXFuzz(const std::string& pathName)
{
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        IMAGE_LOGI("%{public}s fail, Invalid path:%{public}s", __func__, pathName.c_str());
        return;
    }
    Media::SourceOptions opts;
    uint32_t errorCode = 0;
    int32_t offset = 0;
    int32_t length = 1;
    auto imagesource = Media::ImageSource::CreateImageSource(fd, offset, length, opts, errorCode);
    Media::DecodeOptions dopts;
    if (imagesource != nullptr) {
        imagesource->CreatePixelMap(dopts, errorCode);
    }
    close(fd);
}

void CreateImageSourceByIstreamFuzz(const std::string& pathName)
{
    std::unique_ptr<std::istream> is = std::make_unique<std::ifstream>(pathName.c_str());
    Media::SourceOptions opts;
    uint32_t errorCode;
    Media::DecodeOptions dopts;
    auto imageSource = Media::ImageSource::CreateImageSource(std::move(is), opts, errorCode);
    if (imageSource != nullptr) {
        imageSource->CreatePixelMap(dopts, errorCode);
    }
}

void CreateImageSourceByPathNameFuzz(const std::string& pathName)
{
    Media::SourceOptions opts;
    uint32_t errorCode;
    Media::DecodeOptions dopts;
    auto imageSource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imageSource != nullptr) {
        imageSource->CreatePixelMap(dopts, errorCode);
    }
}

void CreateImageSourceByDataFuzz(const uint8_t* data, size_t size)
{
    uint32_t errCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errCode);
}

void ImageSourceFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    SourceOptions opts;
    uint32_t errorCode = 0;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    std::string key = "ImageWidth";
    std::string value = "500";
    imageSource->ModifyImageProperty(0, key, value);
    imageSource->ModifyImagePropertyEx(0, key, value);
    bool isSupportOdd = false;
    bool isAddUV = false;
    std::vector<uint8_t> buffer;
    imageSource->ConvertYUV420ToRGBA(buffer.data(), size, isSupportOdd, isAddUV, errorCode);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < COMMON_OPT_SIZE) {
        return 0;
    }
    /* Run your code on data */
    static const std::string imagePath1 = "/data/local/tmp/test_source.gif";
    static const std::string imagePath2 = "/data/local/tmp/test_source.svg";
    static const std::string imagePath3 = "/data/local/tmp/test_source.jpg";
    std::string pathName = "/data/local/tmp/test_create_imagesource_pathname.png";
    FuzzedDataProvider fdp(data + size - COMMON_OPT_SIZE, COMMON_OPT_SIZE);
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 10;
    if (!WriteDataToFile(data, size - COMMON_OPT_SIZE, pathName)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return 0;
    }
    switch (action) {
        case 0:
            OHOS::Media::CreateImageSourceByPathFuzz(imagePath1);
            break;
        case 1:
            OHOS::Media::CreateImageSourceByPathFuzz(imagePath2);
            break;
        case 2:
            OHOS::Media::CreateImageSourceByPathFuzz(imagePath3);
            break;
        case 3:
            OHOS::Media::CreateImageSourceByFDEXFuzz(imagePath3);
            break;
        case 4:
            OHOS::Media::CreateImageSourceByIstreamFuzz(imagePath3);
            break;
        case 5:
            OHOS::Media::CreateImageSourceByFDEXFuzz(pathName);
            break;
        case 6:
            OHOS::Media::CreateImageSourceByIstreamFuzz(pathName);
            break;
        case 7:
            OHOS::Media::CreateImageSourceByPathFuzz(pathName);
            break;
        case 8:
            OHOS::Media::CreateImageSourceByDataFuzz(data, size - COMMON_OPT_SIZE);
            break;
        case 9:
            OHOS::Media::ImageSourceFuzzTest(data, size - COMMON_OPT_SIZE);
            break;
        default:
            break;
    }
    
    return 0;
}