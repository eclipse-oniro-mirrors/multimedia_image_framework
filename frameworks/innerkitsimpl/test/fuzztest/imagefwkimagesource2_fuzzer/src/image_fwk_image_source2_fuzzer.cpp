/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
constexpr uint32_t SOURCEOPTIONS_MIMETYPE_MODULO = 3;

namespace OHOS {
namespace Media {
FuzzedDataProvider *FDP;
void ImageSourceFuncTest002(std::unique_ptr<ImageSource> &imageSource, DecodeOptions &opts, PixelMap &pixelMap)
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
    imageSource->IsHeifWithoutAlpha();
    imageSource->IsJpegProgressive(errCode);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void ImageSourceFuncTest001(std::unique_ptr<ImageSource> &imageSource)
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

void CreateImageSourceByPathFuzz(const std::string &pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    Media::SourceOptions opts;
    uint32_t errorCode;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    auto imageSource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGI("%{public}s failed", __func__);
        return;
    }
    ImageSourceFuncTest001(imageSource);
    Media::DecodeOptions dopts;
    SetFdpDecodeOptions(FDP, dopts);
    imageSource->CreatePixelMap(dopts, errorCode);
    imageSource->Reset();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void CreateImageSourceByFDEXFuzz(const std::string &pathName)
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
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    auto imagesource = Media::ImageSource::CreateImageSource(fd, offset, length, opts, errorCode);
    Media::DecodeOptions dopts;
    SetFdpDecodeOptions(FDP, dopts);
    if (imagesource != nullptr) {
        imagesource->CreatePixelMap(dopts, errorCode);
        imagesource->RemoveImageProperties(0, {"ImageWidth", "ImageHeight"}, fd);
    }
    close(fd);
}

void CreateImageSourceByIstreamFuzz(const std::string &pathName)
{
    std::unique_ptr<std::istream> is = std::make_unique<std::ifstream>(pathName.c_str());
    Media::SourceOptions opts;
    uint32_t errorCode;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    Media::DecodeOptions dopts;
    SetFdpDecodeOptions(FDP, dopts);
    auto imageSource = Media::ImageSource::CreateImageSource(std::move(is), opts, errorCode);
    if (imageSource != nullptr) {
        imageSource->CreatePixelMap(dopts, errorCode);
    }
}

void CreateImageSourceByPathNameFuzz(const std::string &pathName)
{
    Media::SourceOptions opts;
    uint32_t errorCode;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    Media::DecodeOptions dopts;
    SetFdpDecodeOptions(FDP, dopts);
    auto imageSource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imageSource != nullptr) {
        imageSource->CreatePixelMap(dopts, errorCode);
    }
}

void CreateIncrementalPixelMapFuzz(const std::string &pathName)
{
    Media::SourceOptions opts;
    uint32_t errorCode;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    auto imageSource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    Media::DecodeOptions dopts;
    SetFdpDecodeOptions(FDP, dopts);
    uint32_t index = 1;
    if (imageSource != nullptr) {
        imageSource->CreateIncrementalPixelMap(index, dopts, errorCode);
    }
}

static std::string GetProperty(std::unique_ptr<ImageSource> &imageSource, const std::string &prop)
{
    std::string value = "";
    imageSource->GetImagePropertyString(0, prop, value);
    return value;
}

void GetImagePropertyFuzzTest001(const std::string &pathName)
{
    uint32_t errCode = 0;
    SourceOptions srcOpts;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errCode);
    GetProperty(imageSource, "DateTimeOriginal");
    GetProperty(imageSource, "ExposureTime");
    GetProperty(imageSource, "SceneType");
    std::set<std::string> keys = {"DateTimeOriginal", "ExposureTime", "SceneType"};
    errCode = imageSource->RemoveImageProperties(0, keys, pathName);
    if (errCode != SUCCESS) {
        return;
    }
    auto imageSourceNew = ImageSource::CreateImageSource(pathName, srcOpts, errCode);
    GetProperty(imageSource, "DateTimeOriginal");
    GetProperty(imageSource, "ExposureTime");
    GetProperty(imageSource, "SceneType");
}

}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < COMMON_OPT_SIZE) {
        return 0;
    }
    FuzzedDataProvider fdp(data + size - COMMON_OPT_SIZE, COMMON_OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    std::string pathName = "/data/local/tmp/test_create_imagesource_pathname.png";
    if (!WriteDataToFile(data, size - COMMON_OPT_SIZE, pathName)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return 0;
    }
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 6;
    switch (action) {
        case 0:
            OHOS::Media::CreateImageSourceByPathFuzz(pathName);
            break;
        case 1:
            OHOS::Media::CreateImageSourceByFDEXFuzz(pathName);
            break;
        case 2:
            OHOS::Media::CreateImageSourceByIstreamFuzz(pathName);
            break;
        case 3:
            OHOS::Media::CreateImageSourceByPathNameFuzz(pathName);
            break;
        case 4:
            OHOS::Media::CreateIncrementalPixelMapFuzz(pathName);
            break;
        case 5:
            OHOS::Media::GetImagePropertyFuzzTest001(pathName);
            break;
        default:
            break;
    }
    return 0;
}
