/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
FuzzedDataProvider *FDP;

void CreateIncrementalPixelMapByDataFuzz(const uint8_t* data, size_t size)
{
    Media::SourceOptions opts;
    uint32_t errorCode = 0;
    Media::IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    auto imageSource = Media::ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    if (imageSource != nullptr) {
        DecodeOptions decodeOpts;
        std::unique_ptr<IncrementalPixelMap> incPixelMap =
            imageSource->CreateIncrementalPixelMap(0, decodeOpts, errorCode);
        uint32_t res = imageSource->UpdateData(data, size, true);
        uint8_t decodeProgress = 0;
        res = incPixelMap->PromoteDecoding(decodeProgress);
    }
}

void CreateIncrementalPixelMapFuzz(const std::string& pathName)
{
    Media::SourceOptions opts;
    uint32_t errorCode;
    auto imageSource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    Media::DecodeOptions dopts;
    uint32_t index = 1;
    if (imageSource != nullptr) {
        imageSource->CreateIncrementalPixelMap(index, dopts, errorCode);
    }
}

static std::string GetImageProperty(std::unique_ptr<ImageSource>& imageSource, const std::string& prop)
{
    std::string value = "";
    imageSource->GetImagePropertyString(0, prop, value);
    return value;
}

void GetImagePropertyFuzzTest001(const std::string& pathName)
{
    uint32_t errCode = 0;
    SourceOptions srcOpts;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errCode);
    GetImageProperty(imageSource, "DateTimeOriginal");
    GetImageProperty(imageSource, "ExposureTime");
    GetImageProperty(imageSource, "SceneType");
    std::set<std::string> keys = {"DateTimeOriginal", "ExposureTime", "SceneType"};
    if (imageSource == nullptr) {
        return;
    }
    errCode = imageSource->RemoveImageProperties(0, keys, pathName);
    if (errCode != SUCCESS) {
        return;
    }
    auto imageSourceNew = ImageSource::CreateImageSource(pathName, srcOpts, errCode);
    GetImageProperty(imageSource, "DateTimeOriginal");
    GetImageProperty(imageSource, "ExposureTime");
    GetImageProperty(imageSource, "SceneType");
}

bool CreatePixelMapByRandomImageSource(const uint8_t *data, size_t size)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    if (data == nullptr) {
        IMAGE_LOGE("%{public}s failed, data is nullptr", __func__);
        return false;
    }
    Media::SourceOptions opts;
    uint32_t errorCode;
    auto imageSource = Media::ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s failed, imageSource is nullptr", __func__);
        return false;
    }
    std::vector<DecodeOptions> doptsVector;
    
    DecodeOptions dopts1;
    dopts1.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts1.isAppUseAllocator = true;
    dopts1.allocatorType = AllocatorType::DMA_ALLOC;
    doptsVector.push_back(dopts1);
    
    DecodeOptions dopts2;
    dopts2.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts2.isAppUseAllocator = true;
    dopts2.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    doptsVector.push_back(dopts2);
    
    DecodeOptions dopts3;
    dopts3.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts3.isAppUseAllocator = true;
    dopts3.allocatorType = imageSource->ConvertAutoAllocatorType(dopts2);
    doptsVector.push_back(dopts3);

    DecodeOptions dopts4;
    dopts4.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts4.isAppUseAllocator = true;
    dopts4.allocatorType = AllocatorType::DMA_ALLOC;
    dopts4.desiredPixelFormat = PixelFormat::NV12;
    doptsVector.push_back(dopts4);
    
    DecodeOptions dopts5;
    dopts5.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts5.isAppUseAllocator = true;
    dopts5.allocatorType = AllocatorType::DMA_ALLOC;
    dopts5.desiredPixelFormat = PixelFormat::NV21;
    doptsVector.push_back(dopts5);
    
    DecodeOptions dopts6;
    dopts6.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts6.isAppUseAllocator = true;
    dopts6.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    dopts6.desiredPixelFormat = PixelFormat::NV21;
    doptsVector.push_back(dopts6);
    
    std::shared_ptr<PixelMap> pixelMap = nullptr;
    uint8_t index = FDP->ConsumeIntegral<uint8_t>() % doptsVector.size();
    pixelMap = imageSource->CreatePixelMap(0, doptsVector[index], errorCode);
    return true;
}

void EncodePictureTest(std::shared_ptr<Picture> picture, const std::string& format, const std::string& outputPath)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    if (picture == nullptr) {
        IMAGE_LOGE("%{public}s picture null.", __func__);
        return;
    }
    ImagePacker pack;
    PackOption packOption;
    packOption.format = format;
    if (pack.StartPacking(outputPath, packOption) != SUCCESS) {
        IMAGE_LOGE("%{public}s StartPacking failed.", __func__);
        return;
    }
    if (pack.AddPicture(*picture) != SUCCESS) {
        IMAGE_LOGE("%{public}s AddPicture failed.",  __func__);
        return;
    }
    if (pack.FinalizePacking() != SUCCESS) {
        IMAGE_LOGE("%{public}s FinalizePacking failed.",  __func__);
        return;
    }
    IMAGE_LOGI("%{public}s SUCCESS.",  __func__);
}

void EncodePixelMapTest(std::shared_ptr<PixelMap> pixelmap, const std::string& format, const std::string& outputPath)
{
    IMAGE_LOGI("%{public}s start.", __func__);
    if (pixelmap == nullptr) {
        IMAGE_LOGE("%{public}s picture null.", __func__);
        return;
    }
    ImagePacker pack;
    PackOption packOption;
    packOption.format = format;
    if (pack.StartPacking(outputPath, packOption) != SUCCESS) {
        IMAGE_LOGE("%{public}s StartPacking failed.", __func__);
        return;
    }
    if (pack.AddImage(*pixelmap) != SUCCESS) {
        IMAGE_LOGE("%{public}s AddImage failed.",  __func__);
        return;
    }
    if (pack.FinalizePacking() != SUCCESS) {
        IMAGE_LOGE("%{public}s FinalizePacking failed.",  __func__);
        return;
    }
    IMAGE_LOGI("%{public}s SUCCESS.",  __func__);
}

bool CreatePixelMapUseArgbByRandomImageSource(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return false;
    }
    std::vector<DecodeOptions> doptsVector;
    DecodeOptions dopts1;
    dopts1.desiredPixelFormat = PixelFormat::ARGB_8888;
    dopts1.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts1.allocatorType = AllocatorType::DMA_ALLOC;
    doptsVector.push_back(dopts1);
    DecodeOptions dopts2;
    dopts2.desiredPixelFormat = PixelFormat::ARGB_8888;
    dopts2.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts2.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    doptsVector.push_back(dopts2);
    DecodeOptions dopts3;
    dopts3.desiredPixelFormat = PixelFormat::ARGB_8888;
    dopts3.desiredDynamicRange = DecodeDynamicRange::AUTO;
    dopts3.allocatorType = imageSource->ConvertAutoAllocatorType(dopts3);
    doptsVector.push_back(dopts3);
    std::shared_ptr<PixelMap> pixelMap = nullptr;
    uint8_t index = FDP->ConsumeIntegral<uint8_t>() % doptsVector.size();
    pixelMap = imageSource->CreatePixelMap(0, doptsVector[index], errorCode);

    std::vector<std::string> formats = {JPEG_FORMAT, HEIF_FORMAT, PNG_FORMAT, WEBP_FORMAT, GIF_FORMAT};
    ImageInfo info;
    if (pixelMap != nullptr) {
        uint8_t index = FDP->ConsumeIntegral<uint8_t>() % formats.size();
        EncodePixelMapTest(pixelMap, formats[index], IMAGE_ENCODE_DEST);
        pixelMap->GetImageInfo(info);
    }
    std::shared_ptr<AuxiliaryPicture> auxPicture = AuxiliaryPicture::Create(pixelMap,
        AuxiliaryPictureType::FRAGMENT_MAP, info.size);
    DecodingOptionsForPicture doptsForPicture;
    doptsForPicture.desiredPixelFormat = PixelFormat::ARGB_8888;
    std::shared_ptr<Picture> picture = imageSource->CreatePicture(doptsForPicture, errorCode);
    if (auxPicture != nullptr && picture != nullptr) {
        picture->SetAuxiliaryPicture(auxPicture);
    }
    if (picture != nullptr) {
        uint8_t index = FDP->ConsumeIntegral<uint8_t>() % 2;
        EncodePictureTest(picture, formats[index], IMAGE_ENCODE_DEST);
    }
    return true;
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
    static const std::string imagePath3 = "/data/local/tmp/test_source.jpg";
    std::string pathName = "/data/local/tmp/test_create_imagesource_pathname.png";
    FuzzedDataProvider fdp(data + size - COMMON_OPT_SIZE, COMMON_OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 7;
    if (!WriteDataToFile(data, size - COMMON_OPT_SIZE, pathName)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return 0;
    }
    switch (action) {
        case 0:
            OHOS::Media::CreateIncrementalPixelMapFuzz(imagePath3);
            break;
        case 1:
            OHOS::Media::GetImagePropertyFuzzTest001(imagePath3);
            break;
        case 2:
            OHOS::Media::CreateIncrementalPixelMapFuzz(pathName);
            break;
        case 3:
            OHOS::Media::CreateIncrementalPixelMapByDataFuzz(data, size - COMMON_OPT_SIZE);
            break;
        case 4:
            OHOS::Media::GetImagePropertyFuzzTest001(pathName);
            break;
        case 5:
            OHOS::Media::CreatePixelMapByRandomImageSource(data, size - COMMON_OPT_SIZE);
            break;
        case 6:
            OHOS::Media::CreatePixelMapUseArgbByRandomImageSource(data, size - COMMON_OPT_SIZE);
            break;
        default:
            break;
    }
    
    return 0;
}