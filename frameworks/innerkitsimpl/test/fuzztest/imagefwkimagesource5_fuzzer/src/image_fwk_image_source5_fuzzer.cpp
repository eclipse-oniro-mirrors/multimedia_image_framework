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

void CreateIncrementalPixelMapByDataFuzz(const uint8_t *data, size_t size)
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

void CreateImageSourceByDataFuzz(const uint8_t *data, size_t size)
{
    uint32_t errCode = 0;
    SourceOptions opts;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errCode);
}

void ImageSourceFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    SourceOptions opts;
    uint32_t errorCode = 0;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    uint32_t index = FDP->ConsumeIntegral<uint32_t>() % KEY_VALUE_MAPS.size();
    auto key = KEY_VALUE_MAPS[index].first;
    for (const auto &v : KEY_VALUE_MAPS[index].second) {
        imageSource->ModifyImageProperty(0, key, v);
        imageSource->ModifyImagePropertyEx(0, key, v);
    }
    bool isSupportOdd = false;
    bool isAddUV = false;
    std::vector<uint8_t> buffer;
    imageSource->ConvertYUV420ToRGBA(buffer.data(), size, isSupportOdd, isAddUV, errorCode);
}

void EncodePictureTest(std::shared_ptr<Picture> picture, const std::string &format, const std::string &outputPath)
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
        IMAGE_LOGE("%{public}s AddPicture failed.", __func__);
        return;
    }
    if (pack.FinalizePacking() != SUCCESS) {
        IMAGE_LOGE("%{public}s FinalizePacking failed.", __func__);
        return;
    }
    IMAGE_LOGI("%{public}s SUCCESS.", __func__);
}

void EncodePixelMapTest(std::shared_ptr<PixelMap> pixelmap, const std::string &format, const std::string &outputPath)
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
        IMAGE_LOGE("%{public}s AddImage failed.", __func__);
        return;
    }
    if (pack.FinalizePacking() != SUCCESS) {
        IMAGE_LOGE("%{public}s FinalizePacking failed.", __func__);
        return;
    }
    IMAGE_LOGI("%{public}s SUCCESS.", __func__);
}

bool CreatePixelMapUseArgbByRandomImageSource(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    SourceOptions opts;
    uint32_t errorCode;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return false;
    }
    DecodeOptions dopts;
    SetFdpDecodeOptions(FDP, dopts);
    std::shared_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(0, dopts, errorCode);

    if (pixelMap != nullptr) {
        std::vector<std::string> formats = {JPEG_FORMAT, HEIF_FORMAT, PNG_FORMAT, WEBP_FORMAT, GIF_FORMAT};
        uint8_t index = FDP->ConsumeIntegral<uint8_t>() % formats.size();
        EncodePixelMapTest(pixelMap, formats[index], IMAGE_ENCODE_DEST);
    }
    ImageInfo info;
    if (pixelMap != nullptr) {
        pixelMap->GetImageInfo(info);
    }
    std::shared_ptr<AuxiliaryPicture> auxPicture =
        AuxiliaryPicture::Create(pixelMap, AuxiliaryPictureType::FRAGMENT_MAP, info.size);
    DecodingOptionsForPicture doptsForPicture;
    doptsForPicture.desiredPixelFormat = dopts.desiredPixelFormat;
    std::shared_ptr<Picture> picture = imageSource->CreatePicture(doptsForPicture, errorCode);
    if (auxPicture != nullptr && picture != nullptr) {
        picture->SetAuxiliaryPicture(auxPicture);
    }
    if (picture != nullptr) {
        bool action = FDP->ConsumeBool();
        if (action) {
            EncodePictureTest(picture, JPEG_FORMAT, IMAGE_ENCODE_DEST);
        } else {
            EncodePictureTest(picture, HEIF_FORMAT, IMAGE_ENCODE_DEST);
        }
    }
    return true;
}

}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < COMMON_OPT_SIZE) {
        return 0;
    }
    /* Run your code on data */
    std::string pathName = "/data/local/tmp/test_create_imagesource_pathname.png";
    FuzzedDataProvider fdp(data + size - COMMON_OPT_SIZE, COMMON_OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    if (!WriteDataToFile(data, size - COMMON_OPT_SIZE, pathName)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return 0;
    }
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 4;
    switch (action) {
        case 0:
            OHOS::Media::CreateImageSourceByDataFuzz(data, size - COMMON_OPT_SIZE);
            break;
        case 1:
            OHOS::Media::CreateIncrementalPixelMapByDataFuzz(data, size - COMMON_OPT_SIZE);
            break;
        case 2:
            OHOS::Media::CreatePixelMapUseArgbByRandomImageSource(data, size - COMMON_OPT_SIZE);
            break;
        case 3:
            OHOS::Media::ImageSourceFuzzTest(data, size - COMMON_OPT_SIZE);
            break;
        default:
            break;
    }
    return 0;
}
