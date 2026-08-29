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

#include "image_fwk_packer_fuzzer.h"

#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <unistd.h>
#include <vector>

#define private public
#define protected public
#include "image_packer.h"
#include "image_source.h"
#include "pixel_map.h"
#include "picture.h"
#include "media_errors.h"
#include "image_log.h"
#include "image_utils.h"
#include "image_type.h"
#include "common_fuzztest_function.h"
#include "image_data_writer.h"
#include "include/core/SkStream.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_PACKER_FUZZ"

namespace OHOS {
namespace Media {

static constexpr uint32_t OPT_SIZE = 80;
static constexpr uint32_t MAX_C2PA_DATA_SIZE = 1U << 22; // 4MB
static constexpr uint32_t MAX_FUZZ_VALID_C2PA_DATA_SIZE = 64 * 1024;
static constexpr uint32_t PACKER_BUFFER_SIZE = 2 * 1024 * 1024;

FuzzedDataProvider* FDP = nullptr;

static void PackerFuzzBufferByData(const uint8_t* data, size_t size)
{
    // decode fuzz data as image source first
    SourceOptions srcOpts;
    uint32_t errCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(data, static_cast<uint32_t>(size), srcOpts, errCode);
    if (imageSource == nullptr) {
        return;
    }

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errCode);
    if (pixelMap == nullptr) {
        return;
    }

    ImagePacker packer;
    PackOption option;
    option.format = "image/jpeg";
    option.quality = FDP->ConsumeIntegral<uint8_t>();
    option.needsPackProperties = FDP->ConsumeBool();
    option.c2paDataSize = FDP->ConsumeIntegral<uint32_t>() % MAX_C2PA_DATA_SIZE;
    option.needsPackGPS = FDP->ConsumeBool();
    option.desiredDynamicRange = static_cast<EncodeDynamicRange>(
        FDP->ConsumeIntegral<uint8_t>() % 3);

    uint32_t bufferSize = PACKER_BUFFER_SIZE;
    std::unique_ptr<uint8_t[]> buffer =
        std::make_unique<uint8_t[]>(bufferSize);
    if (buffer == nullptr) {
        return;
    }
    if (packer.StartPacking(buffer.get(), bufferSize, option) != SUCCESS) {
        return;
    }
    packer.AddImage(*pixelMap);
    packer.FinalizePacking();
}

static void PackerFuzzFdByData(const uint8_t* data, size_t size)
{
    SourceOptions srcOpts;
    uint32_t errCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(data, static_cast<uint32_t>(size), srcOpts, errCode);
    if (imageSource == nullptr) {
        return;
    }

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errCode);
    if (pixelMap == nullptr) {
        return;
    }

    std::string pathName = "/data/local/tmp/test_packer_fuzz_" +
        GetNowTimeStr() + ".dat";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return;
    }

    ImagePacker packer;
    PackOption option;
    option.format = "image/jpeg";
    option.quality = FDP->ConsumeIntegral<uint8_t>();
    option.needsPackProperties = FDP->ConsumeBool();
    option.c2paDataSize = FDP->ConsumeIntegral<uint32_t>();

    if (packer.StartPacking(fd, option) == SUCCESS) {
        packer.AddImage(*pixelMap);
        packer.FinalizePacking();
    }
    close(fd);
    std::remove(pathName.c_str());
}

static void PackerFuzzPictureByData(const uint8_t* data, size_t size)
{
    SourceOptions srcOpts;
    uint32_t errCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(data, static_cast<uint32_t>(size), srcOpts, errCode);
    if (imageSource == nullptr) {
        return;
    }

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errCode);
    if (pixelMap == nullptr) {
        return;
    }

    std::shared_ptr<PixelMap> sharedPixelMap = std::shared_ptr<PixelMap>(std::move(pixelMap));
    std::unique_ptr<Picture> picture = Picture::Create(sharedPixelMap);
    if (picture == nullptr) {
        return;
    }

    ImagePacker packer;
    PackOption option;
    size_t fmtIndex = FDP->ConsumeIntegral<uint8_t>() % 2;
    option.format = (fmtIndex == 0) ? "image/jpeg" : "image/heif";
    option.quality = FDP->ConsumeIntegral<uint8_t>();
    option.needsPackProperties = FDP->ConsumeBool();
    option.c2paDataSize = FDP->ConsumeIntegral<uint32_t>();
    option.needsPackGPS = FDP->ConsumeBool();
    option.desiredDynamicRange = static_cast<EncodeDynamicRange>(
        FDP->ConsumeIntegral<uint8_t>() % 3);
    option.maxEmbedThumbnailDimension =
        static_cast<int32_t>(FDP->ConsumeIntegral<uint16_t>());

    uint32_t bufferSize = PACKER_BUFFER_SIZE;
    std::unique_ptr<uint8_t[]> buffer =
        std::make_unique<uint8_t[]>(bufferSize);
    if (buffer == nullptr) {
        return;
    }
    if (packer.StartPacking(buffer.get(), bufferSize, option) != SUCCESS) {
        return;
    }
    packer.AddPicture(*picture);
    packer.FinalizePacking();
}

static void PackerFuzzHeifPictureByData(const uint8_t* data, size_t size)
{
    SourceOptions srcOpts;
    uint32_t errCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(data, static_cast<uint32_t>(size), srcOpts, errCode);
    if (imageSource == nullptr) {
        return;
    }

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errCode);
    if (pixelMap == nullptr) {
        return;
    }

    std::shared_ptr<PixelMap> sharedPixelMap = std::shared_ptr<PixelMap>(std::move(pixelMap));
    std::unique_ptr<Picture> picture = Picture::Create(sharedPixelMap);
    if (picture == nullptr) {
        return;
    }

    ImagePacker packer;
    PackOption option;
    option.format = "image/heif";
    option.quality = FDP->ConsumeIntegral<uint8_t>();
    option.needsPackProperties = true;
    option.c2paDataSize = FDP->ConsumeIntegral<uint32_t>();

    uint32_t bufferSize = PACKER_BUFFER_SIZE;
    std::unique_ptr<uint8_t[]> buffer =
        std::make_unique<uint8_t[]>(bufferSize);
    if (buffer == nullptr) {
        return;
    }
    if (packer.StartPacking(buffer.get(), bufferSize, option) != SUCCESS) {
        return;
    }
    packer.AddPicture(*picture);
    packer.FinalizePacking();
}

static void FuzzImageDataWriter(const uint8_t *data, size_t size)
{
    const size_t jpegSize = std::min(size, static_cast<size_t>(1024));
    std::vector<uint8_t> jpegData(data, data + jpegSize);
    if (jpegData.size() < 2) {
        jpegData.resize(2, 0);
    }
    if (FDP->ConsumeBool()) {
        jpegData[0] = 0xFF;
        jpegData[1] = 0xD8;
    }

    const uint32_t reserveSize = FDP->ConsumeBool() ?
        FDP->ConsumeIntegralInRange<uint32_t>(1, MAX_FUZZ_VALID_C2PA_DATA_SIZE) : MAX_C2PA_DATA_SIZE + 1;
    SkDynamicMemoryWStream output;
    (void)ImagePlugin::ImageDataWriter::WriteJpegC2paDataToStream(output, jpegData.data(),
        static_cast<uint32_t>(jpegData.size()), reserveSize);
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::Media::OPT_SIZE) {
        return 0;
    }

    FuzzedDataProvider fdp(data + size - OHOS::Media::OPT_SIZE, OHOS::Media::OPT_SIZE);
    OHOS::Media::FDP = &fdp;

    size_t dataSize = size - OHOS::Media::OPT_SIZE;
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 5;
    switch (action) {
        case 0:
            OHOS::Media::PackerFuzzBufferByData(data, dataSize);
            break;
        case 1:
            OHOS::Media::PackerFuzzFdByData(data, dataSize);
            break;
        case 2:
            OHOS::Media::PackerFuzzPictureByData(data, dataSize);
            break;
        case 3:
            OHOS::Media::PackerFuzzHeifPictureByData(data, dataSize);
            break;
        case 4:
            OHOS::Media::FuzzImageDataWriter(data, dataSize);
            break;
        default:
            break;
    }
    return 0;
}