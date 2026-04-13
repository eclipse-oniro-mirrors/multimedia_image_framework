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
#include "image_mime_type.h"
#include "image_source.h"
#include "image_utils.h"
#include "media_errors.h"
#include "xmp_metadata.h"

namespace OHOS {
namespace Media {
FuzzedDataProvider *FDP;

namespace {
static constexpr uint32_t NUM_0 = 0;
static constexpr int32_t NUM_5 = 5;
static constexpr int32_t NUM_10 = 10;
static constexpr uint32_t PIXELFORMAT_MODULO = 105;
static const std::string NORMAL_MIMES[] = {
    IMAGE_JPEG_FORMAT,
    IMAGE_PNG_FORMAT,
    IMAGE_GIF_FORMAT,
    IMAGE_TIFF_FORMAT,
    IMAGE_DNG_FORMAT
};
static constexpr size_t NORMAL_MIMES_COUNT = sizeof(NORMAL_MIMES) / sizeof(NORMAL_MIMES[0]);
static const std::string BOUNDARY_MIMES[] = {
    "",
    "invalid/mime",
    "image/",
    "IMAGE/JPEG",
    std::string(100, 'a'),
    "\x01\x02image/jpeg",
};
static constexpr size_t BOUNDARY_MIMES_COUNT = sizeof(BOUNDARY_MIMES) / sizeof(BOUNDARY_MIMES[0]);
}

static std::unique_ptr<ImageSource> CreateImageSourceForFuzzTest(const std::string &pathName)
{
    SourceOptions opts;
    opts.formatHint = NORMAL_MIMES[FDP->ConsumeIntegral<uint8_t>() % NORMAL_MIMES_COUNT];
    opts.pixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint8_t>()% PIXELFORMAT_MODULO);
    uint32_t errorCode = 0;
    auto src = ImageSource::CreateImageSource(pathName, opts, errorCode);
    IMAGE_LOGI("[FUZZ] %{public}s: formatHint=[%{public}.32s] pixelFormat=%{public}d err=%{public}u", __func__,
        opts.formatHint.c_str(), static_cast<int>(opts.pixelFormat), errorCode);
    return src;
}

void CreateXMPMetadataByImageSourceFuzzTest(const std::string &pathName)
{
    auto imageSource = CreateImageSourceForFuzzTest(pathName);
    if (imageSource.get() == nullptr) {
        return;
    }

    for (size_t i = 0; i < NORMAL_MIMES_COUNT; i++) {
        if (FDP->ConsumeBool()) {
            imageSource->CreateXMPMetadataByImageSource(NORMAL_MIMES[i]);
            if (FDP->ConsumeBool()) {
                imageSource->CreateXMPMetadataByImageSource(NORMAL_MIMES[i]);
            }
        }
    }
    for (size_t i = 0; i < BOUNDARY_MIMES_COUNT; i++) {
        if (FDP->ConsumeBool()) {
            imageSource->CreateXMPMetadataByImageSource(BOUNDARY_MIMES[i]);
        }
    }
    for (int i = 0; i < NUM_5; i++) {
        if (FDP->ConsumeBool()) {
            std::string randomMime = FDP->ConsumeRandomLengthString();
            imageSource->CreateXMPMetadataByImageSource(randomMime);
        }
    }
    if (FDP->ConsumeBool()) {
        std::string testMime = IMAGE_JPEG_FORMAT;
        for (int i = 0; i < NUM_10; i++) {
            imageSource->CreateXMPMetadataByImageSource(testMime);
        }
    }
}

void ReadXMPMetadataFuzzTest(const std::string &pathName)
{
    auto imageSource = CreateImageSourceForFuzzTest(pathName);
    if (imageSource.get() == nullptr) {
        return;
    }
    uint32_t errorCode = NUM_0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    IMAGE_LOGI("[FUZZ] %{public}s: read err=%{public}u", __func__, errorCode);
    if (errorCode == SUCCESS) {
        uint32_t errorCode2 = NUM_0;
        std::shared_ptr<XMPMetadata> xmpMetadata2 = imageSource->ReadXMPMetadata(errorCode2);
    }
    if (FDP->ConsumeBool()) {
        for (int i = 0; i < NUM_10; i++) {
            uint32_t tmpErrorCode = NUM_0;
            imageSource->ReadXMPMetadata(tmpErrorCode);
            IMAGE_LOGI("[FUZZ] %{public}s: repeat i=%{public}d err=%{public}u", __func__, i, tmpErrorCode);
        }
    }
}

void WriteXMPMetadataFuzzTest(const std::string &pathName)
{
    auto imageSource = CreateImageSourceForFuzzTest(pathName);
    if (imageSource.get() == nullptr) {
        return;
    }

    if (FDP->ConsumeBool()) {
        std::shared_ptr<XMPMetadata> nullMetadata = nullptr;
        uint32_t nullWriteErr = imageSource->WriteXMPMetadata(nullMetadata);
        IMAGE_LOGI("[FUZZ] %{public}s: write null ret=%{public}u", __func__, nullWriteErr);
    }
    if (FDP->ConsumeBool()) {
        auto metadata = std::make_shared<XMPMetadata>();
        uint32_t emptyWriteErr = imageSource->WriteXMPMetadata(metadata);
        IMAGE_LOGI("[FUZZ] %{public}s: write empty ret=%{public}u", __func__, emptyWriteErr);
    }

    if (FDP->ConsumeBool()) {
        uint32_t readError = NUM_0;
        auto readMetadata = imageSource->ReadXMPMetadata(readError);
        if (readError == SUCCESS && readMetadata) {
            uint32_t rwErr = imageSource->WriteXMPMetadata(readMetadata);
            IMAGE_LOGI("[FUZZ] %{public}s: read-write ret=%{public}u", __func__, rwErr);
        }
    }
    if (FDP->ConsumeBool()) {
        for (int i = 0; i < NUM_5; i++) {
            std::shared_ptr<XMPMetadata> metadata = nullptr;
            uint32_t writeError = imageSource->WriteXMPMetadata(metadata);
            IMAGE_LOGI("[FUZZ] %{public}s: multi-write i=%{public}d errorCode=%{public}u", __func__, i, writeError);
        }
    }
    if (FDP->ConsumeBool()) {
        int fd = open(pathName.c_str(), O_RDWR);
        if (fd >= 0) {
            imageSource->srcFilePath_.clear();
            imageSource->srcFd_ = fd;
            auto metadata = std::make_shared<XMPMetadata>();
            uint32_t fdWriteErr = imageSource->WriteXMPMetadata(metadata);
            IMAGE_LOGI("[FUZZ] %{public}s: fd-write fd=%{public}d ret=%{public}u", __func__, fd, fdWriteErr);
            close(fd);
            imageSource->srcFd_ = -1;
        }
    }
    if (FDP->ConsumeBool()) {
        imageSource->srcFilePath_.clear();
        imageSource->srcFd_ = -1;
        auto metadata = std::make_shared<XMPMetadata>();
        uint32_t badWriteErr = imageSource->WriteXMPMetadata(metadata);
        IMAGE_LOGI("[FUZZ] %{public}s: bad-src write ret=%{public}u", __func__, badWriteErr);
    }
}
} // namespace Media
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < COMMON_OPT_SIZE) {
        return 0;
    }

    FuzzedDataProvider fdp(data + size - COMMON_OPT_SIZE, COMMON_OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    std::string pathName = "/data/local/tmp/test_xmp.jpg";
    if (!WriteDataToFile(data, size - COMMON_OPT_SIZE, pathName)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return 0;
    }

    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 3;
    IMAGE_LOGI("[FUZZ] %{public}s: action=%{public}u size=%{public}zu", __func__, action, size);
    switch (action) {
        case 0:
            OHOS::Media::CreateXMPMetadataByImageSourceFuzzTest(pathName);
            break;
        case 1:
            OHOS::Media::ReadXMPMetadataFuzzTest(pathName);
            break;
        case 2:
            OHOS::Media::WriteXMPMetadataFuzzTest(pathName);
            break;
        default:
            break;
    }
    return 0;
}