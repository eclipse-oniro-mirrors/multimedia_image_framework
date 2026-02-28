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
#include <fuzzer/FuzzedDataProvider.h>
#include <fcntl.h>
#include <memory>
#include <string>
#include "common_fuzztest_function.h"
#include "dng_area_task.h"
#include "dng/dng_exif_metadata.h"
#include "dng_errors.h"
#include "dng_host.h"
#include "dng_sdk_helper.h"
#include "dng_stream.h"
#include "file_metadata_stream.h"
#include "file_source_stream.h"

namespace OHOS {
namespace Media {

static constexpr uint32_t OPT_SIZE = 80;
static constexpr uint8_t CASE0 = 0;
static constexpr uint8_t CASE1 = 1;
static constexpr uint8_t CASE2 = 2;

FuzzedDataProvider* FDP;

void ImageDngSdkHelperParseInfoFromStreamFuzzTest(const std::string& pathName)
{
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return;
    }
    std::shared_ptr<FileMetadataStream> fileStream =
        std::make_shared<FileMetadataStream>(fd, METADATA_STREAM_INVALID_FD);
    if (fileStream == nullptr) {
        close(fd);
        return;
    }
    bool isOpen = fileStream->Open(OpenMode::ReadWrite);
    if (!isOpen) {
        close(fd);
        return;
    }
    std::shared_ptr<MetadataStream> stream = fileStream;
    auto dngInfo = DngSdkHelper::ParseInfoFromStream(stream);
    if (!dngInfo) {
        close(fd);
        return;
    }
    dngInfo->GetAllPropertyKeys();
    close(fd);
}

void ImageDngSdkHelperGetExifPropertyFuzzTest(const std::string& pathName)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(pathName);
    if (stream == nullptr) {
        return;
    }
    bool openSuccess = stream->Open(OpenMode::ReadWrite);
    if (!openSuccess) {
        return;
    }
    auto dngInfo = DngSdkHelper::ParseInfoFromStream(stream);
    if (dngInfo == nullptr) {
        return;
    }

    MetadataValue value{};
    value.key = GetFuzzKey(FDP);
    DngSdkHelper::GetExifProperty(dngInfo, value);
}

void ImageDngSdkHelperGetImageRawDataFuzzTest(const std::string& pathName)
{
    auto stream = FileSourceStream::CreateSourceStream(pathName);
    if (stream == nullptr) {
        return;
    }
    std::vector<uint8_t> data;
    uint32_t bitsPerSample = 0;
    DngSdkHelper::GetImageRawData(stream.get(), data, bitsPerSample);
}

void ImageDngSdkHelperSetExifPropertyFuzzTest(const std::string& pathName)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(pathName);
    if (stream == nullptr) {
        return;
    }
    bool openSuccess = stream->Open(OpenMode::ReadWrite);
    if (!openSuccess) {
        return;
    }
    auto dngInfo = DngSdkHelper::ParseInfoFromStream(stream);
    if (dngInfo == nullptr) {
        return;
    }

    MetadataValue value{};
    value.key = GetFuzzKey(FDP);
    DngSdkHelper::SetExifProperty(dngInfo, value);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (size <  OHOS::Media::OPT_SIZE) {
        return 0;
    }

    FuzzedDataProvider fdp(data + size - OHOS::Media::OPT_SIZE, OHOS::Media::OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    if (OHOS::Media::FDP == nullptr) {
        return 0;
    }
    std::string pathName = "/data/local/tmp/image/test_dng_readmetadata.dng";
    if (!WriteDataToFile(data, size, pathName)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return 0;
    }
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 4;
    switch (action) {
        case OHOS::Media::CASE0:
            OHOS::Media::ImageDngSdkHelperParseInfoFromStreamFuzzTest(pathName);
            break;
        case OHOS::Media::CASE1:
            OHOS::Media::ImageDngSdkHelperGetExifPropertyFuzzTest(pathName);
            break;
        case OHOS::Media::CASE2:
            OHOS::Media::ImageDngSdkHelperGetImageRawDataFuzzTest(pathName);
            break;
        default:
            OHOS::Media::ImageDngSdkHelperSetExifPropertyFuzzTest(pathName);
            break;
    }
    return 0;
}