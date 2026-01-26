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
#include <vector>
#include "common_fuzztest_function.h"
#include "dng_exif_metadata.h"
#include "dng_sdk_helper.h"
#include "dng_sdk_info.h"
#include "exif_metadata.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "DngExifMetadata"

namespace OHOS {
namespace Media {

static constexpr uint32_t MAX_STRING_LENGTH = 10;

FuzzedDataProvider* FDP;

void ImageDngExifMetadataGetValueFuzzTest()
{
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    std::string key = GetFuzzKey(FDP);
    std::string value = FDP->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    dngExifMetadata->GetValue(key, value);
}

void ImageDngExifMetadataSetValueFuzzTest()
{
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    std::string key = GetFuzzKey(FDP);
    std::string value = FDP->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    dngExifMetadata->SetValue(key, value);
}

void ImageDngExifMetadataRemoveEntryFuzzTest()
{
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    std::string key = GetFuzzKey(FDP);
    dngExifMetadata->RemoveEntry(key);
}

void ImageDngExifMetadataGetExifPropertyFuzzTest()
{
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    dngExifMetadata->dngSdkInfo_ = std::make_unique<DngSdkInfo>();
    MetadataValue value{};
    std::string key = GetFuzzKey(FDP);
    dngExifMetadata->GetExifProperty(value);
}

void ImageDngExifMetadataCloneMetadataFuzzTest()
{
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    dngExifMetadata->CloneMetadata();
}

void ImageDngExifMetadataCloneFuzzTest()
{
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    dngExifMetadata->Clone();
}

void ImageDngExifMetadataMarshallingFuzzTest()
{
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    Parcel parcel;
    dngExifMetadata->Marshalling(parcel);
}

void ImageDngExifMetadataGetAllDngPropertiesFuzzTest()
{
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    dngExifMetadata->dngSdkInfo_ = std::make_unique<DngSdkInfo>();
    dngExifMetadata->GetAllDngProperties();
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    if (OHOS::Media::FDP == nullptr) {
        return 0;
    }
    /* Run your code on data */
    OHOS::Media::ImageDngExifMetadataGetValueFuzzTest();
    OHOS::Media::ImageDngExifMetadataSetValueFuzzTest();
    OHOS::Media::ImageDngExifMetadataRemoveEntryFuzzTest();
    OHOS::Media::ImageDngExifMetadataGetExifPropertyFuzzTest();
    OHOS::Media::ImageDngExifMetadataCloneMetadataFuzzTest();
    OHOS::Media::ImageDngExifMetadataCloneFuzzTest();
    OHOS::Media::ImageDngExifMetadataMarshallingFuzzTest();
    OHOS::Media::ImageDngExifMetadataGetAllDngPropertiesFuzzTest();
    return 0;
}