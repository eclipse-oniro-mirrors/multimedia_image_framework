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

const std::vector<std::string> HW_KEYS = {
    "HwMnoteCaptureMode",
    "HwMnotePhysicalAperture",
    "HwMnoteRollAngle",
    "HwMnotePitchAngle",
    "HwMnoteSceneFoodConf",
    "HwMnoteSceneStageConf",
    "HwMnoteSceneBlueSkyConf",
    "HwMnoteSceneGreenPlantConf",
    "HwMnoteSceneBeachConf",
    "HwMnoteSceneSnowConf",
    "HwMnoteSceneSunsetConf",
    "HwMnoteSceneFlowersConf",
    "HwMnoteSceneNightConf",
    "HwMnoteSceneTextConf",
    "HwMnoteFaceCount",
    "HwMnoteFocusMode",
    "HwMnoteFocusModeExif",
    "HwMnoteBurstNumber",
    "HwMnoteFaceConf",
    "HwMnoteFaceLeyeCenter",
    "HwMnoteFaceMouthCenter",
    "HwMnoteFacePointer",
    "HwMnoteFaceRect",
    "HwMnoteFaceReyeCenter",
    "HwMnoteFaceSmileScore",
    "HwMnoteFaceVersion",
    "HwMnoteFrontCamera",
    "HwMnoteScenePointer",
    "HwMnoteSceneVersion",
    "HwMnoteIsXmageSupported",
    "HwMnoteXmageMode",
    "HwMnoteXmageLeft",
    "HwMnoteXmageTop",
    "HwMnoteXmageRight",
    "HwMnoteXmageBottom",
    "HwMnoteCloudEnhancementMode",
    "HwMnoteWindSnapshotMode",
    "HwMnoteXtStyleTemplateName",
    "HwMnoteXtStyleCustomLightAndShadow",
    "HwMnoteXtStyleCustomSaturation",
    "HwMnoteXtStyleCustomHue",
    "HwMnoteXtStyleExposureParam"
    "MovingPhotoId",
    "MovingPhotoVersion",
    "MicroVideoPresentationTimestampUS",
    "HwUnknow",
    "ErrorKey",
};

FuzzedDataProvider* FDP;

void ImageDngExifMetadataGetValueFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    uint8_t randomIdx = FDP->ConsumeIntegral<uint8_t>() % HW_KEYS.size();
    std::string key = HW_KEYS[randomIdx];
    std::string value = "";
    dngExifMetadata->GetValue(key, value);
}

void ImageDngExifMetadataSetValueFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    uint8_t randomIdx = FDP->ConsumeIntegral<uint8_t>() % HW_KEYS.size();
    std::string key = HW_KEYS[randomIdx];
    std::string value = "";
    dngExifMetadata->SetValue(key, value);
}

void ImageDngExifMetadataRemoveEntryFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    uint8_t randomIdx = FDP->ConsumeIntegral<uint8_t>() % HW_KEYS.size();
    std::string key = HW_KEYS[randomIdx];
    dngExifMetadata->RemoveEntry(key);
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

void ImageDngExifMetadataGetExifPropertyFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    dngExifMetadata->dngSdkInfo_ = std::make_unique<DngSdkInfo>();
    MetadataValue value{};
    uint8_t randomIdx = FDP->ConsumeIntegral<uint8_t>() % HW_KEYS.size();
    value.key = HW_KEYS[randomIdx];
    dngExifMetadata->GetExifProperty(value);

    dngExifMetadata->dngSdkInfo_ = nullptr;
    MetadataValue value1{};
    dngExifMetadata->GetExifProperty(value1);
}

void ImageDngExifMetadataGetAllDngPropertiesFuzzTest()
{
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    dngExifMetadata->dngSdkInfo_ = std::make_unique<DngSdkInfo>();
    dngExifMetadata->GetAllDngProperties();
    dngExifMetadata->dngSdkInfo_ = nullptr;
    dngExifMetadata->GetAllDngProperties();
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::ImageDngExifMetadataGetValueFuzzTest();
    OHOS::Media::ImageDngExifMetadataSetValueFuzzTest();
    OHOS::Media::ImageDngExifMetadataRemoveEntryFuzzTest();
    OHOS::Media::ImageDngExifMetadataCloneMetadataFuzzTest();
    OHOS::Media::ImageDngExifMetadataCloneFuzzTest();
    OHOS::Media::ImageDngExifMetadataMarshallingFuzzTest();
    OHOS::Media::ImageDngExifMetadataGetExifPropertyFuzzTest();
    OHOS::Media::ImageDngExifMetadataGetAllDngPropertiesFuzzTest();
    return 0;
}