/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dng/dng_exif_metadata.h"

#include "dng/dng_sdk_helper.h"
#include "exif_metadata.h"
#include "image_log.h"
#include "media_errors.h"
#include <set>
#include <vector>

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "DngExifMetadata"

namespace OHOS {
namespace Media {
static const std::vector<std::string> HW_KEYS = {
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
};

DngExifMetadata::DngExifMetadata() : dngSdkInfo_(nullptr)
{
}

DngExifMetadata::DngExifMetadata(ExifData* exifData, std::unique_ptr<DngSdkInfo>& dngSdkInfo)
    : ExifMetadata(exifData), dngSdkInfo_(dngSdkInfo ? dngSdkInfo.release() : nullptr)
{
    if (dngSdkInfo_ == nullptr) {
        IMAGE_LOGE("dngSdkInfo_ is nullptr in constructor");
    }
}

DngExifMetadata::~DngExifMetadata()
{
}

int DngExifMetadata::GetValue(const std::string &key, std::string &value) const
{
    return ExifMetadata::GetValue(key, value);
}

bool DngExifMetadata::SetValue(const std::string &key, const std::string &value)
{
    return ExifMetadata::SetValue(key, value);
}

bool DngExifMetadata::RemoveEntry(const std::string &key)
{
    return ExifMetadata::RemoveEntry(key);
}

std::shared_ptr<ImageMetadata> DngExifMetadata::CloneMetadata()
{
    return ExifMetadata::CloneMetadata();
}

std::shared_ptr<DngExifMetadata> DngExifMetadata::Clone()
{
    return nullptr;
}

bool DngExifMetadata::Marshalling(Parcel &parcel) const
{
    if (!ExifMetadata::Marshalling(parcel)) {
        return false;
    }

    return true;
}

uint32_t DngExifMetadata::GetExifProperty(MetadataValue& value)
{
    static constexpr uint32_t hwKeySize = 2;
    if (dngSdkInfo_ == nullptr) {
        IMAGE_LOGE("[%{public}s] dngSdkInfo_ is nullptr", __func__);
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    if ((value.key.size() > hwKeySize && value.key.substr(0, hwKeySize) == "Hw") || IsSpecialHwKey(value.key)) {
        std::string key = value.key;
        uint32_t ret = ExifMetadata::GetValueByType(key, value);
        value.type = ExifMetadata::GetPropertyValueType(key);
        value.key = key;
        return ret;
    } else {
        return DngSdkHelper::GetExifProperty(dngSdkInfo_, value);
    }
}


std::vector<MetadataValue> DngExifMetadata::GetAllDngProperties()
{
    std::vector<MetadataValue> result;
    if (dngSdkInfo_ == nullptr) {
        IMAGE_LOGE("[%{public}s] dngSdkInfo_ is nullptr", __func__);
        return result;
    }

    static const std::set<std::string> ALL_KEYS_CACHE = []() {
        std::set<std::string> keys = DngSdkInfo::GetAllPropertyKeys();
        keys.insert(HW_KEYS.begin(), HW_KEYS.end());
        return keys;
    }();

    for (const auto& key : ALL_KEYS_CACHE) {
        MetadataValue value;
        value.key = key;
        uint32_t ret = GetExifProperty(value);
        if (ret == SUCCESS) {
            result.push_back(value);
            continue;
        }
        IMAGE_LOGW("[%{public}s] Failed to get property: %{public}s", __func__, key.c_str());
    }

    return result;
}
} // namespace Media
} // namespace OHOS
