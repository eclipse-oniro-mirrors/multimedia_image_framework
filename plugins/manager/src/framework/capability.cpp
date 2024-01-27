/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "capability.h"
#include "image_log.h"
#include "json_helper.h"
#include "plugin_common_type.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "Capability"

namespace OHOS {
namespace MultimediaPlugin {
using nlohmann::json;
using std::map;
using std::size_t;
using std::string;
const string Capability::CAPABILITY_BOOL_TRUE = "true";
const string Capability::CAPABILITY_BOOL_FALSE = "false";

Capability::Capability(const map<string, AttrData> &caps) : caps_(caps)
{}

Capability::Capability(map<string, AttrData> &&caps) : caps_(std::move(caps))
{}

uint32_t Capability::SetCapability(const json &capsInfo)
{
    if (!capsInfo.is_array()) {
        IMAGE_LOGE("not a array type value.");
        return ERR_INVALID_PARAMETER;
    }

    if (!caps_.empty()) {
        caps_.clear();
    }

    size_t capNum = capsInfo.size();
    IMAGE_LOGD("class cap num: %{public}zu.", capNum);
    string name;
    for (size_t i = 0; i < capNum; i++) {
        const json &capabilityInfo = capsInfo[i];
        if (JsonHelper::GetStringValue(capabilityInfo, "name", name) != SUCCESS) {
            IMAGE_LOGE("failed to analysis cap name.");
            continue;
        }

        IMAGE_LOGD("get new cap, name: %{public}s.", name.c_str());
        AttrData attrData;
        if (AnalyzeAttrData(capabilityInfo, attrData) != SUCCESS) {
            IMAGE_LOGE("failed to analysis cap value.");
            continue;
        }

        caps_.emplace(std::move(name), std::move(attrData));
    }

    return SUCCESS;
}

bool Capability::IsCompatible(const map<string, AttrData> &caps) const
{
    for (const auto &capability : caps) {
        auto iter = caps_.find(capability.first);
        if (iter == caps_.end()) {
            return false;
        }

        if (!iter->second.InRange(capability.second)) {
            return false;
        }
    }

    return true;
}

const AttrData *Capability::GetCapability(const string &key) const
{
    auto iter = caps_.find(key);
    if (iter == caps_.end()) {
        return nullptr;
    }

    return &(iter->second);
}

const std::map<std::string, AttrData> &Capability::GetCapability() const
{
    return caps_;
}

// ------------------------------- private method -------------------------------
uint32_t Capability::AnalyzeAttrData(const json &capInfo, AttrData &attrData)
{
    string type;
    if (JsonHelper::GetStringValue(capInfo, "type", type) != SUCCESS) {
        IMAGE_LOGE("failed to analysis data type.");
        return ERR_INVALID_PARAMETER;
    }

    std::map<string, AttrDataType> typeMap_ = {
        { "bool", AttrDataType::ATTR_DATA_BOOL },
        { "uint32", AttrDataType::ATTR_DATA_UINT32 },
        { "string", AttrDataType::ATTR_DATA_STRING },
        { "uint32Set", AttrDataType::ATTR_DATA_UINT32_SET },
        { "stringSet", AttrDataType::ATTR_DATA_STRING_SET },
        { "uint32Range", AttrDataType::ATTR_DATA_UINT32_RANGE }
    };

    auto iter = typeMap_.find(type);
    if (iter == typeMap_.end()) {
        IMAGE_LOGE("unknown cap value type: %{public}s.", type.c_str());
        return ERR_INVALID_PARAMETER;
    }

    switch (iter->second) {
        case AttrDataType::ATTR_DATA_BOOL: {
            return AnalyzeBool(capInfo, attrData);
        }
        case AttrDataType::ATTR_DATA_UINT32: {
            return AnalyzeUint32(capInfo, attrData);
        }
        case AttrDataType::ATTR_DATA_STRING: {
            return AnalyzeString(capInfo, attrData);
        }
        case AttrDataType::ATTR_DATA_UINT32_SET: {
            return AnalyzeUint32Set(capInfo, attrData);
        }
        case AttrDataType::ATTR_DATA_STRING_SET: {
            return AnalyzeStringSet(capInfo, attrData);
        }
        case AttrDataType::ATTR_DATA_UINT32_RANGE: {
            return AnalyzeUint32Range(capInfo, attrData);
        }
        default: {
            IMAGE_LOGE("unexpected cap value type: %{public}d.", iter->second);
            return ERR_INTERNAL;
        }
    }

    return SUCCESS;
}

uint32_t Capability::AnalyzeBool(const json &capInfo, AttrData &attrData)
{
    string value;
    if (JsonHelper::GetStringValue(capInfo, "value", value) != SUCCESS) {
        IMAGE_LOGE("failed to analysis bool value.");
        return ERR_INVALID_PARAMETER;
    }

    bool attrValue = false;
    if (value == CAPABILITY_BOOL_TRUE) {
        attrValue = true;
    } else if (value == CAPABILITY_BOOL_FALSE) {
        attrValue = false;
    } else {
        IMAGE_LOGE("failed to analyze bool value: %{public}s.", value.c_str());
        return ERR_INVALID_PARAMETER;
    }

    IMAGE_LOGD("get bool AttrData: %{public}s.", value.c_str());
    attrData.SetData(attrValue);

    return SUCCESS;
}

uint32_t Capability::AnalyzeUint32(const json &capInfo, AttrData &attrData)
{
    uint32_t value;
    if (JsonHelper::GetUint32Value(capInfo, "value", value) != SUCCESS) {
        IMAGE_LOGE("failed to analysis uint32 value.");
        return ERR_INVALID_PARAMETER;
    }

    IMAGE_LOGD("get uint32 AttrData: %{public}u.", value);
    attrData.SetData(value);

    return SUCCESS;
}

uint32_t Capability::AnalyzeString(const json &capInfo, AttrData &attrData)
{
    string value;
    if (JsonHelper::GetStringValue(capInfo, "value", value) != SUCCESS) {
        IMAGE_LOGE("failed to analysis string value.");
        return ERR_INVALID_PARAMETER;
    }

    if (value.empty()) {
        IMAGE_LOGE("failed to analyze string value.");
        return ERR_INVALID_PARAMETER;
    }

    IMAGE_LOGD("get string AttrData: %{public}s.", value.c_str());
    if (attrData.SetData(std::move(value)) != SUCCESS) {
        IMAGE_LOGE("AnalyzeString: failed to call SetData for string type.");
        return ERR_INTERNAL;
    }

    return SUCCESS;
}

uint32_t Capability::AnalyzeUint32Set(const json &capInfo, AttrData &attrData)
{
    size_t arraySize;
    if (JsonHelper::GetArraySize(capInfo, "value", arraySize) != SUCCESS) {
        IMAGE_LOGE("failed to analysis uint32Set value.");
        return ERR_INVALID_PARAMETER;
    }
    IMAGE_LOGD("uint32Set size: %{public}zu.", arraySize);

    if (arraySize < SET_MIN_VALUE_NUM) {
        IMAGE_LOGE("invalid uint32Set size: %{public}zu.", arraySize);
        return ERR_INVALID_PARAMETER;
    }

    uint32_t value;
    const json &valueArray = capInfo["value"];
    for (size_t i = 0; i < arraySize; i++) {
        if (JsonHelper::GetUint32Value(valueArray[i], value) != SUCCESS) {
            IMAGE_LOGE("fail to analyze uint32Set[%{public}zu]: %{public}u.", i, value);
            attrData.ClearData();
            return ERR_INVALID_PARAMETER;
        }
        IMAGE_LOGD("get uint32Set[%{public}zu]: %{public}u.", i, value);
        if (attrData.InsertSet(value) != SUCCESS) {
            IMAGE_LOGE("AnalyzeUint32Set: failed to call InsertSet.");
            attrData.ClearData();
            return ERR_INTERNAL;
        }
    }

    return SUCCESS;
}

uint32_t Capability::AnalyzeUint32Range(const json &capInfo, AttrData &attrData)
{
    size_t arraySize;
    if (JsonHelper::GetArraySize(capInfo, "value", arraySize) != SUCCESS) {
        IMAGE_LOGE("failed to analysis uint32Range value.");
        return ERR_INVALID_PARAMETER;
    }
    IMAGE_LOGD("uint32Range size: %{public}zu.", arraySize);

    if (arraySize != AttrData::RANGE_ARRAY_SIZE) {
        IMAGE_LOGE("invalid uint32Range size: %{public}zu.", arraySize);
        return ERR_INVALID_PARAMETER;
    }

    const json &valueArray = capInfo["value"];
    uint32_t lowerBound = 0;
    if (JsonHelper::GetUint32Value(valueArray[AttrData::LOWER_BOUND_INDEX], lowerBound) != SUCCESS) {
        IMAGE_LOGE("fail to analyze uint32 value of lowerBound: %{public}u.", lowerBound);
        return ERR_INVALID_PARAMETER;
    }

    uint32_t upperBound = 0;
    if (JsonHelper::GetUint32Value(valueArray[AttrData::UPPER_BOUND_INDEX], upperBound) != SUCCESS) {
        IMAGE_LOGE("fail to analyze uint32 value of upperBound: %{public}u.", upperBound);
        return ERR_INVALID_PARAMETER;
    }

    IMAGE_LOGD("AnalyzeUint32Range: get lowerBound: %{public}u, upperBound: %{public}u.", lowerBound, upperBound);
    if (attrData.SetData(lowerBound, upperBound) != SUCCESS) {
        IMAGE_LOGE("AnalyzeUint32Range: failed to call SetData.");
        return ERR_INTERNAL;
    }

    return SUCCESS;
}

uint32_t Capability::AnalyzeStringSet(const json &capInfo, AttrData &attrData)
{
    size_t arraySize;
    if (JsonHelper::GetArraySize(capInfo, "value", arraySize) != SUCCESS) {
        IMAGE_LOGE("failed to analysis stringSet value.");
        return ERR_INVALID_PARAMETER;
    }
    IMAGE_LOGD("stringSet size: %{public}zu.", arraySize);

    if (arraySize < SET_MIN_VALUE_NUM) {
        IMAGE_LOGE("invalid stringSet size: %{public}zu.", arraySize);
        return ERR_INVALID_PARAMETER;
    }

    const json &valueArray = capInfo["value"];
    string value;
    for (size_t i = 0; i < arraySize; i++) {
        if (JsonHelper::GetStringValue(valueArray[i], value) != SUCCESS) {
            IMAGE_LOGE("failed to analyze string value in stringSet[%{public}zu].", i);
            attrData.ClearData();
            return ERR_INVALID_PARAMETER;
        }

        IMAGE_LOGD("AnalyzeStringSet: get stringSet[%{public}zu]: %{public}s.", i, value.c_str());
        if (attrData.InsertSet(std::move(value)) != SUCCESS) {
            IMAGE_LOGE("AnalyzeStringSet: failed to call InsertSet.");
            attrData.ClearData();
            return ERR_INTERNAL;
        }
    }

    return SUCCESS;
}
} // namespace MultimediaPlugin
} // namespace OHOS
