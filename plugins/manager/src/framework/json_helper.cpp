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

#include "json_helper.h"
#include "image_log.h"
#include "plugin_common_type.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "JsonHelper"

namespace OHOS {
namespace MultimediaPlugin {
using nlohmann::json;
using std::string;
json JsonHelper::nullJson_;

uint32_t JsonHelper::CheckElementExistence(const json &jsonObject, const string &key)
{
    uint32_t errorCode;
    GetJsonElement(jsonObject, key, errorCode);
    return errorCode;
}

uint32_t JsonHelper::GetStringValue(const json &jsonString, string &value)
{
    if (!jsonString.is_string()) {
        IMAGE_LOGE("GetStringValue: not a string type value.");
        return ERR_DATA_TYPE;
    }

    value = jsonString;
    return SUCCESS;
}

uint32_t JsonHelper::GetStringValue(const json &jsonObject, const string &key, string &value)
{
    uint32_t result;
    const json &jsonString = GetJsonElement(jsonObject, key, result);
    if (result != SUCCESS) {
        PrintElementMissingLog("GetStringValue", key, result);
        return result;
    }

    return GetStringValue(jsonString, value);
}

uint32_t JsonHelper::GetUint32Value(const json &jsonNum, uint32_t &value)
{
    if (!jsonNum.is_number_integer()) {
        IMAGE_LOGE("GetUint32Value: not a integer type value.");
        return ERR_DATA_TYPE;
    }

    bool cond = jsonNum < 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_DATA_TYPE,
                               "GetUint32Value: not a unsigned integer type value, num: %{public}lld.",
                               static_cast<long long>(jsonNum));

    cond = jsonNum > UINT32_MAX_VALUE;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_DATA_TYPE, "GetUint32Value: out of range value, num: %{public}llu.",
                               static_cast<unsigned long long>(jsonNum));

    value = jsonNum;
    return SUCCESS;
}

uint32_t JsonHelper::GetUint32Value(const json &jsonObject, const string &key, uint32_t &value)
{
    uint32_t result;
    const json &jsonNum = GetJsonElement(jsonObject, key, result);
    if (result != SUCCESS) {
        PrintElementMissingLog("GetUint32Value", key, result);
        return result;
    }

    return GetUint32Value(jsonNum, value);
}

uint32_t JsonHelper::GetUint16Value(const json &jsonObject, const string &key, uint16_t &value)
{
    uint32_t result;
    const json &jsonNum = GetJsonElement(jsonObject, key, result);
    if (result != SUCCESS) {
        PrintElementMissingLog("GetUint16Value", key, result);
        return result;
    }

    if (!jsonNum.is_number_integer()) {
        IMAGE_LOGE("GetUint16Value: not a integer type value for key %{public}s.", key.c_str());
        return ERR_DATA_TYPE;
    }

    if (jsonNum < 0) {
        IMAGE_LOGE("GetUint16Value: not a unsigned integer type value for key %{public}s, num: %{public}lld.",
            key.c_str(), static_cast<long long>(jsonNum));
        return ERR_DATA_TYPE;
    }

    if (jsonNum > UINT16_MAX_VALUE) {
        IMAGE_LOGE("GetUint16Value: out of range value for key %{public}s, num: %{public}llu.", key.c_str(),
            static_cast<unsigned long long>(jsonNum));
        return ERR_DATA_TYPE;
    }

    value = jsonNum;
    return SUCCESS;
}

uint32_t JsonHelper::GetArraySize(const json &jsonObject, const string &key, size_t &size)
{
    uint32_t result;
    const json &jsonArray = GetJsonElement(jsonObject, key, result);
    if (result != SUCCESS) {
        PrintElementMissingLog("GetArraySize", key, result);
        return result;
    }

    if (!jsonArray.is_array()) {
        IMAGE_LOGE("GetArraySize: not a array type value for key %{public}s.", key.c_str());
        return ERR_DATA_TYPE;
    }

    size = jsonArray.size();
    return SUCCESS;
}

// ------------------------------- private method -------------------------------
const json &JsonHelper::GetJsonElement(const json &jsonObject, const string &key, uint32_t &errorCode)
{
    if (!jsonObject.is_object()) {
        IMAGE_LOGE("GetJsonElement: not an object type json for key %{public}s.", key.c_str());
        errorCode = ERR_DATA_TYPE;
        return nullJson_;
    }

    auto iter = jsonObject.find(key);
    if (iter == jsonObject.end()) {
        // some elements are optional, it is normal to miss them, so do not use error level here.
        IMAGE_LOGD("GetJsonElement: failed to find key %{public}s.", key.c_str());
        errorCode = ERR_NO_TARGET;
        return nullJson_;
    }

    errorCode = SUCCESS;
    return *iter;
}

void JsonHelper::PrintElementMissingLog(const std::string &identifier, const std::string &key, uint32_t errorCode)
{
    if (errorCode == ERR_NO_TARGET) {
        // some elements are optional, it is normal to miss them, so do not use error level here.
        IMAGE_LOGD("%{public}s: failed to find key %{public}s, ERRNO: %{public}u.", identifier.c_str(),
            key.c_str(), errorCode);
    } else {
        IMAGE_LOGE("%{public}s: failed to find key %{public}s, ERRNO: %{public}u.", identifier.c_str(),
            key.c_str(), errorCode);
    }
}
} // namespace MultimediaPlugin
} // namespace OHOS
