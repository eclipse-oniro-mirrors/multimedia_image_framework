/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "media_errors.h"
#include "metadata_taihe.h"
#include "image_common.h"
#include "image_log.h"
#include "image_taihe_utils.h"

using namespace ANI::Image;

namespace ANI::Image {

struct MetadataTaiheContext {
    uint32_t status;
    std::shared_ptr<OHOS::Media::ImageMetadata> rMetadata;
    std::vector<std::string> keyStrArray;
    std::multimap<int32_t, std::string> errMsgArray;
    std::vector<std::pair<std::string, std::string>> kVStrArray;
};

MetadataImpl::MetadataImpl() {}

MetadataImpl::MetadataImpl(std::shared_ptr<OHOS::Media::ImageMetadata> imageMetadata)
{
    nativeMetadata_ = imageMetadata;
    if (nativeMetadata_  == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Failed to set nativeMetadata_ with null. Maybe a reentrancy error");
    }
}

MetadataImpl::~MetadataImpl()
{
    Release();
}

int64_t MetadataImpl::GetImplPtr()
{
    return static_cast<int64_t>(reinterpret_cast<uintptr_t>(this));
}

std::shared_ptr<OHOS::Media::ImageMetadata> MetadataImpl::GetNativeMetadata()
{
    return nativeMetadata_;
}

static std::vector<std::string> GetKeyStrArray(array_view<string> const& key)
{
    std::vector<std::string> keyStrArray;
    for (const auto& str : key) {
        keyStrArray.emplace_back(str);
    }
    return keyStrArray;
}

static void GetPropertiesSyncExecute(std::unique_ptr<MetadataTaiheContext> &context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    uint32_t status = OHOS::Media::SUCCESS;
    for (auto keyStrIt = context->keyStrArray.begin(); keyStrIt != context->keyStrArray.end(); ++keyStrIt) {
        std::string valueStr = "";
        status = static_cast<uint32_t>(context->rMetadata->GetValue(*keyStrIt, valueStr));
        if (status == OHOS::Media::SUCCESS) {
            context->kVStrArray.emplace_back(std::make_pair(*keyStrIt, valueStr));
        } else {
            context->kVStrArray.emplace_back(std::make_pair(*keyStrIt, ""));
            context->errMsgArray.insert(std::make_pair(status, *keyStrIt));
            IMAGE_LOGE("ErrCode: %{public}u , exif key: %{public}s", status, keyStrIt->c_str());
        }
    }
    context->status =
        context->kVStrArray.size() == context->errMsgArray.size() ? OHOS::Media::ERROR : OHOS::Media::SUCCESS;
}

static PropertyValue CreatePropertyValue(std::string const& valueStr)
{
    if (!valueStr.empty()) {
        return PropertyValue::make_type_string(valueStr);
    } else {
        return PropertyValue::make_type_null();
    }
}

static map<string, PropertyValue> CreatePropertiesRecord(
    std::vector<std::pair<std::string, std::string>> const& kVStrArray)
{
    map<string, PropertyValue> result;
    for (size_t index = 0; index < kVStrArray.size(); ++index) {
        string key = kVStrArray[index].first;
        PropertyValue value = CreatePropertyValue(kVStrArray[index].second);
        result.emplace(key, value);
    }
    IMAGE_LOGD("Get record parameters info success.");
    return result;
}

static bool FragmentValueIsError(std::multimap<std::int32_t, std::string> const& errMsgArray)
{
    static std::set<std::string> fragmentKeys = {
        "XInOriginal", "YInOriginal", "FragmentImageWidth", "FragmentImageHeight"
    };
    for (const auto &errMsg : errMsgArray) {
        if (fragmentKeys.find(errMsg.second) != fragmentKeys.end()) {
            return true;
        }
    }
    return false;
}

static void CreateErrorArray(std::unique_ptr<MetadataTaiheContext> const& context)
{
    std::string errkey = "";
    if (context->errMsgArray.empty()) {
        return;
    }
    for (const auto &errMsg : context->errMsgArray) {
        errkey += errMsg.second + " ";
    }
    if (context->rMetadata->GetType() == OHOS::Media::MetadataType::FRAGMENT &&
        FragmentValueIsError(context->errMsgArray)) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "The input value is incorrect!");
    } else {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_UNSUPPORTED_METADATA,
            "The input data is incorrect! error key: " + errkey);
    }
}

static map<string, PropertyValue> GetPropertiesSyncComplete(std::unique_ptr<MetadataTaiheContext> const& context)
{
    map<string, PropertyValue> result;
    if (context == nullptr) {
        IMAGE_LOGE("Context is nullptr");
        return result;
    }
    if (context->status == OHOS::Media::SUCCESS) {
        result = CreatePropertiesRecord(context->kVStrArray);
    } else {
        CreateErrorArray(context);
    }
    return result;
}

map<string, PropertyValue> MetadataImpl::GetPropertiesSync(array_view<string> key)
{
    std::unique_ptr<MetadataTaiheContext> context = std::make_unique<MetadataTaiheContext>();
    context->rMetadata = nativeMetadata_;
    map<string, PropertyValue> result;
    if (context->rMetadata == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Empty native metadata.");
        return result;
    }
    context->keyStrArray = GetKeyStrArray(key);
    GetPropertiesSyncExecute(context);
    result = GetPropertiesSyncComplete(context);
    return result;
}

static std::vector<std::pair<std::string, std::string>> GetKVStrArray(map_view<string, PropertyValue> const& records)
{
    std::vector<std::pair<std::string, std::string>> kVStrArray;
    for (const auto& [key, value] : records) {
        std::string valueStr;
        if (value.holds_type_string()) {
            valueStr = std::string(value.get_type_string_ref());
        } else if (value.holds_type_null()) {
            valueStr = "";
        }
        kVStrArray.emplace_back(key, valueStr);
    }
    IMAGE_LOGD("Get record argument success.");
    return kVStrArray;
}

static void SetPropertiesSyncExecute(std::unique_ptr<MetadataTaiheContext> &context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    uint32_t status = OHOS::Media::SUCCESS;
    for (auto kVStrIt = context->kVStrArray.begin(); kVStrIt != context->kVStrArray.end(); ++kVStrIt) {
        IMAGE_LOGD("CheckExifDataValue");
        status = context->rMetadata->SetValue(kVStrIt->first, kVStrIt->second);
        IMAGE_LOGD("Check ret status: %{public}d", status);
        if (!status) {
            IMAGE_LOGE("There is invalid exif data parameter");
            context->errMsgArray.insert(std::make_pair(status, kVStrIt->first));
        }
    }
    context->status = context->errMsgArray.size() > 0 ? OHOS::Media::ERROR : OHOS::Media::SUCCESS;
}

static void SetPropertiesComplete(std::unique_ptr<MetadataTaiheContext> const& context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    CreateErrorArray(context);
}

void MetadataImpl::SetPropertiesSync(map_view<string, PropertyValue> records)
{
    std::unique_ptr<MetadataTaiheContext> context = std::make_unique<MetadataTaiheContext>();
    context->rMetadata = nativeMetadata_;
    if (context->rMetadata == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Empty native metadata.");
        return;
    }
    context->kVStrArray = GetKVStrArray(records);
    SetPropertiesSyncExecute(context);
    SetPropertiesComplete(context);
}

static void GetAllPropertiesSyncExecute(std::unique_ptr<MetadataTaiheContext> &context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    OHOS::Media::ImageMetadata::PropertyMapPtr allKey = context->rMetadata->GetAllProperties();
    for (const auto &entry : *allKey) {
        context->kVStrArray.emplace_back(std::make_pair(entry.first, entry.second));
    }
    context->status = OHOS::Media::SUCCESS;
}

static map<string, PropertyValue> GetAllPropertiesSyncComplete(std::unique_ptr<MetadataTaiheContext> const& context)
{
    map<string, PropertyValue> result;
    if (context == nullptr) {
        IMAGE_LOGE("Context is nullptr");
        return result;
    }
    if (context->status == OHOS::Media::SUCCESS) {
        result = CreatePropertiesRecord(context->kVStrArray);
    } else {
        CreateErrorArray(context);
    }
    return result;
}

map<string, PropertyValue> MetadataImpl::GetAllPropertiesSync()
{
    std::unique_ptr<MetadataTaiheContext> context = std::make_unique<MetadataTaiheContext>();
    context->rMetadata = nativeMetadata_;
    map<string, PropertyValue> result;
    if (context->rMetadata == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Empty native metadata.");
        return result;
    }
    GetAllPropertiesSyncExecute(context);
    result = GetAllPropertiesSyncComplete(context);
    return result;
}

Metadata MetadataImpl::CloneSync()
{
    if (nativeMetadata_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Empty native metadata.");
        return make_holder<MetadataImpl, Metadata>();
    }
    auto metadata = nativeMetadata_->CloneMetadata();
    return make_holder<MetadataImpl, Metadata>(std::move(metadata));
}

void MetadataImpl::Release()
{
    if (!isRelease) {
        if (nativeMetadata_ != nullptr) {
            nativeMetadata_ = nullptr;
        }
        isRelease = true;
    }
}

} // namespace ANI::Image