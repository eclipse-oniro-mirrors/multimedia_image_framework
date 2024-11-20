/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <iostream>
#include "fragment_metadata.h"
#include "image_log.h"
#include "image_utils.h"
#include "media_errors.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "FragmentMetadata"

namespace OHOS {
namespace Media {
const static uint64_t MAX_FRAGMENT_MAP_META_COUNT = 10;
const static uint64_t MAX_FRAGMENT_MAP_META_LENGTH = 100;
FragmentMetadata::FragmentMetadata() {}

FragmentMetadata::FragmentMetadata(const FragmentMetadata& fragmentMetadata)
{
    if (fragmentMetadata.properties_ != nullptr) {
        properties_ = std::make_shared<ImageMetadata::PropertyMap>(*fragmentMetadata.properties_);
    }
}

FragmentMetadata::~FragmentMetadata() {}

static bool IsValidKey(const std::string &key)
{
    return FRAGMENT_METADATA_KEYS.find(key) != FRAGMENT_METADATA_KEYS.end();
}

int FragmentMetadata::GetValue(const std::string &key, std::string &value) const
{
    if (properties_ == nullptr) {
        IMAGE_LOGE("%{public}s properties is nullptr.", __func__);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!IsValidKey(key)) {
        IMAGE_LOGE("Key is not supported.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    auto it = properties_->find(key);
    if (it != properties_->end()) {
        value = it->second;
        return SUCCESS;
    }
    IMAGE_LOGE("key is not found in properties: %{public}s", key.c_str());
    return ERR_IMAGE_INVALID_PARAMETER;
}

bool FragmentMetadata::SetValue(const std::string &key, const std::string &value)
{
    if (!IsValidKey(key)) {
        IMAGE_LOGE("Key is not supported.");
        return false;
    }
    if (properties_ == nullptr) {
        IMAGE_LOGE("SetValue: properties_ is nullptr");
        return false;
    }
    uint32_t casted;
    if (!ImageUtils::StrToUint32(value, casted)) {
        IMAGE_LOGE("Invalid value: %{public}s.", value.c_str());
        return false;
    }

    if (properties_->size() >= MAX_FRAGMENT_MAP_META_COUNT) {
        IMAGE_LOGE("Failed to set value, the size of metadata properties exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_FRAGMENT_MAP_META_COUNT));
        return false;
    }
    if (key.length() > MAX_FRAGMENT_MAP_META_LENGTH || value.length() > MAX_FRAGMENT_MAP_META_LENGTH) {
        IMAGE_LOGE("Failed to set value, the length of fragment string exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_FRAGMENT_MAP_META_LENGTH));
        return false;
    }
    (*properties_)[key] = value;
    return true;
}

bool FragmentMetadata::RemoveEntry(const std::string &key)
{
    if (properties_ == nullptr) {
        IMAGE_LOGE("%{public}s properties is nullptr.", __func__);
        return false;
    }
    if (!IsValidKey(key)) {
        IMAGE_LOGE("Key is not supported.");
        return false;
    }
    auto it = properties_->find(key);
    if (it != properties_->end()) {
        properties_->erase(it);
        IMAGE_LOGD("RemoveEntry for key: %{public}s", key.c_str());
        return true;
    } else {
        IMAGE_LOGE("RemoveEntry failed, key is not found in properties: %{public}s", key.c_str());
        return false;
    }
}

const ImageMetadata::PropertyMapPtr FragmentMetadata::GetAllProperties()
{
    return properties_;
}

std::shared_ptr<ImageMetadata> FragmentMetadata::CloneMetadata()
{
    if (properties_->size() > MAX_FRAGMENT_MAP_META_COUNT) {
        IMAGE_LOGE("Failed to clone, the size of metadata properties exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_FRAGMENT_MAP_META_COUNT));
        return nullptr;
    }
    return std::make_shared<FragmentMetadata>(*this);
}

bool FragmentMetadata::Marshalling(Parcel &parcel) const
{
    if (properties_ == nullptr) {
        IMAGE_LOGE("%{public}s properties is nullptr.", __func__);
        return false;
    }
    if (properties_->size() > MAX_FRAGMENT_MAP_META_COUNT) {
        IMAGE_LOGE("The number of metadata properties exceeds the maximum limit.");
        return false;
    }
    if (!parcel.WriteUint64(properties_->size())) {
        return false;
    }
    for (const auto &pair : *properties_) {
        if (!IsValidKey(pair.first)) {
            IMAGE_LOGE("The key of fragmentmetadata is invalid.");
            return false;
        }
        uint32_t casted;
        if (!ImageUtils::StrToUint32(pair.second, casted)) {
            IMAGE_LOGE("The Value of fragmentmetadata is invalid.");
            return false;
        }
        if (pair.first.length() > MAX_FRAGMENT_MAP_META_LENGTH || pair.second.length() > MAX_FRAGMENT_MAP_META_LENGTH) {
            IMAGE_LOGE("The length of fragment string exceeds the maximum limit.");
            return false;
        }
        if (!parcel.WriteString(pair.first)) {
            return false;
        }
        if (!parcel.WriteString(pair.second)) {
            return false;
        }
    }
    return true;
}

FragmentMetadata *FragmentMetadata::Unmarshalling(Parcel &parcel)
{
    PICTURE_ERR error;
    FragmentMetadata* dstFragmentMetadata = FragmentMetadata::Unmarshalling(parcel, error);
    if (dstFragmentMetadata == nullptr || error.errorCode != SUCCESS) {
        IMAGE_LOGE("unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
            error.errorCode, error.errorInfo.c_str());
    }
    return dstFragmentMetadata;
}

FragmentMetadata *FragmentMetadata::Unmarshalling(Parcel &parcel, PICTURE_ERR &error)
{
    std::unique_ptr<FragmentMetadata> fragmentMetadataPtr = std::make_unique<FragmentMetadata>();
    uint64_t size;
    if (!parcel.ReadUint64(size)) {
        return nullptr;
    }
    if (size > MAX_FRAGMENT_MAP_META_COUNT) {
        return nullptr;
    }
    if (fragmentMetadataPtr->properties_ == nullptr) {
        IMAGE_LOGE("Unmarshalling: fragmentMetadataPtr->properties_ is nullptr");
        return nullptr;
    }
    for (uint64_t i = 0; i < size; ++i) {
        std::string key;
        std::string value;
        if (!parcel.ReadString(key)) {
            return nullptr;
        }
        if (!parcel.ReadString(value)) {
            return nullptr;
        }
        if (!IsValidKey(key)) {
            IMAGE_LOGE("The key of fragmentmetadata is invalid.");
            return nullptr;
        }
        uint32_t casted;
        if (!ImageUtils::StrToUint32(value, casted)) {
            IMAGE_LOGE("The Value of fragmentmetadata is invalid.");
            return nullptr;
        }
        if (key.length() > MAX_FRAGMENT_MAP_META_LENGTH || value.length() > MAX_FRAGMENT_MAP_META_LENGTH) {
            IMAGE_LOGE("The length of fragment string exceeds the maximum limit.");
            return nullptr;
        }
        fragmentMetadataPtr->properties_->insert(std::make_pair(key, value));
    }
    return fragmentMetadataPtr.release();
}

} // namespace Media
} // namespace OHOS