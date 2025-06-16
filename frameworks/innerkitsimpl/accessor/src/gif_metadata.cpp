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

#include <iostream>
#include "gif_metadata.h"
#include "image_log.h"
#include "image_utils.h"
#include "media_errors.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "GifMetadata"

namespace OHOS {
namespace Media {
const static uint64_t MAX_GIF_META_COUNT = 10;
const static uint64_t MAX_GIF_META_LENGTH = 128;

const static std::set<std::string> GIF_METADATA_KEYS = {
    GIF_METADATA_KEY_DELAY_TIME,
    GIF_METADATA_KEY_DISPOSAL_TYPE,
};

GifMetadata::GifMetadata() {}

GifMetadata::GifMetadata(const GifMetadata &gifMetadata)
{
    CHECK_ERROR_RETURN(gifMetadata.properties_ == nullptr);
    properties_ = std::make_shared<ImageMetadata::PropertyMap>(*gifMetadata.properties_);
}

GifMetadata::~GifMetadata() {}

static bool IsValidKey(const std::string &key)
{
    return GIF_METADATA_KEYS.find(key) != GIF_METADATA_KEYS.end();
}

int GifMetadata::GetValue(const std::string &key, std::string &value) const
{
    CHECK_ERROR_RETURN_RET_LOG(properties_ == nullptr, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s properties is nullptr.", __func__);
    if (!IsValidKey(key)) {
        IMAGE_LOGE("Key is not supported.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    auto it = properties_->find(key);
    if (it == properties_->end()) {
        IMAGE_LOGE("key is not found in properties: %{public}s", key.c_str());
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    value = it->second;
    return SUCCESS;
}

bool GifMetadata::SetValue(const std::string &key, const std::string &value)
{
    CHECK_ERROR_RETURN_RET_LOG(properties_ == nullptr, false, "SetValue: properties_ is nullptr");
    if (!IsValidKey(key)) {
        IMAGE_LOGE("Key is not supported.");
        return false;
    }

    uint32_t casted;
    if (!ImageUtils::StrToUint32(value, casted)) {
        IMAGE_LOGE("Invalid value: %{public}s.", value.c_str());
        return false;
    }

    if (properties_->size() >= MAX_GIF_META_COUNT) {
        IMAGE_LOGE("Failed to set value, the size of metadata properties exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_GIF_META_COUNT));
        return false;
    }
    if (key.length() > MAX_GIF_META_LENGTH || value.length() > MAX_GIF_META_LENGTH) {
        IMAGE_LOGE("Failed to set value, the length of gif string exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_GIF_META_LENGTH));
        return false;
    }
    (*properties_)[key] = value;
    return true;
}

bool GifMetadata::RemoveEntry(const std::string &key)
{
    CHECK_ERROR_RETURN_RET_LOG(properties_ == nullptr, false, "%{public}s properties is nullptr.", __func__);
    if (!IsValidKey(key)) {
        IMAGE_LOGE("Key is not supported.");
        return false;
    }

    auto it = properties_->find(key);
    if (it == properties_->end()) {
        IMAGE_LOGE("RemoveEntry failed, key is not found in properties: %{public}s", key.c_str());
        return false;
    }
    properties_->erase(it);
    IMAGE_LOGD("RemoveEntry for key: %{public}s", key.c_str());
    return true;
}

const ImageMetadata::PropertyMapPtr GifMetadata::GetAllProperties()
{
    return properties_;
}

std::shared_ptr<ImageMetadata> GifMetadata::CloneMetadata()
{
    CHECK_ERROR_RETURN_RET_LOG(properties_ == nullptr, nullptr, "%{public}s properties is nullptr.", __func__);
    if (properties_->size() > MAX_GIF_META_COUNT) {
        IMAGE_LOGE("Failed to clone, the size of metadata properties exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_GIF_META_COUNT));
        return nullptr;
    }
    return std::make_shared<GifMetadata>(*this);
}

bool GifMetadata::Marshalling(Parcel &parcel) const
{
    CHECK_ERROR_RETURN_RET_LOG(properties_ == nullptr, false, "%{public}s properties is nullptr.", __func__);
    if (properties_->size() > MAX_GIF_META_COUNT) {
        IMAGE_LOGE("The number of metadata properties exceeds the maximum limit.");
        return false;
    }
    if (!parcel.WriteUint64(properties_->size())) {
        return false;
    }
    for (const auto &[key, value] : *properties_) {
        if (!IsValidKey(key)) {
            IMAGE_LOGE("The key of gif metadata is invalid.");
            return false;
        }
        uint32_t casted;
        if (!ImageUtils::StrToUint32(value, casted)) {
            IMAGE_LOGE("The Value of gif metadata is invalid.");
            return false;
        }
        if (key.length() > MAX_GIF_META_LENGTH || value.length() > MAX_GIF_META_LENGTH) {
            IMAGE_LOGE("The length of gif string exceeds the maximum limit.");
            return false;
        }
        if (!parcel.WriteString(key)) {
            return false;
        }
        if (!parcel.WriteString(value)) {
            return false;
        }
    }
    return true;
}

GifMetadata *GifMetadata::Unmarshalling(Parcel &parcel)
{
    PICTURE_ERR error;
    GifMetadata* dstGifMetadata = GifMetadata::Unmarshalling(parcel, error);
    if (dstGifMetadata == nullptr || error.errorCode != SUCCESS) {
        IMAGE_LOGE("unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
            error.errorCode, error.errorInfo.c_str());
    }
    return dstGifMetadata;
}

GifMetadata *GifMetadata::Unmarshalling(Parcel &parcel, PICTURE_ERR &error)
{
    std::unique_ptr<GifMetadata> gifMetadataPtr = std::make_unique<GifMetadata>();
    CHECK_ERROR_RETURN_RET_LOG(gifMetadataPtr == nullptr, nullptr, "%{public}s make_unique failed", __func__);
    uint64_t size = 0;
    if (!parcel.ReadUint64(size)) {
        return nullptr;
    }
    if (size > MAX_GIF_META_COUNT) {
        return nullptr;
    }
    if (gifMetadataPtr->properties_ == nullptr) {
        IMAGE_LOGE("Unmarshalling: gifMetadataPtr->properties_ is nullptr");
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
            IMAGE_LOGE("The key of gif metadata is invalid.");
            return nullptr;
        }
        uint32_t casted = 0;
        if (!ImageUtils::StrToUint32(value, casted)) {
            IMAGE_LOGE("The Value of gif metadata is invalid.");
            return nullptr;
        }
        if (key.length() > MAX_GIF_META_LENGTH || value.length() > MAX_GIF_META_LENGTH) {
            IMAGE_LOGE("The length of gif string exceeds the maximum limit.");
            return nullptr;
        }
        gifMetadataPtr->properties_->insert(std::make_pair(key, value));
    }
    return gifMetadataPtr.release();
}
} // namespace Media
} // namespace OHOS