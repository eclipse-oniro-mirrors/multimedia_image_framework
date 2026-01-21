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
#include "kv_metadata.h"
#include "image_log.h"
#include "image_utils.h"
#include "media_errors.h"
#include "securec.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageKvMetadata"

namespace OHOS {
namespace Media {
const static uint64_t MAX_KV_META_COUNT = 10;
const static uint64_t MAX_KV_META_STRING_LENGTH = 128;

const static std::set<std::string> FRAGMENT_METADATA_KEYS = {
    FRAGMENT_METADATA_KEY_X,
    FRAGMENT_METADATA_KEY_Y,
    FRAGMENT_METADATA_KEY_WIDTH,
    FRAGMENT_METADATA_KEY_HEIGHT,
};

const static std::set<std::string> GIF_METADATA_KEYS = {
    GIF_METADATA_KEY_DELAY_TIME,
    GIF_METADATA_KEY_DISPOSAL_TYPE,
};

const static std::set<std::string> HEIFS_METADATA_KEYS = {
    HEIFS_METADATA_KEY_DELAY_TIME,
};

const static std::map<MetadataType, std::set<std::string>> KV_METADATA_KEYS = {
    {MetadataType::FRAGMENT, FRAGMENT_METADATA_KEYS},
    {MetadataType::GIF, GIF_METADATA_KEYS},
    {MetadataType::HEIFS, HEIFS_METADATA_KEYS},
};

ImageKvMetadata::ImageKvMetadata() {}

ImageKvMetadata::ImageKvMetadata(MetadataType metadataType)
{
    metadataType_ = metadataType;
}

ImageKvMetadata::ImageKvMetadata(const ImageKvMetadata &kvMetadata)
{
    CHECK_ERROR_RETURN(kvMetadata.properties_ == nullptr);
    metadataType_ = kvMetadata.metadataType_;
    ImageMetadata::PropertyMap properties(*kvMetadata.properties_);
    properties_ = std::make_shared<ImageMetadata::PropertyMap>(properties);
}

ImageKvMetadata& ImageKvMetadata::operator=(const ImageKvMetadata &kvMetadata)
{
    CHECK_ERROR_RETURN_RET(kvMetadata.properties_ == nullptr, *this);
    metadataType_ = kvMetadata.metadataType_;
    ImageMetadata::PropertyMap properties(*kvMetadata.properties_);
    properties_ = std::make_shared<ImageMetadata::PropertyMap>(properties);
    return *this;
}

ImageKvMetadata::~ImageKvMetadata() {}

bool ImageKvMetadata::IsKvMetadata(MetadataType metadataType)
{
    return KV_METADATA_KEYS.find(metadataType) != KV_METADATA_KEYS.end();
}

static bool IsValidKey(MetadataType metadataType, const std::string &key)
{
    if (!ImageKvMetadata::IsKvMetadata(metadataType)) {
        IMAGE_LOGE("Invalid kv metadata type: %{public}d", static_cast<int32_t>(metadataType));
        return false;
    }
    std::set<std::string> keys = KV_METADATA_KEYS.at(metadataType);
    return keys.find(key) != keys.end();
}

int ImageKvMetadata::GetValue(const std::string &key, std::string &value) const
{
    CHECK_ERROR_RETURN_RET_LOG(properties_ == nullptr, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s properties is nullptr.", __func__);
    if (!IsValidKey(metadataType_, key)) {
        IMAGE_LOGE("Key is not supported.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    auto it = properties_->find(key);
    if (it == properties_->end()) {
        IMAGE_LOGE("key is not found in properties: %{public}s", key.c_str());
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    std::unique_lock<std::mutex> guard(mutex_);
    value = it->second;
    return SUCCESS;
}

bool ImageKvMetadata::SetValue(const std::string &key, const std::string &value)
{
    CHECK_ERROR_RETURN_RET_LOG(properties_ == nullptr, false, "SetValue: properties_ is nullptr");
    if (!IsValidKey(metadataType_, key) || value.empty()) {
        IMAGE_LOGE("Key is not supported.");
        return false;
    }

    if (properties_->size() >= MAX_KV_META_COUNT) {
        IMAGE_LOGE("Failed to set value, the size of metadata properties exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_KV_META_COUNT));
        return false;
    }
    if (key.length() > MAX_KV_META_STRING_LENGTH || value.length() > MAX_KV_META_STRING_LENGTH) {
        IMAGE_LOGE("Failed to set value, the length of string exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_KV_META_STRING_LENGTH));
        return false;
    }
    std::unique_lock<std::mutex> guard(mutex_);
    properties_->insert_or_assign(key, value);
    return true;
}

bool ImageKvMetadata::RemoveEntry(const std::string &key)
{
    CHECK_ERROR_RETURN_RET_LOG(properties_ == nullptr, false, "%{public}s properties is nullptr.", __func__);
    if (!IsValidKey(metadataType_, key)) {
        IMAGE_LOGE("Key is not supported.");
        return false;
    }
    auto it = properties_->find(key);
    if (it == properties_->end()) {
        IMAGE_LOGE("RemoveEntry failed, key is not found in properties: %{public}s", key.c_str());
        return false;
    }
    std::unique_lock<std::mutex> guard(mutex_);
    properties_->erase(it);
    IMAGE_LOGD("RemoveEntry for key: %{public}s", key.c_str());
    return true;
}

const ImageMetadata::PropertyMapPtr ImageKvMetadata::GetAllProperties()
{
    return properties_;
}

std::shared_ptr<ImageMetadata> ImageKvMetadata::CloneMetadata()
{
    CHECK_ERROR_RETURN_RET_LOG(properties_ == nullptr, nullptr, "%{public}s properties is nullptr.", __func__);
    if (properties_->size() > MAX_KV_META_COUNT) {
        IMAGE_LOGE("Failed to clone, the size of metadata properties exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_KV_META_COUNT));
        return nullptr;
    }
    return std::make_shared<ImageKvMetadata>(*this);
}

bool ImageKvMetadata::Marshalling(Parcel &parcel) const
{
    CHECK_ERROR_RETURN_RET_LOG(properties_ == nullptr, false, "%{public}s properties is nullptr.", __func__);
    if (!parcel.WriteInt32(static_cast<int32_t>(metadataType_))) {
        IMAGE_LOGE("Failed to marshal metadata: %{public}d.", static_cast<int32_t>(metadataType_));
        return false;
    }
    if (properties_->size() > MAX_KV_META_COUNT) {
        IMAGE_LOGE("The number of metadata properties exceeds the maximum limit.");
        return false;
    }
    if (!parcel.WriteUint64(properties_->size())) {
        return false;
    }
    for (const auto &[key, value] : *properties_) {
        if (!IsValidKey(metadataType_, key)) {
            IMAGE_LOGE("The key of kv metadata is invalid.");
            return false;
        }
        if (key.length() > MAX_KV_META_STRING_LENGTH || value.length() > MAX_KV_META_STRING_LENGTH) {
            IMAGE_LOGE("The length of kv string exceeds the maximum limit.");
            return false;
        }
        if (!parcel.WriteString(key) || !parcel.WriteString(value)) {
            return false;
        }
    }
    return true;
}

ImageKvMetadata *ImageKvMetadata::Unmarshalling(Parcel &parcel)
{
    PICTURE_ERR error;
    ImageKvMetadata* dstKvMetadata = ImageKvMetadata::Unmarshalling(parcel, error);
    if (dstKvMetadata == nullptr || error.errorCode != SUCCESS) {
        IMAGE_LOGE("unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
            error.errorCode, error.errorInfo.c_str());
    }
    return dstKvMetadata;
}

ImageKvMetadata *ImageKvMetadata::Unmarshalling(Parcel &parcel, PICTURE_ERR &error)
{
    MetadataType type = static_cast<MetadataType>(parcel.ReadInt32());
    if (!ImageKvMetadata::IsKvMetadata(type)) {
        return nullptr;
    }
    std::unique_ptr<ImageKvMetadata> kvMetadataPtr = std::make_unique<ImageKvMetadata>(type);
    CHECK_ERROR_RETURN_RET_LOG(kvMetadataPtr == nullptr, nullptr, "%{public}s make_unique failed", __func__);
    CHECK_ERROR_RETURN_RET_LOG(kvMetadataPtr->properties_ == nullptr, nullptr,
        "%{public}s kvMetadataPtr->properties_ is nullptr", __func__);
    
    uint64_t size = 0;
    if (!parcel.ReadUint64(size) || size > MAX_KV_META_COUNT) {
        return nullptr;
    }
    for (uint64_t i = 0; i < size; ++i) {
        std::string key;
        std::string value;
        if (!parcel.ReadString(key) || !parcel.ReadString(value)) {
            IMAGE_LOGE("%{public}s ReadString failed.", __func__);
            return nullptr;
        }
        if (!IsValidKey(type, key)) {
            IMAGE_LOGE("The key of kv metadata is invalid.");
            return nullptr;
        }
        if (key.length() > MAX_KV_META_STRING_LENGTH || value.length() > MAX_KV_META_STRING_LENGTH) {
            IMAGE_LOGE("The length of kv string exceeds the maximum limit.");
            return nullptr;
        }
        kvMetadataPtr->properties_->insert(std::make_pair(key, value));
    }
    return kvMetadataPtr.release();
}

bool ImageKvMetadata::IsFragmentMetadataKey(const std::string& key)
{
    return FRAGMENT_METADATA_KEYS.find(key) != FRAGMENT_METADATA_KEYS.end();
}

bool ImageKvMetadata::IsGifMetadataKey(const std::string& key)
{
    return GIF_METADATA_KEYS.find(key) != GIF_METADATA_KEYS.end();
}
std::set<std::string> ImageKvMetadata::GetFragmentMetadataKeys()
{
    return FRAGMENT_METADATA_KEYS;
}

std::set<std::string> ImageKvMetadata::GetGifMetadataKeys()
{
    return GIF_METADATA_KEYS;
}

uint32_t ImageKvMetadata::GetBlobSize()
{
    CHECK_ERROR_RETURN_RET_LOG(!properties_, 0, "GetBlobSize properties is nullptr.");
    Parcel parcel;
    CHECK_ERROR_RETURN_RET(!Marshalling(parcel), 0);
    return parcel.GetDataSize();
}

uint32_t ImageKvMetadata::GetBlob(uint32_t bufferSize, uint8_t *dst)
{
    CHECK_ERROR_RETURN_RET_LOG(!dst, ERR_IMAGE_INVALID_PARAMETER, "GetBlob dst is nullptr.");
    Parcel parcel;
    CHECK_ERROR_RETURN_RET(!Marshalling(parcel), ERR_IMAGE_INVALID_PARAMETER);
    uint32_t blobSize = parcel.GetDataSize();
    CHECK_ERROR_RETURN_RET_LOG(bufferSize < blobSize, ERR_IMAGE_INVALID_PARAMETER,
        "GetBlob bufferSize is too small, need %{public}d, cur %{public}d", blobSize, bufferSize);
    uint8_t *blobPtr = reinterpret_cast<uint8_t*>(parcel.GetData());
    CHECK_ERROR_RETURN_RET(!blobPtr, ERR_IMAGE_INVALID_PARAMETER);
    CHECK_ERROR_RETURN_RET_LOG(memcpy_s(dst, bufferSize, blobPtr, blobSize) != 0, ERR_MEDIA_MALLOC_FAILED,
        "GetBlob copy to dst failed.");
    return SUCCESS;
}

uint32_t ImageKvMetadata::SetBlob(const uint8_t *source, const uint32_t bufferSize)
{
    CHECK_ERROR_RETURN_RET_LOG(!source || bufferSize == 0, ERR_IMAGE_INVALID_PARAMETER,
        "SetBlob source is nullptr or bufferSize is zero.");
    Parcel parcel;
    CHECK_ERROR_RETURN_RET_LOG(!parcel.WriteBuffer(source, bufferSize), ERR_IMAGE_INVALID_PARAMETER,
        "SetBlob parcel write buffer failed.");
    std::unique_ptr<ImageKvMetadata> kvMetadata(Unmarshalling(parcel));
    CHECK_ERROR_RETURN_RET(!kvMetadata, ERR_IMAGE_GET_DATA_ABNORMAL);
    CHECK_ERROR_RETURN_RET_LOG(metadataType_ != kvMetadata->metadataType_, ERR_IMAGE_INVALID_PARAMETER,
        "SetBlob metadataType is different.");
    properties_ = kvMetadata->properties_;
    return SUCCESS;
}
} // namespace Media
} // namespace OHOS