/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "xmp_metadata_taihe.h"

#include "image_common.h"
#include "image_error_convert.h"
#include "image_log.h"
#include "image_taihe_utils.h"
#include "image_type.h"
#include "media_errors.h"
#include "securec.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "XMPMetadataTaihe"

using namespace ANI::Image;

namespace ANI::Image {
XMPMetadataImpl::XMPMetadataImpl()
    : nativeXMPMetadata_(std::make_shared<OHOS::Media::XMPMetadata>()) {}

XMPMetadataImpl::XMPMetadataImpl(std::shared_ptr<OHOS::Media::XMPMetadata> xmpMetadata)
    : nativeXMPMetadata_(xmpMetadata) {}

static XMPTag ToTaiheXMPTag(const OHOS::Media::XMPTag &innerXMPTag)
{
    XMPNamespace ns = {
        .uri = innerXMPTag.xmlns,
        .prefix = innerXMPTag.prefix,
    };

    optional<string> value(std::nullopt);
    if (!innerXMPTag.value.empty()) {
        value.emplace(innerXMPTag.value);
    }

    XMPTag tag {
        .xmpNamespace = ns,
        .name = innerXMPTag.name,
        .type = XMPTagType::from_value(static_cast<int32_t>(innerXMPTag.type)),
        .value = value,
    };
    return tag;
}

static OHOS::Media::XMPEnumerateOptions ParseXMPEnumerateOption(const optional_view<XMPEnumerateOptions> &option)
{
    OHOS::Media::XMPEnumerateOptions innerOption;
    if (!option.has_value()) {
        return innerOption;
    }
    if (option->isRecursive.has_value()) {
        innerOption.isRecursive = option->isRecursive.value();
        IMAGE_LOGD("%{public}s: isRecursive: %{public}d", __func__, innerOption.isRecursive);
    }
    if (option->onlyQualifier.has_value()) {
        innerOption.onlyQualifier = option->onlyQualifier.value();
        IMAGE_LOGD("%{public}s: onlyQualifier: %{public}d", __func__, innerOption.onlyQualifier);
    }
    return innerOption;
}

static void ThrowXMPException(uint32_t innerCode, const std::string &customErrMsg = "",
    OHOS::Media::ImageErrorConvertFunc makeErrMsg = OHOS::Media::ImageErrorConvert::XMPMetadataCommonMakeErrMsg)
{
    const auto [errorCode, errMsg] = makeErrMsg(innerCode);
    std::string combinedErrMsg = customErrMsg.empty() ? errMsg : (errMsg + " " + customErrMsg);
    ImageTaiheUtils::ThrowExceptionError(errorCode, combinedErrMsg);
}

static auto CreateEnumerateTagsCallback(callback_view<bool(string_view path, XMPTag const& tag)> callback)
{
    auto innerCallback = [callback](const std::string &path, const OHOS::Media::XMPTag &tag) -> bool {
        XMPTag taiheTag = ToTaiheXMPTag(tag);
        bool shouldContinue = callback(path, taiheTag);
        return shouldContinue;
    };
    return innerCallback;
}

int64_t XMPMetadataImpl::GetImplPtr()
{
    return static_cast<int64_t>(reinterpret_cast<uintptr_t>(this));
}

std::shared_ptr<OHOS::Media::XMPMetadata> XMPMetadataImpl::GetNativeXMPMetadata()
{
    return nativeXMPMetadata_;
}

void XMPMetadataImpl::RegisterXMPNamespace(XMPNamespace const& ns)
{
    if (nativeXMPMetadata_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_INVALID_PARAMETER, "empty native XMPMetadata");
        return;
    }

    std::string errMsg;
    uint32_t ret = nativeXMPMetadata_->RegisterNamespacePrefix(std::string(ns.uri), std::string(ns.prefix), errMsg);
    if (ret != OHOS::Media::SUCCESS) {
        ThrowXMPException(ret, errMsg);
        return;
    }
}

void XMPMetadataImpl::SetValue(string_view path, XMPTagType type, optional_view<string> value)
{
    if (nativeXMPMetadata_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_INVALID_PARAMETER, "empty native XMPMetadata");
        return;
    }

    std::string innerPath = std::string(path);
    if (!type.is_valid() ||
        !OHOS::Media::XMPMetadata::IsValidTagType(static_cast<OHOS::Media::XMPTagType>(type.get_value()))) {
        IMAGE_LOGE("Invalid tag type: %{public}d", type.get_value());
        ThrowXMPException(IMAGE_INVALID_PARAMETER);
        return;
    }
    OHOS::Media::XMPTagType innerXMPTagType = OHOS::Media::XMPTagType(type.get_value());
    std::string innerValue = std::string(value.value_or(""));
    IMAGE_LOGD("%{public}s path: %{public}s, tagType: %{public}d, tagValue: %{public}s",
        __func__, innerPath.c_str(), innerXMPTagType, innerValue.c_str());

    uint32_t ret = nativeXMPMetadata_->SetValue(innerPath, innerXMPTagType, innerValue);
    if (ret != OHOS::Media::SUCCESS) {
        ThrowXMPException(ret);
        return;
    }
}

NullableXMPTag XMPMetadataImpl::GetTag(string_view path)
{
    if (nativeXMPMetadata_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_INVALID_PARAMETER, "empty native XMPMetadata");
        return NullableXMPTag::make_type_null();
    }

    OHOS::Media::XMPTag innerXMPTag;
    uint32_t ret = nativeXMPMetadata_->GetTag(std::string(path), innerXMPTag);
    if (ret == OHOS::Media::ERR_XMP_TAG_NOT_FOUND) {
        return NullableXMPTag::make_type_null();
    }
    if (ret != OHOS::Media::SUCCESS) {
        ThrowXMPException(ret);
        return NullableXMPTag::make_type_null();
    }

    XMPTag tag = ToTaiheXMPTag(innerXMPTag);
    return NullableXMPTag::make_type_xmpTag(tag);
}

void XMPMetadataImpl::RemoveTag(string_view path)
{
    if (nativeXMPMetadata_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_INVALID_PARAMETER, "empty native XMPMetadata");
        return;
    }

    uint32_t ret = nativeXMPMetadata_->RemoveTag(std::string(path));
    if (ret != OHOS::Media::SUCCESS) {
        ThrowXMPException(ret);
        return;
    }
}

void XMPMetadataImpl::EnumerateTags(callback_view<bool(string_view path, XMPTag const& tag)> callback,
    optional_view<string> rootPath, optional_view<XMPEnumerateOptions> options)
{
    if (nativeXMPMetadata_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_INVALID_PARAMETER, "empty native XMPMetadata");
        return;
    }

    std::string innerPath = std::string(rootPath.value_or(""));
    OHOS::Media::XMPEnumerateOptions innerOption = ParseXMPEnumerateOption(options);
    auto innerCallback = CreateEnumerateTagsCallback(callback);

    uint32_t ret = nativeXMPMetadata_->EnumerateTags(innerCallback, innerPath, innerOption);
    if (ret != OHOS::Media::SUCCESS) {
        ThrowXMPException(ret);
        return;
    }
}

map<string, XMPTag> XMPMetadataImpl::GetTags(optional_view<string> rootPath,
    optional_view<XMPEnumerateOptions> options)
{
    map<string, XMPTag> result;
    if (nativeXMPMetadata_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_INVALID_PARAMETER, "empty native XMPMetadata");
        return result;
    }

    std::string innerPath = std::string(rootPath.value_or(""));
    OHOS::Media::XMPEnumerateOptions innerOption = ParseXMPEnumerateOption(options);

    uint32_t ret = nativeXMPMetadata_->EnumerateTags(
        [&result](const std::string &path, const OHOS::Media::XMPTag &tag) {
            result.emplace(path, ToTaiheXMPTag(tag));
            return true;
        }, innerPath, innerOption);
    if (ret != OHOS::Media::SUCCESS) {
        ThrowXMPException(ret);
        return map<string, XMPTag>();
    }
    return result;
}

void XMPMetadataImpl::SetBlob(array_view<uint8_t> buffer)
{
    if (nativeXMPMetadata_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_INVALID_PARAMETER, "empty native XMPMetadata");
        return;
    }

    uint32_t ret = nativeXMPMetadata_->SetBlob(static_cast<uint8_t*>(buffer.data()), buffer.size());
    if (ret != OHOS::Media::SUCCESS) {
        ThrowXMPException(ret);
        return;
    }
}

array<uint8_t> XMPMetadataImpl::GetBlob()
{
    array<uint8_t> result = ImageTaiheUtils::CreateTaiheArrayBuffer(nullptr, 0);
    if (nativeXMPMetadata_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(IMAGE_INVALID_PARAMETER, "empty native XMPMetadata");
        return result;
    }

    std::string strBuf;
    uint32_t ret = nativeXMPMetadata_->GetBlob(strBuf);
    if (ret != OHOS::Media::SUCCESS) {
        ThrowXMPException(ret, "", OHOS::Media::ImageErrorConvert::XMPMetadataGetBlobMakeErrMsg);
        return result;
    }
    return ImageTaiheUtils::CreateTaiheArrayBuffer(reinterpret_cast<uint8_t*>(strBuf.data()), strBuf.size());
}

// Global Functions
XMPMetadata XMPMetadataCtor()
{
    return taihe::make_holder<XMPMetadataImpl, XMPMetadata>();
}
} // namespace ANI::Image

TH_EXPORT_CPP_API_XMPMetadataCtor(XMPMetadataCtor);