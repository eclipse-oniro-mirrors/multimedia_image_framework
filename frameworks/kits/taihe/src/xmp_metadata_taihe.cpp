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

#include "image_log.h"
#include "image_taihe_utils.h"
#include "image_type.h"
#include "media_errors.h"
#include "securec.h"
#include "xmp_metadata_taihe.h"

using namespace ANI::Image;

namespace ANI::Image {
XMPMetadataImpl::XMPMetadataImpl(std::shared_ptr<OHOS::Media::XMPMetadata> xmpMetadata)
    : nativeXMPMetadata_(xmpMetadata) {}

static XMPTag ToTaiheXMPTag(const OHOS::Media::XMPTag &innerXMPTag)
{
    optional<string> prefix(std::nullopt);
    if (!innerXMPTag.prefix.empty()) {
        prefix.emplace(innerXMPTag.prefix);
    }

    optional<string> value(std::nullopt);
    if (!innerXMPTag.value.empty()) {
        value.emplace(innerXMPTag.value);
    }

    XMPTag tag {
        .xmlns = innerXMPTag.xmlns,
        .prefix = prefix,
        .name = innerXMPTag.name,
        .type = XMPTagType::from_value(static_cast<int32_t>(innerXMPTag.type)),
        .value = value,
    };
    return tag;
}

static OHOS::Media::XMPEnumerateOption ParseXMPEnumerateOption(const optional_view<XMPEnumerateOption> &option)
{
    OHOS::Media::XMPEnumerateOption innerOption;
    if (option->isRecursive.has_value()) {
        innerOption.isRecursive = option->isRecursive.value();
    }
    return innerOption;
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

bool XMPMetadataImpl::RegisterNamespacePrefixSync(string_view xmlns, string_view prefix)
{
    CHECK_ERROR_RETURN_RET_LOG(nativeXMPMetadata_ == nullptr, false, "Empty native XMPMetadata");

    bool ret = nativeXMPMetadata_->RegisterNamespacePrefix(std::string(xmlns), std::string(prefix));
    // through errCode and errMsg
    return ret;
}

bool XMPMetadataImpl::SetValueSync(string_view path, XMPTagType type, optional_view<string> value)
{
    CHECK_ERROR_RETURN_RET_LOG(nativeXMPMetadata_ == nullptr, false, "Empty native XMPMetadata");

    std::string innerPath = std::string(path);
    OHOS::Media::XMPTagType innerXMPTagType = OHOS::Media::XMPTagType(type.get_value());
    std::string innerValue = std::string(value.value_or(""));
    IMAGE_LOGD("%{public}s path: %{public}s, tagType: %{public}d, tagValue: %{public}s",
        __func__, innerPath.c_str(), innerXMPTagType, innerValue.c_str());

    bool ret = nativeXMPMetadata_->SetValue(innerPath, innerXMPTagType, innerValue);
    // through errCode and errMsg
    return ret;
}

NullableXMPTag XMPMetadataImpl::GetTagSync(string_view path)
{
    CHECK_ERROR_RETURN_RET_LOG(nativeXMPMetadata_ == nullptr, NullableXMPTag::make_type_null(),
        "Empty native XMPMetadata instance");

    OHOS::Media::XMPTag innerXMPTag;
    bool ret = nativeXMPMetadata_->GetTag(std::string(path), innerXMPTag);
    // through errCode and errMsg
    CHECK_ERROR_RETURN_RET(!ret, NullableXMPTag::make_type_null());

    XMPTag tag = ToTaiheXMPTag(innerXMPTag);
    return NullableXMPTag::make_type_xmpTag(tag);
}

bool XMPMetadataImpl::RemoveTagSync(string_view path)
{
    CHECK_ERROR_RETURN_RET_LOG(nativeXMPMetadata_ == nullptr, false, "Empty native XMPMetadata");

    bool ret = nativeXMPMetadata_->RemoveTag(std::string(path));
    // through errCode and errMsg
    return ret;
}

void XMPMetadataImpl::EnumerateTags(callback_view<bool(string_view path, XMPTag const& tag)> callback,
    optional_view<string> rootPath, optional_view<XMPEnumerateOption> options)
{
    CHECK_ERROR_RETURN_LOG(nativeXMPMetadata_ == nullptr, "Empty native XMPMetadata");

    std::string innerPath = std::string(rootPath.value_or(""));
    OHOS::Media::XMPEnumerateOption innerOption = ParseXMPEnumerateOption(options);
    auto innerCallback = CreateEnumerateTagsCallback(callback);

    nativeXMPMetadata_->EnumerateTags(innerCallback, innerPath, innerOption);
}

map<string, XMPTag> XMPMetadataImpl::GetTagsSync(optional_view<string> rootPath,
    optional_view<XMPEnumerateOption> options)
{
    map<string, XMPTag> result;
    CHECK_ERROR_RETURN_RET_LOG(nativeXMPMetadata_ == nullptr, result, "Empty native XMPMetadata");
    std::string innerPath = std::string(rootPath.value_or(""));
    OHOS::Media::XMPEnumerateOption innerOption = ParseXMPEnumerateOption(options);

    nativeXMPMetadata_->EnumerateTags([&result](const std::string &path, const OHOS::Media::XMPTag &tag) {
        result.emplace(path, ToTaiheXMPTag(tag));
        return true;
    }, innerPath, innerOption);
    // through errCode and errMsg
    return result;
}

void XMPMetadataImpl::SetBlobSync(array_view<uint8_t> buffer)
{
    CHECK_ERROR_RETURN_LOG(nativeXMPMetadata_ == nullptr, "Empty native XMPMetadata");
    nativeXMPMetadata_->SetBlob(static_cast<uint8_t*>(buffer.data()), buffer.size());
    // through errCode and errMsg
}

array<uint8_t> XMPMetadataImpl::GetBlobSync()
{
    array<uint8_t> result = ImageTaiheUtils::CreateTaiheArrayBuffer(nullptr, 0);
    CHECK_ERROR_RETURN_RET_LOG(nativeXMPMetadata_ == nullptr, result, "Empty native XMPMetadata");

    std::string strBuf;
    nativeXMPMetadata_->GetBlob(strBuf);
    // through errCode and errMsg

    std::unique_ptr<uint8_t[]> buf = std::make_unique<uint8_t[]>(strBuf.size());
    if (memcpy_s(buf.get(), strBuf.size(), strBuf.data(), strBuf.size()) != EOK) {
        IMAGE_LOGE("%{public}s memcpy_s failed", __func__);
        return result;
    }

    result = ImageTaiheUtils::CreateTaiheArrayBuffer(buf.get(), strBuf.size());
    return result;
}
} // namespace ANI::Image