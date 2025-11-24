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

#include "image_log.h"
#include "media_errors.h"
#include "xmp_helper.h"
#include "xmp_metadata.h"

namespace {
static const char *COLON = ":";
}

namespace OHOS {
namespace Media {
bool XMPMetadata::xmpInitialized_ = false;

XMPMetadata::XMPMetadata()
{
    if (!Initialize()) {
        IMAGE_LOGE("%{public}s failed to initialize XMP Metadata", __func__);
        return;
    }

    xmpMeta_ = std::make_shared<SXMPMeta>();
}

XMPMetadata::XMPMetadata(std::shared_ptr<SXMPMeta> &xmpMeta)
{
    if (!Initialize()) {
        IMAGE_LOGE("%{public}s failed to initialize XMP Metadata", __func__);
        return;
    }

    xmpMeta_ = xmpMeta;
}

XMPMetadata::~XMPMetadata() {}

bool XMPMetadata::Initialize()
{
    if (xmpInitialized_) {
        return true;
    }
    CHECK_ERROR_RETURN_RET_LOG(!SXMPFiles::Initialize(kXMPFiles_IgnoreLocalText), false,
        "%{public}s failed to initialize XMPFiles", __func__);
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::Initialize(), false, "%{public}s failed to initialize XMPMeta", __func__);
    xmpInitialized_ = true;
    return true;
}

void XMPMetadata::Terminate()
{
    if (xmpInitialized_) {
        SXMPMeta::Terminate();
        SXMPFiles::Terminate();
        xmpInitialized_ = false;
    }
}

static constexpr XMPTagType ConvertOptionsToTagType(XMP_OptionBits options)
{
    if (options & kXMP_PropValueIsStruct) {
        return XMPTagType::STRUCTURE;
    }
    
    if (options & kXMP_PropValueIsArray) {
        if (options & kXMP_PropArrayIsAlternate) {
            if (options & kXMP_PropArrayIsAltText) {
                return XMPTagType::ALTERNATE_TEXT;
            }
            return XMPTagType::ALTERNATE_ARRAY;
        } else if (options & kXMP_PropArrayIsOrdered) {
            return XMPTagType::ORDERED_ARRAY;
        } else {
            return XMPTagType::UNORDERED_ARRAY;
        }
    }
    
    if (options & kXMP_PropIsQualifier) {
        return XMPTagType::QUALITY;
    }
    
    return XMPTagType::SIMPLE;
}

static constexpr XMP_OptionBits ConvertTagTypeToOptions(XMPTagType tagType)
{
    switch (tagType) {
        case XMPTagType::SIMPLE:
            return kXMP_NoOptions;
        case XMPTagType::UNORDERED_ARRAY:
            return kXMP_PropValueIsArray;
        case XMPTagType::ORDERED_ARRAY:
            return kXMP_PropValueIsArray | kXMP_PropArrayIsOrdered;
        case XMPTagType::ALTERNATE_ARRAY:
            return kXMP_PropValueIsArray | kXMP_PropArrayIsAlternate;
        case XMPTagType::ALTERNATE_TEXT:
            return kXMP_PropValueIsArray | kXMP_PropArrayIsAlternate | kXMP_PropArrayIsAltText;
        case XMPTagType::STRUCTURE:
            return kXMP_PropValueIsStruct;
        case XMPTagType::QUALITY:
            return kXMP_PropIsQualifier;
        default:
            return kXMP_NoOptions;
    }
}

static XMPTag BuildXMPTag(const std::string &uri, const std::string &prefix, const std::string &propName,
    const XMP_OptionBits &options, const std::string &value)
{
    return XMPTag {
        .xmlns = uri,
        .prefix = XMPHelper::Trim(prefix, COLON),
        .name = XMPHelper::ExtractPropertyKey(propName),
        .type = ConvertOptionsToTagType(options),
        .value = value,
    };
}

bool XMPMetadata::RegisterNamespacePrefix(const std::string &uri, const std::string &prefix)
{
    std::string placeholder;
    bool isURIRegistered = SXMPMeta::GetNamespacePrefix(uri.c_str(), &placeholder);
    if (isURIRegistered) {
        IMAGE_LOGI("%{public}s namespace already registered", __func__);
        return false;
    }

    bool isPrefixRegistered = SXMPMeta::GetNamespaceURI(prefix.c_str(), &placeholder);
    if (isPrefixRegistered) {
        IMAGE_LOGI("%{public}s prefix already registered", __func__);
        return false;
    }
    return SXMPMeta::RegisterNamespace(uri.c_str(), prefix.c_str(), &placeholder);
}

bool XMPMetadata::SetTag(const std::string &path, const XMPTag &tag)
{
    CHECK_ERROR_RETURN_RET_LOG(!xmpMeta_, false, "%{public}s xmpMeta is null for path: %{public}s",
        __func__, path.c_str());

    const auto &[prefix, propName] = XMPHelper::SplitPrefixPath(path);

    std::string namespaceUri;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &namespaceUri), false,
        "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());

    XMP_OptionBits options = ConvertTagTypeToOptions(tag.type);
    // TODO: 针对容器节点，需要设置为 nullptr
    if (tag.type != XMPTagType::SIMPLE) {
        xmpMeta_->SetProperty(namespaceUri.c_str(), propName.c_str(), nullptr, options);
    } else {
        xmpMeta_->SetProperty(namespaceUri.c_str(), propName.c_str(), tag.value.c_str(), options);
    }
    return true;
}

bool XMPMetadata::GetTag(const std::string &path, XMPTag &tag)
{
    CHECK_ERROR_RETURN_RET_LOG(!xmpMeta_, false, "%{public}s xmpMeta is null for path: %{public}s",
        __func__, path.c_str());
    
    const auto &[prefix, propName] = XMPHelper::SplitPrefixPath(path);
    std::string namespaceUri;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &namespaceUri), false,
        "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());

    XMP_OptionBits options = kXMP_NoOptions;
    std::string value;
    bool ret = xmpMeta_->GetProperty(namespaceUri.c_str(), propName.c_str(), &value, &options);
    CHECK_ERROR_RETURN_RET_LOG(!ret, false, "%{public}s failed to get property for path: %{public}s",
        __func__, path.c_str());

    tag = BuildXMPTag(namespaceUri, prefix, propName, options, value);
    return true;
}

bool XMPMetadata::RemoveTag(const std::string &path)
{
    CHECK_ERROR_RETURN_RET_LOG(!xmpMeta_, false, "%{public}s xmpMeta is null for path: %{public}s",
        __func__, path.c_str());

    const auto &[prefix, propName] = XMPHelper::SplitPrefixPath(path);
    std::string namespaceUri;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &namespaceUri), false,
        "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());
    xmpMeta_->DeleteProperty(namespaceUri.c_str(), propName.c_str());
    return true;
}

} // namespace Media
} // namespace OHOS