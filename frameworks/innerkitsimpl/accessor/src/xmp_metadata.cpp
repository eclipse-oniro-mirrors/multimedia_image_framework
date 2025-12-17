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
#include "securec.h"
#include "xmp_helper.h"
#include "xmp_metadata.h"
#include "xmp_metadata_impl.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "XMPMetadata"

namespace {
constexpr std::string_view COLON = ":";
constexpr uint32_t MAX_XMP_METADATA_LENGTH = 64 * 1024;
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
    impl_ = std::make_unique<XMPMetadataImpl>();
}

XMPMetadata::XMPMetadata(std::unique_ptr<XMPMetadataImpl> impl)
    : impl_(std::move(impl))
{
    if (!Initialize()) {
        IMAGE_LOGE("%{public}s failed to initialize XMP Metadata", __func__);
        impl_.reset();
        return;
    }
}

XMPMetadata::~XMPMetadata() = default;

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

std::unique_ptr<XMPMetadataImpl>& XMPMetadata::GetImpl()
{
    return impl_;
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
        return XMPTagType::QUALIFIER;
    }

    return XMPTagType::SIMPLE;
}

static constexpr XMP_OptionBits ConvertTagTypeToOptions(XMPTagType tagType)
{
    switch (tagType) {
        case XMPTagType::SIMPLE:
        case XMPTagType::QUALIFIER:
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
        default:
            return kXMP_NoOptions;
    }
}

static bool IsContainerTagType(XMPTagType tagType)
{
    return tagType == XMPTagType::STRUCTURE || tagType == XMPTagType::UNORDERED_ARRAY ||
        tagType == XMPTagType::ORDERED_ARRAY || tagType == XMPTagType::ALTERNATE_ARRAY ||
        tagType == XMPTagType::ALTERNATE_TEXT;
}

static bool BuildXMPTag(const std::string &pathExpression, const XMP_OptionBits &options, const std::string &value,
    XMPTag &outTag)
{
    const auto &[propertyNS, propertyKey] = XMPHelper::ExtractSplitProperty(pathExpression);
    CHECK_ERROR_RETURN_RET_LOG(propertyNS.empty() || propertyKey.empty(), false,
        "%{public}s failed to extract property NS or key for path: %{public}s", __func__, pathExpression.c_str());

    std::string xmlns;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(propertyNS.c_str(), &xmlns), false,
        "%{public}s failed to get namespace URI for path: %{public}s", __func__, pathExpression.c_str());

    outTag = XMPTag {
        .xmlns = xmlns,
        .prefix = propertyNS,
        .name = propertyKey,
        .type = ConvertOptionsToTagType(options),
        .value = value,
    };
    return true;
}

static bool ValidateTagWithPath(const std::string &path, const XMPTag &tag)
{
    CHECK_ERROR_RETURN_RET_LOG(tag.prefix.empty() || tag.xmlns.empty() || tag.name.empty(), false,
        "%{public}s tag is invalid, prefix: %{public}s, xmlns: %{public}s, name: %{public}s", __func__,
        tag.prefix.c_str(), tag.xmlns.c_str(), tag.name.c_str());

    const auto &[expectedNS, expectedKey] = XMPHelper::ExtractSplitProperty(path);
    CHECK_ERROR_RETURN_RET_LOG(expectedNS.empty() || expectedKey.empty(), false,
        "%{public}s path is invalid, expectedNS: %{public}s, expectedKey: %{public}s", __func__,
        expectedNS.c_str(), expectedKey.c_str());

    // TODO: 后续 prefix 可能是可选的
    if (tag.prefix != expectedNS) {
        IMAGE_LOGW("%{public}s tag prefix mismatch: expected %{public}s, got %{public}s",
            __func__, expectedNS.c_str(), tag.prefix.c_str());
        return false;
    }

    std::string expectedXmlns;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(expectedNS.c_str(), &expectedXmlns), false,
        "%{public}s failed to get namespace URI for path: %{public}s", __func__, path.c_str());
    CHECK_ERROR_RETURN_RET_LOG(tag.xmlns != expectedXmlns, false,
        "%{public}s tag xmlns mismatch: expected %{public}s, got %{public}s", __func__,
        expectedXmlns.c_str(), tag.xmlns.c_str());

    CHECK_ERROR_RETURN_RET_LOG(tag.name != expectedKey, false,
        "%{public}s tag name mismatch: expected %{public}s, got %{public}s", __func__,
        expectedKey.c_str(), tag.name.c_str());
    return true;
}

bool XMPMetadata::CreateXMPTag(const std::string &path, const XMPTagType &tagType, const std::string &value,
    XMPTag &outTag)
{
    if (BuildXMPTag(path, ConvertTagTypeToOptions(tagType), value, outTag)) {
        outTag.type = tagType;
        return true;
    }
    return false;
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
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), false,
        "%{public}s impl is null for path: %{public}s", __func__, path.c_str());

    CHECK_ERROR_RETURN_RET_LOG(!ValidateTagWithPath(path, tag), false,
        "%{public}s tag validation failed for path: %{public}s", __func__, path.c_str());

    const auto &[prefix, propName] = XMPHelper::SplitOnce(path, COLON);
    std::string namespaceUri;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &namespaceUri), false,
        "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());

    XMP_OptionBits options = ConvertTagTypeToOptions(tag.type);
    if (IsContainerTagType(tag.type)) {
        impl_->SetProperty(namespaceUri.c_str(), propName.c_str(), nullptr, options);
    } else {
        impl_->SetProperty(namespaceUri.c_str(), propName.c_str(), tag.value.c_str(), options);
    }
    return true;
}

bool XMPMetadata::GetTag(const std::string &path, XMPTag &tag)
{
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), false,
        "%{public}s impl is null for path: %{public}s", __func__, path.c_str());
    
    const auto &[prefix, propName] = XMPHelper::SplitOnce(path, COLON);
    std::string namespaceUri;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &namespaceUri), false,
        "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());

    XMP_OptionBits options = kXMP_NoOptions;
    std::string value;
    bool ret = impl_->GetProperty(namespaceUri.c_str(), propName.c_str(), &value, &options);
    CHECK_ERROR_RETURN_RET_LOG(!ret, false, "%{public}s failed to get property for path: %{public}s",
        __func__, path.c_str());

    return BuildXMPTag(path, options, value, tag);
}

bool XMPMetadata::RemoveTag(const std::string &path)
{
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), false,
        "%{public}s impl is null for path: %{public}s", __func__, path.c_str());

    const auto &[prefix, propName] = XMPHelper::SplitOnce(path, COLON);
    std::string namespaceUri;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &namespaceUri), false,
        "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());
    impl_->DeleteProperty(namespaceUri.c_str(), propName.c_str());
    return true;
}

void XMPMetadata::EnumerateTags(EnumerateCallback callback, const std::string &rootPath, XMPEnumerateOption options)
{
    CHECK_ERROR_RETURN_LOG(!impl_ || !impl_->IsValid(),
        "%{public}s impl is null for path: %{public}s", __func__, rootPath.c_str());
    CHECK_ERROR_RETURN_LOG(!callback, "%{public}s callback is null", __func__);

    std::string schemaNS;
    std::string rootPropName;
    if (!rootPath.empty()) {
        std::string_view rootPathView(rootPath);
        size_t colonPos = rootPathView.find(COLON);
        std::string prefix;
        if (colonPos == std::string_view::npos) {
            prefix = rootPath;
        } else {
            prefix = std::string(rootPathView.substr(0, colonPos));
            rootPropName = std::string(rootPathView.substr(colonPos + COLON.size()));
        }
        CHECK_ERROR_RETURN_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &schemaNS),
            "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());
    }

    XMP_OptionBits iterOptions = kXMP_IterJustChildren;
    if (options.isRecursive) {
        iterOptions = kXMP_NoOptions;
    }
    SXMPIterator iter(impl_->GetMeta(), schemaNS.c_str(), rootPropName.c_str(), iterOptions);
    std::string iterSchemaNS;
    std::string iterPropPath;
    std::string iterPropValue;
    // Iterate through all properties
    while (iter.Next(&iterSchemaNS, &iterPropPath, &iterPropValue, &iterOptions)) {
        if (iterPropPath.empty()) {
            IMAGE_LOGD("Skipping schema node: %{public}s", iterSchemaNS.c_str());
            continue;
        }

        XMPTag tag;
        if (!BuildXMPTag(iterPropPath, iterOptions, iterPropValue, tag)) {
            IMAGE_LOGW("Failed to build XMPTag for path: %{public}s", iterPropPath.c_str());
            continue;
        }

        // Call the callback
        bool shouldContinue = callback(iterPropPath, tag);
        if (!shouldContinue) {
            IMAGE_LOGD("%{public}s enumeration stopped by callback", __func__);
            break;
        }
    }
}

uint32_t XMPMetadata::GetBlob(std::string &buffer)
{
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s impl is invalid", __func__);

    impl_->SerializeToBuffer(buffer, kXMP_UseCompactFormat);
    IMAGE_LOGD("%{public}s success! string buffer size is %{public}u", __func__, buffer.size());
    return SUCCESS;
}

uint32_t XMPMetadata::GetBlob(uint32_t bufferSize, uint8_t *dst)
{
    CHECK_ERROR_RETURN_RET_LOG(dst == nullptr, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s dst is nullptr", __func__);

    std::string buffer;
    this->GetBlob(buffer);
    if (buffer.size() > bufferSize) {
        IMAGE_LOGE("%{public}s buffer size is too small", __func__);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    CHECK_ERROR_RETURN_RET_LOG(memcpy_s(dst, bufferSize, buffer.data(), buffer.size()) != EOK,
        ERR_MEDIA_MALLOC_FAILED, "%{public}s memcpy_s failed", __func__);
    IMAGE_LOGD("%{public}s success! actualSize is %{public}u, bufferSize is %{public}u", __func__,
        buffer.size(), bufferSize);
    return SUCCESS;
}

uint32_t XMPMetadata::SetBlob(const uint8_t *source, uint32_t bufferSize)
{
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s impl is invalid", __func__);
    CHECK_ERROR_RETURN_RET_LOG(source == nullptr || bufferSize == 0 || bufferSize > MAX_XMP_METADATA_LENGTH,
        ERR_IMAGE_INVALID_PARAMETER, "%{public}s source is nullptr or size:(%{public}u) is invalid",
        __func__, bufferSize);

    impl_->ParseFromBuffer(reinterpret_cast<const char*>(source), bufferSize);
    IMAGE_LOGD("%{public}s success! bufferSize is %{public}u", __func__, bufferSize);
    return SUCCESS;
}
} // namespace Media
} // namespace OHOS