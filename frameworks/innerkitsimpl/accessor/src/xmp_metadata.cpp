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
}

namespace OHOS {
namespace Media {
int32_t XMPMetadata::refCount_{0};
std::mutex XMPMetadata::initMutex_;

XMPMetadata::XMPMetadata()
{
    std::lock_guard<std::mutex> lock(initMutex_);
    if (refCount_ == 0) {
        XMP_TRY();
        bool initOk = SXMPMeta::Initialize();
        CHECK_ERROR_RETURN_LOG(!initOk, "%{public}s failed to initialize XMPMeta", __func__);
        XMP_CATCH_NO_RETURN();
    }

    impl_ = std::make_unique<XMPMetadataImpl>();
    CHECK_ERROR_RETURN_LOG(!impl_, "%{public}s failed to create XMPMetadataImpl", __func__);
    ++refCount_;
}

XMPMetadata::XMPMetadata(std::unique_ptr<XMPMetadataImpl> impl)
{
    std::lock_guard<std::mutex> lock(initMutex_);
    CHECK_ERROR_RETURN_LOG(impl == nullptr, "%{public}s impl is nullptr", __func__);

    if (refCount_ == 0) {
        XMP_TRY();
        bool initOk = SXMPMeta::Initialize();
        CHECK_ERROR_RETURN_LOG(!initOk, "%{public}s failed to initialize XMPMeta", __func__);
        XMP_CATCH_NO_RETURN();
    }

    impl_ = std::move(impl);
    CHECK_ERROR_RETURN_LOG(!impl_, "%{public}s failed to move XMPMetadataImpl", __func__);
    ++refCount_;
}

XMPMetadata::~XMPMetadata()
{
    std::lock_guard<std::mutex> lock(initMutex_);
    CHECK_ERROR_RETURN_LOG(impl_ == nullptr, "%{public}s impl is nullptr! Maybe initialization failed.", __func__);

    if (--refCount_ == 0) {
        XMP_TRY();
        SXMPMeta::Terminate();
        XMP_CATCH_NO_RETURN();
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

static constexpr bool IsContainerTagType(XMPTagType tagType)
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

uint32_t XMPMetadata::RegisterNamespacePrefix(const std::string &uri, const std::string &prefix)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(uri.empty() || prefix.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s uri or prefix is empty", __func__);
    std::string placeholder;
    bool isURIRegistered = SXMPMeta::GetNamespacePrefix(uri.c_str(), &placeholder);
    if (isURIRegistered) {
        IMAGE_LOGI("%{public}s namespace already registered", __func__);
        return SUCCESS;
    }

    bool isPrefixRegistered = SXMPMeta::GetNamespaceURI(prefix.c_str(), &placeholder);
    if (isPrefixRegistered) {
        IMAGE_LOGI("%{public}s prefix already registered", __func__);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::RegisterNamespace(uri.c_str(), prefix.c_str(), &placeholder),
        ERR_XMP_SDK_EXCEPTION, "%{public}s failed to register namespace", __func__);
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadata::SetValue(const std::string &path, const XMPTagType &tagType, const std::string &value)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s impl is invalid for path: %{public}s", __func__, path.c_str());
    CHECK_ERROR_RETURN_RET_LOG(path.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s path is empty", __func__);

    const auto &[prefix, propName] = XMPHelper::SplitOnce(path, COLON);
    CHECK_ERROR_RETURN_RET_LOG(prefix.empty() || propName.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s invalid path: %{public}s", __func__, path.c_str());
    std::string namespaceUri;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &namespaceUri),
        ERR_XMP_NAMESPACE_NOT_REGISTERED,
        "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());

    XMP_OptionBits options = ConvertTagTypeToOptions(tagType);
    if (IsContainerTagType(tagType)) {
        CHECK_ERROR_RETURN_RET_LOG(!value.empty(), ERR_IMAGE_INVALID_PARAMETER, "%{public}s: container tag's value "
            "should be empty for path: %{public}s", __func__, path.c_str());
        impl_->SetProperty(namespaceUri.c_str(), propName.c_str(), nullptr, options);
    } else {
        impl_->SetProperty(namespaceUri.c_str(), propName.c_str(), value.c_str(), options);
    }
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadata::GetTag(const std::string &path, XMPTag &tag)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s impl is invalid for path: %{public}s", __func__, path.c_str());
    CHECK_ERROR_RETURN_RET_LOG(path.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s path is empty", __func__);

    const auto &[prefix, propName] = XMPHelper::SplitOnce(path, COLON);
    CHECK_ERROR_RETURN_RET_LOG(prefix.empty() || propName.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s invalid path: %{public}s", __func__, path.c_str());
    std::string namespaceUri;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &namespaceUri),
        ERR_XMP_NAMESPACE_NOT_REGISTERED,
        "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());

    XMP_OptionBits options = kXMP_NoOptions;
    std::string value;
    bool ret = impl_->GetProperty(namespaceUri.c_str(), propName.c_str(), &value, &options);
    CHECK_ERROR_RETURN_RET_LOG(!ret, ERR_XMP_TAG_NOT_FOUND,
        "%{public}s tag not found for path: %{public}s", __func__, path.c_str());

    CHECK_ERROR_RETURN_RET_LOG(!BuildXMPTag(path, options, value, tag), ERR_XMP_DECODE_FAILED,
        "%{public}s failed to build tag for path: %{public}s", __func__, path.c_str());
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadata::RemoveTag(const std::string &path)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s impl is invalid for path: %{public}s", __func__, path.c_str());
    CHECK_ERROR_RETURN_RET_LOG(path.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s path is empty", __func__);

    const auto &[prefix, propName] = XMPHelper::SplitOnce(path, COLON);
    CHECK_ERROR_RETURN_RET_LOG(prefix.empty() || propName.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s invalid path: %{public}s", __func__, path.c_str());
    std::string namespaceUri;
    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &namespaceUri),
        ERR_XMP_NAMESPACE_NOT_REGISTERED,
        "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());
    impl_->DeleteProperty(namespaceUri.c_str(), propName.c_str());
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadata::EnumerateTags(EnumerateCallback callback, const std::string &rootPath, XMPEnumerateOption options)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s impl is invalid for path: %{public}s", __func__, rootPath.c_str());
    CHECK_ERROR_RETURN_RET_LOG(!callback, ERR_IMAGE_INVALID_PARAMETER, "%{public}s callback is null", __func__);

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
        CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &schemaNS),
            ERR_XMP_NAMESPACE_NOT_REGISTERED,
            "%{public}s failed to get namespace URI for prefix: %{public}s", __func__, prefix.c_str());
    }

    XMP_OptionBits iterOptions = kXMP_IterJustChildren;
    if (options.isRecursive) {
        iterOptions = kXMP_NoOptions;
    }
    SXMPIterator iter(*(impl_->GetRawPtr()), schemaNS.c_str(), rootPropName.c_str(), iterOptions);
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
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadata::GetBlob(std::string &buffer)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s impl is invalid", __func__);

    buffer.clear();
    impl_->SerializeToBuffer(buffer, kXMP_OmitPacketWrapper);
    CHECK_ERROR_RETURN_RET_LOG(buffer.empty(), ERR_XMP_DECODE_FAILED,
        "%{public}s failed to serialize to buffer", __func__);
    IMAGE_LOGD("%{public}s success! actual blob size is %{public}zu", __func__, buffer.size());
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadata::SetBlob(const uint8_t *source, uint32_t bufferSize)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s impl is invalid", __func__);
    CHECK_ERROR_RETURN_RET_LOG(source == nullptr || bufferSize == 0, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s source is nullptr or size:(%{public}u) is invalid", __func__, bufferSize);

    impl_->ParseFromBuffer(reinterpret_cast<const char*>(source), bufferSize);
    IMAGE_LOGD("%{public}s success! bufferSize is %{public}u", __func__, bufferSize);
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}
} // namespace Media
} // namespace OHOS