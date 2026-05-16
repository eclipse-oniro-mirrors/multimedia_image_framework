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

#include "xmp_metadata.h"

#include "image_log.h"
#include "media_errors.h"
#include "securec.h"
#include "xmp_helper.h"
#include "xmp_metadata_impl.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "XMPMetadata"

namespace {
constexpr std::string_view COLON = ":";

struct IteratorParams {
    SXMPMeta *meta = nullptr;
    const char *schemaNS = nullptr;
    const char *propName = nullptr;
    const char *rootPath = nullptr;
    XMP_OptionBits options = kXMP_NoOptions;
    bool onlyQualifier = false;
};
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

// Helper to validate path and resolve namespace URI
static uint32_t ValidateAndResolvePath(const std::string &path, std::string &outUri, std::string &outPropName,
    bool isRootPath = false)
{
    const auto &[prefix, propName] = XMPHelper::SplitOnce(path, COLON);
    CHECK_ERROR_RETURN_RET_LOG(prefix.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s invalid path syntax: %{public}s. Expected format: prefix:property", __func__, path.c_str());

    // rootPath allow empty property name
    CHECK_ERROR_RETURN_RET_LOG(!isRootPath && propName.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s invalid path syntax: %{public}s. Property name should not be empty", __func__, path.c_str());

    // Block language qualifiers from being written as "@xml:lang".
    CHECK_ERROR_RETURN_RET_LOG(propName.find("@xml:lang") != std::string::npos, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s invalid path syntax: %{public}s. Language qualifiers should use ?xml:lang",
        __func__, path.c_str());

    CHECK_ERROR_RETURN_RET_LOG(!SXMPMeta::GetNamespaceURI(prefix.c_str(), &outUri),
        ERR_XMP_NAMESPACE_NOT_REGISTERED, "%{public}s failed to get namespace URI for prefix: %{public}s",
        __func__, prefix.c_str());

    outPropName = propName;
    return SUCCESS;
}

// Helper to validate tag type for 'SetValue'
static uint32_t ValidateTagType(const std::string &path, const XMPTagType &tagType)
{
    if (!XMPMetadata::IsValidTagType(tagType)) {
        IMAGE_LOGE("%{public}s tagType is invalid for path: %{public}s", __func__, path.c_str());
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    return SUCCESS;
}

static constexpr XMPTagType ConvertOptionsToTagType(XMP_OptionBits options)
{
    if (XMP_PropIsStruct(options)) {
        return XMPTagType::STRUCTURE;
    }

    if (XMP_PropIsArray(options)) {
        if (XMP_ArrayIsAltText(options)) {
            return XMPTagType::ALTERNATE_TEXT;
        }
        if (XMP_ArrayIsAlternate(options)) {
            return XMPTagType::ALTERNATE_ARRAY;
        }
        if (XMP_ArrayIsOrdered(options)) {
            return XMPTagType::ORDERED_ARRAY;
        }
        return XMPTagType::UNORDERED_ARRAY;
    }

    return XMPTagType::STRING;
}

static constexpr XMP_OptionBits ConvertTagTypeToOptions(XMPTagType tagType)
{
    switch (tagType) {
        case XMPTagType::STRING:
            return kXMP_NoOptions;
        case XMPTagType::UNORDERED_ARRAY:
            return kXMP_PropValueIsArray;
        case XMPTagType::ORDERED_ARRAY:
            return kXMP_PropValueIsArray | kXMP_PropArrayIsOrdered;
        case XMPTagType::ALTERNATE_ARRAY:
            return kXMP_PropValueIsArray | kXMP_PropArrayIsOrdered | kXMP_PropArrayIsAlternate;
        case XMPTagType::ALTERNATE_TEXT:
            return kXMP_PropValueIsArray | kXMP_PropArrayIsOrdered | kXMP_PropArrayIsAlternate |
                kXMP_PropArrayIsAltText;
        case XMPTagType::STRUCTURE:
            return kXMP_PropValueIsStruct;
        default:
            return kXMP_NoOptions;
    }
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
        .isQualifier = XMP_PropIsQualifier(options),
        .value = value,
    };
    return true;
}

uint32_t XMPMetadata::RegisterNamespacePrefix(const std::string &uri, const std::string &prefix,
    std::string &errMsg)
{
    XMP_TRY();
    errMsg.clear();
    CHECK_ERROR_RETURN_RET_LOG(uri.empty() || prefix.empty(), ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s uri or prefix is empty", __func__);
    std::string placeholder;
    bool isUriRegistered = SXMPMeta::GetNamespacePrefix(uri.c_str(), &placeholder);
    if (isUriRegistered) {
        std::string normalizedPrefix = XMPHelper::NormalizeNamespacePrefix(placeholder);
        CHECK_DEBUG_RETURN_RET_LOG(prefix == normalizedPrefix, SUCCESS,
            "%{public}s namespace already registered with same prefix", __func__);

        errMsg = "namespace('" + uri + "') already registered with prefix('" + normalizedPrefix + "').";
        IMAGE_LOGE("%{public}s %{public}s", __func__, errMsg.c_str());
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    bool isPrefixRegistered = SXMPMeta::GetNamespaceURI(prefix.c_str(), &placeholder);
    if (isPrefixRegistered) {
        errMsg = "prefix('" + prefix + "') already registered with namespace('" + placeholder + "').";
        IMAGE_LOGE("%{public}s %{public}s", __func__, errMsg.c_str());
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

    std::string namespaceUri;
    std::string propName;
    uint32_t errorCode = ValidateAndResolvePath(path, namespaceUri, propName);
    CHECK_ERROR_RETURN_RET(errorCode != SUCCESS, errorCode);

    errorCode = ValidateTagType(path, tagType);
    CHECK_ERROR_RETURN_RET(errorCode != SUCCESS, errorCode);

    std::string parentPath = XMPHelper::GetParentProperty(propName);
    if (!parentPath.empty() && !impl_->DoesPropertyExist(namespaceUri.c_str(), parentPath.c_str())) {
        IMAGE_LOGW("%{public}s parent not found for path: %{public}s", __func__, path.c_str());
        return ERR_XMP_PARENT_NOT_FOUND;
    }

    XMP_OptionBits options = ConvertTagTypeToOptions(tagType);
    if (XMPMetadata::IsContainerTagType(tagType)) {
        CHECK_ERROR_RETURN_RET_LOG(!value.empty(), ERR_IMAGE_INVALID_PARAMETER, "%{public}s: container tag's value "
            "MUST be empty for path: %{public}s", __func__, path.c_str());
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

    std::string namespaceUri;
    std::string propName;
    uint32_t errorCode = ValidateAndResolvePath(path, namespaceUri, propName);
    CHECK_ERROR_RETURN_RET(errorCode != SUCCESS, errorCode);

    XMP_OptionBits options = kXMP_NoOptions;
    std::string value;
    bool propRet = impl_->GetProperty(namespaceUri.c_str(), propName.c_str(), &value, &options);
    CHECK_ERROR_RETURN_RET_LOG(!propRet, ERR_XMP_TAG_NOT_FOUND,
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

    std::string namespaceUri;
    std::string propName;
    uint32_t errorCode = ValidateAndResolvePath(path, namespaceUri, propName);
    CHECK_ERROR_RETURN_RET(errorCode != SUCCESS, errorCode);

    // Check if property exists before deleting
    if (!impl_->DoesPropertyExist(namespaceUri.c_str(), propName.c_str())) {
        IMAGE_LOGW("%{public}s tag not found for path: %{public}s", __func__, path.c_str());
        return ERR_XMP_TAG_NOT_FOUND;
    }

    impl_->DeleteProperty(namespaceUri.c_str(), propName.c_str());
    IMAGE_LOGD("%{public}s successfully removed tag: %{public}s", __func__, path.c_str());
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

uint32_t XMPMetadata::RemoveAllTags()
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s impl is invalid", __func__);

    SXMPUtils::RemoveProperties(impl_->GetRawPtr(), nullptr, nullptr, kXMPUtil_DoAllProperties);
    return SUCCESS;
    XMP_CATCH_RETURN_CODE(ERR_XMP_SDK_EXCEPTION);
}

static void EnumerateWithIterator(const IteratorParams &params, const XMPMetadata::EnumerateCallback &callback)
{
    CHECK_ERROR_RETURN_LOG(params.meta == nullptr, "%{public}s meta is null", __func__);
    CHECK_ERROR_RETURN_LOG(!callback, "%{public}s callback is null", __func__);

    XMP_OptionBits iterOptions = params.options;
    SXMPIterator iter(*params.meta, params.schemaNS, params.propName, iterOptions);
    std::string iterSchemaNS;
    std::string iterPropPath;
    std::string iterPropValue;
    // Iterate all properties
    while (iter.Next(&iterSchemaNS, &iterPropPath, &iterPropValue, &iterOptions)) {
        if (iterPropPath.empty()) {
            IMAGE_LOGD("Skipping schema node: %{public}s", iterSchemaNS.c_str());
            continue;
        }

        // Skip rootPath itself
        if (params.rootPath != nullptr && iterPropPath == params.rootPath) {
            continue;
        }

        // Skip non-qualifier nodes when onlyQualifier is set
        if (params.onlyQualifier && !XMP_PropIsQualifier(iterOptions)) {
            continue;
        }

        XMPTag tag;
        if (!BuildXMPTag(iterPropPath, iterOptions, iterPropValue, tag)) {
            IMAGE_LOGW("Failed to build XMPTag for path: %{public}s", iterPropPath.c_str());
            continue;
        }

        // Call the callback
        if (!callback(iterPropPath, tag)) {
            IMAGE_LOGD("%{public}s enumeration stopped by callback", __func__);
            return;
        }
    }
}

static void EnumerateAllSchemasTopLevelProps(SXMPMeta *meta, const XMPMetadata::EnumerateCallback &callback,
    bool onlyQualifier)
{
    CHECK_ERROR_RETURN_LOG(meta == nullptr, "%{public}s meta is null", __func__);
    CHECK_ERROR_RETURN_LOG(!callback, "%{public}s callback is null", __func__);

    std::vector<std::string> schemaList;
    XMP_OptionBits iterOptions = kXMP_IterJustChildren;
    SXMPIterator schemaIter(*meta, "", "", iterOptions);
    std::string iterSchemaNS;
    std::string iterPropPath;
    std::string iterPropValue;
    // Collect all schema namespaces
    while (schemaIter.Next(&iterSchemaNS, &iterPropPath, &iterPropValue, &iterOptions)) {
        if (!iterPropPath.empty() || iterSchemaNS.empty()) {
            continue;
        }
        if (std::find(schemaList.begin(), schemaList.end(), iterSchemaNS) == schemaList.end()) {
            schemaList.emplace_back(iterSchemaNS);
        }
    }

    // Enumerate all schema top level props
    for (const auto &schemaNS : schemaList) {
        IteratorParams params = {
            .meta = meta,
            .schemaNS = schemaNS.c_str(),
            .propName = nullptr,
            .rootPath = nullptr,    // non-recursive mode, no need to manually skip the rootPath
            .options = kXMP_IterJustChildren,
            .onlyQualifier = onlyQualifier,
        };
        EnumerateWithIterator(params, callback);
    }
}

uint32_t XMPMetadata::EnumerateTags(EnumerateCallback callback, const std::string &rootPath,
    XMPEnumerateOptions options)
{
    XMP_TRY();
    CHECK_ERROR_RETURN_RET_LOG(!impl_ || !impl_->IsValid(), ERR_MEDIA_NULL_POINTER,
        "%{public}s impl is invalid for path: %{public}s", __func__, rootPath.c_str());
    CHECK_ERROR_RETURN_RET_LOG(!callback, ERR_IMAGE_INVALID_PARAMETER, "%{public}s callback is null", __func__);

    if (rootPath.empty() && !options.isRecursive) {
        IMAGE_LOGD("%{public}s Enumerate all schemas top level props", __func__);
        EnumerateAllSchemasTopLevelProps(impl_->GetRawPtr(), callback, options.onlyQualifier);
        return SUCCESS;
    }

    std::string schemaNS;
    std::string rootPropName;
    if (!rootPath.empty()) {
        CHECK_ERROR_RETURN_RET(ValidateAndResolvePath(rootPath, schemaNS, rootPropName, true) != SUCCESS,
            ERR_IMAGE_INVALID_PARAMETER);
    }

    XMP_OptionBits iterOptions = kXMP_IterJustChildren;
    if (options.isRecursive) {
        iterOptions = kXMP_NoOptions;
    }

    IteratorParams params = {
        .meta = impl_->GetRawPtr(),
        .schemaNS = schemaNS.c_str(),
        .propName = rootPropName.c_str(),
        .rootPath = rootPath.empty() ? nullptr : rootPath.c_str(),
        .options = iterOptions,
        .onlyQualifier = options.onlyQualifier,
    };
    EnumerateWithIterator(params, callback);
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