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

#include "xmp_metadata_native.h"

#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "common_utils.h"
#include "image_error_convert.h"
#include "image_log.h"
#include "media_errors.h"
#include "xmp_metadata_native_impl.h"
#include "xmp_metadata.h"

#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif

using namespace OHOS;
using namespace Media;

#ifdef __cplusplus
extern "C" {
#endif

struct OH_XMPTag {
    std::string xmlns;
    std::string prefix;
    std::string name;
    OH_XMPTagType type = OH_XMP_TAG_TYPE_UNKNOWN;
    std::string value;
};

struct OH_XMPTagList {
    std::vector<std::pair<std::string, OH_XMPTag *>> tags;
};

MIDK_EXPORT
Image_ErrorCode OH_XMPTag_GetXmlns(const OH_XMPTag *tag, const char **outXmlns)
{
    if (tag == nullptr || outXmlns == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outXmlns = tag->xmlns.c_str();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTag_GetPrefix(const OH_XMPTag *tag, const char **outPrefix)
{
    if (tag == nullptr || outPrefix == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outPrefix = tag->prefix.c_str();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTag_GetName(const OH_XMPTag *tag, const char **outName)
{
    if (tag == nullptr || outName == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outName = tag->name.c_str();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTag_GetType(const OH_XMPTag *tag, OH_XMPTagType *outType)
{
    if (tag == nullptr || outType == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outType = tag->type;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTag_GetValue(const OH_XMPTag *tag, const char **outValue)
{
    if (tag == nullptr || outValue == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outValue = tag->value.c_str();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTag_Release(OH_XMPTag *tag)
{
    if (tag == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete tag;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTagList_GetSize(OH_XMPTagList *list, size_t *outSize)
{
    if (list == nullptr || outSize == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outSize = list->tags.size();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTagList_GetAt(OH_XMPTagList *list, size_t index, const char **outPath, const OH_XMPTag **outTag)
{
    if (list == nullptr || outPath == nullptr || outTag == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    if (index >= list->tags.size()) {
        return IMAGE_BAD_PARAMETER;
    }
    *outPath = list->tags[index].first.c_str();
    *outTag = list->tags[index].second;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTagList_Release(OH_XMPTagList *list)
{
    if (list == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    for (auto &[_, tag] : list->tags) {
        delete tag;
    }
    delete list;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_Create(OH_XMPMetadata **outMeta)
{
    if (outMeta == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    OH_XMPMetadata *meta = new(std::nothrow) OH_XMPMetadata();
    if (meta == nullptr) {
        return IMAGE_SOURCE_ALLOC_FAILED;
    }
    meta->inner = std::make_shared<XMPMetadata>();
    if (meta->inner == nullptr) {
        delete meta;
        return IMAGE_SOURCE_ALLOC_FAILED;
    }

    *outMeta = meta;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_Release(OH_XMPMetadata *meta)
{
    if (meta == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete meta;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_RegisterNamespacePrefix(OH_XMPMetadata *meta, const char *xmlns, const char *prefix)
{
    if (meta == nullptr || meta->inner == nullptr || xmlns == nullptr || prefix == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    bool ok = meta->inner->RegisterNamespacePrefix(std::string(xmlns), std::string(prefix));
    return ok ? IMAGE_SUCCESS : IMAGE_UNKNOWN_ERROR;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_SetValue(OH_XMPMetadata *meta, const char *path, OH_XMPTagType type, const char *value)
{
    if (meta == nullptr || meta->inner == nullptr || path == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    std::string val = value == nullptr ? std::string() : std::string(value);
    XMPTagType innerType = static_cast<XMPTagType>(static_cast<int32_t>(type));
    bool ok = meta->inner->SetValue(std::string(path), innerType, val);
    return ok ? IMAGE_SUCCESS : IMAGE_UNKNOWN_ERROR;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_RemoveTag(OH_XMPMetadata *meta, const char *path)
{
    if (meta == nullptr || meta->inner == nullptr || path == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    bool ok = meta->inner->RemoveTag(std::string(path));
    return ok ? IMAGE_SUCCESS : IMAGE_XMP_TAG_NOT_FOUND;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_GetTag(OH_XMPMetadata *meta, const char *path, OH_XMPTag **outTag)
{
    if (meta == nullptr || meta->inner == nullptr || path == nullptr || outTag == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outTag = nullptr;

    XMPTag tag;
    bool ok = meta->inner->GetTag(std::string(path), tag);
    if (!ok) {
        return IMAGE_XMP_TAG_NOT_FOUND;
    }

    OH_XMPTag *ndkTag = new(std::nothrow) OH_XMPTag();
    if (ndkTag == nullptr) {
        return IMAGE_SOURCE_ALLOC_FAILED;
    }
    ndkTag->xmlns = tag.xmlns;
    ndkTag->prefix = tag.prefix;
    ndkTag->name = tag.name;
    ndkTag->type = static_cast<OH_XMPTagType>(static_cast<int32_t>(tag.type));
    ndkTag->value = tag.value;
    *outTag = ndkTag;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_EnumerateTags(OH_XMPMetadata *meta, OH_XMPEnumerateCallback callback, void *userData,
    const char *rootPath, const OH_XMPEnumerateOptions *options)
{
    if (meta == nullptr || meta->inner == nullptr || callback == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    XMPEnumerateOption innerOpt;
    if (options != nullptr) {
        innerOpt.isRecursive = options->isRecursive;
    }

    std::string root = rootPath == nullptr ? std::string() : std::string(rootPath);

    meta->inner->EnumerateTags(
        [callback, userData](const std::string &path, const XMPTag &tag) -> bool {
            OH_XMPTag *ndkTag = new(std::nothrow) OH_XMPTag();
            if (ndkTag == nullptr) {
                return false;
            }
            ndkTag->xmlns = tag.xmlns;
            ndkTag->prefix = tag.prefix;
            ndkTag->name = tag.name;
            ndkTag->type = static_cast<OH_XMPTagType>(static_cast<int32_t>(tag.type));
            ndkTag->value = tag.value;
            return callback(path.c_str(), ndkTag, userData);
        },
        root, innerOpt);

    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_GetTags(OH_XMPMetadata *meta, const char *rootPath, const OH_XMPEnumerateOptions *options,
    OH_XMPTagList **outList)
{
    if (meta == nullptr || meta->inner == nullptr || outList == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outList = nullptr;

    OH_XMPTagList *list = new(std::nothrow) OH_XMPTagList();
    if (list == nullptr) {
        return IMAGE_SOURCE_ALLOC_FAILED;
    }

    XMPEnumerateOption innerOpt;
    if (options != nullptr) {
        innerOpt.isRecursive = options->isRecursive;
    }
    std::string root = rootPath == nullptr ? std::string() : std::string(rootPath);

    bool allocFailed = false;
    meta->inner->EnumerateTags(
        [list, &allocFailed](const std::string &path, const XMPTag &tag) -> bool {
            OH_XMPTag *ndkTag = new(std::nothrow) OH_XMPTag();
            if (ndkTag == nullptr) {
                allocFailed = true;
                return false;
            }
            ndkTag->xmlns = tag.xmlns;
            ndkTag->prefix = tag.prefix;
            ndkTag->name = tag.name;
            ndkTag->type = static_cast<OH_XMPTagType>(static_cast<int32_t>(tag.type));
            ndkTag->value = tag.value;
            list->tags.emplace_back(path, ndkTag);
            return true;
        },
        root, innerOpt);

    if (allocFailed) {
        for (auto &[_, tag] : list->tags) {
            delete tag;
        }
        delete list;
        return IMAGE_SOURCE_ALLOC_FAILED;
    }

    *outList = list;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_SetBlob(OH_XMPMetadata *meta, const uint8_t *data, size_t size)
{
    if (meta == nullptr || meta->inner == nullptr || data == nullptr || size == 0) {
        return IMAGE_BAD_PARAMETER;
    }

    uint32_t errorCode = meta->inner->SetBlob(data, static_cast<uint32_t>(size));
    return static_cast<Image_ErrorCode>(ImageErrorConvert::XMPMetadataMakeErrMsg(errorCode).first);
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_GetBlobSize(OH_XMPMetadata *meta, size_t *blobSize)
{
    if (meta == nullptr || meta->inner == nullptr || blobSize == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    std::string buffer;
    uint32_t errorCode = meta->inner->GetBlob(buffer);
    if (errorCode != SUCCESS) {
        return static_cast<Image_ErrorCode>(ImageErrorConvert::XMPMetadataMakeErrMsg(errorCode).first);
    }

    *blobSize = buffer.size();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_GetBlob(OH_XMPMetadata *meta, uint8_t *outBuf, size_t bufSize)
{
    if (meta == nullptr || meta->inner == nullptr || outBuf == nullptr || bufSize == 0) {
        return IMAGE_BAD_PARAMETER;
    }

    std::string buffer;
    uint32_t errorCode = meta->inner->GetBlob(buffer);
    if (errorCode != SUCCESS) {
        return static_cast<Image_ErrorCode>(ImageErrorConvert::XMPMetadataMakeErrMsg(errorCode).first);
    }

    if (bufSize < buffer.size()) {
        IMAGE_LOGE("%{public}s buffer size is too small! buffer size: %{public}zu, actual size: %{public}zu",
            __func__, buffer.size(), bufSize);
        return IMAGE_BAD_PARAMETER;
    }

    if (memcpy_s(outBuf, bufSize, buffer.data(), buffer.size()) != EOK) {
        return IMAGE_COPY_FAILED;
    }
    return IMAGE_SUCCESS;
}
#ifdef __cplusplus
};
#endif
