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

#include <memory>
#include <string>
#include <unordered_map>
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

struct OH_XMPTagMap {
    std::unordered_map<std::string, OH_XMPTag *> tags;
    std::vector<std::string> keys;
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
Image_ErrorCode OH_XMPTagMap_GetSize(OH_XMPTagMap *map, size_t *outSize)
{
    if (map == nullptr || outSize == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outSize = map->keys.size();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTagMap_GetKeyAt(OH_XMPTagMap *map, size_t index, const char **outPath)
{
    if (map == nullptr || outPath == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    if (index >= map->keys.size()) {
        return IMAGE_BAD_PARAMETER;
    }
    *outPath = map->keys[index].c_str();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTagMap_GetTag(OH_XMPTagMap *map, const char *path, const OH_XMPTag **outTag)
{
    if (map == nullptr || path == nullptr || outTag == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outTag = nullptr;

    auto it = map->tags.find(std::string(path));
    if (it == map->tags.end()) {
        return IMAGE_XMP_TAG_NOT_FOUND;
    }
    *outTag = it->second;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_XMPTagMap_Release(OH_XMPTagMap *map)
{
    if (map == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    for (auto &item : map->tags) {
        delete item.second;
    }
    delete map;
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
    uint32_t innerCode = meta->inner->RegisterNamespacePrefix(std::string(xmlns), std::string(prefix));
    return static_cast<Image_ErrorCode>(ImageErrorConvert::XMPMetadataMakeErrMsg(innerCode).first);
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_SetValue(OH_XMPMetadata *meta, const char *path, OH_XMPTagType type, const char *value)
{
    if (meta == nullptr || meta->inner == nullptr || path == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    std::string val = value == nullptr ? std::string() : std::string(value);
    XMPTagType innerType = static_cast<XMPTagType>(static_cast<int32_t>(type));
    uint32_t innerCode = meta->inner->SetValue(std::string(path), innerType, val);
    return static_cast<Image_ErrorCode>(ImageErrorConvert::XMPMetadataMakeErrMsg(innerCode).first);
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_RemoveTag(OH_XMPMetadata *meta, const char *path)
{
    if (meta == nullptr || meta->inner == nullptr || path == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    uint32_t innerCode = meta->inner->RemoveTag(std::string(path));
    return static_cast<Image_ErrorCode>(ImageErrorConvert::XMPMetadataMakeErrMsg(innerCode).first);
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_GetTag(OH_XMPMetadata *meta, const char *path, OH_XMPTag **outTag)
{
    if (meta == nullptr || meta->inner == nullptr || path == nullptr || outTag == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outTag = nullptr;

    XMPTag tag;
    uint32_t innerCode = meta->inner->GetTag(std::string(path), tag);
    if (innerCode != SUCCESS) {
        return static_cast<Image_ErrorCode>(ImageErrorConvert::XMPMetadataMakeErrMsg(innerCode).first);
    }

    OH_XMPTag *ndkTag = new(std::nothrow) OH_XMPTag();
    if (ndkTag == nullptr) {
        return IMAGE_ALLOC_FAILED;
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

    uint32_t innerCode = meta->inner->EnumerateTags(
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

    return static_cast<Image_ErrorCode>(ImageErrorConvert::XMPMetadataMakeErrMsg(innerCode).first);
}

MIDK_EXPORT
Image_ErrorCode OH_XMPMetadata_GetTags(OH_XMPMetadata *meta, const char *rootPath, const OH_XMPEnumerateOptions *options,
    OH_XMPTagMap **outMap)
{
    if (meta == nullptr || meta->inner == nullptr || outMap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *outMap = nullptr;

    OH_XMPTagMap *map = new(std::nothrow) OH_XMPTagMap();
    CHECK_ERROR_RETURN_RET_LOG(map == nullptr, IMAGE_ALLOC_FAILED,
        "%{public}s Failed to allocate memory for tag map", __func__);

    XMPEnumerateOption innerOpt;
    if (options != nullptr) {
        innerOpt.isRecursive = options->isRecursive;
    }
    std::string root = rootPath == nullptr ? std::string() : std::string(rootPath);

    bool allocFailed = false;
    uint32_t innerCode = meta->inner->EnumerateTags(
        [map, &allocFailed](const std::string &path, const XMPTag &tag) -> bool {
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
            auto it = map->tags.find(path);
            if (it == map->tags.end()) {
                map->keys.emplace_back(path);
                map->tags.emplace(path, ndkTag);
            } else {
                delete it->second;
                it->second = ndkTag;
            }
            return true;
        },
        root, innerOpt);

    if (allocFailed) {
        for (auto &item : map->tags) {
            delete item.second;
        }
        delete map;
        return IMAGE_ALLOC_FAILED;
    }

    if (innerCode != SUCCESS) {
        for (auto &item : map->tags) {
            delete item.second;
        }
        delete map;
        return static_cast<Image_ErrorCode>(ImageErrorConvert::XMPMetadataMakeErrMsg(innerCode).first);
    }

    *outMap = map;
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
