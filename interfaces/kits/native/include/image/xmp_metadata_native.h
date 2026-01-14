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

#ifndef INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_XMP_METADATA_NATIVE_H_
#define INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_XMP_METADATA_NATIVE_H_

#include "image_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief XMP Basic namespace URI.
 *
 * @since 24
 */
#define OH_XMP_NS_XMP_BASIC_URI "http://ns.adobe.com/xap/1.0/"

/**
 * @brief XMP Basic namespace prefix.
 *
 * @since 24
 */
#define OH_XMP_NS_XMP_BASIC_PREFIX "xmp"

/**
 * @brief XMP Rights Management namespace URI.
 *
 * @since 24
 */
#define OH_XMP_NS_XMP_RIGHTS_URI "http://ns.adobe.com/xap/1.0/rights/"

/**
 * @brief XMP Rights Management namespace prefix.
 *
 * @since 24
 */
#define OH_XMP_NS_XMP_RIGHTS_PREFIX "xmpRights"

/**
 * @brief Dublin Core namespace URI.
 *
 * @since 24
 */
#define OH_XMP_NS_DUBLIN_CORE_URI "http://purl.org/dc/elements/1.1/"

/**
 * @brief Dublin Core namespace prefix.
 *
 * @since 24
 */
#define OH_XMP_NS_DUBLIN_CORE_PREFIX "dc"

/**
 * @brief EXIF namespace URI.
 *
 * @since 24
 */
#define OH_XMP_NS_EXIF_URI "http://ns.adobe.com/exif/1.0/"

/**
 * @brief EXIF namespace prefix.
 *
 * @since 24
 */
#define OH_XMP_NS_EXIF_PREFIX "exif"

/**
 * @brief TIFF namespace URI.
 *
 * @since 24
 */
#define OH_XMP_NS_TIFF_URI "http://ns.adobe.com/tiff/1.0/"

/**
 * @brief TIFF namespace prefix.
 *
 * @since 24
 */
#define OH_XMP_NS_TIFF_PREFIX "tiff"

/**
 * @brief Enumerates the XMP tag type.
 *
 * @since 24
 */
typedef enum OH_XMPTagType {
    OH_XMP_TAG_TYPE_UNKNOWN = 0,
    OH_XMP_TAG_TYPE_SIMPLE = 1,
    OH_XMP_TAG_TYPE_UNORDERED_ARRAY = 2,
    OH_XMP_TAG_TYPE_ORDERED_ARRAY = 3,
    OH_XMP_TAG_TYPE_ALTERNATE_ARRAY = 4,
    OH_XMP_TAG_TYPE_ALTERNATE_TEXT = 5,
    OH_XMP_TAG_TYPE_STRUCTURE = 6,
    OH_XMP_TAG_TYPE_QUALIFIER = 7,
} OH_XMPTagType;

/**
 * @brief Defines XMP metadata object for the image interface.
 *
 * @since 24
 */
struct OH_XMPMetadata;
typedef struct OH_XMPMetadata OH_XMPMetadata;

/**
 * @brief Defines XMP tag object for the image interface.
 *
 * @since 24
 */
struct OH_XMPTag;
typedef struct OH_XMPTag OH_XMPTag;

/**
 * @brief Defines XMP tag list object for the image interface.
 *
 * @since 24
 */
struct OH_XMPTagList;
typedef struct OH_XMPTagList OH_XMPTagList;

/**
 * @brief Defines enumerate options for XMP tags.
 *
 * @since 24
 */
typedef struct OH_XMPEnumerateOptions {
    bool isRecursive;
} OH_XMPEnumerateOptions;

/**
 * @brief Defines the callback function for enumerating XMP tags.
 *
 * @param path Indicates the tag path.
 * @param tag Indicates the tag object. The tag object lifecycle is managed by the caller.
 * @param userData Indicates a pointer to the user data.
 * @return Returns true to continue enumeration; returns false to stop enumeration.
 * @since 24
 */
typedef bool (*OH_XMPEnumerateCallback)(const char *path, OH_XMPTag *tag, void *userData);

/**
 * @brief Obtains the xmlns from an OH_XMPTag object.
 *
 * @param tag Indicates a pointer to the OH_XMPTag object.
 * @param outXmlns Indicates a pointer to the xmlns.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPTag_GetXmlns(const OH_XMPTag *tag, const char **outXmlns);

/**
 * @brief Obtains the prefix from an OH_XMPTag object.
 *
 * @param tag Indicates a pointer to the OH_XMPTag object.
 * @param outPrefix Indicates a pointer to the prefix.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPTag_GetPrefix(const OH_XMPTag *tag, const char **outPrefix);

/**
 * @brief Obtains the name from an OH_XMPTag object.
 *
 * @param tag Indicates a pointer to the OH_XMPTag object.
 * @param outName Indicates a pointer to the name.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPTag_GetName(const OH_XMPTag *tag, const char **outName);

/**
 * @brief Obtains the type from an OH_XMPTag object.
 *
 * @param tag Indicates a pointer to the OH_XMPTag object.
 * @param outType Indicates a pointer to the type.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPTag_GetType(const OH_XMPTag *tag, OH_XMPTagType *outType);

/**
 * @brief Obtains the value from an OH_XMPTag object.
 *
 * @param tag Indicates a pointer to the OH_XMPTag object.
 * @param outValue Indicates a pointer to the value.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPTag_GetValue(const OH_XMPTag *tag, const char **outValue);

/**
 * @brief Releases an OH_XMPTag object.
 *
 * @param tag Indicates a pointer to the OH_XMPTag object.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPTag_Release(OH_XMPTag *tag);

/**
 * @brief Creates an OH_XMPMetadata object.
 *
 * @param outMeta Indicates a pointer to the OH_XMPMetadata object created.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_Create(OH_XMPMetadata **outMeta);

/**
 * @brief Releases an OH_XMPMetadata object.
 *
 * @param meta Indicates a pointer to the OH_XMPMetadata object.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_Release(OH_XMPMetadata *meta);

/**
 * @brief Registers a namespace prefix.
 *
 * @param meta Indicates a pointer to the OH_XMPMetadata object.
 * @param xmlns Indicates the namespace URI.
 * @param prefix Indicates the namespace prefix.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_RegisterNamespacePrefix(OH_XMPMetadata *meta, const char *xmlns, const char *prefix);

/**
 * @brief Sets the value of an XMP tag.
 *
 * @param meta Indicates a pointer to the OH_XMPMetadata object.
 * @param path Indicates the tag path.
 * @param type Indicates the tag type.
 * @param value Indicates the tag value.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_SetValue(OH_XMPMetadata *meta, const char *path, OH_XMPTagType type, const char *value);

/**
 * @brief Removes an XMP tag.
 *
 * @param meta Indicates a pointer to the OH_XMPMetadata object.
 * @param path Indicates the tag path.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_RemoveTag(OH_XMPMetadata *meta, const char *path);

/**
 * @brief Obtains an XMP tag.
 *
 * @param meta Indicates a pointer to the OH_XMPMetadata object.
 * @param path Indicates the tag path.
 * @param outTag Indicates a pointer to the tag object obtained.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_GetTag(OH_XMPMetadata *meta, const char *path, OH_XMPTag **outTag);

/**
 * @brief Enumerates XMP tags.
 *
 * @param meta Indicates a pointer to the OH_XMPMetadata object.
 * @param callback Indicates the callback function.
 * @param userData Indicates a pointer to the user data.
 * @param rootPath Indicates the root tag path.
 * @param options Indicates a pointer to the enumerate options.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_EnumerateTags(OH_XMPMetadata *meta, OH_XMPEnumerateCallback callback, void *userData,
    const char *rootPath, const OH_XMPEnumerateOptions *options);

/**
 * @brief Gets XMP tags list.
 *
 * The tag pointers obtained from {@link OH_XMPTagList_GetAt} are borrowed pointers.
 * The caller MUST NOT release them. They are valid until {@link OH_XMPTagList_Release} is called.
 *
 * @param meta Indicates a pointer to the OH_XMPMetadata object.
 * @param rootPath Indicates the root tag path.
 * @param options Indicates a pointer to the enumerate options.
 * @param outList Indicates a pointer to the tag list object.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_GetTags(OH_XMPMetadata *meta, const char *rootPath,
    const OH_XMPEnumerateOptions *options, OH_XMPTagList **outList);

/**
 * @brief Gets the size of tag list.
 *
 * @param list Indicates a pointer to the tag list object.
 * @param outSize Indicates a pointer to the list size.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPTagList_GetSize(OH_XMPTagList *list, size_t *outSize);

/**
 * @brief Gets the tag information at the specified index.
 *
 * The returned path and tag are borrowed pointers and MUST NOT be released.
 * They are valid until {@link OH_XMPTagList_Release} is called.
 *
 * @param list Indicates a pointer to the tag list object.
 * @param index Indicates the index.
 * @param outPath Indicates a pointer to the borrowed path.
 * @param outTag Indicates a pointer to the borrowed tag.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPTagList_GetAt(OH_XMPTagList *list, size_t index, const char **outPath, const OH_XMPTag **outTag);

/**
 * @brief Releases an OH_XMPTagList object.
 *
 * After release, all borrowed tag pointers obtained from this list become invalid.
 * After release, all borrowed path pointers obtained from this list become invalid.
 *
 * @param list Indicates a pointer to the tag list object.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPTagList_Release(OH_XMPTagList *list);

/**
 * @brief Sets blob data to XMP metadata.
 *
 * @param meta Indicates a pointer to the OH_XMPMetadata object.
 * @param data Indicates a pointer to the blob data.
 * @param size Indicates the size of the blob data.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_SetBlob(OH_XMPMetadata *meta, const uint8_t *data, size_t size);

/**
 * @brief Gets the size of blob data from XMP metadata.
 *
 * @param meta Indicates a pointer to the OH_XMPMetadata object.
 * @param blobSize Indicates a pointer to the blob size.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_GetBlobSize(OH_XMPMetadata *meta, size_t *blobSize);

/**
 * @brief Gets blob data from XMP metadata.
 *
 * @param meta Indicates a pointer to the OH_XMPMetadata object.
 * @param outBuf Indicates a pointer to the buffer.
 * @param bufSize Indicates the size of the buffer.
 * @return Returns {@link Image_ErrorCode}.
 * @since 24
 */
Image_ErrorCode OH_XMPMetadata_GetBlob(OH_XMPMetadata *meta, uint8_t *outBuf, size_t bufSize);
#ifdef __cplusplus
};
#endif

#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_XMP_METADATA_NATIVE_H_
