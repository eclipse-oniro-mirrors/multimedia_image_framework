/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
 
/**
 * @addtogroup image
 * @{
 *
 * @brief Provides APIs for obtaining picture data and information.
 *
 * @Syscap SystemCapability.Multimedia.Image.Core
 * @since 13
 */

/**
 * @file picture_native.h
 *
 * @brief Declares the APIs that can access a picture.
 *
 * @library libpicture.so
 * @kit ImageKit
 * @Syscap SystemCapability.Multimedia.Image.Core
 * @since 13
 */
#ifndef INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_PICTURE_NATIVE_H_
#define INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_PICTURE_NATIVE_H_
#include "image_common.h"
#include "pixelmap_native.h"
 
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Define a Picture struct type, used for picture pointer controls.
 *
 * @since 13
 */
struct OH_PictureNative;

/**
 * @brief Define a Picture struct type, used for picture pointer controls.
 *
 * @since 13
 */
typedef struct OH_PictureNative OH_PictureNative;

/**
 * @brief Define a AuxiliaryPicture struct type, used for auxiliary
 * picture pointer controls.
 *
 * @since 13
 */
struct OH_AuxiliaryPictureNative;

/**
 * @brief Define a AuxiliaryPicture struct type, used for auxiliary
 * picture pointer controls.
 *
 * @since 13
 */
typedef struct OH_AuxiliaryPictureNative OH_AuxiliaryPictureNative;

/**
 * @brief Define a AuxiliaryPictureInfo struct type, used for auxiliary
 * picture info controls.
 *
 * @since 13
 */
struct OH_AuxiliaryPictureInfo;

/**
 * @brief Define a AuxiliaryPictureInfo struct type, used for auxiliary
 * picture info controls.
 *
 * @since 13
 */
typedef struct OH_AuxiliaryPictureInfo OH_AuxiliaryPictureInfo;

/**
 * @brief Define a auxiliary picture type.
 *
 * @since 13
 */
typedef enum {
    /*
    * Gainmap
    */
    AUXILIARY_PICTURE_TYPE_GAINMAP = 1,
    /*
    * Depth map
    */
    AUXILIARY_PICTURE_TYPE_DEPTH_MAP = 2,
    /*
    * Unrefocus map
    */
    AUXILIARY_PICTURE_TYPE_UNREFOCUS_MAP = 3,
    /*
    * Linear map
    */
    AUXILIARY_PICTURE_TYPE_LINEAR_MAP = 4,
    /*
    * Fragment map
    */
    AUXILIARY_PICTURE_TYPE_FRAGMENT_MAP = 5,
    /**
     * Snap map
     *
     * @since 26.0.0
     */
    AUXILIARY_PICTURE_TYPE_SNAP_MAP = 6,
    /**
     * Snap gainmap
     *
     * @since 26.0.0
     */
    AUXILIARY_PICTURE_TYPE_SNAP_GAINMAP = 7,
    /**
     * Pan map
     *
     * @since 26.0.0
     */
    AUXILIARY_PICTURE_TYPE_PAN_MAP = 8,
    /**
     * Pan gainmap
     *
     * @since 26.0.0
     */
    AUXILIARY_PICTURE_TYPE_PAN_GAINMAP = 9,
} Image_AuxiliaryPictureType;

/**
 * @brief Define a OH_ComposeOptions struct type, Describes compose parameters.
 *
 * @since 23
 */
typedef struct OH_ComposeOptions OH_ComposeOptions;

/**
 * @brief Create a instance for OH_ComposeOptions struct.
 *
 * @param options The OH_ComposeOptions pointer will be operated.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} options is nullptr.
 * @since 23
 */
Image_ErrorCode OH_ComposeOptions_Create(OH_ComposeOptions **options);

/**
 * @brief Set desired pixel format for ComposeOptions.
 *
 * @param options The OH_ComposeOptions pointer will be operated.
 * @param desiredPixelFormat The desired pixel format will be set, RGBA_1010102\YCBCR_P010\YCRCB_P010 are supported.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} options is nullptr.
 * @since 23
 */
Image_ErrorCode OH_ComposeOptions_SetDesiredPixelFormat(OH_ComposeOptions *options, PIXEL_FORMAT desiredPixelFormat);

/**
 * @brief Get desired pixel format for ComposeOptions.
 *
 * @param options The OH_ComposeOptions pointer will be operated.
 * @param desiredPixelFormat The desired pixel format.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} options is nullptr, or desiredPixelFormat is nullptr.
 * @since 23
 */
Image_ErrorCode OH_ComposeOptions_GetDesiredPixelFormat(OH_ComposeOptions *options, PIXEL_FORMAT *desiredPixelFormat);

/**
 * @brief Releases an OH_ComposeOptions object.
 *
 * @param options Indicates a OH_ComposeOptions pointer.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} options is nullptr.
 * @since 23
 */
Image_ErrorCode OH_ComposeOptions_Release(OH_ComposeOptions *options);

/**
 * @brief Create a <b>Picture</b> object.
 *
 * @param mainPixelmap The pixel map of the main image.
 * @param picture Picture pointer for created.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} mainPixelmap is nullptr, or picture is nullptr.
 * @since 13
 */
Image_ErrorCode OH_PictureNative_CreatePicture(OH_PixelmapNative *mainPixelmap, OH_PictureNative **picture);

/**
 * @brief Obtains the pixel map of the main image.
 *
 * @param picture The Picture pointer will be operated.
 * @param mainPixelmap Main pixel map pointer for obtained.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} picture is nullptr, or mainPixelmap is nullptr.
 * @since 13
 */
Image_ErrorCode OH_PictureNative_GetMainPixelmap(OH_PictureNative *picture, OH_PixelmapNative **mainPixelmap);

/**
 * @brief Obtains the hdr pixel map.
 *
 * @param picture The Picture pointer will be operated.
 * @param hdrPixelmap Hdr pixel map pointer for obtained.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} picture is nullptr, or hdrPixelmap is nullptr.
 *         {@link IMAGE_UNSUPPORTED_OPERATION} Unsupported operation, e.g. the picture does not has a gainmap.
 * @since 13
 */
Image_ErrorCode OH_PictureNative_GetHdrComposedPixelmap(OH_PictureNative *picture, OH_PixelmapNative **hdrPixelmap);

/**
 * @brief Obtains the hdr pixel map with options.
 *
 * @param picture The Picture pointer will be operated.
 * @param options The compose options.
 * @param hdrPixelmap Hdr pixel map pointer for obtained.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} picture is nullptr, or hdrPixelmap is nullptr.
 *         {@link IMAGE_UNSUPPORTED_OPERATION} Unsupported operation, e.g. the picture does not has a gainmap.
 * @since 23
 */
Image_ErrorCode OH_PictureNative_GetHdrComposedPixelmapWithOptions(OH_PictureNative *picture,
    OH_ComposeOptions *options, OH_PixelmapNative **hdrPixelmap);

/**
 * @brief Obtains the number of auxiliary pictures in a Picture object.
 *
 * @param picture Pointer to an OH_PictureNative object.
 * @param count Pointer to the number of auxiliary pictures.
 * @return <ul>
 *         <li>{@link IMAGE_SUCCESS} if the execution is successful.</li>
 *         <li>{@link IMAGE_INVALID_PARAMETER} picture or count is nullptr, or fail to get the picture.</li>
 *         </ul>
 * @since 26.0.0
 */
Image_ErrorCode OH_PictureNative_GetAuxiliaryPictureCount(OH_PictureNative *picture, uint32_t *count);
 
/**
 * @brief Obtains the types of auxiliary pictures in a Picture object.
 *
 * @param picture Pointer to an OH_PictureNative object.
 * @param auxiliaryPictureTypes Pointer to the array that receives the auxiliary picture types.
 * @param count On input, the size of the auxiliaryPictureTypes array.
 * @return <ul>
 *         <li>{@link IMAGE_SUCCESS} if the execution is successful.</li>
 *         <li>{@link IMAGE_INVALID_PARAMETER} picture, auxiliaryPictureTypes, or count is nullptr,
 *         or fail to get the picture, or count is smaller than required.</li>
 *         </ul>
 * @since 26.0.0
 */
Image_ErrorCode OH_PictureNative_GetAuxiliaryPictureTypes(OH_PictureNative *picture,
    Image_AuxiliaryPictureType *auxiliaryPictureTypes, uint32_t *count);
 
/**
 * @brief Obtains the number of metadata entries in a Picture object.
 *
 * @param picture Pointer to an OH_PictureNative object.
 * @param count Pointer to the number of metadata entries.
 * @return <ul>
 *         <li>{@link IMAGE_SUCCESS} if the execution is successful.</li>
 *         <li>{@link IMAGE_INVALID_PARAMETER} picture or count is nullptr, or fail to get the picture.</li>
 *         </ul>
 * @since 26.0.0
 */
Image_ErrorCode OH_PictureNative_GetMetadataCount(OH_PictureNative *picture, uint32_t *count);
 
/**
 * @brief Obtains the types of metadata in a Picture object.
 *
 * @param picture Pointer to an OH_PictureNative object.
 * @param metadataTypes Pointer to the array that receives the metadata types.
 * @param count On input, the size of the metadataTypes array.
 * @return <ul>
 *         <li>{@link IMAGE_SUCCESS} if the execution is successful.</li>
 *         <li>{@link IMAGE_INVALID_PARAMETER} picture, metadataTypes, or count is nullptr, or fail to get the picture,
 *         or count is smaller than required.</li>
 *         </ul>
 * @since 26.0.0
 */
Image_ErrorCode OH_PictureNative_GetMetadataTypes(OH_PictureNative *picture,
    Image_MetadataType *metadataTypes, uint32_t *count);
 
/**
 * @brief Deep copy a <b>Picture</b> object, selectively copying auxiliary pictures and metadata from the source
 * picture to specified positions of the destination picture. Optionally, if @param mainPixelMapKeyFromSrc is not
 * nullptr, a specific auxiliary picture from the source can be set as the main image of the destination picture.
 *
 * @param source Pointer to the source Picture object to be copied.
 * @param srcAuxiliaryPictures Array of auxiliary picture types in the source that will be copied.
 * @param srcAuxiliaryPictureCount Number of elements in srcAuxiliaryPictures.
 * @param srcMetadatas Array of metadata types in the source that will be copied.
 * @param srcMetadataCount Number of elements in srcMetadatas.
 * @param dstAuxiliaryPictures Array of destination auxiliary picture types corresponding to source auxiliary pictures.
 * @param dstAuxiliaryPictureCount Number of elements in dstAuxiliaryPictures.
 * @param dstMetadatas Array of destination metadata types corresponding to source metadatas.
 * @param dstMetadataCount Number of elements in dstMetadatas.
 * @param mainPixelMapKeyFromSrc Pointer to the auxiliary picture type in the source to be used as the main image
 * in the new picture. Pass nullptr to retain the main image from the source.
 * @param picture Address of a pointer that will receive the newly created deep-copied Picture.
 *
 * @return Image functions result code:
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_INVALID_PARAMETER} if @param source or @param picture is nullptr, or counts mismatch,
 *         or fail to get the source picture, or Count is not zero but corresponding array is nullptr.
 *         {@link IMAGE_ALLOC_FAILED} if memory allocation for the new Picture failed.
 * @since 26.0.0
 */
Image_ErrorCode OH_PictureNative_DeepCopy(OH_PictureNative *source,
    const Image_AuxiliaryPictureType* srcAuxiliaryPictures, uint32_t srcAuxiliaryPictureCount,
    const Image_MetadataType* srcMetadatas, uint32_t srcMetadataCount,
    const Image_AuxiliaryPictureType* dstAuxiliaryPictures, uint32_t dstAuxiliaryPictureCount,
    const Image_MetadataType* dstMetadatas, uint32_t dstMetadataCount,
    Image_AuxiliaryPictureType *mainPixelMapKeyFromSrc,
    OH_PictureNative **picture);
 
/**
 * @brief Removes an auxiliary picture from a Picture object.
 *
 * @param picture Pointer to an OH_PictureNative object.
 * @param type Type of the auxiliary picture to remove.
 * @return <ul>
 *         <li>{@link IMAGE_SUCCESS} if the auxiliary picture was successfully removed or did not exist.</li>
 *         <li>{@link IMAGE_INVALID_PARAMETER} picture is nullptr, or fail to get the picture,
 *         or the type is invalid.</li>
 *         </ul>
 * @since 26.0.0
 */
Image_ErrorCode OH_PictureNative_RemoveAuxiliaryPicture(OH_PictureNative *picture, Image_AuxiliaryPictureType type);
 
/**
 * @brief Removes metadata from a Picture object.
 *
 * @param picture Pointer to an OH_PictureNative object.
 * @param type Type of the metadata to remove.
 * @return <ul>
 *         <li>{@link IMAGE_SUCCESS} if the metadata was successfully removed or did not exist.</li>
 *         <li>{@link IMAGE_INVALID_PARAMETER} picture is nullptr, or fail to get the picture.</li>
 *         <li>{@link IMAGE_UNSUPPORTED_METADATA} unsupported metadata type.</li>
 *         </ul>
 * @since 26.0.0
 */
Image_ErrorCode OH_PictureNative_RemoveMetadata(OH_PictureNative *picture, Image_MetadataType type);

/**
 * @brief This structure is used to specify an auxiliary picture copy rule when creating a deep copy of a
 * PictureNative object. It describes how to copy an auxiliary picture from one type to another.
 *
 * @since 26.0.0
 */
typedef struct OH_PictureNative_AuxiliaryPictureCopyItem {
    /**
     * @brief Source auxiliary picture type. It specifies the type of auxiliary picture to be copied from the
     * source picture.
     *
     * @since 26.0.0
     */
    Image_AuxiliaryPictureType srcType;
 
    /**
     * @brief Destination auxiliary picture type. It specifies the type under which the copied auxiliary picture
     * will be stored in the destination picture.
     *
     * @since 26.0.0
     */
    Image_AuxiliaryPictureType dstType;
} OH_PictureNative_AuxiliaryPictureCopyItem;
 
/**
 * @brief This structure is used to specify a metadata copy rule when creating a deep copy of a PictureNative object.
 * It describes how to copy metadata from one type to another.
 *
 * @since 26.0.0
 */
typedef struct OH_PictureNative_MetadataCopyItem {
    /**
     * @brief Source metadata type. It specifies the type of metadata to be copied from the source picture.
     *
     * @since 26.0.0
     */
    Image_MetadataType srcType;
 
    /**
     * @brief Destination metadata type. It specifies the type under which the copied metadata will be stored in the
     * destination picture.
     *
     * @since 26.0.0
     */
    Image_MetadataType dstType;
} OH_PictureNative_MetadataCopyItem;
 
/**
 * @brief Creates a deep copy of a PictureNative object with specified auxiliary pictures and metadata copied to
 * specified destination types.
 *
 * @param source The source PictureNative object to be copied. Must not be NULL.
 * @param auxiliaryPictureCopyItems An array describing the auxiliary pictures to copy,
 *        including source and destination auxiliary picture types. Can be NULL if
 *        auxiliaryPictureCopyCount is 0.
 * @param auxiliaryPictureCopyCount The number of items in auxiliaryPictureCopyItems.
 * @param metadataCopyItems An array describing the metadata entries to copy,
 *        including source and destination metadata types. Can be NULL if
 *        metadataCopyCount is 0.
 * @param metadataCopyCount The number of items in metadataCopyItems.
 * @param sourceAuxPictureAsMainPixelMap Specifies an auxiliary picture type in the source
 *        picture to be used as the main pixel map in the copied picture. Can be NULL if
 *        the original main pixel map should be used.
 * @param picture Output parameter used to receive the newly created PictureNative object.
 *        The caller is responsible for releasing it when it is no longer needed.
 * @return <ul>
 *         <li>{@link IMAGE_SUCCESS} if the execution is successful.</li>
 *         <li>{@link IMAGE_INVALID_PARAMETER} if source or picture is nullptr, or counts mismatch,
 *         or fail to get the source picture, or Count is not zero but corresponding array is nullptr.</li>
 *         <li>{@link IMAGE_ALLOC_FAILED} memory allocation failed.</li>
 *         </ul>
 * @release picture_native/OH_PictureNative_Release {picture}
 * @since 26.0.0
 */
Image_ErrorCode OH_PictureNative_DeepCopyWithItems(

    OH_PictureNative *source,
    const OH_PictureNative_AuxiliaryPictureCopyItem *auxiliaryPictureCopyItems, uint32_t auxiliaryPictureCopyCount,
    const OH_PictureNative_MetadataCopyItem *metadataCopyItems, uint32_t metadataCopyCount,
    Image_AuxiliaryPictureType *sourceAuxPictureAsMainPixelMap,
    OH_PictureNative **picture);

/**
 * @brief Obtains the gainmap pixel map.
 *
 * @param picture The Picture pointer will be operated.
 * @param gainmapPixelmap Gainmap pointer for obtained.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} picture is nullptr, or gainmapPixelmap is nullptr.
 * @since 13
 */
Image_ErrorCode OH_PictureNative_GetGainmapPixelmap(OH_PictureNative *picture, OH_PixelmapNative **gainmapPixelmap);

/**
 * @brief Set auxiliary picture.
 *
 * @param picture The Picture pointer will be operated.
 * @param type The type of auxiliary picture.
 * @param auxiliaryPicture AuxiliaryPicture object.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} picture is nullptr, or auxiliaryPicture is nullptr, or the type is invalid.
 * @since 13
 */
Image_ErrorCode OH_PictureNative_SetAuxiliaryPicture(OH_PictureNative *picture, Image_AuxiliaryPictureType type,
    OH_AuxiliaryPictureNative *auxiliaryPicture);

/**
 * @brief Obtains the auxiliary picture based on type.
 *
 * @param picture The Picture pointer will be operated.
 * @param type The type of auxiliary picture.
 * @param auxiliaryPicture AuxiliaryPicture pointer for obtained.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} picture is nullptr, or auxiliaryPicture is nullptr, or the type is invalid.
 * @since 13
 */
Image_ErrorCode OH_PictureNative_GetAuxiliaryPicture(OH_PictureNative *picture, Image_AuxiliaryPictureType type,
    OH_AuxiliaryPictureNative **auxiliaryPicture);

/**
 * @brief Obtains the metadata of main picture.
 *
 * @param picture The Picture pointer will be operated.
 * @param metadataType The type of metadata.
 * @param metadata The metadata of main picture.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} picture is nullptr, or metadata is nullptr.
 *         {@link IMAGE_UNSUPPORTED_METADATA} unsupported metadata type.
 * @since 13
 */
Image_ErrorCode OH_PictureNative_GetMetadata(OH_PictureNative *picture, Image_MetadataType metadataType,
    OH_PictureMetadata **metadata);

/**
 * @brief Set main picture metadata.
 *
 * @param picture The Picture pointer will be operated.
 * @param metadataType The type of metadata.
 * @param metadata The metadata will be set.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} picture is nullptr, or metadata is nullptr.
 *         {@link IMAGE_UNSUPPORTED_METADATA} unsupported metadata type.
 * @since 13
 */
Image_ErrorCode OH_PictureNative_SetMetadata(OH_PictureNative *picture, Image_MetadataType metadataType,
    OH_PictureMetadata *metadata);

/**
 * @brief Releases this Picture object.
 *
 * @param picture The Picture pointer will be operated.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} picture is nullptr.
 * @since 13
 */
Image_ErrorCode OH_PictureNative_Release(OH_PictureNative *picture);

/**
 * @brief Create a <b>AuxiliaryPicture</b> object.
 *
 * @param data The image data buffer.
 * @param dataLength The length of data.
 * @param size The size of auxiliary picture.
 * @param type The type of auxiliary picture.
 * @param auxiliaryPicture AuxiliaryPicture pointer for created.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} data is nullptr, or dataLength is invalid, or size is nullptr, or the type
 *         is invalid, or auxiliaryPicture is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureNative_Create(uint8_t *data, size_t dataLength, Image_Size *size,
    Image_AuxiliaryPictureType type, OH_AuxiliaryPictureNative **auxiliaryPicture);

/**
 * @brief Write pixels to auxiliary picture.
 *
 * @param auxiliaryPicture The AuxiliaryPicture pointer will be operated.
 * @param source The pixels will be written.
 * @param bufferSize The size of pixels.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} auxiliaryPicture is nullptr, or source is nullptr, or the bufferSize is invalid.
 *         {@link IMAGE_ALLOC_FAILED} memory alloc failed.
 *         {@link IMAGE_COPY_FAILED} memory copy failed.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureNative_WritePixels(OH_AuxiliaryPictureNative *auxiliaryPicture, uint8_t *source,
    size_t bufferSize);

/**
 * @brief Read pixels from auxiliary picture.
 *
 * @param auxiliaryPicture The AuxiliaryPicture pointer will be operated.
 * @param destination The pixels will be read.
 * @param bufferSize The size of pixels for reading.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} auxiliaryPicture is nullptr, or destination is nullptr,
 *         or the bufferSize is invalid.
 *         {@link IMAGE_ALLOC_FAILED} memory alloc failed.
 *         {@link IMAGE_COPY_FAILED} memory copy failed.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureNative_ReadPixels(OH_AuxiliaryPictureNative *auxiliaryPicture, uint8_t *destination,
    size_t *bufferSize);

/**
 * @brief Obtains the type of auxiliary picture.
 *
 * @param auxiliaryPicture The AuxiliaryPicture pointer will be operated.
 * @param type The type of auxiliary picture.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} auxiliaryPicture is nullptr, or type is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureNative_GetType(OH_AuxiliaryPictureNative *auxiliaryPicture,
    Image_AuxiliaryPictureType *type);

/**
 * @brief Obtains the info of auxiliary picture.
 *
 * @param auxiliaryPicture The AuxiliaryPicture pointer will be operated.
 * @param info The info of auxiliary picture.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} auxiliaryPicture is nullptr, or info is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureNative_GetInfo(OH_AuxiliaryPictureNative *auxiliaryPicture,
    OH_AuxiliaryPictureInfo **info);

/**
 * @brief Set auxiliary picture info.
 *
 * @param auxiliaryPicture The AuxiliaryPicture pointer will be operated.
 * @param info The info will be set.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} auxiliaryPicture is nullptr, or info is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureNative_SetInfo(OH_AuxiliaryPictureNative *auxiliaryPicture,
    OH_AuxiliaryPictureInfo *info);

/**
 * @brief Obtains the metadata of auxiliary picture.
 *
 * @param auxiliaryPicture The AuxiliaryPicture pointer will be operated.
 * @param metadataType The type of metadata.
 * @param metadata The metadata of auxiliary picture.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} auxiliaryPicture is nullptr, or metadata is nullptr.
 *         {@link IMAGE_UNSUPPORTED_METADATA} unsupported metadata type, or the metadata type does not match the
 *         auxiliary picture type.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureNative_GetMetadata(OH_AuxiliaryPictureNative *auxiliaryPicture,
    Image_MetadataType metadataType, OH_PictureMetadata **metadata);

/**
 * @brief Set auxiliary picture metadata.
 *
 * @param auxiliaryPicture The AuxiliaryPicture pointer will be operated.
 * @param metadataType The type of metadata.
 * @param metadata The metadata will be set.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} auxiliaryPicture is nullptr, or metadata is nullptr.
 *         {@link IMAGE_UNSUPPORTED_METADATA} unsupported metadata type, or the metadata type does not match the
 *         auxiliary picture type.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureNative_SetMetadata(OH_AuxiliaryPictureNative *auxiliaryPicture,
    Image_MetadataType metadataType, OH_PictureMetadata *metadata);

/**
 * @brief Obtains the OH_PixelmapNative object of an auxiliary picture.
 *
 * @param auxiliaryPicture Pointer to an OH_AuxiliaryPictureNative object.
 * @param pixelmap Double pointer to the OH_PixelmapNative object obtained.
 * @return <ul>
 *         <li>{@link IMAGE_SUCCESS} if the execution is successful.</li>
 *         <li>{@link IMAGE_INVALID_PARAMETER} auxiliaryPicture is nullptr, or pixelmap is nullptr.</li>
 *         <li>{@link IMAGE_GET_IMAGE_DATA_FAILED} fail to get the auxiliary picture or its pixelmap content.</li>
 *         <li>{@link IMAGE_ALLOC_FAILED} memory allocation failed.</li>
 *         </ul>
 * @release pixelmap_native/OH_PixelmapNative_Destroy {pixelmap}
 * @since 26.0.0
 */
Image_ErrorCode OH_AuxiliaryPictureNative_AcquirePixelmap(OH_AuxiliaryPictureNative *auxiliaryPicture,
    OH_PixelmapNative **pixelmap);

/**
 * @brief Obtains the auxiliary picture pixel map.
 *
 * @param auxiliaryPicture The AuxiliaryPicture pointer will be operated.
 * @param pixelmap Pixelmap pointer for obtained.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_INVALID_PARAMETER} auxiliaryPicture is nullptr, or pixelmap is nullptr.
 *         {@link IMAGE_GET_IMAGE_DATA_FAILED} fail to get the auxiliary picture or its pixelmap content.
 *         {@link IMAGE_ALLOC_FAILED} memory alloc failed.
 * @since 26.0.0
 */
Image_ErrorCode OH_AuxiliaryPictureNative_GetPixelmap(OH_AuxiliaryPictureNative *auxiliaryPicture,
    OH_PixelmapNative **pixelmap);

/**
 * @brief Releases this AuxiliaryPicture object.
 *
 * @param picture The Picture pointer will be operated.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} picture is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureNative_Release(OH_AuxiliaryPictureNative *picture);

/**
 * @brief Create a <b>AuxiliaryPictureInfo</b> object.
 *
 * @param info The AuxiliaryPictureInfo pointer will be operated.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} info is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureInfo_Create(OH_AuxiliaryPictureInfo **info);

/**
 * @brief Obtains the type of auxiliary picture info.
 *
 * @param info The AuxiliaryPictureInfo pointer will be operated.
 * @param type The type of auxiliary picture info.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} info is nullptr, or type is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureInfo_GetType(OH_AuxiliaryPictureInfo *info, Image_AuxiliaryPictureType *type);

/**
 * @brief Set auxiliary picture info type.
 *
 * @param info The AuxiliaryPictureInfo pointer will be operated.
 * @param type The type will be set.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} info is nullptr, or type is invalid.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureInfo_SetType(OH_AuxiliaryPictureInfo *info, Image_AuxiliaryPictureType type);

/**
 * @brief Obtains the size of auxiliary picture info.
 *
 * @param info The AuxiliaryPictureInfo pointer will be operated.
 * @param size The size of auxiliary picture info.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} info is nullptr, or size is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureInfo_GetSize(OH_AuxiliaryPictureInfo *info, Image_Size *size);

/**
 * @brief Set auxiliary picture info size.
 *
 * @param info The AuxiliaryPictureInfo pointer will be operated.
 * @param size The size will be set.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} info is nullptr, or size is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureInfo_SetSize(OH_AuxiliaryPictureInfo *info, Image_Size *size);

/**
 * @brief Obtains the rowStride of auxiliary picture info.
 *
 * @param info The AuxiliaryPictureInfo pointer will be operated.
 * @param rowStride The rowStride of auxiliary picture info.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} info is nullptr, or rowStride is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureInfo_GetRowStride(OH_AuxiliaryPictureInfo *info, uint32_t *rowStride);

/**
 * @brief Set auxiliary picture info rowStride.
 *
 * @param info The AuxiliaryPictureInfo pointer will be operated.
 * @param rowStride The rowStride will be set.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} info is nullptr, or rowStride is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureInfo_SetRowStride(OH_AuxiliaryPictureInfo *info, uint32_t rowStride);

/**
 * @brief Obtains the pixelFormat of auxiliary picture info.
 *
 * @param info The AuxiliaryPictureInfo pointer will be operated.
 * @param pixelFormat The pixelFormat will be get.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} info is nullptr, or pixelFormat is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureInfo_GetPixelFormat(OH_AuxiliaryPictureInfo *info, PIXEL_FORMAT *pixelFormat);

/**
 * @brief Set auxiliary picture info pixelFormat.
 *
 * @param info The AuxiliaryPictureInfo pointer will be operated.
 * @param pixelFormat The pixelFormat will be set.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} info is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureInfo_SetPixelFormat(OH_AuxiliaryPictureInfo *info, PIXEL_FORMAT pixelFormat);

/**
 * @brief Releases this AuxiliaryPictureInfo object.
 *
 * @param info The AuxiliaryPictureInfo pointer will be operated.
 * @return Image functions result code.
 *         {@link IMAGE_SUCCESS} if the execution is successful.
 *         {@link IMAGE_BAD_PARAMETER} info is nullptr.
 * @since 13
 */
Image_ErrorCode OH_AuxiliaryPictureInfo_Release(OH_AuxiliaryPictureInfo *info);

/**
 * @brief Creates an OH_AuxiliaryPictureNative object with a specified memory type. By default, the system selects
 * the memory type based on the image type, image size, platform capability, and other factors. When processing the
 * auxiliary picture returned by this API, always consider the impact of stride. If **data** is null or **dataLength**
 * is less than or equal to 0, the auxiliary picture will not be initialized.
 * @systemapi
 * @param data Pointer to the image data.
 * @param dataLength Length of the image data.
 * @param info Pointer to the basic information of the auxiliary picture.
 * @param allocator Memory type used by the auxiliary picture. For details about the available options, see
 *     {@link IMAGE_ALLOCATOR_MODE}.
 * @param auxiliaryPicture Double pointer to the OH_AuxiliaryPictureNative object created.
 * @return <ul>
 *         <li>{@link IMAGE_SUCCESS} if the execution is successful.</li>
 *         <li>202 if a non-system application calls this system API.</li>
 *         <li>{@link IMAGE_INVALID_PARAMETER} info or auxiliaryPicture is nullptr, or allocator is invalid,
 *         or the size is invalid, or the type is unsupported, or dataLength is smaller than required.</li>
 *         <li>{@link IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE} unsupported allocator type,
 *         e.g., use share memory create a gainmap as only DMA supported hdr metadata.</li>
 *         <li>{@link IMAGE_ALLOC_FAILED} memory allocation failed.</li>
 *         </ul>
 * @release picture_native/OH_AuxiliaryPictureNative_Release {auxiliaryPicture}
 * @since 26.0.0
 */
Image_ErrorCode OH_AuxiliaryPictureNative_CreateUsingAllocator(uint8_t *data, size_t dataLength,
    OH_AuxiliaryPictureInfo *info, IMAGE_ALLOCATOR_MODE allocator, OH_AuxiliaryPictureNative **auxiliaryPicture);

#ifdef __cplusplus
};
#endif
/** @} */
#endif //INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_PICTURE_NATIVE_H_