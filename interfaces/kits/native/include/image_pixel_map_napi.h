/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
 * @brief Provides APIs for obtaining pixel map data and information.
 *
 * @Syscap SystemCapability.Multimedia.Image
 * @since 8
 * @version 1.0
 */

/**
 * @file image_pixel_map_napi.h
 *
 * @brief Declares the APIs that can lock, access, and unlock a pixel map.
 *
 * @since 8
 * @version 1.0
 */

#ifndef INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_PIXEL_MAP_NAPI_H_
#define INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_PIXEL_MAP_NAPI_H_
#include <cstdint>
#include "napi/native_api.h"
namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerates the error codes returned by the functions.
 *
 * @since 8
 * @version 1.0
 */
enum {
    /** Operation success. */
    OHOS_IMAGE_RESULT_SUCCESS = 0,
    /** Invalid value. */
    OHOS_IMAGE_RESULT_BAD_PARAMETER = -1,
};

/**
 * @brief Enumerates the pixel formats.
 *
 * @since 8
 * @version 1.0
 */
enum {
    /**
     * Unknown format.
     */
    OHOS_PIXEL_MAP_FORMAT_NONE = 0,
    /**
     * 32-bit RGBA, with 8 bits each for R (red), G (green), B (blue), and A (alpha).
     * The data is stored from the most significant bit to the least significant bit.
     */
    OHOS_PIXEL_MAP_FORMAT_RGBA_8888 = 3,
    /**
     * 16-bit RGB, with 5, 6, and 5 bits for R, G, and B, respectively.
     * The data is stored from the most significant bit to the least significant bit.
     */
    OHOS_PIXEL_MAP_FORMAT_RGB_565 = 2,
};

/**
 * @brief Defines the pixel map information.
 *
 * @since 8
 * @version 1.0
 */
struct OhosPixelMapInfo {
    /** Image width, in pixels. */
    uint32_t width;
    /** Image height, in pixels. */
    uint32_t height;
    /** Number of bytes per row. */
    uint32_t rowSize;
    /** Pixel format. */
    int32_t pixelFormat;
};

/**
 * @brief Defines the native pixel map information.
 * @since 9
 * @version 2.0
 */
struct NativePixelMap;

/**
 * @brief Defines the data type name of the native pixel map.
 * @since 9
 * @version 2.0
 */
typedef struct NativePixelMap NativePixelMap;

/**
 * @brief Enumerates the pixel map alpha types.
 *
 * @since 10
 * @version 2.0
 */
enum {
    /**
     * Unknown format.
     */
    OHOS_PIXEL_MAP_ALPHA_TYPE_UNKNOWN = 0,
    /**
     * Opaque format.
     */
    OHOS_PIXEL_MAP_ALPHA_TYPE_OPAQUE = 1,
    /**
     * Premultiplied format.
     */
    OHOS_PIXEL_MAP_ALPHA_TYPE_PREMUL = 2,
    /**
     * Unpremultiplied format.
     */
    OHOS_PIXEL_MAP_ALPHA_TYPE_UNPREMUL = 3
};

/**
 * @brief Enumerates the pixel map scale modes.
 *
 * @since 10
 * @version 2.0
 */
enum {
    /**
     * Adaptation to the target image size.
     */
    OHOS_PIXEL_MAP_SCALE_MODE_FIT_TARGET_SIZE = 0,
    /**
     * Cropping the center portion of an image to the target size.
     */
    OHOS_PIXEL_MAP_SCALE_MODE_CENTER_CROP = 1,
};

/**
 * @brief Enumerates the pixel map editing types.
 *
 * @since 10
 * @version 2.0
 */
enum {
    /**
     * Read-only.
     */
    OHOS_PIXEL_MAP_READ_ONLY = 0,
    /**
     * Editable.
     */
    OHOS_PIXEL_MAP_EDITABLE = 1,
};

/**
 * @brief Defines the options used for creating a pixel map.
 *
 * @since 10
 * @version 2.0
 */
struct OhosPixelMapCreateOps {
    /** Image width, in pixels. */
    uint32_t width;
    /** Image height, in pixels. */
    uint32_t height;
    /** Image format. */
    int32_t pixelFormat;
    /** Editing type of the image. */
    uint32_t editable;
    /** Alpha type of the image. */
    uint32_t alphaType;
    /** Scale mode of the image. */
    uint32_t scaleMode;
};

/**
 * @brief Obtains the information about a <b>PixelMap</b> object
 * and stores the information to the {@link OhosPixelMapInfo} struct.
 *
 * @param env Indicates the NAPI environment pointer.
 * @param value Indicates the <b>PixelMap</b> object at the application layer.
 * @param info Indicates the pointer to the object that stores the information obtained.
 * For details, see {@link OhosPixelMapInfo}.
 * @return Returns <b>0</b> if the information is obtained and stored successfully; returns an error code otherwise.
 * @see OhosPixelMapInfo
 * @since 8
 * @version 1.0
 */
int32_t OH_GetImageInfo(napi_env env, napi_value value, OhosPixelMapInfo *info);

/**
 * @brief Obtains the memory address of a <b>PixelMap</b> object and locks the memory.
 *
 * After the function is executed successfully, <b>*addrPtr</b> is the memory address to be accessed.
 * After the access operation is complete, you must use {@link OH_UnAccessPixels} to unlock the memory.
 * Otherwise, the resources in the memory cannot be released.
 * After the memory is unlocked, its address cannot be accessed or operated.
 *
 * @param env Indicates the NAPI environment pointer.
 * @param value Indicates the <b>PixelMap</b> object at the application layer.
 * @param addrPtr Indicates the double pointer to the memory address.
 * @see UnAccessPixels
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful; returns an error code otherwise.
 * @since 8
 * @version 1.0
 */
int32_t OH_AccessPixels(napi_env env, napi_value value, void** addrPtr);

/**
 * @brief Unlocks the memory of a <b>PixelMap</b> object. This function is used with {@link OH_AccessPixels} in pairs.
 *
 * @param env Indicates the NAPI environment pointer.
 * @param value Indicates the <b>PixelMap</b> object at the application layer.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful; returns an error code otherwise.
 * @see AccessPixels
 * @since 8
 * @version 1.0
 */
int32_t OH_UnAccessPixels(napi_env env, napi_value value);

/**
 * @brief Creates a <b>PixelMap</b> object.
 *
 * @param env Indicates the NAPI environment pointer.
 * @param info Indicates the options for setting the <b>PixelMap</b> object.
 * @param buf Indicates the pointer to the buffer of the image.
 * @param len Indicates the image size.
 * @param res Indicates the pointer to the <b>PixelMap</b> object at the application layer.
 * @return Returns a <b>PixelMap</b> object if the operation is successful; returns an error code otherwise.
 * @see CreatePixelMap
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_CreatePixelMap(napi_env env, OhosPixelMapCreateOps info,
    void* buf, size_t len, napi_value* res);

/**
 * @brief Creates a <b>PixelMap</b> object that contains only alpha channel information.
 *
 * @param env Indicates the NAPI environment pointer.
 * @param source Indicates the options for setting the <b>PixelMap</b> object.
 * @param alpha Indicates the pointer to the alpha channel.
 * @return Returns a <b>PixelMap</b> object if the operation is successful; returns an error code otherwise.
 * @see CreateAlphaPixelMap
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_CreateAlphaPixelMap(napi_env env, napi_value source, napi_value* alpha);

/**
 * @brief Initializes a <b>PixelMap</b> object.
 *
 * @param env Indicates the NAPI environment pointer.
 * @param source Indicates the options for setting the <b>PixelMap</b> object.
 * @return Returns a pointer to the <b>NativePixelMap</b> object
 * if the operation is successful; returns an error code otherwise.
 * @see InitNativePixelMap
 * @since 10
 * @version 2.0
 */
NativePixelMap* OH_PixelMap_InitNativePixelMap(napi_env env, napi_value source);

/**
 * @brief Obtains the number of bytes per row of a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param num Indicates the pointer to the number of bytes per row of the <b>PixelMap</b> object.
 * @return Returns the number of bytes per row of the <b>PixelMap</b> object
 * if the operation is successful; returns an error code otherwise.
 * @see GetBytesNumberPerRow
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_GetBytesNumberPerRow(const NativePixelMap* native, int32_t* num);

/**
 * @brief Checks whether a <b>PixelMap</b> object is editable.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param editable Indicates the pointer to the editing type of the <b>PixelMap</b> object.
 * @return Returns an enumerated value that indicates the editing type of the <b>PixelMap</b> object
 * if the operation is successful; returns an error code otherwise.
 * @see GetIsEditable
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_GetIsEditable(const NativePixelMap* native, int32_t* editable);

/**
 * @brief Checks whether a <b>PixelMap</b> object supports alpha channels.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param alpha Indicates the pointer to the support for alpha channels.
 * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
 * @see IsSupportAlpha
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_IsSupportAlpha(const NativePixelMap* native, int32_t* alpha);

/**
 * @brief Sets an alpha channel for a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param alpha Indicates the alpha channel to set.
 * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
 * @see SetAlphaAble
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_SetAlphaAble(const NativePixelMap* native, int32_t alpha);

/**
 * @brief Obtains the pixel density of a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param density Indicates the pointer to the pixel density.
 * @return Returns the pixel density if the operation is successful; returns an error code otherwise.
 * @see GetDensity
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_GetDensity(const NativePixelMap* native, int32_t* density);

/**
 * @brief Sets the pixel density for a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param density Indicates the pixel density to set.
 * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
 * @see GetDensity
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_SetDensity(const NativePixelMap* native, int32_t density);

/**
 * @brief Sets the opacity for a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param opacity Indicates the opacity to set.
 * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
 * @see SetOpacity
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_SetOpacity(const NativePixelMap* native, float opacity);

/**
 * @brief Scales a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param x Indicates the scaling ratio of the width.
 * @param y Indicates the scaling ratio of the height.
 * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
 * @see Scale
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_Scale(const NativePixelMap* native, float x, float y);

/**
 * @brief Translates a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param x Indicates the horizontal distance to translate.
 * @param y Indicates the vertical distance to translate.
 * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
 * @see Translate
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_Translate(const NativePixelMap* native, float x, float y);

/**
 * @brief Rotates a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param angle Indicates the angle to rotate.
 * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
 * @see Rotate
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_Rotate(const NativePixelMap* native, float angle);

/**
 * @brief Flips a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param x Specifies whether to flip around the x axis.
 * @param y Specifies whether to flip around the y axis.
 * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
 * @see Flip
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_Flip(const NativePixelMap* native, int32_t x, int32_t y);

/**
 * @brief Crops a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param x Indicates the x-coordinate of the upper left corner of the target image.
 * @param y Indicates the y-coordinate of the upper left corner of the target image.
 * @param width Indicates the width of the cropped region.
 * @param height Indicates the height of the cropped region.
 * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
 * @see Crop
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_Crop(const NativePixelMap* native, int32_t x, int32_t y, int32_t width, int32_t height);

/**
 * @brief Obtains the image information of a <b>PixelMap</b> object.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param info Indicates the pointer to the image information.
 * @return Returns <b>0</b> if the operation is successful; returns an error code otherwise.
 * @see OhosPixelMapInfo
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_GetImageInfo(const NativePixelMap* native, OhosPixelMapInfo *info);

/**
 * @brief Obtains the memory address of a <b>NativePixelMap</b> object and locks the memory.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @param addr Indicates the double pointer to the memory address.
 * @see UnAccessPixels
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful; returns an error code otherwise.
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_AccessPixels(const NativePixelMap* native, void** addr);

/**
 * @brief Unlocks the memory of the <b>NativePixelMap</b> object data.
 * This function is used with {@link OH_PixelMap_AccessPixels} in pairs.
 *
 * @param native Indicates the pointer to a <b>NativePixelMap</b> object.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful; returns an error code otherwise.
 * @see AccessPixels
 * @since 10
 * @version 2.0
 */
int32_t OH_PixelMap_UnAccessPixels(const NativePixelMap* native);

#ifdef __cplusplus
};
#endif
/** @} */
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_PIXEL_MAP_NAPI_H_
