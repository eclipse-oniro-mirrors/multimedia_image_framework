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
 * @brief Provides access to pixel data and pixel map information.
 *
 * @Syscap SystemCapability.Multimedia.Image
 * @since 8
 * @version 1.0
 */

/**
 * @file image_pixel_map_napi.h
 *
 * @brief Declares functions for you to lock and access or unlock pixel data, and obtain the width and height of a pixel
 * map.
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
 * @brief Enumerates the result codes that may be returned by a function.
 *
 * @since 8
 * @version 1.0
 */
enum {
    /** Success result */
    OHOS_IMAGE_RESULT_SUCCESS = 0,
    /** Invalid parameters */
    OHOS_IMAGE_RESULT_BAD_PARAMETER = -1,
};

/**
 * @brief Enumerates pixel formats.
 *
 * @since 8
 * @version 1.0
 */
enum {
    /**
     * Unknown format
     */
    OHOS_PIXEL_MAP_FORMAT_NONE = 0,
    /**
     * 32-bit RGBA. Components R, G, B, and A each occupies 8 bits
     * and are stored from the higher-order to the lower-order bits.
     */
    OHOS_PIXEL_MAP_FORMAT_RGBA_8888 = 3,
    /**
     * 16-bit RGB. Only the R, G, and B components are encoded
     * from the higher-order to the lower-order bits: red is stored with 5 bits of precision,
     * green is stored with 6 bits of precision, and blue is stored with 5 bits of precision.
     */
    OHOS_PIXEL_MAP_FORMAT_RGB_565 = 2,
};

/**
 * @brief Defines pixel map information.
 *
 * @since 8
 * @version 1.0
 */
struct OhosPixelMapInfo {
    /** Image width, in pixels. */
    uint32_t width;
    /** Image height, in pixels. */
    uint32_t height;
    /** Number of bytes in each row of a pixel map */
    uint32_t rowSize;
    /** Pixel format */
    int32_t pixelFormat;
};

struct NativePixelMap;

typedef struct NativePixelMap NativePixelMap;

enum {
    OHOS_PIXEL_MAP_ALPHA_TYPE_UNKNOWN = 0,
    OHOS_PIXEL_MAP_ALPHA_TYPE_OPAQUE = 1,
    OHOS_PIXEL_MAP_ALPHA_TYPE_PREMUL = 2,
    OHOS_PIXEL_MAP_ALPHA_TYPE_UNPREMUL = 3
};

enum {
    OHOS_PIXEL_MAP_SCALE_MODE_FIT_TARGET_SIZE = 0,
    OHOS_PIXEL_MAP_SCALE_MODE_CENTER_CROP = 1,
};

enum {
    OHOS_PIXEL_MAP_READ_ONLY = 0,
    OHOS_PIXEL_MAP_EDITABLE = 1,
};

struct OhosPixelMapCreateOps {
    uint32_t width;
    uint32_t height;
    int32_t pixelFormat;
    uint32_t editable;
    uint32_t alphaType;
    uint32_t scaleMode;
};

/**
 * @brief Obtains information about a given <b>PixelMap</b> and stores the information in a {@link OhosPixelMapInfo}
 * structure.
 *
 * @param env Indicates the pointer to the JNI environment.
 * @param pixelMapObject Indicates the Java <b>PixelMap</b> object.
 * @param info Indicates the pointer to the pixel map information to obtain. For details, see {@link
 * OhosPixelMapInfo}.
 * @return Returns <b>0</b> if the information is obtained and stored in the structure; returns result codes if the
 * operation fails.
 * @see OhosPixelMapInfo
 * @since 8
 * @version 1.0
 */
int32_t OH_GetImageInfo(napi_env env, napi_value value, OhosPixelMapInfo *info);

/**
 * @brief Obtains the memory address of a given <b>PixelMap</b> object and locks the memory.
 *
 * If this function call is successful, <b>*addrPtr</b> is set to the memory address. After accessing the pixel data,
 * you must use {@link UnAccessPixels} to unlock the memory. Otherwise, resources cannot be released.
 * After the memory is unlocked, it can be invalid and should not be accessed.
 *
 * @param env Indicates the pointer to the JNI environment.
 * @param pixelMapObject Indicates the Java <b>PixelMap</b> object.
 * @param addrPtr Indicates the double pointer to the memory address.
 * @see UnAccessPixels
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful; returns other result codes if
 * the operation fails.
 * @since 8
 * @version 1.0
 */
int32_t OH_AccessPixels(napi_env env, napi_value value, void** addrPtr);

/**
 * @brief Unlocks the memory storing the pixel data of a given <b>PixelMap</b> to balance a successful call to {@link
 * AccessPixels}.
 *
 * @param env Indicates the pointer to the JNI environment.
 * @param pixelMapObject Indicates the Java <b>PixelMap</b> object.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful; returns other result codes if
 * the operation fails.
 * @see AccessPixels
 * @since 8
 * @version 1.0
 */
int32_t OH_UnAccessPixels(napi_env env, napi_value value);


int32_t OH_PixelMap_CreatePixelMap(napi_env env, OhosPixelMapCreateOps info,
    void* buf, size_t len, napi_value* res);
int32_t OH_PixelMap_CreateAlphaPixelMap(napi_env env, napi_value source, napi_value* alpha);
NativePixelMap* OH_PixelMap_InitNativePixelMap(napi_env env, napi_value source);
int32_t OH_PixelMap_GetBytesNumberPerRow(const NativePixelMap* native, int32_t* num);
int32_t OH_PixelMap_GetIsEditable(const NativePixelMap* native, int32_t* editable);
int32_t OH_PixelMap_IsSupportAlpha(const NativePixelMap* native, int32_t* alpha);
int32_t OH_PixelMap_SetAlphaAble(const NativePixelMap* native, int32_t alpha);
int32_t OH_PixelMap_GetDensity(const NativePixelMap* native, int32_t* density);
int32_t OH_PixelMap_SetDensity(const NativePixelMap* native, int32_t density);
int32_t OH_PixelMap_SetOpacity(const NativePixelMap* native, float opacity);
int32_t OH_PixelMap_Scale(const NativePixelMap* native, float x, float y);
int32_t OH_PixelMap_Translate(const NativePixelMap* native, float x, float y);
int32_t OH_PixelMap_Rotate(const NativePixelMap* native, float angle);
int32_t OH_PixelMap_Flip(const NativePixelMap* native, int32_t x, int32_t y);
int32_t OH_PixelMap_Crop(const NativePixelMap* native, int32_t x, int32_t y, int32_t width, int32_t height);

int32_t OH_PixelMap_GetImageInfo(const NativePixelMap* native, OhosPixelMapInfo *info);
int32_t OH_PixelMap_AccessPixels(const NativePixelMap* native, void** addr);
int32_t OH_PixelMap_UnAccessPixels(const NativePixelMap* native);

#ifdef __cplusplus
};
#endif
/** @} */
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_PIXEL_MAP_NAPI_H_
