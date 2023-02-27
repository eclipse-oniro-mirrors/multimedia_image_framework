/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
 * @brief Provides access image functions.
 *
 * @Syscap SystemCapability.Multimedia.Image
 * @since 10
 * @version 2.0
 */

/**
 * @file image_mdk.h
 *
 * @brief Declares function to access image clip rect, size, format and component data.
 *
 * @since 10
 * @version 2.0
 */

#ifndef INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_MDK_H_
#define INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_MDK_H_
#include <cstdint>
#include "napi/native_api.h"
#include "image_mdk_common.h"
namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

struct ImageNative_;

/**
 * @brief Defines native image object for image functions.
 *
 * @since 10
 * @version 2.0
 */
typedef struct ImageNative_ ImageNative;

/**
 * @brief Enumerates for image formats.
 *
 * @since 10
 * @version 2.0
 */
enum {
    /** YCBCR422 semi-planar format.*/
    OHOS_IMAGE_FORMAT_YCBCR_422_SP = 1000,
    /** JPEG encoding format.*/
    OHOS_IMAGE_FORMAT_JPEG = 2000
};

/**
 * @brief Enumerates for the component type of image.
 *
 * @since 10
 * @version 2.0
 */
enum {
    /** Luma info.*/
    OHOS_IMAGE_COMPONENT_FORMAT_YUV_Y = 1,
    /** Chrominance info.*/
    OHOS_IMAGE_COMPONENT_FORMAT_YUV_U = 2,
    /** Chroma info.*/
    OHOS_IMAGE_COMPONENT_FORMAT_YUV_V = 3,
    /** Jpeg type.*/
    OHOS_IMAGE_COMPONENT_FORMAT_JPEG = 4,
};

/**
 * @brief Defines image rect infomations.
 *
 * @since 10
 * @version 2.0
 */
struct OhosImageRect {
    /** Rect x coordinate */
    int32_t x;
    /** Rect y coordinate */
    int32_t y;
    /** Rect width size */
    int32_t width;
    /** Rect height size */
    int32_t height;
};

/**
 * @brief Defines image component infomations.
 *
 * @since 10
 * @version 2.0
 */
struct OhosImageComponent {
    /** Component pixel data address */
    uint8_t* byteBuffer;
    /** Component pixel data size in memory */
    size_t size;
    /** Component type of pixel data */
    int32_t componentType;
    /** Component row stride of pixel data */
    int32_t rowStride;
    /** Component pixel size of pixel data */
    int32_t pixelStride;
};

/**
 * @brief Unwrap native {@link ImageNative} object from input JavaScript Native API <b>Image</b> object.
 *
 * @param env Indicates the pointer to the JNI environment.
 * @param source Indicates the JavaScript Native API <b>Image</b> object.
 * @return Returns {@link ImageNative} pointer if the operation is successful; returns nullptr if the
 * operation fails.
 * @see ImageNative, OH_Image_Release
 * @since 10
 * @version 2.0
 */
ImageNative* OH_Image_InitImageNative(napi_env env, napi_value source);

/**
 * @brief Get {@link OhosImageRect} infomation of native {@link ImageNative} object.
 *
 * @param native Indicates the pointer to {@link ImageNative} native object.
 * @param rect Indicates the pointer of {@link OhosImageRect} object as result.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageNative, OhosImageRect
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_ClipRect(const ImageNative* native, struct OhosImageRect* rect);

/**
 * @brief Get {@link OhosImageSize} infomation of native {@link ImageNative} object.
 *
 * @param native Indicates the pointer to {@link ImageNative} native object.
 * @param size Indicates the pointer of {@link OhosImageSize} object as result.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageNative, OhosImageSize
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Size(const ImageNative* native, struct OhosImageSize* size);

/**
 * @brief Get image format of native {@link ImageNative} object.
 *
 * @param native Indicates the pointer to {@link ImageNative} native object.
 * @param format Indicates the pointer of format object as result.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageNative
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Format(const ImageNative* native, int32_t* format);

/**
 * @brief Get {@link OhosImageComponent} from native {@link ImageNative} object.
 *
 * @param native Indicates the pointer to {@link ImageNative} native object.
 * @param componentType Indicates the component type of component wanted.
 * @param componentNative Indicates the pointer of result {@link OhosImageComponent} object.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageNative, OhosImageComponent
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_GetComponent(const ImageNative* native,
    int32_t componentType, struct OhosImageComponent* componentNative);

/**
 * @brief Release {@link ImageNative} native object.
 * Note: This function could not release JavaScript Native API <b>Image</b> object but
 * the {@link ImageNative} native object unwrap by {@link OH_Image_InitImageNative}.
 *
 * @param native Indicates the pointer to {@link ImageNative} native object.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageNative, OH_Image_InitImageNative
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Release(ImageNative* native);
#ifdef __cplusplus
};
#endif
/** @} */
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_MDK_H_
