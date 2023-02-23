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
 * @brief Provides functions to access the native buffer of image, receiving ready buffer from native.
 *
 * @Syscap SystemCapability.Multimedia.Image
 * @since 10
 * @version 2.0
 */

/**
 * @file image_receiver_mdk.h
 *
 * @brief Declares functions for you to access native image buffer in native layer.
 *
 * @since 10
 * @version 2.0
 */

#ifndef INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_RECEIVER_MDK_H_
#define INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_RECEIVER_MDK_H_
#include <cstdint>
#include "napi/native_api.h"
#include "image_mdk_common.h"
#include "image_mdk.h"

namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

struct ImageReceiverNative_;
/**
 * @brief Defines native image receiver object for native receiving functions.
 *
 * @since 10
 * @version 2.0
 */
typedef struct ImageReceiverNative_ ImageReceiverNative;

/**
 * @brief Defines a type of callback on native image ready.
 *
 * @since 10
 * @version 2.0
 */
typedef void (*OH_Image_Receiver_On_Callback)();

/**
 * @brief Defines image receiver create infomations.
 *
 * @since 10
 * @version 2.0
 */
struct OhosImageReceiverInfo {
    /** Default image width size on receive. */
    int32_t width;
    /** Default image height size on receive. */
    int32_t height;
    /** Create image format throught receiver. */
    int32_t format;
    /** Max capicity of images cache. */
    int32_t capicity;
};

/**
 * @brief Obtains JavaScript Native API <b>ImageReceiver</b> object by a given infomations {@link
 * OhosImageReceiverInfo} structure.
 *
 * @param env Indicates the pointer to the JNI environment.
 * @param info Indicates infomations of creating a image receiver. For details,
 * see {@link OhosImageReceiverInfo}.
 * @param res Indicates the pointer to JavaScript Native API <b>ImageReceiver</b> object.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see OhosImageReceiverInfo
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Receiver_CreateImageReceiver(napi_env env, struct OhosImageReceiverInfo info, napi_value* res);

/**
 * @brief Unwrap native {@link ImageReceiverNative} value from input JavaScript Native API
 * <b>ImageReceiver</b> object.
 *
 * @param env Indicates the pointer to the JNI environment.
 * @param source Indicates JavaScript Native API <b>ImageReceiver</b> object.
 * @return Returns {@link ImageReceiverNative} pointer if the operation is successful;
 * returns nullptr result if the operation fails.
 * @see ImageReceiverNative, OH_Image_Receiver_Release
 * @since 10
 * @version 2.0
 */
ImageReceiverNative* OH_Image_Receiver_InitImageReceiverNative(napi_env env, napi_value source);

/**
 * @brief Get receiver id from native {@link ImageReceiverNative} value.
 *
 * @param native Indicates the pointer to native {@link ImageReceiverNative} value.
 * @param id Indicates the pointer to a char buffer for taking the string id.
 * @param len Indicates the <b>id</b> char buffer size.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageReceiverNative
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Receiver_GetReceivingSurfaceId(const ImageReceiverNative* native, char* id, size_t len);

/**
 * @brief Read the latest image from native {@link ImageReceiverNative} value at least one image ready.
 *
 * @param native Indicates the pointer to native {@link ImageReceiverNative} value.
 * @param image Indicates the pointer to JavaScript Native API <b>Image</b> object by reading.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageReceiverNative
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Receiver_ReadLatestImage(const ImageReceiverNative* native, napi_value* image);

/**
 * @brief Read the next image from native {@link ImageReceiverNative} value at least one image ready.
 *
 * @param native Indicates the pointer to native {@link ImageReceiverNative} value.
 * @param image Indicates the pointer to JavaScript Native API <b>Image</b> object by reading.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageReceiverNative
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Receiver_ReadNextImage(const ImageReceiverNative* native, napi_value* image);

/**
 * @brief Register an {@link OH_Image_Receiver_On_Callback} event callback. The callback function will be
 * called when image ready everytime.
 *
 * @param native Indicates the pointer to native {@link ImageReceiverNative} value.
 * @param callback Indicates the callback function to {@link OH_Image_Receiver_On_Callback} event.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageReceiverNative
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Receiver_On(const ImageReceiverNative* native, OH_Image_Receiver_On_Callback callback);

/**
 * @brief Get recevier size from native {@link ImageReceiverNative} value.
 *
 * @param native Indicates the pointer to native {@link ImageReceiverNative} value.
 * @param size Indicates the pointer to {@link OhosImageSize} value as result.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageReceiverNative, OH_Image_Receiver_On_Callback
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Receiver_GetSize(const ImageReceiverNative* native, struct OhosImageSize* size);

/**
 * @brief Get recevier capacity from native {@link ImageReceiverNative} value.
 *
 * @param native Indicates the pointer to native {@link ImageReceiverNative} value.
 * @param capacity Indicates the pointer to capacity value as result.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageReceiverNative, OhosImageSize
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Receiver_GetCapacity(const ImageReceiverNative* native, int32_t* capacity);

/**
 * @brief Get recevier format from native {@link ImageReceiverNative} value.
 *
 * @param native Indicates the pointer to native {@link ImageReceiverNative} value.
 * @param format Indicates the pointer to format value as result.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageReceiverNative
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Receiver_GetFormat(const ImageReceiverNative* native, int32_t* format);

/**
 * @brief Release native {@link ImageReceiverNative} object.
 * Note: This function could not release JavaScript Native API <b>ImageReceiver</b> object but the
 * native {@link ImageReceiverNative} object unwrap by <b>OH_Image_Receiver_InitImageReceiverNative</b>.
 *
 * @param native Indicates the pointer to native {@link ImageReceiverNative} value.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see ImageReceiverNative
 * @since 10
 * @version 2.0
 */
int32_t OH_Image_Receiver_Release(ImageReceiverNative* native);
#ifdef __cplusplus
};
#endif
/** @} */
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_RECEIVER_MDK_H_
