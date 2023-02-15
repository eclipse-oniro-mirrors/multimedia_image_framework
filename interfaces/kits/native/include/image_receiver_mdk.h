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
 * @addtogroup image_receiver
 * @{
 *
 * @brief Provides access to pixel data and pixel map information.
 *
 * @Syscap SystemCapability.Multimedia.Image
 * @since 8
 * @version 1.0
 */

/**
 * @file image_receiver_mdk.h
 *
 * @brief Declares functions for you to access image in native layer.
 *
 * @since 8
 * @version 1.0
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
typedef struct ImageReceiverNative_ ImageReceiverNative;
typedef void (*OH_Image_Receiver_On_Callback)();

struct OhosImageReceiverInfo {
    int32_t width;
    int32_t height;
    int32_t format;
    int32_t capicity;
};

int32_t OH_Image_Receiver_CreateImageReceiver(napi_env env, struct OhosImageReceiverInfo info, napi_value* res);
ImageReceiverNative* OH_Image_Receiver_InitImageReceiverNative(napi_env env, napi_value source);
int32_t OH_Image_Receiver_GetReceivingSurfaceId(const ImageReceiverNative* native, char* id);
int32_t OH_Image_Receiver_ReadLatestImage(const ImageReceiverNative* native, napi_value* image);
int32_t OH_Image_Receiver_ReadNextImage(const ImageReceiverNative* native, napi_value* image);
int32_t OH_Image_Receiver_On(const ImageReceiverNative* native, OH_Image_Receiver_On_Callback* callback);
int32_t OH_Image_Receiver_GetSize(const ImageReceiverNative* native, struct OhosImageSize* size);
int32_t OH_Image_Receiver_GetCapacity(const ImageReceiverNative* native, int32_t* capacity);
int32_t OH_Image_Receiver_GetFormat(const ImageReceiverNative* native, int32_t* format);
int32_t OH_Image_Receiver_Release(ImageReceiverNative* native);
#ifdef __cplusplus
};
#endif
/** @} */
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_RECEIVER_MDK_H_
