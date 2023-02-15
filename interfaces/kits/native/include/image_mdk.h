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
 * @brief Provides access to pixel data and pixel map information.
 *
 * @Syscap SystemCapability.Multimedia.Image
 * @since 8
 * @version 1.0
 */

/**
 * @file image_mdk.h
 *
 * @brief Declares functions for you to access image in native layer.
 *
 * @since 8
 * @version 1.0
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
typedef struct ImageNative_ ImageNative;

struct OhosImageRect {
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
};

struct OhosImageComponent {
    uint8_t* byteBuffer;
    size_t size;
    int32_t componentType;
    int32_t rowStride;
    int32_t pixelStride;
};

ImageNative* OH_Image_InitImageNative(napi_env env, napi_value source);
int32_t OH_Image_ClipRect(const ImageNative* native, struct OhosImageRect* rect);
int32_t OH_Image_Size(const ImageNative* native, struct OhosImageSize* size);
int32_t OH_Image_Format(const ImageNative* native, int32_t* format);
int32_t OH_Image_GetComponent(const ImageNative* native,
    int32_t componentType, struct OhosImageComponent* componentNative);
int32_t OH_Image_Release(ImageNative* native);
#ifdef __cplusplus
};
#endif
/** @} */
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_MDK_H_
