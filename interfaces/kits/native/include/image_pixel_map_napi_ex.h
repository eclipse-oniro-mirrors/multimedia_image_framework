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

#ifndef INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_PIXEL_MAP_NAPI_EX_H_
#define INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_PIXEL_MAP_NAPI_EX_H_
#include <stdint.h>
#include "napi/native_api.h"
namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

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

struct CreateOps {
    uint32_t width;
    uint32_t height;
    int32_t pixelFormat;
    uint32_t editable;
    uint32_t alphaType;
    uint32_t scaleMode;
};

int32_t OH_PixelMap_CreatePixelMap(napi_env env, CreateOps info, void* buf, size_t len, napi_value* res);
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
#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_PIXEL_MAP_NAPI_EX_H_
