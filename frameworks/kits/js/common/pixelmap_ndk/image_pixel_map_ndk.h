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

#ifndef FRAMEWORKS_KITS_JS_COMMON_PIXELMAP_NDK_IMAGE_PIXEL_MAP_NDK_H_
#define FRAMEWORKS_KITS_JS_COMMON_PIXELMAP_NDK_IMAGE_PIXEL_MAP_NDK_H_

#include "common_utils.h"
#include "pixel_map.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif
NDK_EXPORT PixelMapNapi* PixelMapNapi_Unwrap(napi_env env, napi_value value);
NDK_EXPORT napi_value PixelMapNapi_Create(napi_env env, InitializationOptions info, uint32_t* buf, size_t len);
NDK_EXPORT napi_value PixelMapNapi_CreateAlpha(napi_env env, napi_value source);
NDK_EXPORT PixelMap* PixelMapNapi_Get(PixelMapNapi* napi);
NDK_EXPORT PixelFormat PixelMapNapi_ParsePixelForamt(int32_t val);
NDK_EXPORT AlphaType PixelMapNapi_ParseAlphaType(int32_t val);
NDK_EXPORT ScaleMode PixelMapNapi_ParseScaleMode(int32_t val);
#ifdef __cplusplus
};
#endif
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_KITS_JS_COMMON_PIXELMAP_NDK_IMAGE_PIXEL_MAP_NDK_H_
