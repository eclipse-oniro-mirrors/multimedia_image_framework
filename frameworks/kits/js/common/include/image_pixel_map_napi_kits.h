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

#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_PIXEL_MAP_NAPI_KITS_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_PIXEL_MAP_NAPI_KITS_H

#include "common_utils.h"
#include "pixel_map.h"
#include "pixel_map_napi.h"
#include "image_pixel_map_mdk.h"

namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif
struct PixelMapNapiArgs {
    OhosPixelMapCreateOps createOptions;
    void* inBuffer;
    size_t bufferLen;
    napi_value inValue;
    int32_t inNum0;
    int32_t inNum1;
    int32_t inNum2;
    int32_t inNum3;
    float inFloat0;
    float inFloat1;
    napi_value* outValue;
    int32_t* outNum;
    OhosPixelMapInfos *outInfo;
    void** outAddr;
};

using PixelMapNapiArgs = struct PixelMapNapiArgs;
enum {
    ENV_FUNC_CREATE,
    ENV_FUNC_CREATE_ALPHA,
    CTX_FUNC_GET_ROW_BYTES,
    CTX_FUNC_IS_EDITABLE,
    CTX_FUNC_IS_SUPPORT_ALPHA,
    CTX_FUNC_GET_DENSITY,
    CTX_FUNC_SET_ALPHAABLE,
    CTX_FUNC_SET_DENSITY,
    CTX_FUNC_SET_OPACITY,
    CTX_FUNC_SCALE,
    CTX_FUNC_TRANSLATE,
    CTX_FUNC_ROTATE,
    CTX_FUNC_FLIP,
    CTX_FUNC_CROP,
    CTX_FUNC_GET_IMAGE_INFO,
    CTX_FUNC_ACCESS_PIXELS,
    CTX_FUNC_UNACCESS_PIXELS,
};

PixelMapNapi* PixelMapNapi_Unwrap(napi_env env, napi_value value);
int32_t PixelMapNapiNativeEnvCall(int32_t mode, napi_env env, PixelMapNapiArgs* args);
int32_t PixelMapNapiNativeCtxCall(int32_t mode, PixelMapNapi* native, PixelMapNapiArgs* args);
#ifdef __cplusplus
};
#endif
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_PIXEL_MAP_NAPI_KITS_H
