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

#include "image_pixel_map_mdk.h"
#include "image_pixel_map_napi_kits.h"
#include "native_pixel_map.h"
#include "common_utils.h"

using namespace OHOS::Media;
#ifdef __cplusplus
extern "C" {
#endif

struct NativePixelMap_ {
    OHOS::Media::PixelMapNapi* napi = nullptr;
};

MIDK_EXPORT
NativePixelMap* OH_PixelMap_InitNativePixelMap(napi_env env, napi_value source)
{
    PixelMapNapi* napi = PixelMapNapi_Unwrap(env, source);
    if (napi == nullptr) {
        return nullptr;
    }
    std::unique_ptr<NativePixelMap> result = std::make_unique<NativePixelMap>();
    result->napi = napi;
    return result.release();
}

MIDK_EXPORT
int32_t OH_PixelMap_CreatePixelMap(napi_env env, OhosPixelMapCreateOps info,
    void* buf, size_t len, napi_value* res)
{
    PixelMapNapiArgs args;
    args.createOptions.width = info.width;
    args.createOptions.height = info.height;
    args.createOptions.pixelFormat = info.pixelFormat;
    args.createOptions.editable = info.editable;
    args.createOptions.alphaType = info.alphaType;
    args.createOptions.scaleMode = info.scaleMode;
    args.inBuffer = buf;
    args.bufferLen = len;
    args.outValue = res;
    return PixelMapNapiNativeEnvCall(ENV_FUNC_CREATE, env, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_CreateAlphaPixelMap(napi_env env, napi_value source, napi_value* alpha)
{
    PixelMapNapiArgs args;
    args.inValue = source;
    args.outValue = alpha;
    return PixelMapNapiNativeEnvCall(ENV_FUNC_CREATE_ALPHA, env, &args);
}


MIDK_EXPORT
int32_t OH_PixelMap_GetBytesNumberPerRow(const NativePixelMap* native, int32_t* num)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outNum = num;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_GET_ROW_BYTES, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_GetIsEditable(const NativePixelMap* native, int32_t* editable)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outNum = editable;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_IS_EDITABLE, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_IsSupportAlpha(const NativePixelMap* native, int32_t* alpha)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outNum = alpha;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_IS_SUPPORT_ALPHA, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_SetAlphaAble(const NativePixelMap* native, int32_t alpha)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inNum0 = alpha;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_SET_ALPHAABLE, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_GetDensity(const NativePixelMap* native, int32_t* density)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outNum = density;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_GET_DENSITY, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_SetDensity(const NativePixelMap* native, int32_t density)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inNum0 = density;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_SET_DENSITY, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_SetOpacity(const NativePixelMap* native, float opacity)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inFloat0 = opacity;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_SET_OPACITY, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_Scale(const NativePixelMap* native, float x, float y)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inFloat0 = x;
    args.inFloat1 = y;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_SCALE, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_Translate(const NativePixelMap* native, float x, float y)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inFloat0 = x;
    args.inFloat1 = y;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_TRANSLATE, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_Rotate(const NativePixelMap* native, float angle)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inFloat0 = angle;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_ROTATE, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_Flip(const NativePixelMap* native, int32_t x, int32_t y)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inNum0 = x;
    args.inNum1 = y;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_FLIP, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_Crop(const NativePixelMap* native, int32_t x, int32_t y, int32_t width, int32_t height)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inNum0 = x;
    args.inNum1 = y;
    args.inNum2 = width;
    args.inNum3 = height;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_CROP, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_GetImageInfo(const NativePixelMap* native, OhosPixelMapInfos *info)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outInfo = info;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_GET_IMAGE_INFO, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_AccessPixels(const NativePixelMap* native, void** addr)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outAddr = addr;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_ACCESS_PIXELS, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_PixelMap_UnAccessPixels(const NativePixelMap* native)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    return PixelMapNapiNativeCtxCall(CTX_FUNC_UNACCESS_PIXELS, native->napi, &args);
}
#ifdef __cplusplus
};
#endif

namespace OHOS {
namespace Media {
PixelMapNapi *OH_PixelMapNative_GetPixelMapNapi(struct NativePixelMap_ *nativePixelMap)
{
    return nativePixelMap == nullptr ? nullptr : nativePixelMap->napi;
}
}
}