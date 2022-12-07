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

#include "image_pixel_map_napi.h"

#include "common_utils.h"
#include "image_pixel_map_napi_kits.h"

namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

struct NativePixelMap {
    PixelMapNapi* napi = nullptr;
};

namespace {
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
}
NDK_EXPORT
NativePixelMap* OH_PixelMap_InitNativePixelMap(napi_env env, napi_value source)
{
    napi_valuetype valueType;
    napi_typeof(env, source, &valueType);
    if (valueType != napi_object) {
        return nullptr;
    }
    PixelMapNapi* napi = PixelMapNapi_Unwrap(env, source);
    if (napi == nullptr) {
        return nullptr;
    }
    std::unique_ptr<NativePixelMap> result = std::make_unique<NativePixelMap>();
    result->napi = napi;
    return result.release();
}

NDK_EXPORT
int32_t OH_PixelMap_CreatePixelMap(napi_env env, PixelMapCreateOpions info,
    void* buf, size_t len, napi_value* res)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
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
    return entry->create(env, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_CreateAlphaPixelMap(napi_env env, napi_value source, napi_value* alpha)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inValue = source;
    args.outValue = alpha;
    return entry->createAlpha(env, &args);
}


NDK_EXPORT
int32_t OH_PixelMap_GetBytesNumberPerRow(const NativePixelMap* native, int32_t* num)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outNum = num;
    return entry->getRowBytes(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_GetIsEditable(const NativePixelMap* native, int32_t* editable)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outNum = editable;
    return entry->isEditable(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_IsSupportAlpha(const NativePixelMap* native, int32_t* alpha)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outNum = alpha;
    return entry->isSupportAlpha(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_SetAlphaAble(const NativePixelMap* native, int32_t alpha)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inNum0 = alpha;
    return entry->setAlphaAble(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_GetDensity(const NativePixelMap* native, int32_t* density)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outNum = density;
    return entry->getDensity(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_SetDensity(const NativePixelMap* native, int32_t density)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inNum0 = density;
    return entry->setDensity(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_SetOpacity(const NativePixelMap* native, float opacity)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inFloat0 = opacity;
    return entry->setOpacity(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_Scale(const NativePixelMap* native, float x, float y)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inFloat0 = x;
    args.inFloat1 = y;
    return entry->scale(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_Translate(const NativePixelMap* native, float x, float y)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inFloat0 = x;
    args.inFloat1 = y;
    return entry->translate(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_Rotate(const NativePixelMap* native, float angle)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inFloat0 = angle;
    return entry->rotate(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_Flip(const NativePixelMap* native, int32_t x, int32_t y)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inNum0 = x;
    args.inNum1 = y;
    return entry->flip(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_Crop(const NativePixelMap* native, int32_t x, int32_t y, int32_t width, int32_t height)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.inNum0 = x;
    args.inNum1 = y;
    args.inNum2 = width;
    args.inNum3 = height;
    return entry->crop(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_GetImageInfo(const NativePixelMap* native, OhosPixelMapInfo *info)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outInfo = info;
    return entry->getImageInfo(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_AccessPixels(const NativePixelMap* native, void** addr)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    args.outAddr = addr;
    return entry->accessPixels(native->napi, &args);
}

NDK_EXPORT
int32_t OH_PixelMap_UnAccessPixels(const NativePixelMap* native)
{
    auto entry = PixelMapNapiNativeEntry();
    if (entry == nullptr || native == nullptr || native->napi == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    PixelMapNapiArgs args;
    return entry->accessPixels(native->napi, &args);
}

#ifdef __cplusplus
};
#endif
}  // namespace Media
}  // namespace OHOS
