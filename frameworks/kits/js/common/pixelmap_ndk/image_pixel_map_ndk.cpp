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
#include "pngpriv.h"

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

static PixelMap* getPixelMapInNative(const NativePixelMap* native)
{
    if (native != nullptr && native->napi != nullptr) {
        return PixelMapNapi_Get(native->napi);
    }
    return nullptr;
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
int32_t OH_PixelMap_CreatePixelMap(napi_env env, CreateOps info, void* buf, size_t len, napi_value* res)
{
    InitializationOptions option;
    option.alphaType = PixelMapNapi_ParseAlphaType(info.alphaType);
    option.editable = info.editable != NUM_0;
    option.pixelFormat = PixelMapNapi_ParsePixelForamt(info.pixelFormat);
    option.scaleMode = PixelMapNapi_ParseScaleMode(info.scaleMode);
    option.size.height = info.height;
    option.size.width = info.width;

    *res = PixelMapNapi_Create(env, option, static_cast<uint32_t*>(buf), len);
    if (*res != nullptr) {
        return OHOS_IMAGE_RESULT_SUCCESS;
    }
    return OHOS_IMAGE_RESULT_BAD_PARAMETER;
}

NDK_EXPORT
int32_t OH_PixelMap_CreateAlphaPixelMap(napi_env env, napi_value source, napi_value* alpha)
{
    *alpha = PixelMapNapi_CreateAlpha(env, source);
    if (*alpha == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    return OHOS_IMAGE_RESULT_SUCCESS;
}


NDK_EXPORT
int32_t OH_PixelMap_GetBytesNumberPerRow(const NativePixelMap* native, int32_t* num)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    *num = pixelmap->GetRowBytes();
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_GetIsEditable(const NativePixelMap* native, int32_t* editable)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    *editable = pixelmap->IsEditable();
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_IsSupportAlpha(const NativePixelMap* native, int32_t* alpha)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    auto alphaType = pixelmap->GetAlphaType();
    *alpha = (alphaType != AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_SetAlphaAble(const NativePixelMap* native, int32_t alpha)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    auto alphaType = pixelmap->GetAlphaType();
    if ((alpha != NUM_0) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
        pixelmap->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    } else if ((alpha == NUM_0) && !(alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
        pixelmap->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
    } else {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_GetDensity(const NativePixelMap* native, int32_t* density)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    *density = pixelmap->GetBaseDensity();
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_SetDensity(const NativePixelMap* native, int32_t density)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    ImageInfo imageinfo;
    pixelmap->GetImageInfo(imageinfo);
    if (imageinfo.baseDensity != density) {
        imageinfo.baseDensity = density;
        if (pixelmap->SetImageInfo(imageinfo, true) != OHOS_IMAGE_RESULT_SUCCESS) {
            return OHOS_IMAGE_RESULT_BAD_PARAMETER;
        }
    }
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_SetOpacity(const NativePixelMap* native, float opacity)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    if (pixelmap->SetAlpha(opacity) != OHOS_IMAGE_RESULT_SUCCESS) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_Scale(const NativePixelMap* native, float x, float y)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    pixelmap->scale(x, y);
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_Translate(const NativePixelMap* native, float x, float y)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    pixelmap->translate(x, y);
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_Rotate(const NativePixelMap* native, float angle)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    pixelmap->rotate(angle);
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_Flip(const NativePixelMap* native, int32_t x, int32_t y)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    pixelmap->flip((x == NUM_1), (y == NUM_1));
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_Crop(const NativePixelMap* native, int32_t x, int32_t y, int32_t width, int32_t height)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    Rect region;
    region.left = x;
    region.top = y;
    region.width = width; 
    region.height = height;
    pixelmap->crop(region);
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_GetImageInfo(const NativePixelMap* native, OhosPixelMapInfo *info)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr || info == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageInfo srcInfo;
    pixelmap->GetImageInfo(srcInfo);
    info->width = srcInfo.size.width;
    info->height = srcInfo.size.height;
    info->rowSize = pixelmap->GetRowBytes();
    info->pixelFormat = static_cast<int32_t>(srcInfo.pixelFormat);
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_AccessPixels(const NativePixelMap* native, void** addr)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr || addr == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    native->napi->LockPixelMap();
    *addr = png_constcast(uint8_t*, pixelmap->GetPixels());
    return OHOS_IMAGE_RESULT_SUCCESS;
}

NDK_EXPORT
int32_t OH_PixelMap_UnAccessPixels(const NativePixelMap* native)
{
    auto pixelmap = getPixelMapInNative(native);
    if (pixelmap == nullptr) {
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    native->napi->UnlockPixelMap();
    return OHOS_IMAGE_RESULT_SUCCESS;
}

#ifdef __cplusplus
};
#endif
}  // namespace Media
}  // namespace OHOS
