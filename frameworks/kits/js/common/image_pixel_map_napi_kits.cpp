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

#include "image_pixel_map_napi_kits.h"

#include <map>
#include <set>
#include "pixel_map_napi.h"

namespace {
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
}

namespace OHOS {
namespace Media {
using PixelMapNapiEnvFunc = int32_t (*)(napi_env env, PixelMapNapiArgs* args);
using PixelMapNapiCtxFunc = int32_t (*)(PixelMapNapi* native, PixelMapNapiArgs* args);
#ifdef __cplusplus
extern "C" {
#endif

static bool makeUndefined(napi_env env, napi_value* value)
{
    if (env != nullptr) {
        napi_get_undefined(env, value);
        return true;
    }
    return false;
}

static bool isUndefine(napi_env env, napi_value value)
{
    napi_valuetype res = napi_undefined;
    napi_typeof(env, value, &res);
    return (res == napi_undefined);
}

static std::shared_ptr<PixelMap> GetPixelMap(PixelMapNapi* napi, PixelMapNapiArgs* args,
    int32_t &error)
{
    if (napi == nullptr || napi->GetPixelNapiInner() == nullptr) {
        error = IMAGE_RESULT_DATA_ABNORMAL;
        return nullptr;
    }
    return napi->GetPixelNapiInner();
}

static PixelFormat ParsePixelForamt(int32_t val)
{
    if (val <= static_cast<int32_t>(PixelFormat::CMYK)) {
        return PixelFormat(val);
    }

    return PixelFormat::UNKNOWN;
}
static AlphaType ParseAlphaType(int32_t val)
{
    if (val <= static_cast<int32_t>(AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL)) {
        return AlphaType(val);
    }

    return AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
}

static ScaleMode ParseScaleMode(int32_t val)
{
    if (val <= static_cast<int32_t>(ScaleMode::CENTER_CROP)) {
        return ScaleMode(val);
    }

    return ScaleMode::FIT_TARGET_SIZE;
}

static int32_t PixelMapNapiCreate(napi_env env, PixelMapNapiArgs* args)
{
    if (args == nullptr || args->outValue == nullptr) {
        return IMAGE_RESULT_INVALID_PARAMETER;
    }
    napi_value undefinedValue = nullptr;
    if ((!makeUndefined(env, &undefinedValue)) || args->inBuffer == nullptr || args->bufferLen <= NUM_0) {
        *(args->outValue) = undefinedValue;
        return IMAGE_RESULT_GET_DATA_ABNORMAL;
    }

    *(args->outValue) = undefinedValue;
    InitializationOptions info;
    info.alphaType = ParseAlphaType(args->createOptions.alphaType);
    info.editable = args->createOptions.editable != NUM_0;
    info.pixelFormat = ParsePixelForamt(args->createOptions.pixelFormat);
    info.scaleMode = ParseScaleMode(args->createOptions.scaleMode);
    info.size.height = args->createOptions.height;
    info.size.width = args->createOptions.width;

    BUILD_PARAM pam;
    pam.offset_ = 0;
    pam.width_ = info.size.width;
    pam.flag_ = false;
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = PixelMap::Create(static_cast<uint32_t*>(args->inBuffer), args->bufferLen, pam, info, error);
    if (pixelmap == nullptr) {
        return error;
    }

    *(args->outValue) = PixelMapNapi::CreatePixelMap(env, std::move(pixelmap));
    return isUndefine(env, *(args->outValue))?IMAGE_RESULT_BAD_PARAMETER:IMAGE_RESULT_SUCCESS;
}

static int32_t PixelMapNapiCreateAlpha(napi_env env, PixelMapNapiArgs* args)
{
    if (args == nullptr || args->outValue == nullptr) {
        return IMAGE_RESULT_INVALID_PARAMETER;
    }
    napi_value undefinedValue = nullptr;
    if ((!makeUndefined(env, &undefinedValue)) || args->inValue == nullptr) {
        *(args->outValue) = undefinedValue;
        return IMAGE_RESULT_GET_DATA_ABNORMAL;
    }
    *(args->outValue) = undefinedValue;

    auto pixelmap = PixelMapNapi::GetPixelMap(env, args->inValue);
    if (pixelmap == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }

    InitializationOptions opts;
    opts.pixelFormat = PixelFormat::ALPHA_8;
    Rect rect;
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto alphaPixelMap = PixelMap::Create(*pixelmap, rect, opts, error);
    if (alphaPixelMap == nullptr) {
        return error;
    }

    *(args->outValue) = PixelMapNapi::CreatePixelMap(env, std::move(alphaPixelMap));
    return isUndefine(env, *(args->outValue))?IMAGE_RESULT_BAD_PARAMETER:IMAGE_RESULT_SUCCESS;
}

static std::shared_ptr<PixelMap> CheckAndGetPixelMap(PixelMapNapi* native, PixelMapNapiArgs* args,
    int32_t error)
{
    return args == nullptr ? nullptr : GetPixelMap(native, args, error);
}

static int32_t PixelMapNapiGetRowBytes(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }
    *(args->outNum) = pixelmap->GetRowBytes();
    return IMAGE_RESULT_SUCCESS;
}

static int32_t PixelMapNapiIsEditable(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    *(args->outNum) = pixelmap->IsEditable();
    return IMAGE_RESULT_SUCCESS;
}

static int32_t PixelMapNapiIsSupportAlpha(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    *(args->outNum) = pixelmap->GetAlphaType() != AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    return IMAGE_RESULT_SUCCESS;
}

static int32_t PixelMapNapiSetAlphaAble(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    auto alphaType = pixelmap->GetAlphaType();
    if ((args->inNum0 != NUM_0) && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
        pixelmap->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    } else if ((args->inNum0 == NUM_0) && !(alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
        pixelmap->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
    } else {
        return IMAGE_RESULT_BAD_PARAMETER;
    }

    return IMAGE_RESULT_SUCCESS;
}

static int32_t PixelMapNapiGetDensity(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    *(args->outNum) = pixelmap->GetBaseDensity();
    return IMAGE_RESULT_SUCCESS;
}

static int32_t PixelMapNapiSetDensity(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    ImageInfo imageinfo;
    pixelmap->GetImageInfo(imageinfo);
    if (imageinfo.baseDensity != args->inNum0) {
        imageinfo.baseDensity = args->inNum0;
        if (pixelmap->SetImageInfo(imageinfo, true) != IMAGE_RESULT_SUCCESS) {
            return IMAGE_RESULT_INDEX_INVALID;
        }
    }
    return IMAGE_RESULT_SUCCESS;
}

static int32_t PixelMapNapiSetOpacity(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    if (pixelmap->SetAlpha(args->inFloat0) != IMAGE_RESULT_SUCCESS) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return IMAGE_RESULT_SUCCESS;
}

static int32_t PixelMapNapiScale(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    pixelmap->scale(args->inFloat0, args->inFloat1);
    return pixelmap->errorCode == 0 ? IMAGE_RESULT_SUCCESS : pixelmap->errorCode;
}

static int32_t PixelMapNapiTranslate(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    pixelmap->translate(args->inFloat0, args->inFloat1);
    return pixelmap->errorCode == 0 ? IMAGE_RESULT_SUCCESS : pixelmap->errorCode;
}

static int32_t PixelMapNapiRotate(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    pixelmap->rotate(args->inFloat0);
    return pixelmap->errorCode == 0 ? IMAGE_RESULT_SUCCESS : pixelmap->errorCode;
}

static int32_t PixelMapNapiFlip(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    pixelmap->flip((args->inNum0 == NUM_1), (args->inNum1 == NUM_1));
    return pixelmap->errorCode == 0 ? IMAGE_RESULT_SUCCESS : pixelmap->errorCode;
}

static int32_t PixelMapNapiCrop(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }
    Rect region;
    region.left = args->inNum0;
    region.top = args->inNum1;
    region.width = args->inNum2;
    region.height = args->inNum3;
    pixelmap->crop(region);
    return pixelmap->errorCode == 0 ? IMAGE_RESULT_SUCCESS : pixelmap->errorCode;
}

static int32_t PixelMapNapiGetImageInfo(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr || args->outInfo == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }

    ImageInfo srcInfo;
    pixelmap->GetImageInfo(srcInfo);
    args->outInfo->width = srcInfo.size.width;
    args->outInfo->height = srcInfo.size.height;
    args->outInfo->rowSize = pixelmap->GetRowStride();
    args->outInfo->pixelFormat = static_cast<int32_t>(srcInfo.pixelFormat);
    return pixelmap->errorCode == 0 ? IMAGE_RESULT_SUCCESS : pixelmap->errorCode;
}

static int32_t PixelMapNapiAccessPixels(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    int32_t error = IMAGE_RESULT_SUCCESS;
    auto pixelmap = CheckAndGetPixelMap(native, args, error);
    if (pixelmap == nullptr) {
        return error != 0 ? error : IMAGE_RESULT_INVALID_PARAMETER;
    }
    native->LockPixelMap();
    *(args->outAddr) = static_cast<uint8_t*>(pixelmap->GetWritablePixels());
    return pixelmap->errorCode == 0 ? IMAGE_RESULT_SUCCESS : pixelmap->errorCode;
}

static int32_t PixelMapNapiUnAccessPixels(PixelMapNapi* native, PixelMapNapiArgs* args)
{
    if (native != nullptr) {
        native->UnlockPixelMap();
        return IMAGE_RESULT_SUCCESS;
    } else {
        return IMAGE_RESULT_INVALID_PARAMETER;
    }
}

static const std::map<int32_t, PixelMapNapiEnvFunc> g_EnvFunctions = {
    {ENV_FUNC_CREATE, PixelMapNapiCreate},
    {ENV_FUNC_CREATE_ALPHA, PixelMapNapiCreateAlpha},
};
static const std::map<int32_t, PixelMapNapiCtxFunc> g_CtxFunctions = {
    {CTX_FUNC_GET_ROW_BYTES, PixelMapNapiGetRowBytes},
    {CTX_FUNC_IS_EDITABLE, PixelMapNapiIsEditable},
    {CTX_FUNC_IS_SUPPORT_ALPHA, PixelMapNapiIsSupportAlpha},
    {CTX_FUNC_GET_DENSITY, PixelMapNapiGetDensity},
    {CTX_FUNC_SET_ALPHAABLE, PixelMapNapiSetAlphaAble},
    {CTX_FUNC_SET_DENSITY, PixelMapNapiSetDensity},
    {CTX_FUNC_SET_OPACITY, PixelMapNapiSetOpacity},
    {CTX_FUNC_SCALE, PixelMapNapiScale},
    {CTX_FUNC_TRANSLATE, PixelMapNapiTranslate},
    {CTX_FUNC_ROTATE, PixelMapNapiRotate},
    {CTX_FUNC_FLIP, PixelMapNapiFlip},
    {CTX_FUNC_CROP, PixelMapNapiCrop},
    {CTX_FUNC_GET_IMAGE_INFO, PixelMapNapiGetImageInfo},
    {CTX_FUNC_ACCESS_PIXELS, PixelMapNapiAccessPixels},
    {CTX_FUNC_UNACCESS_PIXELS, PixelMapNapiUnAccessPixels},
};

MIDK_EXPORT
int32_t PixelMapNapiNativeEnvCall(int32_t mode, napi_env env, PixelMapNapiArgs* args)
{
    auto funcSearch = g_EnvFunctions.find(mode);
    if (funcSearch == g_EnvFunctions.end()) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    return funcSearch->second(env, args);
}

MIDK_EXPORT
int32_t PixelMapNapiNativeCtxCall(int32_t mode, PixelMapNapi* native, PixelMapNapiArgs* args)
{
    auto funcSearch = g_CtxFunctions.find(mode);
    if (funcSearch == g_CtxFunctions.end()) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    return funcSearch->second(native, args);
}

MIDK_EXPORT
PixelMapNapi* PixelMapNapi_Unwrap(napi_env env, napi_value value)
{
    napi_valuetype valueType;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_object) {
        return nullptr;
    }
    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&pixelMapNapi));
    if ((status == napi_ok) && pixelMapNapi != nullptr) {
        return pixelMapNapi.release();
    }
    return nullptr;
}
#ifdef __cplusplus
};
#endif
}  // namespace Media
}  // namespace OHOS
