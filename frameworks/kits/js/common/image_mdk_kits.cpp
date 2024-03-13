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

#include "image_mdk_kits.h"
#include "media_errors.h"

#include <map>

namespace {
    constexpr uint32_t NUM_0 = 0;
}

namespace OHOS {
namespace Media {
using ImageNapiEnvFunc = int32_t (*)(napi_env env, struct ImageNapiArgs* args);
using ImageNapiCtxFunc = int32_t (*)(ImageNapi* native, struct ImageNapiArgs* args);
#ifdef __cplusplus
extern "C" {
#endif

static NativeImage* GetNativeImage(ImageNapi* napi)
{
    if (napi == nullptr) {
        return nullptr;
    }
    return napi->GetNative();
}

static NativeImage* CheckAndGetImage(ImageNapi* native, const struct ImageNapiArgs* args)
{
    if (args == nullptr) {
        return nullptr;
    }
    return GetNativeImage(native);
}

static int32_t ImageNapiClipRect(ImageNapi* native, struct ImageNapiArgs* args)
{
    auto nativeImage = CheckAndGetImage(native, args);
    if (nativeImage == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }

    if (nativeImage->GetSize(args->outRect->width, args->outRect->height) != NUM_0) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }

    args->outRect->x = NUM_0;
    args->outRect->y = NUM_0;
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageNapiSize(ImageNapi* native, struct ImageNapiArgs* args)
{
    auto nativeImage = CheckAndGetImage(native, args);
    if (nativeImage == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }

    if (nativeImage->GetSize(args->outSize->width, args->outSize->height) != NUM_0) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageNapiFormat(ImageNapi* native, struct ImageNapiArgs* args)
{
    auto nativeImage = CheckAndGetImage(native, args);
    if (nativeImage == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    int32_t format;
    if (nativeImage->GetFormat(format) != NUM_0) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    *(args->outNum0) = format;
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageNapiGetComponent(ImageNapi* native, struct ImageNapiArgs* args)
{
    auto nativeImage = CheckAndGetImage(native, args);
    if (nativeImage == nullptr || args->outComponent == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }

    auto nativeComponent = nativeImage->GetComponent(args->inNum0);
    if (nativeComponent == nullptr || nativeComponent->size == NUM_0) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }

    if (nativeComponent->virAddr != nullptr) {
        args->outComponent->byteBuffer = nativeComponent->virAddr;
    } else {
        args->outComponent->byteBuffer = nativeComponent->raw.data();
    }

    if (args->outComponent->byteBuffer == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    args->outComponent->size = nativeComponent->size;
    args->outComponent->componentType = args->inNum0;
    args->outComponent->pixelStride = nativeComponent->pixelStride;
    args->outComponent->rowStride = nativeComponent->rowStride;
    return IMAGE_RESULT_SUCCESS;
}

static const std::map<int32_t, ImageNapiCtxFunc> g_CtxFunctions = {
    {CTX_FUNC_IMAGE_CLIP_RECT, ImageNapiClipRect},
    {CTX_FUNC_IMAGE_SIZE, ImageNapiSize},
    {CTX_FUNC_IMAGE_FORMAT, ImageNapiFormat},
    {CTX_FUNC_IMAGE_GET_COMPONENT, ImageNapiGetComponent},
};

MIDK_EXPORT
int32_t ImageNapiNativeCtxCall(int32_t mode, ImageNapi* native, struct ImageNapiArgs* args)
{
    auto funcSearch = g_CtxFunctions.find(mode);
    if (funcSearch == g_CtxFunctions.end()) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return funcSearch->second(native, args);
}

MIDK_EXPORT
ImageNapi* ImageNapi_Unwrap(napi_env env, napi_value value)
{
    napi_valuetype valueType;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_object) {
        return nullptr;
    }
    std::unique_ptr<ImageNapi> imageNapi = nullptr;
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&imageNapi));
    if ((status == napi_ok) && imageNapi != nullptr) {
        return imageNapi.release();
    }
    return nullptr;
}
#ifdef __cplusplus
};
#endif
}  // namespace Media
}  // namespace OHOS
