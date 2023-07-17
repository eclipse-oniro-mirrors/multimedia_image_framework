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

#include "image_mdk.h"

#include "common_utils.h"
#include "image_mdk_kits.h"

using namespace OHOS::Media;
#ifdef __cplusplus
extern "C" {
#endif
struct ImageNative_ {
    ImageNapi* napi = nullptr;
};

MIDK_EXPORT
ImageNative* OH_Image_InitImageNative(napi_env env, napi_value source)
{
    ImageNapi* napi = ImageNapi_Unwrap(env, source);
    if (napi == nullptr) {
        return nullptr;
    }
    std::unique_ptr<ImageNative> result = std::make_unique<ImageNative>();
    result->napi = napi;
    return result.release();
}

MIDK_EXPORT
int32_t OH_Image_ClipRect(const ImageNative* native, struct OhosImageRect* rect)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageNapiArgs args;
    args.outRect = rect;
    auto res = ImageNapiNativeCtxCall(CTX_FUNC_IMAGE_CLIP_RECT, native->napi, &args);
    return res;
}

MIDK_EXPORT
int32_t OH_Image_Size(const ImageNative* native, struct OhosImageSize* size)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    ImageNapiArgs args;
    args.outSize = size;
    auto res = ImageNapiNativeCtxCall(CTX_FUNC_IMAGE_SIZE, native->napi, &args);
    return res;
}

MIDK_EXPORT
int32_t OH_Image_Format(const ImageNative* native, int32_t* format)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    ImageNapiArgs args;
    args.outNum0 = format;
    auto res = ImageNapiNativeCtxCall(CTX_FUNC_IMAGE_FORMAT, native->napi, &args);
    return res;
}

MIDK_EXPORT
int32_t OH_Image_GetComponent(const ImageNative* native, int32_t componentType,
    struct OhosImageComponent* componentNative)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    ImageNapiArgs args;
    args.inNum0 = componentType;
    args.outComponent = componentNative;
    auto res = ImageNapiNativeCtxCall(CTX_FUNC_IMAGE_GET_COMPONENT, native->napi, &args);
    return res;
}

MIDK_EXPORT
int32_t OH_Image_Release(ImageNative* native)
{
    if (native != nullptr) {
        delete native;
    }
    return IMAGE_RESULT_SUCCESS;
}

#ifdef __cplusplus
};
#endif
