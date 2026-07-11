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

#include "image_receiver_mdk.h"

#include "common_utils.h"
#include "image_receiver_mdk_kits.h"

using namespace OHOS::Media;
#ifdef __cplusplus
extern "C" {
#endif
struct ImageReceiverNative_ {
    ImageReceiverNapi* napi = nullptr;
    napi_env env = nullptr;
};

MIDK_EXPORT
ImageReceiverNative* OH_Image_Receiver_InitImageReceiverNative(napi_env env, napi_value source)
{
    ImageReceiverNapi* napi = ImageReceiver_Unwrap(env, source);
    if (napi == nullptr) {
        return nullptr;
    }
    std::unique_ptr<ImageReceiverNative> result = std::make_unique<ImageReceiverNative>();
    result->napi = napi;
    result->env = env;
    return result.release();
}

MIDK_EXPORT
int32_t OH_Image_Receiver_CreateImageReceiver(napi_env env,
    struct OhosImageReceiverInfo info, napi_value* res)
{
    ImageReceiverArgs args;
    args.inNum0 = info.width;
    args.inNum1 = info.height;
    args.inNum2 = info.format;
    args.inNum3 = info.capicity;
    args.outValue = res;
    return ImageReceiverNativeEnvCall(ENV_FUNC_IMAGE_RECEIVER_CREATE, env, &args);
}

MIDK_EXPORT
int32_t OH_Image_Receiver_GetReceivingSurfaceId(const ImageReceiverNative* native, char* id, size_t len)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageReceiverArgs args;
    args.id = id;
    args.inLen = len;
    return ImageReceiverNativeCtxCall(CTX_FUNC_IMAGE_RECEIVER_GET_RECEIVER_ID, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_Image_Receiver_ReadLatestImage(const ImageReceiverNative* native, napi_value* image)
{
    if (native == nullptr || native->napi == nullptr || native->env == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageReceiverArgs args;
    args.outValue = image;
    args.inEnv = native->env;
    return ImageReceiverNativeCtxCall(CTX_FUNC_IMAGE_RECEIVER_READ_LATEST_IMAGE, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_Image_Receiver_ReadNextImage(const ImageReceiverNative* native, napi_value* image)
{
    if (native == nullptr || native->napi == nullptr || native->env == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageReceiverArgs args;
    args.outValue = image;
    args.inEnv = native->env;
    return ImageReceiverNativeCtxCall(CTX_FUNC_IMAGE_RECEIVER_READ_NEXT_IMAGE, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_Image_Receiver_On(const ImageReceiverNative* native, OH_Image_Receiver_On_Callback callback)
{
    if (native == nullptr || native->napi == nullptr || callback == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageReceiverArgs args;
    args.callback = callback;
    return ImageReceiverNativeCtxCall(CTX_FUNC_IMAGE_RECEIVER_ON, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_Image_Receiver_GetSize(const ImageReceiverNative* native, struct OhosImageSize* size)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageReceiverArgs args;
    args.outSize = size;
    return ImageReceiverNativeCtxCall(CTX_FUNC_IMAGE_RECEIVER_GET_SIZE, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_Image_Receiver_GetCapacity(const ImageReceiverNative* native, int32_t* capacity)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageReceiverArgs args;
    args.outNum0 = capacity;
    return ImageReceiverNativeCtxCall(CTX_FUNC_IMAGE_RECEIVER_GET_CAPACITY, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_Image_Receiver_GetFormat(const ImageReceiverNative* native, int32_t* format)
{
    if (native == nullptr || native->napi == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImageReceiverArgs args;
    args.outNum0 = format;
    return ImageReceiverNativeCtxCall(CTX_FUNC_IMAGE_RECEIVER_GET_FORMAT, native->napi, &args);
}

MIDK_EXPORT
int32_t OH_Image_Receiver_Release(ImageReceiverNative* native)
{
    if (native != nullptr) {
        delete native;
    }
    return IMAGE_RESULT_SUCCESS;
}
#ifdef __cplusplus
};
#endif
