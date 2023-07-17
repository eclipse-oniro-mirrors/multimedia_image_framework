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

#include "image_receiver_mdk_kits.h"
#include "image_receiver_napi_listener.h"
#include "image_napi.h"

#include <map>

namespace OHOS {
namespace Media {
using ImageReceiverNapiEnvFunc = int32_t (*)(napi_env env, struct ImageReceiverArgs* args);
using ImageReceiverNapiCtxFunc = int32_t (*)(ImageReceiverNapi* native, struct ImageReceiverArgs* args);
#ifdef __cplusplus
extern "C" {
#endif
static ImageReceiver* GetNativeReceiver(ImageReceiverNapi* napi)
{
    if (napi == nullptr) {
        return nullptr;
    }
    return napi->GetNative();
}

static ImageReceiver* CheckAndGetReceiver(ImageReceiverNapi* native, const struct ImageReceiverArgs* args)
{
    if (args == nullptr) {
        return nullptr;
    }
    return GetNativeReceiver(native);
}

static int32_t ImageReceiverNapiCreate(napi_env env, struct ImageReceiverArgs* args)
{
    if (args == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }

    ImageReceiverCreateArgs createArgs;
    createArgs.width = args->inNum0;
    createArgs.height = args->inNum1;
    createArgs.format = args->inNum2;
    createArgs.capicity = args->inNum3;
    *(args->outValue) = ImageReceiverNapi::CreateImageReceiverJsObject(env, createArgs);
    if (*(args->outValue) == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageReceiverNapiGetReceiverId(ImageReceiverNapi* native, struct ImageReceiverArgs* args)
{
    auto receiver = CheckAndGetReceiver(native, args);
    if (receiver == nullptr || receiver->iraContext_ == nullptr || args->id == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    auto sId = receiver->iraContext_->GetReceiverKey();
    if (sId.empty() || sId.c_str() == nullptr || args->inLen < sId.size()) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    memcpy_s(args->id, args->inLen, sId.c_str(), sId.size());
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageReceiverNapiReadLatestImage(ImageReceiverNapi* native, struct ImageReceiverArgs* args)
{
    auto receiver = CheckAndGetReceiver(native, args);
    if (receiver == nullptr || args->inEnv == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    auto image = receiver->LastNativeImage();
    if (image == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    *(args->outValue) = ImageNapi::Create(args->inEnv, image);
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageReceiverNapiReadNextImage(ImageReceiverNapi* native, struct ImageReceiverArgs* args)
{
    auto receiver = CheckAndGetReceiver(native, args);
    if (receiver == nullptr || args->inEnv == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    auto image = receiver->NextNativeImage();
    if (image == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    *(args->outValue) = ImageNapi::Create(args->inEnv, image);
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageReceiverNapiOn(ImageReceiverNapi* native, struct ImageReceiverArgs* args)
{
    auto receiver = CheckAndGetReceiver(native, args);
    if (receiver == nullptr || args->callback == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    std::shared_ptr<ImageReceiverNapiListener> listener = std::make_shared<ImageReceiverNapiListener>();
    listener->callBack = args->callback;
    receiver->RegisterBufferAvaliableListener(listener);
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageReceiverNapiGetSize(ImageReceiverNapi* native, struct ImageReceiverArgs* args)
{
    auto receiver = CheckAndGetReceiver(native, args);
    if (receiver == nullptr || receiver->iraContext_ == nullptr || args->outSize == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    args->outSize->width = receiver->iraContext_->GetWidth();
    args->outSize->height = receiver->iraContext_->GetHeight();
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageReceiverNapiGetCapacity(ImageReceiverNapi* native, struct ImageReceiverArgs* args)
{
    auto receiver = CheckAndGetReceiver(native, args);
    if (receiver == nullptr || receiver->iraContext_ == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    *(args->outNum0) = receiver->iraContext_->GetCapicity();
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageReceiverNapiGetFormat(ImageReceiverNapi* native, struct ImageReceiverArgs* args)
{
    auto receiver = CheckAndGetReceiver(native, args);
    if (receiver == nullptr || receiver->iraContext_ == nullptr) {
        return IMAGE_RESULT_JNI_ENV_ABNORMAL;
    }
    *(args->outNum0) = receiver->iraContext_->GetFormat();
    return IMAGE_RESULT_SUCCESS;
}
static const std::map<int32_t, ImageReceiverNapiEnvFunc> g_EnvFunctions = {
    {ENV_FUNC_IMAGE_RECEIVER_CREATE, ImageReceiverNapiCreate},
};
static const std::map<int32_t, ImageReceiverNapiCtxFunc> g_CtxFunctions = {
    {CTX_FUNC_IMAGE_RECEIVER_GET_RECEIVER_ID, ImageReceiverNapiGetReceiverId},
    {CTX_FUNC_IMAGE_RECEIVER_READ_LATEST_IMAGE, ImageReceiverNapiReadLatestImage},
    {CTX_FUNC_IMAGE_RECEIVER_READ_NEXT_IMAGE, ImageReceiverNapiReadNextImage},
    {CTX_FUNC_IMAGE_RECEIVER_ON, ImageReceiverNapiOn},
    {CTX_FUNC_IMAGE_RECEIVER_GET_SIZE, ImageReceiverNapiGetSize},
    {CTX_FUNC_IMAGE_RECEIVER_GET_CAPACITY, ImageReceiverNapiGetCapacity},
    {CTX_FUNC_IMAGE_RECEIVER_GET_FORMAT, ImageReceiverNapiGetFormat},
};

MIDK_EXPORT
int32_t ImageReceiverNativeEnvCall(int32_t mode, napi_env env, struct ImageReceiverArgs* args)
{
    auto funcSearch = g_EnvFunctions.find(mode);
    if (funcSearch == g_EnvFunctions.end()) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return funcSearch->second(env, args);
}

MIDK_EXPORT
int32_t ImageReceiverNativeCtxCall(int32_t mode, ImageReceiverNapi* native, struct ImageReceiverArgs* args)
{
    auto funcSearch = g_CtxFunctions.find(mode);
    if (funcSearch == g_CtxFunctions.end()) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return funcSearch->second(native, args);
}

MIDK_EXPORT
ImageReceiverNapi* ImageReceiver_Unwrap(napi_env env, napi_value value)
{
    napi_valuetype valueType;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_object) {
        return nullptr;
    }
    std::unique_ptr<ImageReceiverNapi> receiverNapi = nullptr;
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&receiverNapi));
    if ((status == napi_ok) && receiverNapi != nullptr) {
        return receiverNapi.release();
    }
    return nullptr;
}
#ifdef __cplusplus
};
#endif
}  // namespace Media
}  // namespace OHOS
