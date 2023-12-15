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

#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_RECEIVER_MDK_KITS_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_RECEIVER_MDK_KITS_H

#include "common_utils.h"
#include "native_image.h"
#include "image_receiver_napi.h"
#include "image_receiver_mdk.h"

namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

struct ImageReceiverArgs {
    char* id;
    size_t inLen;
    int32_t inNum0;
    int32_t inNum1;
    int32_t inNum2;
    int32_t inNum3;
    napi_env inEnv;
    OH_Image_Receiver_On_Callback callback;
    napi_value* outValue;
    int32_t* outNum0;
    struct OhosImageSize* outSize;
};

enum {
    ENV_FUNC_IMAGE_RECEIVER_CREATE,
    CTX_FUNC_IMAGE_RECEIVER_GET_RECEIVER_ID,
    CTX_FUNC_IMAGE_RECEIVER_READ_LATEST_IMAGE,
    CTX_FUNC_IMAGE_RECEIVER_READ_NEXT_IMAGE,
    CTX_FUNC_IMAGE_RECEIVER_ON,
    CTX_FUNC_IMAGE_RECEIVER_GET_SIZE,
    CTX_FUNC_IMAGE_RECEIVER_GET_CAPACITY,
    CTX_FUNC_IMAGE_RECEIVER_GET_FORMAT,
};

ImageReceiverNapi* ImageReceiver_Unwrap(napi_env env, napi_value value);
int32_t ImageReceiverNativeEnvCall(int32_t mode, napi_env env, struct ImageReceiverArgs* args);
int32_t ImageReceiverNativeCtxCall(int32_t mode, ImageReceiverNapi* native, struct ImageReceiverArgs* args);
#ifdef __cplusplus
};
#endif
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_RECEIVER_MDK_KITS_H
