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

#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_NAPI_KITS_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_NAPI_KITS_H

#include "common_utils.h"
#include "native_image.h"
#include "image_napi.h"
#include "image_mdk.h"

namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

struct ImageNapiArgs {
    int32_t inNum0;
    struct OhosImageRect* outRect;
    struct OhosImageSize* outSize;
    int32_t* outNum0;
    napi_value* outVal;
    struct OhosImageComponent* outComponent;
};

enum {
    CTX_FUNC_IMAGE_CLIP_RECT,
    CTX_FUNC_IMAGE_SIZE,
    CTX_FUNC_IMAGE_FORMAT,
    CTX_FUNC_IMAGE_GET_COMPONENT
};

ImageNapi* ImageNapi_Unwrap(napi_env env, napi_value value);
int32_t ImageNapiNativeCtxCall(int32_t mode, ImageNapi* native, struct ImageNapiArgs* args);
#ifdef __cplusplus
};
#endif
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_NAPI_KITS_H
