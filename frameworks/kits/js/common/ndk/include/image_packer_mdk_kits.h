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

#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_PACKER_MDK_KITS_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_PACKER_MDK_KITS_H

#include "common_utils.h"
#include "image_packer_napi.h"
#include "image_packer_mdk.h"

namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

struct ImagePackerArgs {
    napi_env inEnv;
    ImagePackerNapi* inNapi;
    int32_t inNum0 = -1;
    napi_value inVal;
    ImagePacker_Opts* inOpts;
    uint8_t* outData;
    size_t* dataSize;
    napi_value* outVal;
};

enum {
    ENV_FUNC_IMAGEPACKER_CREATE,
    CTX_FUNC_IMAGEPACKER_PACKTODATA,
    CTX_FUNC_IMAGEPACKER_PACKTOFILE,
};
ImagePackerNapi* ImagePackerNapi_Unwrap(napi_env env, napi_value value);
int32_t ImagePackerNativeCall(int32_t mode, struct ImagePackerArgs* args);
#ifdef __cplusplus
};
#endif
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_PACKER_MDK_KITS_H
