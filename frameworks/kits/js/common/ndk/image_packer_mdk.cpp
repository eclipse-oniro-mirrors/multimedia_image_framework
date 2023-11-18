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

#include "image_packer_mdk.h"

#include "common_utils.h"
#include "image_packer_mdk_kits.h"

using namespace OHOS::Media;
#ifdef __cplusplus
extern "C" {
#endif
struct ImagePacker_Native_ {
    ImagePackerNapi* napi = nullptr;
    napi_env env = nullptr;
};

MIDK_EXPORT
int32_t OH_ImagePacker_Create(napi_env env, napi_value *res)
{
    ImagePackerArgs args;
    args.inEnv = env;
    args.outVal = res;
    return ImagePackerNativeCall(ENV_FUNC_IMAGEPACKER_CREATE, &args);
}

MIDK_EXPORT
ImagePacker_Native* OH_ImagePacker_InitNative(napi_env env, napi_value packer)
{
    std::unique_ptr<ImagePacker_Native> result = std::make_unique<ImagePacker_Native>();
    result->napi = ImagePackerNapi_Unwrap(env, packer);
    if (result->napi == nullptr) {
        return nullptr;
    }
    result->env = env;
    return result.release();
}

MIDK_EXPORT
int32_t OH_ImagePacker_PackToData(ImagePacker_Native* native, napi_value source,
    ImagePacker_Opts* opts, uint8_t* outData, size_t* size)
{
    if (native == nullptr || native->napi == nullptr || native->env == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImagePackerArgs args;
    args.inEnv = native->env;
    args.inNapi = native->napi;
    args.inVal = source;
    args.inOpts = opts;
    args.outData = outData;
    args.dataSize = size;
    return ImagePackerNativeCall(CTX_FUNC_IMAGEPACKER_PACKTODATA, &args);
}

MIDK_EXPORT
int32_t OH_ImagePacker_PackToFile(ImagePacker_Native* native, napi_value source,
    ImagePacker_Opts* opts, int fd)
{
    if (native == nullptr || native->napi == nullptr || native->env == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    ImagePackerArgs args;
    args.inEnv = native->env;
    args.inNapi = native->napi;
    args.inVal = source;
    args.inOpts = opts;
    args.inNum0 = fd;
    return ImagePackerNativeCall(CTX_FUNC_IMAGEPACKER_PACKTOFILE, &args);
}

MIDK_EXPORT
int32_t OH_ImagePacker_Release(ImagePacker_Native* native)
{
    if (native != nullptr) {
        delete native;
    }
    return IMAGE_RESULT_SUCCESS;
}

#ifdef __cplusplus
};
#endif
