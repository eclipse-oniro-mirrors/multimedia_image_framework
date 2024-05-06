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

#include "image_packer_mdk_kits.h"

#include <map>
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImagePackerMdk"

namespace {
    constexpr size_t SIZE_ZERO = 0;
    constexpr int INVALID_FD = -1;
}

namespace OHOS {
namespace Media {
using ImagePackerNativeFunc = int32_t (*)(struct ImagePackerArgs* args);

enum class PackingSourceType : int32_t {
    TYPE_INVALID = -1,
    TYPE_IMAGE_SOURCE,
    TYPE_PIXEL_MAP,
};

#ifdef __cplusplus
extern "C" {
#endif

static bool IsInstanceOf(napi_env env, napi_value value, napi_value global, const char* type)
{
    napi_value constructor = nullptr;
    if (napi_get_named_property(env, global, type, &constructor) != napi_ok) {
        IMAGE_LOGE("Get constructor property failed!");
        return false;
    }

    bool isInstance = false;
    if (napi_instanceof(env, value, constructor, &isInstance) == napi_ok && isInstance) {
        return true;
    }
    return false;
}

static PackingSourceType ParserPackingArgumentType(napi_env env, napi_value source)
{
    napi_value global = nullptr;
    if (napi_get_global(env, &global) != napi_ok) {
        IMAGE_LOGE("Get global property failed!");
        return PackingSourceType::TYPE_INVALID;
    }

    if (IsInstanceOf(env, source, global, "ImageSource")) {
        IMAGE_LOGD("This is ImageSource!");
        return PackingSourceType::TYPE_IMAGE_SOURCE;
    } else if (IsInstanceOf(env, source, global, "PixelMap")) {
        IMAGE_LOGD("This is PixelMap!");
        return PackingSourceType::TYPE_PIXEL_MAP;
    }

    IMAGE_LOGE("Invalid type!");
    return PackingSourceType::TYPE_INVALID;
}

static int32_t ImagePackerNapiCreate(struct ImagePackerArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr || args->outVal == nullptr) {
        IMAGE_LOGE("ImagePackerNapiCreate bad parameter");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    *(args->outVal) = ImagePackerNapi::CreateImagePacker(args->inEnv, nullptr);
    if (*(args->outVal) == nullptr) {
        IMAGE_LOGE("ImageSourceNapiCreate native create failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    IMAGE_LOGD("ImagePackerNapiCreate success");
    return IMAGE_RESULT_SUCCESS;
}

static std::shared_ptr<ImageSource> GetNativeImageSouce(napi_env env, napi_value source)
{
    std::unique_ptr<ImageSourceNapi> napi = nullptr;
    napi_status status = napi_unwrap(env, source, reinterpret_cast<void**>(&napi));
    if ((status == napi_ok) && napi != nullptr) {
        return napi.release()->nativeImgSrc;
    }
    return nullptr;
}

static int32_t DoStartPacking(std::shared_ptr<ImagePacker> &packer, struct ImagePackerArgs* args)
{
    if (args == nullptr || args->inOpts == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }

    PackOption option;
    option.format = args->inOpts->format;
    option.quality = args->inOpts->quality;
    option.desiredDynamicRange = EncodeDynamicRange::SDR;
    if (args->outData != nullptr && args->dataSize != nullptr && *(args->dataSize) != SIZE_ZERO) {
        return packer->StartPacking(args->outData, *(args->dataSize), option);
    } else if (args->inNum0 > INVALID_FD) {
        return packer->StartPacking(args->inNum0, option);
    }
    IMAGE_LOGE("DoNativePacking StartPacking failed");
    return IMAGE_RESULT_BAD_PARAMETER;
}

static int32_t DoAddImage(std::shared_ptr<ImagePacker> &packer,
    PackingSourceType type, struct ImagePackerArgs* args)
{
    if (args == nullptr || args->inOpts == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }

    if (type == PackingSourceType::TYPE_IMAGE_SOURCE) {
        auto image = GetNativeImageSouce(args->inEnv, args->inVal);
        if (image != nullptr) {
            return packer->AddImage(*image);
        } else {
            IMAGE_LOGE("DoNativePacking get image source native failed");
            return IMAGE_RESULT_BAD_PARAMETER;
        }
    } else if (type == PackingSourceType::TYPE_PIXEL_MAP) {
        auto pixel = PixelMapNapi::GetPixelMap(args->inEnv, args->inVal);
        if (pixel != nullptr) {
            return packer->AddImage(*pixel);
        } else {
            IMAGE_LOGE("DoNativePacking get pixelmap native failed");
            return IMAGE_RESULT_BAD_PARAMETER;
        }
    }
    IMAGE_LOGE("DoNativePacking unsupport packing source type %{public}d", type);
    return IMAGE_RESULT_BAD_PARAMETER;
}

static int32_t DoNativePacking(struct ImagePackerArgs* args)
{
    if (args == nullptr || args->inOpts == nullptr || args->inVal == nullptr) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }

    auto type = ParserPackingArgumentType(args->inEnv, args->inVal);
    if (type == PackingSourceType::TYPE_INVALID) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    auto nativeImagePacker = ImagePackerNapi::GetNative(args->inNapi);
    if (nativeImagePacker == nullptr) {
        IMAGE_LOGE("DoNativePacking get native failed");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    int32_t res = DoStartPacking(nativeImagePacker, args);
    if (res != IMAGE_RESULT_SUCCESS) {
        IMAGE_LOGE("DoNativePacking StartPacking failed");
        return res;
    }
    res = DoAddImage(nativeImagePacker, type, args);
    if (res != IMAGE_RESULT_SUCCESS) {
        IMAGE_LOGE("DoNativePacking AddImage failed");
        return res;
    }
    int64_t packedSize = SIZE_ZERO;
    res = nativeImagePacker->FinalizePacking(packedSize);
    if (args->dataSize != nullptr) {
        *args->dataSize = packedSize;
    }
    return res;
}
static int32_t ImagePackerNapiPackToData(struct ImagePackerArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr ||
        args->inNapi == nullptr || args->inVal == nullptr ||
        args->inOpts == nullptr || args->outData == nullptr ||
        args->dataSize == nullptr || *(args->dataSize) == SIZE_ZERO) {
        IMAGE_LOGE("ImagePackerNapiPackToData bad parameter");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return DoNativePacking(args);
}

static int32_t ImagePackerNapiPackToFile(struct ImagePackerArgs* args)
{
    if (args == nullptr || args->inEnv == nullptr ||
        args->inNapi == nullptr || args->inVal == nullptr ||
        args->inOpts == nullptr || args->inNum0 <= INVALID_FD) {
        IMAGE_LOGE("ImagePackerNapiPackToFile bad parameter");
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return DoNativePacking(args);
}

static const std::map<int32_t, ImagePackerNativeFunc> g_CtxFunctions = {
    {ENV_FUNC_IMAGEPACKER_CREATE, ImagePackerNapiCreate},
    {CTX_FUNC_IMAGEPACKER_PACKTODATA, ImagePackerNapiPackToData},
    {CTX_FUNC_IMAGEPACKER_PACKTOFILE, ImagePackerNapiPackToFile},
};

MIDK_EXPORT
int32_t ImagePackerNativeCall(int32_t mode, struct ImagePackerArgs* args)
{
    auto funcSearch = g_CtxFunctions.find(mode);
    if (funcSearch == g_CtxFunctions.end()) {
        return IMAGE_RESULT_BAD_PARAMETER;
    }
    return funcSearch->second(args);
}

MIDK_EXPORT
ImagePackerNapi* ImagePackerNapi_Unwrap(napi_env env, napi_value value)
{
    napi_valuetype valueType;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_object) {
        return nullptr;
    }
    std::unique_ptr<ImagePackerNapi> napi = nullptr;
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&napi));
    if ((status == napi_ok) && napi != nullptr) {
        return napi.release();
    }
    return nullptr;
}
#ifdef __cplusplus
};
#endif
}  // namespace Media
}  // namespace OHOS
