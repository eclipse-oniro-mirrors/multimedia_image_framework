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
#include "pixel_map_napi.h"
namespace {
    constexpr uint32_t NUM_0 = 0;
}

namespace OHOS {
namespace Media {

#ifdef __cplusplus
extern "C" {
#endif

static bool makeUndefined(napi_env env, napi_value* value)
{
    if (env != nullptr) {
        napi_get_undefined(env, value);
        return true;
    } else {
        value = nullptr;
    }
    return false;
}

NDK_EXPORT
napi_value PixelMapNapi_Create(napi_env env, InitializationOptions info, uint32_t* buf, size_t len)
{
    napi_value undefinedValue = nullptr;
    if((!makeUndefined(env, &undefinedValue)) || buf == nullptr || len  <= NUM_0 ) {
        return undefinedValue;
    }

    auto pixelmap = PixelMap::Create(buf, len, info);
    if (pixelmap != nullptr) {
        return PixelMapNapi::CreatePixelMap(env, std::move(pixelmap));
    }
    return undefinedValue;
}

NDK_EXPORT
napi_value PixelMapNapi_CreateAlpha(napi_env env, napi_value source)
{
    napi_value undefinedValue = nullptr;
    if((!makeUndefined(env, &undefinedValue)) || source == nullptr ) {
        return undefinedValue;
    }
    auto napi = PixelMapNapi_Unwrap(env, source);
    auto orgPixelmap = PixelMapNapi_Get(napi);
    if (orgPixelmap == nullptr) {
        return undefinedValue;
    }

    InitializationOptions opts;
    opts.pixelFormat = PixelFormat::ALPHA_8;
    auto alphaPixelMap = PixelMap::Create(*orgPixelmap, opts);

    if (alphaPixelMap != nullptr) {
        return PixelMapNapi::CreatePixelMap(env, std::move(alphaPixelMap));
    }
    return undefinedValue;
}

NDK_EXPORT
PixelMapNapi* PixelMapNapi_Unwrap(napi_env env, napi_value value)
{
    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&pixelMapNapi));
    if ((status == napi_ok) && pixelMapNapi != nullptr) {
        return pixelMapNapi.release();
    }
    return nullptr;    
}

NDK_EXPORT
PixelMap* PixelMapNapi_Get(PixelMapNapi* napi)
{
    if (napi == nullptr) {
        return nullptr;
    }
    if (napi->GetPixelMap() == nullptr) {
        return nullptr;
    }
    return napi->GetPixelMap()->get();
}

NDK_EXPORT
PixelFormat PixelMapNapi_ParsePixelForamt(int32_t val)
{
    if (val <= static_cast<int32_t>(PixelFormat::CMYK)) {
        return PixelFormat(val);
    }

    return PixelFormat::UNKNOWN;
}

NDK_EXPORT
AlphaType PixelMapNapi_ParseAlphaType(int32_t val)
{
    if (val <= static_cast<int32_t>(AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL)) {
        return AlphaType(val);
    }

    return AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
}

NDK_EXPORT
ScaleMode PixelMapNapi_ParseScaleMode(int32_t val)
{
    if (val <= static_cast<int32_t>(ScaleMode::CENTER_CROP)) {
        return ScaleMode(val);
    }

    return ScaleMode::FIT_TARGET_SIZE;
}
#ifdef __cplusplus
};
#endif
}  // namespace Media
}  // namespace OHOS
