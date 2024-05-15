/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_SENDABLE_NAPI_H
#define INTERFACES_KITS_JS_COMMON_INCLUDE_IMAGE_SOURCE_SENDABLE_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "image_type.h"
#include "image_log.h"
#include "image_source.h"
#include "pixel_map.h"
#include "sendable_pixel_map_napi.h"
#include "media_errors.h"
#include "image_napi_utils.h"
#include "image_dfx.h"

namespace OHOS {
namespace Media {
class SendableImageSourceNapi {
public:
    SendableImageSourceNapi();
    ~SendableImageSourceNapi();
    std::shared_ptr<ImageSource> nativeImgSrc = nullptr;
    static std::string filePath_;
    static int fileDescriptor_;
    static void* fileBuffer_;
    static size_t fileBufferSize_;

    std::shared_ptr<IncrementalPixelMap> GetIncrementalPixelMap()
    {
        return navIncPixelMap_;
    }
    static napi_value Init(napi_env env, napi_value exports);
private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);

    static napi_value CreateImageSource(napi_env env, napi_callback_info info);
    static napi_value CreatePixelMap(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);

    void release();
    static thread_local napi_ref sConstructor_;
    static thread_local std::shared_ptr<ImageSource> sImgSrc_;
    static std::shared_ptr<IncrementalPixelMap> sIncPixelMap_;
    std::shared_ptr<IncrementalPixelMap> navIncPixelMap_ = nullptr;
    static napi_ref pixelMapFormatRef_;
    static napi_ref propertyKeyRef_;
    static napi_ref imageFormatRef_;
    static napi_ref alphaTypeRef_;
    static napi_ref scaleModeRef_;
    static napi_ref componentTypeRef_;
    static napi_ref decodingDynamicRangeRef_;
    static napi_ref decodingResolutionQualityRef_;

    napi_env env_ = nullptr;
    bool isRelease = false;
};
}
}

#endif