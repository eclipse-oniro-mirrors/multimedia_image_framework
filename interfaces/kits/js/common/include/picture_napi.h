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

#ifndef INTERFACES_KITS_JS_COMMON_INCLUDE_PICTURE_NAPI_H
#define INTERFACES_KITS_JS_COMMON_INCLUDE_PICTURE_NAPI_H

#include "picture.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "pixel_map.h"

namespace OHOS {
namespace Media {
class PictureNapi {
public:
    PictureNapi();
    ~PictureNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static std::shared_ptr<Picture> GetPicture(napi_env env, napi_value picture);
    static napi_value CreatePicture(napi_env env, std::shared_ptr<Picture> picture);
    static int32_t CreatePictureNapi(napi_env env, napi_value* result);
    void SetNativePicture(std::shared_ptr<Picture> picture);
    
private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);
    // methods
    static napi_value GetMainPixelmap(napi_env env, napi_callback_info info);
    static napi_value GetHdrComposedPixelMap(napi_env env, napi_callback_info info);
    static napi_value GetGainmapPixelmap(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);
    static napi_value Marshalling(napi_env env, napi_callback_info info);
    static napi_value GetAuxiliaryPicture(napi_env env, napi_callback_info info);
    static napi_value SetAuxiliaryPicture(napi_env env, napi_callback_info info);
    static napi_value GetMetadata(napi_env env, napi_callback_info info);
    static napi_value SetMetadata(napi_env env, napi_callback_info info);

    /* static method */
    static napi_value CreatePicture(napi_env env, napi_callback_info info);
    static napi_value CreatePictureFromParcel(napi_env env, napi_callback_info info);
    static napi_value ThrowExceptionError(napi_env env,
        const std::string &tag, const std::uint32_t &code, const std::string &info);
    void release();
    static thread_local napi_ref sConstructor_;
    static thread_local std::shared_ptr<Picture> sPicture_;
    napi_env env_ = nullptr;
    std::shared_ptr<Picture> nativePicture_;
    bool isRelease = false;
    uint32_t uniqueId_ = 0;
    static napi_ref auxiliaryPictureTypeRef_;
    static napi_ref metadataTypeRef_;
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_JS_COMMON_INCLUDE_PICTURE_NAPI_H
