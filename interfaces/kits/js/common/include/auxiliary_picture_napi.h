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

#ifndef INTERFACES_KITS_JS_COMMON_INCLUDE_AUXILIARY_PICTURE_NAPI_H
#define INTERFACES_KITS_JS_COMMON_INCLUDE_AUXILIARY_PICTURE_NAPI_H

#include "auxiliary_picture.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "pixel_map.h"

namespace OHOS {
namespace Media {
class AuxiliaryPictureNapi {
public:
    AuxiliaryPictureNapi();
    ~AuxiliaryPictureNapi();
    static napi_value Init(napi_env env, napi_value exports);
    std::shared_ptr<AuxiliaryPicture> GetNativeAuxiliaryPic()
    {
        return nativeAuxiliaryPicture_;
    }

    static napi_ref GetConstructor()
    {
        return sConstructor_;
    }

    static napi_value CreateAuxiliaryPicture(napi_env env, std::shared_ptr<AuxiliaryPicture> auxiliaryPic);

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);
    static napi_value ReadPixelsToBuffer(napi_env env, napi_callback_info info);
    static napi_value WritePixelsFromBuffer(napi_env env, napi_callback_info info);
    static napi_value CreateAuxiliaryPicture(napi_env env, napi_callback_info info);
    static napi_value GetMetadata(napi_env env, napi_callback_info info);
    static napi_value SetMetadata(napi_env env, napi_callback_info info);
    static napi_value GetAuxiliaryPictureInfo(napi_env env, napi_callback_info info);
    static napi_value SetAuxiliaryPictureInfo(napi_env env, napi_callback_info info);
    static napi_value GetType(napi_env env, napi_callback_info info);
    static napi_value Release(napi_env env, napi_callback_info info);

    void release();
    static thread_local napi_ref sConstructor_;
    static thread_local std::shared_ptr<AuxiliaryPicture> sAuxiliaryPic_;
    std::shared_ptr<AuxiliaryPicture> nativeAuxiliaryPicture_;
    napi_env env_ = nullptr;
    bool isRelease = false;
    uint32_t uniqueId_ = 0;
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_JS_COMMON_INCLUDE_AUXILIARY_PICTURE_NAPI_H
