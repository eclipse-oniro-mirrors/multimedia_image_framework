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

#ifndef INTERFACES_KITS_JS_COMMON_INCLUDE_IMAGE_NAPI_H
#define INTERFACES_KITS_JS_COMMON_INCLUDE_IMAGE_NAPI_H

#include "native_image.h"
#include "napi/native_api.h"
#include "image_holder_manager.h"

namespace OHOS {
namespace Media {
struct ImageAsyncContext;
class ImageNapi {
public:
    ImageNapi();
    ~ImageNapi();
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value Create(napi_env env);
    static napi_value Create(napi_env env, std::shared_ptr<NativeImage> nativeImage);
    static std::shared_ptr<NativeImage> GetNativeImage(napi_env env, napi_value image);

    NativeImage* GetNative();
    void NativeRelease();

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);

    static napi_value JSGetClipRect(napi_env env, napi_callback_info info);
    static napi_value JsGetSize(napi_env env, napi_callback_info info);
    static napi_value JsGetFormat(napi_env env, napi_callback_info info);
    static napi_value JsGetComponent(napi_env env, napi_callback_info info);
    static napi_value JsRelease(napi_env env, napi_callback_info info);
    static napi_value JsGetTimestamp(napi_env env, napi_callback_info info);

    static thread_local napi_ref sConstructor_;
    static ImageHolderManager<NativeImage> sNativeImageHolder_;
    std::shared_ptr<NativeImage> native_;
    bool isTestImage_;
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_JS_COMMON_INCLUDE_IMAGE_NAPI_H
