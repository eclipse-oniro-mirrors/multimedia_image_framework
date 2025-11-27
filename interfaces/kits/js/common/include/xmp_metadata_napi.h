/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_COMMON_INCLUDE_XMP_METADATA_NAPI_H
#define INTERFACES_KITS_JS_COMMON_INCLUDE_XMP_METADATA_NAPI_H

#include "image_napi_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "xmp_metadata.h"

namespace OHOS {
namespace Media {
class XMPMetadataNapi {
public:
    XMPMetadataNapi();
    ~XMPMetadataNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateXMPMetadata(napi_env env, std::shared_ptr<XMPMetadata> &xmpMetadata);
    std::shared_ptr<XMPMetadata> GetNativeXMPMetadata();
private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);

    static napi_status DefineClassProperties(napi_env env, napi_value &constructor);
    static napi_status DefineStaticProperties(napi_env env, napi_value exports);
    static napi_value CreateXMPNamespaces(napi_env env);

    static napi_value SetTag(napi_env env, napi_callback_info info);
    static napi_value GetTag(napi_env env, napi_callback_info info);
    static napi_value RemoveTag(napi_env env, napi_callback_info info);
    static napi_value CountArrayItems(napi_env env, napi_callback_info info);
    static napi_value RegisterNamespacePrefix(napi_env env, napi_callback_info info);
    static napi_value EnumerateTags(napi_env env, napi_callback_info info);

    void Release();

    static thread_local napi_ref sConstructor_;
    static thread_local std::shared_ptr<XMPMetadata> sXMPMetadata_;
    static thread_local bool sIsExplicitCreate_;
    std::shared_ptr<XMPMetadata> nativeXMPMetadata_;
    napi_env env_ = nullptr;
    bool isRelease = false;
    uint32_t uniqueId_ = 0;
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_JS_COMMON_INCLUDE_XMP_METADATA_NAPI_H
