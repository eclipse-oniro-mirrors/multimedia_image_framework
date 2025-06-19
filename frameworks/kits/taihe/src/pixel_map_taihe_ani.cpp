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

#include "pixel_map_taihe_ani.h"

#include <ani_signature_builder.h>
#include "pixel_map_taihe.h"

// This file is for legacy ANI backward compatibility

namespace OHOS {
namespace Media {
using namespace ANI::Image;
using namespace arkts;

ani_object PixelMapTaiheAni::CreateEtsPixelMap([[maybe_unused]] ani_env* env, std::shared_ptr<PixelMap> pixelMap)
{
    std::unique_ptr<PixelMapTaiheAni> pixelMapAni = std::make_unique<PixelMapTaiheAni>();
    pixelMapAni->nativePixelMap_ = pixelMap;

    ani_signature::Namespace ns = ani_signature::Builder::BuildNamespace("@ohos.multimedia.image.image");
    ani_namespace imageNamespace;
    if (env->FindNamespace(ns.Descriptor().c_str(), &imageNamespace) != ANI_OK) {
        return nullptr;
    }
    ani_function createFunc;
    if (env->Namespace_FindFunction(imageNamespace, "createPixelMapByPtr", nullptr, &createFunc) != ANI_OK) {
        return nullptr;
    }
    ani_ref pixelMapObj;
    if (env->Function_Call_Ref(createFunc, &pixelMapObj, reinterpret_cast<ani_long>(pixelMapAni.release())) != ANI_OK) {
        return nullptr;
    }

    return reinterpret_cast<ani_object>(pixelMapObj);
}

std::shared_ptr<PixelMap> PixelMapTaiheAni::GetNativePixelMap([[maybe_unused]] ani_env* env, ani_object obj)
{
    ani_signature::Type cls = ani_signature::Builder::BuildClass("@ohos.multimedia.image.image.PixelMap");
    ani_class pixelMapCls;
    if (env->FindClass(cls.Descriptor().c_str(), &pixelMapCls) != ANI_OK) {
        return nullptr;
    }
    ani_signature::SignatureBuilder sb{};
    ani_method getMethod;
    sb.SetReturnLong();
    if (env->Class_FindMethod(pixelMapCls, "getImplPtr", sb.BuildSignatureDescriptor().c_str(), &getMethod) != ANI_OK) {
        return nullptr;
    }
    ani_long implPtr;
    if (env->Object_CallMethod_Long(obj, getMethod, &implPtr) != ANI_OK) {
        return nullptr;
    }
    
    PixelMapImpl* pixelMapImpl = reinterpret_cast<PixelMapImpl*>(implPtr);
    if (pixelMapImpl == nullptr) {
        return nullptr;
    }
    return pixelMapImpl->GetNativePtr();
}

} // namespace Media
} // namespace OHOS