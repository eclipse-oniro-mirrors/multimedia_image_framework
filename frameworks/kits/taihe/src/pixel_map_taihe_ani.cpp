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

namespace OHOS {
namespace Media {
using namespace ANI::Image;
using namespace arkts;

ani_ref PixelMapTaiheAni::gImageNamespace{};
ani_ref PixelMapTaiheAni::gPixelMapClass{};
ani_function PixelMapTaiheAni::gCreatePixelMapByPtr{};
ani_method PixelMapTaiheAni::gGetImplPtr{};
bool PixelMapTaiheAni::createPixelMapByPtrInited = false;
bool PixelMapTaiheAni::getImplPtrInited = false;

bool PixelMapTaiheAni::InitCreatePixelMapByPtr(ani_env* env)
{
    if (createPixelMapByPtrInited) {
        return true;
    }

    ani_signature::Namespace ns = ani_signature::Builder::BuildNamespace("@ohos.multimedia.image.image");
    ani_namespace imageNamespace;
    if (env->FindNamespace(ns.Descriptor().c_str(), &imageNamespace) != ANI_OK) {
        return false;
    }
    if (env->GlobalReference_Create(static_cast<ani_ref>(imageNamespace), &gImageNamespace) != ANI_OK) {
        return false;
    }
    if (env->Namespace_FindFunction(imageNamespace, "createPixelMapByPtr", nullptr, &gCreatePixelMapByPtr) != ANI_OK) {
        return false;
    }
    createPixelMapByPtrInited = true;
    return true;
}

// Wrap a native PixelMap into ANI object, for the use of external ANI/Taihe components
ani_object PixelMapTaiheAni::CreateEtsPixelMap([[maybe_unused]] ani_env* env, std::shared_ptr<PixelMap> pixelMap)
{
    if (!InitCreatePixelMapByPtr(env)) {
        return nullptr;
    }

    std::unique_ptr<PixelMapTaiheAni> pixelMapAni = std::make_unique<PixelMapTaiheAni>();
    pixelMapAni->nativePixelMap_ = pixelMap;
    ani_ref pixelMapObj;
    if (env->Function_Call_Ref(
        gCreatePixelMapByPtr, &pixelMapObj, reinterpret_cast<ani_long>(pixelMapAni.get())) == ANI_OK) {
        pixelMapAni.release();
    } else {
        return nullptr;
    }

    return reinterpret_cast<ani_object>(pixelMapObj);
}

bool PixelMapTaiheAni::InitGetImplPtr(ani_env* env)
{
    if (getImplPtrInited) {
        return true;
    }

    ani_signature::Type cls = ani_signature::Builder::BuildClass("@ohos.multimedia.image.image.PixelMap");
    ani_class pixelMapCls;
    if (env->FindClass(cls.Descriptor().c_str(), &pixelMapCls) != ANI_OK) {
        return false;
    }
    if (env->GlobalReference_Create(static_cast<ani_ref>(pixelMapCls), &gPixelMapClass) != ANI_OK) {
        return false;
    }
    ani_signature::SignatureBuilder sb{};
    sb.SetReturnLong();
    if (env->Class_FindMethod(
        pixelMapCls, "getImplPtr", sb.BuildSignatureDescriptor().c_str(), &gGetImplPtr) != ANI_OK) {
        return false;
    }
    getImplPtrInited = true;
    return true;
}

// Unwrap native PixelMap from an ANI object, for the use of external ANI/Taihe components
std::shared_ptr<PixelMap> PixelMapTaiheAni::GetNativePixelMap([[maybe_unused]] ani_env* env, ani_object obj)
{
    if (!InitGetImplPtr(env)) {
        return nullptr;
    }

    ani_long implPtr;
    if (env->Object_CallMethod_Long(obj, gGetImplPtr, &implPtr) != ANI_OK) {
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