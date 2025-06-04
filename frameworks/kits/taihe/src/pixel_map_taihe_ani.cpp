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
#include "pixel_map_taihe.h"

// This file is for legacy ANI backward compatibility

namespace OHOS {
namespace Media {
using namespace ANI::Image;

ani_object PixelMapTaiheAni::CreateEtsPixelMap([[maybe_unused]] ani_env* env, std::shared_ptr<PixelMap> pixelMap)
{
    std::unique_ptr<PixelMapTaiheAni> pixelMapAni = std::make_unique<PixelMapTaiheAni>();
    pixelMapAni->nativePixelMap_ = pixelMap;

    ani_namespace imageNamespace;
    if (env->FindNamespace("L@ohos/multimedia/image/image;", &imageNamespace) != ANI_OK) {
        return nullptr;
    }
    ani_function createFunc;
    if (env->Namespace_FindFunction(imageNamespace, "createPixelMapByPtr", nullptr, &createFunc) != ANI_OK) {
        return nullptr;
    }
    ani_ref pixelMapObj;
    if (env->Function_Call_Ref(createFunc, &pixelMapObj, reinterpret_cast<ani_long>(pixelMapAni.get())) == ANI_OK) {
        pixelMapAni.release();
    } else {
        return nullptr;
    }

    return reinterpret_cast<ani_object>(pixelMapObj);
}

std::shared_ptr<PixelMap> PixelMapTaiheAni::GetNativePixelMap([[maybe_unused]] ani_env* env, ani_object obj)
{
    ani_class pixelMapCls;
    if (env->FindClass("L@ohos/multimedia/image/image/PixelMap;", &pixelMapCls) != ANI_OK) {
        return nullptr;
    }
    ani_method getMethod;
    if (env->Class_FindMethod(pixelMapCls, "getImplPtr", ":J", &getMethod) != ANI_OK) {
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