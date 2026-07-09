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

#include "image_log.h"
#include "picture_taihe_ani.h"

#include <ani_signature_builder.h>
#include <mutex>
#include "picture_taihe.h"

// This file is for legacy ANI backward compatibility

namespace OHOS {
namespace Media {
using namespace ANI::Image;
using namespace arkts;

ani_ref PictureTaiheAni::gPictureClass{};
ani_method PictureTaiheAni::gGetImplPtr{};
bool PictureTaiheAni::getImplPtrInited = false;
std::mutex PictureTaiheAni::getImplPtrMutex;

bool PictureTaiheAni::InitGetImplPtr(ani_env* env)
{
    std::lock_guard<std::mutex> lock(getImplPtrMutex);
    if (getImplPtrInited) {
        return true;
    }

    ani_signature::Type cls = ani_signature::Builder::BuildClass("@ohos.multimedia.image.image.Picture");
    ani_class pictureCls;
    if (env->FindClass(cls.Descriptor().c_str(), &pictureCls) != ANI_OK) {
        return false;
    }
    if (env->GlobalReference_Create(static_cast<ani_ref>(pictureCls), &gPictureClass) != ANI_OK) {
        return false;
    }
    ani_signature::SignatureBuilder sb{};
    sb.SetReturnLong();
    if (env->Class_FindMethod(
        pictureCls, "getImplPtr", sb.BuildSignatureDescriptor().c_str(), &gGetImplPtr) != ANI_OK) {
        if (env->GlobalReference_Delete(gPictureClass) != ANI_OK) {
            IMAGE_LOGD("[%{public}s] ANI GlobalReference_Delete failed", __func__);
        }
        gPictureClass = nullptr;
        return false;
    }
    getImplPtrInited = true;
    return true;
}

// Unwrap native Picture from an ANI object, for the use of external ANI/Taihe components
std::shared_ptr<Picture> PictureTaiheAni::GetNativePicture(ani_env* env, ani_object obj)
{
    if (env == nullptr) {
        IMAGE_LOGE("[%{public}s] ANI env is null", __func__);
        return nullptr;
    }
    if (!InitGetImplPtr(env)) {
        IMAGE_LOGE("[%{public}s] ANI init failed", __func__);
        return nullptr;
    }

    ani_long implPtr;
    if (env->Object_CallMethod_Long(obj, gGetImplPtr, &implPtr) != ANI_OK) {
        IMAGE_LOGE("[%{public}s] Call function getImplPtr failed", __func__);
        return nullptr;
    }
    PictureImpl* pictureImpl = reinterpret_cast<PictureImpl*>(implPtr);
    if (pictureImpl == nullptr) {
        IMAGE_LOGE("[%{public}s] The implPtr obtained is null", __func__);
        return nullptr;
    }

    return pictureImpl->GetNativePtr();
}

ani_object PictureTaiheAni::CreateEtsPicture(ani_env *env, std::shared_ptr<Picture> picture)
{
    std::unique_ptr<PictureTaiheAni> pictureAni = std::make_unique<PictureTaiheAni>();
    pictureAni->nativePicture_ = picture;

    ani_namespace imageNamespace;
    if (env->FindNamespace("@ohos.multimedia.image.image", &imageNamespace) != ANI_OK) {
        IMAGE_LOGE("%{public}s FindNamespace failed", __func__);
        return nullptr;
    }

    ani_function createFunc;
    if (env->Namespace_FindFunction(imageNamespace, "createPictureByPtr", nullptr, &createFunc) != ANI_OK) {
        IMAGE_LOGE("%{public}s Namespace_FindFunction failed", __func__);
        return nullptr;
    }

    ani_ref pictureObj;
    if (env->Function_Call_Ref(createFunc, &pictureObj, reinterpret_cast<ani_long>(pictureAni.get())) != ANI_OK) {
        IMAGE_LOGE("%{public}s Function_Call_Ref failed", __func__);
        return nullptr;
    }

    pictureAni.release();
    return reinterpret_cast<ani_object>(pictureObj);
}
} // namespace Media
} // namespace OHOS