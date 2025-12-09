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
#include "image_source_taihe_ani.h"

// This file is for legacy ANI backward compatibility

namespace OHOS {
namespace Media {
ani_object ImageSourceTaiheAni::CreateEtsImageSource(ani_env *env, std::shared_ptr<ImageSource> imageSource)
{
    std::unique_ptr<ImageSourceTaiheAni> imageSourceAni = std::make_unique<ImageSourceTaiheAni>();
    imageSourceAni->nativeImgSrc = imageSource;

    ani_namespace imageNamespace;
    if (env->FindNamespace("@ohos.multimedia.image.image", &imageNamespace) != ANI_OK) {
        IMAGE_LOGE("%{public}s FindNamespace failed", __func__);
        return nullptr;
    }

    ani_function createFunc;
    if (env->Namespace_FindFunction(imageNamespace, "createImageSourceByPtr", nullptr, &createFunc) != ANI_OK) {
        IMAGE_LOGE("%{public}s Namespace_FindFunction failed", __func__);
        return nullptr;
    }

    ani_ref imageSourceObj;
    if (env->Function_Call_Ref(createFunc, &imageSourceObj,
        reinterpret_cast<ani_long>(imageSourceAni.get())) != ANI_OK) {
        IMAGE_LOGE("%{public}s Function_Call_Ref failed", __func__);
        return nullptr;
    }

    imageSourceAni.release();
    return reinterpret_cast<ani_object>(imageSourceObj);
}

} // namespace Media
} // namespace OHOS