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

#include <ani.h>
#include <iostream>

#include "image_ani_utils.h"
#include "image_log.h"
#include "log_tags.h"
#include "media_errors.h"
#include "picture_ani.h"
#include "pixel_map_ani.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PictureAni"

namespace OHOS {
namespace Media {
using namespace std;

ani_object PictureAni::CreatePictureAni([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_class clazz,
    [[maybe_unused]] ani_object obj)
{
    unique_ptr<PictureAni> pPictureAni = std::make_unique<PictureAni>();
    auto pixelMap = ImageAniUtils::GetPixelMapFromEnv2(env, obj);
    if (pixelMap == nullptr) {
        IMAGE_LOGE("[GetPixelMapFromEnv2] pixelMap nullptr");
        return nullptr;
    }

    pPictureAni->nativePicture_ = Picture::Create(pixelMap);
    return ImageAniUtils::CreateAniPicture(env, pPictureAni);
}


static ani_object GetMainPixelmap([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    auto picture = ImageAniUtils::GetPictureFromEnv(env, obj);
    if (picture == nullptr) {
        IMAGE_LOGE("[GetPictureFromEnv] picture nullptr");
        return nullptr;
    }
    
    return PixelMapAni::CreatePixelMap(env, picture->GetMainPixel());
}

ani_status PictureAni::Init(ani_env* env)
{
    static const char* className = "L@ohos/multimedia/image/image/PictureInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found L@ohos/multimedia/image/image/PictureInner;");
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function {"getMainPixelmap", ":L@ohos/multimedia/image/image/PixelMap;",
            reinterpret_cast<void*>(OHOS::Media::GetMainPixelmap)},
    };
    ani_status ret = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ANI_OK != ret) {
        IMAGE_LOGE("[Init] Class_BindNativeMethods failed: %{public}d", ret);
        return ANI_ERROR;
    };
    return ANI_OK;
}
} // Media
} // OHOS