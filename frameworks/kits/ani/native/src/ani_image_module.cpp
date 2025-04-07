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

#include "ani_image_module.h"
#include "image_log.h"
#include "log_tags.h"
#include "media_errors.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ANI_IMAGE_MODULE"

ANI_EXPORT
ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    ani_env* env;
    IMAGE_LOGD("ANI_Constructor in");
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        IMAGE_LOGE("Unsupported ANI_VERSION_1");
        return ANI_ERROR;
    }
    ani_namespace imageNamespace;
    if (ANI_OK != env->FindNamespace("L@ohos/multimedia/image/image;", &imageNamespace)) {
        IMAGE_LOGE("[ANI_Constructor] FindNamespace failed");
        return ANI_ERROR;
    }
    std::array staticMethods = {
        ani_native_function {"createPixelMapSync", nullptr,
            reinterpret_cast<void*>(OHOS::Media::PixelMapAni::CreatePixelMapAni)},
        ani_native_function {"createImagePacker", nullptr,
            reinterpret_cast<void*>(OHOS::Media::ImagePackerAni::CreateImagePackerAni)},
        ani_native_function {"nativeCreateImageSourceByUri", nullptr,
            reinterpret_cast<void*>(OHOS::Media::ImageSourceAni::CreateImageSourceAni)},
        ani_native_function {"nativeCreateImageSourceByFd", nullptr,
            reinterpret_cast<void*>(OHOS::Media::ImageSourceAni::CreateImageSourceAni)},
        ani_native_function {"createPicture", nullptr,
            reinterpret_cast<void*>(OHOS::Media::PictureAni::CreatePictureAni)},
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(imageNamespace, staticMethods.data(), staticMethods.size())) {
        IMAGE_LOGE("[ANI_Constructor] Namespace_BindNativeFunctions failed");
        return ANI_ERROR;
    };
    OHOS::Media::PixelMapAni::Init(env);
    OHOS::Media::ImagePackerAni::Init(env);
    OHOS::Media::ImageSourceAni::Init(env);
    OHOS::Media::PictureAni::Init(env);
    *result = ANI_VERSION_1;
    return ANI_OK;
}