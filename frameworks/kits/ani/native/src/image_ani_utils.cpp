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

#include "image_ani_utils.h"
#include <array>
#include <iostream>
#include "pixel_map_ani.h"
#include "log_tags.h"
#include "media_errors.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "AniUtilsAni"

namespace OHOS {
namespace Media {
using namespace std;

PixelMap* ImageAniUtils::GetPixelMapFromEnv([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    return ImageAniUtils::GetPixelMapFromEnv2(env, obj).get();
}

shared_ptr<PixelMap> ImageAniUtils::GetPixelMapFromEnv2([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[GetPixelMapFromEnv] Object_GetField_Long fetch failed");
        return nullptr;
    }
    PixelMapAni* pixelmapAni = reinterpret_cast<PixelMapAni*>(nativeObj);
    if (!pixelmapAni) {
        IMAGE_LOGE("[GetPixelMapFromEnv] pixelmapAni failed");
        return nullptr;
    }
    return pixelmapAni->nativePixelMap_;
}

shared_ptr<Picture> ImageAniUtils::GetPictureFromEnv([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[GetPictureFromEnv] Object_GetField_Long fetch failed");
        return nullptr;
    }
    PictureAni* pictureAni = reinterpret_cast<PictureAni*>(nativeObj);
    if (!pictureAni) {
        IMAGE_LOGE("[GetPictureFromEnv] pictureAni failed");
        return nullptr;
    }
    return pictureAni->nativePicture_;
}

static ani_object CreateAniImageInfo(ani_env* env)
{
    static const char* imageInfoClassName = "L@ohos/multimedia/image/image/ImageInfoInner;";
    ani_class imageInfoCls;
    if (ANI_OK != env->FindClass(imageInfoClassName, &imageInfoCls)) {
        IMAGE_LOGE("Not found L@ohos/multimedia/image/image/ImageInfoInner;");
        return nullptr;
    }
    ani_method imageInfoCtor;
    if (ANI_OK != env->Class_FindMethod(imageInfoCls, "<ctor>", nullptr, &imageInfoCtor)) {
        IMAGE_LOGE("Not found Class_FindMethod");
        return nullptr;
    }
    ani_object imageInfoValue;
    if (ANI_OK != env->Object_New(imageInfoCls, imageInfoCtor, &imageInfoValue)) {
        IMAGE_LOGE("New Context Fail");
        return nullptr;
    }
    return imageInfoValue;
}

static bool SetImageInfoSize(ani_env* env, const ImageInfo& imgInfo, ani_object& imageInfoValue)
{
    ani_ref sizeref;
    if (ANI_OK != env->Object_CallMethodByName_Ref(imageInfoValue, "<get>size",
        ":L@ohos/multimedia/image/image/Size;", &sizeref)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref failed");
        return false;
    }
    ani_object sizeObj = reinterpret_cast<ani_object>(sizeref);
    if (ANI_OK != env->Object_CallMethodByName_Void(sizeObj, "<set>width", "I:V",
        static_cast<ani_int>(imgInfo.size.width))) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>width failed");
        return false;
    }
    if (ANI_OK != env->Object_CallMethodByName_Void(sizeObj, "<set>height", "I:V",
        static_cast<ani_int>(imgInfo.size.height))) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>height failed");
        return false;
    }
    return true;
}

ani_object ImageAniUtils::CreateImageInfoValueFromNative(ani_env* env, const ImageInfo &imgInfo, PixelMap* pixelmap)
{
    if (pixelmap == nullptr) {
        IMAGE_LOGE("[CreateImageInfoValueFromNative] pixelmap nullptr ");
        return nullptr;
    }

    ani_object imageInfoValue = CreateAniImageInfo(env);
    if (imageInfoValue == nullptr) {
        return nullptr;
    }

    if (!SetImageInfoSize(env, imgInfo, imageInfoValue)) {
        return nullptr;
    }
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, "<set>density", "I:V",
        static_cast<ani_int>(imgInfo.baseDensity))) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>density failed");
        return nullptr;
    }
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, "<set>stride", "I:V",
        static_cast<ani_int>(imgInfo.size.height))) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>stride failed");
        return nullptr;
    }
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, "<set>pixelFormat", "I:V",
        static_cast<ani_int>(imgInfo.pixelFormat))) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>pixelFormat failed");
        return nullptr;
    }
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, "<set>alphaType", "I:V",
        static_cast<ani_int>(imgInfo.alphaType))) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>alphaType failed");
        return nullptr;
    }
    ani_string encodeStr = ImageAniUtils::GetAniString(env, imgInfo.encodedFormat);
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, "<set>mimeType",
        "Lstd/core/String;:V", encodeStr)) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>encodedFormat failed ");
        return nullptr;
    }
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, "<set>isHdr", "Z:V", pixelmap->IsHdr())) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>isHdr failed ");
        return nullptr;
    }
    return imageInfoValue;
}

ani_object ImageAniUtils::CreateAniPixelMap(ani_env* env, std::unique_ptr<PixelMapAni>& pPixelMapAni)
{
    static const char* className = "L@ohos/multimedia/image/image/PixelMapInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found L@ohos/multimedia/image/image/PixelMapInner;");
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        IMAGE_LOGE("Not found <ctor>");
        return nullptr;
    }
    ani_object aniValue;
    if (ANI_OK != env->Object_New(cls, ctor, &aniValue, reinterpret_cast<ani_long>(pPixelMapAni.release()))) {
        IMAGE_LOGE("New Context Fail");
    }
    return aniValue;
}

ani_object ImageAniUtils::CreateAniImageSource(ani_env* env, std::unique_ptr<ImageSourceAni>& pImageSourceAni)
{
    static const char* className = "L@ohos/multimedia/image/image/ImageSourceInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found L@ohos/multimedia/image/image/ImageSourceInner;");
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        IMAGE_LOGE("Not found <ctor>");
        return nullptr;
    }

    ani_object aniValue;
    if (ANI_OK != env->Object_New(cls, ctor, &aniValue, reinterpret_cast<ani_long>(pImageSourceAni.release()))) {
        IMAGE_LOGE("New Context Fail");
    }
    return aniValue;
}

ani_object ImageAniUtils::CreateAniPicture(ani_env* env, std::unique_ptr<PictureAni>& pPictureAni)
{
    static const char* className = "L@ohos/multimedia/image/image/PictureInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found L@ohos/multimedia/image/image/PictureInner;");
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        IMAGE_LOGE("Not found <ctor>");
        return nullptr;
    }
    ani_object aniValue;
    if (ANI_OK != env->Object_New(cls, ctor, &aniValue, reinterpret_cast<ani_long>(pPictureAni.release()))) {
        IMAGE_LOGE("New Context Fail");
    }
    return aniValue;
}

ani_string ImageAniUtils::GetAniString(ani_env *env, const string &str)
{
    ani_string aniMimeType = nullptr;
    const char *utf8String = str.c_str();
    const ani_size stringLength = strlen(utf8String);
    env->String_NewUTF8(utf8String, stringLength, &aniMimeType);
    return aniMimeType;
}
} // Meida
} // OHOS