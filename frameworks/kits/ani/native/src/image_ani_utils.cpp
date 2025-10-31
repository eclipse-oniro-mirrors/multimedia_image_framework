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
#include <ani_signature_builder.h>

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "AniUtilsAni"

namespace OHOS {
namespace Media {
using namespace std;
using namespace arkts::ani_signature;

PixelMap* ImageAniUtils::GetPixelMapFromEnv([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    return ImageAniUtils::GetPixelMapFromEnvSp(env, obj).get();
}

shared_ptr<PixelMap> ImageAniUtils::GetPixelMapFromEnvSp([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[GetPixelMapFromEnv] Object_GetField_Long fetch failed");
        return nullptr;
    }
    PixelMapAni* pixelmapAni = reinterpret_cast<PixelMapAni*>(nativeObj);
    if (!pixelmapAni) {
        IMAGE_LOGE("[GetPixelMapFromEnv] pixelmapAni nullptr");
        return nullptr;
    }
    return pixelmapAni->nativePixelMap_;
}

ImageSourceAni* ImageAniUtils::GetImageSourceAniFromEnv([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[GetImageSourceFromEnv] Object_GetField_Long fetch failed");
        return nullptr;
    }
    return reinterpret_cast<ImageSourceAni*>(nativeObj);
}

shared_ptr<ImageSource> ImageAniUtils::GetImageSourceFromEnv([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object obj)
{
    ImageSourceAni* imageSourceAni = ImageAniUtils::GetImageSourceAniFromEnv(env, obj);
    if (!imageSourceAni) {
        IMAGE_LOGE("[GetPictureFromEnv] imageSourceAni nullptr");
        return nullptr;
    }
    return imageSourceAni->nativeImageSource_;
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
        IMAGE_LOGE("[GetPictureFromEnv] pictureAni nullptr");
        return nullptr;
    }
    return pictureAni->nativePicture_;
}

static ani_object CreateAniImageInfo(ani_env* env)
{
    static const char* imageInfoClassName = "@ohos.multimedia.image.image.ImageInfoInner";
    ani_class imageInfoCls;
    if (ANI_OK != env->FindClass(imageInfoClassName, &imageInfoCls)) {
        IMAGE_LOGE("Not found @ohos.multimedia.image.image.ImageInfoInner");
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
    if (ANI_OK != env->Object_CallMethodByName_Ref(imageInfoValue, Builder::BuildGetterName("size").c_str(),
        ":C{@ohos.multimedia.image.image.Size}", &sizeref)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref failed");
        return false;
    }
    ani_object sizeObj = reinterpret_cast<ani_object>(sizeref);
    const char *methodName = Builder::BuildSetterName("width").c_str();
    if (ANI_OK != env->Object_CallMethodByName_Void(sizeObj, methodName, "i:",
        static_cast<ani_int>(imgInfo.size.width))) {
        IMAGE_LOGE("Object_CallMethodByName_Void %{public}s failed", methodName);
        return false;
    }
    const char *setterName = Builder::BuildSetterName("height").c_str();
    if (ANI_OK != env->Object_CallMethodByName_Void(sizeObj, setterName, "i:",
        static_cast<ani_int>(imgInfo.size.height))) {
        IMAGE_LOGE("Object_CallMethodByName_Void %{public}s failed", setterName);
        return false;
    }
    return true;
}

static string getPixelFormatItemName(PixelFormat format)
{
    switch (format) {
        case PixelFormat::ARGB_8888:
            return "ARGB_8888";
        case PixelFormat::RGB_565:
            return "RGB_565";
        case PixelFormat::RGBA_8888:
            return "RGBA_8888";
        case PixelFormat::BGRA_8888:
            return "BGRA_8888";
        case PixelFormat::RGB_888:
            return "RGB_888";
        case PixelFormat::ALPHA_8:
            return "ALPHA_8";
        case PixelFormat::RGBA_F16:
            return "RGBA_F16";
        case PixelFormat::NV21:
            return "NV21";
        case PixelFormat::NV12:
            return "NV12";
        case PixelFormat::RGBA_1010102:
            return "RGBA_1010102";
        case PixelFormat::YCBCR_P010:
            return "YCBCR_P010";
        case PixelFormat::YCRCB_P010:
            return "YCRCB_P010";
        case PixelFormat::ASTC_4x4:
            return "ASTC_4x4";
        default:
            return "UNKNOWN";
    }
}

static ani_enum_item findPixelFormatEnumItem([[maybe_unused]] ani_env* env, PixelFormat format)
{
    ani_enum type;
    if (ANI_OK != env->FindEnum("@ohos.multimedia.image.image.PixelMapFormat", &type)) {
        IMAGE_LOGE("FindEnum for PixelMapFormat Failed");
        return {};
    }

    string itemName = getPixelFormatItemName(format);

    ani_enum_item enumItem;
    if (ANI_OK != env->Enum_GetEnumItemByName(type, itemName.c_str(), &enumItem)) {
        IMAGE_LOGE("Enum_GetEnumItemByName for PixelMapFormat Failed");
        return {};
    }

    return enumItem;
}

static string getAlphaTypeItemName(AlphaType alphaType)
{
    switch (alphaType) {
        case AlphaType::IMAGE_ALPHA_TYPE_OPAQUE:
            return "OPAQUE";
        case AlphaType::IMAGE_ALPHA_TYPE_PREMUL:
            return "PREMUL";
        case AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL:
            return "UNPREMUL";
        default:
            return "UNKNOWN";
    }
}

static ani_enum_item findAlphaTypeEnumItem([[maybe_unused]] ani_env* env, AlphaType alphaType)
{
    ani_enum type;
    if (ANI_OK != env->FindEnum("@ohos.multimedia.image.image.AlphaType", &type)) {
        IMAGE_LOGE("FindEnum for AlphaType Failed");
        return {};
    }

    string itemName = getAlphaTypeItemName(alphaType);

    ani_enum_item enumItem;
    if (ANI_OK != env->Enum_GetEnumItemByName(type, itemName.c_str(), &enumItem)) {
        IMAGE_LOGE("Enum_GetEnumItemByName for AlphaType Failed");
        return {};
    }

    return enumItem;
}

ani_object ImageAniUtils::CreateImageInfoValueFromNative(ani_env* env, const ImageInfo &imgInfo, PixelMap* pixelmap)
{
    ani_object imageInfoValue = CreateAniImageInfo(env);
    if (imageInfoValue == nullptr) {
        return nullptr;
    }

    if (!SetImageInfoSize(env, imgInfo, imageInfoValue)) {
        return nullptr;
    }
    const char *densitySetterName = Builder::BuildSetterName("density").c_str();
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, densitySetterName, "i:",
        static_cast<ani_int>(imgInfo.baseDensity))) {
        IMAGE_LOGE("Object_CallMethodByName_Void %{public}s failed", densitySetterName);
        return nullptr;
    }
    const char *strideSetterName = Builder::BuildSetterName("stride").c_str();
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, strideSetterName, "i:",
        static_cast<ani_int>(imgInfo.size.height))) {
        IMAGE_LOGE("Object_CallMethodByName_Void %{public}s failed", strideSetterName);
        return nullptr;
    }
    const char *pixelFormatSetterName = Builder::BuildSetterName("pixelFormat").c_str();
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, pixelFormatSetterName,
        "C{@ohos.multimedia.image.image.PixelMapFormat}:", findPixelFormatEnumItem(env, imgInfo.pixelFormat))) {
        IMAGE_LOGE("Object_CallMethodByName_Void %{public}s failed", pixelFormatSetterName);
        return nullptr;
    }
    const char *alphaTypeSetterName = Builder::BuildSetterName("alphaType").c_str();
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, alphaTypeSetterName,
        "C{@ohos.multimedia.image.image.AlphaType}:", findAlphaTypeEnumItem(env, imgInfo.alphaType))) {
        IMAGE_LOGE("Object_CallMethodByName_Void %{public}s failed",  alphaTypeSetterName);
        return nullptr;
    }
    const char *mimeTypeSetterName = Builder::BuildSetterName("mimeType").c_str();
    ani_string encodeStr = ImageAniUtils::GetAniString(env, imgInfo.encodedFormat);
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, mimeTypeSetterName,
        "C{std.core.String}:", encodeStr)) {
        IMAGE_LOGE("Object_CallMethodByName_Void %{public}s failed", mimeTypeSetterName);
        return nullptr;
    }

    if (pixelmap != nullptr) {
        const char *isHdrSetterName = Builder::BuildSetterName("isHdr").c_str();
        if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, isHdrSetterName, "z:", pixelmap->IsHdr())) {
            IMAGE_LOGE("Object_CallMethodByName_Void %{public}s failed", isHdrSetterName);
            return nullptr;
        }
    }
    return imageInfoValue;
}

ani_object ImageAniUtils::CreateAniPixelMap(ani_env* env, std::unique_ptr<PixelMapAni>& pPixelMapAni)
{
    static const char* className = "@ohos.multimedia.image.image.PixelMapInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found @ohos.multimedia.image.image.PixelMapInner");
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
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
    static const char* className = "@ohos.multimedia.image.image.ImageSourceInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found @ohos.multimedia.image.image.ImageSourceInner");
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
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
    static const char* className = "@ohos.multimedia.image.image.PictureInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found @ohos.multimedia.image.image.PictureInner");
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
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

ani_method ImageAniUtils::GetRecordSetMethod(ani_env* env, ani_object &argumentObj)
{
    ani_status status;
    ani_class recordCls;
    status = env->FindClass("escompat.Record", &recordCls);
    if (status != ANI_OK) {
        IMAGE_LOGE("FindClass failed status :%{public}u", status);
        return nullptr;
    }
    ani_method ctor;
    status = env->Class_FindMethod(recordCls, "<ctor>", nullptr, &ctor);
    if (status != ANI_OK) {
        IMAGE_LOGE("Class_FindMethod failed status :%{public}u", status);
        return nullptr;
    }
    if (ANI_OK != env->Object_New(recordCls, ctor, &argumentObj)) {
        IMAGE_LOGE("Object_New Failed");
        return nullptr;
    }
    ani_method recordSetMethod;
    status = env->Class_FindMethod(recordCls, "$_set",
        "YY:", &recordSetMethod);
    if (status != ANI_OK) {
        IMAGE_LOGE("Class_FindMethod recordSetMethod Failed");
        return nullptr;
    }
    return recordSetMethod;
}
} // Meida
} // OHOS
