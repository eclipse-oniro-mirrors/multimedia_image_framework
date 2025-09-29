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
#include <array>
#include <iostream>

#include "image_ani_utils.h"
#include "image_log.h"
#include "log_tags.h"
#include "media_errors.h"
#include "pixel_map_ani.h"
#include <ani_signature_builder.h>

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelMapAni"

namespace OHOS {
namespace Media {
using namespace std;
using namespace arkts::ani_signature;

static ani_int parseEnumFromStruct(ani_env* env, ani_object &param, string propertyGet, string enumType)
{
    ani_status ret;
    ani_ref enumRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(param, propertyGet.c_str(), enumType.c_str(), &enumRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int enumRef Failed: %{public}d", ret);
        return 0;
    }
    ani_boolean undefined;
    env->Reference_IsUndefined(enumRef, &undefined);
    if (undefined) {
        IMAGE_LOGI("Enum %{public}s is undefined", propertyGet.c_str());
        return 0;
    }

    ani_int enumIndex;
    if (ANI_OK != env->EnumItem_GetValue_Int(static_cast<ani_enum_item>(enumRef), &enumIndex)) {
        IMAGE_LOGE("EnumItem_GetValue_Int enumIndex Failed: %{public}d", ret);
        return 0;
    }
    return enumIndex;
}

static bool ParseInitializationOptions([[maybe_unused]] ani_env* env, ani_object param, InitializationOptions &opts)
{
    ani_boolean isUndefined;
    env->Reference_IsUndefined(param, &isUndefined);
    if (isUndefined) {
        IMAGE_LOGE("ParseInitializationOptions isUndefined ");
        return false;
    }
    ani_class dateCls;
    const char *className = "@ohos.multimedia.image.image.Size";
    if (ANI_OK != env->FindClass(className, &dateCls)) {
        IMAGE_LOGE("Not found %{public}s", className);
        return false;
    }
    ani_ref size;
    if (ANI_OK != env->Object_CallMethodByName_Ref(param, Builder::BuildGetterName("size").c_str(),
        ":C{@ohos.multimedia.image.image.Size}", &size)) {
        IMAGE_LOGE("Object_GetFieldByName_Ref Failed");
    }
    ani_status ret;
    if (ANI_OK != env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size),
        Builder::BuildGetterName("width").c_str(), ":i", &opts.size.width)) {
        IMAGE_LOGE("Object_CallMethodByName_Int width Failed");
    }
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size),
        Builder::BuildGetterName("height").c_str(), ":i", &opts.size.height)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int height Failed");
    }
    opts.srcPixelFormat = PixelFormat(parseEnumFromStruct(env, param,
        Builder::BuildGetterName("srcPixelFormat").c_str(), ":C{@ohos.multimedia.image.image.PixelMapFormat}"));
    opts.pixelFormat = PixelFormat(parseEnumFromStruct(env, param, Builder::BuildGetterName("pixelFormat").c_str(),
        ":C{@ohos.multimedia.image.image.PixelMapFormat}"));
    ani_ref editableRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(param,
        Builder::BuildGetterName("editable").c_str(), ":C{std.core.Boolean}", &editableRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed editableRef:%{public}d", ret);
    }
    ani_boolean editable;
    if ((ret = env->Object_CallMethodByName_Boolean(reinterpret_cast<ani_object>(editableRef),
        "toBoolean", ":z", &editable)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed editable:%{public}d", ret);
    }
    opts.alphaType = AlphaType(parseEnumFromStruct(env, param, Builder::BuildGetterName("alphaType").c_str(),
        ":C{@ohos.multimedia.image.image.AlphaType}"));
    opts.scaleMode = ScaleMode(parseEnumFromStruct(env, param, Builder::BuildGetterName("scaleMode").c_str(),
        ":C{@ohos.multimedia.image.image.ScaleMode}"));
    return true;
}

static bool ParseRegion([[maybe_unused]] ani_env* env, ani_object region, Rect& rect)
{
    ani_boolean undefined;
    env->Reference_IsUndefined(region, &undefined);
    if (undefined) {
        IMAGE_LOGE("ParseRegion argument undefined");
        return false;
    }

    ani_ref size;
    if (ANI_OK != env->Object_CallMethodByName_Ref(region, Builder::BuildGetterName("size").c_str(),
        ":C{@ohos.multimedia.image.image.Size}", &size)) {
        IMAGE_LOGE("Object_GetFieldByName_Ref Failed");
        return false;
    }
    if (ANI_OK != env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size),
        Builder::BuildGetterName("width").c_str(), ":i", &rect.width)) {
        IMAGE_LOGE("Object_CallMethodByName_Int width Failed");
        return false;
    }
    if (ANI_OK != env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size),
        Builder::BuildGetterName("height").c_str(), ":i", &rect.height)) {
        IMAGE_LOGE("Object_CallMethodByName_Int height Failed");
        return false;
    }

    if (ANI_OK != env->Object_CallMethodByName_Int(region, Builder::BuildGetterName("x").c_str(), ":i", &rect.left)) {
        IMAGE_LOGE("Object_CallMethodByName_Int x Failed");
        return false;
    }
    if (ANI_OK != env->Object_CallMethodByName_Int(region, Builder::BuildGetterName("y").c_str(), ":i", &rect.top)) {
        IMAGE_LOGE("Object_CallMethodByName_Int y Failed");
        return false;
    }

    return true;
}

ani_object PixelMapAni::CreatePixelMap([[maybe_unused]] ani_env* env, std::shared_ptr<PixelMap> pixelMap)
{
    unique_ptr<PixelMapAni> pPixelMapAni = make_unique<PixelMapAni>();
    pPixelMapAni->nativePixelMap_ = pixelMap;
    static const char* className = "@ohos.multimedia.image.image.PixelMapInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found @ohos.multimedia.image.image.PixelMapInner");
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
        IMAGE_LOGE("Not found ani_method");
        return nullptr;
    }
    ani_object aniValue;
    if (ANI_OK != env->Object_New(cls, ctor, &aniValue, reinterpret_cast<ani_long>(pPixelMapAni.release()))) {
        IMAGE_LOGE("New Context Fail");
    }
    return aniValue;
}

ani_object PixelMapAni::CreatePixelMapAni([[maybe_unused]] ani_env* env, ani_object obj)
{
    unique_ptr<PixelMapAni> pPixelMapAni = make_unique<PixelMapAni>();
    InitializationOptions opts;
    if (!ParseInitializationOptions(env, obj, opts)) {
        IMAGE_LOGE("ParseInitializationOptions failed '");
        return nullptr;
    }

    pPixelMapAni->nativePixelMap_ = PixelMap::Create(opts);
    return ImageAniUtils::CreateAniPixelMap(env, pPixelMapAni);
}

static ani_object CreateAlphaPixelmap([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    PixelMap* pixelMap = ImageAniUtils::GetPixelMapFromEnv(env, obj);
    if (pixelMap == nullptr) {
        IMAGE_LOGE("[GetPixelMapFromEnv] pixelMap nullptr");
        return nullptr;
    }

    std::unique_ptr<PixelMapAni> pPixelMapAni = std::make_unique<PixelMapAni>();
    InitializationOptions opts;
    opts.pixelFormat = PixelFormat::ALPHA_8;
    pPixelMapAni->nativePixelMap_ = PixelMap::Create(*pixelMap, opts);
    return ImageAniUtils::CreateAniPixelMap(env, pPixelMapAni);
}

static ani_object GetImageInfo([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    PixelMap* pixelmap = ImageAniUtils::GetPixelMapFromEnv(env, obj);
    if (pixelmap == nullptr) {
        IMAGE_LOGE("[GetPixelMapFromEnv] pixelmap nullptr ");
        return nullptr;
    }
    ImageInfo imgInfo;
    pixelmap->GetImageInfo(imgInfo);
    return ImageAniUtils::CreateImageInfoValueFromNative(env, imgInfo, pixelmap);
}

static ani_int GetBytesNumberPerRow([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    PixelMap* pixelmap = ImageAniUtils::GetPixelMapFromEnv(env, obj);
    if (pixelmap == nullptr) {
        IMAGE_LOGE("[GetPixelMapFromEnv] pixelmap nullptr");
        return 0;
    }
    return pixelmap->GetRowBytes();
}

static ani_int GetPixelBytesNumber([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    PixelMap* pixelmap = ImageAniUtils::GetPixelMapFromEnv(env, obj);
    if (pixelmap == nullptr) {
        IMAGE_LOGE("[GetPixelMapFromEnv] pixelmap nullptr");
        return 0;
    }
    return pixelmap->GetByteCount();
}

static void Release([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[Release] Object_GetField_Long fetch field");
        return;
    }
    PixelMapAni* pixelmapAni = reinterpret_cast<PixelMapAni*>(nativeObj);
    pixelmapAni->nativePixelMap_ = nullptr;
}

static void ReadPixelsToBuffer(ani_env* env, ani_object obj, ani_object param0)
{
    PixelMap* pixelmap = ImageAniUtils::GetPixelMapFromEnv(env, obj);
    if (pixelmap == nullptr) {
        IMAGE_LOGE("[ReadPixelsToBuffer] pixelmap nullptr ");
        return;
    }
    size_t bufferLength = 0;
    void *dstbuffer = nullptr;
    ani_arraybuffer arraybuffer = static_cast<ani_arraybuffer>(param0);
    if (ANI_OK != env->ArrayBuffer_GetInfo(arraybuffer, &dstbuffer, &bufferLength)) {
        IMAGE_LOGE("[ReadPixelsToBuffer] ArrayBuffer_GetInfo failed");
    }
    uint32_t ret = pixelmap->ReadPixels(bufferLength, static_cast<uint8_t*>(dstbuffer));
    if (ret != 0) {
        IMAGE_LOGE("[ReadPixelsToBuffer] failed");
    }
}

static void Scale([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj, ani_double x, ani_double y,
    ani_int level)
{
    PixelMap* pixelmap = ImageAniUtils::GetPixelMapFromEnv(env, obj);
    if (pixelmap == nullptr) {
        IMAGE_LOGE("[GetPixelMapFromEnv] pixelmap nullptr");
        return;
    }

    ani_int levelIntValue = 0;
    ani_enum enumType;
    if (ANI_OK != env->FindEnum("@ohos.multimedia.image.image.AntiAliasingLevel", &enumType)) {
        IMAGE_LOGI("Find Enum AntiAliasingLevel Failed");
    }
    ani_enum_item enumItem;
    if (ANI_OK != env->Enum_GetEnumItemByIndex(enumType, level, &enumItem)) {
        IMAGE_LOGI("Enum_GetEnumItemByIndex AntiAliasingLevel Failed");
    }
    if (ANI_OK != env->EnumItem_GetValue_Int(enumItem, &levelIntValue)) {
        IMAGE_LOGI("EnumItem_GetValue_Int AntiAliasingLevel Failed");
    }

    pixelmap->scale(static_cast<float>(x), static_cast<float>(y), AntiAliasingOption(levelIntValue));
}

static void Crop([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj, ani_object region)
{
    PixelMap* pixelmap = ImageAniUtils::GetPixelMapFromEnv(env, obj);
    if (pixelmap == nullptr) {
        IMAGE_LOGE("[GetPixelMapFromEnv] pixelmap nullptr");
        return;
    }

    Rect rect;
    if (!ParseRegion(env, region, rect)) {
        IMAGE_LOGE("ParseRegion failed");
        return;
    }

    pixelmap->crop(rect);
}

static void Flip([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj, ani_boolean horizontal,
    ani_boolean vertical)
{
    PixelMap* pixelmap = ImageAniUtils::GetPixelMapFromEnv(env, obj);
    if (pixelmap == nullptr) {
        IMAGE_LOGE("[GetPixelMapFromEnv] pixelmap nullptr");
        return;
    }

    pixelmap->flip(static_cast<bool>(horizontal), static_cast<bool>(vertical));
}

ani_status PixelMapAni::Init(ani_env* env)
{
    static const char *className = "@ohos.multimedia.image.image.PixelMapInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found @ohos.multimedia.image.image.PixelMapInner");
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function {"nativeCreateAlphaPixelmap", ":C{@ohos.multimedia.image.image.PixelMap}",
            reinterpret_cast<void*>(OHOS::Media::CreateAlphaPixelmap)},
        ani_native_function {"nativeGetImageInfo", ":C{@ohos.multimedia.image.image.ImageInfo}",
            reinterpret_cast<void*>(OHOS::Media::GetImageInfo)},
        ani_native_function {"getBytesNumberPerRow", ":i", reinterpret_cast<void*>(OHOS::Media::GetBytesNumberPerRow)},
        ani_native_function {"getPixelBytesNumber", ":i", reinterpret_cast<void*>(OHOS::Media::GetPixelBytesNumber)},
        ani_native_function {"nativeRelease", ":", reinterpret_cast<void*>(OHOS::Media::Release)},
        ani_native_function {"nativeReadPixelsToBuffer", "C{escompat.ArrayBuffer}:",
            reinterpret_cast<void*>(OHOS::Media::ReadPixelsToBuffer)},
        ani_native_function {"nativeScale", "ddC{@ohos.multimedia.image.image.AntiAliasingLevel}:",
            reinterpret_cast<void*>(OHOS::Media::Scale)},
        ani_native_function {"nativeCrop", "C{@ohos.multimedia.image.image.Region}:",
            reinterpret_cast<void*>(OHOS::Media::Crop)},
        ani_native_function {"nativeFlip", "zz:", reinterpret_cast<void*>(OHOS::Media::Flip)},
    };
    ani_status ret = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ANI_OK != ret) {
        IMAGE_LOGE("[Init] Class_BindNativeMethods failed :%{public}d", ret);
        return ANI_ERROR;
    };
    return ANI_OK;
}
} // Media
} // OHOS
