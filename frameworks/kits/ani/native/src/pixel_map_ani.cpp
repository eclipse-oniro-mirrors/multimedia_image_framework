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

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelMapAni"

namespace OHOS {
namespace Media {
using namespace std;

bool ParseInitializationOptions([[maybe_unused]] ani_env* env, ani_object para, InitializationOptions &opts)
{
    ani_boolean isUndefined;
    env->Reference_IsUndefined(para, &isUndefined);
    if (isUndefined) {
        IMAGE_LOGE("ParseInitializationOptions isUndefined ");
        return false;
    }
    ani_class dateCls;
    const char *className = "L@ohos/multimedia/image/image/Size;";
    if (ANI_OK != env->FindClass(className, &dateCls)) {
        IMAGE_LOGE("Not found %{public}s", className);
        return false;
    }
    ani_ref size;
    if (ANI_OK != env->Object_CallMethodByName_Ref(para, "<get>size", ":L@ohos/multimedia/image/image/Size;", &size)) {
        IMAGE_LOGE("Object_GetFieldByName_Ref Failed");
    }
    ani_status ret;
    if (ANI_OK != env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size),
        "<get>width", ":I", &opts.size.width)) {
        IMAGE_LOGE("Object_CallMethodByName_Int width Failed");
    }
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size),
        "<get>height", ":I", &opts.size.height)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int height Failed");
    }
    ani_ref srcPixelFormatRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>srcPixelFormat",
        ":Lstd/core/Int;", &srcPixelFormatRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed srcPixelFormatRef:%{public}d", ret);
    }
    ani_int srcPixelFormat;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(srcPixelFormatRef),
        "unboxed", ":I", &srcPixelFormat)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed srcPixelFormat:%{public}d", ret);
    }
    ani_ref pixelFormatRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>pixelFormat",
        ":Lstd/core/Int;", &pixelFormatRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed pixelFormatRef:%{public}d", ret);
    }
    ani_int pixelFormat;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(pixelFormatRef),
        "unboxed", ":I", &pixelFormat)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed pixelFormat:%{public}d", ret);
    }
    opts.pixelFormat = static_cast<PixelFormat>(pixelFormat);
    ani_ref editableRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para,
        "<get>editable", ":Lstd/core/Boolean;", &editableRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed editableRef:%{public}d", ret);
    }
    ani_boolean editable;
    if ((ret = env->Object_CallMethodByName_Boolean(reinterpret_cast<ani_object>(editableRef),
        "unboxed", ":Z", &editable)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed editable:%{public}d", ret);
    }
    ani_ref alphaTypeRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>alphaType", ":Lstd/core/Int;", &alphaTypeRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed alphaTypeRef:%{public}d", ret);
    }
    ani_int alphaType;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(alphaTypeRef),
        "unboxed", ":I", &alphaType)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed alphaType:%{public}d", ret);
    }
    ani_ref scaleModeRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>scaleMode", ":Lstd/core/Int;", &scaleModeRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed scaleModeRef:%{public}d", ret);
    }
    ani_int scaleMode;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(scaleModeRef),
        "unboxed", ":I", &scaleMode)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Failed scaleMode:%{public}d", ret);
    }
    return true;
}

bool ParseRegion([[maybe_unused]] ani_env* env, ani_object region, Rect& rect)
{
    ani_boolean undefined;
    env->Reference_IsUndefined(region, &undefined);
    if (undefined) {
        IMAGE_LOGE("ParseRegion argument undefined");
        return false;
    }

    ani_ref size;
    if (ANI_OK != env->Object_CallMethodByName_Ref(region, "<get>size", ":L@ohos/multimedia/image/image/Size;",
        &size)) {
        IMAGE_LOGE("Object_GetFieldByName_Ref Failed");
        return false;
    }
    if (ANI_OK != env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size), "<get>width", ":I",
        &rect.width)) {
        IMAGE_LOGE("Object_CallMethodByName_Int width Failed");
        return false;
    }
    if (ANI_OK != env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size), "<get>height", ":I",
        &rect.height)) {
        IMAGE_LOGE("Object_CallMethodByName_Int height Failed");
        return false;
    }

    if (ANI_OK != env->Object_CallMethodByName_Int(region, "<get>x", ":I", &rect.left)) {
        IMAGE_LOGE("Object_CallMethodByName_Int x Failed");
        return false;
    }
    if (ANI_OK != env->Object_CallMethodByName_Int(region, "<get>y", ":I", &rect.top)) {
        IMAGE_LOGE("Object_CallMethodByName_Int y Failed");
        return false;
    }

    return true;
}

ani_object PixelMapAni::CreatePixelMap([[maybe_unused]] ani_env* env, std::shared_ptr<PixelMap> pixelMap)
{
    unique_ptr<PixelMapAni> pPixelMapAni = make_unique<PixelMapAni>();
    pPixelMapAni->nativePixelMap_ = pixelMap;
    static const char* className = "L@ohos/multimedia/image/image/PixelMapInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found L@ohos/multimedia/image/image/PixelMapInner");
        return nullptr;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        IMAGE_LOGE("Not found ani_method");
        return nullptr;
    }
    ani_object aniValue;
    if (ANI_OK != env->Object_New(cls, ctor, &aniValue, reinterpret_cast<ani_long>(pPixelMapAni.release()))) {
        IMAGE_LOGE("New Context Fail");
    }
    return aniValue;
}

ani_object PixelMapAni::CreatePixelMapAni([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_class clazz, [[maybe_unused]] ani_object obj)
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

    pixelmap->scale(static_cast<float>(x), static_cast<float>(y), static_cast<AntiAliasingOption>(level));
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
    static const char *className = "L@ohos/multimedia/image/image/PixelMapInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found L@ohos/multimedia/image/image/PixelMapInner;");
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function {"nativeCreateAlphaPixelmap", ":L@ohos/multimedia/image/image/PixelMap;",
            reinterpret_cast<void*>(OHOS::Media::CreateAlphaPixelmap)},
        ani_native_function {"nativeGetImageInfo", ":L@ohos/multimedia/image/image/ImageInfo;",
            reinterpret_cast<void*>(OHOS::Media::GetImageInfo)},
        ani_native_function {"getBytesNumberPerRow", ":I", reinterpret_cast<void*>(OHOS::Media::GetBytesNumberPerRow)},
        ani_native_function {"getPixelBytesNumber", ":I", reinterpret_cast<void*>(OHOS::Media::GetPixelBytesNumber)},
        ani_native_function {"nativeRelease", ":V", reinterpret_cast<void*>(OHOS::Media::Release)},
        ani_native_function {"nativeReadPixelsToBuffer", "Lescompat/ArrayBuffer;:V",
            reinterpret_cast<void*>(OHOS::Media::ReadPixelsToBuffer)},
        ani_native_function {"nativeScale", "DDI:V", reinterpret_cast<void*>(OHOS::Media::Scale)},
        ani_native_function {"nativeCrop", "L@ohos/multimedia/image/image/Region;:V",
            reinterpret_cast<void*>(OHOS::Media::Crop)},
        ani_native_function {"nativeFlip", "ZZ:V", reinterpret_cast<void*>(OHOS::Media::Flip)},
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