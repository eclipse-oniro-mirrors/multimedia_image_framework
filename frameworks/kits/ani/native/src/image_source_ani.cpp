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
#include "image_source_ani.h"
#include "pixel_map_ani.h"
#include "ani_utils.h"
#include "log_tags.h"
#include "media_errors.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSourceAni"

namespace OHOS {
namespace Media {
using namespace std;

std::string ANIUtils_ANIStringToStdString2(ani_env *env, ani_string ani_str)
{
    ani_size  strSize;
    env->String_GetUTF8Size(ani_str, &strSize);

    std::vector<char> buffer(strSize + 1); // +1 for null terminator
    char* utfBuffer = buffer.data();

    ani_size bytes_written = 0;
    if (ANI_OK != env->String_GetUTF8(ani_str, utfBuffer, strSize + 1, &bytes_written)) {
        IMAGE_LOGE("ANIUtils_ANIStringToStdString fail");
        return "";
    }

    utfBuffer[bytes_written] = '\0';
    std::string content = std::string(utfBuffer);
    return content;
}

ani_object ImageSourceAni::CreateImageSourceAni([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_class clazz, [[maybe_unused]]ani_object obj)
{
    std::unique_ptr<ImageSourceAni> pImageSourceAni = std::make_unique<ImageSourceAni>();
    ani_class stringClass;
    env->FindClass("Lstd/core/String;", &stringClass);
    ani_boolean isString;
    env->Object_InstanceOf(obj, stringClass, &isString);
    if (isString) {
        auto stringContent = ANIUtils_ANIStringToStdString2(env, static_cast<ani_string>(obj));
        IMAGE_LOGE("Object is String Object Content");
        SourceOptions opts;
        uint32_t errorCode;
        pImageSourceAni->nativeImageSource_ = ImageSource::CreateImageSource(stringContent, opts, errorCode);
        if (pImageSourceAni->nativeImageSource_ == nullptr) {
            IMAGE_LOGE("CreateImageSource failed'");
        }
    }

    ani_class arrayBufferClass;
    env->FindClass("Lescompat/ArrayBuffer;", &arrayBufferClass);
    ani_boolean isArrayBuffer;
    env->Object_InstanceOf(obj, arrayBufferClass, &isArrayBuffer);
    if (isArrayBuffer) {
        ani_int length;
        env->Object_CallMethodByName_Int(obj, "getByteLength", nullptr, &length);
        IMAGE_LOGI("Object is ArraryBuffer Lenght: %{public}d", length);
    }

    ani_class intClass;
    env->FindClass("Lstd/core/Int;", &intClass);
    ani_boolean isInt;
    env->Object_InstanceOf(obj, intClass, &isInt);
    if (isInt) {
        ani_int fd;
        env->Object_CallMethodByName_Int(obj, "unboxed", ":I", &fd);
        IMAGE_LOGI("fd: %{public}d", fd);
        SourceOptions opts;
        uint32_t errorCode;
        pImageSourceAni->nativeImageSource_ = ImageSource::CreateImageSource(fd, opts, errorCode);
    }

    if (pImageSourceAni->nativeImageSource_ == nullptr) {
        IMAGE_LOGE("CreateImageSource failed'");
    }
    static const char* className = "L@ohos/multimedia/image/image/ImageSourceInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found");
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        IMAGE_LOGE("Not found");
        return nullptr;
    }

    ani_object aniValue;
    if (ANI_OK != env->Object_New(cls, ctor, &aniValue, reinterpret_cast<ani_long>(pImageSourceAni.release()))) {
        IMAGE_LOGE("New Context Fail");
    }
    return aniValue;
}


ani_object CreateImageInfoValueFromNative(ani_env* env, const ImageInfo &imgInfo)
{
    static const char* imageInfoClassName = "L@ohos/multimedia/image/image/ImageInfoInner;";
    ani_class imageInfoCls;
    if (ANI_OK != env->FindClass(imageInfoClassName, &imageInfoCls)) {
        IMAGE_LOGE("Not found %{public}s", imageInfoClassName);
        return nullptr;
    }
    ani_method imageInfoCtor;
    if (ANI_OK != env->Class_FindMethod(imageInfoCls, "<ctor>", nullptr, &imageInfoCtor)) {
        IMAGE_LOGE("Not found Class_FindMethod");
        return nullptr;
    }
    ani_object imageInfoValue;
    if (ANI_OK !=env->Object_New(imageInfoCls, imageInfoCtor, &imageInfoValue)) {
        IMAGE_LOGE("New Context Fail");
    }
    ani_ref sizeref;
    if (ANI_OK != env->Object_CallMethodByName_Ref(imageInfoValue, "<get>size",
        ":L@ohos/multimedia/image/image/Size;", &sizeref)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref failed");
        return nullptr;
    }
    ani_object sizeObj = reinterpret_cast<ani_object>(sizeref);
    if (ANI_OK != env->Object_CallMethodByName_Void(sizeObj, "<set>width", "I:V",
        static_cast<ani_int>(imgInfo.size.width))) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>width failed");
        return nullptr;
    }
    if (ANI_OK != env->Object_CallMethodByName_Void(sizeObj, "<set>height", "I:V",
        static_cast<ani_int>(imgInfo.size.height))) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>height failed");
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
    ani_string encodeStr =  AniUtils::GetAniString(env, imgInfo.encodedFormat);
    if (ANI_OK != env->Object_CallMethodByName_Void(imageInfoValue, "<set>mimeType",
        "Lstd/core/String;:V", encodeStr)) {
        IMAGE_LOGE("Object_CallMethodByName_Void <set>encodedFormat failed");
        return nullptr;
    }

    return imageInfoValue;
}

static ani_object GetImageInfo([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj, ani_int indexObj)
{
    ani_status ret;
    IMAGE_LOGE("[GetImageInfo] Object_GetField_Long in");
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[GetImageInfo] Object_GetField_Long fetch field");
        return nullptr;
    }
    IMAGE_LOGE("[GetImageInfo] Object_GetField_Long sucess ");
    ImageSourceAni* imageSourceAni = reinterpret_cast<ImageSourceAni*>(nativeObj);
    int index = reinterpret_cast<int>(indexObj);
    IMAGE_LOGE("[GetImageInfo] index: %{public}d", index);
    ImageInfo imgInfo;
    if (imageSourceAni != nullptr) {
        IMAGE_LOGI("[GetImageInfo] get imageSourceAni success ");
    } else {
        IMAGE_LOGE("[GetImageInfo] imageSourceAni is nullptr ");
        return nullptr;
    }
    return CreateImageInfoValueFromNative(env, imgInfo);
}

bool ParseDecodingOptions([[maybe_unused]] ani_env* env, ani_object para, DecodeOptions &opts)
{
    ani_boolean isUndefined;
    env->Reference_IsUndefined(para, &isUndefined);
    if (isUndefined) {
        IMAGE_LOGE("ParseInitializationOptions isUndefined ");
        return false;
    }

    ani_status ret;
    ani_ref indexRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>index", ":Lstd/core/Int;", &indexRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild indexRef:%{public}d", ret);
    }
    env->Reference_IsUndefined(indexRef, &isUndefined);
    if (!isUndefined) {
        ani_int index;
        if (env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(indexRef),
            "unboxed", ":I", &index) != ANI_OK) {
            IMAGE_LOGE("Object_CallMethodByName_Int Faild");
        }
        IMAGE_LOGE("ParseDecodingOptions get index:%{public}d", index);
    }

    ani_ref sampleRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>sampleSize", ":Lstd/core/Int;", &sampleRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild sampleRef:%{public}d", ret);
    }
    ani_int sample;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(sampleRef),
        "unboxed", ":I", &sample)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild sample:%{public}d", ret);
    }
    IMAGE_LOGE("ParseDecodingOptions get sample:%{public}d", sample);

    ani_ref rotateRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>rotate", ":Lstd/core/Int;", &rotateRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild rotateRef:%{public}d", ret);
    }
    ani_int rotate;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(rotateRef),
        "unboxed", ":I", &rotate)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild rotate:%{public}d", ret);
    }
    IMAGE_LOGE("ParseDecodingOptions get rotate:%{public}d", rotate);

    ani_ref editableRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>editable", ":Lstd/core/Int;", &editableRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild editableRef:%{public}d", ret);
    }
    ani_int editable;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(editableRef),
        "unboxed", ":I", &editable)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild editable:%{public}d", ret);
    }
    IMAGE_LOGE("ParseDecodingOptions get editable:%{public}d", rotate);

    ani_ref size;
    if (ANI_OK != env->Object_CallMethodByName_Ref(para, "<get>desiredSize",
        ":L@ohos/multimedia/image/image/Size;", &size)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref size Faild");
    }
    int32_t width;
    if (ANI_OK != env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size), "<get>width", ":I", &width)) {
        IMAGE_LOGE("Object_CallMethodByName_Int width Faild");
    }
    int32_t height;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size),
        "<get>height", ":I", &height)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int height Faild :%{public}d", ret);
    }
    IMAGE_LOGE("ParseDecodingOptions get width:%{public}d", width);

    ani_ref reginRef;
    if (ANI_OK != env->Object_CallMethodByName_Ref(para, "<get>desiredRegion",
        ":L@ohos/multimedia/image/image/Region;", &reginRef)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref desiredRegion Faild");
    }
    if (ANI_OK != env->Object_CallMethodByName_Ref(static_cast<ani_object>(reginRef),
        "<get>size", ":L@ohos/multimedia/image/image/Size;", &size)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref desiredRegion size Faild");
    }
    width = 0;
    if (ANI_OK != env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size), "<get>width", ":I", &width)) {
        IMAGE_LOGE("Object_CallMethodByName_Int desiredRegion size width Faild");
    }
    height = 0;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size),
        "<get>height", ":I", &height)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int desiredRegion size height Faild :%{public}d", ret);
    }
    ani_ref xRef;
    if (ANI_OK != env->Object_CallMethodByName_Ref(reinterpret_cast<ani_object>(reginRef),
        "<get>x", ":Lstd/core/Int;", &xRef)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref desiredRegion xRef Faild");
    }
    ani_int x;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(xRef), "unboxed", ":I", &x)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int desiredRegion x Faild :%{public}d", ret);
    }
    ani_ref yRef;
    if (ANI_OK != env->Object_CallMethodByName_Ref(reinterpret_cast<ani_object>(reginRef),
        "<get>y", ":Lstd/core/Int;", &yRef)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref desiredRegion yRef Faild");
    }
    ani_int y;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(yRef), "unboxed", ":I", &y)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int desiredRegion y Faild :%{public}d", ret);
    }
    ani_ref desiredPixelFormatRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>desiredPixelFormat",
        ":Lstd/core/Int;", &desiredPixelFormatRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild desiredPixelFormatRef:%{public}d", ret);
    }
    ani_int desiredPixelFormat;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(desiredPixelFormatRef),
        "unboxed", ":I", &desiredPixelFormat)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild desiredPixelFormat:%{public}d", ret);
    }
    IMAGE_LOGE("ParseDecodingOptions get desiredPixelFormat:%{public}d", desiredPixelFormat);
    ani_ref fitDensityRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para,
        "<get>fitDensity", ":Lstd/core/Int;", &fitDensityRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild fitDensityRef:%{public}d", ret);
    }
    ani_int fitDensity;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(fitDensityRef),
        "unboxed", ":I", &fitDensity)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild fitDensity:%{public}d", ret);
    }
    IMAGE_LOGE("ParseDecodingOptions get fitDensity:%{public}d", fitDensity);
    ani_ref desiredColorSpaceRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>desiredColorSpace",
        ":Lstd/core/Int;", &desiredColorSpaceRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild desiredColorSpaceRef:%{public}d", ret);
    }
    ani_int desiredColorSpace;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(desiredColorSpaceRef),
        "unboxed", ":I", &desiredColorSpace)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild desiredColorSpace:%{public}d", ret);
    }
    IMAGE_LOGE("ParseDecodingOptions get desiredColorSpace:%{public}d", desiredColorSpace);
    ani_ref desiredDynamicRangeRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>desiredDynamicRange",
        ":Lstd/core/Int;", &desiredDynamicRangeRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild desiredDynamicRangeRef:%{public}d", ret);
    }
    ani_int desiredDynamicRange;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(desiredDynamicRangeRef),
        "unboxed", ":I", &desiredDynamicRange)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild desiredDynamicRange:%{public}d", ret);
    }
    IMAGE_LOGE("ParseDecodingOptions get desiredDynamicRange:%{public}d", desiredDynamicRange);
    ani_ref resolutionQualityRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>resolutionQuality",
        ":Lstd/core/Int;", &resolutionQualityRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild resolutionQualityRef:%{public}d", ret);
    }
    ani_int resolutionQuality;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(resolutionQualityRef),
        "unboxed", ":I", &resolutionQuality)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild resolutionQuality:%{public}d", ret);
    }
    IMAGE_LOGE("ParseDecodingOptions get resolutionQuality:%{public}d", resolutionQuality);
    return true;
}

static ani_object CreatePixelMapSync([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object obj, [[maybe_unused]]ani_object para)
{
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[CreatePixelMapSync] Object_GetField_Long fetch field ");
        return nullptr;
    }
    ImageSourceAni* imageSourceAni = reinterpret_cast<ImageSourceAni*>(nativeObj);
    ImageInfo imgInfo;
    imgInfo.encodedFormat = "abcdefg";
    if (imageSourceAni != nullptr) {
    } else {
        IMAGE_LOGE("[CreatePixelMapSync] imageSourceAni is nullptr");
    }

    DecodeOptions opts;
    ParseDecodingOptions(env, para, opts);

    return PixelMapAni::CreatePixelMap(env, std::make_shared<PixelMap>());
}

static void ModifyImageProperty([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj,
    ani_long longObj, ani_object key, ani_object value)
{
    IMAGE_LOGE("ModifyImageProperty in ");
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[ModifyImageProperty] Object_GetField_Long fetch field ");
        return;
    }
    ImageSourceAni* imageSourceAni = reinterpret_cast<ImageSourceAni*>(nativeObj);
    if (imageSourceAni == nullptr) {
        IMAGE_LOGE("[ModifyImageProperty] get imageSourceAni failed");
    }
    IMAGE_LOGE("[ModifyImageProperty] get imageSourceAni success");

    ani_class stringClass;
    env->FindClass("Lstd/core/String;", &stringClass);
    ani_boolean isString;
    env->Object_InstanceOf(key, stringClass, &isString);
    std::string keyS = "";
    if (isString) {
        keyS = ANIUtils_ANIStringToStdString2(env, static_cast<ani_string>(key));
    }
    std::string valueS = ANIUtils_ANIStringToStdString2(env, static_cast<ani_string>(value));
    IMAGE_LOGI("ModifyImageProperty get key:%{public}s value:%{public}s", keyS.c_str(), valueS.c_str());
}


template <typename F>
static bool forEachMapEntry(ani_env *env, ani_object map_object, F &&callback)
{
    ani_ref keys;
    if (ANI_OK !=
        env->Object_CallMethodByName_Ref(map_object, "keys", nullptr, &keys)) {
        IMAGE_LOGE("Failed to get keys iterator");
        return false;
    }

    bool success = true;
    while (success) {
        ani_ref next;
        ani_boolean done;

        if (ANI_OK != env->Object_CallMethodByName_Ref(
            static_cast<ani_object>(keys), "next", nullptr, &next)) {
            IMAGE_LOGE("Failed to get next key");
            success = false;
            break;
        }

        if (ANI_OK != env->Object_GetFieldByName_Boolean(
            static_cast<ani_object>(next), "done", &done)) {
            IMAGE_LOGE("Failed to check iterator done");
            success = false;
            break;
        }
        if (done) {
            IMAGE_LOGE("[forEachMapEntry] done break");
            break;
        }

        ani_ref key_value;
        if (ANI_OK != env->Object_GetFieldByName_Ref(static_cast<ani_object>(next),
            "value", &key_value)) {
            IMAGE_LOGE("Failed to get key value");
            success = false;
            break;
        }

        ani_ref value_obj;
        if (ANI_OK != env->Object_CallMethodByName_Ref(map_object, "$_get", nullptr,
            &value_obj, key_value)) {
            IMAGE_LOGE("Failed to get value for key");
            success = false;
            break;
        }

        if (!callback(key_value, value_obj)) {
            success = false;
            break;
        }
    }
    return success;
}


class ANIIntanceHelper {
public:
    ANIIntanceHelper() = default;
    explicit ANIIntanceHelper(ani_env *aniEnv) { env = aniEnv; };
    bool Init()
    {
        if (ANI_OK != env->FindClass("Lstd/core/String;", &stringType)) {
            IMAGE_LOGE("FindClass std/core/String FAILD");
            return false;
        }
        if (ANI_OK != env->FindClass("Lescompat/Record;", &recordType)) {
            IMAGE_LOGE("FindClass Lescompat/Record; FAILD");
            return false;
        }
        if (ANI_OK != env->FindClass("Lstd/core/Numeric;", &numberType)) {
            IMAGE_LOGE("Lstd/core/Numeric; FAILD");
            return false;
        }
        inited = true;
        return true;
    }
    bool isString(ani_object obj)
    {
        if (!inited) {
            return false;
        }
        ani_boolean is_string;
        if (ANI_OK != env->Object_InstanceOf(static_cast<ani_object>(obj),
            static_cast<ani_type>(stringType), &is_string)) {
            IMAGE_LOGE("Call Object_InstanceOf Fail");
            return false;
        }
        return (bool)is_string;
    }
    bool isRecord(ani_object obj)
    {
        if (!inited) {
            return false;
        }
        ani_boolean is_record;
        if (ANI_OK != env->Object_InstanceOf(static_cast<ani_object>(obj),
            static_cast<ani_type>(recordType), &is_record)) {
            IMAGE_LOGE("Call Object_InstanceOf Fail");
            return false;
        }
        return (bool)is_record;
    }
    bool isNumber(ani_object obj)
    {
        if (!inited) {
            return false;
        }
        ani_boolean is_number;
        if (ANI_OK != env->Object_InstanceOf(static_cast<ani_object>(obj),
            static_cast<ani_type>(numberType), &is_number)) {
            IMAGE_LOGE("Call Object_InstanceOf Fail");
            return false;
        }
        return (bool)is_number;
    }
    bool isArray(ani_object obj)
    {
        if (!inited) {
            return false;
        }
        ani_size arrayLength;
        if (ANI_OK !=
            env->Array_GetLength(static_cast<ani_array>(obj), &arrayLength)) {
            return false;
        }
        return true;
    }
private:
    ani_class stringType;
    ani_class recordType;
    ani_class numberType;
    ani_env *env;
    bool inited = false;
};

bool ProcMapEntry(ani_env *env, ani_ref key, ani_ref value,
    ANIIntanceHelper &ih, std::map<std::string, std::string> &input)
{
    if (!ih.isString(static_cast<ani_object>(key))) {
        IMAGE_LOGE("[ProcMapEntry] key is not string");
        return false;
    }
    auto key_string =
        ANIUtils_ANIStringToStdString2(env, static_cast<ani_string>(key));
    auto value_string =
        ANIUtils_ANIStringToStdString2(env, static_cast<ani_string>(value));
    IMAGE_LOGI("[ProcMapEntry] ProcMapEntry  key: %{public}s value:%{public}s",
        key_string.c_str(), value_string.c_str());
    input[key_string] = value_string;
    return true;
}

static void ModifyImageProperties([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object obj, ani_object map_object)
{
    ani_long nativeObj {};
    bool ret;
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[ModifyImageProperties] Object_GetField_Long fetch field ret:%{public}d", ret);
        return;
    }
    ImageSourceAni* imageSourceAni = reinterpret_cast<ImageSourceAni*>(nativeObj);
    if (imageSourceAni == nullptr) {
        IMAGE_LOGE("[ModifyImageProperties] get imageSourceAni failed");
    }
    IMAGE_LOGI("[ModifyImageProperties] get imageSourceAni success");

    ANIIntanceHelper ih(env);
    if (!ih.Init()) {
        IMAGE_LOGE("ih init fail");
        return;
    }
  
    std::map<std::string, std::string> input;
    forEachMapEntry(env, map_object,
        [env, &ih, &input](ani_ref key, ani_ref value) -> bool {
            return ProcMapEntry(env, key, value, ih, input);
        });
    return;
}

bool ParseArrayString([[maybe_unused]] ani_env* env, ani_object arrayObj, std::vector<std::string> &strings)
{
    ani_double length;
    if (ANI_OK != env->Object_GetPropertyByName_Double(arrayObj, "length", &length)) {
        IMAGE_LOGE("Object_GetPropertyByName_Double length Failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref stringEntryRef;
        if (ANI_OK != env->Object_CallMethodByName_Ref(arrayObj, "$_get",
            "I:Lstd/core/Object;", &stringEntryRef, (ani_int)i)) {
            IMAGE_LOGE("Object_GetPropertyByName_Double length Failed");
            return false;
        }
        strings.emplace_back(ANIUtils_ANIStringToStdString2(env, static_cast<ani_string>(stringEntryRef)));
    }
    return true;
}

static ani_object GetImageProperties([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object obj, ani_object arrayObj)
{
    ani_long nativeObj {};
    bool ret;
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[GetImageProperties] Object_GetField_Long fetch field ret:%{public}d", ret);
    }
    ImageSourceAni* imageSourceAni = reinterpret_cast<ImageSourceAni*>(nativeObj);
    if (imageSourceAni == nullptr) {
        IMAGE_LOGE("[GetImageProperties] get imageSourceAni failed");
    }
    IMAGE_LOGI("[GetImageProperties] get imageSourceAni success");

    std::vector<std::string> strings;
    ParseArrayString(env, arrayObj, strings);
    for (const auto &s : strings) {
        IMAGE_LOGE("Array String Content:%{public}s", s.c_str());
    }
    std::map<std::string, std::string> paras = {
        {"aa", "11"},
        {"bb", "22"},
    };
    ani_status status;
    ani_class recordCls;
    status = env->FindClass("Lescompat/Record;", &recordCls);
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
    ani_object argumentObject = {};
    if (ANI_OK != env->Object_New(recordCls, ctor, &argumentObject)) {
        IMAGE_LOGE("Object_New Failed");
        return nullptr;
    }
    ani_method recordSetMethod;
    status = env->Class_FindMethod(recordCls, "$_set",
        "Lstd/core/Object;Lstd/core/Object;:V", &recordSetMethod);
    if (status != ANI_OK) {
        IMAGE_LOGE("Class_FindMethod recordSetMethod Failed");
        return nullptr;
    }
    for (auto iter = paras.begin(); iter != paras.end(); ++iter) {
        std::string key = iter->first;
        std::string value = iter->second;
        ani_string ani_key;
        ani_string ani_value;
        status = env->String_NewUTF8(key.c_str(), key.length(), &ani_key);
        if (status != ANI_OK) {
            IMAGE_LOGE("String_NewUTF8 key failed status :%{public}u", status);
            return nullptr;
        }
        status = env->String_NewUTF8(value.c_str(), value.length(), &ani_value);
        if (status != ANI_OK) {
            IMAGE_LOGE("String_NewUTF8 value failed status : %{public}u", status);
            return nullptr;
        }
        status = env->Object_CallMethod_Void(argumentObject, recordSetMethod, ani_key, ani_value);
        if (status != ANI_OK) {
            IMAGE_LOGE("Object_CallMethod_Void value failed status : %{public}u", status);
            return nullptr;
        }
    }
    return argumentObject;
}

static void Release([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    ani_long nativeObj {};
    bool ret;
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[Release] Object_GetField_Long fetch field ret:%{public}d", ret);
        return;
    }
    ImageSourceAni* imageSourceAni = reinterpret_cast<ImageSourceAni*>(nativeObj);
    if (imageSourceAni == nullptr) {
        IMAGE_LOGE("[Release] get imageSourceAni failed");
    }
    return;
}

ani_status ImageSourceAni::Init(ani_env* env)
{
    static const char *className = "L@ohos/multimedia/image/image/ImageSourceInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found ");
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function {"getImageInfo", "I:L@ohos/multimedia/image/image/ImageInfo;",
            reinterpret_cast<void *>(OHOS::Media::GetImageInfo)},
        ani_native_function {"createPixelMapSync",
            "L@ohos/multimedia/image/image/DecodingOptions;:L@ohos/multimedia/image/image/PixelMap;",
            reinterpret_cast<void *>(OHOS::Media::CreatePixelMapSync)},
        ani_native_function {"modifyImageProperty", "JLstd/core/String;Lstd/core/String;:V",
            reinterpret_cast<void *>(OHOS::Media::ModifyImageProperty)},
        ani_native_function {"modifyImageProperties", "Lescompat/Record;:V",
            reinterpret_cast<void *>(OHOS::Media::ModifyImageProperties)},
        ani_native_function {"getImageProperties", "Lescompat/Array;:Lescompat/Record;",
            reinterpret_cast<void *>(OHOS::Media::GetImageProperties)},
        ani_native_function {"release", ":V", reinterpret_cast<void *>(OHOS::Media::Release)},
    };
    ani_status ret = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ANI_OK != ret) {
        IMAGE_LOGE("[ImageSourceAni] Cannot bind native methods ret: %{public}d", ret);
        return ANI_ERROR;
    };
    return ANI_OK;
}
} // Media
} // OHOS
