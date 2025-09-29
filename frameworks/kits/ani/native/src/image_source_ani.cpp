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
#include "image_ani_utils.h"
#include "log_tags.h"
#include "media_errors.h"
#include "image_log.h"
#include "string_ex.h"
#include <ani_signature_builder.h>

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSourceAni"

namespace OHOS {
namespace Media {
using namespace std;
using namespace arkts::ani_signature;

static const string FILE_URL_PREFIX = "file://";

std::string ANIUtils_ANIStringToStdString2(ani_env *env, ani_string ani_str)
{
    ani_size strSize;
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

static string FileUrlToRawPath(const string &path)
{
    if (path.size() > FILE_URL_PREFIX.size() &&
        (path.compare(0, FILE_URL_PREFIX.size(), FILE_URL_PREFIX) == 0)) {
        return path.substr(FILE_URL_PREFIX.size());
    }
    return path;
}

ani_object ImageSourceAni::CreateImageSourceAni([[maybe_unused]] ani_env* env, ani_object obj)
{
    std::unique_ptr<ImageSourceAni> pImageSourceAni = std::make_unique<ImageSourceAni>();
    ani_class stringClass;
    env->FindClass("std.core.String", &stringClass);
    ani_boolean isString;
    env->Object_InstanceOf(obj, stringClass, &isString);
    if (isString) {
        string fileUrl = ANIUtils_ANIStringToStdString2(env, static_cast<ani_string>(obj));
        IMAGE_LOGI("Image source URI: %{public}s", fileUrl.c_str());
        pImageSourceAni->filePath_ = FileUrlToRawPath(fileUrl);
        SourceOptions opts;
        uint32_t errorCode;
        pImageSourceAni->nativeImageSource_ =
            ImageSource::CreateImageSource(pImageSourceAni->filePath_, opts, errorCode);
        if (pImageSourceAni->nativeImageSource_ == nullptr) {
            IMAGE_LOGE("CreateImageSource failed'");
        }
    }

    ani_class arrayBufferClass;
    env->FindClass("escompat.ArrayBuffer", &arrayBufferClass);
    ani_boolean isArrayBuffer;
    env->Object_InstanceOf(obj, arrayBufferClass, &isArrayBuffer);
    if (isArrayBuffer) {
        ani_int length;
        env->Object_CallMethodByName_Int(obj, "getByteLength", nullptr, &length);
        IMAGE_LOGI("Object is ArraryBuffer Length: %{public}d", length);
    }

    ani_class intClass;
    env->FindClass("std.core.Int", &intClass);
    ani_boolean isInt;
    env->Object_InstanceOf(obj, intClass, &isInt);
    if (isInt) {
        ani_int fd;
        env->Object_CallMethodByName_Int(obj, "toInt", ":i", &fd);
        IMAGE_LOGI("Image source fd: %{public}d", fd);
        SourceOptions opts;
        uint32_t errorCode;
        pImageSourceAni->nativeImageSource_ = ImageSource::CreateImageSource(fd, opts, errorCode);
    }

    if (pImageSourceAni->nativeImageSource_ == nullptr) {
        IMAGE_LOGE("CreateImageSource failed'");
    }

    return ImageAniUtils::CreateAniImageSource(env, pImageSourceAni);
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
    return ImageAniUtils::CreateImageInfoValueFromNative(env, imgInfo, nullptr);
}

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

static bool ParseDecodingOptions2([[maybe_unused]] ani_env* env, ani_object &param, DecodeOptions &opts)
{
    ani_status ret;
    ani_ref size;
    if (ANI_OK != env->Object_CallMethodByName_Ref(param, Builder::BuildGetterName("desiredSize").c_str(),
        ":C{@ohos.multimedia.image.image.Size}", &size)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref size Faild");
    }
    if (ANI_OK != env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size),
        Builder::BuildGetterName("width").c_str(), ":i", &opts.desiredSize.width)) {
        IMAGE_LOGE("Object_CallMethodByName_Int width Faild");
    }
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(size),
        Builder::BuildGetterName("height").c_str(), ":i", &opts.desiredSize.height)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int height Faild :%{public}d", ret);
    }

    ani_ref regionRef;
    if (ANI_OK != env->Object_CallMethodByName_Ref(param, Builder::BuildGetterName("desiredRegion").c_str(),
        ":C{@ohos.multimedia.image.image.Region}", &regionRef)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref desiredRegion Faild");
    }
    if (!ParseRegion(env, static_cast<ani_object>(regionRef), opts.desiredRegion)) {
        IMAGE_LOGE("Parse desiredRegion Faild");
    }
    opts.desiredPixelFormat = PixelFormat(parseEnumFromStruct(env, param,
        Builder::BuildGetterName("desiredPixelFormat").c_str(), ":C{@ohos.multimedia.image.image.PixelMapFormat}"));
    ani_ref fitDensityRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(param, Builder::BuildGetterName("fitDensity").c_str(),
        ":C{std.core.Int}", &fitDensityRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild fitDensityRef:%{public}d", ret);
    }
    ani_int fitDensity;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(fitDensityRef),
        "toInt", ":i", &fitDensity)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild fitDensity:%{public}d", ret);
    }
    return true;
}

static bool ParseDecodingOptions([[maybe_unused]] ani_env* env, ani_object para, DecodeOptions &opts)
{
    ani_boolean isUndefined;
    ani_status ret;
    ani_ref indexRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, Builder::BuildGetterName("index").c_str(),
        ":C{std.core.Int}", &indexRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild indexRef:%{public}d", ret);
    }
    env->Reference_IsUndefined(indexRef, &isUndefined);
    if (!isUndefined) {
        ani_int index;
        if (env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(indexRef),
            "toInt", ":i", &index) != ANI_OK) {
            IMAGE_LOGE("Object_CallMethodByName_Int Faild");
        }
    }

    ani_ref sampleRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, Builder::BuildGetterName("sampleSize").c_str(),
        ":C{std.core.Int}", &sampleRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild sampleRef:%{public}d", ret);
    }
    ani_int sample;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(sampleRef),
        "toInt", ":i", &sample)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild sample:%{public}d", ret);
    }

    ani_ref rotateRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, Builder::BuildGetterName("rotate").c_str(),
        ":C{std.core.Int}", &rotateRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild rotateRef:%{public}d", ret);
    }
    ani_int rotate;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(rotateRef),
        "toInt", ":i", &rotate)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild rotate:%{public}d", ret);
    }

    ani_ref editableRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, Builder::BuildGetterName("editable").c_str(),
        ":C{std.core.Boolean}", &editableRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Ref Faild editableRef:%{public}d", ret);
    }
    ani_boolean editable;
    if ((ret = env->Object_CallMethodByName_Boolean(reinterpret_cast<ani_object>(editableRef),
        "toBoolean", ":z", &editable)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild editable:%{public}d", ret);
    }
    opts.editable = static_cast<bool>(editable);

    return ParseDecodingOptions2(env, para, opts);
}

static ani_object CreatePixelMap([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object obj, [[maybe_unused]]ani_object para)
{
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[CreatePixelMap] Object_GetField_Long fetch field ");
        return nullptr;
    }
    ImageSourceAni* imageSourceAni = reinterpret_cast<ImageSourceAni*>(nativeObj);
    ImageInfo imgInfo;
    imgInfo.encodedFormat = "abcdefg";
    if (imageSourceAni != nullptr) {
    } else {
        IMAGE_LOGE("[CreatePixelMap] imageSourceAni is nullptr");
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
    env->FindClass("std.core.String", &stringClass);
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
    if (ANI_OK != env->Object_CallMethodByName_Ref(map_object, "keys", ":C{escompat.IterableIterator}", &keys)) {
        IMAGE_LOGE("Failed to get keys iterator");
        return false;
    }

    bool success = true;
    while (success) {
        ani_ref next;
        ani_boolean done;

        if (ANI_OK != env->Object_CallMethodByName_Ref(static_cast<ani_object>(keys), "next", nullptr, &next)) {
            IMAGE_LOGE("Failed to get next key");
            success = false;
            break;
        }

        if (ANI_OK != env->Object_GetFieldByName_Boolean(static_cast<ani_object>(next), "done", &done)) {
            IMAGE_LOGE("Failed to check iterator done");
            success = false;
            break;
        }
        if (done) {
            IMAGE_LOGE("[forEachMapEntry] done break");
            break;
        }

        ani_ref key_value;
        if (ANI_OK != env->Object_GetFieldByName_Ref(static_cast<ani_object>(next), "value", &key_value)) {
            IMAGE_LOGE("Failed to get key value");
            success = false;
            break;
        }

        ani_ref value_obj;
        if (ANI_OK != env->Object_CallMethodByName_Ref(map_object, "$_get", nullptr, &value_obj, key_value)) {
            IMAGE_LOGE("Failed to get value for key");
            success = false;
            break;
        }

        callback(key_value, value_obj);
    }
    return success;
}


class ANIIntanceHelper {
public:
    ANIIntanceHelper() = default;
    explicit ANIIntanceHelper(ani_env *aniEnv) { env = aniEnv; };
    bool Init()
    {
        if (ANI_OK != env->FindClass("std.core.String", &stringType)) {
            IMAGE_LOGE("FindClass std.core.String failed");
            return false;
        }
        if (ANI_OK != env->FindClass("escompat.Record", &recordType)) {
            IMAGE_LOGE("FindClass escompat.Record failed");
            return false;
        }
        if (ANI_OK != env->FindClass("std.core.Numeric", &numberType)) {
            IMAGE_LOGE("std.core.Numeric failed");
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
            IMAGE_LOGE("Call Object_InstanceOf failed");
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
            IMAGE_LOGE("Call Object_InstanceOf failed");
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
    ani_class stringType = nullptr;
    ani_class recordType = nullptr;
    ani_class numberType = nullptr;
    ani_env *env;
    bool inited = false;
};

bool ProcMapEntry(ani_env* env, ani_ref key, ani_ref value, ImageSourceAni* imageSourceAni, ANIIntanceHelper &ih)
{
    auto imageSource = imageSourceAni->nativeImageSource_;
    if (imageSource == nullptr) {
        IMAGE_LOGE("[ProcMapEntry] imageSource nullptr");
        return false;
    }
    if (!ih.isString(static_cast<ani_object>(key))) {
        IMAGE_LOGE("[ProcMapEntry] key is not string");
        return false;
    }
    auto keyStr = ANIUtils_ANIStringToStdString2(env, static_cast<ani_string>(key));
    auto valueStr = ANIUtils_ANIStringToStdString2(env, static_cast<ani_string>(value));
    IMAGE_LOGI("[ProcMapEntry] ProcMapEntry key:%{public}s value:%{public}s", keyStr.c_str(), valueStr.c_str());

    if (!IsSameTextStr(imageSourceAni->filePath_, "")) {
        imageSource->ModifyImageProperty(0, keyStr, valueStr, imageSourceAni->filePath_);
    } else if (imageSourceAni->fileDescriptor_ != -1) {
        imageSource->ModifyImageProperty(0, keyStr, valueStr, imageSourceAni->fileDescriptor_);
    } else {
        IMAGE_LOGE("There is no image source!");
        return false;
    }
    return true;
}

static void ModifyImageProperties([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj, ani_object recordsObj)
{
    ImageSourceAni* imageSourceAni = ImageAniUtils::GetImageSourceAniFromEnv(env, obj);
    if (imageSourceAni == nullptr) {
        IMAGE_LOGE("[GetImageSourceFromEnv] imageSource nullptr");
        return;
    }

    ANIIntanceHelper ih(env);
    if (!ih.Init()) {
        IMAGE_LOGE("[ModifyImageProperties] ih init fail");
        return;
    }

    forEachMapEntry(env, recordsObj,
        [env, &imageSourceAni, &ih](ani_ref key, ani_ref value) -> bool {
            return ProcMapEntry(env, key, value, imageSourceAni, ih);
        });
}

bool ParseArrayString([[maybe_unused]] ani_env* env, ani_object arrayObj, std::vector<std::string> &strings)
{
    ani_double length;
    if (ANI_OK != env->Object_GetPropertyByName_Double(arrayObj, "length", &length)) {
        IMAGE_LOGE("Object_GetPropecortyByName_Double length Failed");
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref stringEntryRef;
        if (ANI_OK != env->Object_CallMethodByName_Ref(arrayObj, "$_get",
            "i:C{std.core.Object}", &stringEntryRef, (ani_int)i)) {
            IMAGE_LOGE("Object_GetPropertyByName_Double length Failed");
            return false;
        }
        strings.emplace_back(ANIUtils_ANIStringToStdString2(env, static_cast<ani_string>(stringEntryRef)));
    }
    return true;
}

static ani_object GetImageProperties([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj,
    ani_object arrayObj)
{
    auto imageSource = ImageAniUtils::GetImageSourceFromEnv(env, obj);
    if (imageSource == nullptr) {
        IMAGE_LOGE("[GetImageProperties] imageSource nullptr");
        return nullptr;
    }

    vector<string> keyStrArray;
    ParseArrayString(env, arrayObj, keyStrArray);

    vector<pair<string, string>> kVStrArray;
    uint32_t errCode = SUCCESS;
    for (auto keyStrIt = keyStrArray.begin(); keyStrIt != keyStrArray.end(); ++keyStrIt) {
        string valueStr = "";
        errCode = imageSource->GetImagePropertyString(0, *keyStrIt, valueStr);
        if (errCode == SUCCESS) {
            kVStrArray.emplace_back(make_pair(*keyStrIt, valueStr));
        } else {
            kVStrArray.emplace_back(make_pair(*keyStrIt, ""));
            IMAGE_LOGE("errCode: %{public}u , exif key: %{public}s", errCode, keyStrIt->c_str());
        }
    }

    ani_object argumentObj = {};
    ani_method recordSetMethod = ImageAniUtils::GetRecordSetMethod(env, argumentObj);
    if (recordSetMethod == nullptr) {
        IMAGE_LOGE("[GetImageProperties] recordSetMethod nullptr");
    }

    ani_status status;
    for (auto iter = kVStrArray.begin(); iter != kVStrArray.end(); ++iter) {
        string key = iter->first;
        string value = iter->second;
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
        status = env->Object_CallMethod_Void(argumentObj, recordSetMethod, ani_key, ani_value);
        if (status != ANI_OK) {
            IMAGE_LOGE("Object_CallMethod_Void value failed status : %{public}u", status);
            return nullptr;
        }
    }
    return argumentObj;
}

static void Release([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[Release] Object_GetField_Long fetch field ret:%{public}d", ret);
        return;
    }
    ImageSourceAni* imageSourceAni = reinterpret_cast<ImageSourceAni*>(nativeObj);
    imageSourceAni->nativeImageSource_ = nullptr;
}

ani_status ImageSourceAni::Init(ani_env* env)
{
    static const char *className = "@ohos.multimedia.image.image.ImageSourceInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found ");
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function {"nativeGetImageInfo", "i:C{@ohos.multimedia.image.image.ImageInfo}",
            reinterpret_cast<void*>(OHOS::Media::GetImageInfo)},
        ani_native_function {"nativeCreatePixelMap",
            "C{@ohos.multimedia.image.image.DecodingOptions}:C{@ohos.multimedia.image.image.PixelMap}",
            reinterpret_cast<void*>(OHOS::Media::CreatePixelMap)},
        ani_native_function {"modifyImageProperty", "lC{std.core.String}C{std.core.String}:",
            reinterpret_cast<void*>(OHOS::Media::ModifyImageProperty)},
        ani_native_function {"nativeModifyImageProperties", "C{escompat.Record}:",
            reinterpret_cast<void*>(OHOS::Media::ModifyImageProperties)},
        ani_native_function {"nativeGetImageProperties", "C{escompat.Array}:C{escompat.Record}",
            reinterpret_cast<void*>(OHOS::Media::GetImageProperties)},
        ani_native_function {"release", ":", reinterpret_cast<void *>(OHOS::Media::Release)},
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
