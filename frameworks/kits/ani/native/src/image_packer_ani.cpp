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
#include "image_packer_ani.h"
#include "image_log.h"
#include "log_tags.h"
#include "media_errors.h"
#include "pixel_map_ani.h"
#include "securec.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImagePackerAni"

namespace OHOS {
namespace Media {
using namespace std;

ani_object ImagePackerAni::CreateImagePackerAni([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_class clazz, [[maybe_unused]]ani_object obj)
{
    std::unique_ptr<ImagePackerAni> imagePackerAni = std::make_unique<ImagePackerAni>();
    std::shared_ptr<ImagePacker> imagePacker = std::make_shared<ImagePacker>();
    imagePackerAni->nativeImagePacker_ = imagePacker;

    static const char* className = "L@ohos/multimedia/image/image/ImagePackerInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found L@ohos/multimedia/image/image/ImagePacker;");
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        IMAGE_LOGE("Not found Class_FindMethod");
        return nullptr;
    }

    ani_object aniValue;
    if (ANI_OK != env->Object_New(cls, ctor, &aniValue, reinterpret_cast<ani_long>(imagePackerAni.release()))) {
        IMAGE_LOGE("New Context Fail");
    }
    return aniValue;
}

ImagePacker* GetImagePackerFromAniEnv([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    ani_status ret;
    ani_long nativeObj {};
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[GetImagePackerFromAniEnv] Object_GetField_Long fetch field ");
        return nullptr;
    }
    ImagePackerAni* imagePackerAni = reinterpret_cast<ImagePackerAni*>(nativeObj);
    if (!imagePackerAni) {
        IMAGE_LOGE("[GetImagePackerFromAniEnv] imagePackerAni field ");
        return nullptr;
    }
    return (imagePackerAni->nativeImagePacker_).get();
}

std::string ANIUtils_ANIStringToStdString(ani_env *env, ani_string ani_str)
{
    ani_size  strSize;
    env->String_GetUTF8Size(ani_str, &strSize);

    std::vector<char> buffer(strSize + 1); // +1 for null terminator
    char* utfBuffer = buffer.data();

    ani_size bytes_written = 0;
    env->String_GetUTF8(ani_str, utfBuffer, strSize + 1, &bytes_written);

    utfBuffer[bytes_written] = '\0';
    std::string content = std::string(utfBuffer);
    return content;
}

bool ParsePackingOptions([[maybe_unused]] ani_env* env, ani_object para, PackOption &packOpts, uint32_t &outBufferSize)
{
    ani_ref tmptest;
    if (ANI_OK != env->Object_CallMethodByName_Ref(para, "<get>format", ":Lstd/core/String;", &tmptest)) {
        IMAGE_LOGE("Object_CallMethodByName_Ref <get>format failed");
        return false;
    }
    std::string retStr = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(tmptest));
    ani_status ret;
    ani_ref qualityRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>quality", ":Lstd/core/Int;", &qualityRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild qualityRef:%{public}d", ret);
    }
    ani_int quality;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(qualityRef),
        "unboxed", ":I", &quality)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild quality:%{public}d", ret);
    }
    ani_ref bufferSizeRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para,
        "<get>bufferSize", ":Lstd/core/Int;", &bufferSizeRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild bufferSizeRef:%{public}d", ret);
    }
    ani_int bufferSize;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(bufferSizeRef),
        "unboxed", ":I", &bufferSize)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild bufferSize:%{public}d", ret);
    }
    ani_ref desiredDynamicRangeRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>desiredDynamicRange",
        ":Lstd/core/Int;", &desiredDynamicRangeRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild desiredDynamicRangeRef:%{public}d", ret);
    }
    ani_int desiredDynamicRange;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(desiredDynamicRangeRef),
        "unboxed", ":I", &desiredDynamicRange)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild desiredDynamicRange:%{public}d", ret);
    }
    ani_ref needsPackPropertiesRef;
    if (ANI_OK != (ret = env->Object_CallMethodByName_Ref(para, "<get>needsPackProperties",
        ":Lstd/core/Int;", &needsPackPropertiesRef))) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild needsPackPropertiesRef:%{public}d", ret);
    }
    ani_int needsPackProperties;
    if ((ret = env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(needsPackPropertiesRef),
        "unboxed", ":I", &needsPackProperties)) != ANI_OK) {
        IMAGE_LOGE("Object_CallMethodByName_Int Faild needsPackProperties:%{public}d", ret);
    }

    packOpts.format = retStr;
    packOpts.quality = static_cast<uint8_t>(quality);
    outBufferSize = bufferSize;
    return true;
}

ani_arraybuffer nativePackingWithPixelMap([[maybe_unused]] ani_env* env,
    [[maybe_unused]] ani_object obj, ani_object obj2, ani_object obj3)
{
    ImagePacker* imgPacker = GetImagePackerFromAniEnv(env, obj);
    if (!imgPacker) {
        IMAGE_LOGE("nativePackingWithPixelMap  isPacker null ");
        return nullptr;
    }
    PixelMap* pixelamp = ImageAniUtils::GetPixelMapFromEnv(env, obj2);
    if (!pixelamp) {
        IMAGE_LOGE("nativePackingWithPixelMap  pixmap null ");
        return nullptr;
    }
    ani_class optsClass;
    env->FindClass("L@ohos/multimedia/image/image/PackingOption;", &optsClass);
    ani_boolean isOpts;
    env->Object_InstanceOf(obj3, optsClass, &isOpts);
    if (!isOpts) {
        IMAGE_LOGE("nativePackingWithPixelMap  pixmap null ");
        return nullptr;
    } else {
        IMAGE_LOGE("nativePackingWithPixelMap  opts sucess ");
    }
    PackOption packOpts;
    uint32_t bufferSize = 0;
    if (!ParsePackingOptions(env, obj3, packOpts, bufferSize)) {
        IMAGE_LOGE("ParsePackingOptions  failed ");
        return nullptr;
    }
    std::unique_ptr<uint8_t[]> outBuffer = std::make_unique<uint8_t[]>(bufferSize);
    uint8_t* data = outBuffer.get();
    imgPacker->StartPacking(data, bufferSize, packOpts);
    imgPacker->AddImage(*(pixelamp));
    int64_t packedSize = 0;
    auto pacRes = imgPacker->FinalizePacking(packedSize);
    if (pacRes) {
        IMAGE_LOGE("FinalizePacking  failed: %{public}d", pacRes);
        return nullptr;
    }
    void* outData = static_cast<void*>(data);
    ani_arraybuffer arrayBuffer;
    env->CreateArrayBuffer(packedSize, &outData, &arrayBuffer);
    return arrayBuffer;
}

static void Release([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object obj)
{
    ani_long nativeObj {};
    bool ret;
    if ((ret = env->Object_GetFieldByName_Long(obj, "nativeObj", &nativeObj)) != ANI_OK) {
        IMAGE_LOGE("[Release] Object_GetField_Long fetch field ret:%{public}d", ret);
        return;
    }
    ImagePackerAni* imagePackerAni = reinterpret_cast<ImagePackerAni*>(nativeObj);
    if (imagePackerAni == nullptr) {
        IMAGE_LOGE("[Release] get ImagePackerAni failed");
    }
    imagePackerAni->nativeImagePacker_ = nullptr;
    return;
}

ani_status ImagePackerAni::Init(ani_env* env)
{
    static const char *className = "L@ohos/multimedia/image/image/ImagePackerInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        IMAGE_LOGE("Not found L@ohos/multimedia/image/image/ImagePacker;");
        return ANI_ERROR;
    }
    std::array methods = {
        ani_native_function {"nativePackingWithPixelMap",
            "L@ohos/multimedia/image/image/PixelMap;L@ohos/multimedia/image/image/PackingOption;:Lescompat/ArrayBuffer;",
            reinterpret_cast<void*>(OHOS::Media::nativePackingWithPixelMap)},
        ani_native_function {"nativeRelease", ":V", reinterpret_cast<void*>(OHOS::Media::Release)},
    };
    ani_status ret = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ANI_OK != ret) {
        IMAGE_LOGE("[ImagePackerAni] Cannot bind native methods ret: %{public}d", ret);
        return ANI_ERROR;
    };
    return ANI_OK;
}
} // Media
} // OHOS