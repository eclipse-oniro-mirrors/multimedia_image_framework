/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "my_pixel_map.h"
#include "media_errors.h"
#include "image_log.h"
#include "image_napi_utils.h"
#include "image_pixel_map_napi.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "MyPixelMapNapiTest"

namespace {
constexpr uint32_t TEST_ARG_SUM = 1;
}
namespace OHOS {
namespace Media {
static const std::string CLASS_NAME = "MyPixelMap";
napi_ref MyPixelMap::sConstructor_ = nullptr;
MyPixelMap::MyPixelMap():env_(nullptr)
{
}

MyPixelMap::~MyPixelMap()
{
}

napi_value MyPixelMap::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor props[] = {
    };

    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("testGetImageInfo", TestGetImageInfo),
        DECLARE_NAPI_STATIC_FUNCTION("testAccessPixels", TestAccessPixels),
        DECLARE_NAPI_STATIC_FUNCTION("testUnAccessPixels", TestUnAccessPixels),
    };

    napi_value constructor = nullptr;

    if (napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr, IMG_ARRAY_SIZE(props),
        props, &constructor) != napi_ok) {
        IMAGE_LOGE("define class fail");
        return nullptr;
    }

    if (napi_create_reference(env, constructor, 1, &sConstructor_) != napi_ok) {
        IMAGE_LOGE("create reference fail");
        return nullptr;
    }

    if (napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor) != napi_ok) {
        IMAGE_LOGE("set named property fail");
        return nullptr;
    }

    if (napi_define_properties(env, exports, IMG_ARRAY_SIZE(static_prop), static_prop) != napi_ok) {
        IMAGE_LOGE("define properties fail");
        return nullptr;
    }

    IMAGE_LOGD("Init success");
    return exports;
}

napi_value MyPixelMap::Constructor(napi_env env, napi_callback_info info)
{
    IMAGE_LOGD("Constructor IN");
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &thisVar);

    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    IMAGE_LOGD("Constructor OUT");
    return thisVar;
}

napi_value MyPixelMap::TestGetImageInfo(napi_env env, napi_callback_info info)
{
    IMAGE_LOGD("TestGetImageInfo IN");

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[TEST_ARG_SUM] = {0};
    size_t argCount = TEST_ARG_SUM;

    status = napi_get_cb_info(env, info, &argCount, argValue, &thisVar, nullptr);
    if (status != napi_ok) {
        IMAGE_LOGE("napi_get_cb_info fail");
    }

    IMAGE_LOGD("OH_GetImageInfo Test|Begin");
    OhosPixelMapInfo pixelMapInfo;
    int32_t res = OH_GetImageInfo(env, argValue[0], &pixelMapInfo);
    IMAGE_LOGD("OH_GetImageInfo Test|End, res=%{public}d", res);
    IMAGE_LOGD("OH_GetImageInfo, w=%{public}u, h=%{public}u, r=%{public}u, f=%{public}d",
        pixelMapInfo.width, pixelMapInfo.height, pixelMapInfo.rowSize, pixelMapInfo.pixelFormat);

    IMAGE_LOGD("TestGetImageInfo OUT");
    return result;
}

napi_value MyPixelMap::TestAccessPixels(napi_env env, napi_callback_info info)
{
    IMAGE_LOGD("TestAccessPixels IN");

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[TEST_ARG_SUM] = {0};
    size_t argCount = TEST_ARG_SUM;

    status = napi_get_cb_info(env, info, &argCount, argValue, &thisVar, nullptr);
    if (status != napi_ok) {
        IMAGE_LOGE("napi_get_cb_info fail");
    }

    IMAGE_LOGD("OH_AccessPixels Test|Begin");
    void* addrPtr = nullptr;
    int32_t res = OH_AccessPixels(env, argValue[0], &addrPtr);
    IMAGE_LOGD("OH_AccessPixels Test|End, res=%{public}d", res);

    IMAGE_LOGD("TestAccessPixels OUT");
    return result;
}

napi_value MyPixelMap::TestUnAccessPixels(napi_env env, napi_callback_info info)
{
    IMAGE_LOGD("TestUnAccessPixels IN");

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[TEST_ARG_SUM] = {0};
    size_t argCount = TEST_ARG_SUM;

    status = napi_get_cb_info(env, info, &argCount, argValue, &thisVar, nullptr);
    if (status != napi_ok) {
        IMAGE_LOGE("napi_get_cb_info fail");
    }

    IMAGE_LOGD("OH_UnAccessPixels Test|Begin");
    int32_t res = OH_UnAccessPixels(env, argValue[0]);
    IMAGE_LOGD("OH_UnAccessPixels Test|End, res=%{public}d", res);

    IMAGE_LOGD("TestUnAccessPixels OUT");
    return result;
}

/*
 * Function registering all props and functions of ohos.medialibrary module
 */
static napi_value Export(napi_env env, napi_value exports)
{
    IMAGE_LOGI("MyPixelMap CALL");
    MyPixelMap::Init(env, exports);
    return exports;
}

/*
 * module define
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Export,
    .nm_modname = "xtstest.mypixelmap",
    .nm_priv = ((void*)0),
    .reserved = {0}
};

/*
 * module register
 */
extern "C" __attribute__((constructor)) void MyPixelMapRegisterModule(void)
{
    napi_module_register(&g_module);
}
}  // namespace Media
}  // namespace OHOS
