/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <map>
#include "metadata_napi.h"
#include "media_errors.h"
#include "image_log.h"
#include "image_napi_utils.h"
#include "napi_message_sequence.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "MetadataNapi"

namespace {
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
}

namespace OHOS {
namespace Media {
    static const std::string CLASS_NAME = "ImageMetadata";
    thread_local napi_ref MetadataNapi::sConstructor_ = nullptr;
    thread_local std::shared_ptr<ImageMetadata> MetadataNapi::sMetadata_ = nullptr;

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#endif

struct MetadataNapiAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    napi_ref error = nullptr;
    uint32_t status;
    MetadataNapi *nConstructor;
    std::shared_ptr<ImageMetadata> rMetadata;
    std::vector<std::string> keyStrArray;
    std::multimap<int32_t, std::string> errMsgArray;
    std::vector<std::pair<std::string, std::string>> KVSArray;
};
using MetadataNapiAsyncContextPtr = std::unique_ptr<MetadataNapiAsyncContext>;

MetadataNapi::MetadataNapi():env_(nullptr)
{
    static std::atomic<uint32_t> currentId = 0;
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
}

MetadataNapi::~MetadataNapi()
{
    release();
}

napi_status SetValueStr(napi_env env, std::string keyStr, std::string valueStr, napi_value &object)
{
    napi_value value = nullptr;
    napi_status status;
    if (valueStr != "") {
        status = napi_create_string_utf8(env, valueStr.c_str(), valueStr.length(), &value);
        if (status != napi_ok) {
            IMAGE_LOGE("Set Value failed %{public}d", status);
            return napi_invalid_arg;
        }
    } else {
        status = napi_get_null(env, &value);
        if (status != napi_ok) {
            IMAGE_LOGE("Set null failed %{public}d", status);
            return napi_invalid_arg;
        }
    }
    status = napi_set_named_property(env, object, keyStr.c_str(), value);
    if (status != napi_ok) {
        IMAGE_LOGE("Set Key failed %{public}d", status);
        return napi_invalid_arg;
    }
    IMAGE_LOGD("Set string value success.");
    return napi_ok;
}

napi_value SetArrayInfo(napi_env env, std::vector<std::pair<std::string, std::string>> recordParameters)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok) {
        IMAGE_LOGE("Create record failed %{public}d", status);
        return result;
    }

    for (size_t index = 0; index < recordParameters.size(); ++index) {
        status = SetValueStr(env, recordParameters[index].first, recordParameters[index].second, result);
        if (status != napi_ok) {
            IMAGE_LOGE("Set current record parameter failed %{public}d", status);
            continue;
        }
    }

    IMAGE_LOGD("Set record parameters info success.");
    return result;
}

static void CommonCallbackRoutine(napi_env env, MetadataNapiAsyncContext* &asyncContext, const napi_value &valueParam)
{
    napi_value result[NUM_2] = {0};

    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        return;
    }

    if (asyncContext == nullptr) {
        return;
    }
    if (asyncContext->status == SUCCESS) {
        result[NUM_1] = valueParam;
    } else if (asyncContext->error != nullptr) {
        napi_get_reference_value(env, asyncContext->error, &result[NUM_0]);
        napi_delete_reference(env, asyncContext->error);
    } else {
        napi_create_uint32(env, asyncContext->status, &result[NUM_0]);
    }

    if (asyncContext->deferred) {
        if (asyncContext->status == SUCCESS) {
            napi_resolve_deferred(env, asyncContext->deferred, result[NUM_1]);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, result[NUM_0]);
        }
    }

    napi_delete_async_work(env, asyncContext->work);
    napi_close_handle_scope(env, scope);

    delete asyncContext;
    asyncContext = nullptr;
}

napi_value MetadataNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor props[] = {
        DECLARE_NAPI_FUNCTION("getProperties", GetProperties),
        DECLARE_NAPI_FUNCTION("setProperties", SetProperties),
        DECLARE_NAPI_FUNCTION("getAllProperties", GetAllProperties),
        DECLARE_NAPI_FUNCTION("clone", Clone),
    };
    napi_property_descriptor static_prop[] = {};

    napi_value constructor = nullptr;

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                          Constructor, nullptr, IMG_ARRAY_SIZE(props),
                          props, &constructor)),
        nullptr, IMAGE_LOGE("Define class fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_create_reference(env, constructor, 1, &sConstructor_)),
        nullptr, IMAGE_LOGE("Create reference fail")
    );

    napi_value global = nullptr;
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_get_global(env, &global)),
        nullptr, IMAGE_LOGE("Init:get global fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_set_named_property(env, global, CLASS_NAME.c_str(), constructor)),
        nullptr, IMAGE_LOGE("Init:set global named property fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor)),
        nullptr, IMAGE_LOGE("Set named property fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_properties(env, exports, IMG_ARRAY_SIZE(static_prop), static_prop)),
        nullptr, IMAGE_LOGE("Define properties fail")
    );

    IMAGE_LOGD("Init success");
    return exports;
}

napi_value MetadataNapi::CreateMetadata(napi_env env, std::shared_ptr<ImageMetadata> metadata)
{
    if (sConstructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        MetadataNapi::Init(env, exports);
    }

    napi_value constructor = nullptr;
    napi_value result = nullptr;
    IMAGE_LOGD("CreateMetadata IN");
    napi_status status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        sMetadata_ = metadata;
        status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
    }
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("CreateMetadata | New instance could not be obtained");
        napi_get_undefined(env, &result);
    }
    return result;
}

napi_value MetadataNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &thisVar);
    IMAGE_LOGD("Constructor IN");
    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    IMG_NAPI_CHECK_RET(IMG_IS_READY(status, thisVar), undefineVar);
    std::unique_ptr<MetadataNapi> pMetadataNapi = std::make_unique<MetadataNapi>();
    if (pMetadataNapi != nullptr) {
        pMetadataNapi->env_ = env;
        pMetadataNapi->nativeMetadata_ = sMetadata_;
        if (pMetadataNapi->nativeMetadata_  == nullptr) {
            IMAGE_LOGE("Failed to set nativeMetadata_ with null. Maybe a reentrancy error");
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void *>(pMetadataNapi.get()),
                           MetadataNapi::Destructor, nullptr, nullptr);
        if (status != napi_ok) {
            IMAGE_LOGE("Failure wrapping js to native napi");
            return undefineVar;
        }
    }
    pMetadataNapi.release();
    return thisVar;
}

void MetadataNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        IMAGE_LOGD("Destructor PictureNapi");
        delete reinterpret_cast<MetadataNapi*>(nativeObject);
        nativeObject = nullptr;
    }
}

static std::string GetStringArgument(napi_env env, napi_value value)
{
    std::string strValue = "";
    size_t bufLength = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, NUM_0, &bufLength);
    if (status == napi_ok && bufLength > NUM_0 && bufLength < PATH_MAX) {
        char *buffer = reinterpret_cast<char *>(malloc((bufLength + NUM_1) * sizeof(char)));
        if (buffer == nullptr) {
            IMAGE_LOGE("No memory");
            return strValue;
        }

        status = napi_get_value_string_utf8(env, value, buffer, bufLength + NUM_1, &bufLength);
        if (status == napi_ok) {
            IMAGE_LOGD("Get Success");
            strValue.assign(buffer, 0, bufLength + NUM_1);
        }
        if (buffer != nullptr) {
            free(buffer);
            buffer = nullptr;
        }
    }
    return strValue;
}

std::vector<std::string> GetStrArrayArgument(napi_env env, napi_value object)
{
    std::vector<std::string> keyStrArray;
    uint32_t arrayLen = 0;
    napi_status status = napi_get_array_length(env, object, &arrayLen);
    if (status != napi_ok) {
        IMAGE_LOGE("Get array length failed: %{public}d", status);
        return keyStrArray;
    }

    for (uint32_t i = 0; i < arrayLen; i++) {
        napi_value element;
        if (napi_get_element(env, object, i, &element) == napi_ok) {
            keyStrArray.emplace_back(GetStringArgument(env, element));
        }
    }
    IMAGE_LOGD("Get string argument success.");
    return keyStrArray;
}

std::vector<std::pair<std::string, std::string>> GetArrayArgument(napi_env env, napi_value object)
{
    std::vector<std::pair<std::string, std::string>> kVStrArray;
    napi_value recordNameList = nullptr;
    uint32_t recordCount = 0;
    napi_status status = napi_get_property_names(env, object, &recordNameList);
    if (status != napi_ok) {
        IMAGE_LOGE("Get recordNameList property names failed %{public}d", status);
        return kVStrArray;
    }
    status = napi_get_array_length(env, recordNameList, &recordCount);
    if (status != napi_ok) {
        IMAGE_LOGE("Get recordNameList array length failed %{public}d", status);
        return kVStrArray;
    }

    napi_value recordName = nullptr;
    napi_value recordValue = nullptr;
    for (uint32_t i = 0; i < recordCount; ++i) {
        status = napi_get_element(env, recordNameList, i, &recordName);
        if (status != napi_ok) {
            IMAGE_LOGE("Get recordName element failed %{public}d", status);
            continue;
        }
        std::string keyStr = GetStringArgument(env, recordName);
        status = napi_get_named_property(env, object, keyStr.c_str(), &recordValue);
        if (status != napi_ok) {
            IMAGE_LOGE("Get recordValue name property failed %{public}d", status);
            continue;
        }
        std::string valueStr = GetStringArgument(env, recordValue);
        kVStrArray.push_back(std::make_pair(keyStr, valueStr));
    }

    IMAGE_LOGD("Get record argument success.");
    return kVStrArray;
}

napi_value CreateErrorArray(napi_env env, std::multimap<std::int32_t, std::string> errMsgArray)
{
    napi_value result = nullptr;
    napi_status status = napi_create_array_with_length(env, errMsgArray.size(), &result);
    if (status != napi_ok) {
        IMAGE_LOGE("Malloc array buffer failed %{public}d", status);
        return result;
    }

    uint32_t index = 0;
    for (auto it = errMsgArray.begin(); it != errMsgArray.end(); ++it) {
        napi_value errMsgVal;
        napi_get_undefined(env, &errMsgVal);
        ImageNapiUtils::CreateErrorObj(env, errMsgVal, it->first,
            "The image source data is incorrect! exif key: " + it->second);
        status = napi_set_element(env, result, index, errMsgVal);
        if (status != napi_ok) {
            IMAGE_LOGE("Add error message to array failed %{public}d", status);
            continue;
        }
        ++index;
    }

    IMAGE_LOGD("Create obtain error array success.");
    return result;
}

static void GetPropertiesComplete(napi_env env, napi_status status, MetadataNapiAsyncContext *context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Context is nullptr");
        return;
    }

    napi_value result[NUM_2] = {0};

    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    if (context->status == SUCCESS) {
        result[NUM_1] = SetArrayInfo(env, context->KVSArray);
    } else {
        result[NUM_0] = CreateErrorArray(env, context->errMsgArray);
    }

    if (context->status == SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result[NUM_1]);
    } else {
        napi_reject_deferred(env, context->deferred, result[NUM_0]);
    }

    napi_delete_async_work(env, context->work);
    delete context;
    context = nullptr;
}

static void SetPropertiesComplete(napi_env env, napi_status status, MetadataNapiAsyncContext *context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Context is nullptr");
        return;
    }

    napi_value result[NUM_2] = {0};
    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    result[NUM_0] = CreateErrorArray(env, context->errMsgArray);
    if (context->status == SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result[NUM_1]);
    } else {
        napi_reject_deferred(env, context->deferred, result[NUM_0]);
    }
    
    napi_delete_async_work(env, context->work);

    delete context;
    context = nullptr;
}

static std::unique_ptr<MetadataNapiAsyncContext> UnwrapContext(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMAGE_LOGD("GetProperties argCount is [%{public}zu]", argCount);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> context = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&context->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));

    context->rMetadata = context->nConstructor->GetNativeMetadata();

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->rMetadata),
        nullptr, IMAGE_LOGE("Empty native rMetadata"));

    if (argCount != NUM_1) {
        IMAGE_LOGE("ArgCount mismatch");
        return nullptr;
    }
    if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_object) {
        context->keyStrArray = GetStrArrayArgument(env, argValue[NUM_0]);
        if (context->keyStrArray.size() == 0) {
            return nullptr;
        }
    } else {
        IMAGE_LOGE("Arg 0 type mismatch");
        return nullptr;
    }
    return context;
}

static std::unique_ptr<MetadataNapiAsyncContext> UnwrapContextForModify(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> context = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&context->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->nConstructor), nullptr, IMAGE_LOGE("Fail to unwrap context"));

    context->rMetadata = context->nConstructor->GetNativeMetadata();

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->rMetadata), nullptr, IMAGE_LOGE("Empty native rMetadata"));
    if (argCount != NUM_1) {
        IMAGE_LOGE("ArgCount mismatch");
        return nullptr;
    }
    if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_object) {
        context->KVSArray = GetArrayArgument(env, argValue[NUM_0]);
        if (context->KVSArray.size() == 0) {
            return nullptr;
        }
    } else {
        IMAGE_LOGE("Arg 0 type mismatch");
        return nullptr;
    }
    return context;
}

static void GetPropertiesExecute(napi_env env, void *data)
{
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    uint32_t status = SUCCESS;
    for (auto keyStrIt = context->keyStrArray.begin(); keyStrIt != context->keyStrArray.end(); ++keyStrIt) {
        std::string valueStr = "";
        status = context->rMetadata->GetValue(*keyStrIt, valueStr);
        if (status == SUCCESS) {
            context->KVSArray.emplace_back(std::make_pair(*keyStrIt, valueStr));
        } else {
            context->KVSArray.emplace_back(std::make_pair(*keyStrIt, ""));
            context->errMsgArray.insert(std::make_pair(status, *keyStrIt));
            IMAGE_LOGE("ErrCode: %{public}u , exif key: %{public}s", status, keyStrIt->c_str());
        }
    }
    context->status = context->KVSArray.size() == context->errMsgArray.size() ? ERROR : SUCCESS;
}

static void SetPropertiesExecute(napi_env env, void *data)
{
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    uint32_t status = SUCCESS;
    for (auto recordIterator = context->KVSArray.begin(); recordIterator != context->KVSArray.end();
        ++recordIterator) {
        IMAGE_LOGD("CheckExifDataValue");
        status = context->rMetadata->SetValue(recordIterator->first, recordIterator->second);
        IMAGE_LOGD("Check ret status: %{public}d", status);
        if (status != SUCCESS) {
            IMAGE_LOGE("There is invalid exif data parameter");
            context->errMsgArray.insert(std::make_pair(status, recordIterator->first));
            continue;
        }
    }
    context->status = context->errMsgArray.size() > 0 ? ERROR : SUCCESS;
}

static void CloneMetadataComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<MetadataNapiAsyncContext*>(data);

    if (context->rMetadata != nullptr) {
        result = MetadataNapi::CreateMetadata(env, context->rMetadata);
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value MetadataNapi::GetProperties(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = UnwrapContext(env, info);
    if (asyncContext == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Async context unwrap failed");
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetProperties",
        GetPropertiesExecute,
        reinterpret_cast<napi_async_complete_callback>(GetPropertiesComplete),
        asyncContext,
        asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

napi_value MetadataNapi::SetProperties(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = UnwrapContextForModify(env, info);
    if (asyncContext == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Async context unwrap failed");
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "SetProperties",
        SetPropertiesExecute,
        reinterpret_cast<napi_async_complete_callback>(SetPropertiesComplete),
        asyncContext,
        asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

napi_value MetadataNapi::GetAllProperties(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor), nullptr,
                         IMAGE_LOGE("Fail to unwrap context"));

    asyncContext->rMetadata = asyncContext->nConstructor->nativeMetadata_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rMetadata), nullptr, IMAGE_LOGE("Empty native rMetadata"));
    if (argCount != NUM_0) {
        IMAGE_LOGE("ArgCount mismatch");
        return nullptr;
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetAllProperties",
        [](napi_env env, void *data) {
            auto context = static_cast<MetadataNapiAsyncContext*>(data);
            if (context == nullptr) {
                IMAGE_LOGE("Empty context");
                return;
            }
            for (const auto &entry : *context->rMetadata->GetAllProperties()) {
                context->KVSArray.emplace_back(std::make_pair(entry.first, entry.second));
            }
            context->status = SUCCESS;
        }, reinterpret_cast<napi_async_complete_callback>(GetPropertiesComplete),
        asyncContext,
        asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

napi_value MetadataNapi::Clone(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor), nullptr,
                         IMAGE_LOGE("Fail to unwrap context"));

    asyncContext->rMetadata = asyncContext->nConstructor->nativeMetadata_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rMetadata), nullptr, IMAGE_LOGE("Empty native rMetadata"));
    if (argCount != NUM_0) {
        IMAGE_LOGE("ArgCount mismatch");
        return nullptr;
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "Clone",
        [](napi_env env, void *data) {
            auto context = static_cast<MetadataNapiAsyncContext*>(data);
            auto tmpixel = context->rMetadata->CloneMetadata();
            context->rMetadata = std::move(tmpixel);
            context->status = SUCCESS;
        }, CloneMetadataComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

void MetadataNapi::release()
{
    if (!isRelease) {
        if (nativeMetadata_ != nullptr) {
            nativeMetadata_ = nullptr;
        }
        isRelease = true;
    }
}
} // namespace Media
} // namespace OHOS