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

#include "image_common.h"
#include "image_error_convert.h"
#include "image_log.h"
#include "image_napi_utils.h"
#include "image_type.h"
#include "media_errors.h"
#include "securec.h"
#include "xmp_metadata_napi.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "XMPMetadataNapi"

namespace {
constexpr uint32_t NUM_0 = 0;
constexpr uint32_t NUM_1 = 1;
constexpr uint32_t NUM_2 = 2;
constexpr uint32_t NUM_3 = 3;

static std::vector<struct OHOS::Media::ImageEnum> sXMPTagType = {
    {"UNKNOWN", 0, ""},
    {"SIMPLE", 1, ""},
    {"UNORDERED_ARRAY", 2, ""},
    {"ORDERED_ARRAY", 3, ""},
    {"ALTERNATE_ARRAY", 4, ""},
    {"ALTERNATE_TEXT", 5, ""},
    {"STRUCTURE", 6, ""},
    {"QUALIFIER", 7, ""}
};

struct JsXMPTag {
    napi_value xmlns;
    napi_value prefix;
    napi_value name;
    napi_value type;
    napi_value value;
};

struct XMPMetadataAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    uint32_t status;
    std::string errMsg;
    OHOS::Media::XMPMetadataNapi *xmpMetadataNapi;
    std::shared_ptr<OHOS::Media::XMPMetadata> rXMPMetadata;
    std::string xmlns;
    std::string prefix;
    OHOS::Media::XMPTagType tagType = OHOS::Media::XMPTagType::UNKNOWN;
    std::string tagValue;
    std::string path;
    OHOS::Media::XMPTag tag;
    napi_value callbackValue = nullptr;
    std::string rootPath;
    OHOS::Media::XMPEnumerateOption options;
    void *arrayBuffer = nullptr;
    size_t arrayBufferSize = 0;
    std::vector<std::pair<std::string, OHOS::Media::XMPTag>> tags;
};

// Structure to hold callback information for EnumerateTags
struct EnumerateTagsCallbackContext {
    napi_env env = nullptr;
    napi_ref callbackRef = nullptr;
};
}

namespace OHOS {
namespace Media {
static const std::string CLASS_NAME = "XMPMetadata";
thread_local napi_ref XMPMetadataNapi::sConstructor_ = nullptr;
thread_local std::shared_ptr<XMPMetadata> XMPMetadataNapi::sXMPMetadata_ = nullptr;
thread_local bool XMPMetadataNapi::sIsExplicitCreate_ = false;

XMPMetadataNapi::XMPMetadataNapi() : env_(nullptr)
{
    static std::atomic<uint32_t> currentId = 0;
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
}

XMPMetadataNapi::~XMPMetadataNapi()
{
    Release();
}

napi_status XMPMetadataNapi::DefineClassProperties(napi_env env, napi_value &constructor)
{
    napi_property_descriptor props[] = {
        DECLARE_NAPI_FUNCTION("registerNamespacePrefix", RegisterNamespacePrefix),
        DECLARE_NAPI_FUNCTION("setValue", SetValue),
        DECLARE_NAPI_FUNCTION("getTag", GetTag),
        DECLARE_NAPI_FUNCTION("removeTag", RemoveTag),
        DECLARE_NAPI_FUNCTION("enumerateTags", EnumerateTags),
        DECLARE_NAPI_FUNCTION("getTags", GetTags),
        DECLARE_NAPI_FUNCTION("setBlob", SetBlob),
        DECLARE_NAPI_FUNCTION("getBlob", GetBlob),
    };

    return napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                            Constructor, nullptr, IMG_ARRAY_SIZE(props),
                            props, &constructor);
}

napi_status XMPMetadataNapi::DefineStaticProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_PROPERTY("XMP_BASIC", CreateXMPNamespace(env, NS_XMP_BASIC, PF_XMP_BASIC)),
        DECLARE_NAPI_PROPERTY("XMP_RIGHTS", CreateXMPNamespace(env, NS_XMP_RIGHTS, PF_XMP_RIGHTS)),
        DECLARE_NAPI_PROPERTY("EXIF", CreateXMPNamespace(env, NS_EXIF, PF_EXIF)),
        DECLARE_NAPI_PROPERTY("DUBLIN_CORE", CreateXMPNamespace(env, NS_DC, PF_DC)),
        DECLARE_NAPI_PROPERTY("TIFF", CreateXMPNamespace(env, NS_TIFF, PF_TIFF)),
        DECLARE_NAPI_PROPERTY("XMPTagType", ImageNapiUtils::CreateEnumTypeObject(env, napi_number, sXMPTagType)),
    };

    return napi_define_properties(env, exports, IMG_ARRAY_SIZE(static_prop), static_prop);
}

napi_value XMPMetadataNapi::Init(napi_env env, napi_value exports)
{
    napi_value constructor = nullptr;
    int32_t refCount = 1;

    napi_status status = DefineClassProperties(env, constructor);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Define class fail"));

    status = napi_create_reference(env, constructor, refCount, &sConstructor_);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Create reference fail"));

    auto ctorContext = new NapiConstructorContext();
    ctorContext->env_ = env;
    ctorContext->ref_ = sConstructor_;
    napi_add_env_cleanup_hook(env, ImageNapiUtils::CleanUpConstructorContext, ctorContext);

    napi_value global = nullptr;
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_get_global(env, &global)),
        nullptr, IMAGE_LOGE("Init:get global fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_set_named_property(env, global, CLASS_NAME.c_str(), constructor)),
        nullptr, IMAGE_LOGE("Init:set global named property fail")
    );

    status = napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Set named property fail"));

    status = DefineStaticProperties(env, exports);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Define static properties fail"));

    IMAGE_LOGD("Init success");
    return exports;
}

napi_value XMPMetadataNapi::CreateXMPMetadata(napi_env env, std::shared_ptr<XMPMetadata> &xmpMetadata)
{
    if (sConstructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        XMPMetadataNapi::Init(env, exports);
    }

    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    IMAGE_LOGD("CreateXMPMetadata IN");
    napi_status status = napi_get_reference_value(env, sConstructor_, &constructor);
    CHECK_ERROR_RETURN_RET_LOG(!IMG_IS_OK(status), result, "%{public}s Get constructor failed", __func__);
    CHECK_ERROR_RETURN_RET_LOG(xmpMetadata == nullptr, result, "%{public}s xmpMetadata is nullptr", __func__);

    sXMPMetadata_ = xmpMetadata;
    sIsExplicitCreate_ = true;
    status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
    sIsExplicitCreate_ = false;
    CHECK_ERROR_RETURN_RET_LOG(!IMG_IS_OK(status), result, "%{public}s New instance could not be obtained", __func__);
    return result;
}

std::shared_ptr<XMPMetadata> XMPMetadataNapi::GetXMPMetadata(napi_env env, napi_value xmpMetadata)
{
    std::unique_ptr<XMPMetadataNapi> xmpMetadataNapi = nullptr;

    napi_status status = napi_unwrap(env, xmpMetadata, reinterpret_cast<void**>(&xmpMetadataNapi));
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("GetXMPMetadata napi unwrap failed, status is %{public}d", status);
        return nullptr;
    }

    if (xmpMetadataNapi == nullptr) {
        IMAGE_LOGE("GetXMPMetadata xmpMetadataNapi is nullptr");
        return nullptr;
    }

    auto xmpMetadataNapiPtr = xmpMetadataNapi.release();
    if (xmpMetadataNapiPtr == nullptr) {
        IMAGE_LOGE("GetXMPMetadata xmpMetadataNapi is nullptr");
        return nullptr;
    }
    return xmpMetadataNapiPtr->nativeXMPMetadata_;
}

std::shared_ptr<XMPMetadata> XMPMetadataNapi::GetNativeXMPMetadata()
{
    return nativeXMPMetadata_;
}

napi_value XMPMetadataNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &thisVar);
    IMAGE_LOGD("Constructor IN");
    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    IMG_NAPI_CHECK_RET(IMG_IS_READY(status, thisVar), undefineVar);

    std::unique_ptr<XMPMetadataNapi> pXMPMetadataNapi = std::make_unique<XMPMetadataNapi>();
    if (pXMPMetadataNapi != nullptr) {
        pXMPMetadataNapi->env_ = env;

        // Check if this is an explicit CreateXMPMetadata call or direct 'new' call
        if (sIsExplicitCreate_) {
            // Called from CreateXMPMetadata, must have valid sXMPMetadata_
            pXMPMetadataNapi->nativeXMPMetadata_ = sXMPMetadata_;
            if (pXMPMetadataNapi->nativeXMPMetadata_ == nullptr) {
                IMAGE_LOGE("CreateXMPMetadata called with null XMPMetadata pointer");
                return undefineVar;
            }
        } else {
            // Direct 'new XMPMetadata()' call, create a new default instance
            IMAGE_LOGD("Creating new default XMPMetadata instance for direct 'new' constructor");
            pXMPMetadataNapi->nativeXMPMetadata_ = std::make_shared<XMPMetadata>();
        }

        // Clear the thread-local storage after use
        sXMPMetadata_ = nullptr;

        status = napi_wrap(env, thisVar, reinterpret_cast<void *>(pXMPMetadataNapi.release()),
                           XMPMetadataNapi::Destructor, nullptr, nullptr);
        if (status != napi_ok) {
            IMAGE_LOGE("Failure wrapping js to native napi");
            return undefineVar;
        }
    }
    return thisVar;
}

void XMPMetadataNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        IMAGE_LOGD("Destructor XMPMetadataNapi");
        delete reinterpret_cast<XMPMetadataNapi*>(nativeObject);
        nativeObject = nullptr;
    }
}

void XMPMetadataNapi::Release()
{
    if (!isRelease) {
        if (nativeXMPMetadata_ != nullptr) {
            nativeXMPMetadata_ = nullptr;
        }
        isRelease = true;
    }
}

napi_value XMPMetadataNapi::CreateXMPNamespace(napi_env env, const std::string &uri, const std::string &prefix)
{
    napi_value namespaceObj = nullptr;
    napi_create_object(env, &namespaceObj);

    napi_value uriValue, prefixValue;
    napi_create_string_utf8(env, uri.c_str(), uri.length(), &uriValue);
    napi_create_string_utf8(env, prefix.c_str(), prefix.length(), &prefixValue);

    napi_set_named_property(env, namespaceObj, "uri", uriValue);
    napi_set_named_property(env, namespaceObj, "prefix", prefixValue);

    return namespaceObj;
}

static napi_value CreateJsXMPTag(napi_env env, const XMPTag &tag)
{
    napi_value tagObj = nullptr;
    napi_create_object(env, &tagObj);

    JsXMPTag jsTag;
    napi_create_string_utf8(env, tag.xmlns.c_str(), tag.xmlns.length(), &jsTag.xmlns);
    if (!tag.prefix.empty()) {
        napi_create_string_utf8(env, tag.prefix.c_str(), tag.prefix.length(), &jsTag.prefix);
    } else {
        napi_get_undefined(env, &jsTag.prefix);
    }
    napi_create_string_utf8(env, tag.name.c_str(), tag.name.length(), &jsTag.name);
    napi_create_int32(env, static_cast<int32_t>(tag.type), &jsTag.type);
    if (!tag.value.empty()) {
        napi_create_string_utf8(env, tag.value.c_str(), tag.value.length(), &jsTag.value);
    } else {
        napi_get_undefined(env, &jsTag.value);
    }

    napi_set_named_property(env, tagObj, "xmlns", jsTag.xmlns);
    napi_set_named_property(env, tagObj, "prefix", jsTag.prefix);
    napi_set_named_property(env, tagObj, "name", jsTag.name);
    napi_set_named_property(env, tagObj, "type", jsTag.type);
    napi_set_named_property(env, tagObj, "value", jsTag.value);

    return tagObj;
}

static void CommonCallbackRoutine(napi_env env, XMPMetadataAsyncContext* &context, const napi_value &valueParam)
{
    if (context == nullptr) {
        IMAGE_LOGE("context is nullptr");
        return;
    }

    napi_value result[NUM_2] = {0};
    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        IMAGE_LOGE("Failed to open handle scope");
        return;
    }

    if (context->status == SUCCESS) {
        result[NUM_1] = valueParam;
    } else {
        const auto &&[errorCode, errMsg] = OHOS::Media::ImageErrorConvert::XMPMetadataMakeErrMsg(context->status);
        OHOS::Media::ImageNapiUtils::CreateErrorObj(env, result[NUM_0], errorCode, errMsg);
    }

    if (context->deferred) {
        if (context->status == SUCCESS) {
            napi_resolve_deferred(env, context->deferred, result[NUM_1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[NUM_0]);
        }
    }

    napi_delete_async_work(env, context->work);
    napi_close_handle_scope(env, scope);

    delete context;
    context = nullptr;
}

static void SetValueExecute(napi_env env, void *data)
{
    IMAGE_LOGD("SetValueExecute IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    CHECK_ERROR_RETURN_LOG(context->rXMPMetadata == nullptr, "%{public}s XMP metadata is null", __func__);
    context->status = context->rXMPMetadata->SetValue(context->path, context->tagType, context->tagValue);
}

static void SetValueComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("SetValueComplete IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    CommonCallbackRoutine(env, context, result);
}

napi_value XMPMetadataNapi::SetValue(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_3] = {0};
    size_t argCount = NUM_3;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to napi_get_cb_info"));
    if (argCount < NUM_2 || argCount > NUM_3) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER, "Invalid argument count");
    }

    std::unique_ptr<XMPMetadataAsyncContext> asyncContext = std::make_unique<XMPMetadataAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->xmpMetadataNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->xmpMetadataNapi), result,
        IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rXMPMetadata = asyncContext->xmpMetadataNapi->GetNativeXMPMetadata();
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rXMPMetadata), result,
        IMAGE_LOGE("Empty native XMPMetadata"));

    // Parse arguments
    asyncContext->path = ImageNapiUtils::GetStringArgument(env, argValue[NUM_0]);
    int32_t typeValue;
    napi_get_value_int32(env, argValue[NUM_1], &typeValue);
    asyncContext->tagType = static_cast<XMPTagType>(typeValue);
    if (argCount == NUM_3) {
        asyncContext->tagValue = ImageNapiUtils::GetStringArgument(env, argValue[NUM_2]);
        IMAGE_LOGD("SetValue path: %{public}s, tagType: %{public}d, tagValue: %{public}s",
            asyncContext->path.c_str(), static_cast<int32_t>(asyncContext->tagType), asyncContext->tagValue.c_str());
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "SetValue",
        SetValueExecute, SetValueComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Failed to create async work"));
    return result;
}

static void GetTagExecute(napi_env env, void *data)
{
    IMAGE_LOGD("GetTagExecute IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    context->status = context->rXMPMetadata->GetTag(context->path, context->tag);
}

static void GetTagComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("GetTagComplete IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    napi_value result = nullptr;
    if (context->status == SUCCESS) {
        result = CreateJsXMPTag(env, context->tag);
        context->status = SUCCESS;
    } else if (context->status == ERR_XMP_TAG_NOT_FOUND) {
        napi_get_null(env, &result);
        context->status = SUCCESS;
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value XMPMetadataNapi::GetTag(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to napi_get_cb_info"));
    if (argCount != NUM_1) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER, "Invalid argument count");
    }

    std::unique_ptr<XMPMetadataAsyncContext> asyncContext = std::make_unique<XMPMetadataAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->xmpMetadataNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->xmpMetadataNapi), result,
        IMAGE_LOGE("Fail to unwrap XMPMetadataNapi"));
    asyncContext->rXMPMetadata = asyncContext->xmpMetadataNapi->GetNativeXMPMetadata();
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rXMPMetadata), result,
        IMAGE_LOGE("Empty native XMPMetadata instance"));

    asyncContext->path = ImageNapiUtils::GetStringArgument(env, argValue[NUM_0]);
    IMAGE_LOGD("GetTag path: %{public}s", asyncContext->path.c_str());

    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetTag",
        GetTagExecute, GetTagComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Failed to create async work"));
    return result;
}

static void RemoveTagExecute(napi_env env, void *data)
{
    IMAGE_LOGD("RemoveTagExecute IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    context->status = context->rXMPMetadata->RemoveTag(context->path);
}

static void RemoveTagComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("RemoveTagComplete IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    CommonCallbackRoutine(env, context, result);
}

napi_value XMPMetadataNapi::RemoveTag(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to napi_get_cb_info"));
    if (argCount != NUM_1) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER, "Invalid argument count");
    }

    std::unique_ptr<XMPMetadataAsyncContext> asyncContext = std::make_unique<XMPMetadataAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->xmpMetadataNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->xmpMetadataNapi), result,
        IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rXMPMetadata = asyncContext->xmpMetadataNapi->GetNativeXMPMetadata();
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rXMPMetadata), result,
        IMAGE_LOGE("Empty native XMPMetadata"));

    asyncContext->path = ImageNapiUtils::GetStringArgument(env, argValue[NUM_0]);
    IMAGE_LOGD("RemoveTag path: %{public}s", asyncContext->path.c_str());

    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "RemoveTag",
        RemoveTagExecute, RemoveTagComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Failed to create async work"));
    return result;
}

static void RegisterNamespacePrefixExecute(napi_env env, void *data)
{
    IMAGE_LOGD("RegisterNamespacePrefixExecute IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    context->status = context->rXMPMetadata->RegisterNamespacePrefix(context->xmlns, context->prefix);
}

static void RegisterNamespacePrefixComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("RegisterNamespacePrefixComplete IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    CommonCallbackRoutine(env, context, result);
}

napi_value XMPMetadataNapi::RegisterNamespacePrefix(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to napi_get_cb_info"));
    if (argCount != NUM_2) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER, "Invalid argument count");
    }

    std::unique_ptr<XMPMetadataAsyncContext> asyncContext = std::make_unique<XMPMetadataAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->xmpMetadataNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->xmpMetadataNapi), result,
        IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rXMPMetadata = asyncContext->xmpMetadataNapi->GetNativeXMPMetadata();
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rXMPMetadata), result,
        IMAGE_LOGE("Empty native XMPMetadata"));

    asyncContext->xmlns = ImageNapiUtils::GetStringArgument(env, argValue[NUM_0]);
    asyncContext->prefix = ImageNapiUtils::GetStringArgument(env, argValue[NUM_1]);

    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "RegisterNamespacePrefix",
        RegisterNamespacePrefixExecute, RegisterNamespacePrefixComplete,
        asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Failed to create async work"));
    return result;
}

static void ParseEnumerateTagsOptions(napi_env env, napi_value root, XMPEnumerateOption &option)
{
    if (ImageNapiUtils::GetBoolByName(env, root, "isRecursive", &option.isRecursive)) {
        IMAGE_LOGD("%{public}s: isRecursive: %{public}d", __func__, option.isRecursive);
    }
}

static auto CreateEnumerateTagsCallback(std::shared_ptr<EnumerateTagsCallbackContext> &callbackContext)
{
    auto innerCallback = [callbackContext](const std::string &path, const XMPTag &tag) -> bool {
        napi_env env = callbackContext->env;
        napi_handle_scope scope = nullptr;
        napi_status status = napi_open_handle_scope(env, &scope);
        if (status != napi_ok) {
            IMAGE_LOGE("%{public}s Failed to open handle scope in callback", __func__);
            return false;
        }

        // Get the callback function
        bool shouldContinue = true;
        napi_value callback = nullptr;
        status = napi_get_reference_value(env, callbackContext->callbackRef, &callback);
        if (status != napi_ok || callback == nullptr) {
            IMAGE_LOGE("%{public}s Failed to get callback reference value", __func__);
            napi_close_handle_scope(env, scope);
            return false;
        }

        // Prepare callback arguments
        napi_value pathValue = nullptr;
        napi_create_string_utf8(env, path.c_str(), path.length(), &pathValue);
        napi_value tagValue = CreateJsXMPTag(env, tag);
        napi_value args[NUM_2] = { pathValue, tagValue };

        // Call the JavaScript callback
        napi_value returnValue = nullptr;
        napi_value global = nullptr;
        napi_get_global(env, &global);

        status = napi_call_function(env, global, callback, NUM_2, args, &returnValue);
        if (status != napi_ok) {
            IMAGE_LOGE("%{public}s Failed to call JavaScript callback", __func__);
            napi_close_handle_scope(env, scope);
            return false;
        }

        // Get the return value (boolean)
        if (returnValue != nullptr) {
            napi_valuetype returnType = ImageNapiUtils::getType(env, returnValue);
            if (returnType == napi_boolean) {
                napi_get_value_bool(env, returnValue, &shouldContinue);
            } else {
                // If return value is not boolean, default to true (continue)
                shouldContinue = true;
            }
        }

        napi_close_handle_scope(env, scope);
        return shouldContinue;
    };
    return innerCallback;
}

static bool ProcessEnumerateTags(napi_env env, std::unique_ptr<XMPMetadataAsyncContext> &context,
    std::shared_ptr<XMPMetadata> &nativePtr)
{
    // Create a persistent reference to the callback
    napi_ref callbackRef = nullptr;
    napi_status status = napi_create_reference(env, context->callbackValue, 1, &callbackRef);
    if (status != napi_ok || callbackRef == nullptr) {
        IMAGE_LOGE("%{public}s Failed to create callback reference", __func__);
        return false;
    }

    // Create callback context
    auto callbackContext = std::make_shared<EnumerateTagsCallbackContext>();
    callbackContext->env = env;
    callbackContext->callbackRef = callbackRef;

    // Define the C++ callback that will be passed to the inner layer
    auto innerCallback = CreateEnumerateTagsCallback(callbackContext);

    // Call the inner layer EnumerateTags synchronously
    context->status = nativePtr->EnumerateTags(innerCallback, context->rootPath, context->options);
    napi_delete_reference(env, callbackRef);
    return context->status == SUCCESS;
}

napi_value XMPMetadataNapi::EnumerateTags(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    IMAGE_LOGD("EnumerateTags called");

    // Parse arguments
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argc = NUM_3;
    napi_value argv[NUM_3] = {0};
    IMG_JS_ARGS(env, info, status, argc, argv, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to napi_get_cb_info"));
    // At least callback is required
    if (argc < NUM_1) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER,
            "Invalid argument count, at least callback is required");
    }

    // Unwrap native object
    std::unique_ptr<XMPMetadataAsyncContext> context = std::make_unique<XMPMetadataAsyncContext>();
    CHECK_ERROR_RETURN_RET_LOG(context == nullptr, result, "Fail to create context");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&context->xmpMetadataNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->xmpMetadataNapi), result, IMAGE_LOGE("Fail to unwrap context"));
    std::shared_ptr<XMPMetadata> nativePtr = context->xmpMetadataNapi->nativeXMPMetadata_;
    if (!nativePtr) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER, "Native XMPMetadata is null");
    }

    // First parameter must be callback function
    napi_valuetype type0 = ImageNapiUtils::getType(env, argv[0]);
    if (type0 != napi_function) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER,
            "First argument must be a callback function");
    }
    context->callbackValue = argv[0];

    // Check remaining parameters
    if (argc >= NUM_2) {
        napi_valuetype type1 = ImageNapiUtils::getType(env, argv[1]);
        if (type1 == napi_string) {
            context->rootPath = ImageNapiUtils::GetStringArgument(env, argv[1]);
            IMAGE_LOGD("%{public}s: rootPath: %{public}s", __func__, context->rootPath.c_str());
        }

        // Check for options parameter
        if (argc >= NUM_3) {
            ParseEnumerateTagsOptions(env, argv[NUM_2], context->options);
        }
    }

    if (!ProcessEnumerateTags(env, context, nativePtr)) {
        const auto &&[errorCode, errMsg] = OHOS::Media::ImageErrorConvert::XMPMetadataMakeErrMsg(context->status);
        return ImageNapiUtils::ThrowExceptionError(env, errorCode, errMsg);
    }
    IMAGE_LOGD("EnumerateTags completed successfully");
    return result;
}

static void GetTagsExecute(napi_env env, void *data)
{
    IMAGE_LOGD("GetTagsExecute IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    CHECK_ERROR_RETURN_LOG(context->rXMPMetadata == nullptr, "%{public}s XMP metadata is null", __func__);
    context->status = context->rXMPMetadata->EnumerateTags([&context](const std::string &path, const XMPTag &tag) {
        context->tags.emplace_back(path, tag);
        return true;
    }, context->rootPath, context->options);
}

static void GetTagsComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("GetTagsComplete IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);

    napi_value result = nullptr;
    if (context->status == SUCCESS) {
        // Create JavaScript object (Record<string, XMPTag>)
        napi_create_object(env, &result);
        for (const auto &[path, tag] : context->tags) {
            napi_value tagObj = CreateJsXMPTag(env, tag);
            napi_set_named_property(env, result, path.c_str(), tagObj);
        }
    } else {
        napi_get_undefined(env, &result);
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value XMPMetadataNapi::GetTags(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argc = NUM_2;
    napi_value argv[NUM_2] = {0};
    IMG_JS_ARGS(env, info, status, argc, argv, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<XMPMetadataAsyncContext> asyncContext = std::make_unique<XMPMetadataAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->xmpMetadataNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->xmpMetadataNapi), result,
        IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rXMPMetadata = asyncContext->xmpMetadataNapi->GetNativeXMPMetadata();
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rXMPMetadata), result,
        IMAGE_LOGE("Empty native XMPMetadata"));

    // Parse optional arguments: rootPath and options
    if (argc >= NUM_1) {
        napi_valuetype type0 = ImageNapiUtils::getType(env, argv[0]);
        if (type0 == napi_string) {
            asyncContext->rootPath = ImageNapiUtils::GetStringArgument(env, argv[0]);
            IMAGE_LOGD("%{public}s: rootPath: %{public}s", __func__, asyncContext->rootPath.c_str());
        }

        if (argc >= NUM_2) {
            ParseEnumerateTagsOptions(env, argv[1], asyncContext->options);
        }
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetTags",
        GetTagsExecute, GetTagsComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Failed to create async work"));
    return result;
}

static void SetBlobExec(napi_env env, void* data)
{
    IMAGE_LOGD("SetBlobExec IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    CHECK_ERROR_RETURN_LOG(context->rXMPMetadata == nullptr, "%{public}s XMP metadata is null", __func__);
    context->status = context->rXMPMetadata->SetBlob(
        static_cast<const uint8_t*>(context->arrayBuffer), context->arrayBufferSize);
}

static void SetBlobComplete(napi_env env, napi_status status, void* data)
{
    IMAGE_LOGD("SetBlobComplete IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "%{public}s context is null", __func__);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    CommonCallbackRoutine(env, context, result);
}

napi_value XMPMetadataNapi::SetBlob(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to napi_get_cb_info"));
    if (argCount != NUM_1) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER, "Invalid argument count");
    }

    std::unique_ptr<XMPMetadataAsyncContext> asyncContext = std::make_unique<XMPMetadataAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->xmpMetadataNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->xmpMetadataNapi), result,
        IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rXMPMetadata = asyncContext->xmpMetadataNapi->GetNativeXMPMetadata();
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rXMPMetadata), result,
        IMAGE_LOGE("Empty native XMPMetadata"));

    // Parse argument
    status = napi_get_arraybuffer_info(env, argValue[NUM_0],
        &(asyncContext->arrayBuffer), &(asyncContext->arrayBufferSize));
    if (status != napi_ok || asyncContext->arrayBuffer == nullptr || asyncContext->arrayBufferSize == NUM_0) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER, "Invalid blob data");
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "SetBlob",
        SetBlobExec, SetBlobComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Failed to create async work"));
    return result;
}

static void GetBlobExec(napi_env env, void *data)
{
    IMAGE_LOGD("GetBlobExec IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "empty context");
    CHECK_ERROR_RETURN_LOG(context->rXMPMetadata == nullptr, "empty native XMPMetadata");
    std::string buffer;
    context->status = context->rXMPMetadata->GetBlob(buffer);
    CHECK_ERROR_RETURN_LOG(context->status != SUCCESS, "GetBlob failed");
    context->arrayBufferSize = buffer.size();
    context->arrayBuffer = new(std::nothrow) uint8_t[context->arrayBufferSize];
    if (context->arrayBuffer == nullptr) {
        context->status = ERR_MEDIA_MALLOC_FAILED;
        return;
    }
    if (memcpy_s(context->arrayBuffer, context->arrayBufferSize, buffer.data(), buffer.size()) != EOK) {
        context->status = ERR_MEMORY_COPY_FAILED;
        IMAGE_LOGE("%{public}s memcpy_s failed", __func__);
    }
}

static void GetBlobComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("GetBlobComplete IN");
    auto context = static_cast<XMPMetadataAsyncContext*>(data);
    CHECK_ERROR_RETURN_LOG(context == nullptr, "empty context");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (context->status == SUCCESS) {
        if (!ImageNapiUtils::CreateExternalArrayBuffer(env, context->arrayBuffer, context->arrayBufferSize, &result)) {
            delete[] static_cast<uint8_t*>(context->arrayBuffer);
            context->arrayBuffer = nullptr;
            context->arrayBufferSize = 0;
            context->status = ERR_MEDIA_MALLOC_FAILED;
            IMAGE_LOGE("%{public}s Fail to create napi external arraybuffer!", __func__);
            napi_get_undefined(env, &result);
        } else {
            context->arrayBuffer = nullptr;
            context->arrayBufferSize = 0;
        }
    } else {
        delete[] static_cast<uint8_t*>(context->arrayBuffer);
        context->arrayBuffer = nullptr;
        context->arrayBufferSize = 0;
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value XMPMetadataNapi::GetBlob(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar;
    IMG_JS_NO_ARGS(env, info, status, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, thisVar), result, IMAGE_LOGE("fail to get thisVar"));

    std::unique_ptr<XMPMetadataAsyncContext> asyncContext = std::make_unique<XMPMetadataAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->xmpMetadataNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->xmpMetadataNapi), result,
        IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rXMPMetadata = asyncContext->xmpMetadataNapi->GetNativeXMPMetadata();
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rXMPMetadata), result,
        IMAGE_LOGE("Empty native XMPMetadata"));

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetBlob",
        GetBlobExec, GetBlobComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Failed to create async work"));
    return result;
}
} // namespace Media
} // namespace OHOS