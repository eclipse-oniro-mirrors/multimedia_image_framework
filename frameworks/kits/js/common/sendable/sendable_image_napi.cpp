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

#include "sendable_image_napi.h"

#include "napi/native_node_api.h"
#include "image_log.h"
#include "media_errors.h"
#include "image_format.h"
#include "image_napi_utils.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "SendableImageNapi"

namespace {
    constexpr int NUM0 = 0;
    constexpr int NUM1 = 1;
    constexpr int NUM2 = 2;
    const std::string MY_NAME = "SendableImageNapi";
}

namespace OHOS {
namespace Media {
struct SendableImageAsyncContext {
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    napi_ref thisRef = nullptr;
    SendableImageNapi *napi = nullptr;
    uint32_t status;
    int32_t componentType;
    NativeImage* image = nullptr;
    NativeComponent* component = nullptr;
    bool isTestContext = false;
};
ImageHolderManager<NativeImage> SendableImageNapi::sNativeImageHolder_;
thread_local napi_ref SendableImageNapi::sConstructor_ = nullptr;

SendableImageNapi::SendableImageNapi()
{}

SendableImageNapi::~SendableImageNapi()
{
    NativeRelease();
}

void SendableImageNapi::NativeRelease()
{
    if (native_ != nullptr) {
        native_->release();
        native_ = nullptr;
    }
}

napi_value SendableImageNapi::Init(napi_env env, napi_value exports)
{
    IMAGE_FUNCTION_IN();
    napi_property_descriptor props[] = {
        DECLARE_NAPI_GETTER("clipRect", JSGetClipRect),
        DECLARE_NAPI_GETTER("size", JsGetSize),
        DECLARE_NAPI_GETTER("format", JsGetFormat),
        DECLARE_NAPI_GETTER("timestamp", JsGetTimestamp),
        DECLARE_NAPI_FUNCTION("getComponent", JsGetComponent),
        DECLARE_NAPI_FUNCTION("release", JsRelease),
    };
    size_t size = IMG_ARRAY_SIZE(props);
    napi_value thisVar = nullptr;
    auto name = MY_NAME.c_str();
    if (napi_define_sendable_class(env, name, SIZE_MAX, Constructor, nullptr, size, props, nullptr, &thisVar) != napi_ok) {
        IMAGE_ERR("Define class failed");
        return exports;
    }

    if (sConstructor_ != nullptr) {
        napi_delete_reference(env, sConstructor_);
        sConstructor_ = nullptr;
    }

    if (napi_create_reference(env, thisVar, NUM1, &sConstructor_) != napi_ok) {
        IMAGE_ERR("Create reference failed");
        return exports;
    }

    if (napi_set_named_property(env, exports, name, thisVar) != napi_ok) {
        IMAGE_ERR("Define class failed");
        return exports;
    }

    IMAGE_DEBUG("Init success");
    return exports;
}


std::shared_ptr<NativeImage> SendableImageNapi::GetNativeImage(napi_env env, napi_value image)
{
    SendableImageNapi* napi = nullptr;

    napi_status status = napi_unwrap_sendable(env, image, reinterpret_cast<void**>(&napi));
    if (!IMG_IS_OK(status) || napi == nullptr) {
        IMAGE_ERR("GetImage napi unwrap failed");
        return nullptr;
    }
    return napi->native_;
}

napi_value SendableImageNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value undefineVar;
    size_t argc = NUM1;
    napi_value argv[NUM1];

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &undefineVar);
    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok || thisVar == nullptr || argc != NUM1) {
        IMAGE_ERR("Constructor Failed to napi_get_cb_info");
        return undefineVar;
    }
    std::string id;
    if (!ImageNapiUtils::GetUtf8String(env, argv[NUM0], id) || (id.size() == NUM0)) {
        IMAGE_ERR("Failed to parse native image id");
        return undefineVar;
    }
    std::unique_ptr<SendableImageNapi> napi = std::make_unique<SendableImageNapi>();
    napi->native_ = sNativeImageHolder_.get(id);
    napi->isTestImage_ = false;
    if (napi->native_ == nullptr) {
        if (MY_NAME.compare(id.c_str()) == 0) {
            napi->isTestImage_ = true;
        } else {
            IMAGE_ERR("Failed to get native image");
            return undefineVar;
        }
    }
    status = napi_wrap_sendable(env, thisVar,
        reinterpret_cast<void *>(napi.get()), SendableImageNapi::Destructor, nullptr);
    if (status != napi_ok) {
        IMAGE_ERR("Failure wrapping js to native napi");
        return undefineVar;
    }

    napi.release();
    IMAGE_FUNCTION_OUT();
    return thisVar;
}

void SendableImageNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        delete reinterpret_cast<SendableImageNapi *>(nativeObject);
    }
}

napi_value SendableImageNapi::Create(napi_env env)
{
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_value argv[NUM1];

    IMAGE_FUNCTION_IN();
    if (env == nullptr) {
        IMAGE_ERR("Input args is invalid");
        return nullptr;
    }
    if (napi_get_reference_value(env, sConstructor_, &constructor) == napi_ok && constructor != nullptr) {
        if (napi_create_string_utf8(env, MY_NAME.c_str(), NAPI_AUTO_LENGTH, &(argv[NUM0])) != napi_ok) {
            IMAGE_ERR("Create native image id Failed");
        }
        if (napi_new_instance(env, constructor, NUM1, argv, &result) != napi_ok) {
            IMAGE_ERR("New instance could not be obtained");
        }
    }
    IMAGE_FUNCTION_OUT();
    return result;
}
napi_value SendableImageNapi::Create(napi_env env, std::shared_ptr<NativeImage> nativeImage)
{
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_value argv[NUM1];

    IMAGE_FUNCTION_IN();
    if (env == nullptr || nativeImage == nullptr) {
        IMAGE_ERR("Input args is invalid %{public}p vs %{public}p", env, nativeImage.get());
        return nullptr;
    }
    if (napi_get_reference_value(env, sConstructor_, &constructor) == napi_ok && constructor != nullptr) {
        auto id = sNativeImageHolder_.save(nativeImage);
        if (napi_create_string_utf8(env, id.c_str(), NAPI_AUTO_LENGTH, &(argv[NUM0])) != napi_ok) {
            IMAGE_ERR("Create native image id Failed");
        }
        if (napi_new_instance(env, constructor, NUM1, argv, &result) != napi_ok) {
            IMAGE_ERR("New instance could not be obtained");
        }
    }
    IMAGE_FUNCTION_OUT();
    return result;
}
static inline bool JsCheckObjectType(napi_env env, napi_value value, napi_valuetype type)
{
    return (ImageNapiUtils::getType(env, value) == type);
}

static inline bool JsGetCallbackFunc(napi_env env, napi_value value, napi_ref *result)
{
    if (JsCheckObjectType(env, value, napi_function)) {
        napi_create_reference(env, value, NUM1, result);
        return true;
    }
    return false;
}

static inline bool JsGetInt32Args(napi_env env, napi_value value, int *result)
{
    if (JsCheckObjectType(env, value, napi_number)) {
        napi_get_value_int32(env, value, result);
        return true;
    }
    return false;
}
using AsyncExecCallback = void (*)(napi_env env, SendableImageAsyncContext* ctx);
using AsyncCompleteCallback = void (*)(napi_env env, napi_status status, SendableImageAsyncContext* ctx);
static bool JsCreateWork(napi_env env, const char* name, AsyncExecCallback exec,
    AsyncCompleteCallback complete, SendableImageAsyncContext* ctx)
{
    napi_value resource = nullptr;
    napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resource);
    napi_status status = napi_create_async_work(
        env, nullptr, resource, reinterpret_cast<napi_async_execute_callback>(exec),
        reinterpret_cast<napi_async_complete_callback>(complete), static_cast<void *>(ctx), &(ctx->work));
    if (status != napi_ok) {
        IMAGE_ERR("fail to create async work %{public}d", status);
        return false;
    }

    if (napi_queue_async_work(env, ctx->work) != napi_ok) {
        IMAGE_ERR("fail to queue async work");
        return false;
    }
    return true;
}

NativeImage* SendableImageNapi::GetNative()
{
    if (native_ != nullptr) {
        return native_.get();
    }
    return nullptr;
}

static std::unique_ptr<SendableImageAsyncContext> UnwrapContext(napi_env env, napi_callback_info info,
    size_t* argc = nullptr, napi_value* argv = nullptr)
{
    napi_value thisVar = nullptr;
    size_t tmp = NUM0;

    IMAGE_FUNCTION_IN();

    if (napi_get_cb_info(env, info, (argc == nullptr)?&tmp:argc, argv, &thisVar, nullptr) != napi_ok) {
        IMAGE_ERR("Fail to napi_get_cb_info");
        return nullptr;
    }

    std::unique_ptr<SendableImageAsyncContext> ctx = std::make_unique<SendableImageAsyncContext>();
    if (napi_unwrap_sendable(env, thisVar, reinterpret_cast<void**>(&ctx->napi)) != napi_ok || ctx->napi == nullptr) {
        IMAGE_ERR("fail to unwrap ets image object, image maybe released");
        return nullptr;
    }
    ctx->image = ctx->napi->GetNative();
    napi_create_reference(env, thisVar, NUM1, &(ctx->thisRef));
    return ctx;
}

static inline void ProcessPromise(napi_env env, napi_deferred deferred, napi_value* result, bool resolved)
{
    if (resolved) {
        napi_resolve_deferred(env, deferred, result[NUM1]);
    } else {
        napi_reject_deferred(env, deferred, result[NUM0]);
    }
}
static inline void ProcessCallback(napi_env env, napi_ref ref, napi_value* result)
{
    napi_value retVal;
    napi_value callback;
    napi_get_reference_value(env, ref, &callback);
    napi_call_function(env, nullptr, callback, NUM2, result, &retVal);
    napi_delete_reference(env, ref);
}
static void CommonCallbackRoutine(napi_env env, SendableImageAsyncContext* &context, const napi_value &valueParam)
{
    IMAGE_FUNCTION_IN();
    napi_value result[2] = {0};

    if (context == nullptr) {
        IMAGE_ERR("context is nullptr");
        return;
    }

    if (context->status == SUCCESS) {
        napi_create_uint32(env, context->status, &result[0]);
        result[1] = valueParam;
    } else {
        ImageNapiUtils::CreateErrorObj(env, result[0], context->status,
            "There is generic napi failure!");
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred) {
        ProcessPromise(env, context->deferred, result, context->status == SUCCESS);
    } else {
        ProcessCallback(env, context->callbackRef, result);
    }

    napi_delete_async_work(env, context->work);

    delete context;
    context = nullptr;
    IMAGE_FUNCTION_OUT();
}

static void BuildIntProperty(napi_env env, const std::string &name,
                             int32_t val, napi_value result)
{
    napi_value nVal;
    napi_create_int32(env, val, &nVal);
    napi_set_named_property(env, result, name.c_str(), nVal);
}

static napi_value BuildJsSize(napi_env env, int32_t width, int32_t height)
{
    napi_value result = nullptr;

    napi_create_object(env, &result);

    BuildIntProperty(env, "width", width, result);
    BuildIntProperty(env, "height", height, result);
    return result;
}

static napi_value BuildJsRegion(napi_env env, int32_t width,
                                int32_t height, int32_t x, int32_t y)
{
    napi_value result = nullptr;

    napi_create_object(env, &result);

    napi_set_named_property(env, result, "size", BuildJsSize(env, width, height));

    BuildIntProperty(env, "x", x, result);
    BuildIntProperty(env, "y", y, result);
    return result;
}

napi_value SendableImageNapi::JSGetClipRect(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    std::unique_ptr<SendableImageAsyncContext> context = UnwrapContext(env, info);
    if (context != nullptr && context->napi != nullptr && context->napi->isTestImage_) {
        const int32_t WIDTH = 8192;
        const int32_t HEIGHT = 8;
        return BuildJsRegion(env, WIDTH, HEIGHT, NUM0, NUM0);
    }
    if (context == nullptr || context->image == nullptr) {
        IMAGE_ERR("Image surfacebuffer is nullptr");
        return result;
    }

    int32_t width = NUM0;
    int32_t height = NUM0;
    if (context->image->GetSize(width, height) != SUCCESS) {
        IMAGE_ERR("Image native get size failed");
        return result;
    }
    return BuildJsRegion(env, width, height, NUM0, NUM0);
}

napi_value SendableImageNapi::JsGetSize(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    std::unique_ptr<SendableImageAsyncContext> context = UnwrapContext(env, info);
    if (context != nullptr && context->napi != nullptr && context->napi->isTestImage_) {
        const int32_t WIDTH = 8192;
        const int32_t HEIGHT = 8;
        return BuildJsSize(env, WIDTH, HEIGHT);
    }
    if (context == nullptr || context->image == nullptr) {
        IMAGE_ERR("Image surfacebuffer is nullptr");
        return result;
    }

    int32_t width = NUM0;
    int32_t height = NUM0;
    if (context->image->GetSize(width, height) != SUCCESS) {
        IMAGE_ERR("Image native get size failed");
        return result;
    }
    return BuildJsSize(env, width, height);
}

napi_value SendableImageNapi::JsGetFormat(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    std::unique_ptr<SendableImageAsyncContext> context = UnwrapContext(env, info);
    if (context != nullptr && context->napi != nullptr && context->napi->isTestImage_) {
        const int32_t FORMAT = 12;
        napi_create_int32(env, FORMAT, &result);
        return result;
    }
    if (context == nullptr || context->image == nullptr) {
        IMAGE_ERR("Image surfacebuffer is nullptr");
        return result;
    }

    int32_t format = NUM0;
    if (context->image->GetFormat(format) != SUCCESS) {
        IMAGE_ERR("Image native get format failed");
        return result;
    }

    napi_create_int32(env, format, &result);
    return result;
}

napi_value SendableImageNapi::JsGetTimestamp(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    std::unique_ptr<SendableImageAsyncContext> context = UnwrapContext(env, info);
    if (context == nullptr || context->image == nullptr) {
        IMAGE_ERR("context is nullptr or Image native is nullptr");
        return result;
    }

    int64_t timestamp = 0;
    if (context->image->GetTimestamp(timestamp) != SUCCESS) {
        IMAGE_ERR("Image native get timestamp failed");
        return result;
    }

    napi_create_int64(env, timestamp, &result);
    return result;
}

static void JSReleaseCallBack(napi_env env, napi_status status,
                              SendableImageAsyncContext* context)
{
    IMAGE_FUNCTION_IN();
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    if (context == nullptr) {
        IMAGE_ERR("context is nullptr");
        return;
    }

    if (context->thisRef != nullptr) {
        napi_value thisVar;
        napi_get_reference_value(env, context->thisRef, &thisVar);
        napi_delete_reference(env, context->thisRef);
        if (thisVar != nullptr) {
            SendableImageNapi *tmp = nullptr;
            auto status_ = napi_remove_wrap_sendable(env, thisVar, reinterpret_cast<void**>(&tmp));
            if (status_ != napi_ok) {
                IMAGE_ERR("NAPI remove wrap failed status %{public}d", status_);
            }
        }
    }

    context->status = SUCCESS;
    IMAGE_FUNCTION_OUT();
    CommonCallbackRoutine(env, context, result);
}

napi_value SendableImageNapi::JsRelease(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    napi_value result = nullptr;
    size_t argc = NUM1;
    napi_value argv[NUM1] = {0};

    napi_get_undefined(env, &result);
    auto context = UnwrapContext(env, info, &argc, argv);
    if (context == nullptr) {
        IMAGE_ERR("fail to unwrap ets image object, image maybe released");
        return result;
    }
    if (argc == NUM1) {
        if (!JsGetCallbackFunc(env, argv[NUM0], &(context->callbackRef))) {
            IMAGE_ERR("Unsupport arg 0 type");
            return result;
        }
    } else {
        napi_create_promise(env, &(context->deferred), &result);
    }

    if (JsCreateWork(env, "JsRelease", [](napi_env env, SendableImageAsyncContext* data) {},
        JSReleaseCallBack, context.get())) {
        context.release();
    }
    IMAGE_FUNCTION_OUT();
    return result;
}

static bool CreateArrayBuffer(napi_env env, uint8_t* src, size_t srcLen, napi_value *res)
{
    if (src == nullptr || srcLen == 0) {
        return false;
    }
    auto status = napi_create_external_arraybuffer(env, src, srcLen,
        [](napi_env env, void* data, void* hint) { }, nullptr, res);
    if (status != napi_ok) {
        return false;
    }
    return true;
}

static inline bool IsEqual(const int32_t& check,  ImageFormat format)
{
    return (check == int32_t(format));
}
static inline bool IsEqual(const int32_t& check,  ComponentType type)
{
    return (check == int32_t(type));
}
static inline bool IsYUVComponent(const int32_t& type)
{
    return (IsEqual(type, ComponentType::YUV_Y) ||
        IsEqual(type, ComponentType::YUV_U) ||
        IsEqual(type, ComponentType::YUV_V));
}
static inline bool IsYUV422SPImage(int32_t format)
{
    return (IsEqual(format, ImageFormat::YCBCR_422_SP) ||
        (format == int32_t(GRAPHIC_PIXEL_FMT_YCBCR_422_SP)));
}
static inline bool CheckComponentType(const int32_t& type, int32_t format)
{
    return ((IsYUV422SPImage(format) && IsYUVComponent(type)) ||
        (!IsYUV422SPImage(format) && IsEqual(type, ComponentType::JPEG)));
}

static bool BuildJsComponentObject(napi_env env, int32_t type, uint8_t* buffer,
    NativeComponent* component, napi_value* result)
{
    napi_value array;
    if (!CreateArrayBuffer(env, buffer, component->size, &array)) {
        return false;
    }
    napi_create_object(env, result);
    napi_set_named_property(env, *result, "byteBuffer", array);
    BuildIntProperty(env, "componentType", type, *result);
    BuildIntProperty(env, "rowStride", component->rowStride, *result);
    BuildIntProperty(env, "pixelStride", component->pixelStride, *result);
    return true;
}
static void TestGetComponentCallBack(napi_env env, napi_status status, SendableImageAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_ERR("Invalid input context");
        return;
    }
    napi_value result;
    napi_value array;
    void *nativePtr = nullptr;
    if (napi_create_arraybuffer(env, NUM1, &nativePtr, &array) != napi_ok || nativePtr == nullptr) {
        return;
    }
    napi_create_object(env, &result);
    napi_set_named_property(env, result, "byteBuffer", array);
    BuildIntProperty(env, "componentType", context->componentType, result);
    BuildIntProperty(env, "rowStride", NUM0, result);
    BuildIntProperty(env, "pixelStride", NUM0, result);
    context->status = SUCCESS;
    CommonCallbackRoutine(env, context, result);
}

static void JsGetComponentCallBack(napi_env env, napi_status status, SendableImageAsyncContext* context)
{
    IMAGE_FUNCTION_IN();
    napi_value result;
    napi_get_undefined(env, &result);

    if (context != nullptr && context->napi != nullptr && context->isTestContext) {
        TestGetComponentCallBack(env, status, context);
        return;
    }

    if (context == nullptr) {
        IMAGE_ERR("Invalid input context");
        return;
    }
    context->status = ERROR;
    NativeComponent* component = context->component;
    if (component == nullptr) {
        IMAGE_ERR("Invalid component");
        CommonCallbackRoutine(env, context, result);
        return;
    }

    uint8_t *buffer = nullptr;
    if (component->virAddr != nullptr) {
        buffer = component->virAddr;
    } else {
        buffer = component->raw.data();
    }

    if (buffer == nullptr || component->size == NUM0) {
        IMAGE_ERR("Invalid buffer");
        CommonCallbackRoutine(env, context, result);
        return;
    }

    if (BuildJsComponentObject(env, context->componentType, buffer, component, &result)) {
        context->status = SUCCESS;
    } else {
        IMAGE_ERR("napi_create_arraybuffer failed!");
    }

    IMAGE_FUNCTION_OUT();
    CommonCallbackRoutine(env, context, result);
}
static void JsGetComponentExec(napi_env env, SendableImageAsyncContext* context)
{
    if (context == nullptr || context->napi == nullptr) {
        IMAGE_ERR("Invalid input context");
        return;
    }

    auto native = context->napi->GetNative();
    if (native == nullptr) {
        IMAGE_ERR("Empty native");
        return;
    }
    context->component = native->GetComponent(context->componentType);
}

static bool JsGetComponentArgs(napi_env env, size_t argc, napi_value* argv, SendableImageAsyncContext* context)
{
    if (argv == nullptr || context == nullptr || argc < NUM1 || context->napi == nullptr) {
        IMAGE_ERR("argv is nullptr");
        return false;
    }

    if (!JsGetInt32Args(env, argv[NUM0], &(context->componentType))) {
        IMAGE_ERR("Unsupport arg 0 type");
        return false;
    }

    auto native = context->napi->GetNative();
    if (native == nullptr && !context->isTestContext) {
        IMAGE_ERR("native is nullptr");
        return false;
    }

    int32_t format = NUM0;
    if (context->isTestContext) {
        const int32_t TEST_FORMAT = 12;
        format = TEST_FORMAT;
    } else {
        native->GetFormat(format);
    }

    if (!CheckComponentType(context->componentType, format)) {
        IMAGE_ERR("Unsupport component type 0 value: %{public}d", context->componentType);
        return false;
    }

    if (argc == NUM2 && !JsGetCallbackFunc(env, argv[NUM1], &(context->callbackRef))) {
        IMAGE_ERR("Unsupport arg 1 type");
        return false;
    }
    return true;
}

napi_value SendableImageNapi::JsGetComponent(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    napi_value result = nullptr;
    size_t argc = NUM2;
    napi_value argv[NUM2] = {0};

    napi_get_undefined(env, &result);
    auto context = UnwrapContext(env, info, &argc, argv);
    if (context == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, static_cast<int32_t>(napi_invalid_arg),
            "fail to unwrap ets image object, image maybe released");
    }
    context->isTestContext = context->napi->isTestImage_;
    if (!JsGetComponentArgs(env, argc, argv, context.get())) {
        return ImageNapiUtils::ThrowExceptionError(env, static_cast<int32_t>(napi_invalid_arg),
            "Unsupport arg type!");
    }

    if (context->callbackRef == nullptr) {
        napi_create_promise(env, &(context->deferred), &result);
    }

    if (JsCreateWork(env, "JsGetComponent", JsGetComponentExec, JsGetComponentCallBack, context.get())) {
        context.release();
    }

    IMAGE_FUNCTION_OUT();
    return result;
}
}  // namespace Media
}  // namespace OHOS
