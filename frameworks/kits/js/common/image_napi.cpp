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

#include "image_napi.h"
#include "media_errors.h"
#include "hilog/log.h"
#include "image_format.h"
#include "image_napi_utils.h"

using OHOS::HiviewDFX::HiLog;
using std::string;
using std::shared_ptr;
using std::unique_ptr;
using std::vector;
using std::make_shared;
using std::make_unique;

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "ImageNapi"};
}

namespace OHOS {
namespace Media {
static const std::string CLASS_NAME = "ImageNapi";
std::shared_ptr<ImageReceiver> ImageNapi::staticImageReceiverInstance_ = nullptr;
std::shared_ptr<ImageCreator> ImageNapi::staticImageCreatorInstance_ = nullptr;
sptr<SurfaceBuffer> ImageNapi::staticInstance_ = nullptr;
thread_local napi_ref ImageNapi::sConstructor_ = nullptr;

const int ARGS0 = 0;
const int ARGS1 = 1;
const int ARGS2 = 2;
const int PARAM0 = 0;
const int PARAM1 = 1;
const int PARAM2 = 2;
const int NUM0 = 0;

ImageNapi::ImageNapi():env_(nullptr)
{}

ImageNapi::~ImageNapi()
{
    release();
}

static void CommonCallbackRoutine(napi_env env, ImageAsyncContext* &context,
                                  const napi_value &valueParam)
{
    IMAGE_FUNCTION_IN();
    napi_value result[2] = {0};
    napi_value retVal;
    napi_value callback = nullptr;

    napi_get_undefined(env, &result[0]);
    napi_get_undefined(env, &result[1]);

    if (context == nullptr) {
        IMAGE_ERR("context is nullptr");
        return;
    }

    if (context->status == SUCCESS) {
        result[1] = valueParam;
    }

    if (context->deferred) {
        if (context->status == SUCCESS) {
            napi_resolve_deferred(env, context->deferred, result[1]);
        } else {
            ImageNapiUtils::CreateErrorObj(env, result[0], context->status,
                "There is generic napi failure!");
            napi_reject_deferred(env, context->deferred, result[0]);
        }
    } else {
        if (context->status == SUCCESS) {
            napi_create_uint32(env, context->status, &result[0]);
        } else {
            ImageNapiUtils::CreateErrorObj(env, result[0], context->status,
                "There is generic napi failure!");
        }
        napi_get_reference_value(env, context->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, PARAM2, result, &retVal);
        napi_delete_reference(env, context->callbackRef);
    }

    napi_delete_async_work(env, context->work);

    delete context;
    context = nullptr;
    IMAGE_FUNCTION_OUT();
}

void ImageNapi::NativeRelease()
{
    if (imageReceiver_ != nullptr) {
        imageReceiver_->ReleaseBuffer(sSurfaceBuffer_);
        imageReceiver_ = nullptr;
    }
    sSurfaceBuffer_ = nullptr;
}

napi_value ImageNapi::Init(napi_env env, napi_value exports)
{
    IMAGE_FUNCTION_IN();
    napi_property_descriptor props[] = {
        DECLARE_NAPI_GETTER("clipRect", JSGetClipRect),
        DECLARE_NAPI_GETTER("size", JsGetSize),
        DECLARE_NAPI_GETTER("format", JsGetFormat),
        DECLARE_NAPI_FUNCTION("getComponent", JsGetComponent),
        DECLARE_NAPI_FUNCTION("release", JsRelease),
    };
    napi_value constructor = nullptr;

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor,
        nullptr, IMG_ARRAY_SIZE(props), props, &constructor)),
        nullptr,
        IMAGE_ERR("define class fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_create_reference(env, constructor, 1, &sConstructor_)),
        nullptr,
        IMAGE_ERR("create reference fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor)),
        nullptr,
        IMAGE_ERR("set named property fail")
    );

    IMAGE_DEBUG("Init success");

    IMAGE_FUNCTION_OUT();
    return exports;
}

std::shared_ptr<ImageNapi> ImageNapi::GetImageSource(napi_env env, napi_value image)
{
    std::unique_ptr<ImageNapi> imageNapi = std::make_unique<ImageNapi>();

    napi_status status = napi_unwrap(env, image, reinterpret_cast<void**>(&imageNapi));
    if (!IMG_IS_OK(status)) {
        IMAGE_ERR("GetImage napi unwrap failed");
        return nullptr;
    }

    if (imageNapi == nullptr) {
        IMAGE_ERR("GetImage imageNapi is nullptr");
        return nullptr;
    }
    IMAGE_ERR("get nativeImage");

    return imageNapi;
}

napi_value ImageNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    napi_status status;
    napi_value thisVar = nullptr;

    IMAGE_FUNCTION_IN();
    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<ImageNapi> reference = std::make_unique<ImageNapi>();
        if (reference != nullptr) {
            reference->env_ = env;
            reference->sSurfaceBuffer_ = staticInstance_;
            reference->imageReceiver_ = staticImageReceiverInstance_;
            staticImageReceiverInstance_ = nullptr;
            status = napi_wrap(env, thisVar, reinterpret_cast<void *>(reference.get()),
                               ImageNapi::Destructor, nullptr, nullptr);
            if (status == napi_ok) {
                IMAGE_FUNCTION_OUT();
                reference.release();
                return thisVar;
            } else {
                IMAGE_ERR("Failure wrapping js to native napi");
            }
        }
    }

    return undefineVar;
}

void ImageNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
}

napi_value ImageNapi::Create(napi_env env, sptr<SurfaceBuffer> surfaceBuffer,
    std::shared_ptr<ImageReceiver> imageReceiver)
{
    napi_status status;
    napi_value constructor = nullptr, result = nullptr;

    IMAGE_FUNCTION_IN();
    if (surfaceBuffer == nullptr) {
        IMAGE_ERR("surfaceBuffer is nullptr");
        return result;
    }

    napi_get_undefined(env, &result);

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        staticInstance_ = surfaceBuffer;
        staticImageReceiverInstance_ = imageReceiver;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        if (status == napi_ok) {
            IMAGE_FUNCTION_OUT();
            return result;
        } else {
            IMAGE_ERR("New instance could not be obtained");
        }
    }

    IMAGE_ERR("Failed to get reference of constructor");
    return result;
}

napi_value ImageNapi::CreateBufferToImage(napi_env env, sptr<SurfaceBuffer> surfaceBuffer,
    std::shared_ptr<ImageCreator> imageCreator)
{
    napi_status status;
    napi_value constructor = nullptr, result = nullptr;

    IMAGE_FUNCTION_IN();
    if (surfaceBuffer == nullptr) {
        IMAGE_ERR("surfaceBuffer is nullptr");
        return result;
    }

    napi_get_undefined(env, &result);

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        staticInstance_ = surfaceBuffer;
        staticImageCreatorInstance_ = imageCreator;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        if (status == napi_ok) {
            IMAGE_FUNCTION_OUT();
            return result;
        } else {
            IMAGE_ERR("New instance could not be obtained");
        }
    }

    IMAGE_ERR("Failed to get reference of constructor");
    return result;
}

unique_ptr<ImageAsyncContext> ImageNapi::UnwarpContext(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argc = ARGS0;

    IMAGE_FUNCTION_IN();

    status = napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    if (status != napi_ok) {
        IMAGE_ERR("fail to napi_get_cb_info %{public}d", status);
        return nullptr;
    }

    unique_ptr<ImageAsyncContext> context = make_unique<ImageAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&context->constructor_));
    if (status != napi_ok || context->constructor_ == nullptr) {
        IMAGE_ERR("fail to unwrap constructor_ %{public}d", status);
        return nullptr;
    }
    return context;
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

napi_value ImageNapi::JSGetClipRect(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    unique_ptr<ImageAsyncContext> context;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    context = UnwarpContext(env, info);
    if (context == nullptr) {
        return result;
    }

    if (context->constructor_ == nullptr) {
        IMAGE_ERR("Image context is nullptr");
        return result;
    }
    auto surfaceBuffer = context->constructor_->sSurfaceBuffer_;

    if (surfaceBuffer == nullptr) {
        IMAGE_ERR("Image surface buffer is nullptr");
        return result;
    }

    return BuildJsRegion(env, surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight(), NUM0, NUM0);
}

napi_value ImageNapi::JsGetSize(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    unique_ptr<ImageAsyncContext> context;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    context = UnwarpContext(env, info);
    if (context == nullptr) {
        return result;
    }

    if (context->constructor_ == nullptr) {
        IMAGE_ERR("Image context is nullptr");
        return result;
    }
    auto surfaceBuffer = context->constructor_->sSurfaceBuffer_;

    if (surfaceBuffer == nullptr) {
        IMAGE_ERR("Image surface buffer is nullptr");
        return result;
    }

    return BuildJsSize(env, surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight());
}

napi_value ImageNapi::JsGetFormat(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    unique_ptr<ImageAsyncContext> context;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    context = UnwarpContext(env, info);
    if (context == nullptr) {
        return result;
    }

    if (context->constructor_ == nullptr) {
        IMAGE_ERR("Image context is nullptr");
        return result;
    }

    auto surfaceBuffer = context->constructor_->sSurfaceBuffer_;
    if (surfaceBuffer == nullptr) {
        IMAGE_ERR("Image surface buffer is nullptr");
        return result;
    }

    napi_create_int32(env, surfaceBuffer->GetFormat(), &result);
    return result;
}

static void JSReleaseCallBack(napi_env env, napi_status status,
                              ImageAsyncContext* context)
{
    IMAGE_FUNCTION_IN();
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    if (context == nullptr) {
        IMAGE_ERR("context is nullptr");
        return;
    }
    context->constructor_->NativeRelease();
    context->status = SUCCESS;

    IMAGE_FUNCTION_OUT();
    CommonCallbackRoutine(env, context, result);
}

napi_value ImageNapi::JsRelease(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    napi_status status;
    napi_value result = nullptr, thisVar = nullptr;
    size_t argc = ARGS1;
    napi_value argv[ARGS1] = {0};

    napi_get_undefined(env, &result);

    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        IMAGE_ERR("fail to napi_get_cb_info %{public}d", status);
        return result;
    }

    unique_ptr<ImageAsyncContext> context = UnwarpContext(env, info);
    if (context == nullptr) {
        IMAGE_ERR("fail to unwrap constructor_ %{public}d", status);
        return result;
    }

    if (argc == ARGS1) {
        auto argType = ImageNapiUtils::getType(env, argv[PARAM0]);
        if (argType == napi_function) {
            int32_t refCount = 1;
            napi_create_reference(env, argv[PARAM0], refCount, &context->callbackRef);
        } else {
            IMAGE_ERR("Unsupport arg 0 type: %{public}d", argType);
            return result;
        }
    }

    if (context->callbackRef == nullptr) {
        napi_create_promise(env, &(context->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsRelease", NAPI_AUTO_LENGTH, &resource);
    status = napi_create_async_work(
        env, nullptr, resource, [](napi_env env, void* data) {},
        reinterpret_cast<napi_async_complete_callback>(JSReleaseCallBack),
        static_cast<void *>(context.get()), &(context->work));
    if (status != napi_ok) {
        IMAGE_ERR("fail to create async work %{public}d", status);
        return result;
    }

    status = napi_queue_async_work(env, context->work);
    if (status != napi_ok) {
        IMAGE_ERR("fail to queue async work %{public}d", status);
        return result;
    }

    context.release();

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

void ImageNapi::JsGetComponentCallBack(napi_env env, napi_status status,
                                       ImageAsyncContext* context)
{
    IMAGE_FUNCTION_IN();
    napi_value result = nullptr;

    napi_create_object(env, &result);
    uint32_t bufferSize = context->constructor_->sSurfaceBuffer_->GetSize();
    void *buffer = context->constructor_->sSurfaceBuffer_->GetVirAddr();

    napi_value array;
    if (!CreateArrayBuffer(env, static_cast<uint8_t*>(buffer), bufferSize, &array)) {
        context->status = ERROR;
        HiLog::Error(LABEL, "napi_create_arraybuffer failed!");
        napi_get_undefined(env, &result);
    } else {
        context->status = SUCCESS;
        napi_set_named_property(env, result, "byteBuffer", array);
    }

    BuildIntProperty(env, "componentType", context->componentType, result);
    BuildIntProperty(env, "rowStride", 0, result);
    BuildIntProperty(env, "pixelStride", 0, result);

    IMAGE_FUNCTION_OUT();
    CommonCallbackRoutine(env, context, result);
}

static bool CheckComponentType(const int32_t& type)
{
    if (type == static_cast<int32_t>(ComponentType::YUV_Y) ||
        type == static_cast<int32_t>(ComponentType::YUV_U) ||
        type == static_cast<int32_t>(ComponentType::YUV_V) ||
        type == static_cast<int32_t>(ComponentType::JPEG)) {
        return true;
    }
    return false;
}

static bool JsGetComponentArgs(napi_env env, size_t argc, napi_value* argv,
                               int32_t* componentType, napi_ref* callbackRef)
{
    if (argv == nullptr) {
        IMAGE_ERR("argv is nullptr");
        return false;
    }

    if (argc == ARGS1 || argc == ARGS2) {
        auto argType0 = ImageNapiUtils::getType(env, argv[PARAM0]);
        if (argType0 == napi_number) {
            napi_get_value_int32(env, argv[PARAM0], componentType);
        } else {
            IMAGE_ERR("Unsupport arg 0 type: %{public}d", argType0);
            return false;
        }

        if (!CheckComponentType(*componentType)) {
            IMAGE_ERR("Unsupport component type 0 value: %{public}d", *componentType);
            return false;
        }
    }
    if (argc == ARGS2) {
        auto argType1 = ImageNapiUtils::getType(env, argv[PARAM1]);
        if (argType1 == napi_function) {
            int32_t refCount = 1;
            napi_create_reference(env, argv[PARAM1], refCount, callbackRef);
        } else {
            IMAGE_ERR("Unsupport arg 1 type: %{public}d", argType1);
            return false;
        }
    }
    return true;
}

napi_value ImageNapi::JsGetComponent(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    napi_status status;
    napi_value result = nullptr, thisVar = nullptr;
    size_t argc = ARGS2;
    napi_value argv[ARGS2] = {0};

    napi_get_undefined(env, &result);

    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        IMAGE_ERR("fail to napi_get_cb_info %{public}d", status);
        return result;
    }

    unique_ptr<ImageAsyncContext> context = UnwarpContext(env, info);
    if (context == nullptr) {
        std::string errMsg = "fail to unwrap constructor_ ";
        return ImageNapiUtils::ThrowExceptionError(env, static_cast<int32_t>(napi_invalid_arg),
            errMsg.append(std::to_string(status)));
    }

    if (!JsGetComponentArgs(env, argc, argv,
                            &(context->componentType),
                            &(context->callbackRef))) {
        return ImageNapiUtils::ThrowExceptionError(env, static_cast<int32_t>(napi_invalid_arg),
            "Unsupport arg type!");
    }

    if (context->callbackRef == nullptr) {
        napi_create_promise(env, &(context->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsGetComponent", NAPI_AUTO_LENGTH, &resource);
    status = napi_create_async_work(
        env, nullptr, resource, [](napi_env env, void* data) {},
        reinterpret_cast<napi_async_complete_callback>(JsGetComponentCallBack),
        static_cast<void *>(context.get()), &(context->work));
    if (status != napi_ok) {
        IMAGE_ERR("fail to create async work %{public}d", status);
        return result;
    }

    status = napi_queue_async_work(env, context->work);
    if (status != napi_ok) {
        IMAGE_ERR("fail to queue async work %{public}d", status);
        return result;
    }
    context.release();

    IMAGE_FUNCTION_OUT();
    return result;
}

void ImageNapi::release()
{
    if (!isRelease) {
        NativeRelease();
        isRelease = true;
    }
}
}  // namespace Media
}  // namespace OHOS
