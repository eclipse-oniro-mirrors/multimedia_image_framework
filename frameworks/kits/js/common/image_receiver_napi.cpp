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

#include "image_receiver_napi.h"
#include <uv.h>
#include "media_errors.h"
#include "image_log.h"
#include "image_napi_utils.h"
#include "image_napi.h"
#include "image_receiver_context.h"
#include "image_receiver_manager.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageReceiverNapi"

using std::string;
using std::shared_ptr;
using std::unique_ptr;
using std::vector;
using std::make_shared;
using std::make_unique;

namespace OHOS {
namespace Media {
static const std::string CLASS_NAME = "ImageReceiver";
static const std::string DEVICE_ERRCODE = "001";
shared_ptr<ImageReceiver> ImageReceiverNapi::staticInstance_ = nullptr;
thread_local napi_ref ImageReceiverNapi::sConstructor_ = nullptr;
using SurfaceListener = SurfaceBufferAvaliableListener;

const int ARGS0 = 0;
const int ARGS1 = 1;
const int ARGS2 = 2;
const int ARGS3 = 3;
const int ARGS4 = 4;
const int PARAM0 = 0;
const int PARAM1 = 1;
const int PARAM2 = 2;
const int PARAM3 = 3;

struct ImageEnum {
    std::string name;
    int32_t numVal;
    std::string strVal;
};

static std::vector<struct ImageEnum> sImageFormatMap = {
    {"CAMERA_APP_INNER", 4, ""},
    {"JPEG", 2000, ""},
};

ImageReceiverNapi::ImageReceiverNapi():env_(nullptr)
{}

ImageReceiverNapi::~ImageReceiverNapi()
{
    release();
}

static void CommonCallbackRoutine(napi_env env, Context &context, const napi_value &valueParam, bool isRelease = true)
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
            napi_reject_deferred(env, context->deferred, result[0]);
        }
    } else {
        napi_create_uint32(env, context->status, &result[0]);
        napi_get_reference_value(env, context->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, PARAM2, result, &retVal);
    }

    if (isRelease) {
        if (context->callbackRef != nullptr) {
            napi_delete_reference(env, context->callbackRef);
            context->callbackRef = nullptr;
        }

        napi_delete_async_work(env, context->work);

        delete context;
        context = nullptr;
    }
    IMAGE_FUNCTION_OUT();
}

void ImageReceiverNapi::NativeRelease()
{
    imageReceiver_ = nullptr;
}

void ImageReceiverNapi::UnRegisterReceiverListener()
{
    if (imageReceiver_ != nullptr) {
        imageReceiver_->UnRegisterBufferAvaliableListener();
    }
}

ImageReceiver* ImageReceiverNapi::GetNative()
{
    if (imageReceiver_ != nullptr) {
        return imageReceiver_.get();
    }
    return nullptr;
}
napi_value ImageReceiverNapi::Init(napi_env env, napi_value exports)
{
    IMAGE_FUNCTION_IN();
    napi_property_descriptor props[] = {
        DECLARE_NAPI_FUNCTION("getReceivingSurfaceId", JsGetReceivingSurfaceId),
        DECLARE_NAPI_FUNCTION("readLatestImage", JsReadLatestImage),
        DECLARE_NAPI_FUNCTION("readNextImage", JsReadNextImage),
        DECLARE_NAPI_FUNCTION("on", JsOn),
        DECLARE_NAPI_FUNCTION("off", JsOff),
        DECLARE_NAPI_FUNCTION("release", JsRelease),
#ifdef IMAGE_DEBUG_FLAG
        DECLARE_NAPI_GETTER("test", JsTest),
        DECLARE_NAPI_GETTER("checkDeviceTest", JsCheckDeviceTest),
        DECLARE_NAPI_GETTER("testYUV", JsTestYUV),
#endif
        DECLARE_NAPI_GETTER("size", JsGetSize),
        DECLARE_NAPI_GETTER("capacity", JsGetCapacity),
        DECLARE_NAPI_GETTER("format", JsGetFormat),
    };
    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createImageReceiver", JSCreateImageReceiver),
    };

    napi_value constructor = nullptr;
    size_t props_count = IMG_ARRAY_SIZE(props);
    size_t static_props_count = IMG_ARRAY_SIZE(static_prop);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor,
        nullptr, props_count, props, &constructor)),
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
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_properties(env, exports, static_props_count, static_prop)),
        nullptr,
        IMAGE_ERR("define properties fail")
    );

    IMAGE_DEBUG("Init success");

    IMAGE_FUNCTION_OUT();
    return exports;
}

struct ImageReceiverInputArgs {
    napi_value thisVar;
    size_t argc;
    napi_value argv[ARGS4];
    int32_t args[ARGS4];
};

static bool parseImageReceiverArgs(napi_env env, napi_callback_info info,
    ImageReceiverInputArgs &args, std::string &errMsg)
{
    napi_status status = napi_get_cb_info(env, info, &(args.argc), args.argv, &(args.thisVar), nullptr);
    if (status != napi_ok) {
        IMAGE_ERR("fail to napi_get_cb_info %{public}d", status);
        errMsg = "Fail to napi_get_cb_info";
        return false;
    }

    if (args.argc != ARGS3 && args.argc != ARGS4) {
        errMsg = "Invalid arg counts ";
        errMsg.append(std::to_string(args.argc));
        return false;
    }

    return ImageNapiUtils::ParseImageCreatorReceiverArgs(env, args.argc, args.argv, args.args, errMsg);
}

napi_value ImageReceiverNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    IMAGE_FUNCTION_IN();
    std::string errMsg;
    ImageReceiverInputArgs inputArgs;
    inputArgs.argc = ARGS4;
    if (!parseImageReceiverArgs(env, info, inputArgs, errMsg) || inputArgs.thisVar == nullptr) {
        IMAGE_ERR("Failure. %{public}s", errMsg.c_str());
        return undefineVar;
    }
    auto reference = std::make_unique<ImageReceiverNapi>();
    reference->env_ = env;
    reference->imageReceiver_ = ImageReceiver::CreateImageReceiver((inputArgs.args)[PARAM0],
        (inputArgs.args)[PARAM1], (inputArgs.args)[PARAM2], (inputArgs.args)[PARAM3]);
    if (reference->imageReceiver_ == nullptr) {
        IMAGE_ERR("Create native image receiver failed");
        return undefineVar;
    }
    napi_status status = napi_wrap(env, inputArgs.thisVar, reinterpret_cast<void *>(reference.get()),
        ImageReceiverNapi::Destructor, nullptr, nullptr);
    if (status == napi_ok) {
        reference.release();
        return inputArgs.thisVar;
    }
    IMAGE_ERR("Failure wrapping js to native napi");
    return undefineVar;
}

void ImageReceiverNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        delete reinterpret_cast<ImageReceiverNapi*>(nativeObject);
        nativeObject = nullptr;
    }
}

static bool checkFormat(int32_t format)
{
    for (auto imgEnum : sImageFormatMap) {
        if (imgEnum.numVal == format) {
            return true;
        }
    }
    return false;
}

napi_value ImageReceiverNapi::CreateImageReceiverJsObject(napi_env env, struct ImageReceiverCreateArgs args)
{
    napi_status status;
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    ImageReceiverInputArgs inputArgs;
    inputArgs.argc = ARGS4;

    IMAGE_FUNCTION_IN();
    if (!checkFormat(args.format)) {
        IMAGE_ERR("Invalid type");
        return nullptr;
    }
    napi_create_int32(env, args.width, &(inputArgs.argv[PARAM0]));
    napi_create_int32(env, args.height, &(inputArgs.argv[PARAM1]));
    napi_create_int32(env, args.format, &(inputArgs.argv[PARAM2]));
    napi_create_int32(env, args.capicity, &(inputArgs.argv[PARAM3]));
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status != napi_ok || constructor == nullptr) {
        IMAGE_ERR("Failed to get reference of constructor");
        return nullptr;
    }

    status = napi_new_instance(env, constructor, inputArgs.argc, inputArgs.argv, &result);
    if (status != napi_ok || result == nullptr) {
        IMAGE_ERR("New instance could not be obtained");
        return nullptr;
    }

    IMAGE_FUNCTION_OUT();
    return result;
}

napi_value ImageReceiverNapi::JSCreateImageReceiver(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    ImageReceiverInputArgs inputArgs;
    inputArgs.argc = ARGS4;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);

    std::string errMsg;
    if (!parseImageReceiverArgs(env, info, inputArgs, errMsg)) {
        return ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, errMsg);
    }

    if (!checkFormat(inputArgs.args[PARAM2])) {
        return ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Invalid type");
    }

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = napi_new_instance(env, constructor, inputArgs.argc, inputArgs.argv, &result);
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

static bool CheckArgs(const ImageReceiverCommonArgs &args)
{
    if (args.async != CallType::GETTER) {
        if (args.queryArgs == nullptr) {
            IMAGE_ERR("No query args function");
            return false;
        }
    }

    if (args.async != CallType::ASYNC || args.asyncLater) {
        if (args.nonAsyncBack == nullptr) {
            IMAGE_ERR("No non async back function");
            return false;
        }
    }
    return true;
}

static bool PrepareOneArg(ImageReceiverCommonArgs &args, struct ImageReceiverInnerContext &ic)
{
    if (ic.argc == ARGS1) {
        auto argType = ImageNapiUtils::getType(args.env, ic.argv[PARAM0]);
        if (argType == napi_function) {
            napi_create_reference(args.env, ic.argv[PARAM0], ic.refCount, &(ic.context->callbackRef));
        } else {
            IMAGE_ERR("Unsupport arg 0 type: %{public}d", argType);
            return false;
        }
    }

    if (ic.context->callbackRef == nullptr) {
        napi_create_promise(args.env, &(ic.context->deferred), &(ic.result));
    } else {
        napi_get_undefined(args.env, &ic.result);
    }
    return true;
}

napi_value ImageReceiverNapi::JSCommonProcess(ImageReceiverCommonArgs &args)
{
    IMAGE_FUNCTION_IN();
    struct ImageReceiverInnerContext ic;
    ic.argc = args.argc;
    ic.argv.resize(ic.argc);
    napi_get_undefined(args.env, &ic.result);

    IMG_NAPI_CHECK_RET(CheckArgs(args), ic.result);

    IMG_JS_ARGS(args.env, args.info, ic.status, ic.argc, &(ic.argv[0]), ic.thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(ic.status), ic.result, IMAGE_ERR("fail to napi_get_cb_info"));

    if (args.async != CallType::STATIC) {
        ic.context = std::make_unique<ImageReceiverAsyncContext>();
        if (ic.context == nullptr) {
            return ic.result;
        }
        ic.status = napi_unwrap(args.env, ic.thisVar, reinterpret_cast<void**>(&(ic.context->constructor_)));

        IMG_NAPI_CHECK_RET_D(IMG_IS_READY(ic.status, ic.context->constructor_),
            ic.result, IMAGE_ERR("fail to unwrap context"));

        if (ic.context->constructor_ == nullptr) {
            return ic.result;
        }

        IMG_NAPI_CHECK_RET_D(IMG_IS_READY(ic.status, ic.context->constructor_->imageReceiver_),
            ic.result, IMAGE_ERR("empty native receiver"));
    }
    if (args.async != CallType::GETTER) {
        if (!args.queryArgs(args, ic)) {
            return ic.result;
        }
    }

    if (args.async == CallType::ASYNC) {
        if (args.asyncLater) {
            args.nonAsyncBack(args, ic);
        } else {
            napi_value _resource = nullptr;
            napi_create_string_utf8((args.env), (args.name.c_str()), NAPI_AUTO_LENGTH, &_resource);
            (ic.status) = napi_create_async_work(args.env, nullptr, _resource,
                                                 ([](napi_env env, void *data) {}),
                                                 (reinterpret_cast<napi_async_complete_callback>(args.callBack)),
                                                 static_cast<void *>((ic.context).get()), &(ic.context->work));
            napi_queue_async_work((args.env), (ic.context->work));
            ic.context.release();
        }
    } else {
        args.nonAsyncBack(args, ic);
    }

    IMAGE_FUNCTION_OUT();
    return ic.result;
}

static napi_value BuildJsSize(napi_env env, int32_t width, int32_t height)
{
    napi_value result = nullptr;
    napi_value sizeWith = nullptr;
    napi_value sizeHeight = nullptr;

    napi_create_object(env, &result);

    napi_create_int32(env, width, &sizeWith);
    napi_set_named_property(env, result, "width", sizeWith);

    napi_create_int32(env, height, &sizeHeight);
    napi_set_named_property(env, result, "height", sizeHeight);
    return result;
}

napi_value ImageReceiverNapi::JsGetSize(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::GETTER,
    };
    args.argc = ARGS0;

    args.nonAsyncBack = [](ImageReceiverCommonArgs &args, ImageReceiverInnerContext &ic) -> bool {
        napi_get_undefined(args.env, &(ic.result));
        auto native = ic.context->constructor_->imageReceiver_;
        if (native == nullptr) {
            IMAGE_ERR("Native instance is nullptr");
            return false;
        }

        if (native->iraContext_ == nullptr) {
            IMAGE_ERR("Image receiver context is nullptr");
            return false;
        }
        ic.result = BuildJsSize(args.env,
                                native->iraContext_->GetWidth(),
                                native->iraContext_->GetHeight());
        return true;
    };

    return JSCommonProcess(args);
}

napi_value ImageReceiverNapi::JsGetCapacity(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::GETTER,
    };
    args.argc = ARGS0;

    args.nonAsyncBack = [](ImageReceiverCommonArgs &args, ImageReceiverInnerContext &ic) -> bool {
        napi_get_undefined(args.env, &(ic.result));
        auto native = ic.context->constructor_->imageReceiver_;
        if (native == nullptr) {
            IMAGE_ERR("Native instance is nullptr");
            return false;
        }

        if (native->iraContext_ == nullptr) {
            IMAGE_ERR("Image receiver context is nullptr");
            return false;
        }
        napi_create_int32(args.env, native->iraContext_->GetCapicity(), &(ic.result));
        return true;
    };

    return JSCommonProcess(args);
}

napi_value ImageReceiverNapi::JsGetFormat(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::GETTER,
    };
    args.argc = ARGS0;

    args.nonAsyncBack = [](ImageReceiverCommonArgs &args, ImageReceiverInnerContext &ic) -> bool {
        napi_get_undefined(args.env, &(ic.result));
        auto native = ic.context->constructor_->imageReceiver_;
        if (native == nullptr) {
            IMAGE_ERR("Native instance is nullptr");
            return false;
        }

        if (native->iraContext_ == nullptr) {
            IMAGE_ERR("Image receiver context is nullptr");
            return false;
        }
        napi_create_int32(args.env, native->iraContext_->GetFormat(), &(ic.result));
        return true;
    };

    return JSCommonProcess(args);
}

#ifdef IMAGE_DEBUG_FLAG
static void TestRequestBuffer(OHOS::sptr<OHOS::Surface> &receiverSurface,
                              OHOS::BufferRequestConfig requestConfig,
                              OHOS::BufferFlushConfig flushConfig)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer;
    int32_t releaseFence;
    if (receiverSurface == nullptr) {
        IMAGE_ERR("Image receiver receiverSurface is nullptr");
        return;
    }
    requestConfig.width = receiverSurface->GetDefaultWidth();
    requestConfig.height = receiverSurface->GetDefaultHeight();
    receiverSurface->RequestBuffer(buffer, releaseFence, requestConfig);
    if (buffer == nullptr) {
        IMAGE_ERR("Image receiver buffer is nullptr");
        return;
    }
    IMAGE_ERR("RequestBuffer");
    int32_t *p = reinterpret_cast<int32_t *>(buffer->GetVirAddr());
    int32_t size = static_cast<int32_t>(buffer->GetSize() / 4);
    if (p != nullptr) {
        for (int32_t i = 0; i < size; i++) {
            p[i] = i;
        }
    }
    receiverSurface->FlushBuffer(buffer, -1, flushConfig);
    IMAGE_ERR("FlushBuffer");
}

static void DoTest(std::shared_ptr<ImageReceiver> imageReceiver, int pixelFormat)
{
    OHOS::BufferRequestConfig requestConfig = {
        .width = 0x100,
        .height = 0x100,
        .strideAlignment = 0x8,
        .format = pixelFormat,
        .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
        .timeout = 0,
    };

    OHOS::BufferFlushConfig flushConfig = {
        .damage = {
            .w = 0x100,
            .h = 0x100,
        },
    };

    if (imageReceiver == nullptr || imageReceiver->iraContext_ == nullptr) {
        IMAGE_ERR("Image receiver DoTest imageReceiver is nullptr");
        return;
    }
    std::string receiveKey = imageReceiver->iraContext_->GetReceiverKey();
    IMAGE_ERR("ReceiverKey = %{public}s", receiveKey.c_str());
    OHOS::sptr<OHOS::Surface> receiverSurface = ImageReceiver::getSurfaceById(receiveKey);
    if (receiverSurface == nullptr) {
        IMAGE_ERR("Image receiver DoTest receiverSurface is nullptr");
        return;
    }
    IMAGE_ERR("getDefaultWidth = %{public}d", receiverSurface->GetDefaultWidth());
    IMAGE_ERR("getDefaultHeight = %{public}d", receiverSurface->GetDefaultHeight());
    IMAGE_ERR("TestRequestBuffer 1 ...");
    TestRequestBuffer(receiverSurface, requestConfig, flushConfig);
    IMAGE_ERR("TestRequestBuffer 2 ...");
    TestRequestBuffer(receiverSurface, requestConfig, flushConfig);
    IMAGE_ERR("TestRequestBuffer 3 ...");
    TestRequestBuffer(receiverSurface, requestConfig, flushConfig);
}

napi_value ImageReceiverNapi::JsTest(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::GETTER,
    };
    args.argc = ARGS0;

    args.nonAsyncBack = [](ImageReceiverCommonArgs &args, ImageReceiverInnerContext &ic) -> bool {
        ic.context->constructor_->isCallBackTest = true;
        DoTest(ic.context->constructor_->imageReceiver_, PIXEL_FMT_RGBA_8888);
        return true;
    };

    return JSCommonProcess(args);
}

napi_value ImageReceiverNapi::JsCheckDeviceTest(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::GETTER,
    };
    args.argc = ARGS0;

    args.nonAsyncBack = [](ImageReceiverCommonArgs &args, ImageReceiverInnerContext &ic) -> bool {
        napi_get_undefined(args.env, &(ic.result));
        napi_value mess = nullptr;
        ic.context->constructor_->isCallBackTest = true;
        napi_create_string_utf8(args.env, DEVICE_ERRCODE.c_str(), NAPI_AUTO_LENGTH, &mess);
        ic.result = mess;
        if (args.async != CallType::GETTER) {
            DoTest(ic.context->constructor_->imageReceiver_, PIXEL_FMT_RGBA_8888);
        }
        return true;
    };

    return JSCommonProcess(args);
}

napi_value ImageReceiverNapi::JsTestYUV(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::GETTER,
    };
    args.argc = ARGS0;

    args.nonAsyncBack = [](ImageReceiverCommonArgs &args, ImageReceiverInnerContext &ic) -> bool {
        ic.context->constructor_->isCallBackTest = true;
        DoTest(ic.context->constructor_->imageReceiver_, PIXEL_FMT_YCBCR_422_SP);
        return true;
    };

    return JSCommonProcess(args);
}
#endif

napi_value ImageReceiverNapi::JsGetReceivingSurfaceId(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::ASYNC,
        .name = "JsGetReceivingSurfaceId",
        .callBack = nullptr,
        .argc = ARGS1,
        .queryArgs = PrepareOneArg,
    };

    args.callBack = [](napi_env env, napi_status status, Context context) {
        IMAGE_LINE_IN();
        napi_value result = nullptr;
        napi_get_undefined(env, &result);

        auto native = context->constructor_->imageReceiver_;
        if (native == nullptr) {
            IMAGE_ERR("Native instance is nullptr");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        } else if (native->iraContext_ == nullptr) {
            IMAGE_ERR("Image receiver context is nullptr");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        } else {
            napi_create_string_utf8(env, native->iraContext_->GetReceiverKey().c_str(),
                                    NAPI_AUTO_LENGTH, &result);
            context->status = SUCCESS;
        }

        IMAGE_LINE_OUT();
        CommonCallbackRoutine(env, context, result);
    };

    return JSCommonProcess(args);
}

#ifdef IMAGE_SAVE_BUFFER_TO_PIC
static void DoCallBackTest(OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1)
{
    if (surfaceBuffer1 == nullptr) {
        IMAGE_ERR("surfaceBuffer1 is null");
        return;
    }

    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    shared_ptr<ImageReceiver> imageReceiver1 = imageReceiverManager.getImageReceiverByKeyId("1");
    if (imageReceiver1 == nullptr || imageReceiver1->iraContext_ == nullptr) {
        return;
    }
    IMAGE_ERR("DoCallBackTest format %{public}d", imageReceiver1->iraContext_->GetFormat());

    InitializationOptions opts;
    opts.size.width = surfaceBuffer1->GetWidth();
    opts.size.height = surfaceBuffer1->GetHeight();
    opts.pixelFormat = OHOS::Media::PixelFormat::BGRA_8888;
    opts.alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.scaleMode = OHOS::Media::ScaleMode::CENTER_CROP;
    opts.editable = true;
    IMAGE_ERR("DoCallBackTest Width %{public}d", opts.size.width);
    IMAGE_ERR("DoCallBackTest Height %{public}d", opts.size.height);
    int fd = open("/data/receiver/test.jpg", O_RDWR | O_CREAT);
    imageReceiver1->SaveBufferAsImage(fd, surfaceBuffer1, opts);
}
#endif
static void FailedCallbackRoutine(napi_env env, Context &context, uint32_t errCode)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (context != nullptr) {
        context->status = ERR_IMAGE_INIT_ABNORMAL;
    }
    CommonCallbackRoutine(env, context, result);
}
napi_value ImageReceiverNapi::JsReadLatestImage(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::ASYNC,
        .name = "JsReadLatestImage",
        .callBack = nullptr,
        .argc = ARGS1,
        .queryArgs = PrepareOneArg,
    };

    args.callBack = [](napi_env env, napi_status status, Context context) {
        IMAGE_LINE_IN();
        auto native = context->constructor_->imageReceiver_;
        if (native == nullptr) {
            IMAGE_ERR("Native instance is nullptr");
            FailedCallbackRoutine(env, context, ERR_IMAGE_INIT_ABNORMAL);
            return;
        }
        auto image = native->LastNativeImage();
        if (image == nullptr) {
            IMAGE_ERR("LastNativeImage is nullptr");
            FailedCallbackRoutine(env, context, ERR_IMAGE_INIT_ABNORMAL);
            return;
        }
#ifdef IMAGE_DEBUG_FLAG
        if (context->constructor_->isCallBackTest) {
            context->constructor_->isCallBackTest = false;
#ifdef IMAGE_SAVE_BUFFER_TO_PIC
            DoCallBackTest(image->GetBuffer());
#endif
        }
#endif
        napi_value result = ImageNapi::Create(env, image);
        if (result == nullptr) {
            IMAGE_ERR("ImageNapi Create is nullptr");
            FailedCallbackRoutine(env, context, ERR_IMAGE_INIT_ABNORMAL);
            return;
        }
        context->status = SUCCESS;
        IMAGE_LINE_OUT();
        CommonCallbackRoutine(env, context, result);
    };

    return JSCommonProcess(args);
}

napi_value ImageReceiverNapi::JsReadNextImage(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::ASYNC,
        .name = "JsReadNextImage",
        .callBack = nullptr,
        .argc = ARGS1,
        .queryArgs = PrepareOneArg,
    };

    args.callBack = [](napi_env env, napi_status status, Context context) {
        IMAGE_LINE_IN();
        auto native = context->constructor_->imageReceiver_;
        if (native == nullptr) {
            IMAGE_ERR("Native instance is nullptr");
            FailedCallbackRoutine(env, context, ERR_IMAGE_INIT_ABNORMAL);
            return;
        }
        auto image = native->NextNativeImage();
        if (image == nullptr) {
            IMAGE_ERR("NextNativeImage is nullptr");
            FailedCallbackRoutine(env, context, ERR_IMAGE_INIT_ABNORMAL);
            return;
        }
#ifdef IMAGE_DEBUG_FLAG
        if (context->constructor_->isCallBackTest) {
            context->constructor_->isCallBackTest = false;
#ifdef IMAGE_SAVE_BUFFER_TO_PIC
            DoCallBackTest(image->GetBuffer());
#endif
        }
#endif
        napi_value result = ImageNapi::Create(env, image);
        if (result == nullptr) {
            IMAGE_ERR("ImageNapi Create is nullptr");
            FailedCallbackRoutine(env, context, ERR_IMAGE_INIT_ABNORMAL);
            return;
        }
        context->status = SUCCESS;
        IMAGE_LINE_OUT();
        CommonCallbackRoutine(env, context, result);
    };

    return JSCommonProcess(args);
}

static bool CheckOnParam0(napi_env env, napi_value value, const std::string& refStr)
{
    bool ret = true;
    size_t bufLength = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &bufLength);
    if (status != napi_ok || bufLength > PATH_MAX) {
        return false;
    }

    char *buffer = static_cast<char *>(malloc((bufLength + 1) * sizeof(char)));
    if (buffer == nullptr) {
        return false;
    }

    status = napi_get_value_string_utf8(env, value, buffer, bufLength + 1, &bufLength);
    if (status != napi_ok) {
        ret = false;
    } else {
        std::string strValue = buffer;
        if (strValue.compare(refStr) != 0) {
            IMAGE_ERR("strValue is %{public}s", strValue.c_str());
            ret = false;
        }
    }

    free(buffer);
    buffer = nullptr;
    return ret;
}

static bool JsOnQueryArgs(ImageReceiverCommonArgs &args, ImageReceiverInnerContext &ic)
{
    if (ic.argc == ARGS2) {
        auto argType0 = ImageNapiUtils::getType(args.env, ic.argv[PARAM0]);
        auto argType1 = ImageNapiUtils::getType(args.env, ic.argv[PARAM1]);
        if (argType0 == napi_string && argType1 == napi_function) {
            if (!ImageNapiUtils::GetUtf8String(args.env, ic.argv[PARAM0], ic.onType)) {
                ImageNapiUtils::ThrowExceptionError(args.env, static_cast<int32_t>(napi_invalid_arg),
                    "Could not get On type string");
                return false;
            }

            if (!CheckOnParam0(args.env, ic.argv[PARAM0], "imageArrival")) {
                ImageNapiUtils::ThrowExceptionError(args.env, static_cast<int32_t>(napi_invalid_arg),
                    "Unsupport PARAM0");
                return false;
            }

            napi_create_reference(args.env, ic.argv[PARAM1], ic.refCount, &(ic.context->callbackRef));
        } else {
            std::string errMsg = "Unsupport args type: ";
            ImageNapiUtils::ThrowExceptionError(args.env, static_cast<int32_t>(napi_invalid_arg),
                errMsg.append(std::to_string(argType0)).append(std::to_string(argType1)));
            return false;
        }
    } else {
        std::string errMsg = "Invalid argc: ";
        ImageNapiUtils::ThrowExceptionError(args.env, static_cast<int32_t>(napi_invalid_arg),
            errMsg.append(std::to_string(ic.argc)));
        return false;
    }

    napi_get_undefined(args.env, &ic.result);
    return true;
}

static void Callback(uv_work_t *work, int status)
{
    IMAGE_LINE_IN();
    Context context = reinterpret_cast<Context>(work->data);
    if (context == nullptr) {
        IMAGE_ERR("context is empty");
    } else {
        if (context->env != nullptr && context->callbackRef != nullptr) {
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(context->env, &scope);
            napi_value result[PARAM2] = {0};
            napi_value retVal;
            napi_value callback = nullptr;
            if (scope == nullptr) {
                delete work;
                return;
            }
            napi_create_uint32(context->env, SUCCESS, &result[0]);
            napi_get_undefined(context->env, &result[1]);
            napi_get_reference_value(context->env, context->callbackRef, &callback);
            if (callback != nullptr) {
                napi_call_function(context->env, nullptr, callback, PARAM2, result, &retVal);
            } else {
                IMAGE_ERR("napi_get_reference_value callback is empty");
            }
            napi_close_handle_scope(context->env, scope);
        } else {
            IMAGE_ERR("env or callbackRef is empty");
        }
    }
    delete work;
    IMAGE_LINE_OUT();
}

void ImageReceiverNapi::DoCallBack(shared_ptr<ImageReceiverAsyncContext> &context,
                                   string name, CompleteCallback callBack)
{
    IMAGE_FUNCTION_IN();
    auto localContext = std::make_unique<shared_ptr<ImageReceiverAsyncContext>> (context);
    if (context == nullptr) {
        IMAGE_ERR("gContext is empty");
        localContext.release();
        return;
    }
    if (context->env == nullptr) {
        IMAGE_ERR("env is empty");
        localContext.release();
        return;
    }

    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(context->env, &loop);
    if (loop == nullptr) {
        IMAGE_ERR("napi_get_uv_event_loop failed");
        localContext.release();
        return;
    }

    unique_ptr<uv_work_t> work = make_unique<uv_work_t>();
    if (work == nullptr) {
        IMAGE_ERR("DoCallBack: No memory");
        localContext.release();
        return;
    }
    work->data = reinterpret_cast<void *>(context.get());
    int ret = uv_queue_work(loop, work.get(), [] (uv_work_t *work) {}, [] (uv_work_t *work, int status) {
        Callback(work, status);
    });
    if (ret != 0) {
        IMAGE_ERR("Failed to execute DoCallBack work queue");
    } else {
        work.release();
    }
    localContext.release();
    IMAGE_FUNCTION_OUT();
}

napi_value ImageReceiverNapi::JsOn(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::ASYNC,
        .name = "JsOn",
    };
    args.argc = ARGS2;
    args.asyncLater = true;
    args.queryArgs = JsOnQueryArgs;
    args.nonAsyncBack = [](ImageReceiverCommonArgs &args, ImageReceiverInnerContext &ic) -> bool {
        IMAGE_LINE_IN();
        napi_get_undefined(args.env, &(ic.result));

        auto native = ic.context->constructor_->imageReceiver_;
        if (native == nullptr) {
            IMAGE_ERR("Native instance is nullptr");
            ic.context->status = ERR_IMAGE_INIT_ABNORMAL;
            return false;
        }
        shared_ptr<ImageReceiverAvaliableListener> listener = make_shared<ImageReceiverAvaliableListener>();
        listener->context = std::move(ic.context);
        listener->context->env = args.env;
        listener->name = args.name;

        native->RegisterBufferAvaliableListener((std::shared_ptr<SurfaceBufferAvaliableListener> &)listener);

        IMAGE_LINE_OUT();
        return true;
    };

    return JSCommonProcess(args);
}

napi_value ImageReceiverNapi::JsOffOneArg(napi_env env, napi_callback_info info)
{
    ImageReceiverCommonArgs args = {
        .env = env, .info = info, .async = CallType::ASYNC,
        .name = "JsOff", .argc = ARGS1, .asyncLater = true,
    };

    args.queryArgs = [](ImageReceiverCommonArgs &args, ImageReceiverInnerContext &ic) -> bool {
        if (ic.argc != ARGS1) {
            std::string errMsg = "Invalid argc: ";
            ImageNapiUtils::ThrowExceptionError(args.env, static_cast<int32_t>(napi_invalid_arg),
                errMsg.append(std::to_string(ic.argc)));
            return false;
        }
        auto argType = ImageNapiUtils::getType(args.env, ic.argv[PARAM0]);
        if (argType != napi_string) {
            std::string errMsg = "Unsupport args type: ";
            ImageNapiUtils::ThrowExceptionError(args.env, static_cast<int32_t>(napi_invalid_arg),
                errMsg.append(std::to_string(argType)));
            return false;
        }
        if (!ImageNapiUtils::GetUtf8String(args.env, ic.argv[PARAM0], ic.onType)) {
            ImageNapiUtils::ThrowExceptionError(args.env, static_cast<int32_t>(napi_invalid_arg),
                "Could not get On type string");
            return false;
        }
        if (!CheckOnParam0(args.env, ic.argv[PARAM0], "imageArrival")) {
            ImageNapiUtils::ThrowExceptionError(args.env, static_cast<int32_t>(napi_invalid_arg),
                "Unsupport PARAM0");
            return false;
        }
        napi_get_undefined(args.env, &ic.result);
        return true;
    };

    args.nonAsyncBack = [](ImageReceiverCommonArgs &args, ImageReceiverInnerContext &ic) -> bool {
        IMAGE_LINE_IN();
        napi_get_undefined(args.env, &ic.result);
        ic.context->constructor_->imageReceiver_->UnRegisterBufferAvaliableListener();
        ic.context->status = SUCCESS;
        napi_create_uint32(args.env, ic.context->status, &ic.result);
        IMAGE_LINE_OUT();
        return true;
    };

    return JSCommonProcess(args);
}

napi_value ImageReceiverNapi::JsOffTwoArgs(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    ImageReceiverCommonArgs args = {
        .env = env, .info = info, .async = CallType::ASYNC,
        .name = "JsOff", .argc = ARGS2, .queryArgs = JsOnQueryArgs,
    };

    args.callBack = [](napi_env env, napi_status status, Context context) {
        IMAGE_LINE_IN();
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        context->constructor_->imageReceiver_->UnRegisterBufferAvaliableListener();
        context->status = SUCCESS;
        IMAGE_LINE_OUT();
        CommonCallbackRoutine(env, context, result);
    };

    JSCommonProcess(args);
    napi_create_uint32(args.env, SUCCESS, &result);
    return result;
}

napi_value ImageReceiverNapi::JsOff(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    struct ImageReceiverInnerContext ic;
    ic.argc = ARGS2;
    ic.argv.resize(ic.argc);
    napi_get_undefined(env, &ic.result);
    IMG_JS_ARGS(env, info, ic.status, ic.argc, &(ic.argv[0]), ic.thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(ic.status), ic.result, IMAGE_ERR("fail to napi_get_cb_info"));

    if (ic.argc == ARGS1) {
        return JsOffOneArg(env, info);
    } else if (ic.argc == ARGS2) {
        return JsOffTwoArgs(env, info);
    } else {
        IMAGE_ERR("invalid argument count");
        return ic.result;
    }
}

napi_value ImageReceiverNapi::JsRelease(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    ImageReceiverCommonArgs args = {
        .env = env, .info = info,
        .async = CallType::ASYNC,
        .name = "JsRelease",
        .callBack = nullptr,
        .argc = ARGS1,
        .queryArgs = PrepareOneArg,
    };

    args.callBack = [](napi_env env, napi_status status, Context context) {
        IMAGE_LINE_IN();
        napi_value result = nullptr;
        napi_get_undefined(env, &result);

        context->constructor_->UnRegisterReceiverListener();
        context->constructor_->NativeRelease();
        context->status = SUCCESS;

        IMAGE_LINE_OUT();
        CommonCallbackRoutine(env, context, result);
    };

    return JSCommonProcess(args);
}

void ImageReceiverNapi::release()
{
    if (!isRelease) {
        NativeRelease();
        isRelease = true;
    }
}
}  // namespace Media
}  // namespace OHOS
