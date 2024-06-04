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

#include "sendable_pixel_map_napi.h"
#include <mutex>
#include "media_errors.h"
#include "image_log.h"
#include "image_napi_utils.h"
#include "image_pixel_map_napi.h"
#include "image_trace.h"
#include "log_tags.h"
#include "color_space_object_convertor.h"
#include "napi_message_sequence.h"
#include "hitrace_meter.h"
#include "pixel_map.h"
#include "transaction/rs_interfaces.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "SendablePixelMapNapi yzp"

namespace {
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
    constexpr uint32_t NUM_3 = 3;
    constexpr uint32_t NUM_4 = 4;
}

namespace OHOS {
namespace Media {
static const std::string CREATE_PIXEL_MAP_FROM_PARCEL = "CreateSendablPixelMapFromParcel";
static const std::string MARSHALLING = "marshalling";
static const std::map<std::string, std::set<uint32_t>> ETS_API_ERROR_CODE = {
    {CREATE_PIXEL_MAP_FROM_PARCEL, {62980096, 62980105, 62980115, 62980097,
        62980177, 62980178, 62980179, 62980180, 62980246}},
    {MARSHALLING, {62980115, 62980097, 62980096}}
};
static const std::string CLASS_NAME = "SendablePixelMap";
static const std::int32_t NEW_INSTANCE_ARGC = 1;
thread_local napi_ref SendablePixelMapNapi::sConstructor_ = nullptr;
NAPI_MessageSequence* napi_messageSequence_sendable = nullptr;

std::shared_mutex SendablePixelMapNapi::mutex_;
static std::mutex pixelMapCrossThreadMutex_;
struct PositionArea {
    void* pixels;
    size_t size;
    uint32_t offset;
    uint32_t stride;
    Rect region;
};

struct PixelMapAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    napi_ref error = nullptr;
    uint32_t status;
    SendablePixelMapNapi *nConstructor;
    void* colorsBuffer;
    size_t colorsBufferSize;
    InitializationOptions opts;
    PositionArea area;
    std::shared_ptr<PixelMap> rPixelMap;
    std::shared_ptr<PixelMap> alphaMap;
    std::shared_ptr<PixelMap> wPixelMap;
    double alpha = -1;
    uint32_t resultUint32;
    ImageInfo imageInfo;
    double xArg = 0;
    double yArg = 0;
    bool xBarg = false;
    bool yBarg = false;
    std::shared_ptr<OHOS::ColorManager::ColorSpace> colorSpace;
    std::string surfaceId;
};

static PixelFormat ParsePixlForamt(int32_t val)
{
    if (val <= static_cast<int32_t>(PixelFormat::CMYK)) {
        return PixelFormat(val);
    }

    return PixelFormat::UNKNOWN;
}

static AlphaType ParseAlphaType(int32_t val)
{
    if (val <= static_cast<int32_t>(AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL)) {
        return AlphaType(val);
    }

    return AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
}

static ScaleMode ParseScaleMode(int32_t val)
{
    if (val <= static_cast<int32_t>(ScaleMode::CENTER_CROP)) {
        return ScaleMode(val);
    }

    return ScaleMode::FIT_TARGET_SIZE;
}

static bool parseSize(napi_env env, napi_value root, Size* size)
{
    if (size == nullptr) {
        return false;
    }

    if (!GET_INT32_BY_NAME(root, "height", size->height)) {
        return false;
    }

    if (!GET_INT32_BY_NAME(root, "width", size->width)) {
        return false;
    }

    return true;
}

static bool parseInitializationOptions(napi_env env, napi_value root, InitializationOptions* opts)
{
    uint32_t tmpNumber = 0;
    napi_value tmpValue = nullptr;

    if (opts == nullptr) {
        return false;
    }

    if (!GET_BOOL_BY_NAME(root, "editable", opts->editable)) {
        opts->editable = true;
    }

    if (!GET_UINT32_BY_NAME(root, "alphaType", tmpNumber)) {
        IMAGE_LOGI("no alphaType in initialization options");
    }
    opts->alphaType = ParseAlphaType(tmpNumber);

    tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "pixelFormat", tmpNumber)) {
        IMAGE_LOGI("no pixelFormat in initialization options");
    }
    opts->pixelFormat = ParsePixlForamt(tmpNumber);

    tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "srcPixelFormat", tmpNumber)) {
        IMAGE_LOGI("no srcPixelFormat in initialization options");
    }
    opts->srcPixelFormat = ParsePixlForamt(tmpNumber);

    tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "scaleMode", tmpNumber)) {
        IMAGE_LOGI("no scaleMode in initialization options");
    }
    opts->scaleMode = ParseScaleMode(tmpNumber);

    if (!GET_NODE_BY_NAME(root, "size", tmpValue)) {
        return false;
    }

    if (!parseSize(env, tmpValue, &(opts->size))) {
        return false;
    }
    return true;
}

ImageType SendablePixelMapNapi::ParserImageType(napi_env env, napi_value argv)
{
    napi_value constructor = nullptr;
    napi_value global = nullptr;
    bool isInstance = false;
    napi_status ret = napi_invalid_arg;

    napi_get_global(env, &global);

    ret = napi_get_named_property(env, global, "PixelMap", &constructor);
    if (ret != napi_ok) {
        IMAGE_LOGI("Get SendablePixelMapNapi property failed!");
    }

    ret = napi_instanceof(env, argv, constructor, &isInstance);
    if (ret == napi_ok && isInstance) {
        return ImageType::TYPE_PIXEL_MAP;
    }

    IMAGE_LOGI("InValued type!");
    return ImageType::TYPE_UNKNOWN;
}

static bool parseRegion(napi_env env, napi_value root, Rect* region)
{
    napi_value tmpValue = nullptr;

    if (region == nullptr) {
        return false;
    }

    if (!GET_INT32_BY_NAME(root, "x", region->left)) {
        return false;
    }

    if (!GET_INT32_BY_NAME(root, "y", region->top)) {
        return false;
    }

    if (!GET_NODE_BY_NAME(root, "size", tmpValue)) {
        return false;
    }

    if (!GET_INT32_BY_NAME(tmpValue, "height", region->height)) {
        return false;
    }

    if (!GET_INT32_BY_NAME(tmpValue, "width", region->width)) {
        return false;
    }

    return true;
}

static bool parsePositionArea(napi_env env, napi_value root, PositionArea* area)
{
    napi_value tmpValue = nullptr;

    if (area == nullptr) {
        return false;
    }

    if (!GET_BUFFER_BY_NAME(root, "pixels", area->pixels, area->size)) {
        return false;
    }

    if (!GET_UINT32_BY_NAME(root, "offset", area->offset)) {
        return false;
    }

    if (!GET_UINT32_BY_NAME(root, "stride", area->stride)) {
        return false;
    }

    if (!GET_NODE_BY_NAME(root, "region", tmpValue)) {
        return false;
    }

    if (!parseRegion(env, tmpValue, &(area->region))) {
        return false;
    }
    return true;
}

static void CommonCallbackRoutine(napi_env env, PixelMapAsyncContext* &asyncContext, const napi_value &valueParam)
{
    napi_value result[NUM_2] = {0};
    napi_value retVal;
    napi_value callback = nullptr;

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
    } else {
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, NUM_2, result, &retVal);
        napi_delete_reference(env, asyncContext->callbackRef);
    }

    napi_delete_async_work(env, asyncContext->work);
    napi_close_handle_scope(env, scope);

    delete asyncContext;
    asyncContext = nullptr;
}

STATIC_COMPLETE_FUNC(EmptyResult)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto context = static_cast<PixelMapAsyncContext*>(data);

    CommonCallbackRoutine(env, context, result);
}

STATIC_COMPLETE_FUNC(GeneralError)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<PixelMapAsyncContext*>(data);
    context->status = ERR_RESOURCE_UNAVAILABLE;
    CommonCallbackRoutine(env, context, result);
}

SendablePixelMapNapi::SendablePixelMapNapi():env_(nullptr)
{
    static std::atomic<uint32_t> currentId = 0;
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
}

SendablePixelMapNapi::~SendablePixelMapNapi()
{
    release();
}

static napi_value DoInitAfter(napi_env env,
                              napi_value exports,
                              napi_value constructor,
                              size_t property_count,
                              const napi_property_descriptor* properties)
{
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
        nullptr, IMAGE_LOGE("set named property fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_properties(env, exports, property_count, properties)),
        nullptr, IMAGE_LOGE("define properties fail")
    );
    return exports;
}

napi_value SendablePixelMapNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor props[] = {
        DECLARE_NAPI_FUNCTION("readPixelsToBuffer", ReadPixelsToBuffer),
        DECLARE_NAPI_FUNCTION("readPixelsToBufferSync", ReadPixelsToBufferSync),
        DECLARE_NAPI_FUNCTION("readPixels", ReadPixels),
        DECLARE_NAPI_FUNCTION("readPixelsSync", ReadPixelsSync),
        DECLARE_NAPI_FUNCTION("writePixels", WritePixels),
        DECLARE_NAPI_FUNCTION("writePixelsSync", WritePixelsSync),
        DECLARE_NAPI_FUNCTION("writeBufferToPixels", WriteBufferToPixels),
        DECLARE_NAPI_FUNCTION("writeBufferToPixelsSync", WriteBufferToPixelsSync),
        DECLARE_NAPI_FUNCTION("getImageInfo", GetImageInfo),
        DECLARE_NAPI_FUNCTION("getImageInfoSync", GetImageInfoSync),
        DECLARE_NAPI_FUNCTION("getBytesNumberPerRow", GetBytesNumberPerRow),
        DECLARE_NAPI_FUNCTION("getPixelBytesNumber", GetPixelBytesNumber),
        DECLARE_NAPI_FUNCTION("isSupportAlpha", IsSupportAlpha),
        DECLARE_NAPI_FUNCTION("setAlphaAble", SetAlphaAble),
        DECLARE_NAPI_FUNCTION("createAlphaPixelmap", CreateAlphaPixelmap),
        DECLARE_NAPI_FUNCTION("createAlphaPixelmapSync", CreateAlphaPixelmapSync),
        DECLARE_NAPI_FUNCTION("getDensity", GetDensity),
        DECLARE_NAPI_FUNCTION("setDensity", SetDensity),
        DECLARE_NAPI_FUNCTION("opacity", SetAlpha),
        DECLARE_NAPI_FUNCTION("opacitySync", SetAlphaSync),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("scale", Scale),
        DECLARE_NAPI_FUNCTION("scaleSync", ScaleSync),
        DECLARE_NAPI_FUNCTION("translate", Translate),
        DECLARE_NAPI_FUNCTION("translateSync", TranslateSync),
        DECLARE_NAPI_FUNCTION("rotate", Rotate),
        DECLARE_NAPI_FUNCTION("rotateSync", RotateSync),
        DECLARE_NAPI_FUNCTION("flip", Flip),
        DECLARE_NAPI_FUNCTION("flipSync", FlipSync),
        DECLARE_NAPI_FUNCTION("crop", Crop),
        DECLARE_NAPI_FUNCTION("cropSync", CropSync),
        DECLARE_NAPI_FUNCTION("getColorSpace", GetColorSpace),
        DECLARE_NAPI_FUNCTION("setColorSpace", SetColorSpace),
        DECLARE_NAPI_FUNCTION("applyColorSpace", ApplyColorSpace),
        DECLARE_NAPI_FUNCTION("marshalling", Marshalling),
        DECLARE_NAPI_FUNCTION("unmarshalling", Unmarshalling),
        DECLARE_NAPI_GETTER("isEditable", GetIsEditable),
        DECLARE_NAPI_GETTER("isStrideAlignment", GetIsStrideAlignment),
    };

    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMap", CreateSendablePixelMap),
        DECLARE_NAPI_STATIC_FUNCTION("createPremultipliedPixelMap", CreatePremultipliedSendablePixelMap),
        DECLARE_NAPI_STATIC_FUNCTION("createUnpremultipliedPixelMap", CreateUnpremultipliedSendablePixelMap),
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapSync", CreateSendablePixelMapSync),
        DECLARE_NAPI_STATIC_FUNCTION("unmarshalling", Unmarshalling),
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapFromParcel", CreateSendablPixelMapFromParcel),
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapFromSurface", CreateSendablePixelMapFromSurface),
        DECLARE_NAPI_STATIC_FUNCTION("convertFromPixelMap", ConvertFromPixelMap),
        DECLARE_NAPI_STATIC_FUNCTION("convertToPixelMap", ConvertToPixelMap),
    };

    napi_value constructor = nullptr;

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_sendable_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
            Constructor, nullptr, IMG_ARRAY_SIZE(props), props, nullptr, &constructor)),
        nullptr, IMAGE_LOGE("define class fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_create_reference(env, constructor, 1, &sConstructor_)),
        nullptr, IMAGE_LOGE("create reference fail")
    );

    auto result = DoInitAfter(env, exports, constructor,
        IMG_ARRAY_SIZE(static_prop), static_prop);

    IMAGE_LOGD("Init success");
    return result;
}

static napi_status NapiUnwrap(napi_env env, napi_value object, void** result, bool isSendable = true)
{
    napi_status status = napi_invalid_arg;
    if (isSendable) {
        status = napi_unwrap_sendable(env, object, result);
        if (!IMG_IS_OK(status)) {
            IMAGE_LOGE("NapiUnwrap napi_unwrap_sendable failed");
        }
    } else {
        status = napi_unwrap(env, object, result);
        if (!IMG_IS_OK(status)) {
            IMAGE_LOGE("NapiUnwrap napi_unwrap failed");
        }
    }
    return status;
}

std::shared_ptr<PixelMap> SendablePixelMapNapi::GetSendablePixelMap(napi_env env, napi_value pixelmap)
{
    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;

    napi_status status = NapiUnwrap(env, pixelmap, reinterpret_cast<void**>(&pixelMapNapi));
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("GetPixelMap napi unwrap failed");
        return nullptr;
    }
    IMG_NAPI_CHECK_RET_D(IMG_NOT_NULL(pixelMapNapi), nullptr,
        IMAGE_LOGE("GetPixelMap pixmapNapi is nullptr"));

    auto pixelmapNapiPtr = pixelMapNapi.release();
    if (pixelmapNapiPtr == nullptr) {
        IMAGE_LOGE("GetPixelMap SendablePixelMapNapi is nullptr");
        return nullptr;
    }
    return pixelmapNapiPtr->nativePixelMap_;
}

bool SendablePixelMapNapi::IsLockPixelMap()
{
    return (lockCount > 0);
}

bool SendablePixelMapNapi::LockPixelMap()
{
    lockCount++;
    return true;
}

void SendablePixelMapNapi::UnlockPixelMap()
{
    if (lockCount > 0) {
        lockCount--;
    }
}

static napi_status NewPixelNapiInstance(napi_env &env, napi_value &constructor,
    std::shared_ptr<PixelMap> &pixelMap, napi_value &result)
{
    napi_status status;
    if (pixelMap == nullptr) {
        status = napi_invalid_arg;
        IMAGE_LOGE("NewPixelNapiInstance pixelMap is nullptr");
        return status;
    }
    size_t argc = NEW_INSTANCE_ARGC;
    napi_value argv[NEW_INSTANCE_ARGC] = { 0 };
    napi_create_int32(env, pixelMap->GetUniqueId(), &argv[0]);
    PixelMapContainer::GetInstance().Insert(pixelMap->GetUniqueId(), pixelMap);
    status = napi_new_instance(env, constructor, argc, argv, &result);
    return status;
}

napi_value SendablePixelMapNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &thisVar);
    size_t argc = NEW_INSTANCE_ARGC;
    napi_value argv[NEW_INSTANCE_ARGC] = { 0 };
    IMAGE_LOGD("Constructor IN");
    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    IMG_NAPI_CHECK_RET(IMG_IS_READY(status, thisVar), undefineVar);
    uint32_t pixelMapId = 0;
    napi_get_value_uint32(env, argv[0], &pixelMapId);
    std::unique_ptr<SendablePixelMapNapi> pPixelMapNapi = std::make_unique<SendablePixelMapNapi>();

    IMG_NAPI_CHECK_RET(IMG_NOT_NULL(pPixelMapNapi), undefineVar);

    pPixelMapNapi->env_ = env;
    if (PixelMapContainer::GetInstance().Find(pixelMapId)) {
        pPixelMapNapi->nativePixelMap_ = PixelMapContainer::GetInstance()[pixelMapId];
        IMAGE_LOGD("Constructor in napi_id:%{public}d, id:%{public}d",
            pPixelMapNapi->GetUniqueId(), pPixelMapNapi->nativePixelMap_->GetUniqueId());
    } else {
        IMAGE_LOGE("Constructor nativePixelMap is nullptr");
    }

    status = napi_wrap_sendable(env, thisVar, reinterpret_cast<void*>(pPixelMapNapi.get()),
        SendablePixelMapNapi::Destructor, nullptr);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), undefineVar, IMAGE_LOGE("Failure wrapping js to native napi"));

    pPixelMapNapi.release();
    PixelMapContainer::GetInstance().Erase(pixelMapId);
    return thisVar;
}

void SendablePixelMapNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        std::lock_guard<std::mutex> lock(pixelMapCrossThreadMutex_);
        IMAGE_LOGD("Destructor SendablePixelMapNapi");
        delete reinterpret_cast<SendablePixelMapNapi*>(nativeObject);
        nativeObject = nullptr;
    }
}

static void BuildContextError(napi_env env, napi_ref &error, const std::string errMsg, const int32_t errCode)
{
    IMAGE_LOGE("%{public}s", errMsg.c_str());
    napi_value tmpError;
    ImageNapiUtils::CreateErrorObj(env, tmpError, errCode, errMsg);
    napi_create_reference(env, tmpError, NUM_1, &(error));
}

STATIC_EXEC_FUNC(CreateSendablePixelMap)
{
    auto context = static_cast<PixelMapAsyncContext*>(data);
    auto colors = static_cast<uint32_t*>(context->colorsBuffer);
    if (colors == nullptr) {
        auto pixelmap = PixelMap::Create(context->opts);
        context->rPixelMap = std::move(pixelmap);
    } else {
        auto pixelmap = PixelMap::Create(colors, context->colorsBufferSize, context->opts);
        context->rPixelMap = std::move(pixelmap);
    }

    if (IMG_NOT_NULL(context->rPixelMap)) {
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
}

void SendablePixelMapNapi::CreateSendablePixelMapComplete(napi_env env, napi_status status, void *data)
{
    napi_value constructor = nullptr;
    napi_value result = nullptr;

    IMAGE_LOGD("CreatePixelMapComplete IN");
    auto context = static_cast<PixelMapAsyncContext*>(data);
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, context->rPixelMap, result);
    }
    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        IMAGE_LOGE("New instance could not be obtained");
        napi_get_undefined(env, &result);
    }
    CommonCallbackRoutine(env, context, result);
}

STATIC_EXEC_FUNC(CreatePremultipliedPixelMap)
{
    auto context = static_cast<PixelMapAsyncContext*>(data);
    if (IMG_NOT_NULL(context->rPixelMap) && IMG_NOT_NULL(context->wPixelMap)) {
        bool isPremul = true;
        if (context->wPixelMap->IsEditable()) {
            context->status = context->rPixelMap->ConvertAlphaFormat(*context->wPixelMap.get(), isPremul);
        } else {
            context->status = ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY;
        }
    } else {
        context->status = ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
}

STATIC_EXEC_FUNC(CreateUnpremultipliedPixelMap)
{
    auto context = static_cast<PixelMapAsyncContext*>(data);
    if (IMG_NOT_NULL(context->rPixelMap) && IMG_NOT_NULL(context->wPixelMap)) {
        bool isPremul = false;
        if (context->wPixelMap->IsEditable()) {
            context->status = context->rPixelMap->ConvertAlphaFormat(*context->wPixelMap.get(), isPremul);
        } else {
            context->status = ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY;
        }
    } else {
        context->status = ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
}

napi_value SendablePixelMapNapi::CreatePremultipliedSendablePixelMap(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_3] = {0};
    size_t argCount = NUM_3;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount >= NUM_2,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"),
        IMAGE_LOGE("Invalid args count %{public}zu", argCount));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();

    if (ParserImageType(env, argValue[NUM_0]) == ImageType::TYPE_PIXEL_MAP &&
        ParserImageType(env, argValue[NUM_1]) == ImageType::TYPE_PIXEL_MAP) {
        asyncContext->rPixelMap = GetSendablePixelMap(env, argValue[NUM_0]);
        asyncContext->wPixelMap = GetSendablePixelMap(env, argValue[NUM_1]);
        if (asyncContext->rPixelMap == nullptr || asyncContext->wPixelMap == nullptr) {
            BuildContextError(env, asyncContext->error, "input image type mismatch", ERR_IMAGE_GET_DATA_ABNORMAL);
        }
    } else {
        BuildContextError(env, asyncContext->error, "input image type mismatch",
            ERR_IMAGE_GET_DATA_ABNORMAL);
    }

    IMG_NAPI_CHECK_RET_D(asyncContext->error == nullptr, nullptr, IMAGE_LOGE("input image type mismatch"));
    if (argCount == NUM_3 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    }

    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->error == nullptr,
        BuildContextError(env, asyncContext->error, "CreatePremultipliedPixelMapError", ERR_IMAGE_GET_DATA_ABNORMAL),
        IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreatePremultipliedPixelMapGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreatePremultipliedPixelMap",
        CreatePremultipliedPixelMapExec, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value SendablePixelMapNapi::CreateUnpremultipliedSendablePixelMap(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_3] = {0};
    size_t argCount = NUM_3;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount >= NUM_2,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"),
        IMAGE_LOGE("Invalid args count %{public}zu", argCount));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();

    if (ParserImageType(env, argValue[NUM_0]) == ImageType::TYPE_PIXEL_MAP &&
        ParserImageType(env, argValue[NUM_1]) == ImageType::TYPE_PIXEL_MAP) {
        asyncContext->rPixelMap = GetSendablePixelMap(env, argValue[NUM_0]);
        asyncContext->wPixelMap = GetSendablePixelMap(env, argValue[NUM_1]);
        if (asyncContext->rPixelMap == nullptr || asyncContext->wPixelMap == nullptr) {
            BuildContextError(env, asyncContext->error, "input image type mismatch", ERR_IMAGE_GET_DATA_ABNORMAL);
        }
    } else {
        BuildContextError(env, asyncContext->error, "input image type mismatch",
            ERR_IMAGE_GET_DATA_ABNORMAL);
    }

    IMG_NAPI_CHECK_RET_D(asyncContext->error == nullptr, nullptr, IMAGE_LOGE("input image type mismatch"));
    if (argCount == NUM_3 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    }

    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->error == nullptr,
        BuildContextError(env, asyncContext->error, "CreateUnpremultipliedPixelMapError", ERR_IMAGE_GET_DATA_ABNORMAL),
        IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreateUnpremultipliedPixelMapGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreateUnpremultipliedPixelMap",
        CreateUnpremultipliedPixelMapExec, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value SendablePixelMapNapi::CreateSendablePixelMap(napi_env env, napi_callback_info info)
{
    if (SendablePixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        SendablePixelMapNapi::Init(env, exports);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_4] = {0};
    size_t argCount = NUM_4;
    IMAGE_LOGD("CreateSendablePixelMap IN");

    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    // we are static method!
    // thisVar is nullptr here
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();

    status = napi_get_arraybuffer_info(env, argValue[NUM_0], &(asyncContext->colorsBuffer),
        &(asyncContext->colorsBufferSize));

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("colors mismatch"));

    IMG_NAPI_CHECK_RET_D(parseInitializationOptions(env, argValue[1], &(asyncContext->opts)),
        nullptr, IMAGE_LOGE("InitializationOptions mismatch"));

    if (argCount == NUM_3 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreateSendablePixelMap",
        CreateSendablePixelMapExec, CreateSendablePixelMapComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value SendablePixelMapNapi::ConvertFromPixelMap(napi_env env, napi_callback_info info)
{
    if (SendablePixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        SendablePixelMapNapi::Init(env, exports);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;
    IMAGE_LOGD("ConvertFromPixelMap IN2");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    if (!IMG_IS_OK(status)) {
        return ImageNapiUtils::ThrowExceptionError(env,
            COMMON_ERR_INVALID_PARAMETER, "ConvertFromPixelMap Invalid parameter");
    }
    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    NapiUnwrap(env, argValue[0], reinterpret_cast<void**>(&pixelMapNapi), false);
    if (!(IMG_NOT_NULL(pixelMapNapi) && IMG_NOT_NULL(pixelMapNapi->GetPixelNapiInner()))) {
        return ImageNapiUtils::ThrowExceptionError(env,
            ERR_IMAGE_INIT_ABNORMAL, "ConvertFromPixelMap napi_unwrap failed");
    }

    std::shared_ptr<PixelMap> nativePixelMap = pixelMapNapi->GetPixelNapiInner();
    pixelMapNapi->ReleasePixelNapiInner();
    pixelMapNapi.release();
    result = CreateSendablePixelMap(env, nativePixelMap);
    if (!IMG_NOT_NULL(result)) {
        return ImageNapiUtils::ThrowExceptionError(env,
            ERR_IMAGE_INIT_ABNORMAL, "ConvertFromPixelMap wrap failed");
    }
    return result;
}

napi_value SendablePixelMapNapi::ConvertToPixelMap(napi_env env, napi_callback_info info)
{
    if (SendablePixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        SendablePixelMapNapi::Init(env, exports);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;
    IMAGE_LOGD("ConvertToPixelMap IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    if (!IMG_IS_OK(status)) {
        return ImageNapiUtils::ThrowExceptionError(env,
            COMMON_ERR_INVALID_PARAMETER, "ConvertToPixelMap Invalid parameter");
    }
    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    NapiUnwrap(env, argValue[0], reinterpret_cast<void**>(&pixelMapNapi));
    if (!(IMG_NOT_NULL(pixelMapNapi) && IMG_NOT_NULL(pixelMapNapi->nativePixelMap_))) {
        return ImageNapiUtils::ThrowExceptionError(env,
            ERR_IMAGE_INIT_ABNORMAL, "ConvertToPixelMap napi_unwrap failed");
    }

    std::shared_ptr<PixelMap> nativePixelMap = pixelMapNapi->nativePixelMap_;
    pixelMapNapi->ReleasePixelNapiInner();
    pixelMapNapi.release();
    result = PixelMapNapi::CreatePixelMap(env, nativePixelMap);
    if (!IMG_NOT_NULL(result)) {
        return ImageNapiUtils::ThrowExceptionError(env,
            ERR_IMAGE_INIT_ABNORMAL, "ConvertToPixelMap wrap failed");
    }
    return result;
}

napi_value SendablePixelMapNapi::CreateSendablePixelMapSync(napi_env env, napi_callback_info info)
{
    if (SendablePixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        SendablePixelMapNapi::Init(env, exports);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value constructor = nullptr;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;
    IMAGE_LOGD("CreatePixelMap IN");

    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    // we are static method!
    // thisVar is nullptr here
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    IMG_NAPI_CHECK_RET_D(argCount == NUM_2 || argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"),
        IMAGE_LOGE("Invalid args count %{public}zu", argCount));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();

    if (argCount == NUM_2) {
        status = napi_get_arraybuffer_info(env, argValue[NUM_0], &(asyncContext->colorsBuffer),
        &(asyncContext->colorsBufferSize));
        IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("colors mismatch"));
        IMG_NAPI_CHECK_RET_D(parseInitializationOptions(env, argValue[1], &(asyncContext->opts)),
            nullptr, IMAGE_LOGE("InitializationOptions mismatch"));
    } else if (argCount == NUM_1) {
        IMG_NAPI_CHECK_RET_D(parseInitializationOptions(env, argValue[NUM_0], &(asyncContext->opts)),
            nullptr, IMAGE_LOGE("InitializationOptions mismatch"));
    }
    CreateSendablePixelMapExec(env, static_cast<void*>((asyncContext).get()));
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, asyncContext->rPixelMap, result);
    }
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to create pixel map sync"));
    return result;
}

#if !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
STATIC_EXEC_FUNC(CreateSendablePixelMapFromSurface)
{
    auto context = static_cast<PixelMapAsyncContext*>(data);
    IMAGE_LOGD("CreateSendablePixelMapFromSurface id:%{public}s,area:%{public}d,%{public}d,%{public}d,%{public}d",
        context->surfaceId.c_str(), context->area.region.left, context->area.region.top,
        context->area.region.height, context->area.region.width);

    auto &rsClient = Rosen::RSInterfaces::GetInstance();
    OHOS::Rect r = {
        .x = context->area.region.left,
        .y = context->area.region.top,
        .w = context->area.region.width,
        .h = context->area.region.height,
    };
    std::shared_ptr<Media::PixelMap> pixelMap =
        rsClient.CreatePixelMapFromSurfaceId(std::stoull(context->surfaceId), r);
    context->rPixelMap = std::move(pixelMap);

    if (IMG_NOT_NULL(context->rPixelMap)) {
        context->status = SUCCESS;
    } else {
        context->status = ERR_IMAGE_INVALID_PARAMETER;
    }
}

void SendablePixelMapNapi::CreateSendablePixelMapFromSurfaceComplete(napi_env env, napi_status status, void *data)
{
    napi_value constructor = nullptr;
    napi_value result = nullptr;

    IMAGE_LOGD("CreateSendablePixelMapFromSurface IN");
    auto context = static_cast<PixelMapAsyncContext*>(data);
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, context->rPixelMap, result);
    }
    if (!IMG_IS_OK(status)) {
        context->status = ERR_IMAGE_PIXELMAP_CREATE_FAILED;
        IMAGE_LOGE("New instance could not be obtained");
        napi_get_undefined(env, &result);
    }
    CommonCallbackRoutine(env, context, result);
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

napi_value SendablePixelMapNapi::CreateSendablePixelMapFromSurface(napi_env env, napi_callback_info info)
{
    napi_value globalValue;
    napi_get_global(env, &globalValue);
    napi_value func;
    napi_get_named_property(env, globalValue, "requireNapi", &func);

    napi_value imageInfo;
    napi_create_string_utf8(env, "multimedia.image", NAPI_AUTO_LENGTH, &imageInfo);
    napi_value funcArgv[1] = { imageInfo };
    napi_value returnValue;
    napi_call_function(env, globalValue, func, 1, funcArgv, &returnValue);

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_4] = {0};
    size_t argCount = NUM_4;
    IMAGE_LOGD("CreateSendablePixelMapFromSurface IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    asyncContext->surfaceId = GetStringArgument(env, argValue[NUM_0]);
    bool ret = parseRegion(env, argValue[NUM_1], &(asyncContext->area.region));
    IMAGE_LOGD("CreateSendablePixelMapFromSurface get data: %{public}d", ret);
    if (argCount == NUM_3 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }
    IMG_NAPI_CHECK_BUILD_ERROR(ret,
        BuildContextError(env, asyncContext->error, "image invalid parameter", ERR_IMAGE_GET_DATA_ABNORMAL),
        IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreateSendablePixelMapFromSurfaceGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreateSendablePixelMapFromSurface",
        CreateSendablePixelMapFromSurfaceExec, CreateSendablePixelMapFromSurfaceComplete,
        asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}
#endif
napi_value SendablePixelMapNapi::CreateSendablePixelMap(napi_env env, std::shared_ptr<PixelMap> pixelmap)

{
    if (SendablePixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        SendablePixelMapNapi::Init(env, exports);
    }
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_status status;
    IMAGE_LOGD("CreatePixelMap IN");
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, pixelmap, result);
    }
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("CreatePixelMap | New instance could not be obtained");
        napi_get_undefined(env, &result);
    }
    return result;
}

STATIC_EXEC_FUNC(Unmarshalling)
{
    auto context = static_cast<PixelMapAsyncContext*>(data);

    auto messageParcel = napi_messageSequence_sendable->GetMessageParcel();
    auto pixelmap = PixelMap::Unmarshalling(*messageParcel);
    std::unique_ptr<OHOS::Media::PixelMap> pixelmap_ptr(pixelmap);

    context->rPixelMap = std::move(pixelmap_ptr);

    if (IMG_NOT_NULL(context->rPixelMap)) {
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
}

void SendablePixelMapNapi::UnmarshallingComplete(napi_env env, napi_status status, void *data)
{
    napi_value constructor = nullptr;
    napi_value result = nullptr;

    IMAGE_LOGD("UnmarshallingComplete IN");
    auto context = static_cast<PixelMapAsyncContext*>(data);

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, context->rPixelMap, result);
    }

    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        IMAGE_LOGE("New instance could not be obtained");
        napi_get_undefined(env, &result);
    }

    CommonCallbackRoutine(env, context, result);
}

napi_value SendablePixelMapNapi::Unmarshalling(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (SendablePixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        SendablePixelMapNapi::Init(env, exports);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_4] = {0};
    size_t argCount = NUM_4;
    IMAGE_LOGD("Unmarshalling IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    // we are static method!
    // thisVar is nullptr here
    if (!IMG_IS_OK(status)) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Fail to napi_get_cb_info");
    }
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();

    if (argCount == NUM_3 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }

    NapiUnwrap(env, argValue[NUM_0], (void **)&napi_messageSequence_sendable, false);
    if (napi_messageSequence_sendable == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERROR, "napi_messageSequence_sendable unwrapped is nullptr");
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "Unmarshalling",
        UnmarshallingExec, UnmarshallingComplete, asyncContext, asyncContext->work);

    if (!IMG_IS_OK(status)) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERROR, "Fail to create async work");
    }
    return result;
}

napi_value SendablePixelMapNapi::ThrowExceptionError(napi_env env,
    const std::string &tag, const std::uint32_t &code, const std::string &info)
{
    auto errNode = ETS_API_ERROR_CODE.find(tag);
    if (errNode != ETS_API_ERROR_CODE.end() &&
        errNode->second.find(code) != errNode->second.end()) {
        return ImageNapiUtils::ThrowExceptionError(env, code, info);
    }
    return ImageNapiUtils::ThrowExceptionError(env, ERROR, "Operation failed");
}

napi_value SendablePixelMapNapi::CreateSendablPixelMapFromParcel(napi_env env, napi_callback_info info)
{
    if (SendablePixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        SendablePixelMapNapi::Init(env, exports);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMAGE_LOGD("CreateSendablPixelMapFromParcel IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    if (!IMG_IS_OK(status) || argCount != NUM_1) {
        return SendablePixelMapNapi::ThrowExceptionError(env,
            CREATE_PIXEL_MAP_FROM_PARCEL, ERR_IMAGE_INVALID_PARAMETER, "Fail to napi_get_cb_info");
    }
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    NapiUnwrap(env, argValue[NUM_0], (void **)&napi_messageSequence_sendable, false);
    IMG_NAPI_CHECK_RET_D(IMG_NOT_NULL(napi_messageSequence_sendable), result,
        IMAGE_LOGE("CreateSendablPixelMapFromParcel pixmapNapi unwrapped is nullptr"));
    auto messageParcel = napi_messageSequence_sendable->GetMessageParcel();
    if (messageParcel == nullptr) {
        return SendablePixelMapNapi::ThrowExceptionError(env,
            CREATE_PIXEL_MAP_FROM_PARCEL, ERR_IPC, "get pacel failed");
    }
    PIXEL_MAP_ERR error;
    auto pixelmap = PixelMap::Unmarshalling(*messageParcel, error);
    if (!IMG_NOT_NULL(pixelmap)) {
        return SendablePixelMapNapi::ThrowExceptionError(env,
            CREATE_PIXEL_MAP_FROM_PARCEL, error.errorCode, error.errorInfo);
    }
    std::shared_ptr<OHOS::Media::PixelMap> pixelPtr(pixelmap);
    napi_value constructor = nullptr;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, pixelPtr, result);
    }
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("New instance could not be obtained");
        return SendablePixelMapNapi::ThrowExceptionError(env,
            CREATE_PIXEL_MAP_FROM_PARCEL, ERR_IMAGE_NAPI_ERROR, "New instance could not be obtained");
    }
    return result;
}

napi_value SendablePixelMapNapi::GetIsEditable(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;
    IMAGE_LOGD("GetIsEditable IN");

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("GetIsEditable fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(IMG_NOT_NULL(pixelMapNapi), result,
        IMAGE_LOGE("SendablePixelMapNapi unwrapped is nullptr"));
    IMG_NAPI_CHECK_RET_D(IMG_NOT_NULL(pixelMapNapi->nativePixelMap_), result,
        IMAGE_LOGE("nativePixelMap_ is nullptr"));
    bool isEditable = pixelMapNapi->nativePixelMap_->IsEditable();

    napi_get_boolean(env, isEditable, &result);
    pixelMapNapi.release();

    return result;
}

napi_value SendablePixelMapNapi::GetIsStrideAlignment(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;
    IMAGE_LOGD("GetIsStrideAlignment IN");

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi),
        result, IMAGE_LOGE("GetIsStrideAlignment fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(IMG_NOT_NULL(pixelMapNapi), result,
        IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(IMG_NOT_NULL(pixelMapNapi->nativePixelMap_), result,
        IMAGE_LOGE("SendablePixelMapNapi->nativePixelMap_ is nullptr"));
    bool isDMA = pixelMapNapi->nativePixelMap_->IsStrideAlignment();
    napi_get_boolean(env, isDMA, &result);
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::ReadPixelsToBuffer(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    ImageTrace imageTrace("SendablePixelMapNapi::ReadPixelsToBuffer");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;

    IMAGE_LOGD("ReadPixelsToBuffer IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("ReadPixelsToBuffer fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, IMAGE_LOGE("empty native pixelmap"));

    status = napi_get_arraybuffer_info(env, argValue[NUM_0],
        &(asyncContext->colorsBuffer), &(asyncContext->colorsBufferSize));

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("colors mismatch"));

    if (argCount == NUM_2 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, asyncContext->error, "pixelmap has crossed threads . ReadPixelsToBuffer failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, status, "ReadPixelsToBufferGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK_WITH_QOS(env, status, "ReadPixelsToBuffer",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            context->status = context->rPixelMap->ReadPixels(
                context->colorsBufferSize, static_cast<uint8_t*>(context->colorsBuffer));
        }, EmptyResultComplete, asyncContext, asyncContext->work, napi_qos_user_initiated);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value SendablePixelMapNapi::ReadPixelsToBufferSync(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    ImageTrace imageTrace("SendablePixelMapNapi::ReadPixelsToBufferSync");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    uint32_t status = SUCCESS;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_1;
    napi_value argValue[NUM_1] = {0};
    void* colorsBuffer = nullptr;
    size_t colorsBufferSize = 0;

    IMAGE_LOGD("ReadPixelsToBuffeSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "ReadPixelsToBuffeSync failed"),
        IMAGE_LOGE("ReadPixelsToBuffeSync failed, invalid parameter"));

    napiStatus = napi_get_arraybuffer_info(env, argValue[NUM_0],
        &colorsBuffer, &colorsBufferSize);
    IMG_NAPI_CHECK_RET_D(napiStatus == napi_ok, result, IMAGE_LOGE("get arraybuffer info failed"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("ReadPixelsToBufferSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . ReadPixelsToBuffeSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . ReadPixelsToBuffeSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        status = pixelMapNapi->nativePixelMap_->ReadPixels(
            colorsBufferSize, static_cast<uint8_t*>(colorsBuffer));
        if (status != SUCCESS) {
            IMAGE_LOGE("ReadPixels failed");
        }
    } else {
        IMAGE_LOGE("Null native ref");
    }
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::ReadPixels(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;

    IMAGE_LOGD("ReadPixels IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("ReadPixels fail to unwrap context"));

    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, IMAGE_LOGE("empty native pixelmap"));

    IMG_NAPI_CHECK_RET_D(parsePositionArea(env, argValue[NUM_0], &(asyncContext->area)),
        nullptr, IMAGE_LOGE("fail to parse position area"));

    if (argCount == NUM_2 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, asyncContext->error, "pixelmap has crossed threads . ReadPixels failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, status, "ReadPixelsGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "ReadPixels",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            auto area = context->area;
            context->status = context->rPixelMap->ReadPixels(
                area.size, area.offset, area.stride, area.region, static_cast<uint8_t*>(area.pixels));
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value SendablePixelMapNapi::ReadPixelsSync(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    PositionArea area;
    IMAGE_LOGD("ReadPixelsSync IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"),
        IMAGE_LOGE("Invalid args count %{public}zu", argCount));
    IMG_NAPI_CHECK_RET_D(parsePositionArea(env, argValue[NUM_0], &area),
        nullptr, IMAGE_LOGE("fail to parse position area"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("ReadPixelsSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . ReadPixelsToBuffeSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . ReadPixelsToBuffeSync failed"));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi->nativePixelMap_),
        nullptr, IMAGE_LOGE("empty native pixelmap"));

    auto nativeStatus = pixelMapNapi->nativePixelMap_->ReadPixels(
        area.size, area.offset, area.stride, area.region, static_cast<uint8_t*>(area.pixels));
    pixelMapNapi.release();

    IMG_NAPI_CHECK_RET_D(nativeStatus == SUCCESS,
        nullptr, IMAGE_LOGE("fail to read pixels"));
    return result;
}

napi_value SendablePixelMapNapi::WritePixels(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;

    IMAGE_LOGD("WritePixels IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("WritePixels fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, IMAGE_LOGE("empty native pixelmap"));

    IMG_NAPI_CHECK_RET_D(parsePositionArea(env, argValue[NUM_0], &(asyncContext->area)),
        nullptr, IMAGE_LOGE("fail to parse position area"));

    if (argCount == NUM_2 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }
    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, asyncContext->error, "pixelmap has crossed threads . WritePixels failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, status, "WritePixelsGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "WritePixels",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            auto area = context->area;
            context->status = context->rPixelMap->WritePixels(
                static_cast<uint8_t*>(area.pixels), area.size, area.offset, area.stride, area.region);
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value SendablePixelMapNapi::WritePixelsSync(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    uint32_t status = SUCCESS;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_1;
    napi_value argValue[NUM_1] = {0};
    PositionArea area;
    IMAGE_LOGD("WritePixelsSyncIN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to arg info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"),
        IMAGE_LOGE("Invalid args count %{public}zu", argCount));
    IMG_NAPI_CHECK_RET_D(parsePositionArea(env, argValue[NUM_0], &area),
        nullptr, IMAGE_LOGE("fail to parse position area"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    napiStatus = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result,
        IMAGE_LOGE("WritePixelsSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . WritePixelsSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . WritePixelsSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        status = pixelMapNapi->nativePixelMap_->WritePixels(
            static_cast<uint8_t*>(area.pixels), area.size, area.offset, area.stride, area.region);
        IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr,
            IMAGE_LOGE("fail to write pixels"));
    } else {
        IMAGE_LOGE("Null native ref");
    }
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::WriteBufferToPixels(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    ImageTrace imageTrace("SendablePixelMapNapi::WriteBufferToPixels");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;

    IMAGE_LOGD("WriteBufferToPixels IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("WriteBufferToPixels fail to unwrap context"));

    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, IMAGE_LOGE("empty native pixelmap"));
    status = napi_get_arraybuffer_info(env, argValue[NUM_0],
        &(asyncContext->colorsBuffer), &(asyncContext->colorsBufferSize));

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to get buffer info"));

    if (argCount == NUM_2 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }
    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, asyncContext->error, "pixelmap has crossed threads . WriteBufferToPixels failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, status, "WriteBufferToPixelsGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "WriteBufferToPixels",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            context->status = context->rPixelMap->WritePixels(static_cast<uint8_t*>(context->colorsBuffer),
                context->colorsBufferSize);
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value SendablePixelMapNapi::WriteBufferToPixelsSync(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    ImageTrace imageTrace("SendablePixelMapNapi::WriteBufferToPixelsSync");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    uint32_t status = SUCCESS;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_1;
    napi_value argValue[NUM_1] = {0};
    void* colorsBuffer = nullptr;
    size_t colorsBufferSize = 0;

    IMAGE_LOGD("WriteBufferToPixelsSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "WriteBufferToPixelsSync failed"),
        IMAGE_LOGE("WriteBufferToPixelsSync failed, invalid parameter"));

    napiStatus = napi_get_arraybuffer_info(env, argValue[NUM_0],
        &colorsBuffer, &colorsBufferSize);
    IMG_NAPI_CHECK_RET_D(napiStatus == napi_ok, result, IMAGE_LOGE("get arraybuffer info failed"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("WriteBufferToPixelsSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . WriteBufferToPixelsSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . WriteBufferToPixelsSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        status = pixelMapNapi->nativePixelMap_->WritePixels(
            static_cast<uint8_t*>(colorsBuffer), colorsBufferSize);
        if (status != SUCCESS) {
            IMAGE_LOGE("WritePixels failed");
        }
    } else {
        IMAGE_LOGE("Null native ref");
    }
    pixelMapNapi.release();
    return result;
}

STATIC_NAPI_VALUE_FUNC(GetImageInfo)
{
    IMAGE_LOGD("[PixelMap]GetImageInfoNapiValue IN");
    napi_value result = nullptr;
    napi_create_object(env, &result);
    auto imageInfo = static_cast<ImageInfo*>(data);
    auto rPixelMap = static_cast<PixelMap*>(ptr);
    napi_value size = nullptr;
    napi_create_object(env, &size);
    napi_value sizeWith = nullptr;
    napi_create_int32(env, imageInfo->size.width, &sizeWith);
    napi_set_named_property(env, size, "width", sizeWith);
    napi_value sizeHeight = nullptr;
    napi_create_int32(env, imageInfo->size.height, &sizeHeight);
    napi_set_named_property(env, size, "height", sizeHeight);
    napi_set_named_property(env, result, "size", size);
    napi_value pixelFormatValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(imageInfo->pixelFormat), &pixelFormatValue);
    napi_set_named_property(env, result, "pixelFormat", pixelFormatValue);
    napi_value colorSpaceValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(imageInfo->colorSpace), &colorSpaceValue);
    napi_set_named_property(env, result, "colorSpace", colorSpaceValue);
    napi_value alphaTypeValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(imageInfo->alphaType), &alphaTypeValue);
    napi_set_named_property(env, result, "alphaType", alphaTypeValue);
    napi_value densityValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(imageInfo->baseDensity), &densityValue);
    napi_set_named_property(env, result, "density", densityValue);
    napi_value strideValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(rPixelMap->GetRowStride()), &strideValue);
    napi_set_named_property(env, result, "stride", strideValue);
    napi_value encodedFormatValue = nullptr;
    napi_create_string_utf8(env, imageInfo->encodedFormat.c_str(),
        imageInfo->encodedFormat.length(), &encodedFormatValue);
    napi_set_named_property(env, result, "mimeType", encodedFormatValue);
    napi_value isHdrValue = nullptr;
    napi_get_boolean(env, rPixelMap->IsHdr(), &isHdrValue);
    napi_set_named_property(env, result, "isHdr", isHdrValue);
    return result;
}

STATIC_COMPLETE_FUNC(GetImageInfo)
{
    IMAGE_LOGD("[PixelMap]GetImageInfoComplete IN");
    auto context = static_cast<PixelMapAsyncContext*>(data);
    napi_value result = GetImageInfoNapiValue(env, &(context->imageInfo), context->rPixelMap.get());

    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        IMAGE_LOGE("napi_create_int32 failed!");
        napi_get_undefined(env, &result);
    } else {
        context->status = SUCCESS;
    }
    IMAGE_LOGD("[PixelMap]GetImageInfoComplete OUT");
    CommonCallbackRoutine(env, context, result);
}
napi_value SendablePixelMapNapi::GetImageInfo(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = 1;
    IMAGE_LOGD("GetImageInfo IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("GetImageInfo fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, IMAGE_LOGE("empty native pixelmap"));
    if (argCount == NUM_1 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }
    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, asyncContext->error, "pixelmap has crossed threads . GetImageInfo failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetImageInfoGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetImageInfo",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            context->rPixelMap->GetImageInfo(context->imageInfo);
            context->status = SUCCESS;
        }, GetImageInfoComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value SendablePixelMapNapi::GetImageInfoSync(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;

    IMAGE_LOGD("GetImageInfoSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to arg info"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    napiStatus = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result,
        IMAGE_LOGE("GetImageInfoSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . GetImageInfoSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . GetImageInfoSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        ImageInfo imageinfo;
        pixelMapNapi->nativePixelMap_->GetImageInfo(imageinfo);
        result = GetImageInfoNapiValue(env, &imageinfo, pixelMapNapi->nativePixelMap_.get());
    } else {
        IMAGE_LOGE("native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::GetBytesNumberPerRow(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    ImageTrace imageTrace("SendablePixelMapNapi::GetBytesNumberPerRow");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;

    IMAGE_LOGD("GetBytesNumberPerRow IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . GetBytesNumberPerRow failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . GetBytesNumberPerRow failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        uint32_t rowBytes = pixelMapNapi->nativePixelMap_->GetRowBytes();
        status = napi_create_int32(env, rowBytes, &result);
        if (!IMG_IS_OK(status)) {
            IMAGE_LOGE("napi_create_int32 failed!");
        }
    } else {
        IMAGE_LOGE("native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::GetPixelBytesNumber(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    ImageTrace imageTrace("SendablePixelMapNapi::GetPixelBytesNumber");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;

    IMAGE_LOGD("GetPixelBytesNumber IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("GetPixelBytesNumber fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . GetPixelBytesNumber failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . GetPixelBytesNumber failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        uint32_t byteCount = pixelMapNapi->nativePixelMap_->GetByteCount();
        status = napi_create_int32(env, byteCount, &result);
        if (!IMG_IS_OK(status)) {
            IMAGE_LOGE("napi_create_int32 failed!");
        }
    } else {
        IMAGE_LOGE("native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::IsSupportAlpha(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;

    IMAGE_LOGD("IsSupportAlpha IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("IsSupportAlpha fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . IsSupportAlpha failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . IsSupportAlpha failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        AlphaType alphaType = pixelMapNapi->nativePixelMap_->GetAlphaType();
        bool isSupportAlpha = !(alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
        status = napi_get_boolean(env, isSupportAlpha, &result);
        if (!IMG_IS_OK(status)) {
            IMAGE_LOGE("napi_create_bool failed!");
        }
    } else {
        IMAGE_LOGE("native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::SetAlphaAble(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    bool isAlphaAble = false;

    IMAGE_LOGD("SetAlphaAble IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    NAPI_ASSERT(env, argCount > NUM_0, "Invalid input");
    NAPI_ASSERT(env, ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_boolean, "Invalid input type");
    NAPI_ASSERT(env, napi_get_value_bool(env, argValue[NUM_0], &isAlphaAble) == napi_ok, "Parse input error");

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("SetAlphaAble fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . SetAlphaAble failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . SetAlphaAble failed"));
    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        AlphaType alphaType = pixelMapNapi->nativePixelMap_->GetAlphaType();
        if (isAlphaAble && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
            pixelMapNapi->nativePixelMap_->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
        } else if ((!isAlphaAble) && !(alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
            pixelMapNapi->nativePixelMap_->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
        }
    } else {
        IMAGE_LOGE("native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

static void CreateAlphaPixelmapComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<PixelMapAsyncContext*>(data);

    if (context->alphaMap != nullptr) {
        result = SendablePixelMapNapi::CreateSendablePixelMap(env, context->alphaMap);
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value SendablePixelMapNapi::CreateAlphaPixelmap(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = 1;
    IMAGE_LOGD("CreateAlphaPixelmap IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("CreateAlphaPixelmap fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, IMAGE_LOGE("empty native pixelmap"));
    if (argCount == NUM_1 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }
    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, asyncContext->error, "pixelmap has crossed threads . CreateAlphaPixelmap failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreateAlphaPixelmapGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreateAlphaPixelmap",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            InitializationOptions opts;
            opts.pixelFormat = PixelFormat::ALPHA_8;
            auto tmpPixelMap = PixelMap::Create(*(context->rPixelMap), opts);
            context->alphaMap = std::move(tmpPixelMap);
            context->status = SUCCESS;
        }, CreateAlphaPixelmapComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value SendablePixelMapNapi::CreateAlphaPixelmapSync(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;

    IMAGE_LOGD("CreateAlphaPixelmapSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_0,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "CreateAlphaPixelmapSync failed"),
        IMAGE_LOGE("CreateAlphaPixelmapSync failed, invalid parameter"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    napiStatus = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result,
        IMAGE_LOGE("CreateAlphaPixelmapSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . CreateAlphaPixelmapSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . CreateAlphaPixelmapSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        InitializationOptions opts;
        opts.pixelFormat = PixelFormat::ALPHA_8;
        auto tmpPixelMap = PixelMap::Create(*(pixelMapNapi->nativePixelMap_), opts);
        result = SendablePixelMapNapi::CreateSendablePixelMap(env, std::move(tmpPixelMap));
    } else {
        IMAGE_LOGE("Null native ref");
    }
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::GetDensity(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;

    IMAGE_LOGD("GetDensity IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("GetDensity fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . GetDensity failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . GetDensity failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        uint32_t baseDensity = pixelMapNapi->nativePixelMap_->GetBaseDensity();
        status = napi_create_int32(env, baseDensity, &result);
        if (!IMG_IS_OK(status)) {
            IMAGE_LOGE("napi_create_int32 failed!");
        }
    } else {
        IMAGE_LOGE("native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::SetDensity(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    uint32_t density = 0;

    IMAGE_LOGD("SetDensity IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    NAPI_ASSERT(env,
        (argCount == NUM_1 && ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_number),
        "Density input mismatch");
    NAPI_ASSERT(env, napi_get_value_uint32(env, argValue[NUM_0], &density) == napi_ok, "Could not parse density");

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("SetDensity fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . SetDensity failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . SetDensity failed"));
    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        ImageInfo imageinfo;
        pixelMapNapi->nativePixelMap_->GetImageInfo(imageinfo);
        imageinfo.baseDensity = density;
        pixelMapNapi->nativePixelMap_->SetImageInfo(imageinfo, true);
    } else {
        IMAGE_LOGE("native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::Release(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[1] = {0};
    size_t argCount = 1;

    IMAGE_LOGD("Release IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("Release fail to unwrap context"));

    if (argCount == 1 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }
    if (asyncContext->nConstructor->IsLockPixelMap()) {
        asyncContext->status = ERROR;
    } else {
        if (asyncContext->nConstructor->nativePixelMap_ != nullptr) {
            IMAGE_LOGD("Release in napi_id:%{public}d, id:%{public}d",
                asyncContext->nConstructor->GetUniqueId(),
                asyncContext->nConstructor->nativePixelMap_->GetUniqueId());
            asyncContext->nConstructor->nativePixelMap_.reset();
        }
        asyncContext->status = SUCCESS;
    }
    IMG_CREATE_CREATE_ASYNC_WORK_WITH_QOS(env, status, "Release",
        [](napi_env env, void *data) {
        }, EmptyResultComplete, asyncContext, asyncContext->work, napi_qos_user_initiated);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

struct NapiValues {
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_value* argv = nullptr;
    size_t argc;
    int32_t refCount = 1;
    std::unique_ptr<PixelMapAsyncContext> context;
};

static bool prepareNapiEnv(napi_env env, napi_callback_info info, struct NapiValues* nVal)
{
    napi_get_undefined(env, &(nVal->result));
    nVal->status = napi_get_cb_info(env, info, &(nVal->argc), nVal->argv, &(nVal->thisVar), nullptr);
    if (nVal->status != napi_ok) {
        IMAGE_LOGE("fail to napi_get_cb_info");
        return false;
    }
    nVal->context = std::make_unique<PixelMapAsyncContext>();
    nVal->status = NapiUnwrap(env, nVal->thisVar, reinterpret_cast<void**>(&(nVal->context->nConstructor)));
    if (nVal->status != napi_ok || nVal->context->nConstructor == nullptr) {
        IMAGE_LOGE("fail to unwrap context");
        return false;
    }
    nVal->context->status = SUCCESS;
    return true;
}

static void SetAlphaExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->status = context->rPixelMap->SetAlpha(
                static_cast<float>(context->alpha));
        } else {
            IMAGE_LOGE("Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        IMAGE_LOGD("Scale has failed. do nothing");
    }
}

napi_value SendablePixelMapNapi::SetAlpha(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    NapiValues nVal;
    nVal.argc = NUM_2;
    napi_value argValue[NUM_2] = {0};
    nVal.argv = argValue;

    IMAGE_LOGD("SetAlpha IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_1 && nVal.argc != NUM_2) {
        IMAGE_LOGE("Invalid args count %{public}zu", nVal.argc);
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (napi_ok !=
            napi_get_value_double(env, nVal.argv[NUM_0], &(nVal.context->alpha))) {
            IMAGE_LOGE("Arg 0 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
    }
    if (nVal.argc >= 1 && ImageNapiUtils::getType(env, nVal.argv[nVal.argc - 1]) == napi_function) {
        napi_create_reference(env, nVal.argv[nVal.argc - 1], nVal.refCount, &(nVal.context->callbackRef));
    }

    if (nVal.context->callbackRef == nullptr) {
        napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    }
    IMG_NAPI_CHECK_BUILD_ERROR(nVal.context->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, nVal.context->error, "pixelmap has crossed threads . SetAlpha failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, nVal.status, "SetAlphaGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, nVal.context, nVal.context->work),
        nVal.result);
    napi_value _resource = nullptr;
    napi_create_string_utf8(env, "SetAlpha", NAPI_AUTO_LENGTH, &_resource);
    nVal.status = napi_create_async_work(env, nullptr, _resource,
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            SetAlphaExec(env, context);
        }, EmptyResultComplete, static_cast<void*>(nVal.context.get()), &(nVal.context->work));

    if (nVal.status == napi_ok) {
        nVal.status = napi_queue_async_work(env, nVal.context->work);
        if (nVal.status == napi_ok) {
            nVal.context.release();
        }
    }
    return nVal.result;
}

napi_value SendablePixelMapNapi::SetAlphaSync(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    uint32_t status = SUCCESS;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_1;
    napi_value argValue[NUM_1] = {0};
    double alpha = 0;

    IMAGE_LOGD("SetAlphaSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "SetAlphaSync failed"),
        IMAGE_LOGE("SetAlphaSync failed, invalid parameter"));
    napiStatus= napi_get_value_double(env, argValue[NUM_0], &alpha);

    IMG_NAPI_CHECK_RET_D(napiStatus == napi_ok, result, IMAGE_LOGE("get arraybuffer info failed"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("SetAlphaSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . SetAlphaSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . SetAlphaSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        status = pixelMapNapi->nativePixelMap_->SetAlpha(
            static_cast<float>(alpha));
        if (status != SUCCESS) {
            IMAGE_LOGE("SetAlphaSync failed");
        }
    } else {
        IMAGE_LOGE("Null native ref");
    }
    pixelMapNapi.release();
    return result;
}

static void ScaleExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->rPixelMap->scale(static_cast<float>(context->xArg), static_cast<float>(context->yArg));
            context->status = SUCCESS;
        } else {
            IMAGE_LOGE("Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        IMAGE_LOGD("Scale has failed. do nothing");
    }
}

napi_value SendablePixelMapNapi::Scale(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    NapiValues nVal;
    nVal.argc = NUM_3;
    napi_value argValue[NUM_3] = {0};
    nVal.argv = argValue;
    IMAGE_LOGD("Scale IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_2 && nVal.argc != NUM_3) {
        IMAGE_LOGE("Invalid args count %{public}zu", nVal.argc);
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (napi_ok != napi_get_value_double(env, nVal.argv[NUM_0], &(nVal.context->xArg))) {
            IMAGE_LOGE("Arg 0 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
        if (napi_ok != napi_get_value_double(env, nVal.argv[NUM_1], &(nVal.context->yArg))) {
            IMAGE_LOGE("Arg 1 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
    }
    if (nVal.argc >= 1 && ImageNapiUtils::getType(env, nVal.argv[nVal.argc - 1]) == napi_function) {
        napi_create_reference(env, nVal.argv[nVal.argc - 1], nVal.refCount, &(nVal.context->callbackRef));
    }

    if (nVal.context->callbackRef == nullptr) {
        napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    }
    IMG_NAPI_CHECK_BUILD_ERROR(nVal.context->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, nVal.context->error, "pixelmap has crossed threads . Scale failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, nVal.status, "ScaleGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, nVal.context, nVal.context->work),
        nVal.result);
    napi_value _resource = nullptr;
    napi_create_string_utf8(env, "Scale", NAPI_AUTO_LENGTH, &_resource);
    nVal.status = napi_create_async_work(env, nullptr, _resource,
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            ScaleExec(env, context);
        }, EmptyResultComplete, static_cast<void*>(nVal.context.get()), &(nVal.context->work));

    if (nVal.status == napi_ok) {
        nVal.status = napi_queue_async_work_with_qos(env, nVal.context->work, napi_qos_user_initiated);
        if (nVal.status == napi_ok) {
            nVal.context.release();
        }
    }
    return nVal.result;
}

napi_value SendablePixelMapNapi::ScaleSync(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_2;
    napi_value argValue[NUM_2] = {0};
    double xArg = 0;
    double yArg = 0;
    IMAGE_LOGD("ScaleSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to arg info"));

    IMG_NAPI_CHECK_RET_D(argCount == NUM_2,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"),
        IMAGE_LOGE("Invalid args count %{public}zu", argCount));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_double(env, argValue[NUM_0], &xArg)),
        result, IMAGE_LOGE("Arg 0 type mismatch"));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_double(env, argValue[NUM_1], &yArg)),
        result, IMAGE_LOGE("Arg 1 type mismatch"));
    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    napiStatus = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result,
        IMAGE_LOGE("ScaleSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . ScaleSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . ScaleSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        pixelMapNapi->nativePixelMap_->scale(static_cast<float>(xArg), static_cast<float>(yArg));
    } else {
        IMAGE_LOGE("Null native ref");
    }
    pixelMapNapi.release();
    return result;
}

static void TranslateExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->rPixelMap->translate(static_cast<float>(context->xArg), static_cast<float>(context->yArg));
            context->status = SUCCESS;
        } else {
            IMAGE_LOGE("Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        IMAGE_LOGD("Translate has failed. do nothing");
    }
}

napi_value SendablePixelMapNapi::Translate(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    NapiValues nVal;
    nVal.argc = NUM_3;
    napi_value argValue[NUM_3] = {0};
    nVal.argv = argValue;
    IMAGE_LOGD("Translate IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_2 && nVal.argc != NUM_3) {
        IMAGE_LOGE("Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (napi_ok != napi_get_value_double(env, nVal.argv[NUM_0], &(nVal.context->xArg))) {
            IMAGE_LOGE("Arg 0 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
        if (napi_ok != napi_get_value_double(env, nVal.argv[NUM_1], &(nVal.context->yArg))) {
            IMAGE_LOGE("Arg 1 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
    }
    if (nVal.argc >= 1 && ImageNapiUtils::getType(env, nVal.argv[nVal.argc - 1]) == napi_function) {
        napi_create_reference(env, nVal.argv[nVal.argc - 1], nVal.refCount, &(nVal.context->callbackRef));
    }

    if (nVal.context->callbackRef == nullptr) {
        napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    }
    IMG_NAPI_CHECK_BUILD_ERROR(nVal.context->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, nVal.context->error, "pixelmap has crossed threads . Translate failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, nVal.status, "TranslateGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, nVal.context, nVal.context->work),
        nVal.result);
    napi_value _resource = nullptr;
    napi_create_string_utf8(env, "Translate", NAPI_AUTO_LENGTH, &_resource);
    nVal.status = napi_create_async_work(env, nullptr, _resource,
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            TranslateExec(env, context);
        }, EmptyResultComplete, static_cast<void*>(nVal.context.get()), &(nVal.context->work));

    if (nVal.status == napi_ok) {
        nVal.status = napi_queue_async_work(env, nVal.context->work);
        if (nVal.status == napi_ok) {
            nVal.context.release();
        }
    }
    return nVal.result;
}

napi_value SendablePixelMapNapi::TranslateSync(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_2;
    napi_value argValue[NUM_2] = {0};
    double x = 0;
    double y = 0;

    IMAGE_LOGD("TranslateSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_2,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "TranslateSync failed"),
        IMAGE_LOGE("TranslateSync failed, invalid parameter"));

    if (napi_ok != napi_get_value_double(env, argValue[NUM_0], &x) ||
        napi_ok != napi_get_value_double(env, argValue[NUM_1], &y)) {
        IMAGE_LOGE("get arraybuffer info failed");
        return result;
    }

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    napiStatus = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result,
        IMAGE_LOGE("TranslateSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . TranslateSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . TranslateSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        pixelMapNapi->nativePixelMap_->translate(static_cast<float>(x), static_cast<float>(y));
    } else {
        IMAGE_LOGE("Null native ref");
    }
    pixelMapNapi.release();
    return result;
}

static void RotateExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->rPixelMap->rotate(context->xArg);
            context->status = SUCCESS;
        } else {
            IMAGE_LOGE("Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        IMAGE_LOGD("Rotate has failed. do nothing");
    }
}

napi_value SendablePixelMapNapi::Rotate(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    NapiValues nVal;
    nVal.argc = NUM_2;
    napi_value argValue[NUM_2] = {0};
    nVal.argv = argValue;
    IMAGE_LOGD("Rotate IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_1 && nVal.argc != NUM_2) {
        IMAGE_LOGE("Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (napi_ok != napi_get_value_double(env, nVal.argv[NUM_0], &(nVal.context->xArg))) {
            IMAGE_LOGE("Arg 0 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
    }
    if (nVal.argc >= 1 && ImageNapiUtils::getType(env, nVal.argv[nVal.argc - 1]) == napi_function) {
        napi_create_reference(env, nVal.argv[nVal.argc - 1], nVal.refCount, &(nVal.context->callbackRef));
    }

    if (nVal.context->callbackRef == nullptr) {
        napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    }
    IMG_NAPI_CHECK_BUILD_ERROR(nVal.context->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, nVal.context->error, "pixelmap has crossed threads . Rotate failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, nVal.status, "RotateGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, nVal.context, nVal.context->work),
        nVal.result);
    napi_value _resource = nullptr;
    napi_create_string_utf8(env, "Rotate", NAPI_AUTO_LENGTH, &_resource);
    nVal.status = napi_create_async_work(env, nullptr, _resource,
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            RotateExec(env, context);
        }, EmptyResultComplete, static_cast<void*>(nVal.context.get()), &(nVal.context->work));

    if (nVal.status == napi_ok) {
        nVal.status = napi_queue_async_work(env, nVal.context->work);
        if (nVal.status == napi_ok) {
            nVal.context.release();
        }
    }
    return nVal.result;
}

napi_value SendablePixelMapNapi::RotateSync(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_1;
    napi_value argValue[NUM_1] = {0};
    double angle = 0;

    IMAGE_LOGD("RotateSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "RotateSync failed"),
        IMAGE_LOGE("RotateSync failed, invalid parameter"));
    napiStatus = napi_get_value_double(env, argValue[NUM_0], &angle);
    IMG_NAPI_CHECK_RET_D(napiStatus == napi_ok, result, IMAGE_LOGE("get arraybuffer info failed"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    napiStatus = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result,
        IMAGE_LOGE("RotateSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . RotateSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . RotateSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        pixelMapNapi->nativePixelMap_->rotate(static_cast<float>(angle));
    } else {
        IMAGE_LOGE("Null native ref");
    }
    pixelMapNapi.release();
    return result;
}
static void FlipExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->rPixelMap->flip(context->xBarg, context->yBarg);
            context->status = SUCCESS;
        } else {
            IMAGE_LOGE("Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        IMAGE_LOGD("Flip has failed. do nothing");
    }
}

napi_value SendablePixelMapNapi::Flip(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    NapiValues nVal;
    nVal.argc = NUM_3;
    napi_value argValue[NUM_3] = {0};
    nVal.argv = argValue;
    IMAGE_LOGD("Flip IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_2 && nVal.argc != NUM_3) {
        IMAGE_LOGE("Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (napi_ok != napi_get_value_bool(env, nVal.argv[NUM_0], &(nVal.context->xBarg))) {
            IMAGE_LOGE("Arg 0 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
        if (napi_ok != napi_get_value_bool(env, nVal.argv[NUM_1], &(nVal.context->yBarg))) {
            IMAGE_LOGE("Arg 1 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
    }
    if (nVal.argc >= 1 && ImageNapiUtils::getType(env, nVal.argv[nVal.argc - 1]) == napi_function) {
        napi_create_reference(env, nVal.argv[nVal.argc - 1], nVal.refCount, &(nVal.context->callbackRef));
    }

    if (nVal.context->callbackRef == nullptr) {
        napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    }
    IMG_NAPI_CHECK_BUILD_ERROR(nVal.context->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, nVal.context->error, "pixelmap has crossed threads . Flip failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, nVal.status, "FlipGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, nVal.context, nVal.context->work),
        nVal.result);
    napi_value _resource = nullptr;
    napi_create_string_utf8(env, "Flip", NAPI_AUTO_LENGTH, &_resource);
    nVal.status = napi_create_async_work(env, nullptr, _resource,
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            FlipExec(env, context);
        }, EmptyResultComplete, static_cast<void*>(nVal.context.get()), &(nVal.context->work));

    if (nVal.status == napi_ok) {
        nVal.status = napi_queue_async_work(env, nVal.context->work);
        if (nVal.status == napi_ok) {
            nVal.context.release();
        }
    }
    return nVal.result;
}

napi_value SendablePixelMapNapi::FlipSync(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    uint32_t status = SUCCESS;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_2;
    napi_value argValue[NUM_2] = {0};
    bool xBarg = 0;
    bool yBarg = 0;

    IMAGE_LOGD("FlipSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_2,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "FlipSync failed"),
        IMAGE_LOGE("FlipSync failed, invalid parameter"));

    if (napi_ok != napi_get_value_bool(env, argValue[NUM_0], &xBarg)) {
        IMAGE_LOGE("Arg 0 type mismatch");
        status = COMMON_ERR_INVALID_PARAMETER;
    }
    if (napi_ok != napi_get_value_bool(env, argValue[NUM_1], &yBarg)) {
        IMAGE_LOGE("Arg 1 type mismatch");
        status = COMMON_ERR_INVALID_PARAMETER;
    }

    IMG_NAPI_CHECK_RET_D(status == SUCCESS, result, IMAGE_LOGE("FlipSync failed, invalid parameter"));

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("FlipSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . FlipSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . FlipSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        pixelMapNapi->nativePixelMap_->flip(xBarg, yBarg);
    } else {
        IMAGE_LOGE("Null native ref");
    }
    pixelMapNapi.release();
    return result;
}

static void CropExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->status = context->rPixelMap->crop(context->area.region);
        } else {
            IMAGE_LOGE("Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        IMAGE_LOGD("Crop has failed. do nothing");
    }
}

napi_value SendablePixelMapNapi::Crop(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    NapiValues nVal;
    nVal.argc = NUM_2;
    napi_value argValue[NUM_2] = {0};
    nVal.argv = argValue;
    IMAGE_LOGD("Crop IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_1 && nVal.argc != NUM_2) {
        IMAGE_LOGE("Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (!parseRegion(env, nVal.argv[NUM_0], &(nVal.context->area.region))) {
            IMAGE_LOGE("Region type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
    }
    if (nVal.argc >= 1 && ImageNapiUtils::getType(env, nVal.argv[nVal.argc - 1]) == napi_function) {
        napi_create_reference(env, nVal.argv[nVal.argc - 1], nVal.refCount, &(nVal.context->callbackRef));
    }

    if (nVal.context->callbackRef == nullptr) {
        napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    }
    IMG_NAPI_CHECK_BUILD_ERROR(nVal.context->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, nVal.context->error, "pixelmap has crossed threads . Crop failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, nVal.status, "CropGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, nVal.context, nVal.context->work),
        nVal.result);
    napi_value _resource = nullptr;
    napi_create_string_utf8(env, "CropExec", NAPI_AUTO_LENGTH, &_resource);
    nVal.status = napi_create_async_work(env, nullptr, _resource,
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            CropExec(env, context);
        }, EmptyResultComplete, static_cast<void*>(nVal.context.get()), &(nVal.context->work));

    if (nVal.status == napi_ok) {
        nVal.status = napi_queue_async_work(env, nVal.context->work);
        if (nVal.status == napi_ok) {
            nVal.context.release();
        }
    }
    return nVal.result;
}

napi_value SendablePixelMapNapi::CropSync(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    uint32_t status = SUCCESS;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_1;
    napi_value argValue[NUM_1] = {0};
    Rect region;

    IMAGE_LOGD("CropSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "CropSync failed"),
        IMAGE_LOGE("CropSync failed, invalid parameter"));
    if (!parseRegion(env, argValue[NUM_0], &region)) {
        IMAGE_LOGE("Region type mismatch");
        return result;
    }

    std::unique_ptr<SendablePixelMapNapi> pixelMapNapi = nullptr;
    status = NapiUnwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result,
        IMAGE_LOGE("CropSync fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . CropSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . CropSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        status = pixelMapNapi->nativePixelMap_->crop(region);
        if (status != SUCCESS) {
            IMAGE_LOGE("CropSync failed");
        }
    } else {
        IMAGE_LOGE("Null native ref");
    }
    pixelMapNapi.release();
    return result;
}

napi_value SendablePixelMapNapi::GetColorSpace(napi_env env, napi_callback_info info)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    NapiValues nVal;
    nVal.argc = NUM_0;
    IMAGE_LOGD("GetColorSpace IN");
    napi_get_undefined(env, &nVal.result);
    if (!prepareNapiEnv(env, info, &nVal)) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Fail to unwrap context");
    }
    if (nVal.argc != NUM_0) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Invalid args count");
    }
    IMG_NAPI_CHECK_RET_D(nVal.context->nConstructor->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . GetColorSpace failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . GetColorSpace failed"));
#ifdef IMAGE_COLORSPACE_FLAG
    if (nVal.context->nConstructor->nativePixelMap_ == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_DATA_ABNORMAL, "Invalid native pixelmap");
    }
    auto grCS = nVal.context->nConstructor->nativePixelMap_->InnerGetGrColorSpacePtr();
    if (grCS == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_DATA_UNSUPPORT, "No colorspace in pixelmap");
    }
    auto resultValue = ColorManager::CreateJsColorSpaceObject(env, grCS);
    nVal.result = reinterpret_cast<napi_value>(resultValue);
#else
    return ImageNapiUtils::ThrowExceptionError(
        env, ERR_INVALID_OPERATION, "Unsupported operation");
#endif
    return nVal.result;
}

napi_value SendablePixelMapNapi::SetColorSpace(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    NapiValues nVal;
    nVal.argc = NUM_1;
    napi_value argValue[NUM_1] = {0};
    nVal.argv = argValue;
    IMAGE_LOGD("SetColorSpace IN");
    napi_get_undefined(env, &nVal.result);
    if (!prepareNapiEnv(env, info, &nVal)) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Fail to unwrap context");
    }
    if (nVal.argc != NUM_1) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Invalid args count");
    }
    IMG_NAPI_CHECK_RET_D(nVal.context->nConstructor->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . SetColorSpace failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . SetColorSpace failed"));
#ifdef IMAGE_COLORSPACE_FLAG
    nVal.context->colorSpace = ColorManager::GetColorSpaceByJSObject(env, nVal.argv[NUM_0]);
    if (nVal.context->colorSpace == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "ColorSpace mismatch");
    }
    nVal.context->nConstructor->nativePixelMap_->InnerSetColorSpace(*(nVal.context->colorSpace));
#else
    return ImageNapiUtils::ThrowExceptionError(
        env, ERR_INVALID_OPERATION, "Unsupported operation");
#endif
    return nVal.result;
}

napi_value SendablePixelMapNapi::Marshalling(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    NapiValues nVal;
    nVal.argc = NUM_1;
    napi_value argValue[NUM_1] = {0};
    nVal.argv = argValue;
    IMAGE_LOGD("Marshalling IN");

    if (!prepareNapiEnv(env, info, &nVal)) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Fail to unwrap context");
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;
    if (nVal.argc != NUM_0 && nVal.argc != NUM_1) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Invalid args count");
    }
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_get_cb_info(env, info, &nVal.argc, nVal.argv, nullptr, nullptr);
    NapiUnwrap(env, nVal.argv[0], reinterpret_cast<void**>(&napiSequence));
    IMG_NAPI_CHECK_RET_D(IMG_NOT_NULL(napiSequence), nullptr,
        IMAGE_LOGE("Marshalling fail to unwrap context"));
    auto messageParcel = napiSequence->GetMessageParcel();
    bool st = nVal.context->rPixelMap->Marshalling(*messageParcel);
    if (!st) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IPC, "marshalling pixel map to parcel failed.");
    }
    return nVal.result;
}

static void ApplyColorSpaceExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Null context");
        return;
    }
    if (context->status != SUCCESS) {
        IMAGE_LOGD("ApplyColorSpace has failed. do nothing");
        return;
    }
    if (context->rPixelMap == nullptr || context->colorSpace == nullptr) {
        context->status = ERR_IMAGE_INIT_ABNORMAL;
        IMAGE_LOGE("ApplyColorSpace Null native ref");
        return;
    }
    context->status = context->rPixelMap->ApplyColorSpace(*(context->colorSpace));
}

static void ParseColorSpaceVal(napi_env env, napi_value val, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Null context");
        return;
    }

#ifdef IMAGE_COLORSPACE_FLAG
    context->colorSpace = ColorManager::GetColorSpaceByJSObject(env, val);
    if (context->colorSpace == nullptr) {
        context->status = ERR_IMAGE_INVALID_PARAMETER;
    }
#else
    Val.context->status = ERR_IMAGE_DATA_UNSUPPORT;
#endif
}

napi_value SendablePixelMapNapi::ApplyColorSpace(napi_env env, napi_callback_info info)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    NapiValues nVal;
    nVal.argc = NUM_2;
    napi_value argValue[NUM_2] = {0};
    nVal.argv = argValue;
    IMAGE_LOGD("ApplyColorSpace IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_1 && nVal.argc != NUM_2) {
        IMAGE_LOGE("Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        ParseColorSpaceVal(env, nVal.argv[NUM_0], nVal.context.get());
    }
    if (nVal.argc >= NUM_1 && ImageNapiUtils::getType(env, nVal.argv[nVal.argc - 1]) == napi_function) {
        napi_create_reference(env, nVal.argv[nVal.argc - 1], nVal.refCount, &(nVal.context->callbackRef));
    }

    if (nVal.context->callbackRef == nullptr) {
        napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    }
    IMG_NAPI_CHECK_BUILD_ERROR(nVal.context->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, nVal.context->error, "pixelmap has crossed threads . ApplyColorSpace failed",
        ERR_RESOURCE_UNAVAILABLE), IMG_CREATE_CREATE_ASYNC_WORK(env, nVal.status, "ApplyColorSpaceGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, nVal.context, nVal.context->work),
        nVal.result);
    napi_value _resource = nullptr;
    napi_create_string_utf8(env, "ApplyColorSpace", NAPI_AUTO_LENGTH, &_resource);
    nVal.status = napi_create_async_work(env, nullptr, _resource, [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            ApplyColorSpaceExec(env, context);
        }, EmptyResultComplete, static_cast<void*>(nVal.context.get()), &(nVal.context->work));

    if (nVal.status == napi_ok) {
        nVal.status = napi_queue_async_work(env, nVal.context->work);
        if (nVal.status == napi_ok) {
            nVal.context.release();
        }
    }
    return nVal.result;
}

void SendablePixelMapNapi::release()
{
    if (!isRelease) {
        if (nativePixelMap_ != nullptr) {
            nativePixelMap_.reset();
        }
        isRelease = true;
    }
}
}  // namespace Media
}  // namespace OHOS
