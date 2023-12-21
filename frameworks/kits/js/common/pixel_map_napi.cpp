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

#include "pixel_map_napi.h"
#include "media_errors.h"
#include "hilog/log.h"
#include "log_tags.h"
#include "image_napi_utils.h"
#include "image_pixel_map_napi.h"
#include "image_trace.h"
#include "log_tags.h"
#if !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
#include "color_space_object_convertor.h"
#include "js_runtime_utils.h"
#include "napi_message_sequence.h"
#endif
#include "hitrace_meter.h"
#include "pixel_map.h"
#include "pixel_map_from_surface.h"

using OHOS::HiviewDFX::HiLog;
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
        LOG_TAG_DOMAIN_ID_PIXEL_MAP_NAPI, "PixelMapNapi"};
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
    constexpr uint32_t NUM_3 = 3;
    constexpr uint32_t NUM_4 = 4;
}

namespace OHOS {
namespace Media {
static const std::string CREATE_PIXEL_MAP_FROM_PARCEL = "createPixelMapFromParcel";
static const std::string MARSHALLING = "marshalling";
static const std::map<std::string, std::set<uint32_t>> ETS_API_ERROR_CODE = {
    {CREATE_PIXEL_MAP_FROM_PARCEL, {62980096, 62980105, 62980115, 62980097,
        62980177, 62980178, 62980179, 62980180, 62980246}},
    {MARSHALLING, {62980115, 62980097, 62980096}}
};
static const std::string CLASS_NAME = "PixelMap";
static const std::int32_t NEW_INSTANCE_ARGC = 1;
thread_local napi_ref PixelMapNapi::sConstructor_ = nullptr;
#if !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
NAPI_MessageSequence* napi_messageSequence = nullptr;
#endif

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
    PixelMapNapi *nConstructor;
    void* colorsBuffer;
    size_t colorsBufferSize;
    InitializationOptions opts;
    PositionArea area;
    std::shared_ptr<PixelMap> rPixelMap;
    std::shared_ptr<PixelMap> alphaMap;
    double alpha = -1;
    uint32_t resultUint32;
    ImageInfo imageInfo;
    double xArg = 0;
    double yArg = 0;
    bool xBarg = false;
    bool yBarg = false;
#if !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
    std::shared_ptr<OHOS::ColorManager::ColorSpace> colorSpace;
#endif
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
        HiLog::Info(LABEL, "no alphaType in initialization options");
    }
    opts->alphaType = ParseAlphaType(tmpNumber);

    tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "pixelFormat", tmpNumber)) {
        HiLog::Info(LABEL, "no pixelFormat in initialization options");
    }
    opts->pixelFormat = ParsePixlForamt(tmpNumber);

    tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "scaleMode", tmpNumber)) {
        HiLog::Info(LABEL, "no scaleMode in initialization options");
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

PixelMapNapi::PixelMapNapi():env_(nullptr)
{
    static std::atomic<uint32_t> currentId = 0;
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
}

PixelMapNapi::~PixelMapNapi()
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
        nullptr, HiLog::Error(LABEL, "Init:get global fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_set_named_property(env, global, CLASS_NAME.c_str(), constructor)),
        nullptr, HiLog::Error(LABEL, "Init:set global named property fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor)),
        nullptr, HiLog::Error(LABEL, "set named property fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_properties(env, exports, property_count, properties)),
        nullptr, HiLog::Error(LABEL, "define properties fail")
    );
    return exports;
}

napi_value PixelMapNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor props[] = {
        DECLARE_NAPI_FUNCTION("readPixelsToBuffer", ReadPixelsToBuffer),
        DECLARE_NAPI_FUNCTION("readPixels", ReadPixels),
        DECLARE_NAPI_FUNCTION("writePixels", WritePixels),
        DECLARE_NAPI_FUNCTION("writeBufferToPixels", WriteBufferToPixels),
        DECLARE_NAPI_FUNCTION("getImageInfo", GetImageInfo),
        DECLARE_NAPI_FUNCTION("getBytesNumberPerRow", GetBytesNumberPerRow),
        DECLARE_NAPI_FUNCTION("getPixelBytesNumber", GetPixelBytesNumber),
        DECLARE_NAPI_FUNCTION("isSupportAlpha", IsSupportAlpha),
        DECLARE_NAPI_FUNCTION("setAlphaAble", SetAlphaAble),
        DECLARE_NAPI_FUNCTION("createAlphaPixelmap", CreateAlphaPixelmap),
        DECLARE_NAPI_FUNCTION("getDensity", GetDensity),
        DECLARE_NAPI_FUNCTION("setDensity", SetDensity),
        DECLARE_NAPI_FUNCTION("opacity", SetAlpha),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("scale", Scale),
        DECLARE_NAPI_FUNCTION("translate", Translate),
        DECLARE_NAPI_FUNCTION("rotate", Rotate),
        DECLARE_NAPI_FUNCTION("flip", Flip),
        DECLARE_NAPI_FUNCTION("crop", Crop),
        DECLARE_NAPI_FUNCTION("getColorSpace", GetColorSpace),
        DECLARE_NAPI_FUNCTION("setColorSpace", SetColorSpace),
        DECLARE_NAPI_FUNCTION("applyColorSpace", ApplyColorSpace),
        DECLARE_NAPI_FUNCTION("marshalling", Marshalling),
        DECLARE_NAPI_FUNCTION("unmarshalling", Unmarshalling),
        DECLARE_NAPI_GETTER("isEditable", GetIsEditable),
        DECLARE_NAPI_GETTER("isStrideAlignment", GetIsStrideAlignment),
    };

    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMap", CreatePixelMap),
        DECLARE_NAPI_STATIC_FUNCTION("unmarshalling", Unmarshalling),
        DECLARE_NAPI_STATIC_FUNCTION(CREATE_PIXEL_MAP_FROM_PARCEL.c_str(), CreatePixelMapFromParcel),
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapFromSurface", CreatePixelMapFromSurface),
    };

    napi_value constructor = nullptr;

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                          Constructor, nullptr, IMG_ARRAY_SIZE(props),
                          props, &constructor)),
        nullptr, HiLog::Error(LABEL, "define class fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_create_reference(env, constructor, 1, &sConstructor_)),
        nullptr, HiLog::Error(LABEL, "create reference fail")
    );

    auto result = DoInitAfter(env, exports, constructor,
        IMG_ARRAY_SIZE(static_prop), static_prop);

    HiLog::Debug(LABEL, "Init success");
    return result;
}

std::shared_ptr<PixelMap> PixelMapNapi::GetPixelMap(napi_env env, napi_value pixelmap)
{
    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;

    napi_status status = napi_unwrap(env, pixelmap, reinterpret_cast<void**>(&pixelMapNapi));
    if (!IMG_IS_OK(status)) {
        HiLog::Error(LABEL, "GetPixelMap napi unwrap failed");
        return nullptr;
    }

    if (pixelMapNapi == nullptr) {
        HiLog::Error(LABEL, "GetPixelMap pixmapNapi is nullptr");
        return nullptr;
    }

    auto pixelmapNapiPtr = pixelMapNapi.release();
    if (pixelmapNapiPtr == nullptr) {
        HiLog::Error(LABEL, "GetPixelMap pixelmapNapi is nullptr");
        return nullptr;
    }
    return pixelmapNapiPtr->nativePixelMap_;
}

std::shared_ptr<PixelMap>* PixelMapNapi::GetPixelMap()
{
    return &nativePixelMap_;
}

bool PixelMapNapi::IsLockPixelMap()
{
    return (lockCount > 0);
}

bool PixelMapNapi::LockPixelMap()
{
    lockCount++;
    return true;
}

void PixelMapNapi::UnlockPixelMap()
{
    if (lockCount > 0) {
        lockCount--;
    }
}

extern "C" __attribute__((visibility("default"))) void* OHOS_MEDIA_GetPixelMap(napi_env env, napi_value value)
{
    PixelMapNapi *pixmapNapi = nullptr;
    napi_unwrap(env, value, reinterpret_cast<void**>(&pixmapNapi));
    if (pixmapNapi == nullptr) {
        HiLog::Error(LABEL, "pixmapNapi unwrapped is nullptr");
        return nullptr;
    }
    return reinterpret_cast<void*>(pixmapNapi->GetPixelMap());
}

extern "C" __attribute__((visibility("default"))) int32_t OHOS_MEDIA_GetImageInfo(napi_env env, napi_value value,
    OhosPixelMapInfo *info)
{
    HiLog::Debug(LABEL, "GetImageInfo IN");

    if (info == nullptr) {
        HiLog::Error(LABEL, "info is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    PixelMapNapi *pixmapNapi = nullptr;
    napi_unwrap(env, value, reinterpret_cast<void**>(&pixmapNapi));
    if (pixmapNapi == nullptr) {
        HiLog::Error(LABEL, "pixmapNapi unwrapped is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    std::shared_ptr<PixelMap> pixelMap = pixmapNapi->GetPixelNapiInner();
    if ((pixelMap == nullptr)) {
        HiLog::Error(LABEL, "pixelMap is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    info->width = imageInfo.size.width;
    info->height = imageInfo.size.height;
    info->rowSize = pixelMap->GetRowStride();
    info->pixelFormat = static_cast<int32_t>(imageInfo.pixelFormat);

    HiLog::Debug(LABEL, "GetImageInfo, w=%{public}u, h=%{public}u, r=%{public}u, f=%{public}d",
        info->width, info->height, info->rowSize, info->pixelFormat);

    return OHOS_IMAGE_RESULT_SUCCESS;
}

extern "C" __attribute__((visibility("default"))) int32_t OHOS_MEDIA_AccessPixels(napi_env env, napi_value value,
    uint8_t** addrPtr)
{
    HiLog::Info(LABEL, "AccessPixels IN");

    PixelMapNapi *pixmapNapi = nullptr;
    napi_unwrap(env, value, reinterpret_cast<void**>(&pixmapNapi));
    if (pixmapNapi == nullptr) {
        HiLog::Error(LABEL, "pixmapNapi unwrapped is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    std::shared_ptr<PixelMap> pixelMap = pixmapNapi->GetPixelNapiInner();
    if (pixelMap == nullptr) {
        HiLog::Error(LABEL, "pixelMap is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    const uint8_t *constPixels = pixelMap->GetPixels();
    if (constPixels == nullptr) {
        HiLog::Error(LABEL, "const pixels is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    uint8_t *pixels = const_cast<uint8_t*>(constPixels);
    if (pixels == nullptr) {
        HiLog::Error(LABEL, "pixels is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    pixmapNapi->LockPixelMap();

    if (addrPtr != nullptr) {
        *addrPtr = pixels;
    }

    HiLog::Debug(LABEL, "AccessPixels OUT");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

extern "C" __attribute__((visibility("default"))) int32_t OHOS_MEDIA_UnAccessPixels(napi_env env, napi_value value)
{
    HiLog::Debug(LABEL, "UnAccessPixels IN");

    PixelMapNapi *pixmapNapi = nullptr;
    napi_unwrap(env, value, reinterpret_cast<void**>(&pixmapNapi));
    if (pixmapNapi == nullptr) {
        HiLog::Error(LABEL, "pixmapNapi unwrapped is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    pixmapNapi->UnlockPixelMap();

    return OHOS_IMAGE_RESULT_SUCCESS;
}

inline void *DetachPixelMapFunc(napi_env env, void *value, void *)
{
    HiLog::Debug(LABEL, "DetachPixelMapFunc in");
    if (value == nullptr) {
        HiLog::Error(LABEL, "DetachPixelMapFunc value is nullptr");
        return value;
    }
    auto pixelNapi = reinterpret_cast<PixelMapNapi*>(value);
    pixelNapi->setPixelNapiEditable(false);
    return value;
}

static napi_status NewPixelNapiInstance(napi_env &env, napi_value &constructor,
    std::shared_ptr<PixelMap> &pixelMap, napi_value &result)
{
    napi_status status;
    if (pixelMap == nullptr) {
        status = napi_invalid_arg;
        HiLog::Error(LABEL, "NewPixelNapiInstance pixelMap is nullptr");
        return status;
    }
    size_t argc = NEW_INSTANCE_ARGC;
    napi_value argv[NEW_INSTANCE_ARGC] = { 0 };
    napi_create_int32(env, pixelMap->GetUniqueId(), &argv[0]);
    PixelMapContainer::GetInstance().Insert(pixelMap->GetUniqueId(), pixelMap);
    status = napi_new_instance(env, constructor, argc, argv, &result);
    return status;
}

napi_value AttachPixelMapFunc(napi_env env, void *value, void *)
{
    if (value == nullptr) {
        HiLog::Error(LABEL, "attach value is nullptr");
        return nullptr;
    }
    auto pixelNapi = reinterpret_cast<PixelMapNapi*>(value);

    napi_value result = nullptr;
    napi_value constructor = nullptr;
    napi_status status;

    if (PixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PixelMapNapi::Init(env, exports);
    }
    napi_value globalValue = nullptr;
    status = napi_get_named_property(env, globalValue, CLASS_NAME.c_str(), &constructor);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "napi_get_named_property error"));

    std::shared_ptr<PixelMap> attachPixelMap = pixelNapi->GetPixelNapiInner();
    if (attachPixelMap == nullptr) {
        HiLog::Error(LABEL, "AttachPixelMapFunc attachPixelMap is nullptr");
        napi_get_undefined(env, &result);
        return result;
    }
    HiLog::Debug(LABEL, "AttachPixelMapFunc in napi_id:%{public}d, id:%{public}d",
        pixelNapi->GetUniqueId(), attachPixelMap->GetUniqueId());
    status = NewPixelNapiInstance(env, constructor, attachPixelMap, result);
    if (!IMG_IS_OK(status)) {
        HiLog::Error(LABEL, "AttachPixelMapFunc napi_get_referencce_value failed");
    }
    return result;
}

napi_value PixelMapNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &thisVar);
    size_t argc = NEW_INSTANCE_ARGC;
    napi_value argv[NEW_INSTANCE_ARGC] = { 0 };
    HiLog::Debug(LABEL, "Constructor IN");
    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    IMG_NAPI_CHECK_RET(IMG_IS_READY(status, thisVar), undefineVar);
    uint32_t pixelMapId = 0;
    napi_get_value_uint32(env, argv[0], &pixelMapId);
    std::unique_ptr<PixelMapNapi> pPixelMapNapi = std::make_unique<PixelMapNapi>();

    IMG_NAPI_CHECK_RET(IMG_NOT_NULL(pPixelMapNapi), undefineVar);

    pPixelMapNapi->env_ = env;
    if (PixelMapContainer::GetInstance().Find(pixelMapId)) {
        pPixelMapNapi->nativePixelMap_ = PixelMapContainer::GetInstance()[pixelMapId];
        HiLog::Debug(LABEL, "Constructor in napi_id:%{public}d, id:%{public}d",
            pPixelMapNapi->GetUniqueId(), pPixelMapNapi->nativePixelMap_->GetUniqueId());
    } else {
        HiLog::Error(LABEL, "Constructor nativePixelMap is nullptr");
    }

    napi_coerce_to_native_binding_object(
        env, thisVar, DetachPixelMapFunc, AttachPixelMapFunc, pPixelMapNapi.get(), nullptr);

    status = napi_wrap(env, thisVar, reinterpret_cast<void*>(pPixelMapNapi.get()),
        PixelMapNapi::Destructor, nullptr, nullptr);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), undefineVar, HiLog::Error(LABEL, "Failure wrapping js to native napi"));

    pPixelMapNapi.release();
    PixelMapContainer::GetInstance().Erase(pixelMapId);
    return thisVar;
}

void PixelMapNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        HiLog::Debug(LABEL, "Destructor in napi_id:%{public}d",
            reinterpret_cast<PixelMapNapi*>(nativeObject)->GetUniqueId());
        delete reinterpret_cast<PixelMapNapi*>(nativeObject);
        nativeObject = nullptr;
    }
}

static void BuildContextError(napi_env env, napi_ref &error, const std::string errMsg, const int32_t errCode)
{
    HiLog::Error(LABEL, "%{public}s", errMsg.c_str());
    napi_value tmpError;
    ImageNapiUtils::CreateErrorObj(env, tmpError, errCode, errMsg);
    napi_create_reference(env, tmpError, NUM_1, &(error));
}

STATIC_EXEC_FUNC(CreatePixelMap)
{
    auto context = static_cast<PixelMapAsyncContext*>(data);
    auto colors = static_cast<uint32_t*>(context->colorsBuffer);
    auto pixelmap = PixelMap::Create(colors, context->colorsBufferSize, context->opts);

    context->rPixelMap = std::move(pixelmap);

    if (IMG_NOT_NULL(context->rPixelMap)) {
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
}

void PixelMapNapi::CreatePixelMapComplete(napi_env env, napi_status status, void *data)
{
    napi_value constructor = nullptr;
    napi_value result = nullptr;

    HiLog::Debug(LABEL, "CreatePixelMapComplete IN");
    auto context = static_cast<PixelMapAsyncContext*>(data);

    status = napi_get_reference_value(env, sConstructor_, &constructor);

    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, context->rPixelMap, result);
    }

    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        HiLog::Error(LABEL, "New instance could not be obtained");
        napi_get_undefined(env, &result);
    }

    CommonCallbackRoutine(env, context, result);
}

napi_value PixelMapNapi::CreatePixelMap(napi_env env, napi_callback_info info)
{
    if (PixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PixelMapNapi::Init(env, exports);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_4] = {0};
    size_t argCount = NUM_4;
    HiLog::Debug(LABEL, "CreatePixelMap IN");

    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    // we are static method!
    // thisVar is nullptr here
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "fail to napi_get_cb_info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();

    status = napi_get_arraybuffer_info(env, argValue[NUM_0], &(asyncContext->colorsBuffer),
        &(asyncContext->colorsBufferSize));

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "colors mismatch"));

    IMG_NAPI_CHECK_RET_D(parseInitializationOptions(env, argValue[1], &(asyncContext->opts)),
        nullptr, HiLog::Error(LABEL, "InitializationOptions mismatch"));

    if (argCount == NUM_3 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreatePixelMap",
        CreatePixelMapExec, CreatePixelMapComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, HiLog::Error(LABEL, "fail to create async work"));
    return result;
}

STATIC_EXEC_FUNC(CreatePixelMapFromSurface)
{
    auto context = static_cast<PixelMapAsyncContext*>(data);
    HiLog::Debug(LABEL, "CreatePixelMapFromSurface id:%{public}s,area:%{public}d,%{public}d,%{public}d,%{public}d",
        context->surfaceId.c_str(), context->area.region.left, context->area.region.top,
        context->area.region.height, context->area.region.width);
    
    auto pixelMap = CreatePixelMapFromSurfaceId(std::stoull(context->surfaceId), context->area.region);
    context->rPixelMap = std::move(pixelMap);

    if (IMG_NOT_NULL(context->rPixelMap)) {
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
}

void PixelMapNapi::CreatePixelMapFromSurfaceComplete(napi_env env, napi_status status, void *data)
{
    napi_value constructor = nullptr;
    napi_value result = nullptr;

    HiLog::Debug(LABEL, "CreatePixelMapFromSurface IN");
    auto context = static_cast<PixelMapAsyncContext*>(data);
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, context->rPixelMap, result);
    }

    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        HiLog::Error(LABEL, "New instance could not be obtained");
        napi_get_undefined(env, &result);
    }

    CommonCallbackRoutine(env, context, result);
}

void setSurfaceId(const char *surfaceId, std::string &dst)
{
    dst = surfaceId;
}

static std::string GetStringArgument(napi_env env, napi_value value)
{
    std::string strValue = "";
    size_t bufLength = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, NUM_0, &bufLength);
    if (status == napi_ok && bufLength > NUM_0 && bufLength < PATH_MAX) {
        char *buffer = reinterpret_cast<char *>(malloc((bufLength + NUM_1) * sizeof(char)));
        if (buffer == nullptr) {
            HiLog::Error(LABEL, "No memory");
            return strValue;
        }

        status = napi_get_value_string_utf8(env, value, buffer, bufLength + NUM_1, &bufLength);
        if (status == napi_ok) {
            HiLog::Debug(LABEL, "Get Success");
            strValue.assign(buffer, 0, bufLength + NUM_1);
        }
        if (buffer != nullptr) {
            free(buffer);
            buffer = nullptr;
        }
    }
    return strValue;
}

napi_value PixelMapNapi::CreatePixelMapFromSurface(napi_env env, napi_callback_info info)
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
    HiLog::Debug(LABEL, "CreatePixelMapFromSurface IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "fail to napi_get_cb_info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    asyncContext->surfaceId = GetStringArgument(env, argValue[NUM_0]);
    bool ret = parseRegion(env, argValue[NUM_1], &(asyncContext->area.region));
    HiLog::Debug(LABEL, "CreatePixelMapFromSurface get data: %{public}d", ret);
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
        IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreatePixelMapFromSurfaceGeneralError",
        [](napi_env env, void *data) {}, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreatePixelMapFromSurface",
        CreatePixelMapFromSurfaceExec, CreatePixelMapFromSurfaceComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, HiLog::Error(LABEL, "fail to create async work"));
    return result;
}

napi_value PixelMapNapi::CreatePixelMap(napi_env env, std::shared_ptr<PixelMap> pixelmap)
{
    if (PixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PixelMapNapi::Init(env, exports);
    }

    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_status status;

    HiLog::Debug(LABEL, "CreatePixelMap IN");
    status = napi_get_reference_value(env, sConstructor_, &constructor);

    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, pixelmap, result);
    }

    if (!IMG_IS_OK(status)) {
        HiLog::Error(LABEL, "CreatePixelMap | New instance could not be obtained");
        napi_get_undefined(env, &result);
    }

    return result;
}

STATIC_EXEC_FUNC(Unmarshalling)
{
#if !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
    auto context = static_cast<PixelMapAsyncContext*>(data);

    auto messageParcel = napi_messageSequence->GetMessageParcel();
    auto pixelmap = PixelMap::Unmarshalling(*messageParcel);
    std::unique_ptr<OHOS::Media::PixelMap> pixelmap_ptr(pixelmap);

    context->rPixelMap = std::move(pixelmap_ptr);

    if (IMG_NOT_NULL(context->rPixelMap)) {
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
#endif
}

void PixelMapNapi::UnmarshallingComplete(napi_env env, napi_status status, void *data)
{
    napi_value constructor = nullptr;
    napi_value result = nullptr;

    HiLog::Debug(LABEL, "UnmarshallingComplete IN");
    auto context = static_cast<PixelMapAsyncContext*>(data);

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, context->rPixelMap, result);
    }

    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        HiLog::Error(LABEL, "New instance could not be obtained");
        napi_get_undefined(env, &result);
    }

    CommonCallbackRoutine(env, context, result);
}

napi_value PixelMapNapi::Unmarshalling(napi_env env, napi_callback_info info)
{
#if !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
    if (PixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PixelMapNapi::Init(env, exports);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_4] = {0};
    size_t argCount = NUM_4;
    HiLog::Debug(LABEL, "Unmarshalling IN");

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

    napi_unwrap(env, argValue[NUM_0], (void **)&napi_messageSequence);

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
#else
    napi_value result = nullptr;
    return result;
#endif
}

napi_value PixelMapNapi::ThrowExceptionError(napi_env env,
    const std::string &tag, const std::uint32_t &code, const std::string &info)
{
    auto errNode = ETS_API_ERROR_CODE.find(tag);
    if (errNode != ETS_API_ERROR_CODE.end() &&
        errNode->second.find(code) != errNode->second.end()) {
        return ImageNapiUtils::ThrowExceptionError(env, code, info);
    }
    return ImageNapiUtils::ThrowExceptionError(env, ERROR, "Operation failed");
}

napi_value PixelMapNapi::CreatePixelMapFromParcel(napi_env env, napi_callback_info info)
#if defined(IOS_PLATFORM) || defined(A_PLATFORM)
{
    napi_value result = nullptr;
    return result;
}
#else
{
    if (PixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PixelMapNapi::Init(env, exports);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    HiLog::Debug(LABEL, "CreatePixelMapFromParcel IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    if (!IMG_IS_OK(status) || argCount != NUM_1) {
        return PixelMapNapi::ThrowExceptionError(env,
            CREATE_PIXEL_MAP_FROM_PARCEL, ERR_IMAGE_INVALID_PARAMETER, "Fail to napi_get_cb_info");
    }
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    napi_unwrap(env, argValue[NUM_0], (void **)&napi_messageSequence);
    auto messageParcel = napi_messageSequence->GetMessageParcel();
    if (messageParcel == nullptr) {
        return PixelMapNapi::ThrowExceptionError(env,
            CREATE_PIXEL_MAP_FROM_PARCEL, ERR_IPC, "get pacel failed");
    }
    PIXEL_MAP_ERR error;
    auto pixelmap = PixelMap::Unmarshalling(*messageParcel, error);
    if (!IMG_NOT_NULL(pixelmap)) {
        return PixelMapNapi::ThrowExceptionError(env,
            CREATE_PIXEL_MAP_FROM_PARCEL, error.errorCode, error.errorInfo);
    }
    std::shared_ptr<OHOS::Media::PixelMap> pixelPtr(pixelmap);
    napi_value constructor = nullptr;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, pixelPtr, result);
    }
    if (!IMG_IS_OK(status)) {
        HiLog::Error(LABEL, "New instance could not be obtained");
        return PixelMapNapi::ThrowExceptionError(env,
            CREATE_PIXEL_MAP_FROM_PARCEL, ERR_IMAGE_NAPI_ERROR, "New instance could not be obtained");
    }
    return result;
}
#endif

napi_value PixelMapNapi::GetIsEditable(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;
    HiLog::Debug(LABEL, "GetIsEditable IN");

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, HiLog::Error(LABEL, "fail to unwrap context"));

    if (pixelMapNapi->nativePixelMap_ == nullptr) {
        return result;
    }
    bool isEditable = pixelMapNapi->nativePixelMap_->IsEditable();

    napi_get_boolean(env, isEditable, &result);
    pixelMapNapi.release();

    return result;
}

napi_value PixelMapNapi::GetIsStrideAlignment(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;
    HiLog::Debug(LABEL, "GetIsStrideAlignment IN");
    
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi),
        result, HiLog::Error(LABEL, "fail to unwrap context"));
        
    if (pixelMapNapi->nativePixelMap_ == nullptr) {
        return result;
    }
    bool isDMA = pixelMapNapi->nativePixelMap_->IsStrideAlignment();
    napi_get_boolean(env, isDMA, &result);
    pixelMapNapi.release();
    return result;
}

napi_value PixelMapNapi::ReadPixelsToBuffer(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("PixelMapNapi::ReadPixelsToBuffer");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;

    HiLog::Debug(LABEL, "ReadPixelsToBuffer IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, HiLog::Error(LABEL, "fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, HiLog::Error(LABEL, "empty native pixelmap"));

    status = napi_get_arraybuffer_info(env, argValue[NUM_0],
            &(asyncContext->colorsBuffer), &(asyncContext->colorsBufferSize));

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "colors mismatch"));

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
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "ReadPixelsToBuffer",
        [](napi_env env, void *data)
        {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            context->status = context->rPixelMap->ReadPixels(
                context->colorsBufferSize, static_cast<uint8_t*>(context->colorsBuffer));
        }
        , EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, HiLog::Error(LABEL, "fail to create async work"));
    return result;
}

napi_value PixelMapNapi::ReadPixels(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;

    HiLog::Debug(LABEL, "ReadPixels IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, HiLog::Error(LABEL, "fail to unwrap context"));

    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, HiLog::Error(LABEL, "empty native pixelmap"));

    IMG_NAPI_CHECK_RET_D(parsePositionArea(env, argValue[NUM_0], &(asyncContext->area)),
        nullptr, HiLog::Error(LABEL, "fail to parse position area"));

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
        [](napi_env env, void *data)
        {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            auto area = context->area;
            context->status = context->rPixelMap->ReadPixels(
                area.size, area.offset, area.stride, area.region, static_cast<uint8_t*>(area.pixels));
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, HiLog::Error(LABEL, "fail to create async work"));
    return result;
}

napi_value PixelMapNapi::WritePixels(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;

    HiLog::Debug(LABEL, "WritePixels IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, HiLog::Error(LABEL, "fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, HiLog::Error(LABEL, "empty native pixelmap"));

    IMG_NAPI_CHECK_RET_D(parsePositionArea(env, argValue[NUM_0], &(asyncContext->area)),
        nullptr, HiLog::Error(LABEL, "fail to parse position area"));

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
        [](napi_env env, void *data)
        {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            auto area = context->area;
            context->status = context->rPixelMap->WritePixels(
                static_cast<uint8_t*>(area.pixels), area.size, area.offset, area.stride, area.region);
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, HiLog::Error(LABEL, "fail to create async work"));
    return result;
}

napi_value PixelMapNapi::WriteBufferToPixels(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("PixelMapNapi::WriteBufferToPixels");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;

    HiLog::Debug(LABEL, "WriteBufferToPixels IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, HiLog::Error(LABEL, "fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, HiLog::Error(LABEL, "empty native pixelmap"));
    status = napi_get_arraybuffer_info(env, argValue[NUM_0],
        &(asyncContext->colorsBuffer), &(asyncContext->colorsBufferSize));

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, HiLog::Error(LABEL, "fail to get buffer info"));

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
        [](napi_env env, void *data)
        {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            context->status = context->rPixelMap->WritePixels(static_cast<uint8_t*>(context->colorsBuffer),
                context->colorsBufferSize);
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, HiLog::Error(LABEL, "fail to create async work"));
    return result;
}

STATIC_COMPLETE_FUNC(GetImageInfo)
{
    HiLog::Debug(LABEL, "[PixelMap]GetImageInfoComplete IN");
    napi_value result = nullptr;
    napi_create_object(env, &result);
    auto context = static_cast<PixelMapAsyncContext*>(data);
    napi_value size = nullptr;
    napi_create_object(env, &size);
    napi_value sizeWith = nullptr;
    napi_create_int32(env, context->imageInfo.size.width, &sizeWith);
    napi_set_named_property(env, size, "width", sizeWith);
    napi_value sizeHeight = nullptr;
    napi_create_int32(env, context->imageInfo.size.height, &sizeHeight);
    napi_set_named_property(env, size, "height", sizeHeight);
    napi_set_named_property(env, result, "size", size);
    napi_value pixelFormatValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(context->imageInfo.pixelFormat), &pixelFormatValue);
    napi_set_named_property(env, result, "pixelFormat", pixelFormatValue);
    napi_value colorSpaceValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(context->imageInfo.colorSpace), &colorSpaceValue);
    napi_set_named_property(env, result, "colorSpace", colorSpaceValue);
    napi_value alphaTypeValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(context->imageInfo.alphaType), &alphaTypeValue);
    napi_set_named_property(env, result, "alphaType", alphaTypeValue);
    napi_value densityValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(context->imageInfo.baseDensity), &densityValue);
    napi_set_named_property(env, result, "density", densityValue);
    napi_value strideValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(context->rPixelMap->GetRowStride()), &strideValue);
    napi_set_named_property(env, result, "stride", strideValue);
    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        HiLog::Error(LABEL, "napi_create_int32 failed!");
        napi_get_undefined(env, &result);
    } else {
        context->status = SUCCESS;
    }
    HiLog::Debug(LABEL, "[PixelMap]GetImageInfoComplete OUT");
    CommonCallbackRoutine(env, context, result);
}
napi_value PixelMapNapi::GetImageInfo(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = 1;
    HiLog::Debug(LABEL, "GetImageInfo IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "fail to napi_get_cb_info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, HiLog::Error(LABEL, "fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, HiLog::Error(LABEL, "empty native pixelmap"));
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
        [](napi_env env, void *data)
        {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            context->rPixelMap->GetImageInfo(context->imageInfo);
            context->status = SUCCESS;
        }, GetImageInfoComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, HiLog::Error(LABEL, "fail to create async work"));
    return result;
}

napi_value PixelMapNapi::GetBytesNumberPerRow(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("PixelMapNapi::GetBytesNumberPerRow");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;

    HiLog::Debug(LABEL, "GetBytesNumberPerRow IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, HiLog::Error(LABEL, "fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . GetBytesNumberPerRow failed"),
        HiLog::Error(LABEL, "Pixelmap has crossed threads . GetBytesNumberPerRow failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        uint32_t rowBytes = pixelMapNapi->nativePixelMap_->GetRowBytes();
        status = napi_create_int32(env, rowBytes, &result);
        if (!IMG_IS_OK(status)) {
            HiLog::Error(LABEL, "napi_create_int32 failed!");
        }
    } else {
        HiLog::Error(LABEL, "native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value PixelMapNapi::GetPixelBytesNumber(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("PixelMapNapi::GetPixelBytesNumber");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;

    HiLog::Debug(LABEL, "GetPixelBytesNumber IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, HiLog::Error(LABEL, "fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . GetPixelBytesNumber failed"),
        HiLog::Error(LABEL, "Pixelmap has crossed threads . GetPixelBytesNumber failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        uint32_t byteCount = pixelMapNapi->nativePixelMap_->GetByteCount();
        status = napi_create_int32(env, byteCount, &result);
        if (!IMG_IS_OK(status)) {
            HiLog::Error(LABEL, "napi_create_int32 failed!");
        }
    } else {
        HiLog::Error(LABEL, "native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value PixelMapNapi::IsSupportAlpha(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;

    HiLog::Debug(LABEL, "IsSupportAlpha IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, HiLog::Error(LABEL, "fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . IsSupportAlpha failed"),
        HiLog::Error(LABEL, "Pixelmap has crossed threads . IsSupportAlpha failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        AlphaType alphaType = pixelMapNapi->nativePixelMap_->GetAlphaType();
        bool isSupportAlpha = !(alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
        status = napi_get_boolean(env, isSupportAlpha, &result);
        if (!IMG_IS_OK(status)) {
            HiLog::Error(LABEL, "napi_create_bool failed!");
        }
    } else {
        HiLog::Error(LABEL, "native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value PixelMapNapi::SetAlphaAble(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    bool isAlphaAble = false;

    HiLog::Debug(LABEL, "SetAlphaAble IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, HiLog::Error(LABEL, "fail to napi_get_cb_info"));
    NAPI_ASSERT(env, argCount > NUM_0, "Invalid input");
    NAPI_ASSERT(env, ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_boolean, "Invalid input type");
    NAPI_ASSERT(env, napi_get_value_bool(env, argValue[NUM_0], &isAlphaAble) == napi_ok, "Parse input error");

    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, HiLog::Error(LABEL, "fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . SetAlphaAble failed"),
        HiLog::Error(LABEL, "Pixelmap has crossed threads . SetAlphaAble failed"));
    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        AlphaType alphaType = pixelMapNapi->nativePixelMap_->GetAlphaType();
        if (isAlphaAble && (alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
            pixelMapNapi->nativePixelMap_->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
        } else if ((!isAlphaAble) && !(alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)) {
            pixelMapNapi->nativePixelMap_->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
        }
    } else {
        HiLog::Error(LABEL, "native pixelmap is nullptr!");
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
        result = PixelMapNapi::CreatePixelMap(env, context->alphaMap);
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value PixelMapNapi::CreateAlphaPixelmap(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = 1;
    HiLog::Debug(LABEL, "CreateAlphaPixelmap IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "fail to napi_get_cb_info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, HiLog::Error(LABEL, "fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, HiLog::Error(LABEL, "empty native pixelmap"));
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
        [](napi_env env, void *data)
        {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            InitializationOptions opts;
            opts.pixelFormat = PixelFormat::ALPHA_8;
            auto tmpPixelMap = PixelMap::Create(*(context->rPixelMap), opts);
            context->alphaMap = std::move(tmpPixelMap);
            context->status = SUCCESS;
        }, CreateAlphaPixelmapComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, HiLog::Error(LABEL, "fail to create async work"));
    return result;
}

napi_value PixelMapNapi::GetDensity(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;

    HiLog::Debug(LABEL, "GetDensity IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, HiLog::Error(LABEL, "fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . GetDensity failed"),
        HiLog::Error(LABEL, "Pixelmap has crossed threads . GetDensity failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        uint32_t baseDensity = pixelMapNapi->nativePixelMap_->GetBaseDensity();
        status = napi_create_int32(env, baseDensity, &result);
        if (!IMG_IS_OK(status)) {
            HiLog::Error(LABEL, "napi_create_int32 failed!");
        }
    } else {
        HiLog::Error(LABEL, "native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value PixelMapNapi::SetDensity(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    uint32_t density = 0;

    HiLog::Debug(LABEL, "SetDensity IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    NAPI_ASSERT(env,
        (argCount == NUM_1 && ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_number),
        "Density input mismatch");
    NAPI_ASSERT(env, napi_get_value_uint32(env, argValue[NUM_0], &density) == napi_ok, "Could not parse density");

    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, HiLog::Error(LABEL, "fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . SetDensity failed"),
        HiLog::Error(LABEL, "Pixelmap has crossed threads . SetDensity failed"));
    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        ImageInfo imageinfo;
        pixelMapNapi->nativePixelMap_->GetImageInfo(imageinfo);
        imageinfo.baseDensity = density;
        pixelMapNapi->nativePixelMap_->SetImageInfo(imageinfo, true);
    } else {
        HiLog::Error(LABEL, "native pixelmap is nullptr!");
    }
    pixelMapNapi.release();
    return result;
}

napi_value PixelMapNapi::Release(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[1] = {0};
    size_t argCount = 1;

    HiLog::Debug(LABEL, "Release IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, HiLog::Error(LABEL, "fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, HiLog::Error(LABEL, "fail to unwrap context"));

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
            HiLog::Debug(LABEL, "Release in napi_id:%{public}d, id:%{public}d",
                asyncContext->nConstructor->GetUniqueId(),
                asyncContext->nConstructor->nativePixelMap_->GetUniqueId());
            asyncContext->nConstructor->nativePixelMap_.reset();
        }
        asyncContext->status = SUCCESS;
    }
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "Release",
        [](napi_env env, void *data)
        {
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, HiLog::Error(LABEL, "fail to create async work"));
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
        HiLog::Error(LABEL, "fail to napi_get_cb_info");
        return false;
    }
    nVal->context = std::make_unique<PixelMapAsyncContext>();
    nVal->status = napi_unwrap(env, nVal->thisVar, reinterpret_cast<void**>(&(nVal->context->nConstructor)));
    if (nVal->status != napi_ok) {
        HiLog::Error(LABEL, "fail to unwrap context");
        return false;
    }
    nVal->context->status = SUCCESS;
    return true;
}

static void SetAlphaExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        HiLog::Error(LABEL, "Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->status = context->rPixelMap->SetAlpha(
                static_cast<float>(context->alpha));
        } else {
            HiLog::Error(LABEL, "Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        HiLog::Debug(LABEL, "Scale has failed. do nothing");
    }
}

napi_value PixelMapNapi::SetAlpha(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_2;
    napi_value argValue[NUM_2] = {0};
    nVal.argv = argValue;

    HiLog::Debug(LABEL, "SetAlpha IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_1 && nVal.argc != NUM_2) {
        HiLog::Error(LABEL, "Invalid args count %{public}zu", nVal.argc);
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (napi_ok !=
            napi_get_value_double(env, nVal.argv[NUM_0], &(nVal.context->alpha))) {
            HiLog::Error(LABEL, "Arg 0 type mismatch");
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
        [](napi_env env, void *data)
        {
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

static void ScaleExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        HiLog::Error(LABEL, "Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->rPixelMap->scale(static_cast<float>(context->xArg), static_cast<float>(context->yArg));
            context->status = SUCCESS;
        } else {
            HiLog::Error(LABEL, "Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        HiLog::Debug(LABEL, "Scale has failed. do nothing");
    }
}

napi_value PixelMapNapi::Scale(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_3;
    napi_value argValue[NUM_3] = {0};
    nVal.argv = argValue;
    HiLog::Debug(LABEL, "Scale IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_2 && nVal.argc != NUM_3) {
        HiLog::Error(LABEL, "Invalid args count %{public}zu", nVal.argc);
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (napi_ok != napi_get_value_double(env, nVal.argv[NUM_0], &(nVal.context->xArg))) {
            HiLog::Error(LABEL, "Arg 0 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
        if (napi_ok != napi_get_value_double(env, nVal.argv[NUM_1], &(nVal.context->yArg))) {
            HiLog::Error(LABEL, "Arg 1 type mismatch");
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
        [](napi_env env, void *data)
        {
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

static void TranslateExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        HiLog::Error(LABEL, "Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->rPixelMap->translate(static_cast<float>(context->xArg), static_cast<float>(context->yArg));
            context->status = SUCCESS;
        } else {
            HiLog::Error(LABEL, "Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        HiLog::Debug(LABEL, "Translate has failed. do nothing");
    }
}

napi_value PixelMapNapi::Translate(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_3;
    napi_value argValue[NUM_3] = {0};
    nVal.argv = argValue;
    HiLog::Debug(LABEL, "Translate IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_2 && nVal.argc != NUM_3) {
        HiLog::Error(LABEL, "Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (napi_ok != napi_get_value_double(env, nVal.argv[NUM_0], &(nVal.context->xArg))) {
            HiLog::Error(LABEL, "Arg 0 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
        if (napi_ok != napi_get_value_double(env, nVal.argv[NUM_1], &(nVal.context->yArg))) {
            HiLog::Error(LABEL, "Arg 1 type mismatch");
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
        [](napi_env env, void *data)
        {
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

static void RotateExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        HiLog::Error(LABEL, "Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->rPixelMap->rotate(context->xArg);
            context->status = SUCCESS;
        } else {
            HiLog::Error(LABEL, "Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        HiLog::Debug(LABEL, "Rotate has failed. do nothing");
    }
}

napi_value PixelMapNapi::Rotate(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_2;
    napi_value argValue[NUM_2] = {0};
    nVal.argv = argValue;
    HiLog::Debug(LABEL, "Rotate IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_1 && nVal.argc != NUM_2) {
        HiLog::Error(LABEL, "Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (napi_ok != napi_get_value_double(env, nVal.argv[NUM_0], &(nVal.context->xArg))) {
            HiLog::Error(LABEL, "Arg 0 type mismatch");
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
        [](napi_env env, void *data)
        {
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

static void FlipExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        HiLog::Error(LABEL, "Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->rPixelMap->flip(context->xBarg, context->yBarg);
            context->status = SUCCESS;
        } else {
            HiLog::Error(LABEL, "Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        HiLog::Debug(LABEL, "Flip has failed. do nothing");
    }
}

napi_value PixelMapNapi::Flip(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_3;
    napi_value argValue[NUM_3] = {0};
    nVal.argv = argValue;
    HiLog::Debug(LABEL, "Flip IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_2 && nVal.argc != NUM_3) {
        HiLog::Error(LABEL, "Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (napi_ok != napi_get_value_bool(env, nVal.argv[NUM_0], &(nVal.context->xBarg))) {
            HiLog::Error(LABEL, "Arg 0 type mismatch");
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
        if (napi_ok != napi_get_value_bool(env, nVal.argv[NUM_1], &(nVal.context->yBarg))) {
            HiLog::Error(LABEL, "Arg 1 type mismatch");
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
        [](napi_env env, void *data)
        {
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

static void CropExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        HiLog::Error(LABEL, "Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->status = context->rPixelMap->crop(context->area.region);
        } else {
            HiLog::Error(LABEL, "Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        HiLog::Debug(LABEL, "Crop has failed. do nothing");
    }
}

napi_value PixelMapNapi::Crop(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_2;
    napi_value argValue[NUM_2] = {0};
    nVal.argv = argValue;
    HiLog::Debug(LABEL, "Crop IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_1 && nVal.argc != NUM_2) {
        HiLog::Error(LABEL, "Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    } else {
        if (!parseRegion(env, nVal.argv[NUM_0], &(nVal.context->area.region))) {
            HiLog::Error(LABEL, "Region type mismatch");
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
        [](napi_env env, void *data)
        {
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

napi_value PixelMapNapi::GetColorSpace(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_0;
    HiLog::Debug(LABEL, "GetColorSpace IN");
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
        HiLog::Error(LABEL, "Pixelmap has crossed threads . GetColorSpace failed"));
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

napi_value PixelMapNapi::SetColorSpace(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_1;
    napi_value argValue[NUM_1] = {0};
    nVal.argv = argValue;
    HiLog::Debug(LABEL, "SetColorSpace IN");
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
        HiLog::Error(LABEL, "Pixelmap has crossed threads . SetColorSpace failed"));
#ifdef IMAGE_COLORSPACE_FLAG
#if !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
    nVal.context->colorSpace = ColorManager::GetColorSpaceByJSObject(env, nVal.argv[NUM_0]);
#endif
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

napi_value PixelMapNapi::Marshalling(napi_env env, napi_callback_info info)
{
#if !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
    NapiValues nVal;
    nVal.argc = NUM_1;
    napi_value argValue[NUM_1] = {0};
    nVal.argv = argValue;
    HiLog::Debug(LABEL, "Marshalling IN");

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
    napi_unwrap(env, nVal.argv[0], reinterpret_cast<void**>(&napiSequence));
    auto messageParcel = napiSequence->GetMessageParcel();
    bool st = nVal.context->rPixelMap->Marshalling(*messageParcel);
    if (!st) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IPC, "marshalling pixel map to parcel failed.");
    }
    return nVal.result;
#else
    napi_value result = nullptr;
    return result;
#endif
}

static void ApplyColorSpaceExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        HiLog::Error(LABEL, "Null context");
        return;
    }
    if (context->status != SUCCESS) {
        HiLog::Debug(LABEL, "ApplyColorSpace has failed. do nothing");
        return;
    }
    if (context->rPixelMap == nullptr || context->colorSpace == nullptr) {
        context->status = ERR_IMAGE_INIT_ABNORMAL;
        HiLog::Error(LABEL, "ApplyColorSpace Null native ref");
        return;
    }
    context->status = context->rPixelMap->ApplyColorSpace(*(context->colorSpace));
}

static void ParseColorSpaceVal(napi_env env, napi_value val, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        HiLog::Error(LABEL, "Null context");
        return;
    }

#ifdef IMAGE_COLORSPACE_FLAG
#if !defined(IOS_PLATFORM) && !defined(A_PLATFORM)
    context->colorSpace = ColorManager::GetColorSpaceByJSObject(env, val);
#endif
    if (context->colorSpace == nullptr) {
        context->status = ERR_IMAGE_INVALID_PARAMETER;
    }
#else
    Val.context->status = ERR_IMAGE_DATA_UNSUPPORT;
#endif
}

napi_value PixelMapNapi::ApplyColorSpace(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_2;
    napi_value argValue[NUM_2] = {0};
    nVal.argv = argValue;
    HiLog::Debug(LABEL, "ApplyColorSpace IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    if (nVal.argc != NUM_1 && nVal.argc != NUM_2) {
        HiLog::Error(LABEL, "Invalid args count");
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

void PixelMapNapi::release()
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
