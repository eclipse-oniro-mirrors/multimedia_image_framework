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
#include "image_log.h"
#include "image_napi_utils.h"
#include "image_pixel_map_napi.h"
#include "image_source_napi.h"
#include "image_trace.h"
#include "log_tags.h"
#include "color_space_object_convertor.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include <charconv>
#include <cstdint>
#include <regex>
#include <vector>
#include <memory>
#include "vpe_utils.h"
#include "napi_message_sequence.h"
#include "pixel_map_from_surface.h"
#include "transaction/rs_interfaces.h"
#include "color_utils.h"
#else
static int g_uniqueTid = 0;
#endif
#include "hitrace_meter.h"
#include "pixel_map.h"
#include "image_format_convert.h"
#include <securec.h>
#include "image_utils.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelMapNapi"

namespace {
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
    constexpr uint32_t NUM_3 = 3;
    constexpr uint32_t NUM_4 = 4;
}

enum class FormatType:int8_t {
    UNKNOWN,
    YUV,
    RGB,
    ASTC
};

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
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
NAPI_MessageSequence* napi_messageSequence = nullptr;
#endif
static std::mutex pixelMapCrossThreadMutex_;
struct PositionArea {
    void* pixels;
    size_t size;
    uint32_t offset;
    uint32_t stride;
    Rect region;
};

struct ImageEnum {
    std::string name;
    int32_t numVal;
    std::string strVal;
};

static std::vector<struct ImageEnum> AntiAliasingLevelMap = {
    {"NONE", 0, ""},
    {"LOW", 1, ""},
    {"MEDIUM", 2, ""},
    {"HIGH", 3, ""},
};

static std::vector<struct ImageEnum> HdrMetadataKeyMap = {
    {"HDR_METADATA_TYPE", 0, ""},
    {"HDR_STATIC_METADATA", 1, ""},
    {"HDR_DYNAMIC_METADATA", 2, ""},
    {"HDR_GAINMAP_METADATA", 3, ""},
};

static std::vector<struct ImageEnum> HdrMetadataTypeMap = {
    {"NONE", 0, ""},
    {"BASE", 1, ""},
    {"GAINMAP", 2, ""},
    {"ALTERNATE", 3, ""},
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
    PixelFormat destFormat = PixelFormat::UNKNOWN;
    FormatType srcFormatType = FormatType::UNKNOWN;
    FormatType dstFormatType = FormatType::UNKNOWN;
    AntiAliasingOption antiAliasing;
    std::shared_ptr<napi_value[]> argv = nullptr;
    size_t argc = 0;
    bool transformEnabled = false;
};
using PixelMapAsyncContextPtr = std::unique_ptr<PixelMapAsyncContext>;
std::shared_ptr<PixelMap> srcPixelMap = nullptr;

class AgainstTransferGC {
public:
    std::shared_ptr<PixelMap> pixelMap = nullptr;
    ~AgainstTransferGC()
    {
        pixelMap = nullptr;
    }
};

static PixelFormat ParsePixlForamt(int32_t val)
{
    if (val < static_cast<int32_t>(PixelFormat::EXTERNAL_MAX)) {
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

static AntiAliasingOption ParseAntiAliasingOption(int32_t val)
{
    if (val <= static_cast<int32_t>(AntiAliasingOption::SPLINE)) {
        return AntiAliasingOption(val);
    }

    return AntiAliasingOption::NONE;
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
        IMAGE_LOGD("no alphaType in initialization options");
    }
    opts->alphaType = ParseAlphaType(tmpNumber);

    tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "pixelFormat", tmpNumber)) {
        IMAGE_LOGD("no pixelFormat in initialization options");
    }
    opts->pixelFormat = ParsePixlForamt(tmpNumber);

    tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "srcPixelFormat", tmpNumber)) {
        IMAGE_LOGD("no srcPixelFormat in initialization options");
    }
    opts->srcPixelFormat = ParsePixlForamt(tmpNumber);

    tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "scaleMode", tmpNumber)) {
        IMAGE_LOGD("no scaleMode in initialization options");
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

ImageType PixelMapNapi::ParserImageType(napi_env env, napi_value argv)
{
    napi_value constructor = nullptr;
    napi_value global = nullptr;
    bool isInstance = false;
    napi_status ret = napi_invalid_arg;

    napi_get_global(env, &global);

    ret = napi_get_named_property(env, global, "PixelMap", &constructor);
    if (ret != napi_ok) {
        IMAGE_LOGI("Get PixelMapNapi property failed!");
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

static napi_value CreateEnumTypeObject(napi_env env, napi_valuetype type, std::vector<struct ImageEnum> imageEnumMap)
{
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status == napi_ok) {
        for (auto imgEnum : imageEnumMap) {
            napi_value enumNapiValue = nullptr;
            if (type == napi_string) {
                status = napi_create_string_utf8(env, imgEnum.strVal.c_str(),
                    NAPI_AUTO_LENGTH, &enumNapiValue);
            } else if (type == napi_number) {
                status = napi_create_int32(env, imgEnum.numVal, &enumNapiValue);
            } else {
                IMAGE_LOGE("Unsupported type %{public}d!", type);
            }
            if (status == napi_ok && enumNapiValue != nullptr) {
                status = napi_set_named_property(env, result, imgEnum.name.c_str(), enumNapiValue);
            }
            if (status != napi_ok) {
                IMAGE_LOGE("Failed to add named prop!");
                break;
            }
        }

        if (status == napi_ok) {
            return result;
        }
    }
    IMAGE_LOGE("CreateEnumTypeObject is Failed!");
    napi_get_undefined(env, &result);
    return result;
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
        napi_close_handle_scope(env, scope);
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

static void NapiSendEvent(napi_env env, PixelMapAsyncContext *asyncContext,
    napi_event_priority prio, uint32_t status = SUCCESS)
{
    if (napi_status::napi_ok != napi_send_event(env, [env, asyncContext, status]() {
        if (!IMG_NOT_NULL(asyncContext)) {
            IMAGE_LOGE("SendEvent asyncContext is nullptr!");
            return;
        }
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        asyncContext->status = status;
        PixelMapAsyncContext *context = asyncContext;
        CommonCallbackRoutine(env, context, result);
    }, prio)) {
        IMAGE_LOGE("failed to sendEvent!");
    }
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
    if (data == nullptr) {
        IMAGE_LOGE("GeneralErrorComplete invalid parameter: data is null");
        return;
    }

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

void PixelMapNapi::ExtraAddNapiFunction(std::vector<napi_property_descriptor> &props)
{
    props.insert(props.end(), {
        DECLARE_NAPI_FUNCTION("setMemoryNameSync", SetMemoryNameSync),
        DECLARE_NAPI_FUNCTION("cloneSync", CloneSync),
        DECLARE_NAPI_FUNCTION("clone", Clone),
        DECLARE_NAPI_FUNCTION("isReleased", IsReleased),
        DECLARE_NAPI_FUNCTION("getUniqueId", GetNativeUniqueId),
        DECLARE_NAPI_FUNCTION("createCroppedAndScaledPixelMapSync", CreateCroppedAndScaledPixelMapSync),
        DECLARE_NAPI_FUNCTION("createCroppedAndScaledPixelMap", CreateCroppedAndScaledPixelMap),
        });
}

std::vector<napi_property_descriptor> PixelMapNapi::RegisterNapi()
{
    std::vector<napi_property_descriptor> props = {
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
        DECLARE_NAPI_FUNCTION("createScaledPixelMap", CreateScaledPixelMap),
        DECLARE_NAPI_FUNCTION("createScaledPixelMapSync", CreateScaledPixelMapSync),
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
        DECLARE_NAPI_FUNCTION("toSdr", ToSdr),
        DECLARE_NAPI_FUNCTION("convertPixelFormat", ConvertPixelMapFormat),
        DECLARE_NAPI_FUNCTION("setTransferDetached", SetTransferDetached),
        DECLARE_NAPI_FUNCTION("getMetadata", GetMetadata),
        DECLARE_NAPI_FUNCTION("setMetadata", SetMetadata),
        DECLARE_NAPI_FUNCTION("setMetadataSync", SetMetadataSync),
    };
    ExtraAddNapiFunction(props);
    return props;
}

napi_value PixelMapNapi::Init(napi_env env, napi_value exports)
{
    std::vector<napi_property_descriptor> props = PixelMapNapi::RegisterNapi();
    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMap", CreatePixelMap),
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapUsingAllocator", CreatePixelMapUsingAllocator),
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapUsingAllocatorSync", CreatePixelMapUsingAllocatorSync),
        DECLARE_NAPI_STATIC_FUNCTION("createPremultipliedPixelMap", CreatePremultipliedPixelMap),
        DECLARE_NAPI_STATIC_FUNCTION("createUnpremultipliedPixelMap", CreateUnpremultipliedPixelMap),
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapSync", CreatePixelMapSync),
        DECLARE_NAPI_STATIC_FUNCTION("unmarshalling", Unmarshalling),
        DECLARE_NAPI_STATIC_FUNCTION(CREATE_PIXEL_MAP_FROM_PARCEL.c_str(), CreatePixelMapFromParcel),
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapFromSurface", CreatePixelMapFromSurface),
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapFromSurfaceSync", CreatePixelMapFromSurfaceSync),
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapFromSurfaceWithTransformation",
            CreatePixelMapFromSurfaceWithTransformation),
        DECLARE_NAPI_STATIC_FUNCTION("createPixelMapFromSurfaceWithTransformationSync",
            CreatePixelMapFromSurfaceWithTransformationSync),
        DECLARE_NAPI_STATIC_FUNCTION("convertPixelFormat", ConvertPixelMapFormat),
#endif
        DECLARE_NAPI_PROPERTY("AntiAliasingLevel", CreateEnumTypeObject(env, napi_number, AntiAliasingLevelMap)),
        DECLARE_NAPI_PROPERTY("HdrMetadataKey", CreateEnumTypeObject(env, napi_number, HdrMetadataKeyMap)),
        DECLARE_NAPI_PROPERTY("HdrMetadataType", CreateEnumTypeObject(env, napi_number, HdrMetadataTypeMap)),
    };

    napi_value constructor = nullptr;

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                          Constructor, nullptr, props.size(),
                          props.data(), &constructor)),
        nullptr, IMAGE_LOGE("define class fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_create_reference(env, constructor, 1, &sConstructor_)),
        nullptr, IMAGE_LOGE("create reference fail")
    );

    auto ctorContext = new NapiConstructorContext();
    ctorContext->env_ = env;
    ctorContext->ref_ = sConstructor_;
    napi_add_env_cleanup_hook(env, ImageNapiUtils::CleanUpConstructorContext, ctorContext);

    auto result = DoInitAfter(env, exports, constructor,
        IMG_ARRAY_SIZE(static_prop), static_prop);

    IMAGE_LOGD("Init success");
    return result;
}

std::shared_ptr<PixelMap> PixelMapNapi::GetPixelMap(napi_env env, napi_value pixelmap)
{
    std::unique_ptr<PixelMapNapi> pixelMapNapi = nullptr;

    napi_status status = napi_unwrap(env, pixelmap, reinterpret_cast<void**>(&pixelMapNapi));
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("GetPixelMap napi unwrap failed, status is %{public}d", status);
        return nullptr;
    }

    if (pixelMapNapi == nullptr) {
        IMAGE_LOGE("GetPixelMap pixmapNapi is nullptr");
        return nullptr;
    }

    auto pixelmapNapiPtr = pixelMapNapi.release();
    if (pixelmapNapiPtr == nullptr) {
        IMAGE_LOGE("GetPixelMap pixelmapNapi is nullptr");
        return nullptr;
    }
    return pixelmapNapiPtr->nativePixelMap_;
}

std::shared_ptr<std::vector<std::shared_ptr<PixelMap>>> PixelMapNapi::GetPixelMaps(napi_env env, napi_value pixelmaps)
{
    auto PixelMaps = std::make_shared<std::vector<std::shared_ptr<PixelMap>>>();
    uint32_t length = 0;
    auto status = napi_get_array_length(env, pixelmaps, &length);
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("GetPixelMaps napi get array length failed");
        return nullptr;
    }
    for (uint32_t i = 0; i < length; ++i) {
        napi_value element;
        status = napi_get_element(env, pixelmaps, i, &element);
        if (!IMG_IS_OK(status)) {
            IMAGE_LOGE("GetPixelMaps napi get element failed");
            return nullptr;
        }
        std::shared_ptr<PixelMap> pixelMap;
        pixelMap = GetPixelMap(env, element);
        PixelMaps->push_back(pixelMap);
    }
    return PixelMaps;
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
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&pixmapNapi));
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("OHOS_MEDIA_GetPixelMap unwrap failed, status is %{public}d", status);
        return nullptr;
    }
    if (pixmapNapi == nullptr) {
        IMAGE_LOGD("%{public}s pixmapNapi unwrapped is nullptr", __func__);
        return nullptr;
    }
    return reinterpret_cast<void*>(pixmapNapi->GetPixelMap());
}

extern "C" __attribute__((visibility("default"))) int32_t OHOS_MEDIA_GetImageInfo(napi_env env, napi_value value,
    OhosPixelMapInfo *info)
{
    IMAGE_LOGD("GetImageInfo IN");

    if (info == nullptr) {
        IMAGE_LOGE("info is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    PixelMapNapi *pixmapNapi = nullptr;
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&pixmapNapi));
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("pixmapNapi unwrap failed, status is %{public}d", status);
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    if (pixmapNapi == nullptr) {
        IMAGE_LOGD("%{public}s pixmapNapi unwrapped is nullptr", __func__);
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    std::shared_ptr<PixelMap> pixelMap = pixmapNapi->GetPixelNapiInner();
    if ((pixelMap == nullptr)) {
        IMAGE_LOGE("pixelMap is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    info->width = imageInfo.size.width;
    info->height = imageInfo.size.height;
    info->rowSize = pixelMap->GetRowStride();
    info->pixelFormat = static_cast<int32_t>(imageInfo.pixelFormat);

    IMAGE_LOGD("GetImageInfo, w=%{public}u, h=%{public}u, r=%{public}u, f=%{public}d",
        info->width, info->height, info->rowSize, info->pixelFormat);

    return OHOS_IMAGE_RESULT_SUCCESS;
}

static bool CheckAstc(PixelFormat format)
{
    return format == PixelFormat::ASTC_4x4 ||
        format == PixelFormat::ASTC_6x6 ||
        format == PixelFormat::ASTC_8x8;
}

extern "C" __attribute__((visibility("default"))) int32_t OHOS_MEDIA_AccessPixels(napi_env env, napi_value value,
    uint8_t** addrPtr)
{
    IMAGE_LOGD("AccessPixels IN");

    PixelMapNapi *pixmapNapi = nullptr;
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&pixmapNapi));
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("OHOS_MEDIA_AccessPixels unwrap failed, status is %{public}d", status);
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    if (pixmapNapi == nullptr) {
        IMAGE_LOGD("%{public}s pixmapNapi unwrapped is nullptr", __func__);
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    std::shared_ptr<PixelMap> pixelMap = pixmapNapi->GetPixelNapiInner();
    if (pixelMap == nullptr) {
        IMAGE_LOGE("pixelMap is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    if (CheckAstc(pixelMap->GetPixelFormat())) {
        IMAGE_LOGE("ASTC is not supported");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    const uint8_t *constPixels = pixelMap->GetPixels();
    if (constPixels == nullptr) {
        IMAGE_LOGE("const pixels is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    uint8_t *pixels = const_cast<uint8_t*>(constPixels);
    if (pixels == nullptr) {
        IMAGE_LOGE("pixels is nullptr");
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    pixmapNapi->LockPixelMap();

    if (addrPtr != nullptr) {
        *addrPtr = pixels;
    }

    IMAGE_LOGD("AccessPixels OUT");
    return OHOS_IMAGE_RESULT_SUCCESS;
}

extern "C" __attribute__((visibility("default"))) int32_t OHOS_MEDIA_UnAccessPixels(napi_env env, napi_value value)
{
    IMAGE_LOGD("UnAccessPixels IN");

    PixelMapNapi *pixmapNapi = nullptr;
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&pixmapNapi));
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("OHOS_MEDIA_UnAccessPixels unwrap failed, status is %{public}d", status);
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }
    if (pixmapNapi == nullptr) {
        IMAGE_LOGD("%{public}s pixmapNapi unwrapped is nullptr", __func__);
        return OHOS_IMAGE_RESULT_BAD_PARAMETER;
    }

    pixmapNapi->UnlockPixelMap();

    return OHOS_IMAGE_RESULT_SUCCESS;
}

void *DetachPixelMapFunc(napi_env env, void *value, void *)
{
    IMAGE_LOGD("DetachPixelMapFunc in");
    if (value == nullptr) {
        IMAGE_LOGE("DetachPixelMapFunc value is nullptr");
        return value;
    }
    auto pixelNapi = reinterpret_cast<PixelMapNapi*>(value);
    pixelNapi->setPixelNapiEditable(false);
    AgainstTransferGC *data = new AgainstTransferGC();
    data->pixelMap = pixelNapi->GetPixelNapiInner();
    if (pixelNapi->GetTransferDetach()) {
        pixelNapi->ReleasePixelNapiInner();
    }
    return reinterpret_cast<void*>(data);
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
    uint64_t pixelMapId;
    uint64_t UNIQUE_ID_SHIFT = 32;
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    pixelMapId = (static_cast<uint64_t>(pixelMap->GetUniqueId()) << UNIQUE_ID_SHIFT) |
        static_cast<uint64_t>(g_uniqueTid++);
#else
    pixelMapId = (static_cast<uint64_t>(pixelMap->GetUniqueId()) << UNIQUE_ID_SHIFT) | static_cast<uint64_t>(gettid());
#endif
    status = napi_create_bigint_uint64(env, pixelMapId, &argv[0]);
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("NewPixelNapiInstance napi_create_bigint_uint64 failed");
        return status;
    }
    PixelMapContainer::GetInstance().Insert(pixelMapId, pixelMap);

    status = napi_new_instance(env, constructor, argc, argv, &result);
    return status;
}

napi_value AttachPixelMapFunc(napi_env env, void *value, void *)
{
    if (value == nullptr) {
        IMAGE_LOGE("attach value is nullptr");
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(pixelMapCrossThreadMutex_);

    napi_value result = nullptr;
    if (value == nullptr) {
        IMAGE_LOGE("attach value lock losed");
        napi_get_undefined(env, &result);
        return result;
    }
    AgainstTransferGC *data = reinterpret_cast<AgainstTransferGC*>(value);
    std::shared_ptr<PixelMap> attachPixelMap = std::move(data->pixelMap);
    delete data;
    if (attachPixelMap == nullptr) {
        IMAGE_LOGE("AttachPixelMapFunc attachPixelMap is nullptr");
        napi_get_undefined(env, &result);
        return result;
    }
    napi_value constructor = nullptr;
    napi_status status;

    if (PixelMapNapi::GetConstructor() == nullptr) {
        IMAGE_LOGI("PixelMapNapi::GetConstructor() is nullptr");
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PixelMapNapi::Init(env, exports);
    }
    napi_value globalValue;
    napi_get_global(env, &globalValue);
    status = napi_get_named_property(env, globalValue, CLASS_NAME.c_str(), &constructor);
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGI("napi_get_named_property failed requireNapi in");
        napi_value func;
        napi_get_named_property(env, globalValue, "requireNapi", &func);

        napi_value imageInfo;
        napi_create_string_utf8(env, "multimedia.image", NAPI_AUTO_LENGTH, &imageInfo);
        napi_value funcArgv[1] = { imageInfo };
        napi_value returnValue;
        napi_call_function(env, globalValue, func, 1, funcArgv, &returnValue);
        status = napi_get_named_property(env, globalValue, CLASS_NAME.c_str(), &constructor);
        IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("napi_get_named_property error"));
    }

    status = NewPixelNapiInstance(env, constructor, attachPixelMap, result);
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("AttachPixelMapFunc napi_get_referencce_value failed");
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
    IMAGE_LOGD("Constructor IN");
    status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    IMG_NAPI_CHECK_RET(IMG_IS_READY(status, thisVar), undefineVar);
    uint64_t pixelMapId = 0;
    bool lossless = true;
    if (!IMG_IS_OK(napi_get_value_bigint_uint64(env, argv[0], &pixelMapId, &lossless))) {
        IMAGE_LOGE("Constructor napi_get_value_bigint_uint64 failed");
        return undefineVar;
    }
    std::unique_ptr<PixelMapNapi> pPixelMapNapi = std::make_unique<PixelMapNapi>();

    IMG_NAPI_CHECK_RET(IMG_NOT_NULL(pPixelMapNapi), undefineVar);

    pPixelMapNapi->env_ = env;
    if (PixelMapContainer::GetInstance().Find(pixelMapId)) {
        pPixelMapNapi->nativePixelMap_ = PixelMapContainer::GetInstance()[pixelMapId];
        IMAGE_LOGD("Constructor in napi_id:%{public}d, id:%{public}d",
            pPixelMapNapi->GetUniqueId(), pPixelMapNapi->nativePixelMap_->GetUniqueId());
    } else {
        IMAGE_LOGE("Constructor nativePixelMap is nullptr");
    }

    napi_coerce_to_native_binding_object(
        env, thisVar, DetachPixelMapFunc, AttachPixelMapFunc, pPixelMapNapi.get(), nullptr);

    if (pPixelMapNapi->nativePixelMap_ == nullptr) {
        status = napi_wrap(env, thisVar, reinterpret_cast<void*>(pPixelMapNapi.get()), PixelMapNapi::Destructor,
            nullptr, nullptr);
    } else {
        status = napi_wrap_enhance(env, thisVar, reinterpret_cast<void*>(pPixelMapNapi.get()),
            PixelMapNapi::Destructor, true, nullptr,
            static_cast<size_t>(pPixelMapNapi->nativePixelMap_->GetByteCount()), nullptr);
    }
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), undefineVar, IMAGE_LOGE("Failure wrapping js to native napi"));

    pPixelMapNapi.release();
    PixelMapContainer::GetInstance().Erase(pixelMapId);
    return thisVar;
}

void PixelMapNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        IMAGE_LOGD("Destructor pixelmapNapi");
        delete reinterpret_cast<PixelMapNapi*>(nativeObject);
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

STATIC_EXEC_FUNC(CreatePixelMap)
{
    if (data == nullptr) {
        IMAGE_LOGE("CreatePixelMapExec invalid parameter: data is null");
        return;
    }

    auto context = static_cast<PixelMapAsyncContext*>(data);
    auto colors = static_cast<uint32_t*>(context->colorsBuffer);
    if (colors == nullptr) {
        if (context->opts.pixelFormat == PixelFormat::RGBA_1010102 ||
            context->opts.pixelFormat == PixelFormat::YCBCR_P010 ||
            context->opts.pixelFormat == PixelFormat::YCRCB_P010) {
            context->opts.useDMA = true;
        }
        auto pixelmap = PixelMap::Create(context->opts);
        context->rPixelMap = std::move(pixelmap);
    } else {
        if (context->opts.pixelFormat == PixelFormat::RGBA_1010102 ||
            context->opts.pixelFormat == PixelFormat::YCBCR_P010 ||
            context->opts.pixelFormat == PixelFormat::YCRCB_P010) {
            context->rPixelMap = nullptr;
        } else {
            auto pixelmap = PixelMap::Create(colors, context->colorsBufferSize, context->opts);
            context->rPixelMap = std::move(pixelmap);
        }
    }
    if (IMG_NOT_NULL(context->rPixelMap)) {
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
}

void PixelMapNapi::CreatePixelMapComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        IMAGE_LOGE("CreatePixelMapComplete invalid parameter: data is null");
        return;
    }

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
    if (data == nullptr) {
        IMAGE_LOGE("CreatePremultipliedPixelMapExec invalid parameter: data is null");
        return;
    }

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
    if (data == nullptr) {
        IMAGE_LOGE("CreateUnpremultipliedPixelMapExec invalid parameter: data is null");
        return;
    }

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

napi_value PixelMapNapi::CreatePremultipliedPixelMap(napi_env env, napi_callback_info info)
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
        asyncContext->rPixelMap = GetPixelMap(env, argValue[NUM_0]);
        asyncContext->wPixelMap = GetPixelMap(env, argValue[NUM_1]);
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
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_IMAGE_GET_DATA_ABNORMAL),
        result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreatePremultipliedPixelMap",
        CreatePremultipliedPixelMapExec, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
}

napi_value PixelMapNapi::CreateUnpremultipliedPixelMap(napi_env env, napi_callback_info info)
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
        asyncContext->rPixelMap = GetPixelMap(env, argValue[NUM_0]);
        asyncContext->wPixelMap = GetPixelMap(env, argValue[NUM_1]);
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
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_IMAGE_GET_DATA_ABNORMAL),
        result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreateUnpremultipliedPixelMap",
        CreateUnpremultipliedPixelMapExec, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
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
    IMAGE_LOGD("CreatePixelMap IN");

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

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreatePixelMap",
        CreatePixelMapExec, CreatePixelMapComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
}

napi_value PixelMapNapi::CreatePixelMapSync(napi_env env, napi_callback_info info)
{
    if (PixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PixelMapNapi::Init(env, exports);
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
    CreatePixelMapExec(env, static_cast<void*>((asyncContext).get()));
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
            status = NewPixelNapiInstance(env, constructor, asyncContext->rPixelMap, result);
    }
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to create pixel map sync"));
    return result;
}

STATIC_EXEC_FUNC(CreatePixelMapUsingAllocator)
{
    if (data == nullptr) {
        IMAGE_LOGE("CreatePixelMapUsingAllocatorExec invalid parameter: data is null");
        return;
    }

    auto context = static_cast<PixelMapAsyncContext*>(data);
    auto colors = static_cast<uint32_t*>(context->colorsBuffer);
    if (colors == nullptr) {
        auto pixelmap = PixelMap::Create(context->opts);
        context->rPixelMap = std::move(pixelmap);
    } else {
        Media::ImageInfo info;
        info.size = context->opts.size;
        info.pixelFormat = context->opts.srcPixelFormat;
        int32_t bufferSize = Media::ImageUtils::GetByteCount(info);
        if (bufferSize <= 0 || context->colorsBufferSize < static_cast<size_t>(bufferSize)) {
            IMAGE_LOGE("invalid parameter: buffer size %{public}zu is less than required buffer size %{public}d",
            context->colorsBufferSize, bufferSize);
            context->status = ERR_MEDIA_UNSUPPORT_OPERATION;
        } else {
            auto pixelmap = PixelMap::Create(colors, context->colorsBufferSize, context->opts);
            context->rPixelMap = std::move(pixelmap);
        }
    }
    if (IMG_NOT_NULL(context->rPixelMap)) {
        context->status = SUCCESS;
    } else {
        context->status = ERR_MEDIA_UNSUPPORT_OPERATION;
    }
}

void PixelMapNapi::CreatePixelMapUsingAllocatorComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        IMAGE_LOGE("CreatePixelMapComplete invalid parameter: data is null");
        return;
    }

    napi_value constructor = nullptr;
    napi_value result = nullptr;

    IMAGE_LOGD("CreatePixelMapComplete IN");
    auto context = static_cast<PixelMapAsyncContext*>(data);

    status = napi_get_reference_value(env, sConstructor_, &constructor);

    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, context->rPixelMap, result);
    }

    if (!IMG_IS_OK(status)) {
        context->status = ERR_MEDIA_UNSUPPORT_OPERATION;
        IMAGE_LOGE("New instance could not be obtained");
        napi_get_undefined(env, &result);
    }

    CommonCallbackRoutine(env, context, result);
}

static bool UsingAllocatorFormatCheck(napi_env env, napi_value value, bool isSupportYUV10Bit = false)
{
    uint32_t tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(value, "pixelFormat", tmpNumber)) {
        IMAGE_LOGD("no pixelFormat in initialization options");
    }
    if (tmpNumber <= static_cast<uint32_t>(PixelFormat::UNKNOWN) ||
        tmpNumber >= static_cast<uint32_t>(PixelFormat::EXTERNAL_MAX)) {
        IMAGE_LOGE("pixelFormat:%{public}d not support", tmpNumber);
        return false;
    }
    if (!isSupportYUV10Bit &&
        (tmpNumber == static_cast<uint32_t>(PixelFormat::YCBCR_P010) ||
        tmpNumber == static_cast<uint32_t>(PixelFormat::YCRCB_P010))) {
        IMAGE_LOGE("pixelFormat:%{public}d not support", tmpNumber);
        return false;
    }
    if (!GET_UINT32_BY_NAME(value, "srcPixelFormat", tmpNumber)) {
        IMAGE_LOGD("no srcPixelFormat in initialization options");
    }
    if (tmpNumber <= static_cast<uint32_t>(PixelFormat::UNKNOWN) ||
        tmpNumber >= static_cast<uint32_t>(PixelFormat::EXTERNAL_MAX)) {
        IMAGE_LOGE("srcPixelFormat:%{public}d not support", tmpNumber);
        return false;
    }
    if (!isSupportYUV10Bit &&
        (tmpNumber == static_cast<uint32_t>(PixelFormat::YCBCR_P010) ||
        tmpNumber == static_cast<uint32_t>(PixelFormat::YCRCB_P010))) {
        IMAGE_LOGE("pixelFormat:%{public}d not support", tmpNumber);
        return false;
    }
    return true;
}

napi_value PixelMapNapi::CreatePixelMapUsingAllocator(napi_env env, napi_callback_info info)
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
    napi_value argValue[NUM_3] = {0};
    size_t argCount = NUM_3;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_get_arraybuffer_info(env, argValue[NUM_0], &(asyncContext->colorsBuffer),
        &(asyncContext->colorsBufferSize));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        ImageNapiUtils::ThrowExceptionError(env,
        ERR_MEDIA_UNSUPPORT_OPERATION, "napi_get_arraybuffer_info failed."),
        IMAGE_LOGE("colors mismatch"));
    IMG_NAPI_CHECK_RET_D(UsingAllocatorFormatCheck(env, argValue[1]) &&
        parseInitializationOptions(env, argValue[1], &(asyncContext->opts)),
        ImageNapiUtils::ThrowExceptionError(env,
        ERR_MEDIA_UNSUPPORT_OPERATION, "parseInitializationOptions failed."),
        IMAGE_LOGE("InitializationOptions mismatch"));

    int32_t allocatorType = 0;
    if (argCount == NUM_3) {
        if (ImageNapiUtils::getType(env, argValue[NUM_2]) == napi_number) {
            napi_get_value_int32(env, argValue[NUM_2], &allocatorType);
        } else {
            return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION,
                "AllocatorType type does not match.");
        }
    }
    if (!ImageUtils::SetInitializationOptionAllocatorType(asyncContext->opts, allocatorType)) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION,
            "Unsupported allocator type.");
    }
    IMAGE_LOGD("%{public}s %{public}d,%{public}d.", __func__, allocatorType, asyncContext->opts.allocatorType);
    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreatePixelMap", CreatePixelMapUsingAllocatorExec,
        CreatePixelMapUsingAllocatorComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
}

static bool GetAllocatValue(napi_env &env, napi_value argValue[], size_t argCount,
    std::unique_ptr<PixelMapAsyncContext> &asyncContext, int32_t &allocatorType)
{
    IMAGE_LOGD("GetAllocatValue argCount:%{public}zu", argCount);
    if (argValue == nullptr) {
        return false;
    }
    napi_status status = napi_get_arraybuffer_info(env, argValue[NUM_0], &(asyncContext->colorsBuffer),
        &(asyncContext->colorsBufferSize));
    if (IMG_IS_OK(status)) {
        if (!UsingAllocatorFormatCheck(env, argValue[NUM_1])) {
            return false;
        }
        if (!parseInitializationOptions(env, argValue[NUM_1], &(asyncContext->opts))) {
            IMAGE_LOGE("parseInitializationOptions failed");
            return false;
        }
        if (argCount == NUM_2) {
            return true;
        }
        if (ImageNapiUtils::getType(env, argValue[NUM_2]) == napi_number) {
            napi_get_value_int32(env, argValue[NUM_2], &allocatorType);
        } else {
            IMAGE_LOGE("get allocatorType failed");
            return false;
        }
    } else {
        if (!UsingAllocatorFormatCheck(env, argValue[0], true)) {
            return false;
        }
        if (!parseInitializationOptions(env, argValue[0], &(asyncContext->opts))) {
            IMAGE_LOGE("parseInitializationOptions failed");
            return false;
        }
        if (argCount == NUM_1) {
            return true;
        }
        if (ImageNapiUtils::getType(env, argValue[NUM_1]) == napi_number) {
            napi_get_value_int32(env, argValue[NUM_1], &allocatorType);
        } else {
            IMAGE_LOGE("get allocatorType failed");
            return false;
        }
    }
    return true;
}

napi_value PixelMapNapi::CreatePixelMapUsingAllocatorSync(napi_env env, napi_callback_info info)
{
    if (PixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PixelMapNapi::Init(env, exports);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value constructor = nullptr;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_3] = {0};
    size_t argCount = NUM_3;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_2 || argCount == NUM_1 || argCount == NUM_3,
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION,
        "Invalid args count"),
        IMAGE_LOGE("Invalid args count %{public}zu", argCount));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    int32_t allocatorType = 0;
    if (!GetAllocatValue(env, argValue, argCount, asyncContext, allocatorType)) {
        return ImageNapiUtils::ThrowExceptionError(env,
            ERR_MEDIA_UNSUPPORT_OPERATION, "AllocatorType type does not match.");
    }
    IMAGE_LOGD("%{public}s %{public}d,%{public}d.", __func__, allocatorType, asyncContext->opts.allocatorType);
    if (!ImageUtils::SetInitializationOptionAllocatorType(asyncContext->opts, allocatorType)) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION,
            "Unsupported allocator type.");
    }
    CreatePixelMapUsingAllocatorExec(env, static_cast<void*>((asyncContext).get()));
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
            status = NewPixelNapiInstance(env, constructor, asyncContext->rPixelMap, result);
    }
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to create pixel map sync"));
    return result;
}

static bool DealSurfaceId(std::string &surfaceId, unsigned long &id)
{
    if (surfaceId.find_first_not_of("0123456789") != std::string::npos) {
        IMAGE_LOGE("The input string contains non-decimal characters.");
    }
    auto res = std::from_chars(surfaceId.c_str(), surfaceId.c_str() + surfaceId.size(), id);
    if (res.ec != std::errc()) {
        return true;
    } else if (res.ec == std::errc::invalid_argument) {
        IMAGE_LOGE("Invalid argument: the input string is not a valid number.");
    return false;
    } else if (res.ec == std::errc::result_out_of_range) {
        IMAGE_LOGE("Out of range: the number is too large or too small for the target type.");
        return false;
    } else {
        IMAGE_LOGE("Unknown error occured during conversion.");
        return false;
    }
}

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static bool GetSurfaceSize(size_t argc, Rect &region, std::string fd)
{
    if (argc == NUM_2 && (region.width <= 0 || region.height <= 0)) {
        IMAGE_LOGE("GetSurfaceSize invalid parameter argc = %{public}zu", argc);
        return false;
    }
    if (region.width <= 0 || region.height <= 0) {
        unsigned long number_fd = 0;
        auto res = std::from_chars(fd.c_str(), fd.c_str() + fd.size(), number_fd);
        if (res.ec != std::errc()) {
            IMAGE_LOGE("GetSurfaceSize invalid fd");
            return false;
        }
        sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(std::stoull(fd));
        if (surface == nullptr) {
            return false;
        }
        sptr<SyncFence> fence = SyncFence::InvalidFence();
        // a 4 * 4 idetity matrix
        float matrix[16] = {
            1, 0, 0, 0,
            0, 1, 0, 0,
            0, 0, 1, 0,
            0, 0, 0, 1
        };
        sptr<SurfaceBuffer> surfaceBuffer = nullptr;
        GSError ret = surface->GetLastFlushedBuffer(surfaceBuffer, fence, matrix);
        if (ret != OHOS::GSERROR_OK || surfaceBuffer == nullptr) {
            IMAGE_LOGE("GetLastFlushedBuffer fail, ret = %{public}d", ret);
            return false;
        }
        region.width = surfaceBuffer->GetWidth();
        region.height = surfaceBuffer->GetHeight();
    }
    return true;
}

static bool GetSurfaceSize(Rect &region, unsigned long fd)
{
    if (region.width <= 0 || region.height <= 0) {
        sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(fd);
        if (surface == nullptr) {
            return false;
        }
        sptr<SyncFence> fence = SyncFence::InvalidFence();
        // a 4 * 4 idetity matrix
        float matrix[16] = {
            1, 0, 0, 0,
            0, 1, 0, 0,
            0, 0, 1, 0,
            0, 0, 0, 1
        };
        sptr<SurfaceBuffer> surfaceBuffer = nullptr;
        GSError ret = surface->GetLastFlushedBuffer(surfaceBuffer, fence, matrix);
        if (ret != OHOS::GSERROR_OK || surfaceBuffer == nullptr) {
            IMAGE_LOGE("GetLastFlushedBuffer fail, ret = %{public}d", ret);
            return false;
        }
        region.width = surfaceBuffer->GetWidth();
        region.height = surfaceBuffer->GetHeight();
    }
    return true;
}
STATIC_EXEC_FUNC(CreatePixelMapFromSurface)
{
    if (data == nullptr) {
        IMAGE_LOGE("CreatePixelMapFromSurfaceExec invalid parameter: data is null");
        return;
    }

    auto context = static_cast<PixelMapAsyncContext*>(data);
    IMAGE_LOGD("CreatePixelMapFromSurface id:%{public}s,area:%{public}d,%{public}d,%{public}d,%{public}d",
        context->surfaceId.c_str(), context->area.region.left, context->area.region.top,
        context->area.region.height, context->area.region.width);
    if (!std::regex_match(context->surfaceId, std::regex("\\d+"))) {
        IMAGE_LOGE("CreatePixelMapFromSurface empty or invalid surfaceId");
        context->status = context->argc == NUM_2 ?
            ERR_IMAGE_INVALID_PARAMETER : COMMON_ERR_INVALID_PARAMETER;
        return;
    }
    if (!GetSurfaceSize(context->argc, context->area.region, context->surfaceId)) {
        context->status = context->argc == NUM_2 ?
            ERR_IMAGE_INVALID_PARAMETER : COMMON_ERR_INVALID_PARAMETER;
        return;
    }
    auto &rsClient = Rosen::RSInterfaces::GetInstance();
    OHOS::Rect r = {.x = context->area.region.left, .y = context->area.region.top,
        .w = context->area.region.width, .h = context->area.region.height, };
    std::shared_ptr<Media::PixelMap> pixelMap =
        rsClient.CreatePixelMapFromSurfaceId(std::stoull(context->surfaceId), r);
#ifndef EXT_PIXEL
    if (pixelMap == nullptr) {
        pixelMap = CreatePixelMapFromSurfaceId(std::stoull(context->surfaceId), context->area.region);
    }
#endif
    context->rPixelMap = std::move(pixelMap);

    if (IMG_NOT_NULL(context->rPixelMap)) {
        context->status = SUCCESS;
    } else {
        context->status = context->argc == NUM_2 ?
            ERR_IMAGE_INVALID_PARAMETER : COMMON_ERR_INVALID_PARAMETER;
    }
}

STATIC_EXEC_FUNC(CreatePixelMapFromSurfaceWithTransformation)
{
    if (data == nullptr) {
        IMAGE_LOGE("CreatePixelMapFromSurfaceWithTransformationExec invalid parameter: data is null");
        return;
    }

    auto context = static_cast<PixelMapAsyncContext*>(data);
    IMAGE_LOGD("CreatePixelMapFromSurface id:%{public}s,area:%{public}d,%{public}d,%{public}d,%{public}d",
        context->surfaceId.c_str(), context->area.region.left, context->area.region.top,
        context->area.region.height, context->area.region.width);
    unsigned long surfaceId = 0;
    if (!DealSurfaceId(context->surfaceId, surfaceId)) {
        context->status = ERR_IMAGE_INVALID_PARAM;
        return;
    }
    if (!GetSurfaceSize(context->area.region, surfaceId)) {
        context->status = ERR_IMAGE_GET_IMAGE_DATA_FAILED;
        return;
    }
    auto &rsClient = Rosen::RSInterfaces::GetInstance();
    OHOS::Rect r = {.x = context->area.region.left, .y = context->area.region.top,
        .w = context->area.region.width, .h = context->area.region.height, };
    std::shared_ptr<Media::PixelMap> pixelMap = rsClient.CreatePixelMapFromSurfaceId(surfaceId,
        r, context->transformEnabled);
    ImageUtils::DumpPixelMap(pixelMap.get(), "CreatePixelMapFromSurfaceWithTransformation");
#ifndef EXT_PIXEL
    if (pixelMap == nullptr) {
        pixelMap = CreatePixelMapFromSurfaceId(surfaceId, context->area.region);
    }
#endif
    context->rPixelMap = std::move(pixelMap);

    if (IMG_NOT_NULL(context->rPixelMap)) {
        context->status = SUCCESS;
    } else {
        context->status = ERR_IMAGE_CREATE_PIXELMAP_FAILED;
    }
}

void PixelMapNapi::CreatePixelMapFromSurfaceComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        IMAGE_LOGE("CreatePixelMapFromSurfaceComplete invalid parameter: data is null");
        return;
    }

    napi_value constructor = nullptr;
    napi_value result = nullptr;

    IMAGE_LOGD("CreatePixelMapFromSurface IN");
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

static bool ParseSurfaceRegion(napi_env env, napi_value root, size_t argCount, Rect* region)
{
    if (argCount == NUM_2) {
        IMAGE_LOGD("ParseSurfaceRegion IN");
        return parseRegion(env, root, region);
    }
    return true;
}
#endif

void RegisterArkEngine(napi_env env)
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
}
napi_value PixelMapNapi::CreatePixelMapFromSurface(napi_env env, napi_callback_info info)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    napi_value result = nullptr;
    return result;
#else
    RegisterArkEngine(env);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_4] = {0};
    size_t argCount = NUM_4;
    IMAGE_LOGD("CreatePixelMapFromSurface IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_2 || argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Invalid args count"),
        IMAGE_LOGE("CreatePixelMapFromSurface Invalid args count %{public}zu", argCount));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    asyncContext->surfaceId = GetStringArgument(env, argValue[NUM_0]);
    bool ret = ParseSurfaceRegion(env, argValue[NUM_1], argCount, &(asyncContext->area.region));
    asyncContext->argc = argCount;
    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_NAPI_CHECK_BUILD_ERROR(ret,
        BuildContextError(env, asyncContext->error, "image invalid parameter", ERR_IMAGE_GET_DATA_ABNORMAL),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_IMAGE_GET_DATA_ABNORMAL),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreatePixelMapFromSurface",
        CreatePixelMapFromSurfaceExec, CreatePixelMapFromSurfaceComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
#endif
}

napi_value PixelMapNapi::CreatePixelMapFromSurfaceWithTransformation(napi_env env,
    napi_callback_info info)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_GET_IMAGE_DATA_FAILED,
        "Unsupported operation on cross-platform");
#else
    RegisterArkEngine(env);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_3] = {0};
    size_t argCount = NUM_3;
    IMAGE_LOGD("CreatePixelMapFromSurfaceWithTransformation IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_2,
        ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_INVALID_PARAM, "Invalid args count"),
        IMAGE_LOGE("CreatePixelMapFromSurfaceWithTransformation Invalid args count %{public}zu", argCount));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    asyncContext->surfaceId = GetStringArgument(env, argValue[NUM_0]);
    bool transformEnabled = false;
    NAPI_ASSERT(env, napi_get_value_bool(env, argValue[NUM_1], &transformEnabled) == napi_ok,
        "Parse input error");
    asyncContext->transformEnabled = transformEnabled;
    asyncContext->argc = argCount;
    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreatePixelMapFromSurfaceWithTransformation",
        CreatePixelMapFromSurfaceWithTransformationExec, CreatePixelMapFromSurfaceComplete,
        asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_CREATE_PIXELMAP_FAILED,
            "Failed to create async work"), {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
#endif
}

napi_value PixelMapNapi::CreatePixelMapFromSurfaceSync(napi_env env, napi_callback_info info)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    napi_value result = nullptr;
    return result;
#else
    if (PixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PixelMapNapi::Init(env, exports);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value constructor = nullptr;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;
    IMAGE_LOGD("CreatePixelMapFromSurfaceSync IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_GET_DATA_ABNORMAL,
        "Failed to get data"),
        IMAGE_LOGE("CreatePixelMapFromSurfaceSync fail to get data"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_2 || argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Invalid args count"),
        IMAGE_LOGE("CreatePixelMapFromSurfaceSync Invalid args count %{public}zu", argCount));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    asyncContext->surfaceId = GetStringArgument(env, argValue[NUM_0]);
    bool ret = ParseSurfaceRegion(env, argValue[NUM_1], argCount, &(asyncContext->area.region));
    IMG_NAPI_CHECK_RET_D(ret,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"),
        IMAGE_LOGE("CreatePixelMapFromSurfaceSync invalid args count"));
    asyncContext->argc = argCount;
    CreatePixelMapFromSurfaceExec(env, static_cast<void*>((asyncContext).get()));
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
            status = NewPixelNapiInstance(env, constructor, asyncContext->rPixelMap, result);
    }
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_PIXELMAP_CREATE_FAILED,
        "Failed to create pixelmap"),
        IMAGE_LOGE("CreatePixelMapFromSurfaceSync fail to create pixel map sync"));
    return result;
#endif
}

napi_value PixelMapNapi::CreatePixelMapFromSurfaceWithTransformationSync(napi_env env,
    napi_callback_info info)
{
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_GET_IMAGE_DATA_FAILED,
        "Unsupported operation on cross-platform");
#else
    if (PixelMapNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PixelMapNapi::Init(env, exports);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value constructor = nullptr;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;
    IMAGE_LOGD("CreatePixelMapFromSurfaceWithTransformationSync IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_GET_DATA_ABNORMAL,
        "Failed to get data"),
        IMAGE_LOGE("CreatePixelMapFromSurfaceWithTransformationSync fail to get data"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_2,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Invalid args count"),
        IMAGE_LOGE("CreatePixelMapFromSurfaceWithTransformationSync Invalid args count %{public}zu", argCount));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    asyncContext->surfaceId = GetStringArgument(env, argValue[NUM_0]);
    bool transformEnabled = false;
    NAPI_ASSERT(env, napi_get_value_bool(env, argValue[NUM_1], &transformEnabled) == napi_ok,
        "Parse input error");
    asyncContext->transformEnabled = transformEnabled;
    asyncContext->argc = argCount;
    CreatePixelMapFromSurfaceWithTransformationExec(env, static_cast<void*>((asyncContext).get()));
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        status = NewPixelNapiInstance(env, constructor, asyncContext->rPixelMap, result);
    }
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_CREATE_PIXELMAP_FAILED, "Failed to create pixelmap"),
        IMAGE_LOGE("CreatePixelMapFromSurfaceWithTransformationSync fail to create pixel map sync"));
    return result;
#endif
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

extern "C" {
napi_value GetPixelMapNapi(napi_env env, std::shared_ptr<PixelMap> pixelMap)
{
    return PixelMapNapi::CreatePixelMap(env, pixelMap);
}

bool GetNativePixelMap(void* pixelMapNapi, std::shared_ptr<PixelMap> &pixelMap)
{
    if (pixelMapNapi == nullptr) {
        IMAGE_LOGE("%{public}s pixelMapNapi is nullptr", __func__);
        return false;
    }
    pixelMap = reinterpret_cast<PixelMapNapi*>(pixelMapNapi)->GetPixelNapiInner();
    return true;
}
}

STATIC_EXEC_FUNC(Unmarshalling)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (data == nullptr) {
        IMAGE_LOGE("UnmarshallingExec invalid parameter: data is null");
        return;
    }
    auto context = static_cast<PixelMapAsyncContext*>(data);

    if (!napi_messageSequence) {
        context->status = ERROR;
        IMAGE_LOGE("UnmarshallingExec invalid parameter: napi_messageSequence is null");
        return;
    }
    auto messageParcel = napi_messageSequence->GetMessageParcel();
    if (!messageParcel) {
        context->status = ERROR;
        IMAGE_LOGE("UnmarshallingExec invalid parameter: messageParcel is null");
        return;
    }
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
    if (data == nullptr) {
        IMAGE_LOGE("UnmarshallingComplete invalid parameter: data is null");
        return;
    }

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

napi_value PixelMapNapi::Unmarshalling(napi_env env, napi_callback_info info)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
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

    napi_unwrap(env, argValue[NUM_0], (void **)&napi_messageSequence);

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "Unmarshalling",
        UnmarshallingExec, UnmarshallingComplete, asyncContext, asyncContext->work);

    if (!IMG_IS_OK(status)) {
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
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
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
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
    IMAGE_LOGD("CreatePixelMapFromParcel IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    if (!IMG_IS_OK(status) || argCount != NUM_1) {
        return PixelMapNapi::ThrowExceptionError(env,
            CREATE_PIXEL_MAP_FROM_PARCEL, ERR_IMAGE_INVALID_PARAMETER, "Fail to napi_get_cb_info");
    }
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    napi_unwrap(env, argValue[NUM_0], (void **)&napi_messageSequence);
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, napi_messageSequence), result, IMAGE_LOGE("fail to unwrap context"));
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
        IMAGE_LOGE("New instance could not be obtained");
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
    IMAGE_LOGD("GetIsEditable IN");

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));

    if (pixelMapNapi->nativePixelMap_ == nullptr) {
        return result;
    }
    bool isEditable = pixelMapNapi->nativePixelMap_->IsEditable();

    napi_get_boolean(env, isEditable, &result);

    return result;
}

napi_value PixelMapNapi::GetNativeUniqueId(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;
    IMAGE_LOGD("GetUniqueId IN");

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION,
        "Pixelmap has crossed threads. GetUniqueId failed"), {});
    if (pixelMapNapi->nativePixelMap_ == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "native pixelmap is nullptr");
    }
    int32_t id = static_cast<int32_t>(pixelMapNapi->nativePixelMap_->GetUniqueId());

    napi_create_int32(env, id, &result);
    return result;
}

napi_value PixelMapNapi::IsReleased(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;
    IMAGE_LOGD("IsReleased IN");

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));

    IMAGE_LOGD("Native PixelMap use count is %{public}ld", pixelMapNapi->nativePixelMap_.use_count());
    bool isReleased = pixelMapNapi->nativePixelMap_ == nullptr || pixelMapNapi->nativePixelMap_.use_count() == 0;
    napi_get_boolean(env, isReleased, &result);

    return result;
}

static napi_value BuildClonePixelMapError(napi_env& env, int32_t errorCode)
{
    if (errorCode == ERR_IMAGE_INIT_ABNORMAL) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_MEMORY_ALLOC_FAILED,
            "Initial a empty pixelmap failed");
    }
    if (errorCode == ERR_IMAGE_MALLOC_ABNORMAL) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_MEMORY_ALLOC_FAILED,
            "Clone pixelmap data failed");
    }
    if (errorCode == ERR_IMAGE_DATA_UNSUPPORT) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORTED_MEMORY_FORMAT,
            "PixelMap type does not support clone");
    }
    if (errorCode == ERR_IMAGE_TOO_LARGE) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_MEMORY_ALLOC_FAILED,
            "PixelMap Size (byte count) out of range");
    }
    return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_MEMORY_ALLOC_FAILED, "Clone PixelMap failed");
}

napi_value PixelMapNapi::CreateCroppedAndScaledPixelMapSync(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_4;
    napi_value argValue[NUM_4] = {0};
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi),
        nullptr, IMAGE_LOGE("fail to unwrap context %{public}d", status));

    IMG_NAPI_CHECK_RET_D(pixelMapNapi->nativePixelMap_ != nullptr,
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "native pixelmap has released"), {});

    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION,
        "Pixelmap has crossed threads. CreateCroppedAndScaledPixelMapSync failed"), {});

    IMG_NAPI_CHECK_RET_D((argCount == NUM_3 || argCount == NUM_4),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "Invalid argument count"),
        IMAGE_LOGE("%{public}s Invalid argument count", __func__));

    Rect region;
    double xArg = 0;
    double yArg = 0;
    int32_t antiAliasing = 0;
    IMG_NAPI_CHECK_RET_D(parseRegion(env, argValue[NUM_0], &region),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_INVALID_REGION, "Invalid argument region type"), {});
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_double(env, argValue[NUM_1], &xArg)),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "Invalid argument x"), {});
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_double(env, argValue[NUM_2], &yArg)),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "Invalid argument y"), {});
    if (argCount == NUM_4) {
        IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_int32(env, argValue[NUM_3], &antiAliasing)),
            ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "Invalid antiAliasing"), {});
        IMG_NAPI_CHECK_RET_D(antiAliasing >= static_cast<int32_t>(NUM_0) && antiAliasing <= static_cast<int32_t>(NUM_3),
            ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "Not support antiAliasing"), {});
    }
    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        int32_t errorCode = 0;
        auto clonePixelMap = pixelMapNapi->nativePixelMap_->Clone(errorCode);
        if (clonePixelMap == nullptr) {
            return BuildClonePixelMapError(env, errorCode);
        }
        IMG_NAPI_CHECK_RET_D(SUCCESS == clonePixelMap->crop(region), ImageNapiUtils::ThrowExceptionError(env,
            ERR_MEDIA_INVALID_REGION, "Crop failed, region or properties invalid"), {});
        clonePixelMap->scale(xArg, yArg, ParseAntiAliasingOption(antiAliasing));
        result = PixelMapNapi::CreatePixelMap(env, std::move(clonePixelMap));
    }
    return result;
}

STATIC_EXEC_FUNC(CreateCropAndScalePixelMap)
{
    if (data == nullptr) {
        IMAGE_LOGE("CreateCropAndScalePixelMapExec invalid parameter: data is null");
        return;
    }
    auto context = static_cast<PixelMapAsyncContext*>(data);
    std::shared_ptr<PixelMap> pixelMap = context->wPixelMap;
    if (pixelMap != nullptr) {
        int32_t errorCode = SUCCESS;
        auto clonePixelMap = pixelMap->Clone(errorCode);
        if (clonePixelMap == nullptr || errorCode != SUCCESS) {
            context->status = static_cast<uint32_t>(errorCode);
            context->resultUint32 = NUM_1;
            return;
        }
        uint32_t ret = clonePixelMap->crop(context->area.region);
        if (ret != SUCCESS) {
            context->status = ret;
            context->resultUint32 = NUM_2;
            return;
        }
        clonePixelMap->scale(context->xArg, context->yArg, context->antiAliasing);
        context->rPixelMap = std::move(clonePixelMap);
    }
}

STATIC_COMPLETE_FUNC(CreateCropAndScalePixelMap)
{
    auto context = static_cast<PixelMapAsyncContext*>(data);
    if (context == nullptr) {
        return;
    }
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
    if (context->status == SUCCESS) {
        napi_value value = nullptr;
        napi_get_undefined(env, &value);
        value = PixelMapNapi::CreatePixelMap(env, context->rPixelMap);
        if (value == nullptr) {
            context->status = ERR_MEDIA_UNSUPPORT_OPERATION;
            ImageNapiUtils::CreateErrorObj(env, result[NUM_0], context->status, "napi pixelmap create failed");
        }
        result[NUM_1] = value;
    } else {
        if (context->resultUint32 == NUM_1) {
            context->status = context->status == ERR_IMAGE_DATA_UNSUPPORT ?
                ERR_MEDIA_UNSUPPORTED_MEMORY_FORMAT : ERR_MEDIA_MEMORY_ALLOC_FAILED;
            ImageNapiUtils::CreateErrorObj(env, result[NUM_0], context->status, "pixelMap clone failed");
        } else {
            ImageNapiUtils::CreateErrorObj(env, result[NUM_0], ERR_MEDIA_INVALID_REGION,
                "Crop failed, region or properties invalid");
        }
    }
    if (context->deferred) {
        if (context->status == SUCCESS) {
            napi_resolve_deferred(env, context->deferred, result[NUM_1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[NUM_0]);
        }
    } else {
        napi_get_reference_value(env, context->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, NUM_2, result, &retVal);
        NAPI_CHECK_AND_DELETE_REF(env, context->callbackRef);
    }
    napi_delete_async_work(env, context->work);
    napi_close_handle_scope(env, scope);
    delete context;
    context = nullptr;
}

napi_value PixelMapNapi::CreateCroppedAndScaledPixelMap(napi_env env, napi_callback_info info)
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
    size_t argCount = NUM_4;
    napi_value argValue[NUM_4] = {0};
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("fail to unwrap context %{public}d", status));
    IMG_NAPI_CHECK_RET_D(asyncContext->nConstructor->nativePixelMap_ != nullptr,
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "native pixelmap has released"), {});
    asyncContext->wPixelMap = asyncContext->nConstructor->nativePixelMap_;
    IMG_NAPI_CHECK_RET_D(asyncContext->nConstructor->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION,
        "Pixelmap has crossed threads. CreateCroppedAndScaledPixelMap failed"), {});

    IMG_NAPI_CHECK_RET_D((argCount == NUM_3 || argCount == NUM_4),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "Invalid argument count"),
        IMAGE_LOGE("%{public}s Invalid argument count", __func__));
    int32_t antiAliasing = 0;
    asyncContext->antiAliasing = AntiAliasingOption::NONE;
    IMG_NAPI_CHECK_RET_D(parseRegion(env, argValue[NUM_0], &(asyncContext->area.region)),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_INVALID_REGION, "Invalid argument region type"), {});

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_double(env, argValue[NUM_1], &(asyncContext->xArg))),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "Invalid argument x"), {});

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_double(env, argValue[NUM_2], &(asyncContext->yArg))),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "Invalid argument y"), {});
    if (argCount == NUM_4) {
        IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_int32(env, argValue[NUM_3], &antiAliasing)),
            ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "Invalid antiAliasing"), {});
        IMG_NAPI_CHECK_RET_D(antiAliasing >= static_cast<int32_t>(NUM_0) && antiAliasing <= static_cast<int32_t>(NUM_3),
            ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNSUPPORT_OPERATION, "Not support antiAliasing"), {});
        asyncContext->antiAliasing = ParseAntiAliasingOption(antiAliasing);
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreateCropAndScalePixelMap", CreateCropAndScalePixelMapExec,
        CreateCropAndScalePixelMapComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
}

napi_value PixelMapNapi::GetIsStrideAlignment(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;
    IMAGE_LOGD("GetIsStrideAlignment IN");

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi),
        result, IMAGE_LOGE("fail to unwrap context"));

    if (pixelMapNapi->nativePixelMap_ == nullptr) {
        return result;
    }
    bool isDMA = pixelMapNapi->nativePixelMap_->IsStrideAlignment();
    napi_get_boolean(env, isDMA, &result);
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

    IMAGE_LOGD("ReadPixelsToBuffer IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK_WITH_QOS(env, status, "ReadPixelsToBuffer",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            context->status = context->rPixelMap->ReadPixels(
                context->colorsBufferSize, static_cast<uint8_t*>(context->colorsBuffer));
        }, EmptyResultComplete, asyncContext, asyncContext->work, napi_qos_user_initiated);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
}

napi_value PixelMapNapi::ReadPixelsToBufferSync(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("PixelMapNapi::ReadPixelsToBufferSync");
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

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
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

    IMAGE_LOGD("ReadPixels IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("fail to unwrap context"));

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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "ReadPixels",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            auto area = context->area;
            context->status = context->rPixelMap->ReadPixels(
                area.size, area.offset, area.stride, area.region, static_cast<uint8_t*>(area.pixels));
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
}

napi_value PixelMapNapi::ReadPixelsSync(napi_env env, napi_callback_info info)
{
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

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . ReadPixelsToBuffeSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . ReadPixelsToBuffeSync failed"));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi->nativePixelMap_),
        nullptr, IMAGE_LOGE("empty native pixelmap"));

    auto nativeStatus = pixelMapNapi->nativePixelMap_->ReadPixels(
        area.size, area.offset, area.stride, area.region, static_cast<uint8_t*>(area.pixels));

    IMG_NAPI_CHECK_RET_D(nativeStatus == SUCCESS,
        nullptr, IMAGE_LOGE("fail to read pixels"));
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

    IMAGE_LOGD("WritePixels IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "WritePixels",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            auto area = context->area;
            context->status = context->rPixelMap->WritePixels(
                static_cast<uint8_t*>(area.pixels), area.size, area.offset, area.stride, area.region);
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
}

napi_value PixelMapNapi::WritePixelsSync(napi_env env, napi_callback_info info)
{
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

    PixelMapNapi* pixelMapNapi = nullptr;
    napiStatus = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
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

    IMAGE_LOGD("WriteBufferToPixels IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "WriteBufferToPixels",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            context->status = context->rPixelMap->WritePixels(static_cast<uint8_t*>(context->colorsBuffer),
                context->colorsBufferSize);
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
}

napi_value PixelMapNapi::WriteBufferToPixelsSync(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("PixelMapNapi::WriteBufferToPixelsSync");
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

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
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
    return result;
}

STATIC_NAPI_VALUE_FUNC(GetImageInfo)
{
    if (data == nullptr) {
        IMAGE_LOGE("GetImageInfoNapiValue invalid parameter: data is null");
        return nullptr;
    }

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
napi_value PixelMapNapi::GetImageInfo(napi_env env, napi_callback_info info)
{
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
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetImageInfo",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            context->rPixelMap->GetImageInfo(context->imageInfo);
            context->status = SUCCESS;
        }, GetImageInfoComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
}

napi_value PixelMapNapi::GetImageInfoSync(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;

    IMAGE_LOGD("GetImageInfoSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to arg info"));

    PixelMapNapi* pixelMapNapi = nullptr;
    napiStatus = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
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

    IMAGE_LOGD("GetBytesNumberPerRow IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
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

    IMAGE_LOGD("GetPixelBytesNumber IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
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
    return result;
}

napi_value PixelMapNapi::IsSupportAlpha(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;

    IMAGE_LOGD("IsSupportAlpha IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
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

    IMAGE_LOGD("SetAlphaAble IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    NAPI_ASSERT(env, argCount > NUM_0, "Invalid input");
    NAPI_ASSERT(env, ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_boolean, "Invalid input type");
    NAPI_ASSERT(env, napi_get_value_bool(env, argValue[NUM_0], &isAlphaAble) == napi_ok, "Parse input error");

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
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
    return result;
}

static void CreateAlphaPixelmapComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        IMAGE_LOGE("CreateAlphaPixelmapComplete invalid parameter: data is null");
        return;
    }

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
    IMAGE_LOGD("CreateAlphaPixelmap IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
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
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, {
        IMAGE_LOGE("fail to create async work");
        NAPI_CHECK_AND_DELETE_REF(env, asyncContext->callbackRef);
    });
    return result;
}

napi_value PixelMapNapi::CreateAlphaPixelmapSync(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    uint32_t status = SUCCESS;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;

    IMAGE_LOGD("CreateAlphaPixelmapSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_0,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "CreateAlphaPixelmapSync failed"),
        IMAGE_LOGE("CreateAlphaPixelmapSync failed, invalid parameter"));

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . CreateAlphaPixelmapSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . CreateAlphaPixelmapSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        InitializationOptions opts;
        opts.pixelFormat = PixelFormat::ALPHA_8;
        auto tmpPixelMap = PixelMap::Create(*(pixelMapNapi->nativePixelMap_), opts);
        result = PixelMapNapi::CreatePixelMap(env, std::move(tmpPixelMap));
    } else {
        IMAGE_LOGE("Null native ref");
    }
    return result;
}

napi_value PixelMapNapi::GetDensity(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;

    IMAGE_LOGD("GetDensity IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . GetDensity failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . GetDensity failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        uint32_t baseDensity = static_cast<uint32_t>(pixelMapNapi->nativePixelMap_->GetBaseDensity());
        status = napi_create_int32(env, baseDensity, &result);
        if (!IMG_IS_OK(status)) {
            IMAGE_LOGE("napi_create_int32 failed!");
        }
    } else {
        IMAGE_LOGE("native pixelmap is nullptr!");
    }
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

    IMAGE_LOGD("SetDensity IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    NAPI_ASSERT(env,
        (argCount == NUM_1 && ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_number),
        "Density input mismatch");
    NAPI_ASSERT(env, napi_get_value_uint32(env, argValue[NUM_0], &density) == napi_ok, "Could not parse density");

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . SetDensity failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . SetDensity failed"));
    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        ImageInfo imageinfo;
        pixelMapNapi->nativePixelMap_->GetImageInfo(imageinfo);
        imageinfo.baseDensity = static_cast<int32_t>(density);
        pixelMapNapi->nativePixelMap_->SetImageInfo(imageinfo, true);
    } else {
        IMAGE_LOGE("native pixelmap is nullptr!");
    }
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

    IMAGE_LOGD("Release IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("fail to unwrap context"));

    if (argCount == 1 && ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
        napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    if (asyncContext->nConstructor->IsLockPixelMap() ||
        (asyncContext->nConstructor->nativePixelMap_ && !asyncContext->nConstructor->nativePixelMap_->IsModifiable())) {
        IMAGE_LOGE("[PixelMap] Release failed: Unable to release the PixelMap because it's locked or unmodifiable");
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
    uint32_t resultCode = asyncContext->status;
    NapiSendEvent(env, asyncContext.release(), napi_eprio_high, resultCode);
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
    if (nVal == nullptr) {
        IMAGE_LOGE("prepareNapiEnv invalid parameter: nVal is null");
        return false;
    }

    napi_get_undefined(env, &(nVal->result));
    nVal->status = napi_get_cb_info(env, info, &(nVal->argc), nVal->argv, &(nVal->thisVar), nullptr);
    if (nVal->status != napi_ok) {
        IMAGE_LOGE("fail to napi_get_cb_info");
        return false;
    }
    nVal->context = std::make_unique<PixelMapAsyncContext>();
    nVal->status = napi_unwrap(env, nVal->thisVar, reinterpret_cast<void**>(&(nVal->context->nConstructor)));
    if (nVal->status != napi_ok) {
        IMAGE_LOGE("fail to unwrap context");
        return false;
    }
    if (nVal->context->nConstructor == nullptr ||
        nVal->context->nConstructor->GetPixelNapiInner() == nullptr) {
        IMAGE_LOGE("prepareNapiEnv pixelmap is nullptr");
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

napi_value PixelMapNapi::SetAlpha(napi_env env, napi_callback_info info)
{
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, nVal.context.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
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
        } else {
            IMAGE_LOGE("fail to create async work");
            NAPI_CHECK_AND_DELETE_REF(env, nVal.context->callbackRef);
        }
    }
    return nVal.result;
}

napi_value PixelMapNapi::SetAlphaSync(napi_env env, napi_callback_info info)
{
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

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
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
            if (context->antiAliasing == AntiAliasingOption::NONE) {
                context->rPixelMap->scale(static_cast<float>(context->xArg), static_cast<float>(context->yArg));
            } else {
                context->rPixelMap->scale(static_cast<float>(context->xArg), static_cast<float>(context->yArg),
                    context->antiAliasing);
            }
            context->status = SUCCESS;
        } else {
            IMAGE_LOGE("Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        IMAGE_LOGD("Scale has failed. do nothing");
    }
}

static void NapiParseCallbackOrAntiAliasing(napi_env &env, NapiValues &nVal, int argi)
{
    if (ImageNapiUtils::getType(env, nVal.argv[argi]) == napi_function) {
        napi_create_reference(env, nVal.argv[argi], nVal.refCount, &(nVal.context->callbackRef));
    } else {
        int32_t antiAliasing;
        if (!IMG_IS_OK(napi_get_value_int32(env, nVal.argv[argi], &antiAliasing))) {
            IMAGE_LOGE("Arg %{public}d type mismatch", argi);
            nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
        }
        nVal.context->antiAliasing = ParseAntiAliasingOption(antiAliasing);
    }
}

napi_value PixelMapNapi::Scale(napi_env env, napi_callback_info info)
{
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
    if (nVal.argc == NUM_3) {
        NapiParseCallbackOrAntiAliasing(env, nVal, NUM_2);
    }

    if (nVal.context->callbackRef == nullptr) {
        napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    }
    IMG_NAPI_CHECK_BUILD_ERROR(nVal.context->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, nVal.context->error, "pixelmap has crossed threads . Scale failed",
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, nVal.context.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
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

napi_value PixelMapNapi::ScaleSync(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    uint32_t status = SUCCESS;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_3;
    napi_value argValue[NUM_3] = {0};
    double xArg = 0;
    double yArg = 0;
    int32_t antiAliasing = 0;
    IMAGE_LOGD("ScaleSync IN");
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to arg info"));

    IMG_NAPI_CHECK_RET_D(argCount == NUM_2 || argCount == NUM_3,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"),
        IMAGE_LOGE("Invalid args count %{public}zu", argCount));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_double(env, argValue[NUM_0], &xArg)),
        result, IMAGE_LOGE("Arg 0 type mismatch"));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_double(env, argValue[NUM_1], &yArg)),
        result, IMAGE_LOGE("Arg 1 type mismatch"));
    if (argCount == NUM_3) {
        IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_int32(env, argValue[NUM_2], &antiAliasing)),
            result, IMAGE_LOGE("Arg 2 type mismatch"));
    }
    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . ScaleSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . ScaleSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        if (antiAliasing == 0) {
            pixelMapNapi->nativePixelMap_->scale(static_cast<float>(xArg), static_cast<float>(yArg));
        } else {
            pixelMapNapi->nativePixelMap_->scale(static_cast<float>(xArg), static_cast<float>(yArg),
                ParseAntiAliasingOption(antiAliasing));
        }
    } else {
        IMAGE_LOGE("Null native ref");
    }
    return result;
}

static void CreateScaledPixelMapExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            InitializationOptions opts;
            std::unique_ptr<PixelMap> clonePixelMap = PixelMap::Create(*(context->rPixelMap), opts);
            if (clonePixelMap == nullptr) {
                IMAGE_LOGE("Null clonePixelMap");
                return;
            }
            if (context->antiAliasing == AntiAliasingOption::NONE) {
                clonePixelMap->scale(static_cast<float>(context->xArg), static_cast<float>(context->yArg));
            } else {
                clonePixelMap->scale(static_cast<float>(context->xArg), static_cast<float>(context->yArg),
                    context->antiAliasing);
            }
            context->alphaMap = std::move(clonePixelMap);
            context->status = SUCCESS;
        } else {
            IMAGE_LOGE("Null native ref");
            context->status = COMMON_ERR_INVALID_PARAMETER;
        }
    } else {
        IMAGE_LOGD("Scale has failed. do nothing");
    }
}

static void CreateScaledPixelMapComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        IMAGE_LOGE("CreateScaledPixelMapComplete invalid parameter: data is null");
        return;
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto context = static_cast<PixelMapAsyncContext*>(data);
    if (context->alphaMap != nullptr) {
        result = PixelMapNapi::CreatePixelMap(env, context->alphaMap);
        context->status = SUCCESS;
    } else {
        IMAGE_LOGE("Null alphaMap");
        context->status = COMMON_ERR_INVALID_PARAMETER;
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value PixelMapNapi::CreateScaledPixelMap(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_3] = {0};
    size_t argCount = NUM_3;
    IMAGE_LOGD("CreateScaledPixelMap IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to arg info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_NAPI_CHECK_BUILD_ERROR(argCount == NUM_2 || argCount == NUM_3,
        BuildContextError(env, asyncContext->error, "Invalid args count",
        COMMON_ERR_INVALID_PARAMETER),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, COMMON_ERR_INVALID_PARAMETER), result);
    IMG_NAPI_CHECK_BUILD_ERROR(IMG_IS_OK(napi_get_value_double(env, argValue[NUM_0], &asyncContext->xArg)),
        BuildContextError(env, asyncContext->error, "Arg 0 type mismatch",
        COMMON_ERR_INVALID_PARAMETER),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, COMMON_ERR_INVALID_PARAMETER), result);
    IMG_NAPI_CHECK_BUILD_ERROR(IMG_IS_OK(napi_get_value_double(env, argValue[NUM_1], &asyncContext->yArg)),
        BuildContextError(env, asyncContext->error, "Arg 1 type mismatch",
        COMMON_ERR_INVALID_PARAMETER),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, COMMON_ERR_INVALID_PARAMETER), result);
    if (argCount == NUM_3) {
        int32_t antiAliasing = 0;
        IMG_NAPI_CHECK_BUILD_ERROR(IMG_IS_OK(napi_get_value_int32(env, argValue[NUM_2], &antiAliasing)),
            BuildContextError(env, asyncContext->error, "Arg 2 type mismatch",
            COMMON_ERR_INVALID_PARAMETER),
            NapiSendEvent(env, asyncContext.release(), napi_eprio_high, COMMON_ERR_INVALID_PARAMETER), result);
        asyncContext->antiAliasing = ParseAntiAliasingOption(antiAliasing);
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap), nullptr, IMAGE_LOGE("empty native pixelmap"));
    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, asyncContext->error, "pixelmap has crossed threads. CreateScaledPixelMap failed",
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE), result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CreateScaledPixelMap",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            CreateScaledPixelMapExec(env, context);
        }, CreateScaledPixelMapComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to create deferred async work"));
    return result;
}

static napi_value CreateScaledPixelMapSyncPrepareArgs(napi_env env, struct NapiValues* nVal)
{
    IMG_NAPI_CHECK_RET_D(nVal->argc == NUM_2 || nVal->argc == NUM_3,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Invalid args count"),
        IMAGE_LOGE("Invalid args count %{public}zu", nVal->argc));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_double(env, nVal->argv[NUM_0], &(nVal->context->xArg))),
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Arg 0 type mismatch"),
        IMAGE_LOGE("Arg 0 type mismatch"));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_double(env, nVal->argv[NUM_1], &(nVal->context->yArg))),
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Arg 1 type mismatch"),
        IMAGE_LOGE("Arg 1 type mismatch"));
    if (nVal->argc == NUM_3) {
        int32_t antiAliasing = 0;
        IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_value_int32(env, nVal->argv[NUM_2], &antiAliasing)),
            ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Arg 2 type mismatch"),
            IMAGE_LOGE("Arg 2 type mismatch"));
        nVal->context->antiAliasing = ParseAntiAliasingOption(antiAliasing);
    }
    IMG_NAPI_CHECK_RET_D(nVal->context->nConstructor->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads. CreateScaledPixelMapSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads. CreateScaledPixelMapSync failed"));
    return nVal->result;
}

napi_value PixelMapNapi::CreateScaledPixelMapSync(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_3;
    napi_value argValue[NUM_3] = {0};
    nVal.argv = argValue;
    IMAGE_LOGD("CreateScaledPixelMapSync IN");
    IMG_NAPI_CHECK_RET_D(prepareNapiEnv(env, info, &nVal),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE, "Fail to unwrap context"),
        IMAGE_LOGE("Fail to unwrap context"));
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;

    CreateScaledPixelMapSyncPrepareArgs(env, &nVal);

    InitializationOptions opts;
    std::unique_ptr<PixelMap> clonePixelMap = PixelMap::Create(*(nVal.context->rPixelMap), opts);
    IMG_NAPI_CHECK_RET_D(clonePixelMap != nullptr,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Null clonePixelMap"),
        IMAGE_LOGE("Null clonePixelMap"));
    if (nVal.context->antiAliasing == AntiAliasingOption::NONE) {
        clonePixelMap->scale(static_cast<float>(nVal.context->xArg), static_cast<float>(nVal.context->yArg));
    } else {
        clonePixelMap->scale(static_cast<float>(nVal.context->xArg), static_cast<float>(nVal.context->yArg),
            nVal.context->antiAliasing);
    }
    nVal.result = PixelMapNapi::CreatePixelMap(env, std::move(clonePixelMap));
    return nVal.result;
}

napi_value PixelMapNapi::SetMemoryNameSync(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
#if defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return result;
#else
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_1;
    napi_value argValue[NUM_1] = {0};
    NapiValues nVal;
    nVal.argc = NUM_1;
    nVal.argv = argValue;
    IMAGE_LOGD("SetName IN");
    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;
    IMG_JS_ARGS(env, info, napiStatus, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napiStatus), result, IMAGE_LOGE("fail to arg info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_1,
        ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"),
        IMAGE_LOGE("Invalid args count %{public}zu", argCount));
    std::string pixelMapName = GetStringArgument(env, argValue[0]);

    PixelMapNapi* pixelMapNapi = nullptr;
    napiStatus = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));

    // corssed threads error
    IMG_NAPI_CHECK_BUILD_ERROR(nVal.context->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, nVal.context->error, "pixelmap has crossed threads . setname failed",
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, nVal.context.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
        nVal.result);

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        uint32_t ret = pixelMapNapi->nativePixelMap_->SetMemoryName(pixelMapName);
        if (ret == SUCCESS) {
            return result;
        } else if (ret == ERR_MEMORY_NOT_SUPPORT) {
            ImageNapiUtils::ThrowExceptionError(env, ERR_MEMORY_NOT_SUPPORT, "fail set name");
        } else if (ret == COMMON_ERR_INVALID_PARAMETER) {
            ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "name size out of range");
        }
    } else {
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE, "Invalid nativePixelMap");
        IMAGE_LOGE("Null native pixemap object");
    }
    return result;
#endif
}

static void CloneExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Null context");
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            int32_t errorCode = SUCCESS;
            auto clonePixelMap = context->rPixelMap->Clone(errorCode);
            if (clonePixelMap == nullptr) {
                context->status = static_cast<uint32_t>(errorCode);
                IMAGE_LOGE("Clone PixelMap failed");
                return;
            }
            context->alphaMap = std::move(clonePixelMap);
            context->status = SUCCESS;
        } else {
            IMAGE_LOGE("Null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        context->status = ERR_IMAGE_INIT_ABNORMAL;
        IMAGE_LOGE("Clone has failed. do nothing");
    }
}

static void CloneComplete(napi_env env, napi_status status, void *data)
{
    if (data == nullptr) {
        IMAGE_LOGE("ClonedPixelMapComplete invalid parameter: data is null");
        return;
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
 
    auto context = static_cast<PixelMapAsyncContext*>(data);
    if (context->alphaMap != nullptr) {
        result = PixelMapNapi::CreatePixelMap(env, context->alphaMap);
        context->status = SUCCESS;
    } else {
        context->status = ERR_IMAGE_INIT_ABNORMAL;
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value PixelMapNapi::Clone(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    size_t argCount = NUM_0;
    napi_value thisVar = nullptr;
    IMAGE_LOGD("Clone IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to arg info"));
    std::unique_ptr<PixelMapAsyncContext> asyncContext = std::make_unique<PixelMapAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
    asyncContext->rPixelMap = asyncContext->nConstructor->nativePixelMap_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPixelMap),
        nullptr, IMAGE_LOGE("empty native pixelmap"));
    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->nConstructor->GetPixelNapiEditable(),
        BuildContextError(env, asyncContext->error, "pixelmap has crossed threads. Clone PixelMap failed",
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, asyncContext.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
        result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "Clone",
        [](napi_env env, void *data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            CloneExec(env, context);
        }, CloneComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to clone deferred async work"));
    return result;
}

napi_value PixelMapNapi::CloneSync(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    size_t argCount = NUM_0;
    napi_value thisVar = nullptr;
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to arg info"));
    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads. ClonePixelmapSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads. ClonePixelmapSync failed"));
    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        int32_t errorCode = 0;
        auto clonePixelMap = pixelMapNapi->nativePixelMap_->Clone(errorCode);
        if (clonePixelMap == nullptr) {
            if (errorCode == ERR_IMAGE_INIT_ABNORMAL) {
                return ImageNapiUtils::ThrowExceptionError(env, errorCode, "Initial a empty pixelmap failed");
            }
            if (errorCode == ERR_IMAGE_MALLOC_ABNORMAL) {
                return ImageNapiUtils::ThrowExceptionError(env, errorCode, "Clone pixelmap data failed");
            }
            if (errorCode == ERR_IMAGE_DATA_UNSUPPORT) {
                return ImageNapiUtils::ThrowExceptionError(env, errorCode, "PixelMap type does not support clone");
            }
            if (errorCode == ERR_IMAGE_TOO_LARGE) {
                return ImageNapiUtils::ThrowExceptionError(env, errorCode, "PixelMap Size (byte count) out of range");
            }
            return ImageNapiUtils::ThrowExceptionError(env, errorCode, "Clone PixelMap failed");
        }
        result = PixelMapNapi::CreatePixelMap(env, std::move(clonePixelMap));
    } else {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_INIT_ABNORMAL, "Null Native Ref");
    }
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

napi_value PixelMapNapi::Translate(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_3;
    napi_value argValue[NUM_3] = {0};
    nVal.argv = argValue;
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, nVal.context.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
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
        } else {
            NAPI_CHECK_AND_DELETE_REF(env, nVal.context->callbackRef);
        }
    }
    return nVal.result;
}

napi_value PixelMapNapi::TranslateSync(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    uint32_t status = SUCCESS;
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

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . TranslateSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . TranslateSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        pixelMapNapi->nativePixelMap_->translate(static_cast<float>(x), static_cast<float>(y));
    } else {
        IMAGE_LOGE("Null native ref");
    }
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

napi_value PixelMapNapi::Rotate(napi_env env, napi_callback_info info)
{
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, nVal.context.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
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
        } else {
            NAPI_CHECK_AND_DELETE_REF(env, nVal.context->callbackRef);
        }
    }
    return nVal.result;
}

napi_value PixelMapNapi::RotateSync(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status napiStatus;
    uint32_t status = SUCCESS;
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

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . RotateSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . RotateSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        pixelMapNapi->nativePixelMap_->rotate(static_cast<float>(angle));
    } else {
        IMAGE_LOGE("Null native ref");
    }
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

napi_value PixelMapNapi::Flip(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_3;
    napi_value argValue[NUM_3] = {0};
    nVal.argv = argValue;
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, nVal.context.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
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
        } else {
            NAPI_CHECK_AND_DELETE_REF(env, nVal.context->callbackRef);
        }
    }
    return nVal.result;
}

napi_value PixelMapNapi::FlipSync(napi_env env, napi_callback_info info)
{
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

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(pixelMapNapi->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . FlipSync failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . FlipSync failed"));

    if (pixelMapNapi->nativePixelMap_ != nullptr) {
        pixelMapNapi->nativePixelMap_->flip(xBarg, yBarg);
    } else {
        IMAGE_LOGE("Null native ref");
    }
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

napi_value PixelMapNapi::Crop(napi_env env, napi_callback_info info)
{
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, nVal.context.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
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
        } else {
            NAPI_CHECK_AND_DELETE_REF(env, nVal.context->callbackRef);
        }
    }
    return nVal.result;
}

napi_value PixelMapNapi::CropSync(napi_env env, napi_callback_info info)
{
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

    PixelMapNapi* pixelMapNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pixelMapNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(napiStatus, pixelMapNapi), result, IMAGE_LOGE("fail to unwrap context"));
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
    return result;
}

STATIC_COMPLETE_FUNC(ToSdr)
{
    auto context = static_cast<PixelMapAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("ToSdrComplete context is nullptr");
        return;
    }
    napi_value result[NUM_2] = {0};
    napi_value retVal;
    napi_value callback = nullptr;
    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        IMAGE_LOGE("ToSdrComplete scope is nullptr");
        return;
    }
    if (context->status == SUCCESS) {
        napi_value value = nullptr;
        napi_get_undefined(env, &value);
        result[NUM_1] = value;
    } else if (context->status == ERR_MEDIA_INVALID_OPERATION) {
        ImageNapiUtils::CreateErrorObj(env, result[NUM_0], context->status, "The pixelmap is not hdr.");
    } else if (context->status == IMAGE_RESULT_GET_SURFAC_FAILED) {
        ImageNapiUtils::CreateErrorObj(env, result[NUM_0], ERR_MEDIA_INVALID_OPERATION, "Alloc new memory failed.");
    } else if (context->status == ERR_RESOURCE_UNAVAILABLE) {
        ImageNapiUtils::CreateErrorObj(env, result[NUM_0], ERR_MEDIA_INVALID_OPERATION, "Pixelmap is not editable");
    } else {
        ImageNapiUtils::CreateErrorObj(env, result[NUM_0], ERR_MEDIA_INVALID_OPERATION, "Internal error.");
    }
    if (context->deferred) {
        if (context->status == SUCCESS) {
            napi_resolve_deferred(env, context->deferred, result[NUM_1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[NUM_0]);
        }
    } else {
        napi_get_reference_value(env, context->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, NUM_2, result, &retVal);
        NAPI_CHECK_AND_DELETE_REF(env, context->callbackRef);
    }
    napi_delete_async_work(env, context->work);
    napi_close_handle_scope(env, scope);
    delete context;
    context = nullptr;
}

static void ToSdrExec(napi_env env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("ToSdrExec null context");
        return;
    }
    if (!context->nConstructor->GetPixelNapiEditable()) {
        IMAGE_LOGE("ToSdrExec pixelmap is not editable");
        context->status = ERR_RESOURCE_UNAVAILABLE;
        return;
    }
    if (context->status == SUCCESS) {
        if (context->rPixelMap != nullptr) {
            context->status = context->rPixelMap->ToSdr();
        } else {
            IMAGE_LOGE("ToSdrExec null native ref");
            context->status = ERR_IMAGE_INIT_ABNORMAL;
        }
    } else {
        IMAGE_LOGI("ToSdrExec has failed. Do nothing");
    }
}

napi_value PixelMapNapi::ToSdr(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.argc = NUM_1;
    napi_value argValue[NUM_1] = {0};
    nVal.argv = argValue;
    if (!prepareNapiEnv(env, info, &nVal)) {
        IMAGE_LOGI("ToSdr prepare napi env failed");
        return nVal.result;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;
    napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    napi_value _resource = nullptr;
    napi_create_string_utf8(env, "ToSdrExec", NAPI_AUTO_LENGTH, &_resource);
    nVal.status = napi_create_async_work(env, nullptr, _resource,
        [](napi_env env, void* data) {
            auto context = static_cast<PixelMapAsyncContext*>(data);
            ToSdrExec(env, context);
        }, ToSdrComplete, static_cast<void*>(nVal.context.get()), &(nVal.context->work));

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

napi_value PixelMapNapi::SetColorSpace(napi_env env, napi_callback_info info)
{
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

napi_value PixelMapNapi::Marshalling(napi_env env, napi_callback_info info)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
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
    if (nVal.context->rPixelMap == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_IPC, "marshalling pixel map to parcel failed.");
    }
    if (nVal.argc != NUM_0 && nVal.argc != NUM_1) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Invalid args count");
    }
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_get_cb_info(env, info, &nVal.argc, nVal.argv, nullptr, nullptr);
    napi_status status = napi_unwrap(env, nVal.argv[0], reinterpret_cast<void**>(&napiSequence));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, napiSequence), nullptr, IMAGE_LOGE("fail to unwrap context"));
    auto messageParcel = napiSequence->GetMessageParcel();
    if (messageParcel == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IPC, "marshalling pixel map to parcel failed.");
    }
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

napi_value PixelMapNapi::ApplyColorSpace(napi_env env, napi_callback_info info)
{
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
        ERR_RESOURCE_UNAVAILABLE),
        NapiSendEvent(env, nVal.context.release(), napi_eprio_high, ERR_RESOURCE_UNAVAILABLE),
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
        } else {
            NAPI_CHECK_AND_DELETE_REF(env, nVal.context->callbackRef);
        }
    }
    return nVal.result;
}

static bool IsMatchFormatType(FormatType type, PixelFormat format)
{
    if (type == FormatType::YUV) {
        switch (format) {
            case PixelFormat::NV21:
            case PixelFormat::NV12:
            case PixelFormat::YCBCR_P010:
            case PixelFormat::YCRCB_P010:{
                return true;
            }
            default:{
                return false;
            }
        }
    } else if (type == FormatType::RGB) {
        switch (format) {
            case PixelFormat::ARGB_8888:
            case PixelFormat::RGB_565:
            case PixelFormat::RGBA_8888:
            case PixelFormat::BGRA_8888:
            case PixelFormat::RGB_888:
            case PixelFormat::RGBA_F16:
            case PixelFormat::RGBA_1010102:{
                return true;
            }
            default:{
                return false;
            }
        }
    } else if (type == FormatType::ASTC) {
        switch (format) {
            case PixelFormat::ASTC_4x4:{
                return true;
            }
            default:{
                return false;
            }
        }
    } else {
        return false;
    }
}

STATIC_EXEC_FUNC(GeneralError)
{
    if (data == nullptr) {
        IMAGE_LOGE("GeneralErrorExec invalid parameter: data is null");
        return;
    }
    auto context = static_cast<PixelMapAsyncContext*>(data);
    context->status = IMAGE_RESULT_CREATE_FORMAT_CONVERT_FAILED;
}

static FormatType TypeFormat(PixelFormat &pixelForamt)
{
    switch (pixelForamt) {
        case PixelFormat::ARGB_8888:
        case PixelFormat::RGB_565:
        case PixelFormat::RGBA_8888:
        case PixelFormat::BGRA_8888:
        case PixelFormat::RGB_888:
        case PixelFormat::RGBA_F16:
        case PixelFormat::RGBA_1010102:{
            return FormatType::RGB;
        }
        case PixelFormat::NV21:
        case PixelFormat::NV12:
        case PixelFormat::YCBCR_P010:
        case PixelFormat::YCRCB_P010:{
            return FormatType::YUV;
        }
        case PixelFormat::ASTC_4x4:{
            return FormatType::ASTC;
        }
        default:
            return FormatType::UNKNOWN;
    }
}

static uint32_t GetNativePixelMapInfo(napi_env &env, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("GetNativePixelMapInfo invalid parameter: context is null");
        return ERROR;
    }

    PixelFormat destPixelFormat = context->destFormat;
    std::shared_ptr<PixelMap> pixelMap = nullptr;
    IMG_NAPI_CHECK_BUILD_ERROR(IsMatchFormatType(context->dstFormatType, destPixelFormat),
        BuildContextError(env, context->error, "dest format is wrong!", ERR_IMAGE_INVALID_PARAMETER),
        context->status = ERR_IMAGE_INVALID_PARAMETER, ERR_IMAGE_INVALID_PARAMETER);
    IMG_NAPI_CHECK_BUILD_ERROR(IsMatchFormatType(context->srcFormatType, context->rPixelMap->GetPixelFormat()),
        BuildContextError(env, context->error, "source format is wrong!", ERR_IMAGE_INVALID_PARAMETER),
        context->status = ERR_IMAGE_INVALID_PARAMETER, ERR_IMAGE_INVALID_PARAMETER);
    return SUCCESS;
}

static uint32_t GetNativeConvertInfo(napi_env &env, napi_callback_info &info, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("GetNativeConvertInfo invalid parameter: context is null");
        return ERROR;
    }

    napi_status status = napi_invalid_arg;
    napi_value thisVar = nullptr;
    size_t argc = NUM_1;
    napi_value argv[NUM_1] = {nullptr};
    IMG_JS_ARGS(env, info, status, argc, argv, thisVar);
    IMG_NAPI_CHECK_BUILD_ERROR(IMG_IS_OK(status),
        BuildContextError(env, context->error, "fail to napi_get_cb_info", ERROR), context->status = ERROR, ERROR);
    IMG_NAPI_CHECK_BUILD_ERROR(argc == NUM_1,
        BuildContextError(env, context->error, "incorrect number of parametersarguments!", ERR_IMAGE_INVALID_PARAMETER),
        context->status = ERR_IMAGE_INVALID_PARAMETER, ERR_IMAGE_INVALID_PARAMETER);
    napi_value constructor = nullptr;
    napi_value global = nullptr;
    napi_get_global(env, &global);
    status = napi_get_named_property(env, global, "PixelFormat", &constructor);
    IMG_NAPI_CHECK_BUILD_ERROR(IMG_IS_OK(status),
        BuildContextError(env, context->error, "Get PixelMapNapi property failed!", ERR_IMAGE_PROPERTY_NOT_EXIST),
        context->status = ERR_IMAGE_PROPERTY_NOT_EXIST, ERR_IMAGE_PROPERTY_NOT_EXIST);

    bool isPixelFormat = false;
    if (context->destFormat == PixelFormat::UNKNOWN) {
        isPixelFormat = false;
    } else {
        isPixelFormat = true;
    }

    if (isPixelFormat) {
        return GetNativePixelMapInfo(env, context);
    }
    IMG_NAPI_CHECK_BUILD_ERROR(false,
        BuildContextError(env, context->error, "wrong arguments!", ERR_IMAGE_INVALID_PARAMETER),
        context->status = ERR_IMAGE_INVALID_PARAMETER, ERR_IMAGE_INVALID_PARAMETER);
}

static napi_value Convert(napi_env &env, napi_callback_info &info, FormatType srcFormatType, std::string workName,
    PixelMapAsyncContext* context)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    if (context == nullptr) {
        return nullptr;
    }
    context->status = SUCCESS;
    context->srcFormatType = srcFormatType;
    uint32_t ret = GetNativeConvertInfo(env, info, context);
    napi_create_promise(env, &(context->deferred), &result);
    PixelMapAsyncContextPtr asyncContext = std::make_unique<PixelMapAsyncContext>(*context);
    IMG_NAPI_CHECK_BUILD_ERROR(asyncContext->error == nullptr,
        asyncContext->status = IMAGE_RESULT_CREATE_FORMAT_CONVERT_FAILED,
        IMG_CREATE_CREATE_ASYNC_WORK(env, status, (workName + "GeneralError").c_str(),
        GeneralErrorExec, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);

    IMG_NAPI_CHECK_BUILD_ERROR(ret == SUCCESS,
        BuildContextError(env, asyncContext->error, "get native convert info failed!", ret),
        IMG_CREATE_CREATE_ASYNC_WORK(env, status, (workName + "GeneralError").c_str(),
        GeneralErrorExec, GeneralErrorComplete, asyncContext, asyncContext->work),
        result);

    context->status = ImageFormatConvert::ConvertImageFormat(context->rPixelMap, context->destFormat);
    if (context->status == SUCCESS) {
        ImageUtils::FlushSurfaceBuffer(const_cast<PixelMap*>(context->rPixelMap.get()));
        result = PixelMapNapi::CreatePixelMap(env, context->rPixelMap);
        return result;
    }
    return result;
}

static napi_value YUVToRGB(napi_env env, napi_callback_info &info, PixelMapAsyncContext* context)
{
    return Convert(env, info, FormatType::YUV, "YUVToRGB", context);
}

static napi_value RGBToYUV(napi_env env, napi_callback_info &info,  PixelMapAsyncContext* context)
{
    return Convert(env, info, FormatType::RGB, "RGBToYUV", context);
}

static napi_value ASTCToRGB(napi_env env, napi_callback_info &info, PixelMapAsyncContext* context)
{
    return Convert(env, info, FormatType::ASTC, "ASTCToRGB", context);
}

static napi_value PixelFormatConvert(napi_env env, napi_callback_info &info, PixelMapAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_LOGE("PixelFormatConvert invalid parameter: context is null");
        return nullptr;
    }

    napi_value result = nullptr;
    napi_create_promise(env, &(context->deferred), &result);
    PixelFormat dstFormat = context->destFormat;

    if (dstFormat != PixelFormat::UNKNOWN) {
        context->dstFormatType = TypeFormat(dstFormat);
        if (context->dstFormatType == FormatType::YUV &&
            (context->srcFormatType == FormatType::UNKNOWN || context->srcFormatType == FormatType::RGB)) {
            result = RGBToYUV(env, info, context);
        } else if ((context->dstFormatType == FormatType::RGB) &&
            (context->srcFormatType == FormatType::UNKNOWN || context->srcFormatType == FormatType::YUV)) {
            result = YUVToRGB(env, info, context);
        } else if ((context->dstFormatType == FormatType::RGB) && (context->srcFormatType == FormatType::ASTC)) {
            result = ASTCToRGB(env, info, context);
        }
    }
    return result;
}

napi_value PixelMapNapi::ConvertPixelMapFormat(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_value argValue[NUM_2];
    size_t argc = NUM_2;
    nVal.argc = argc;
    nVal.argv = argValue;

    if (!prepareNapiEnv(env, info, &nVal)) {
        return nVal.result;
    }
    if (!nVal.context) {
        return nullptr;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;
    if (nVal.argc >= 1 && ImageNapiUtils::getType(env, nVal.argv[nVal.argc - 1]) == napi_function) {
        napi_create_reference(env, nVal.argv[nVal.argc - 1], nVal.refCount, &(nVal.context->callbackRef));
    }
    napi_get_undefined(env, &nVal.result);
    if (nVal.argc != NUM_1) {
        IMAGE_LOGE("Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    }

    if (nVal.context->callbackRef == nullptr) {
        napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    } else {
        napi_get_undefined(env, &(nVal.result));
    }

    napi_value jsArg = nVal.argv[0];
    int32_t pixelFormatInt;
    napi_get_value_int32(env, jsArg, &pixelFormatInt);
    nVal.context->destFormat = static_cast<PixelFormat>(pixelFormatInt);
    if (nVal.context->nConstructor->nativePixelMap_->GetPixelFormat() == PixelFormat::ASTC_4x4) {
        nVal.context->srcFormatType = FormatType::ASTC;
    }

    if (TypeFormat(nVal.context->destFormat) == FormatType::UNKNOWN) {
        napi_value errCode = nullptr;
        napi_create_int32(env, ERR_IMAGE_INVALID_PARAMETER, &errCode);
        napi_reject_deferred(env, nVal.context->deferred, errCode);
        IMAGE_LOGE("dstFormat is not support or invalid");
        return nVal.result;
    }

    nVal.result = PixelFormatConvert(env, info, nVal.context.get());
    nVal.context->nConstructor->nativePixelMap_ = nVal.context->rPixelMap;
    if (nVal.result == nullptr) {
        return nVal.result;
    }
    return nVal.result;
}

napi_value PixelMapNapi::SetTransferDetached(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_value argValue[NUM_1];
    nVal.argc = NUM_1;
    nVal.argv = argValue;
    napi_status status = napi_invalid_arg;
    napi_get_undefined(env, &nVal.result);
    if (!prepareNapiEnv(env, info, &nVal)) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE, "Fail to unwrap context");
    }
    bool detach;
    status = napi_get_value_bool(env, nVal.argv[NUM_0], &detach);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "SetTransferDetached get detach failed"),
        IMAGE_LOGE("SetTransferDetached get detach failed"));
    nVal.context->nConstructor->SetTransferDetach(detach);
    return nVal.result;
}
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
enum HdrMetadataKey : uint32_t {
    HDR_METADATA_TYPE = 0,
    HDR_STATIC_METADATA,
    HDR_DYNAMIC_METADATA,
    HDR_GAINMAP_METADATA,
};

enum HdrMetadataType : uint32_t {
    NONE = 0,
    BASE,
    GAINMAP,
    ALTERNATE,
    INVALID,
};

static std::map<HdrMetadataType, CM_HDR_Metadata_Type> EtsMetadataMap = {
    {NONE, CM_METADATA_NONE},
    {BASE, CM_IMAGE_HDR_VIVID_DUAL},
    {GAINMAP, CM_METADATA_NONE},
    {ALTERNATE, CM_IMAGE_HDR_VIVID_SINGLE},
};

static std::map<CM_HDR_Metadata_Type, HdrMetadataType> MetadataEtsMap = {
    {CM_METADATA_NONE, NONE},
    {CM_IMAGE_HDR_VIVID_DUAL, BASE},
    {CM_IMAGE_HDR_VIVID_SINGLE, ALTERNATE},
};

static double FloatToDouble(float val)
{
    const double precision = 1000000.0;
    val *= precision;
    double result = static_cast<double>(val / precision);
    return result;
}

static bool CreateArrayDouble(napi_env env, napi_value &root, float value, int index)
{
    napi_value node = nullptr;
    if (!CREATE_NAPI_DOUBLE(FloatToDouble(value), node)) {
        return false;
    }
    if (napi_set_element(env, root, index, node) != napi_ok) {
        return false;
    }
    return true;
}

inline napi_value CreateJsNumber(napi_env env, double value)
{
    napi_value result = nullptr;
    napi_create_double(env, value, &result);
    return result;
}

static bool CreateNapiDouble(napi_env env, napi_value &root, float value, std::string name)
{
    napi_value node = CreateJsNumber(env, FloatToDouble(value));
    if (napi_set_named_property(env, root, name.c_str(), node) != napi_ok) {
        return false;
    }
    return true;
}

static bool CreateNapiUint32(napi_env env, napi_value &root, int32_t value, std::string name)
{
    napi_value node = nullptr;
    if (!CREATE_NAPI_INT32(value, node)) {
        return false;
    }

    if (napi_set_named_property(env, root, name.c_str(), node) != napi_ok) {
        return false;
    }
    return true;
}

static bool CreateNapiBool(napi_env env, napi_value &root, bool value, std::string name)
{
    napi_value node = nullptr;
    if (napi_get_boolean(env, value, &node) != napi_ok) {
        return false;
    }
    if (napi_set_named_property(env, root, name.c_str(), node) != napi_ok) {
        return false;
    }
    return true;
}
static napi_value BuildStaticMetadataNapi(napi_env env,
    HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata &staticMetadata)
{
    napi_value metadataValue = nullptr;
    napi_create_object(env, &metadataValue);
    napi_value displayPrimariesX = nullptr;
    napi_create_array_with_length(env, NUM_3, &displayPrimariesX);
    bool status = true;
    status &= CreateArrayDouble(env, displayPrimariesX, staticMetadata.smpte2086.displayPrimaryRed.x, NUM_0);
    status &= CreateArrayDouble(env, displayPrimariesX, staticMetadata.smpte2086.displayPrimaryGreen.x, NUM_1);
    status &= CreateArrayDouble(env, displayPrimariesX, staticMetadata.smpte2086.displayPrimaryBlue.x, NUM_2);
    status &= napi_set_named_property(env, metadataValue, "displayPrimariesX", displayPrimariesX) == napi_ok;
    napi_value displayPrimariesY = nullptr;
    napi_create_array_with_length(env, NUM_3, &displayPrimariesY);
    status &= CreateArrayDouble(env, displayPrimariesY, staticMetadata.smpte2086.displayPrimaryRed.y, NUM_0);
    status &= CreateArrayDouble(env, displayPrimariesY, staticMetadata.smpte2086.displayPrimaryGreen.y, NUM_1);
    status &= CreateArrayDouble(env, displayPrimariesY, staticMetadata.smpte2086.displayPrimaryBlue.y, NUM_2);
    status &= napi_set_named_property(env, metadataValue, "displayPrimariesY", displayPrimariesY) == napi_ok;
    status &= CreateNapiDouble(env, metadataValue, staticMetadata.smpte2086.whitePoint.x, "whitePointX");
    status &= CreateNapiDouble(env, metadataValue, staticMetadata.smpte2086.whitePoint.y, "whitePointY");
    status &= CreateNapiDouble(env, metadataValue, staticMetadata.smpte2086.maxLuminance, "maxLuminance");
    status &= CreateNapiDouble(env, metadataValue, staticMetadata.smpte2086.minLuminance, "minLuminance");
    status &= CreateNapiDouble(env, metadataValue,
        staticMetadata.cta861.maxContentLightLevel, "maxContentLightLevel");
    status &= CreateNapiDouble(env, metadataValue,
        staticMetadata.cta861.maxFrameAverageLightLevel, "maxFrameAverageLightLevel");
    if (!status) {
        IMAGE_LOGD("BuildStaticMetadataNapi failed");
    }
    return metadataValue;
}

static bool BuildGainmapChannel(napi_env env, napi_value &root, HDRVividExtendMetadata & gainmapMetadata, int index)
{
    bool status = true;
    status &= CreateNapiDouble(env, root,
        gainmapMetadata.metaISO.enhanceClippedThreholdMaxGainmap[index], "gainmapMax");
    status &= CreateNapiDouble(env, root,
        gainmapMetadata.metaISO.enhanceClippedThreholdMinGainmap[index], "gainmapMin");
    status &= CreateNapiDouble(env, root,
        gainmapMetadata.metaISO.enhanceMappingGamma[index], "gamma");
    status &= CreateNapiDouble(env, root,
        gainmapMetadata.metaISO.enhanceMappingBaselineOffset[index], "baseOffset");
    status &= CreateNapiDouble(env, root,
        gainmapMetadata.metaISO.enhanceMappingAlternateOffset[index], "alternateOffset");
    return status;
}

static napi_value BuildDynamicMetadataNapi(napi_env env, HDRVividExtendMetadata &gainmapMetadata)
{
    napi_value metadataValue = nullptr;
    napi_create_object(env, &metadataValue);
    bool status = true;
    status &= CreateNapiUint32(env, metadataValue, static_cast<int32_t>(
        gainmapMetadata.metaISO.writeVersion), "writerVersion");
    status &= CreateNapiUint32(env, metadataValue, static_cast<int32_t>(
        gainmapMetadata.metaISO.miniVersion), "miniVersion");
    status &= CreateNapiUint32(env, metadataValue, static_cast<int32_t>(
        gainmapMetadata.metaISO.gainmapChannelNum), "gainmapChannelCount");
    status &= CreateNapiBool(env, metadataValue, static_cast<bool>(
        gainmapMetadata.metaISO.useBaseColorFlag), "useBaseColorFlag");
    status &= CreateNapiDouble(env, metadataValue, gainmapMetadata.metaISO.baseHeadroom, "baseHeadroom");
    status &= CreateNapiDouble(env, metadataValue, gainmapMetadata.metaISO.alternateHeadroom, "alternateHeadroom");
    napi_value array = nullptr;
    napi_create_object(env, &array);
    for (uint32_t i = 0; i < NUM_3; i++) {
        napi_value gainmapChannel = nullptr;
        napi_create_object(env, &gainmapChannel);
        status &= BuildGainmapChannel(env, gainmapChannel, gainmapMetadata, i);
        napi_set_element(env, array, i, gainmapChannel);
    }
    napi_set_named_property(env, metadataValue, "channels", array);
    if (!status) {
        IMAGE_LOGD("BuildDynamicMetadataNapi failed");
    }
    return metadataValue;
}

static napi_status GetStaticMetadata(napi_env env, OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer,
    napi_value &metadataValue)
{
    HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata staticMetadata;
    uint32_t vecSize = sizeof(HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata);
    std::vector<uint8_t> staticData;
    if (!VpeUtils::GetSbStaticMetadata(surfaceBuffer, staticData) ||
        (staticData.size() != vecSize)) {
        IMAGE_LOGE("GetSbStaticMetadata failed");
        return napi_invalid_arg;
    }
    if (memcpy_s(&staticMetadata, vecSize, staticData.data(), staticData.size()) != EOK) {
        return napi_invalid_arg;
    }
    metadataValue = BuildStaticMetadataNapi(env, staticMetadata);
    return napi_ok;
}

static napi_status GetDynamicMetadata(napi_env env,
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer, napi_value &metadataValue)
{
    std::vector<uint8_t> dynamicData;
    if (VpeUtils::GetSbDynamicMetadata(surfaceBuffer, dynamicData) && (dynamicData.size() > 0)) {
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        ImageNapiUtils::CreateArrayBuffer(env, dynamicData.data(), dynamicData.size(), &result);
        metadataValue = result;
        if (metadataValue == nullptr) {
            return napi_invalid_arg;
        }
        return napi_ok;
    }
    IMAGE_LOGE("GetSbDynamicMetadata failed");
    return napi_invalid_arg;
}

static napi_status GetMetadataType(napi_env env,
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer, napi_value &metadataValue)
{
    CM_HDR_Metadata_Type type;
    VpeUtils::GetSbMetadataType(surfaceBuffer, type);
    if (MetadataEtsMap.find(type) != MetadataEtsMap.end()) {
        int32_t value = static_cast<int32_t>(MetadataEtsMap[type]);
        std::vector<uint8_t> gainmapData;
        if (type == CM_HDR_Metadata_Type::CM_METADATA_NONE &&
            VpeUtils::GetSbDynamicMetadata(surfaceBuffer, gainmapData) &&
            gainmapData.size() == sizeof(HDRVividExtendMetadata)) {
            value = static_cast<int32_t>(HdrMetadataType::GAINMAP);
        }
        if (!CREATE_NAPI_INT32(value, metadataValue)) {
            return napi_invalid_arg;
        }
        return napi_ok;
    }
    IMAGE_LOGE("GetMetadataType failed");
    return napi_invalid_arg;
}

static napi_status BuildHdrMetadataValue(napi_env env, napi_value argv[],
    std::shared_ptr<PixelMap> pixelMap, napi_value &metadataValue)
{
    uint32_t metadataKey = 0;
    napi_get_value_uint32(env, argv[NUM_0], &metadataKey);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer(
        reinterpret_cast<OHOS::SurfaceBuffer*>(pixelMap->GetFd()));
    switch (HdrMetadataKey(metadataKey)) {
        case HDR_METADATA_TYPE:
            return GetMetadataType(env, surfaceBuffer, metadataValue);
            break;
        case HDR_STATIC_METADATA:
            return GetStaticMetadata(env, surfaceBuffer, metadataValue);
            break;
        case HDR_DYNAMIC_METADATA:
            return GetDynamicMetadata(env, surfaceBuffer, metadataValue);
            break;
        case HDR_GAINMAP_METADATA:
            {
                std::vector<uint8_t> gainmapData;
                if (VpeUtils::GetSbDynamicMetadata(surfaceBuffer, gainmapData) &&
                    (gainmapData.size() == sizeof(HDRVividExtendMetadata))) {
                    HDRVividExtendMetadata &gainmapMetadata =
                        *(reinterpret_cast<HDRVividExtendMetadata*>(gainmapData.data()));
                    metadataValue = BuildDynamicMetadataNapi(env, gainmapMetadata);
                    return napi_ok;
                }
                IMAGE_LOGE("GetSbDynamicMetadata failed");
            }
            break;
        default:
            break;
    }
    return napi_invalid_arg;
}

napi_value PixelMapNapi::GetMetadata(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_value argValue[NUM_1];
    nVal.argc = NUM_1;
    nVal.argv = argValue;
    nVal.status = napi_invalid_arg;
    if (!prepareNapiEnv(env, info, &nVal) || !nVal.context || !nVal.context->nConstructor ||
        !nVal.context->nConstructor->nativePixelMap_) {
        return ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "Fail to unwrap context");
    }
    std::shared_ptr<PixelMap> pixelMap = nVal.context->nConstructor->nativePixelMap_;
    if (pixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_DMA_NOT_EXIST, "Not DMA memory");
    }

    IMG_NAPI_CHECK_RET_D(nVal.context->nConstructor->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . GetMetadata failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . GetMetadata failed"));
    nVal.status = BuildHdrMetadataValue(env, nVal.argv, pixelMap, nVal.result);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(nVal.status),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEMORY_COPY_FAILED,
        "BuildHdrMetadataValue failed"),
        IMAGE_LOGE("BuildHdrMetadataValue failed"));
    return nVal.result;
}

static HdrMetadataType ParseHdrMetadataType(napi_env env, napi_value &hdrMetadataType)
{
    uint32_t type = 0;
    napi_get_value_uint32(env, hdrMetadataType, &type);
    if (type < HdrMetadataType::INVALID && type >= HdrMetadataType::NONE) {
        return HdrMetadataType(type);
    }
    return HdrMetadataType::INVALID;
}

static bool ParseArrayDoubleNode(napi_env env, napi_value &root, std::vector<float> &vec)
{
    uint32_t vecSize = 0;
    napi_get_array_length(env, root, &vecSize);
    if (vecSize > 0) {
        for (uint32_t i = 0; i < NUM_3; i++) {
            napi_value tempDiv = nullptr;
            napi_get_element(env, root, i, &tempDiv);
            double gamma = 0.0f;
            if (napi_get_value_double(env, tempDiv, &gamma) != napi_ok) {
                IMAGE_LOGE("ParseArrayDoubleNode get value failed");
                return false;
            }
            vec.emplace_back((float)gamma);
        }
        return true;
    }
    return false;
}

static bool ParseDoubleMetadataNode(napi_env env, napi_value &root,
    std::string name, float &value)
{
    double ret = 0.0;
    if (!GET_DOUBLE_BY_NAME(root, name.c_str(), ret)) {
        IMAGE_LOGI("parse %{public}s failed", name.c_str());
        return false;
    }
    value = static_cast<float>(ret);
    return true;
}

static bool ParseStaticMetadata(napi_env env, napi_value &hdrStaticMetadata, std::vector<uint8_t> &staticMetadataVec)
{
    HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata staticMetadata{};
    napi_value displayX = nullptr;
    std::vector<float> displayPrimariesX;
    if (!GET_NODE_BY_NAME(hdrStaticMetadata, "displayPrimariesX", displayX)) {
        IMAGE_LOGE("parse displayPrimariesX failed");
        return false;
    }
    if (!ParseArrayDoubleNode(env, displayX, displayPrimariesX)) {
        IMAGE_LOGE("parse array x failed");
        return false;
    }
    std::vector<float> displayPrimariesY;
    napi_value displayY = nullptr;
    if (!GET_NODE_BY_NAME(hdrStaticMetadata, "displayPrimariesY", displayY)) {
        IMAGE_LOGE("parse displayPrimariesY failed");
        return false;
    }
    if (!ParseArrayDoubleNode(env, displayY, displayPrimariesY)) {
        IMAGE_LOGE("parse array y failed");
        return false;
    }
    staticMetadata.smpte2086.displayPrimaryRed.x = displayPrimariesX[NUM_0];
    staticMetadata.smpte2086.displayPrimaryRed.y = displayPrimariesY[NUM_0];
    staticMetadata.smpte2086.displayPrimaryGreen.x = displayPrimariesX[NUM_1];
    staticMetadata.smpte2086.displayPrimaryGreen.y = displayPrimariesY[NUM_1];
    staticMetadata.smpte2086.displayPrimaryBlue.x = displayPrimariesX[NUM_2];
    staticMetadata.smpte2086.displayPrimaryBlue.y = displayPrimariesY[NUM_2];
    ParseDoubleMetadataNode(env, hdrStaticMetadata, "whitePointX", staticMetadata.smpte2086.whitePoint.x);
    ParseDoubleMetadataNode(env, hdrStaticMetadata, "whitePointY", staticMetadata.smpte2086.whitePoint.y);
    ParseDoubleMetadataNode(env, hdrStaticMetadata, "maxLuminance", staticMetadata.smpte2086.maxLuminance);
    ParseDoubleMetadataNode(env, hdrStaticMetadata, "minLuminance", staticMetadata.smpte2086.minLuminance);
    ParseDoubleMetadataNode(env, hdrStaticMetadata, "maxContentLightLevel",
        staticMetadata.cta861.maxContentLightLevel);
    ParseDoubleMetadataNode(env, hdrStaticMetadata, "maxFrameAverageLightLevel",
        staticMetadata.cta861.maxFrameAverageLightLevel);
    uint32_t vecSize = sizeof(HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata);
    if (memcpy_s(staticMetadataVec.data(), vecSize, &staticMetadata, vecSize) != EOK) {
        IMAGE_LOGE("staticMetadataVec memcpy failed");
        return false;
    }
    return true;
}

static bool ParseDynamicMetadata(napi_env env, napi_value &root, std::vector<uint8_t> &dynamicMetadataVec)
{
    void *buffer = nullptr;
    size_t size;
    if (napi_get_arraybuffer_info(env, root, &buffer, &size) != napi_ok) {
        return false;
    }
    dynamicMetadataVec.resize(size);
    if (memcpy_s(dynamicMetadataVec.data(), size, buffer, size) != EOK) {
        return false;
    }
    return true;
}

static bool ParseGainmapChannel(napi_env env, napi_value &root, HDRVividExtendMetadata &extendMetadata, int index)
{
    if (!ParseDoubleMetadataNode(env, root, "gainmapMax",
        extendMetadata.metaISO.enhanceClippedThreholdMaxGainmap[index])) {
        return false;
    }
    if (!ParseDoubleMetadataNode(env, root, "gainmapMin",
        extendMetadata.metaISO.enhanceClippedThreholdMinGainmap[index])) {
        return false;
    }
    if (!ParseDoubleMetadataNode(env, root, "gamma", extendMetadata.metaISO.enhanceMappingGamma[index])) {
        return false;
    }
    if (!ParseDoubleMetadataNode(env, root, "baseOffset", extendMetadata.metaISO.enhanceMappingBaselineOffset[index])) {
        return false;
    }
    if (!ParseDoubleMetadataNode(env, root, "alternateOffset",
        extendMetadata.metaISO.enhanceMappingAlternateOffset[index])) {
        return false;
    }
    return true;
}

static void ParseGainmapNode(napi_env env, napi_value &root, HDRVividExtendMetadata &extendMetadata)
{
    uint32_t isoMetadata = 0;
    if (!GET_UINT32_BY_NAME(root, "writerVersion", isoMetadata)) {
        IMAGE_LOGI("ParseGainmapNode parse writerVersion failed");
    }
    extendMetadata.metaISO.writeVersion = static_cast<unsigned short>(isoMetadata);
    if (!GET_UINT32_BY_NAME(root, "miniVersion", isoMetadata)) {
        IMAGE_LOGI("ParseGainmapNode parse miniVersion failed");
    }
    extendMetadata.metaISO.miniVersion = static_cast<unsigned short>(isoMetadata);
    if (!GET_UINT32_BY_NAME(root, "gainmapChannelCount", isoMetadata)) {
        IMAGE_LOGI("ParseGainmapNode parse gainmapChannelCount failed");
    }
    extendMetadata.metaISO.gainmapChannelNum = static_cast<unsigned char>(isoMetadata);
    bool colorflag = false;
    if (!GET_BOOL_BY_NAME(root, "useBaseColorFlag", colorflag)) {
        IMAGE_LOGI("ParseGainmapNode parse useBaseColorFlag failed");
    }
    extendMetadata.metaISO.useBaseColorFlag = static_cast<unsigned char>(colorflag);
    if (!ParseDoubleMetadataNode(env, root, "baseHeadroom", extendMetadata.metaISO.baseHeadroom)) {
        return;
    }
    if (!ParseDoubleMetadataNode(env, root, "alternateHeadroom", extendMetadata.metaISO.alternateHeadroom)) {
        return;
    }
    napi_value gainmap = nullptr;
    if (!GET_NODE_BY_NAME(root, "channels", gainmap)) {
        return;
    }
    bool isArray = false;
    napi_is_array(env, gainmap, &isArray);
    if (gainmap == nullptr || !isArray) {
        return;
    }
    uint32_t vecSize = 0;
    napi_get_array_length(env, gainmap, &vecSize);
    if (vecSize <= 0) {
        return;
    }
    for (uint32_t i = 0; i < NUM_3; i++) {
        napi_value tempDiv = nullptr;
        napi_get_element(env, gainmap, i, &tempDiv);
        ParseGainmapChannel(env, tempDiv, extendMetadata, i);
    }
    return;
}

static bool ParseGainmapMetedata(napi_env env, OHOS::Media::PixelMap &pixelmap,
    napi_value &root, std::vector<uint8_t> &gainmapMetadataVec)
{
    HDRVividExtendMetadata extendMetadata;
    #ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace colorSpace = pixelmap.InnerGetGrColorSpace();
    uint16_t SS = ColorUtils::GetPrimaries(colorSpace.GetColorSpaceName());
    #else
    uint16_t SS = 0;
    #endif
    extendMetadata.baseColorMeta.baseColorPrimary = SS;
    bool colorflag = false;
    if (GET_BOOL_BY_NAME(root, "useBaseColorFlag", colorflag)) {
        extendMetadata.gainmapColorMeta.combineColorPrimary = colorflag ? SS : (uint8_t)CM_BT2020_HLG_FULL;
        extendMetadata.gainmapColorMeta.enhanceDataColorModel = colorflag ? SS : (uint8_t)CM_BT2020_HLG_FULL;
        extendMetadata.gainmapColorMeta.alternateColorPrimary = (uint8_t)CM_BT2020_HLG_FULL;
    }
    ParseGainmapNode(env, root, extendMetadata);
    uint32_t vecSize = sizeof(HDRVividExtendMetadata);
    if (memcpy_s(gainmapMetadataVec.data(), vecSize, &extendMetadata, vecSize) != EOK) {
        IMAGE_LOGE("ParseGainmapMetedata memcpy failed");
        return false;
    }
    return true;
}

static napi_status SetStaticMetadata(napi_env env, napi_value hdrMetadataValue,
    OHOS::sptr<OHOS::SurfaceBuffer> &surfaceBuffer)
{
    uint32_t vecSize = sizeof(HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata);
    std::vector<uint8_t> metadataVec(vecSize);
    if (!ParseStaticMetadata(env, hdrMetadataValue, metadataVec)) {
        return napi_invalid_arg;
    }
    if (!VpeUtils::SetSbStaticMetadata(surfaceBuffer, metadataVec)) {
        IMAGE_LOGE("SetSbStaticMetadata failed");
        return napi_invalid_arg;
    }
    return napi_ok;
}

static napi_status ParseHdrMetadataValue(napi_env env, napi_value argv[],
    std::shared_ptr<PixelMap> pixelMap)
{
    uint32_t metadataKey = 0;
    napi_get_value_uint32(env, argv[0], &metadataKey);
    napi_value &hdrMetadataValue = argv[NUM_1];
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer(
        reinterpret_cast<OHOS::SurfaceBuffer*>(pixelMap->GetFd()));
    switch (HdrMetadataKey(metadataKey)) {
        case HDR_METADATA_TYPE:
            {
                HdrMetadataType type = ParseHdrMetadataType(env, hdrMetadataValue);
                if (EtsMetadataMap.find(type) != EtsMetadataMap.end()) {
                    VpeUtils::SetSbMetadataType(surfaceBuffer, EtsMetadataMap[type]);
                } else {
                    IMAGE_LOGE("SetSbMetadataType failed");
                    return napi_invalid_arg;
                }
            }
            break;
        case HDR_STATIC_METADATA:
            return SetStaticMetadata(env, hdrMetadataValue, surfaceBuffer);
            break;
        case HDR_DYNAMIC_METADATA:
            {
                std::vector<uint8_t> dynamicMetadataVec;
                if (!ParseDynamicMetadata(env, hdrMetadataValue, dynamicMetadataVec)) {
                    return napi_invalid_arg;
                }
                if (!VpeUtils::SetSbDynamicMetadata(surfaceBuffer, dynamicMetadataVec)) {
                    return napi_invalid_arg;
                }
            }
            break;
        case HDR_GAINMAP_METADATA:
            {
                std::vector<uint8_t> gainmapMetadataVec(sizeof(HDRVividExtendMetadata));
                if (!ParseGainmapMetedata(env, *(pixelMap.get()), hdrMetadataValue, gainmapMetadataVec)) {
                    return napi_invalid_arg;
                }
                if (!VpeUtils::SetSbDynamicMetadata(surfaceBuffer, gainmapMetadataVec)) {
                    return napi_invalid_arg;
                }
            }
            break;
        default:
            return napi_invalid_arg;
    }
    return napi_ok;
}

napi_value PixelMapNapi::SetMetadataSync(napi_env env, napi_callback_info info)
{
    IMAGE_LOGD("SetMetadataSync IN");
    NapiValues nVal;
    nVal.argc = NUM_2;
    napi_value argValue[NUM_2] = {0};
    nVal.argv = argValue;
    nVal.status = napi_invalid_arg;
    napi_get_undefined(env, &nVal.result);
    if (!prepareNapiEnv(env, info, &nVal)) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Fail to unwrap context");
    }
    if (nVal.argc != NUM_2) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Invalid args count");
    }
    uint32_t metadataKey = 0;
    napi_get_value_uint32(env, argValue[NUM_0], &metadataKey);
    if (metadataKey != 0 && ImageNapiUtils::getType(env, argValue[NUM_1]) != napi_object) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Invalid parameter");
    }
    std::shared_ptr<PixelMap> pixelMap = nVal.context->nConstructor->nativePixelMap_;
    if (pixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_DMA_NOT_EXIST, "Not DMA memory");
    }

    IMG_NAPI_CHECK_RET_D(nVal.context->nConstructor->GetPixelNapiEditable(),
        ImageNapiUtils::ThrowExceptionError(env, ERR_RESOURCE_UNAVAILABLE,
        "Pixelmap has crossed threads . SetColorSpace failed"),
        IMAGE_LOGE("Pixelmap has crossed threads . SetColorSpace failed"));
    nVal.status = ParseHdrMetadataValue(env, nVal.argv, pixelMap);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(nVal.status),
        ImageNapiUtils::ThrowExceptionError(env, ERR_MEMORY_COPY_FAILED,
        "ParseHdrMetadataValue failed"),
        IMAGE_LOGE("ParseHdrMetadataValue failed"));
    return nVal.result;
}

napi_value PixelMapNapi::SetMetadata(napi_env env, napi_callback_info info)
{
    IMAGE_LOGD("SetMetadataSync IN");
    NapiValues nVal;
    nVal.argc = NUM_2;
    napi_value argValue[NUM_2] = {0};
    nVal.argv = argValue;
    nVal.status = napi_ok;
    napi_get_undefined(env, &nVal.result);
    if (!prepareNapiEnv(env, info, &nVal)) {
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    }
    if (nVal.argc != NUM_2) {
        IMAGE_LOGE("Invalid args count");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    }
    uint32_t metadataKey = 0;
    napi_get_value_uint32(env, argValue[NUM_0], &metadataKey);
    if (metadataKey != 0 && ImageNapiUtils::getType(env, argValue[NUM_1]) != napi_object) {
        IMAGE_LOGE("Invalid parameter");
        nVal.context->status = ERR_IMAGE_INVALID_PARAMETER;
    }
    nVal.context->rPixelMap = nVal.context->nConstructor->nativePixelMap_;
    if (nVal.context->rPixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        nVal.context->status = ERR_DMA_NOT_EXIST;
    }
    if (nVal.context->status == napi_ok) {
        nVal.status = ParseHdrMetadataValue(env, nVal.argv, nVal.context->rPixelMap);
        if (nVal.status != napi_ok) {
            nVal.context->status = ERR_MEMORY_COPY_FAILED;
        }
    }
    napi_create_promise(env, &(nVal.context->deferred), &(nVal.result));
    if (!nVal.context->nConstructor->GetPixelNapiEditable()) {
        nVal.context->status = ERR_RESOURCE_UNAVAILABLE;
        IMAGE_LOGE("Pixelmap has crossed threads . SetColorSpace failed");
    }
    uint32_t errorCode = nVal.context->status;
    NapiSendEvent(env, nVal.context.release(), napi_eprio_high, errorCode);
    return nVal.result;
}
#else
napi_value PixelMapNapi::SetMetadata(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_get_undefined(env, &nVal.result);
    return nVal.result;
}
napi_value PixelMapNapi::SetMetadataSync(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_get_undefined(env, &nVal.result);
    return nVal.result;
}
napi_value PixelMapNapi::GetMetadata(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_get_undefined(env, &nVal.result);
    return nVal.result;
}
#endif

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
