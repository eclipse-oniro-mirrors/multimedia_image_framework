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

#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif
#include "media_errors.h"
#include "napi/native_node_api.h"
#include "image_common.h"
#include "image_log.h"
#include "image_format.h"
#include "image_napi_utils.h"
#include "image_utils.h"
#if !defined(CROSS_PLATFORM)
#include "vpe_utils.h"
#include "v1_0/cm_color_space.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageNapi"

namespace {
    constexpr int NUM0 = 0;
    constexpr int NUM1 = 1;
    constexpr int NUM2 = 2;
    constexpr int NUM3 = 3;
    const std::string MY_NAME = "ImageNapi";
}

namespace OHOS {
namespace Media {

struct ImageAsyncContext {
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callbackRef = nullptr;
    napi_ref thisRef = nullptr;
    ImageNapi *napi = nullptr;
    uint32_t status;
    int32_t componentType;
    NativeImage* image = nullptr;
    NativeComponent* component = nullptr;
    bool isTestContext = false;
};

#if !defined(CROSS_PLATFORM)
using namespace HDI::Display::Graphic::Common::V1_0;
enum HdrMetadataType : uint32_t {
    NONE = 0,
    BASE,
    GAINMAP,
    ALTERNATE,
};

static std::map<CM_HDR_Metadata_Type, HdrMetadataType> MetadataEtsMap = {
    {CM_METADATA_NONE, NONE},
    {CM_VIDEO_HDR_VIVID, BASE},
    {CM_IMAGE_HDR_VIVID_DUAL, BASE},
    {CM_IMAGE_HDR_VIVID_SINGLE, ALTERNATE},
};

struct NapiValues {
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_value* argv = nullptr;
    size_t argc;
    int32_t refCount = 1;
    std::unique_ptr<ImageAsyncContext> context;
};

enum HdrMetadataKey : uint32_t {
    HDR_METADATA_TYPE = 0,
    HDR_STATIC_METADATA,
    HDR_DYNAMIC_METADATA,
    HDR_GAINMAP_METADATA,
};
#endif

ImageHolderManager<NativeImage> ImageNapi::sNativeImageHolder_;
thread_local napi_ref ImageNapi::sConstructor_ = nullptr;

ImageNapi::ImageNapi()
{}

ImageNapi::~ImageNapi()
{
    NativeRelease();
}

void ImageNapi::NativeRelease()
{
    if (native_ != nullptr) {
        sNativeImageHolder_.release(native_->GetId());
        native_->release();
        native_ = nullptr;
    }
}

napi_value ImageNapi::Init(napi_env env, napi_value exports)
{
    IMAGE_FUNCTION_IN();
    napi_property_descriptor props[] = {
        DECLARE_NAPI_GETTER("clipRect", JSGetClipRect),
        DECLARE_NAPI_GETTER("size", JsGetSize),
        DECLARE_NAPI_GETTER("format", JsGetFormat),
        DECLARE_NAPI_GETTER("timestamp", JsGetTimestamp),
        DECLARE_NAPI_GETTER("colorSpace", JsGetColorSpace),
        DECLARE_NAPI_FUNCTION("getBufferData", JsGetBufferData),
        DECLARE_NAPI_FUNCTION("getMetadata", JsGetHdrMetadata),
        DECLARE_NAPI_FUNCTION("getComponent", JsGetComponent),
        DECLARE_NAPI_FUNCTION("release", JsRelease),
    };
    size_t size = IMG_ARRAY_SIZE(props);
    napi_value thisVar = nullptr;
    auto name = MY_NAME.c_str();
    if (napi_define_class(env, name, SIZE_MAX, Constructor, nullptr, size, props, &thisVar) != napi_ok) {
        IMAGE_ERR("Define class failed");
        return exports;
    }

    sConstructor_ = nullptr;

    if (napi_create_reference(env, thisVar, NUM1, &sConstructor_) != napi_ok) {
        IMAGE_ERR("Create reference failed");
        return exports;
    }
    auto ctorContext = new NapiConstructorContext();
    ctorContext->env_ = env;
    ctorContext->ref_ = sConstructor_;
    napi_add_env_cleanup_hook(env, ImageNapiUtils::CleanUpConstructorContext, ctorContext);

    if (napi_set_named_property(env, exports, name, thisVar) != napi_ok) {
        IMAGE_ERR("Define class failed");
        return exports;
    }

    IMAGE_DEBUG("Init success");
    return exports;
}


std::shared_ptr<NativeImage> ImageNapi::GetNativeImage(napi_env env, napi_value image)
{
    ImageNapi* napi = nullptr;

    napi_status status = napi_unwrap(env, image, reinterpret_cast<void**>(&napi));
    if (!IMG_IS_OK(status) || napi == nullptr) {
        IMAGE_ERR("GetImage napi unwrap failed");
        return nullptr;
    }
    return napi->native_;
}

napi_value ImageNapi::Constructor(napi_env env, napi_callback_info info)
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
    std::unique_ptr<ImageNapi> napi = std::make_unique<ImageNapi>();
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
    status = napi_wrap(env, thisVar,
        reinterpret_cast<void *>(napi.get()), ImageNapi::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        IMAGE_ERR("Failure wrapping js to native napi");
        return undefineVar;
    }

    napi.release();
    IMAGE_FUNCTION_OUT();
    return thisVar;
}

void ImageNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        delete reinterpret_cast<ImageNapi *>(nativeObject);
    }
}

napi_value ImageNapi::Create(napi_env env)
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
napi_value ImageNapi::Create(napi_env env, std::shared_ptr<NativeImage> nativeImage)
{
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_value argv[NUM1];

    IMAGE_FUNCTION_IN();
    if (env == nullptr || nativeImage == nullptr) {
        IMAGE_ERR("Input args is invalid");
        return nullptr;
    }
    if (napi_get_reference_value(env, sConstructor_, &constructor) == napi_ok && constructor != nullptr) {
        auto id = sNativeImageHolder_.save(nativeImage);
        nativeImage->SetId(id);
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
using AsyncExecCallback = void (*)(napi_env env, ImageAsyncContext* ctx);
using AsyncCompleteCallback = void (*)(napi_env env, napi_status status, ImageAsyncContext* ctx);
static bool JsCreateWork(napi_env env, const char* name, AsyncExecCallback exec,
    AsyncCompleteCallback complete, ImageAsyncContext* ctx)
{
    napi_value resource = nullptr;
    if (napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resource) != napi_ok) {
        IMAGE_ERR("napi_create_string_utf8 failed");
        return false;
    }
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

NativeImage* ImageNapi::GetNative()
{
    if (native_ != nullptr) {
        return native_.get();
    }
    return nullptr;
}

static std::unique_ptr<ImageAsyncContext> UnwrapContext(napi_env env, napi_callback_info info,
    size_t* argc = nullptr, napi_value* argv = nullptr, bool needCreateRef = false)
{
    napi_value thisVar = nullptr;
    size_t tmp = NUM0;

    IMAGE_FUNCTION_IN();

    if (napi_get_cb_info(env, info, (argc == nullptr)?&tmp:argc, argv, &thisVar, nullptr) != napi_ok) {
        IMAGE_ERR("Fail to napi_get_cb_info");
        return nullptr;
    }

    std::unique_ptr<ImageAsyncContext> ctx = std::make_unique<ImageAsyncContext>();
    if (napi_unwrap(env, thisVar, reinterpret_cast<void**>(&ctx->napi)) != napi_ok || ctx->napi == nullptr) {
        IMAGE_ERR("fail to unwrap constructor_");
        return nullptr;
    }
    ctx->image = ctx->napi->GetNative();
    if (needCreateRef) {
        napi_create_reference(env, thisVar, NUM1, &(ctx->thisRef));
    }
    return ctx;
}

static inline void ProcessPromise(napi_env env, napi_deferred deferred, napi_value* result, bool resolved)
{
    napi_status status;
    if (resolved) {
        status = napi_resolve_deferred(env, deferred, result[NUM1]);
    } else {
        status = napi_reject_deferred(env, deferred, result[NUM0]);
    }
    if (status != napi_ok) {
        IMAGE_ERR("ProcessPromise failed");
    }
    deferred = nullptr;
}
static inline void ProcessCallback(napi_env env, napi_ref ref, napi_value* result)
{
    napi_value retVal;
    napi_value callback;
    napi_get_reference_value(env, ref, &callback);
    if (callback != nullptr) {
        napi_call_function(env, nullptr, callback, NUM2, result, &retVal);
    }
    napi_delete_reference(env, ref);
}
static void CommonCallbackRoutine(napi_env env, ImageAsyncContext* &context, const napi_value &valueParam)
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

napi_value ImageNapi::JSGetClipRect(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    std::unique_ptr<ImageAsyncContext> context = UnwrapContext(env, info);
    if (context != nullptr && context->napi != nullptr && context->napi->isTestImage_) {
        const int32_t WIDTH = 8192;
        const int32_t HEIGHT = 8;
        return BuildJsRegion(env, WIDTH, HEIGHT, NUM0, NUM0);
    }
    if (context == nullptr || context->image == nullptr) {
        IMAGE_ERR("Image surface buffer is nullptr");
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

napi_value ImageNapi::JsGetSize(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    std::unique_ptr<ImageAsyncContext> context = UnwrapContext(env, info);
    if (context != nullptr && context->napi != nullptr && context->napi->isTestImage_) {
        const int32_t WIDTH = 8192;
        const int32_t HEIGHT = 8;
        return BuildJsSize(env, WIDTH, HEIGHT);
    }
    if (context == nullptr || context->image == nullptr) {
        IMAGE_ERR("Image surface buffer is nullptr");
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

napi_value ImageNapi::JsGetFormat(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    std::unique_ptr<ImageAsyncContext> context = UnwrapContext(env, info);
    if (context != nullptr && context->napi != nullptr && context->napi->isTestImage_) {
        const int32_t FORMAT = 12;
        napi_create_int32(env, FORMAT, &result);
        return result;
    }
    if (context == nullptr || context->image == nullptr) {
        IMAGE_ERR("Image surface buffer is nullptr");
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

napi_value ImageNapi::JsGetTimestamp(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;

    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
    std::unique_ptr<ImageAsyncContext> context = UnwrapContext(env, info);
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

napi_value ImageNapi::JsGetColorSpace(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    IMAGE_FUNCTION_IN();
    napi_get_undefined(env, &result);
#if !defined(CROSS_PLATFORM) && defined(IMAGE_COLORSPACE_FLAG)
    std::unique_ptr<ImageAsyncContext> context = UnwrapContext(env, info);
    if (context == nullptr || context->image == nullptr) {
        IMAGE_ERR("context is nullptr or Image native is nullptr");
        return result;
    }
    int32_t colorSpace;
    if (context->image->GetColorSpace(colorSpace) != SUCCESS) {
        IMAGE_ERR("Image native get color space failed");
        return result;
    }
    ColorManager::ColorSpaceName colorSpaceName = ImageUtils::SbCMColorSpaceType2ColorSpaceName(
        static_cast<CM_ColorSpaceType>(colorSpace));
    napi_create_int32(env, static_cast<int32_t>(colorSpaceName), &result);
#endif
    return result;
}

static bool CreateArrayBuffer(napi_env env, uint8_t* src, size_t srcLen, napi_value *res)
{
    if (src == nullptr || srcLen == 0) {
        IMAGE_LOGE("Invalid input src or srcLen");
        return false;
    }
    auto status = napi_create_external_arraybuffer(env, src, srcLen,
        [](napi_env env, void* data, void* hint) { }, nullptr, res);
    if (status != napi_ok) {
        IMAGE_LOGE("Failed to create arraybuffer");
        return false;
    }
    return true;
}

static napi_value BuildImageBufferData(napi_env env, NativeBufferData* bufferData)
{
    if (bufferData == nullptr) {
        IMAGE_LOGE("bufferData is nullptr");
        return nullptr;
    }

    napi_value result = nullptr;
    napi_create_object(env, &result);

    napi_value rowStrideArray = nullptr;
    if (napi_create_array_with_length(env, bufferData->rowStride.size(), &rowStrideArray) != napi_ok) {
        IMAGE_LOGE("Failed to create rowStride array");
        return nullptr;
    }
    for (size_t i = NUM0; i < bufferData->rowStride.size(); i++) {
        napi_value stride = nullptr;
        napi_create_int32(env, bufferData->rowStride[i], &stride);
        napi_set_element(env, rowStrideArray, i, stride);
    }
    napi_set_named_property(env, result, "rowStride", rowStrideArray);

    napi_value pixelStrideArray = nullptr;
    if (napi_create_array_with_length(env, bufferData->pixelStride.size(), &pixelStrideArray) != napi_ok) {
        IMAGE_LOGE("Failed to create pixelStride array");
        return nullptr;
    }
    for (size_t i = NUM0; i < bufferData->pixelStride.size(); i++) {
        napi_value stride = nullptr;
        napi_create_int32(env, bufferData->pixelStride[i], &stride);
        napi_set_element(env, pixelStrideArray, i, stride);
    }
    napi_set_named_property(env, result, "pixelStride", pixelStrideArray);

    napi_value byteBuffer = nullptr;
    if (!CreateArrayBuffer(env, bufferData->virAddr, bufferData->size, &byteBuffer)) {
        IMAGE_LOGE("Failed to create ArrayBuffer");
        return nullptr;
    }
    napi_set_named_property(env, result, "byteBuffer", byteBuffer);

    return result;
}

napi_value ImageNapi::JsGetBufferData(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    IMAGE_FUNCTION_IN();
    napi_get_null(env, &result);
    std::unique_ptr<ImageAsyncContext> context = UnwrapContext(env, info);
    if (context == nullptr || context->image == nullptr) {
        IMAGE_ERR("context is nullptr or Image native is nullptr");
        return result;
    }

    NativeBufferData* bufferData = context->image->GetBufferData();
    if (bufferData == nullptr) {
        IMAGE_LOGE("Failed to get buffer data from NativeImage");
        return result;
    }

    napi_value bufferDataObj = BuildImageBufferData(env, bufferData);
    if (bufferDataObj == nullptr) {
        IMAGE_LOGE("Failed to build ImageBufferData object");
        return result;
    }

    IMAGE_FUNCTION_OUT();
    return bufferDataObj;
}

#if !defined(CROSS_PLATFORM)

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
    napi_create_array_with_length(env, NUM3, &displayPrimariesX);
    bool status = true;
    status &= CreateArrayDouble(env, displayPrimariesX, staticMetadata.smpte2086.displayPrimaryRed.x, NUM0);
    status &= CreateArrayDouble(env, displayPrimariesX, staticMetadata.smpte2086.displayPrimaryGreen.x, NUM1);
    status &= CreateArrayDouble(env, displayPrimariesX, staticMetadata.smpte2086.displayPrimaryBlue.x, NUM2);
    status &= napi_set_named_property(env, metadataValue, "displayPrimariesX", displayPrimariesX) == napi_ok;
    napi_value displayPrimariesY = nullptr;
    napi_create_array_with_length(env, NUM3, &displayPrimariesY);
    status &= CreateArrayDouble(env, displayPrimariesY, staticMetadata.smpte2086.displayPrimaryRed.y, NUM0);
    status &= CreateArrayDouble(env, displayPrimariesY, staticMetadata.smpte2086.displayPrimaryGreen.y, NUM1);
    status &= CreateArrayDouble(env, displayPrimariesY, staticMetadata.smpte2086.displayPrimaryBlue.y, NUM2);
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
    for (uint32_t i = 0; i < NUM3; i++) {
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

static napi_status BuildHdrMetadataValue(napi_env env, napi_value argv[],
    std::shared_ptr<NativeImage> nativeImage, napi_value &metadataValue)
{
    uint32_t metadataKey = 0;
    napi_get_value_uint32(env, argv[NUM0], &metadataKey);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = nativeImage->GetBuffer();
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
    nVal->context = std::make_unique<ImageAsyncContext>();
    nVal->status = napi_unwrap(env, nVal->thisVar, reinterpret_cast<void**>(&(nVal->context->napi)));
    if (nVal->status != napi_ok) {
        IMAGE_LOGE("fail to unwrap context");
        return false;
    }
    if (nVal->context->napi == nullptr || nVal->context->napi->GetNative() == nullptr) {
        IMAGE_LOGE("prepareNapiEnv native image is nullptr");
        return false;
    }
    nVal->context->status = SUCCESS;
    return true;
}

napi_value ImageNapi::JsGetHdrMetadata(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_value argValue[NUM1];
    nVal.argc = NUM1;
    nVal.argv = argValue;
    nVal.status = napi_invalid_arg;
    napi_get_null(env, &nVal.result);
    if (!prepareNapiEnv(env, info, &nVal)) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_INVALID_PARAMETER, "Fail to unwrap context");
    }
    nVal.status = BuildHdrMetadataValue(env, nVal.argv, nVal.context->napi->native_, nVal.result);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(nVal.status),
        ImageNapiUtils::ThrowExceptionError(env, IMAGE_COPY_FAILED,
        "BuildHdrMetadataValue failed"),
        IMAGE_LOGE("BuildHdrMetadataValue failed"));
    return nVal.result;
}
#endif

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

    if (context->thisRef != nullptr) {
        napi_value thisVar;
        napi_get_reference_value(env, context->thisRef, &thisVar);
        napi_delete_reference(env, context->thisRef);
        if (thisVar != nullptr) {
            ImageNapi *tmp = nullptr;
            auto status_ = napi_remove_wrap(env, thisVar, reinterpret_cast<void**>(&tmp));
            if (status_ != napi_ok) {
                IMAGE_ERR("NAPI remove wrap failed status %{public}d", status_);
            }
        }
    }

    context->status = SUCCESS;
    IMAGE_FUNCTION_OUT();
    CommonCallbackRoutine(env, context, result);
}

napi_value ImageNapi::JsRelease(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    napi_value result = nullptr;
    size_t argc = NUM1;
    napi_value argv[NUM1] = {0};

    napi_get_undefined(env, &result);
    auto context = UnwrapContext(env, info, &argc, argv, true);
    if (context == nullptr) {
        IMAGE_ERR("fail to unwrap constructor_");
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

    if (JsCreateWork(env, "JsRelease", [](napi_env env, ImageAsyncContext* data) {},
        JSReleaseCallBack, context.get())) {
        context.release();
    }
    IMAGE_FUNCTION_OUT();
    return result;
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
static void TestGetComponentCallBack(napi_env env, napi_status status, ImageAsyncContext* context)
{
    if (context == nullptr) {
        IMAGE_ERR("Invalid input context");
        return;
    }
    napi_value result;
    napi_value array;
    void *nativePtr = nullptr;
    if (napi_create_arraybuffer(env, NUM1, &nativePtr, &array) != napi_ok || nativePtr == nullptr) {
        delete context;
        context = nullptr;
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

static void JsGetComponentCallBack(napi_env env, napi_status status, ImageAsyncContext* context)
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
static void JsGetComponentExec(napi_env env, ImageAsyncContext* context)
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

static bool JsGetComponentArgs(napi_env env, size_t argc, napi_value* argv, ImageAsyncContext* context)
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

napi_value ImageNapi::JsGetComponent(napi_env env, napi_callback_info info)
{
    IMAGE_FUNCTION_IN();
    napi_value result = nullptr;
    size_t argc = NUM2;
    napi_value argv[NUM2] = {0};

    napi_get_undefined(env, &result);
    auto context = UnwrapContext(env, info, &argc, argv);
    if (context == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, static_cast<int32_t>(napi_invalid_arg),
            "fail to unwrap constructor_ ");
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
