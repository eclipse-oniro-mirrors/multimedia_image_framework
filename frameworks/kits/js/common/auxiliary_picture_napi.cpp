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

#include <memory.h>
#include "auxiliary_picture_napi.h"
#include "media_errors.h"
#include "image_log.h"
#include "image_napi.h"
#include "image_napi_utils.h"
#include "pixel_map_napi.h"
#include "pixel_map.h"
#include "metadata_napi.h"
#include "color_space_object_convertor.h"
#include "image_utils.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "AuxiliaryPictureNapi"

namespace {
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
    constexpr uint32_t NUM_3 = 3;
}

namespace OHOS {
namespace Media {
static const std::string CLASS_NAME = "AuxiliaryPicture";
thread_local napi_ref AuxiliaryPictureNapi::sConstructor_ = nullptr;
thread_local std::shared_ptr<AuxiliaryPicture> AuxiliaryPictureNapi::sAuxiliaryPic_ = nullptr;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#endif

struct AuxiliaryPictureNapiAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    napi_ref error = nullptr;
    uint32_t status;
    AuxiliaryPictureNapi *nConstructor;
    std::shared_ptr<PixelMap> rPixelmap;
    std::shared_ptr<Picture> rPicture;
    std::shared_ptr<AuxiliaryPicture> auxPicture;
    void *arrayBuffer;
    size_t arrayBufferSize;
    Size size;
    AuxiliaryPictureType type;
    MetadataNapi *metadataNapi;
    std::shared_ptr<AuxiliaryPicture> rAuxiliaryPicture;
    std::shared_ptr<ImageMetadata> imageMetadata;
    MetadataType metadataType = MetadataType::EXIF;
    AuxiliaryPictureNapi *auxiliaryPictureNapi;
    AuxiliaryPictureInfo auxiliaryPictureInfo;
    std::shared_ptr<OHOS::ColorManager::ColorSpace> AuxColorSpace = nullptr;
};

using AuxiliaryPictureNapiAsyncContextPtr = std::unique_ptr<AuxiliaryPictureNapiAsyncContext>;

struct NapiValues {
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_value* argv = nullptr;
    size_t argc;
    int32_t refCount = 1;
    std::unique_ptr<AuxiliaryPictureNapiAsyncContext> context;
};

AuxiliaryPictureNapi::AuxiliaryPictureNapi():env_(nullptr)
{
    static std::atomic<uint32_t> currentId = 0;
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
}

AuxiliaryPictureNapi::~AuxiliaryPictureNapi()
{
    release();
}

napi_value AuxiliaryPictureNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor props[] = {
        DECLARE_NAPI_FUNCTION("readPixelsToBuffer", ReadPixelsToBuffer),
        DECLARE_NAPI_FUNCTION("writePixelsFromBuffer", WritePixelsFromBuffer),
        DECLARE_NAPI_FUNCTION("getType", GetType),
        DECLARE_NAPI_FUNCTION("getMetadata", GetMetadata),
        DECLARE_NAPI_FUNCTION("setMetadata", SetMetadata),
        DECLARE_NAPI_FUNCTION("getAuxiliaryPictureInfo", GetAuxiliaryPictureInfo),
        DECLARE_NAPI_FUNCTION("setAuxiliaryPictureInfo", SetAuxiliaryPictureInfo),
        DECLARE_NAPI_FUNCTION("release", Release),
    };
    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAuxiliaryPicture", CreateAuxiliaryPicture),
    };

    napi_value constructor = nullptr;

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                          Constructor, nullptr, IMG_ARRAY_SIZE(props),
                          props, &constructor)),
        nullptr, IMAGE_LOGE("define class fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_create_reference(env, constructor, 1, &sConstructor_)),
        nullptr, IMAGE_LOGE("create reference fail")
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
        nullptr, IMAGE_LOGE("set named property fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_properties(env, exports, IMG_ARRAY_SIZE(static_prop), static_prop)),
        nullptr, IMAGE_LOGE("define properties fail")
    );

    IMAGE_LOGD("Init success");
    return exports;
}

napi_value AuxiliaryPictureNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &thisVar);
    IMAGE_LOGD("Constructor IN");
    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    IMG_NAPI_CHECK_RET(IMG_IS_READY(status, thisVar), undefineVar);
    std::unique_ptr<AuxiliaryPictureNapi> pAuxiliaryPictureNapi = std::make_unique<AuxiliaryPictureNapi>();
    if (pAuxiliaryPictureNapi != nullptr) {
        pAuxiliaryPictureNapi->env_ = env;
        pAuxiliaryPictureNapi->nativeAuxiliaryPicture_ = sAuxiliaryPic_;
        if (pAuxiliaryPictureNapi->nativeAuxiliaryPicture_ == nullptr) {
            IMAGE_LOGE("Failed to set nativeAuxiliaryPicture_ with null. Maybe a reentrancy error");
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void *>(pAuxiliaryPictureNapi.get()),
                           AuxiliaryPictureNapi::Destructor, nullptr, nullptr);
        if (status != napi_ok) {
            IMAGE_LOGE("Failure wrapping js to native napi");
            return undefineVar;
        }
    }
    pAuxiliaryPictureNapi.release();
    return thisVar;
}

void AuxiliaryPictureNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        IMAGE_LOGD("Destructor PictureNapi");
        delete reinterpret_cast<AuxiliaryPictureNapi*>(nativeObject);
        nativeObject = nullptr;
    }
}

napi_value AuxiliaryPictureNapi::CreateAuxiliaryPicture(napi_env env, std::shared_ptr<AuxiliaryPicture> auxiliaryPic)
{
    if (AuxiliaryPictureNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        AuxiliaryPictureNapi::Init(env, exports);
    }

    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_status status;
    IMAGE_LOGD("CreateAuxiliaryPicture IN");
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        sAuxiliaryPic_ = auxiliaryPic;
        status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
    }
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("CreateAuxiliaryPicture | New instance could not be obtained");
        napi_get_undefined(env, &result);
    }

    return result;
}

STATIC_EXEC_FUNC(CreateAuxiliaryPicture)
{
    auto context = static_cast<AuxiliaryPictureNapiAsyncContext*>(data);
    InitializationOptions opts;
    opts.size = context->size;
    opts.editable = true;
    auto colors = static_cast<uint32_t*>(context->arrayBuffer);
    auto tmpPixelmap = PixelMap::Create(colors, context->arrayBufferSize, opts);
    std::shared_ptr<PixelMap> pixelmap = std::move(tmpPixelmap);
    auto picture = AuxiliaryPicture::Create(pixelmap, context->type, context->size);
    context->auxPicture = std::move(picture);
    if (IMG_NOT_NULL(context->auxPicture)) {
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
}

static bool ParseSize(napi_env env, napi_value root, int32_t& width, int32_t& height)
{
    if (!GET_INT32_BY_NAME(root, "width", width) || !GET_INT32_BY_NAME(root, "height", height)) {
        return false;
    }
    return true;
}

static AuxiliaryPictureType ParseAuxiliaryPictureType(int32_t val)
{
    if (val >= static_cast<int32_t>(AuxiliaryPictureType::GAINMAP)
        && val <= static_cast<int32_t>(AuxiliaryPictureType::FRAGMENT_MAP)) {
        return AuxiliaryPictureType(val);
    }
    return AuxiliaryPictureType::NONE;
}

napi_value AuxiliaryPictureNapi::CreateAuxiliaryPicture(napi_env env, napi_callback_info info)
{
    if (AuxiliaryPictureNapi::GetConstructor() == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        AuxiliaryPictureNapi::Init(env, exports);
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value constructor = nullptr;
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_3;
    napi_value argValue[NUM_3] = {0};
    uint32_t auxiType = 0;
    std::unique_ptr<AuxiliaryPictureNapiAsyncContext> asyncContext =
        std::make_unique<AuxiliaryPictureNapiAsyncContext>();
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Call napi_get_cb_info failed"));
    
    IMG_NAPI_CHECK_RET_D(argCount == NUM_3, ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"), IMAGE_LOGE("Invalid args count %{public}zu", argCount));

    status = napi_get_arraybuffer_info(env, argValue[NUM_0], &(asyncContext->arrayBuffer),
                                       &(asyncContext->arrayBufferSize));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to get auxiliary picture buffer"));
    if (asyncContext->arrayBuffer == nullptr || asyncContext->arrayBufferSize < NUM_0) {
        IMAGE_LOGE("Auxiliary picture buffer invalid or Auxiliary picture buffer size invalid");
        return result;
    }
    
    if (!ParseSize(env, argValue[NUM_1], asyncContext->size.width, asyncContext->size.height)) {
        IMAGE_LOGE("Fail to get auxiliary picture size");
        return result;
    }
    status = napi_get_value_uint32(env, argValue[NUM_2], &auxiType);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to get auxiliary picture Type"));
    if (auxiType < static_cast<int32_t>(AuxiliaryPictureType::GAINMAP)
        || auxiType > static_cast<int32_t>(AuxiliaryPictureType::FRAGMENT_MAP)) {
        IMAGE_LOGE("AuxiliaryFigureType is invalid");
        return result;
    }
    asyncContext->type = ParseAuxiliaryPictureType(auxiType);
    CreateAuxiliaryPictureExec(env, static_cast<void*>((asyncContext).get()));
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        sAuxiliaryPic_ = std::move(asyncContext->auxPicture);
        status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
    }
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to create picture sync"));
    return result;
}

napi_value AuxiliaryPictureNapi::GetType(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_get_undefined(env, &nVal.result);
    nVal.argc = NUM_0;
    IMAGE_LOGD("Call GetType");
    IMG_JS_ARGS(env, info, nVal.status, nVal.argc, nullptr, nVal.thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(nVal.status), nVal.result, IMAGE_LOGE("Fail to call napi_get_cb_info"));

    AuxiliaryPictureNapi* auxPictureNapi = nullptr;
    nVal.status = napi_unwrap(env, nVal.thisVar, reinterpret_cast<void**>(&auxPictureNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(nVal.status, auxPictureNapi), nVal.result, IMAGE_LOGE("Fail to unwrap context"));
    if (auxPictureNapi->nativeAuxiliaryPicture_ != nullptr) {
        auto auxType = auxPictureNapi->nativeAuxiliaryPicture_->GetType();
        IMAGE_LOGD("AuxiliaryPictureNapi::GetType %{public}d", auxType);
        if (static_cast<int32_t>(auxType) >= NUM_0 && auxType <= AuxiliaryPictureType::FRAGMENT_MAP) {
            napi_value type = nullptr;
            napi_create_object(env, &nVal.result);
            napi_create_int32(env, static_cast<int32_t>(auxType), &type);
            napi_set_named_property(env, nVal.result, "auxiliaryPictureType", type);
        }
    } else {
        IMAGE_LOGE("Native picture is nullptr!");
    }
    return nVal.result;
}

napi_value AuxiliaryPictureNapi::Release(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.result = nullptr;
    napi_get_undefined(env, &nVal.result);
    nVal.argc = NUM_0;
    IMAGE_LOGD("Call Release");
    std::unique_ptr<AuxiliaryPictureNapiAsyncContext> asyncContext =
        std::make_unique<AuxiliaryPictureNapiAsyncContext>();
    IMG_JS_ARGS(env, info, nVal.status, nVal.argc, nullptr, nVal.thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(nVal.status), nVal.result, IMAGE_LOGE("Fail to call napi_get_cb_info"));
    nVal.status = napi_unwrap(env, nVal.thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(nVal.status, asyncContext->nConstructor), nVal.result,
        IMAGE_LOGE("Fail to unwrap context"));
    asyncContext.release();
    return nVal.result;
}

static void CommonCallbackRoutine(napi_env env, AuxiliaryPictureNapiAsyncContext* &connect,
                                  const napi_value &valueParam)
{
    napi_value result[NUM_2] = {0};

    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    if (connect->status == SUCCESS) {
        result[NUM_1] = valueParam;
    } else {
        ImageNapiUtils::CreateErrorObj(env, result[0], connect->status,
                                       "There is generic napi failure!");
        napi_get_undefined(env, &result[1]);
    }

    if (connect->deferred) {
        if (connect->status == SUCCESS) {
            napi_resolve_deferred(env, connect->deferred, result[NUM_1]);
        } else {
            napi_reject_deferred(env, connect->deferred, result[NUM_0]);
        }
    }

    napi_delete_async_work(env, connect->work);

    delete connect;
    connect = nullptr;
}

static void GetMetadataComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("[AuxiliaryPicture]GetMetadata IN");
    auto context = static_cast<AuxiliaryPictureNapiAsyncContext*>(data);
    napi_value result = MetadataNapi::CreateMetadata(env, context->imageMetadata);

    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        IMAGE_LOGE("Get Metadata failed!");
        napi_get_undefined(env, &result);
    } else {
        context->status = SUCCESS;
    }
    IMAGE_LOGD("[AuxiliaryPicture]GetMetadata OUT");
    CommonCallbackRoutine(env, context, result);
}

napi_value AuxiliaryPictureNapi::GetMetadata(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_1;
    napi_value argValue[NUM_1] = {0};
    uint32_t metadataType = 0;

    IMAGE_LOGD("GetMetadata IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to get argment from info"));
    std::unique_ptr<AuxiliaryPictureNapiAsyncContext> asyncContext =
        std::make_unique<AuxiliaryPictureNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rAuxiliaryPicture = asyncContext->nConstructor->nativeAuxiliaryPicture_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rAuxiliaryPicture),
        nullptr, IMAGE_LOGE("Empty native auxiliary picture"));
    status = napi_get_value_uint32(env, argValue[NUM_0], &metadataType);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to get metadata type"));
    if (metadataType >= static_cast<int32_t>(MetadataType::EXIF)
        && metadataType <= static_cast<int32_t>(MetadataType::FRAGMENT)) {
        asyncContext->metadataType = MetadataType(metadataType);
    } else {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Invalid args metadata type");
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetMetadata",
        [](napi_env env, void* data) {
            auto context = static_cast<AuxiliaryPictureNapiAsyncContext*>(data);
            context->imageMetadata = context->rAuxiliaryPicture->GetMetadata(context->metadataType);
            context->status = SUCCESS;
        }, GetMetadataComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

static void SetMetadataComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("[AuxiliaryPicture]GetMetadata IN");
    auto context = static_cast<AuxiliaryPictureNapiAsyncContext*>(data);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        IMAGE_LOGE("Set Metadata failed!");
    } else {
        context->status = SUCCESS;
    }
    IMAGE_LOGD("[AuxiliaryPicture]GetMetadata OUT");
    CommonCallbackRoutine(env, context, result);
}

napi_value AuxiliaryPictureNapi::SetMetadata(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_2;
    napi_value argValue[NUM_2] = {0};
    uint32_t metadataType = 0;

    IMAGE_LOGD("SetMetadata IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to get argments from info"));
    std::unique_ptr<AuxiliaryPictureNapiAsyncContext> asyncContext =
        std::make_unique<AuxiliaryPictureNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rAuxiliaryPicture = asyncContext->nConstructor->nativeAuxiliaryPicture_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rAuxiliaryPicture),
        nullptr, IMAGE_LOGE("Empty native auxiliary picture"));

    status = napi_get_value_uint32(env, argValue[NUM_0], &metadataType);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to get metadata type"));
    if (metadataType >= static_cast<int32_t>(MetadataType::EXIF)
        && metadataType <= static_cast<int32_t>(MetadataType::FRAGMENT)) {
        asyncContext->metadataType = MetadataType(metadataType);
    } else {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Invalid args metadata type");
    }

    status = napi_unwrap(env, argValue[NUM_1], reinterpret_cast<void**>(&asyncContext->metadataNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->metadataNapi),
        nullptr, IMAGE_LOGE("Fail to unwrap MetadataNapi"));
    asyncContext->imageMetadata = asyncContext->metadataNapi->GetNativeMetadata();
    if (asyncContext->imageMetadata == nullptr) {
        IMAGE_LOGE("Empty native metadata");
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "SetMetadata",
        [](napi_env env, void* data) {
            auto context = static_cast<AuxiliaryPictureNapiAsyncContext*>(data);
            context->rAuxiliaryPicture->SetMetadata(context->metadataType, context->imageMetadata);
            context->status = SUCCESS;
        }, SetMetadataComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

static napi_value GetAuxiliaryPictureInfoNapiValue(napi_env env, void* data, std::shared_ptr<AuxiliaryPicture> picture)
{
    napi_value result = nullptr;
    auto auxiliaryPictureInfo = static_cast<AuxiliaryPictureInfo*>(data);
    napi_create_object(env, &result);
    napi_value auxiliaryPictureTypeValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(auxiliaryPictureInfo->auxiliaryPictureType),
        &auxiliaryPictureTypeValue);
    napi_set_named_property(env, result, "auxiliaryPictureType", auxiliaryPictureTypeValue);

    napi_value size = nullptr;
    napi_create_object(env, &size);

    napi_value sizeWidth = nullptr;
    napi_create_int32(env, auxiliaryPictureInfo->size.width, &sizeWidth);
    napi_set_named_property(env, size, "width", sizeWidth);

    napi_value sizeHeight = nullptr;
    napi_create_int32(env, auxiliaryPictureInfo->size.height, &sizeHeight);
    napi_set_named_property(env, size, "height", sizeHeight);

    napi_set_named_property(env, result, "size", size);

    napi_value rowStrideValue = nullptr;
    napi_create_int32(env, auxiliaryPictureInfo->rowStride, &rowStrideValue);
    napi_set_named_property(env, result, "rowStride", rowStrideValue);

    napi_value pixelFormatValue = nullptr;
    napi_create_int32(env, static_cast<int32_t>(auxiliaryPictureInfo->pixelFormat), &pixelFormatValue);
    napi_set_named_property(env, result, "pixelFormat", pixelFormatValue);
    std::shared_ptr<PixelMap> rPixelmap = nullptr;

    if (picture->GetContentPixel() == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_DATA_ABNORMAL, "Invalid pixelmap");
    }
    auto grCS = picture->GetContentPixel()->InnerGetGrColorSpacePtr();
    if (grCS == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_DATA_UNSUPPORT, "No colorspace in pixelmap");
    }
    auto resultValue = ColorManager::CreateJsColorSpaceObject(env, grCS);
    napi_value colorSpaceValue = reinterpret_cast<napi_value>(resultValue);
    napi_create_int32(env, static_cast<int32_t>(auxiliaryPictureInfo->colorSpace), &colorSpaceValue);
    napi_set_named_property(env, result, "colorSpace", colorSpaceValue);
    return result;
}

napi_value AuxiliaryPictureNapi::GetAuxiliaryPictureInfo(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_get_undefined(env, &nVal.result);
    nVal.argc = NUM_0;
    IMAGE_LOGD("Call GetAuxiliaryPictureInfo");
    IMG_JS_ARGS(env, info, nVal.status, nVal.argc, nullptr, nVal.thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(nVal.status), nullptr, IMAGE_LOGE("Call napi_get_cb_info failed"));
    std::unique_ptr<AuxiliaryPictureNapi> auxiliaryPictureNapi = nullptr;
    nVal.status = napi_unwrap(env, nVal.thisVar, reinterpret_cast<void**>(&auxiliaryPictureNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(nVal.status, auxiliaryPictureNapi),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(nVal.status, auxiliaryPictureNapi->nativeAuxiliaryPicture_),
        nullptr, IMAGE_LOGE("Empty native auxiliarypicture"));
    if (auxiliaryPictureNapi->nativeAuxiliaryPicture_ != nullptr) {
        AuxiliaryPictureInfo auxiliaryPictureInfo =
            auxiliaryPictureNapi->nativeAuxiliaryPicture_->GetAuxiliaryPictureInfo();
        nVal.result = GetAuxiliaryPictureInfoNapiValue(env, &auxiliaryPictureInfo,
            auxiliaryPictureNapi->nativeAuxiliaryPicture_);
    } else {
        IMAGE_LOGE("Native auxiliarypicture is nullptr!");
    }
    auxiliaryPictureNapi.release();
    return nVal.result;
}

static PixelFormat ParsePixelFormat(int32_t val)
{
    if (val >= static_cast<int32_t>(PixelFormat::ARGB_8888) && val <= static_cast<int32_t>(PixelFormat::CMYK)) {
        return PixelFormat(val);
    }
    return PixelFormat::UNKNOWN;
}

static void ParseColorSpace(napi_env env, napi_value val, AuxiliaryPictureNapiAsyncContext* context)
{
#ifdef IMAGE_COLORSPACE_FLAG
    context->AuxColorSpace = ColorManager::GetColorSpaceByJSObject(env, val);
    if (context->AuxColorSpace == nullptr) {
        ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "ColorSpace mismatch");
    }
    context->rPixelmap->InnerSetColorSpace(*(context->AuxColorSpace));
#else
    ImageNapiUtils::ThrowExceptionError(
        env, ERR_INVALID_OPERATION, "Unsupported operation");
#endif
}

static bool ParseAuxiliaryPictureInfo(napi_env env, napi_value result, napi_value root,
    AuxiliaryPictureNapiAsyncContext* auxiliaryPictureNapiAsyncContext)
{
    uint32_t tmpNumber = 0;
    napi_value tmpValue = nullptr;
    auto context = static_cast<AuxiliaryPictureNapiAsyncContext*>(auxiliaryPictureNapiAsyncContext);

    if (!GET_UINT32_BY_NAME(root, "auxiliaryPictureType", tmpNumber)) {
        IMAGE_LOGI("No auxiliaryPictureType in auxiliaryPictureInfo");
        return false;
    }
    context->auxiliaryPictureInfo.auxiliaryPictureType = ParseAuxiliaryPictureType(tmpNumber);

    if (!GET_NODE_BY_NAME(root, "size", tmpValue)) {
        return false;
    }
    if (!ParseSize(env, tmpValue, context->auxiliaryPictureInfo.size.width,
        context->auxiliaryPictureInfo.size.height)) {
        return false;
    }

    tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "rowStride", tmpNumber)) {
        IMAGE_LOGI("No rowStride in auxiliaryPictureInfo");
    }
    context->auxiliaryPictureInfo.rowStride = tmpNumber;

    tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "pixelFormat", tmpNumber)) {
        IMAGE_LOGI("No pixelFormat in auxiliaryPictureInfo");
    }
    context->auxiliaryPictureInfo.pixelFormat = ParsePixelFormat(tmpNumber);

    context->rPixelmap = context->auxPicture->GetContentPixel();
    napi_value auxColorSpace = nullptr;
    if (!GET_NODE_BY_NAME(root, "colorSpace", auxColorSpace)) {
        IMAGE_LOGI("No colorSpace in auxiliaryPictureInfo");
    }
    ParseColorSpace(env, auxColorSpace, context);
    return true;
}
 
napi_value AuxiliaryPictureNapi::SetAuxiliaryPictureInfo(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_2;
    napi_value argValue[NUM_2] = {0};

    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Call napi_get_cb_info failed"));
    std::unique_ptr<AuxiliaryPictureNapiAsyncContext> asyncContext =
        std::make_unique<AuxiliaryPictureNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->auxPicture = asyncContext->nConstructor->nativeAuxiliaryPicture_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->auxPicture),
        nullptr, IMAGE_LOGE("Empty native auxiliary picture"));
    IMG_NAPI_CHECK_RET_D(ParseAuxiliaryPictureInfo(env, result, argValue[NUM_0], asyncContext.get()),
        nullptr, IMAGE_LOGE("AuxiliaryPictureInfo mismatch"));
    
    if (status == napi_ok) {
        asyncContext->auxPicture->SetAuxiliaryPictureInfo(asyncContext->auxiliaryPictureInfo);
    } else {
        IMAGE_LOGE("Failed to call napi_unwrap for auxilianypictureinfo");
    }
    return result;
}

static void ReadPixelsToBufferComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<AuxiliaryPictureNapiAsyncContext*>(data);

    if (context->status == SUCCESS &&
        !ImageNapiUtils::CreateArrayBuffer(env, context->arrayBuffer, context->arrayBufferSize, &result)) {
        context->status = ERROR;
        IMAGE_LOGE("Fail to create napi arraybuffer!");
        napi_get_undefined(env, &result);
    }

    delete[] static_cast<uint8_t*>(context->arrayBuffer);
    context->arrayBuffer = nullptr;
    context->arrayBufferSize = 0;
    CommonCallbackRoutine(env, context, result);
}

napi_value AuxiliaryPictureNapi::ReadPixelsToBuffer(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to get argments from info"));

    std::unique_ptr<AuxiliaryPictureNapiAsyncContext> asyncContext =
        std::make_unique<AuxiliaryPictureNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rAuxiliaryPicture = asyncContext->nConstructor->nativeAuxiliaryPicture_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rAuxiliaryPicture),
        nullptr, IMAGE_LOGE("Empty native auxiliary picture"));

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "ReadPixelsToBuffer",
        [](napi_env env, void *data) {
            auto context = static_cast<AuxiliaryPictureNapiAsyncContext*>(data);
            AuxiliaryPictureInfo info = context->rAuxiliaryPicture->GetAuxiliaryPictureInfo();
            context->arrayBufferSize = info.size.width * info.size.height * ImageUtils::GetPixelBytes(info.pixelFormat);
            context->arrayBuffer = new uint8_t[context->arrayBufferSize];
            if (context->arrayBuffer != nullptr) {
                context->status = context->rAuxiliaryPicture->ReadPixels(
                    context->arrayBufferSize, static_cast<uint8_t*>(context->arrayBuffer));
            } else {
                context->status = ERR_MEDIA_MALLOC_FAILED;
                IMAGE_LOGE("Fail to malloc memory for arraybuffer");
            }
        }, ReadPixelsToBufferComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

static void EmptyResultComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<AuxiliaryPictureNapiAsyncContext*>(data);
    CommonCallbackRoutine(env, context, result);
}

napi_value AuxiliaryPictureNapi::WritePixelsFromBuffer(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_1;
    napi_value argValue[NUM_1] = {0};

    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to get argments from info"));

    std::unique_ptr<AuxiliaryPictureNapiAsyncContext> asyncContext =
        std::make_unique<AuxiliaryPictureNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rAuxiliaryPicture = asyncContext->nConstructor->nativeAuxiliaryPicture_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rAuxiliaryPicture),
        nullptr, IMAGE_LOGE("Empty native auxiliary picture"));
    status = napi_get_arraybuffer_info(env, argValue[NUM_0],
        &(asyncContext->arrayBuffer), &(asyncContext->arrayBufferSize));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to get buffer info"));

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "WritePixelsFromBuffer",
        [](napi_env env, void *data) {
            auto context = static_cast<AuxiliaryPictureNapiAsyncContext*>(data);
            context->status = context->rAuxiliaryPicture->WritePixels(
                static_cast<uint8_t*>(context->arrayBuffer), context->arrayBufferSize);
        }, EmptyResultComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

void AuxiliaryPictureNapi::release()
{
    if (!isRelease) {
        if (nativeAuxiliaryPicture_ != nullptr) {
            nativeAuxiliaryPicture_ = nullptr;
        }
        isRelease = true;
    }
}
}  // namespace Media
}  // namespace OHOS
