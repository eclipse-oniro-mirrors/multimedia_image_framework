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

#include "picture_napi.h"
#include "media_errors.h"
#include "image_log.h"
#include "image_napi_utils.h"
#include "image_napi.h"
#include "pixel_map_napi.h"
#include "auxiliary_picture_napi.h"
#include "auxiliary_picture.h"
#include "napi_message_sequence.h"
#include "metadata.h"
#include "metadata_napi.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PictureNapi"

namespace {
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
}

namespace OHOS {
namespace Media {
static const std::string CREATE_PICTURE_FROM_PARCEL = "createPictureFromParcel";
static const std::map<std::string, std::set<uint32_t>> ETS_API_ERROR_CODE = {
    {CREATE_PICTURE_FROM_PARCEL, {62980096, 62980105, 62980115, 62980097,
        62980177, 62980178, 62980179, 62980180, 62980246}}
};
static const std::string CLASS_NAME = "Picture";
thread_local napi_ref PictureNapi::sConstructor_ = nullptr;
thread_local std::shared_ptr<Picture> PictureNapi::sPicture_ = nullptr;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
NAPI_MessageSequence* messageSequence = nullptr;
#endif

struct PictureAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    napi_ref error = nullptr;
    uint32_t status;
    std::shared_ptr<Picture> rPicture;
    PictureNapi *nConstructor;
    std::shared_ptr<PixelMap> rPixelMap;
    MetadataNapi *metadataNapi;
    std::shared_ptr<ImageMetadata> imageMetadata;
    MetadataType metadataType = MetadataType::EXIF;
};

using PictureAsyncContextPtr = std::unique_ptr<PictureAsyncContext>;

napi_ref PictureNapi::auxiliaryPictureTypeRef_ = nullptr;
napi_ref PictureNapi::metadataTypeRef_ = nullptr;

struct PictureEnum {
    std::string name;
    int32_t numVal;
    std::string strVal;
};

static std::vector<struct PictureEnum> auxiliaryPictureTypeMap = {
    {"GAINMAP", static_cast<uint32_t>(AuxiliaryPictureType::GAINMAP), ""},
    {"DEPTH_MAP", static_cast<uint32_t>(AuxiliaryPictureType::DEPTH_MAP), ""},
    {"UNREFOCUS_MAP", static_cast<uint32_t>(AuxiliaryPictureType::UNREFOCUS_MAP), ""},
    {"LINEAR_MAP", static_cast<uint32_t>(AuxiliaryPictureType::LINEAR_MAP), ""},
    {"FRAGMENT_MAP", static_cast<uint32_t>(AuxiliaryPictureType::FRAGMENT_MAP), ""},
};

static std::vector<struct PictureEnum> metadataTypeMap = {
    {"EXIF", static_cast<uint32_t>(MetadataType::EXIF), ""},
    {"FRAGMENT", static_cast<uint32_t>(MetadataType::FRAGMENT), ""},
};

struct NapiValues {
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    napi_value* argv = nullptr;
    size_t argc;
    int32_t refCount = 1;
    std::unique_ptr<PictureAsyncContext> context;
};

static napi_value CreateEnumTypeObject(napi_env env,
    napi_valuetype type, napi_ref* ref, std::vector<struct PictureEnum> pictureEnumMap)
{
    napi_value result = nullptr;
    napi_status status;
    std::string propName;
    status = napi_create_object(env, &result);
    if (status == napi_ok) {
        for (auto imgEnum : pictureEnumMap) {
            napi_value enumNapiValue = nullptr;
            if (type == napi_string) {
                status = napi_create_string_utf8(env, imgEnum.strVal.c_str(),
                    NAPI_AUTO_LENGTH, &enumNapiValue);
            } else if (type == napi_number) {
                status = napi_create_int32(env, imgEnum.numVal, &enumNapiValue);
            } else {
                IMAGE_LOGE("Unsupported type %{public}d!", type);
                break;
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
            int32_t refCount = 1;
            status = napi_create_reference(env, result, refCount, ref);
            if (status == napi_ok) {
                return result;
            }
        }
    }
    IMAGE_LOGE("CreateEnumTypeObject is Failed!");
    napi_get_undefined(env, &result);
    return result;
}

static void CommonCallbackRoutine(napi_env env, PictureAsyncContext* &asyncContext, const napi_value &valueParam)
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

static ImageType ParserImageType(napi_env env, napi_value argv)
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

static bool prepareNapiEnv(napi_env env, napi_callback_info info, struct NapiValues* nVal)
{
    napi_get_undefined(env, &(nVal->result));
    nVal->status = napi_get_cb_info(env, info, &(nVal->argc), nVal->argv, &(nVal->thisVar), nullptr);
    if (nVal->status != napi_ok) {
        IMAGE_LOGE("Fail to napi_get_cb_info");
        return false;
    }
    nVal->context = std::make_unique<PictureAsyncContext>();
    nVal->status = napi_unwrap(env, nVal->thisVar, reinterpret_cast<void**>(&(nVal->context->nConstructor)));
    if (nVal->status != napi_ok) {
        IMAGE_LOGE("Fail to unwrap context");
        return false;
    }
    nVal->context->status = SUCCESS;
    return true;
}

PictureNapi::PictureNapi():env_(nullptr)
{
    static std::atomic<uint32_t> currentId = 0;
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
}

PictureNapi::~PictureNapi()
{
    release();
}

napi_value PictureNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor props[] = {
        DECLARE_NAPI_FUNCTION("getMainPixelmap", GetMainPixelmap),
        DECLARE_NAPI_FUNCTION("getHdrComposedPixelmap", GetHdrComposedPixelMap),
        DECLARE_NAPI_FUNCTION("getGainmapPixelmap", GetGainmapPixelmap),
        DECLARE_NAPI_FUNCTION("getAuxiliaryPicture", GetAuxiliaryPicture),
        DECLARE_NAPI_FUNCTION("setAuxiliaryPicture", SetAuxiliaryPicture),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_FUNCTION("marshalling", Marshalling),
        DECLARE_NAPI_FUNCTION("getMetadata", GetMetadata),
        DECLARE_NAPI_FUNCTION("setMetadata", SetMetadata),
    };
    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createPicture", CreatePicture),
        DECLARE_NAPI_STATIC_FUNCTION("createPictureFromParcel", CreatePictureFromParcel),
        DECLARE_NAPI_PROPERTY("AuxiliaryPictureType", CreateEnumTypeObject(env, napi_number,
            &auxiliaryPictureTypeRef_, auxiliaryPictureTypeMap)),
        DECLARE_NAPI_PROPERTY("MetadataType", CreateEnumTypeObject(env, napi_number,
            &metadataTypeRef_, metadataTypeMap)),
    };

    napi_value constructor = nullptr;

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr, IMG_ARRAY_SIZE(props),
        props, &constructor)), nullptr, IMAGE_LOGE("define class fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_create_reference(env, constructor, 1, &sConstructor_)),
        nullptr, IMAGE_LOGE("create reference fail")
    );

    napi_value global = nullptr;
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(napi_get_global(env, &global)), nullptr, IMAGE_LOGE("Init:get global fail"));

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

napi_value PictureNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &thisVar);
    IMAGE_LOGD("Constructor IN");
    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    IMG_NAPI_CHECK_RET(IMG_IS_READY(status, thisVar), undefineVar);
    std::unique_ptr<PictureNapi> pPictureNapi = std::make_unique<PictureNapi>();
    if (pPictureNapi != nullptr) {
        pPictureNapi->env_ = env;
        pPictureNapi->nativePicture_ = sPicture_;
        if (pPictureNapi->nativePicture_ == nullptr) {
            IMAGE_LOGE("Failed to set nativePicture_ with null. Maybe a reentrancy error");
        }
        status = napi_wrap(env, thisVar, reinterpret_cast<void *>(pPictureNapi.get()),
                           PictureNapi::Destructor, nullptr, nullptr);
        if (status != napi_ok) {
            IMAGE_LOGE("Failure wrapping js to native napi");
            return undefineVar;
        }
    }
    pPictureNapi.release();
    return thisVar;
}

void PictureNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        IMAGE_LOGD("Destructor PictureNapi");
        delete reinterpret_cast<PictureNapi*>(nativeObject);
        nativeObject = nullptr;
    }
}

napi_value PictureNapi::CreatePicture(napi_env env, std::shared_ptr<Picture> picture)
{
    if (sConstructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PictureNapi::Init(env, exports);
    }
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_status status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        if (picture != nullptr) {
            sPicture_ = std::move(picture);
            status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
        } else {
            status = napi_invalid_arg;
            IMAGE_LOGE("New PictureNapi Instance picture is nullptr");
            napi_get_undefined(env, &result);
        }
    }
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("CreatePicture | New instance could not be obtained");
        napi_get_undefined(env, &result);
    }
    return result;
}

static AuxiliaryPictureType ParseAuxiliaryPictureType(int32_t val)
{
    if (val >= static_cast<int32_t>(AuxiliaryPictureType::GAINMAP)
        && val<= static_cast<int32_t>(AuxiliaryPictureType::FRAGMENT_MAP)) {
        return AuxiliaryPictureType(val);
    }

    return AuxiliaryPictureType::NONE;
}

static void PreparePicNapiEnv(napi_env env)
{
    napi_value globalValue;
    napi_get_global(env, &globalValue);
    napi_value func;
    napi_get_named_property(env, globalValue, "requireNapi", &func);

    napi_value picture;
    napi_create_string_utf8(env, "multimedia.image", NAPI_AUTO_LENGTH, &picture);
    napi_value funcArgv[NUM_1] = { picture };
    napi_value returnValue;
    napi_call_function(env, globalValue, func, NUM_1, funcArgv, &returnValue);
}

int32_t PictureNapi::CreatePictureNapi(napi_env env, napi_value* result)
{
    napi_value constructor = nullptr;
    napi_status status = napi_ok;
    PreparePicNapiEnv(env);

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok && constructor != nullptr) {
        status = napi_new_instance(env, constructor, NUM_0, nullptr, result);
    }

    if (status != napi_ok || result == nullptr) {
        IMAGE_LOGE("CreatePictureNapi new instance failed");
        napi_get_undefined(env, result);
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    return SUCCESS;
}

void PictureNapi::SetNativePicture(std::shared_ptr<Picture> picture)
{
    nativePicture_ = picture;
}

napi_value PictureNapi::GetAuxiliaryPicture(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    uint32_t auxiType = 0;

    IMAGE_LOGD("GetAuxiliaryPicture IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to arg info"));
    PictureNapi* pictureNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pictureNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pictureNapi), result, IMAGE_LOGE("fail to unwrap PictureNapi"));
    status = napi_get_value_uint32(env, argValue[NUM_0], &auxiType);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to get auxiliary picture Type"));

    AuxiliaryPictureType type = ParseAuxiliaryPictureType(auxiType);

    if (pictureNapi->nativePicture_ != nullptr) {
        auto auxiliaryPic = pictureNapi->nativePicture_->GetAuxiliaryPicture(type);
        if (auxiliaryPic != nullptr) {
            result = AuxiliaryPictureNapi::CreateAuxiliaryPicture(env, std::move(auxiliaryPic));
        } else {
            IMAGE_LOGE("native auxiliary picture is nullptr!");
        }
    } else {
        IMAGE_LOGE("native picture is nullptr!");
    }
    return result;
}

std::shared_ptr<Picture> PictureNapi::GetPicture(napi_env env, napi_value picture)
{
    std::unique_ptr<PictureNapi> pictureNapi = nullptr;
    napi_status status = napi_unwrap(env, picture, reinterpret_cast<void**>(&pictureNapi));
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("GetPicture napi unwrap failed");
        return nullptr;
    }
    if (pictureNapi == nullptr) {
        IMAGE_LOGE("GetPixelMap pixmapNapi is nullptr");
        return nullptr;
    }
    auto pictureNapiPtr = pictureNapi.release();
    if (pictureNapiPtr == nullptr) {
        IMAGE_LOGE("GetPicture pictureNapi is nullptr");
        return nullptr;
    }
    return pictureNapiPtr->nativePicture_;
}

napi_value PictureNapi::SetAuxiliaryPicture(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;
    uint32_t auxiType = 0;

    IMAGE_LOGD("SetAuxiliaryPictureSync IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    PictureNapi* pictureNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&pictureNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pictureNapi), result, IMAGE_LOGE("fail to unwrap PictureNapi"));

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to arg info"));
    status = napi_get_value_uint32(env, argValue[NUM_0], &auxiType);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to get auxiliary picture Type"));
    AuxiliaryPictureType type = ParseAuxiliaryPictureType(auxiType);

    AuxiliaryPictureNapi* auxiliaryPictureNapi = nullptr;
    status = napi_unwrap(env, argValue[NUM_1], reinterpret_cast<void**>(&auxiliaryPictureNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, pictureNapi), result,
                         IMAGE_LOGE("fail to unwrap AuxiliaryPictureNapi"));

    if (pictureNapi->nativePicture_ != nullptr) {
        auto auxiliaryPicturePtr = auxiliaryPictureNapi->GetNativeAuxiliaryPic();
        if (auxiliaryPicturePtr != nullptr) {
            if (type != auxiliaryPicturePtr->GetAuxiliaryPictureInfo().auxiliaryPictureType) {
                IMAGE_LOGE("The type does not match the auxiliary picture type!");
            } else {
                pictureNapi->nativePicture_->SetAuxiliaryPicture(auxiliaryPicturePtr);
            }
        } else {
            IMAGE_LOGE("native auxiliary picture is nullptr!");
        }
    } else {
        IMAGE_LOGE("native picture is nullptr!");
    }

    return result;
}

STATIC_EXEC_FUNC(CreatePicture)
{
    IMAGE_INFO("CreatePictureEX IN");
    auto context = static_cast<PictureAsyncContext*>(data);
    auto picture = Picture::Create(context->rPixelMap);
    context->rPicture = std::move(picture);
    IMAGE_INFO("CreatePictureEX OUT");
    if (IMG_NOT_NULL(context->rPicture)) {
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
}

static void BuildContextError(napi_env env, napi_ref &error, const std::string errMsg, const int32_t errCode)
{
    IMAGE_LOGE("%{public}s", errMsg.c_str());
    napi_value tmpError;
    ImageNapiUtils::CreateErrorObj(env, tmpError, errCode, errMsg);
    napi_create_reference(env, tmpError, NUM_1, &(error));
}

napi_value PictureNapi::CreatePicture(napi_env env, napi_callback_info info)
{
    IMAGE_INFO("CreatePicture IN");
    if (sConstructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PictureNapi::Init(env, exports);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_value constructor = nullptr;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMAGE_LOGD("CreatePicture IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    IMG_NAPI_CHECK_RET_D(argCount == NUM_1, ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER,
        "Invalid args count"), IMAGE_LOGE("Invalid args count %{public}zu", argCount));
    std::unique_ptr<PictureAsyncContext> asyncContext = std::make_unique<PictureAsyncContext>();
    if (ParserImageType(env, argValue[NUM_0]) == ImageType::TYPE_PIXEL_MAP) {
        asyncContext->rPixelMap = PixelMapNapi::GetPixelMap(env, argValue[NUM_0]);
        if (asyncContext->rPixelMap == nullptr) {
            BuildContextError(env, asyncContext->error, "input image type mismatch", ERR_IMAGE_GET_DATA_ABNORMAL);
        }
    } else {
        BuildContextError(env, asyncContext->error, "input image type mismatch",
            ERR_IMAGE_GET_DATA_ABNORMAL);
    }
    CreatePictureExec(env, static_cast<void*>((asyncContext).get()));
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        sPicture_ = std::move(asyncContext->rPicture);
        status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
    }
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to create picture sync"));
    IMAGE_INFO("CreatePicture OUT");
    return result;
}

napi_value PictureNapi::ThrowExceptionError(napi_env env,
    const std::string &tag, const std::uint32_t &code, const std::string &info)
{
    auto errNode = ETS_API_ERROR_CODE.find(tag);
    if (errNode != ETS_API_ERROR_CODE.end() &&
        errNode->second.find(code) != errNode->second.end()) {
        return ImageNapiUtils::ThrowExceptionError(env, code, info);
    }
    return ImageNapiUtils::ThrowExceptionError(env, ERROR, "Operation failed");
}

napi_value PictureNapi::CreatePictureFromParcel(napi_env env, napi_callback_info info)
{
    if (sConstructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        PictureNapi::Init(env, exports);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMAGE_LOGD("Call CreatePictureFromParcel");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    if (!IMG_IS_OK(status) || argCount != NUM_1) {
        return PictureNapi::ThrowExceptionError(env,
            CREATE_PICTURE_FROM_PARCEL, ERR_IMAGE_INVALID_PARAMETER, "Fail to napi_get_cb_info");
    }
    napi_unwrap(env, argValue[NUM_0], (void **)&messageSequence);
    auto messageParcel = messageSequence->GetMessageParcel();
    if (messageParcel == nullptr) {
        return PictureNapi::ThrowExceptionError(env,
            CREATE_PICTURE_FROM_PARCEL, ERR_IPC, "get parcel failed");
    }
    PICTURE_ERR error;
    auto picture = Picture::Unmarshalling(*messageParcel, error);
    if (!IMG_NOT_NULL(picture)) {
        return PictureNapi::ThrowExceptionError(env,
            CREATE_PICTURE_FROM_PARCEL, error.errorCode, error.errorInfo);
    }
    std::shared_ptr<OHOS::Media::Picture> picturePtr(picture);
    sPicture_ = std::move(picturePtr);
    napi_value constructor = nullptr;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        if (sPicture_ == nullptr) {
            status = napi_invalid_arg;
            IMAGE_LOGE("NewPictureNapiInstance picture is nullptr");
        } else {
            status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
        }
    }
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("New instance could not be obtained");
        return PictureNapi::ThrowExceptionError(env,
            CREATE_PICTURE_FROM_PARCEL, ERR_IMAGE_NAPI_ERROR, "New instance could not be obtained");
    }
    return result;
}
napi_value PictureNapi::GetMainPixelmap(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_get_undefined(env, &nVal.result);
    nVal.argc = NUM_0;
    IMG_JS_ARGS(env, info, nVal.status, nVal.argc, nullptr, nVal.thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(nVal.status), nVal.result, IMAGE_LOGE("Fail to arg info"));

    PictureNapi* pictureNapi = nullptr;
    nVal.status = napi_unwrap(env, nVal.thisVar, reinterpret_cast<void**>(&pictureNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(nVal.status, pictureNapi), nVal.result, IMAGE_LOGE("Fail to unwrap context"));
    
    if (pictureNapi->nativePicture_ != nullptr) {
        auto pixelmap = pictureNapi->nativePicture_->GetMainPixel();
        nVal.result = PixelMapNapi::CreatePixelMap(env, pixelmap);
    } else {
        IMAGE_LOGE("Native picture is nullptr!");
    }
    return nVal.result;
}

napi_value PictureNapi::Release(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    nVal.result = nullptr;
    napi_get_undefined(env, &nVal.result);
    nVal.argc = NUM_0;
    std::unique_ptr<PictureAsyncContext> asyncContext = std::make_unique<PictureAsyncContext>();
    IMG_JS_ARGS(env, info, nVal.status, nVal.argc, nullptr, nVal.thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(nVal.status), nVal.result, IMAGE_LOGE("Fail to call napi_get_cb_info"));
    nVal.status = napi_unwrap(env, nVal.thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(nVal.status, asyncContext->nConstructor),
                         nVal.result, IMAGE_LOGE("Fail to unwrap context"));
    asyncContext.release();
    return nVal.result;
}

napi_value PictureNapi::Marshalling(napi_env env, napi_callback_info info)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    NapiValues nVal;
    nVal.argc = NUM_1;
    napi_value argValue[NUM_1] = {0};
    nVal.argv = argValue;
    if (!prepareNapiEnv(env, info, &nVal)) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Fail to unwrap context");
    }
    nVal.context->rPicture = nVal.context->nConstructor->nativePicture_;
    if (nVal.argc != NUM_0 && nVal.argc != NUM_1) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Invalid args count");
    }
    NAPI_MessageSequence *napiSequence = nullptr;
    napi_get_cb_info(env, info, &nVal.argc, nVal.argv, nullptr, nullptr);
    napi_unwrap(env, nVal.argv[0], reinterpret_cast<void**>(&napiSequence));
        auto messageParcel = napiSequence->GetMessageParcel();
    if (messageParcel == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IPC, "Marshalling picture to parcel failed.");
    }
    bool st = nVal.context->rPicture->Marshalling(*messageParcel);
    if (!st) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IPC, "Marshalling picture to parcel failed.");
    }
    return nVal.result;
#else
    return napi_value(nullptr);
#endif
}

static void CreateHDRComposedPixelmapComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<PictureAsyncContext*>(data);

    if (context->rPixelMap != nullptr) {
        result = PixelMapNapi::CreatePixelMap(env, context->rPixelMap);
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value PictureNapi::GetHdrComposedPixelMap(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;

    IMAGE_LOGD("GetHdrComposedPixelMap IN");
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<PictureAsyncContext> asyncContext = std::make_unique<PictureAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor), result,
                         IMAGE_LOGE("Fail to napi_unwrap context"));
    asyncContext->rPicture = asyncContext->nConstructor->nativePicture_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPicture),
        nullptr, IMAGE_LOGE("Empty native pixelmap"));
    if (asyncContext->rPicture->GetAuxiliaryPicture(AuxiliaryPictureType::GAINMAP) == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNKNOWN, "There is no GAINMAP");
    }
    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetHdrComposedPixelMap",
        [](napi_env env, void *data) {
            auto context = static_cast<PictureAsyncContext*>(data);
            auto tmpixel = context->rPicture->GetHdrComposedPixelMap();
            context->rPixelMap = std::move(tmpixel);
            context->status = SUCCESS;
        }, CreateHDRComposedPixelmapComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));

    return result;
}

napi_value PictureNapi::GetGainmapPixelmap(napi_env env, napi_callback_info info)
{
    NapiValues nVal;
    napi_get_undefined(env, &nVal.result);
    IMAGE_LOGD("GetGainmapPixelmap");
    nVal.argc = NUM_0;
    IMG_JS_ARGS(env, info, nVal.status, nVal.argc, nullptr, nVal.thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(nVal.status), nVal.result, IMAGE_LOGE("Parameter acquisition failed"));

    PictureNapi* pictureNapi = nullptr;
    nVal.status = napi_unwrap(env, nVal.thisVar, reinterpret_cast<void**>(&pictureNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(nVal.status, pictureNapi),
        nVal.result, IMAGE_LOGE("Failed to retrieve native pointer"));

    if (pictureNapi->nativePicture_ != nullptr) {
        auto gainpixelmap = pictureNapi->nativePicture_->GetGainmapPixelMap();
        nVal.result = PixelMapNapi::CreatePixelMap(env, gainpixelmap);
    } else {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_MEDIA_UNKNOWN, "Picture is a null pointer");
    }
    return nVal.result;
}

static void GetMetadataComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("[Picture]GetMetadata IN");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<PictureAsyncContext*>(data);
    if (context->imageMetadata != nullptr) {
        result = MetadataNapi::CreateMetadata(env, context->imageMetadata);
    }

    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        IMAGE_LOGE("Get Metadata failed!");
    } else {
        context->status = SUCCESS;
    }
    IMAGE_LOGD("[Picture]GetMetadata OUT");
    CommonCallbackRoutine(env, context, result);
}

napi_value PictureNapi::GetMetadata(napi_env env, napi_callback_info info)
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
    std::unique_ptr<PictureAsyncContext> asyncContext = std::make_unique<PictureAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rPicture = asyncContext->nConstructor->nativePicture_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPicture), nullptr, IMAGE_LOGE("Empty native picture"));
    status = napi_get_value_uint32(env, argValue[NUM_0], &metadataType);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to get metadata type"));
    if (metadataType != static_cast<int32_t>(MetadataType::EXIF)) {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_DECODE_EXIF_UNSUPPORT, "Unsupport MetadataType");
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetMetadata",
        [](napi_env env, void* data) {
            auto context = static_cast<PictureAsyncContext*>(data);
            context->imageMetadata = std::reinterpret_pointer_cast<ImageMetadata>(context->rPicture->GetExifMetadata());
        }, GetMetadataComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

static void SetMetadataComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("[Picture]SetMetadata IN");
    auto context = static_cast<PictureAsyncContext*>(data);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        IMAGE_LOGE("Set Metadata failed!");
    }
    IMAGE_LOGD("[Picture]SetMetadata OUT");
    CommonCallbackRoutine(env, context, result);
}

napi_value PictureNapi::SetMetadata(napi_env env, napi_callback_info info)
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
    std::unique_ptr<PictureAsyncContext> asyncContext = std::make_unique<PictureAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));
    asyncContext->rPicture = asyncContext->nConstructor->nativePicture_;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rPicture), nullptr, IMAGE_LOGE("Empty native picture"));

    status = napi_get_value_uint32(env, argValue[NUM_0], &metadataType);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("Fail to get metadata type"));
    if (metadataType == static_cast<int32_t>(MetadataType::EXIF)) {
        asyncContext->metadataType = MetadataType(metadataType);
    } else {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_DECODE_EXIF_UNSUPPORT, "Unsupport MetadataType");
    }

    status = napi_unwrap(env, argValue[NUM_1], reinterpret_cast<void**>(&asyncContext->metadataNapi));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to unwrap MetadataNapi"));
    if (asyncContext->metadataNapi != nullptr) {
        asyncContext->imageMetadata = asyncContext->metadataNapi->GetNativeMetadata();
    } else {
        return ImageNapiUtils::ThrowExceptionError(
            env, ERR_IMAGE_INVALID_PARAMETER, "Invalid args Metadata");
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "SetMetadata",
        [](napi_env env, void* data) {
            auto context = static_cast<PictureAsyncContext*>(data);
            context->status = context->rPicture->SetExifMetadata(
                std::reinterpret_pointer_cast<ExifMetadata>(context->imageMetadata));
        }, SetMetadataComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

void PictureNapi::release()
{
    if (!isRelease) {
        if (nativePicture_ != nullptr) {
            nativePicture_ = nullptr;
        }
        isRelease = true;
    }
}
}  // namespace Media
}  // namespace OHOS
