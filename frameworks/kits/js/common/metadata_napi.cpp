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

#include <map>
#include "metadata_napi.h"
#include "media_errors.h"
#include "image_log.h"
#include "image_napi_utils.h"
#include "image_common.h"
#include "napi_message_sequence.h"
#include "exif_metadata_formatter.h"
#include "exif_metadata.h"
#include "heifs_metadata.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "MetadataNapi"

namespace {
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
}

namespace OHOS {
namespace Media {
    static const std::string CLASS_NAME = "ImageMetadata";
    static const std::string EXIF_CLASS = "ExifMetadata";
    static const std::string MAKERNOTE_CLASS = "MakerNoteHuaweiMetadata";
    static const std::string HEIFS_CLASS = "HeifsMetadata";
    thread_local napi_ref MetadataNapi::sConstructor_ = nullptr;
    thread_local napi_ref MetadataNapi::sExifConstructor_ = nullptr;
    thread_local napi_ref MetadataNapi::sMakerNoteConstructor_ = nullptr;
    thread_local napi_ref MetadataNapi::sHeifsMetadataConstructor_ = nullptr;
    thread_local std::shared_ptr<ImageMetadata> MetadataNapi::sMetadata_ = nullptr;

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#endif
static const uint32_t XMAGE_WATERMARK_MODE_AT_THE_BOTTOM = 9;
static const uint32_t XMAGE_WATERMARK_MODE_BORDER = 10;
static const uint32_t CAPTURE_MODE_PROFESSIONAL = 2;
static const uint32_t CAPTURE_MODE_FRONT_LENS_NIGHT_VIEW = 7;
static const uint32_t CAPTURE_MODE_PANORAMA = 8;
static const uint32_t CAPTURE_MODE_TAIL_LIGHT = 9;
static const uint32_t CAPTURE_MODE_LIGHT_GRAFFITI = 10;
static const uint32_t CAPTURE_MODE_SILKY_WATER = 11;
static const uint32_t CAPTURE_MODE_STAR_TRACK = 12;
static const uint32_t CAPTURE_MODE_WIDEAPERTURE = 19;
static const uint32_t CAPTURE_MODE_MOVING_PHOTO = 20;
static const uint32_t CAPTURE_MODE_PORTRAIT = 23;
static const uint32_t CAPTURE_MODE_REAR_LENS_NIGHT_VIEW = 42;
static const uint32_t CAPTURE_MODE_SUPER_MACRO = 47;
static const uint32_t CAPTURE_MODE_SNAP_SHOT = 62;


struct MetadataNapiAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    napi_ref error = nullptr;
    uint32_t status;
    MetadataNapi *nConstructor;
    std::shared_ptr<ImageMetadata> rMetadata;
    std::vector<std::string> keyStrArray;
    std::multimap<int32_t, std::string> errMsgArray;
    std::vector<std::pair<std::string, std::string>> KVSArray;
    void *arrayBuffer;
    size_t arrayBufferSize;
    std::vector<std::pair<std::string, napi_ref>> customProperties;
};
using MetadataNapiAsyncContextPtr = std::unique_ptr<MetadataNapiAsyncContext>;

MetadataNapi::MetadataNapi():env_(nullptr)
{
    static std::atomic<uint32_t> currentId = 0;
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
}

MetadataNapi::~MetadataNapi()
{
    release();
}

napi_status SetValueStr(napi_env env, std::string keyStr, std::string valueStr, napi_value &object)
{
    napi_value value = nullptr;
    napi_status status;
    if (valueStr != "") {
        status = napi_create_string_utf8(env, valueStr.c_str(), valueStr.length(), &value);
        if (status != napi_ok) {
            IMAGE_LOGE("Set Value failed %{public}d", status);
            return napi_invalid_arg;
        }
    } else {
        status = napi_get_null(env, &value);
        if (status != napi_ok) {
            IMAGE_LOGE("Set null failed %{public}d", status);
            return napi_invalid_arg;
        }
    }
    status = napi_set_named_property(env, object, keyStr.c_str(), value);
    if (status != napi_ok) {
        IMAGE_LOGE("Set Key failed %{public}d", status);
        return napi_invalid_arg;
    }
    IMAGE_LOGD("Set string value success.");
    return napi_ok;
}

napi_value SetArrayInfo(napi_env env, std::vector<std::pair<std::string, std::string>> recordParameters)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok) {
        IMAGE_LOGE("Create record failed %{public}d", status);
        return result;
    }

    for (size_t index = 0; index < recordParameters.size(); ++index) {
        status = SetValueStr(env, recordParameters[index].first, recordParameters[index].second, result);
        if (status != napi_ok) {
            IMAGE_LOGE("Set current record parameter failed %{public}d", status);
            continue;
        }
    }

    IMAGE_LOGD("Set record parameters info success.");
    return result;
}

static void CommonCallbackRoutine(napi_env env, MetadataNapiAsyncContext* &asyncContext, const napi_value &valueParam)
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
    }

    napi_delete_async_work(env, asyncContext->work);
    napi_close_handle_scope(env, scope);

    delete asyncContext;
    asyncContext = nullptr;
}

napi_value MetadataNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor props[] = {
        DECLARE_NAPI_FUNCTION("getProperties", GetProperties),
        DECLARE_NAPI_FUNCTION("setProperties", SetProperties),
        DECLARE_NAPI_FUNCTION("getAllProperties", GetAllProperties),
        DECLARE_NAPI_FUNCTION("getBlob", GetBlob),
        DECLARE_NAPI_FUNCTION("setBlob", SetBlob),
        DECLARE_NAPI_FUNCTION("clone", Clone),
    };
    napi_property_descriptor static_prop[] = {};

    napi_value constructor = nullptr;

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                          Constructor, nullptr, IMG_ARRAY_SIZE(props),
                          props, &constructor)),
        nullptr, IMAGE_LOGE("Define class fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_create_reference(env, constructor, 1, &sConstructor_)),
        nullptr, IMAGE_LOGE("Create reference fail")
    );
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

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor)),
        nullptr, IMAGE_LOGE("Set named property fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_properties(env, exports, IMG_ARRAY_SIZE(static_prop), static_prop)),
        nullptr, IMAGE_LOGE("Define properties fail")
    );

    IMAGE_LOGD("Init success");
    return exports;
}

napi_value MetadataNapi::InitExifMetadata(napi_env env, napi_value exports)
{
    IMAGE_LOGD("InitExifMetadata ENTER");
    
    napi_property_descriptor instanceProps[] = {
        DECLARE_NAPI_FUNCTION("getProperties", GetProperties),
        DECLARE_NAPI_FUNCTION("setProperties", SetProperties),
        DECLARE_NAPI_FUNCTION("getAllProperties", GetAllProperties),
        DECLARE_NAPI_FUNCTION("getBlob", GetBlob),
        DECLARE_NAPI_FUNCTION("setBlob", SetBlob),
        DECLARE_NAPI_FUNCTION("clone", CloneExif),
    };
    
    napi_property_descriptor staticProps[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createInstance", CreateInstance),
    };
    
    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, EXIF_CLASS.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(instanceProps) / sizeof(instanceProps[0]), instanceProps, &constructor);
    
    if (status != napi_ok || constructor == nullptr) {
        IMAGE_LOGE("Failed to define ExifMetadata class: %{public}d", status);
        return exports;
    }
    status = napi_define_properties(env, constructor, sizeof(staticProps) / sizeof(staticProps[0]), staticProps);
    if (status != napi_ok) {
        IMAGE_LOGE("Failed to define static methods: %{public}d", status);
    }
    
    status = napi_create_reference(env, constructor, 1, &sExifConstructor_);
    if (status != napi_ok || sExifConstructor_ == nullptr) {
        IMAGE_LOGE("Failed to create EXIF ref: %{public}d", status);
        return exports;
    }
    
    status = napi_set_named_property(env, exports, EXIF_CLASS.c_str(), constructor);
    if (status != napi_ok) {
        IMAGE_LOGE("Failed to export %{public}s class: %{public}d", EXIF_CLASS.c_str(), status);
    }
    
    auto context = new NapiConstructorContext();
    context->env_ = env;
    context->ref_ = sExifConstructor_;
    napi_add_env_cleanup_hook(env, ImageNapiUtils::CleanUpConstructorContext, context);
    
    IMAGE_LOGD("InitExifMetadata EXIT");
    return exports;
}

static void ExportConstant(napi_env env, napi_value exports, const char* name, PropertyValueType type, void* value)
{
    napi_value constantValue;
    napi_status status = napi_ok;
    switch (type) {
        case PropertyValueType::INT:
            status = napi_create_int32(env, *static_cast<int32_t*>(value), &constantValue);
            break;
        case PropertyValueType::STRING:
            status = napi_create_string_utf8(env, static_cast<const char*>(value),
                NAPI_AUTO_LENGTH, &constantValue);
            break;
        case PropertyValueType::DOUBLE:
            status = napi_create_double(env, *static_cast<double*>(value), &constantValue);
            break;
        default:
            IMAGE_LOGE("Unsupported constant type for '%s'", name);
            return;
    }
    if (status != napi_ok) {
        IMAGE_LOGE("Failed to create constant '%s': %{public}d", name, status);
        return;
    }
    napi_status exportStatus = napi_set_named_property(env, exports, name, constantValue);
    if (exportStatus != napi_ok) {
        IMAGE_LOGE("Failed to export constant '%s': %{public}d", name, exportStatus);
    }
}

static void ExportValue(napi_env env, napi_value exports)
{
    const int32_t exportValueXmageWatermarkModeAtTheBottom = XMAGE_WATERMARK_MODE_AT_THE_BOTTOM;
    ExportConstant(env, exports, "XMAGE_WATERMARK_MODE_AT_THE_BOTTOM", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueXmageWatermarkModeAtTheBottom)));
    const int32_t exportValueXmageWatermarkModeBorder = XMAGE_WATERMARK_MODE_BORDER;
    ExportConstant(env, exports, "XMAGE_WATERMARK_MODE_BORDER", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueXmageWatermarkModeBorder)));
    const int32_t exportValueCaptureModeProfessional = CAPTURE_MODE_PROFESSIONAL;
    ExportConstant(env, exports, "CAPTURE_MODE_PROFESSIONAL", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeProfessional)));
    const int32_t exportValueCaptureModeFrontLensNightView = CAPTURE_MODE_FRONT_LENS_NIGHT_VIEW;
    ExportConstant(env, exports, "CAPTURE_MODE_FRONT_LENS_NIGHT_VIEW", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeFrontLensNightView)));
    const int32_t exportValueCaptureModePanorama = CAPTURE_MODE_PANORAMA;
    ExportConstant(env, exports, "CAPTURE_MODE_PANORAMA", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModePanorama)));
    const int32_t exportValueCaptureModeTailLight = CAPTURE_MODE_TAIL_LIGHT;
    ExportConstant(env, exports, "CAPTURE_MODE_TAIL_LIGHT", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeTailLight)));
    const int32_t exportValueCaptureModeLightGraffiti = CAPTURE_MODE_LIGHT_GRAFFITI;
    ExportConstant(env, exports, "CAPTURE_MODE_LIGHT_GRAFFITI", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeLightGraffiti)));
    const int32_t exportValueCaptureModeSilkyWater = CAPTURE_MODE_SILKY_WATER;
    ExportConstant(env, exports, "CAPTURE_MODE_SILKY_WATER", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeSilkyWater)));
    const int32_t exportValueCaptureModeStarTrack = CAPTURE_MODE_STAR_TRACK;
    ExportConstant(env, exports, "CAPTURE_MODE_STAR_TRACK", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeStarTrack)));
    const int32_t exportValueCaptureModeWideaperture = CAPTURE_MODE_WIDEAPERTURE;
    ExportConstant(env, exports, "CAPTURE_MODE_WIDEAPERTURE", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeWideaperture)));
    const int32_t exportValueCaptureModeMovingPhoto = CAPTURE_MODE_MOVING_PHOTO;
    ExportConstant(env, exports, "CAPTURE_MODE_MOVING_PHOTO", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeMovingPhoto)));
    const int32_t exportValueCaptureModePortrait = CAPTURE_MODE_PORTRAIT;
    ExportConstant(env, exports, "CAPTURE_MODE_PORTRAIT", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModePortrait)));
    const int32_t exportValueCaptureModeRearLensNightView = CAPTURE_MODE_REAR_LENS_NIGHT_VIEW;
    ExportConstant(env, exports, "CAPTURE_MODE_REAR_LENS_NIGHT_VIEW", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeRearLensNightView)));
    const int32_t exportValueCaptureModeSuperMacro = CAPTURE_MODE_SUPER_MACRO;
    ExportConstant(env, exports, "CAPTURE_MODE_SUPER_MACRO", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeSuperMacro)));
    const int32_t exportValueCaptureModeSnapShot = CAPTURE_MODE_SNAP_SHOT;
    ExportConstant(env, exports, "CAPTURE_MODE_SNAP_SHOT", PropertyValueType::INT,
        const_cast<void*>(static_cast<const void*>(&exportValueCaptureModeSnapShot)));
}

napi_value MetadataNapi::InitMakerNoteMetadata(napi_env env, napi_value exports)
{
    IMAGE_LOGD("InitMakerNoteMetadata ENTER");
    ExportValue(env, exports);

    napi_property_descriptor instanceProps[] = {
        DECLARE_NAPI_FUNCTION("getProperties", GetProperties),
        DECLARE_NAPI_FUNCTION("setProperties", SetProperties),
        DECLARE_NAPI_FUNCTION("getAllProperties", GetAllProperties),
        DECLARE_NAPI_FUNCTION("getBlob", GetBlob),
        DECLARE_NAPI_FUNCTION("setBlob", SetBlob),
        DECLARE_NAPI_FUNCTION("clone", CloneExif),
    };
    
    napi_property_descriptor staticProps[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createInstance", CreateInstance),
    };
    
    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, MAKERNOTE_CLASS.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(instanceProps) / sizeof(instanceProps[0]), instanceProps, &constructor);
    
    if (status != napi_ok || constructor == nullptr) {
        IMAGE_LOGE("Failed to define ExifMetadata class: %{public}d", status);
        return exports;
    }
    status = napi_define_properties(env, constructor, sizeof(staticProps) / sizeof(staticProps[0]), staticProps);
    if (status != napi_ok) {
        IMAGE_LOGE("Failed to define static methods: %{public}d", status);
    }
    
    status = napi_create_reference(env, constructor, 1, &sMakerNoteConstructor_);
    if (status != napi_ok || sMakerNoteConstructor_ == nullptr) {
        IMAGE_LOGE("Failed to create EXIF ref: %{public}d", status);
        return exports;
    }
    
    status = napi_set_named_property(env, exports, MAKERNOTE_CLASS.c_str(), constructor);
    if (status != napi_ok) {
        IMAGE_LOGE("Failed to export %{public}s class: %{public}d", MAKERNOTE_CLASS.c_str(), status);
    }
    
    auto context = new NapiConstructorContext();
    context->env_ = env;
    context->ref_ = sMakerNoteConstructor_;
    napi_add_env_cleanup_hook(env, ImageNapiUtils::CleanUpConstructorContext, context);
    
    IMAGE_LOGD("InitMakerNoteMetadata EXIT");
    return exports;
}

napi_value MetadataNapi::InitHeifsMetadata(napi_env env, napi_value exports)
{
    IMAGE_LOGD("InitHeifsMetadata ENTER");
    
    napi_property_descriptor instanceProps[] = {
        DECLARE_NAPI_FUNCTION("getProperties", GetProperties),
        DECLARE_NAPI_FUNCTION("setProperties", SetProperties),
        DECLARE_NAPI_FUNCTION("getAllProperties", GetAllProperties),
        DECLARE_NAPI_FUNCTION("clone", CloneHeifsMetadata),
    };
    
    napi_property_descriptor staticProps[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createInstance", CreateHeifsMetadataInstance),
    };
    
    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, HEIFS_CLASS.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(instanceProps) / sizeof(instanceProps[0]), instanceProps, &constructor);
    if (status != napi_ok || constructor == nullptr) {
        IMAGE_LOGE("Failed to define HeifsMetadata class: %{public}d", status);
        return exports;
    }
    status = napi_define_properties(env, constructor, sizeof(staticProps) / sizeof(staticProps[0]), staticProps);
    if (status != napi_ok) {
        IMAGE_LOGE("Failed to define static methods: %{public}d", status);
    }
    
    status = napi_create_reference(env, constructor, 1, &sHeifsMetadataConstructor_);
    if (status != napi_ok || sHeifsMetadataConstructor_ == nullptr) {
        IMAGE_LOGE("Failed to create HeifsMetadata ref: %{public}d", status);
        return exports;
    }
    
    status = napi_set_named_property(env, exports, HEIFS_CLASS.c_str(), constructor);
    if (status != napi_ok) {
        IMAGE_LOGE("Failed to export %{public}s class: %{public}d", HEIFS_CLASS.c_str(), status);
    }
    
    auto context = new NapiConstructorContext();
    context->env_ = env;
    context->ref_ = sHeifsMetadataConstructor_;
    napi_add_env_cleanup_hook(env, ImageNapiUtils::CleanUpConstructorContext, context);
    
    IMAGE_LOGD("InitHeifsMetadata EXIT");
    return exports;
}

napi_value MetadataNapi::CreateMetadata(napi_env env, std::shared_ptr<ImageMetadata> metadata)
{
    if (sConstructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        MetadataNapi::Init(env, exports);
    }

    napi_value constructor = nullptr;
    napi_value result = nullptr;
    IMAGE_LOGD("CreateMetadata IN");
    napi_status status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        sMetadata_ = metadata;
        status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
    }
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("CreateMetadata | New instance could not be obtained");
        napi_get_undefined(env, &result);
    }
    return result;
}

napi_value MetadataNapi::CreateExifMetadata(napi_env env, std::shared_ptr<ImageMetadata> metadata)
{
    if (sExifConstructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        MetadataNapi::InitExifMetadata(env, exports);
    }
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_status status = napi_get_reference_value(env, sExifConstructor_, &constructor);
    if (status == napi_ok) {
        sMetadata_ = metadata;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
    }
    if (status != napi_ok) {
        IMAGE_LOGE("CreateExifMetadata | Failed to create instance");
        napi_get_undefined(env, &result);
    }
    return result;
}

napi_value MetadataNapi::CreateHeifsMetadata(napi_env env, std::shared_ptr<ImageMetadata> metadata)
{
    if (sHeifsMetadataConstructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        MetadataNapi::InitHeifsMetadata(env, exports);
    }
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_status status = napi_get_reference_value(env, sHeifsMetadataConstructor_, &constructor);
    if (status == napi_ok) {
        sMetadata_ = metadata;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
    }
    if (status != napi_ok) {
        IMAGE_LOGE("CreateHeifsMetadata | Failed to create instance");
        napi_get_undefined(env, &result);
    }
    return result;
}

napi_value MetadataNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_get_undefined(env, &thisVar);
    IMAGE_LOGD("Constructor IN");
    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    IMG_NAPI_CHECK_RET(IMG_IS_READY(status, thisVar), undefineVar);
    std::unique_ptr<MetadataNapi> pMetadataNapi = std::make_unique<MetadataNapi>();
    if (pMetadataNapi != nullptr) {
        pMetadataNapi->env_ = env;
        pMetadataNapi->nativeMetadata_ = sMetadata_;
        status = napi_wrap(env, thisVar, reinterpret_cast<void *>(pMetadataNapi.release()),
                           MetadataNapi::Destructor, nullptr, nullptr);
        if (status != napi_ok) {
            IMAGE_LOGE("Failure wrapping js to native napi");
            return undefineVar;
        }
    }
    return thisVar;
}

void MetadataNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    if (nativeObject != nullptr) {
        IMAGE_LOGD("Destructor PictureNapi");
        delete reinterpret_cast<MetadataNapi*>(nativeObject);
        nativeObject = nullptr;
    }
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

std::vector<std::string> GetStrArrayArgument(napi_env env, napi_value object)
{
    std::vector<std::string> keyStrArray;
    uint32_t arrayLen = 0;
    napi_status status = napi_get_array_length(env, object, &arrayLen);
    if (status != napi_ok) {
        IMAGE_LOGE("Get array length failed: %{public}d", status);
        return keyStrArray;
    }

    for (uint32_t i = 0; i < arrayLen; i++) {
        napi_value element;
        if (napi_get_element(env, object, i, &element) == napi_ok) {
            keyStrArray.emplace_back(GetStringArgument(env, element));
        }
    }
    IMAGE_LOGD("Get string argument success.");
    return keyStrArray;
}

std::vector<std::pair<std::string, std::string>> GetArrayArgument(napi_env env, napi_value object)
{
    std::vector<std::pair<std::string, std::string>> kVStrArray;
    napi_value recordNameList = nullptr;
    uint32_t recordCount = 0;
    napi_status status = napi_get_property_names(env, object, &recordNameList);
    if (status != napi_ok) {
        IMAGE_LOGE("Get recordNameList property names failed %{public}d", status);
        return kVStrArray;
    }
    status = napi_get_array_length(env, recordNameList, &recordCount);
    if (status != napi_ok) {
        IMAGE_LOGE("Get recordNameList array length failed %{public}d", status);
        return kVStrArray;
    }

    napi_value recordName = nullptr;
    napi_value recordValue = nullptr;
    for (uint32_t i = 0; i < recordCount; ++i) {
        status = napi_get_element(env, recordNameList, i, &recordName);
        if (status != napi_ok) {
            IMAGE_LOGE("Get recordName element failed %{public}d", status);
            continue;
        }
        std::string keyStr = GetStringArgument(env, recordName);
        status = napi_get_named_property(env, object, keyStr.c_str(), &recordValue);
        if (status != napi_ok) {
            IMAGE_LOGE("Get recordValue name property failed %{public}d", status);
            continue;
        }
        std::string valueStr = GetStringArgument(env, recordValue);
        kVStrArray.push_back(std::make_pair(keyStr, valueStr));
    }

    IMAGE_LOGD("Get record argument success.");
    return kVStrArray;
}

static bool FragmentValueIsError(const std::multimap<std::int32_t, std::string> &errMsgArray)
{
    static std::set<std::string> fragmentKeys = {
        "XInOriginal", "YInOriginal", "FragmentImageWidth", "FragmentImageHeight"
    };
    for (const auto &errMsg : errMsgArray) {
        // As long as a key is found, return true
        if (fragmentKeys.find(errMsg.second) != fragmentKeys.end()) {
            return true;
        }
    }
    return false;
}

napi_value CreateErrorArray(napi_env env, const MetadataNapiAsyncContext *context)
{
    napi_value result = nullptr;
    std::string errkey = "";
    if (context->errMsgArray.empty()) {
        return result;
    }
    for (const auto &errMsg : context->errMsgArray) {
        errkey += errMsg.second + " ";
    }
    if (context->rMetadata->GetType() == MetadataType::FRAGMENT && FragmentValueIsError(context->errMsgArray)) {
        ImageNapiUtils::CreateErrorObj(env, result, IMAGE_BAD_PARAMETER, "The input value is incorrect!");
    } else {
        ImageNapiUtils::CreateErrorObj(env, result, IMAGE_UNSUPPORTED_METADATA,
            "The input data is incorrect! error key: " + errkey);
    }
    return result;
}

static void GetPropertiesComplete(napi_env env, napi_status status, MetadataNapiAsyncContext *context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Context is nullptr");
        return;
    }

    napi_value result[NUM_2] = {0};

    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    if (context->status == SUCCESS) {
        result[NUM_1] = SetArrayInfo(env, context->KVSArray);
    } else {
        result[NUM_0] = CreateErrorArray(env, context);
    }

    if (context->status == SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result[NUM_1]);
    } else {
        napi_reject_deferred(env, context->deferred, result[NUM_0]);
    }

    napi_delete_async_work(env, context->work);
    delete context;
    context = nullptr;
}

static void SetPropertiesComplete(napi_env env, napi_status status, MetadataNapiAsyncContext *context)
{
    if (context == nullptr) {
        IMAGE_LOGE("Context is nullptr");
        return;
    }

    napi_value result[NUM_2] = {0};
    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    result[NUM_0] = CreateErrorArray(env, context);
    if (context->status == SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result[NUM_1]);
    } else {
        napi_reject_deferred(env, context->deferred, result[NUM_0]);
    }
    
    napi_delete_async_work(env, context->work);

    delete context;
    context = nullptr;
}

static std::unique_ptr<MetadataNapiAsyncContext> UnwrapContext(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMAGE_LOGD("GetProperties argCount is [%{public}zu]", argCount);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> context = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&context->nConstructor));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));

    context->rMetadata = context->nConstructor->GetNativeMetadata();

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->rMetadata),
        nullptr, IMAGE_LOGE("Empty native rMetadata"));

    if (argCount != NUM_1) {
        IMAGE_LOGE("ArgCount mismatch");
        return nullptr;
    }
    if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_object) {
        context->keyStrArray = GetStrArrayArgument(env, argValue[NUM_0]);
    } else {
        IMAGE_LOGE("Arg 0 type mismatch");
        return nullptr;
    }
    return context;
}

static std::unique_ptr<MetadataNapiAsyncContext> UnwrapContextForModify(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> context = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&context->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->nConstructor), nullptr, IMAGE_LOGE("Fail to unwrap context"));

    context->rMetadata = context->nConstructor->GetNativeMetadata();

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->rMetadata), nullptr, IMAGE_LOGE("Empty native rMetadata"));
    if (argCount != NUM_1) {
        IMAGE_LOGE("ArgCount mismatch");
        return nullptr;
    }
    if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_object) {
        context->KVSArray = GetArrayArgument(env, argValue[NUM_0]);
    } else {
        IMAGE_LOGE("Arg 0 type mismatch");
        return nullptr;
    }
    return context;
}

static void GetPropertiesExecute(napi_env env, void *data)
{
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    uint32_t status = SUCCESS;
    for (auto keyStrIt = context->keyStrArray.begin(); keyStrIt != context->keyStrArray.end(); ++keyStrIt) {
        std::string valueStr = "";
        status = static_cast<uint32_t>(context->rMetadata->GetValue(*keyStrIt, valueStr));
        if (status == SUCCESS) {
            context->KVSArray.emplace_back(std::make_pair(*keyStrIt, valueStr));
        } else {
            context->KVSArray.emplace_back(std::make_pair(*keyStrIt, ""));
            context->errMsgArray.insert(std::make_pair(status, *keyStrIt));
            IMAGE_LOGE("ErrCode: %{public}u , exif key: %{public}s", status, keyStrIt->c_str());
        }
    }
    context->status = context->KVSArray.size() == context->errMsgArray.size() ? ERROR : SUCCESS;
}

static void SetPropertiesExecute(napi_env env, void *data)
{
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    uint32_t status = SUCCESS;
    for (auto recordIterator = context->KVSArray.begin(); recordIterator != context->KVSArray.end();
        ++recordIterator) {
        IMAGE_LOGD("CheckExifDataValue");
        status = context->rMetadata->SetValue(recordIterator->first, recordIterator->second);
        IMAGE_LOGD("Check ret status: %{public}d", status);
        if (!status) {
            IMAGE_LOGE("There is invalid exif data parameter");
            context->errMsgArray.insert(std::make_pair(status, recordIterator->first));
            continue;
        }
    }
    context->status = context->errMsgArray.size() > 0 ? ERROR : SUCCESS;
}

static void CloneMetadataComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<MetadataNapiAsyncContext*>(data);

    if (context->rMetadata != nullptr) {
        result = MetadataNapi::CreateMetadata(env, context->rMetadata);
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value CreateBusinessError(napi_env env, int errCode, const char* msg)
{
    napi_value error;
    napi_value codeValue;
    napi_value msgValue;
    
    napi_create_int32(env, errCode, &codeValue);
    napi_create_string_utf8(env, msg, NAPI_AUTO_LENGTH, &msgValue);
    
    napi_create_error(env, nullptr, msgValue, &error);
    napi_set_named_property(env, error, "code", codeValue);
    
    return error;
}

static void CloneExifMetadataComplete(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
    napi_handle_scope scope;
    napi_open_handle_scope(env, &scope);
    
    napi_value result = nullptr;
    if (context->rMetadata != nullptr) {
        result = MetadataNapi::CreateExifMetadata(env, context->rMetadata);
    }
    if (result != nullptr) {
        for (auto& [name, ref] : context->customProperties) {
            napi_value propValue;
            if (napi_get_reference_value(env, ref, &propValue) == napi_ok) {
                napi_set_named_property(env, result, name.c_str(), propValue);
            }
            napi_delete_reference(env, ref);
        }
        context->customProperties.clear();
    }
    napi_deferred deferred = context->deferred;
    if (result != nullptr) {
        napi_resolve_deferred(env, deferred, result);
    } else {
        napi_reject_deferred(env, deferred, CreateBusinessError(env,
            IMAGE_SOURCE_UNSUPPORTED_METADATA, "Failed to clone EXIF metadata"));
    }
    napi_delete_async_work(env, context->work);
    napi_close_handle_scope(env, scope);
    delete context;
}

static void CloneHeifsMetadataComplete(napi_env env, napi_status status, void *data)
{
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
    napi_handle_scope scope;
    napi_open_handle_scope(env, &scope);
    
    napi_value result = MetadataNapi::CreateHeifsMetadata(env, context->rMetadata);
    if (context->rMetadata != nullptr && result != nullptr) {
        for (auto& [name, ref] : context->customProperties) {
            napi_value propValue;
            if (napi_get_reference_value(env, ref, &propValue) == napi_ok) {
                napi_set_named_property(env, result, name.c_str(), propValue);
            }
            napi_delete_reference(env, ref);
        }
        context->customProperties.clear();
    }
    napi_deferred deferred = context->deferred;
    if (context->rMetadata != nullptr && result != nullptr) {
        napi_resolve_deferred(env, deferred, result);
    } else {
        napi_reject_deferred(env, deferred, CreateBusinessError(env,
            IMAGE_SOURCE_UNSUPPORTED_METADATA, "Failed to clone EXIF metadata"));
    }
    napi_delete_async_work(env, context->work);
    napi_close_handle_scope(env, scope);
    delete context;
}

napi_value MetadataNapi::GetProperties(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = UnwrapContext(env, info);
    if (asyncContext == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER, "Async context unwrap failed");
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetProperties",
        GetPropertiesExecute,
        reinterpret_cast<napi_async_complete_callback>(GetPropertiesComplete),
        asyncContext,
        asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

napi_value MetadataNapi::SetProperties(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = UnwrapContextForModify(env, info);
    if (asyncContext == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER, "Async context unwrap failed");
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "SetProperties",
        SetPropertiesExecute,
        reinterpret_cast<napi_async_complete_callback>(SetPropertiesComplete),
        asyncContext,
        asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

napi_value MetadataNapi::GetAllProperties(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor), nullptr,
                         IMAGE_LOGE("Fail to unwrap context"));

    asyncContext->rMetadata = asyncContext->nConstructor->nativeMetadata_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rMetadata), nullptr, IMAGE_LOGE("Empty native rMetadata"));
    if (argCount != NUM_0) {
        IMAGE_LOGE("ArgCount mismatch");
        return nullptr;
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetAllProperties",
        [](napi_env env, void *data) {
            auto context = static_cast<MetadataNapiAsyncContext*>(data);
            if (context == nullptr) {
                IMAGE_LOGE("Empty context");
                return;
            }
            ImageMetadata::PropertyMapPtr allKey = context->rMetadata->GetAllProperties();
            for (const auto &entry : *allKey) {
                context->KVSArray.emplace_back(std::make_pair(entry.first, entry.second));
            }
            context->status = SUCCESS;
        }, reinterpret_cast<napi_async_complete_callback>(GetPropertiesComplete),
        asyncContext,
        asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

napi_value MetadataNapi::Clone(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor), nullptr,
                         IMAGE_LOGE("Fail to unwrap context"));

    asyncContext->rMetadata = asyncContext->nConstructor->nativeMetadata_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rMetadata), nullptr, IMAGE_LOGE("Empty native rMetadata"));
    if (argCount != NUM_0) {
        IMAGE_LOGE("ArgCount mismatch");
        return nullptr;
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "Clone",
        [](napi_env env, void *data) {
            auto context = static_cast<MetadataNapiAsyncContext*>(data);
            auto tmpixel = context->rMetadata->CloneMetadata();
            context->rMetadata = std::move(tmpixel);
            context->status = SUCCESS;
        }, CloneMetadataComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

static void CloneExifExecute(napi_env env, void *data)
{
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    auto tmpixel = context->rMetadata->CloneMetadata();
    context->rMetadata = std::move(tmpixel);
    context->status = SUCCESS;
}

static void CloneHeifsMetadataExecute(napi_env env, void *data)
{
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    auto tmpixel = context->rMetadata->CloneMetadata();
    context->rMetadata = std::move(tmpixel);
    context->status = SUCCESS;
}

std::string GetStringFromValue(napi_env env, napi_value value)
{
    char buffer[256] = {0};
    size_t length = 0;
    napi_get_value_string_utf8(env, value, buffer, sizeof(buffer) - 1, &length);
    return std::string(buffer, length);
}

static void GetJsProperties(napi_env env, napi_value thisVar, void *data)
{
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("Empty context");
        return;
    }
    napi_value propNames;
    if (napi_get_property_names(env, thisVar, &propNames) == napi_ok) {
        uint32_t count = 0;
        napi_get_array_length(env, propNames, &count);
        
        for (uint32_t i = 0; i < count; i++) {
            napi_value name;
            napi_status nameStatus = napi_get_element(env, propNames, i, &name);
            if (nameStatus != napi_ok) {
                continue;
            }
            std::string propName = GetStringFromValue(env, name);
            if (propName.empty() || propName[0] == '_') {
                continue;
            }
            napi_value propValue;
            if (napi_get_property(env, thisVar, name, &propValue) != napi_ok) {
                continue;
            }
            napi_ref ref;
            if (napi_create_reference(env, propValue, 1, &ref) == napi_ok) {
                context->customProperties.push_back({propName, ref});
                IMAGE_LOGD("Collecting custom property: %s", propName.c_str());
            }
        }
    }
}

napi_value MetadataNapi::CloneExif(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor), nullptr,
                         IMAGE_LOGE("Fail to unwrap context"));

    asyncContext->rMetadata = asyncContext->nConstructor->nativeMetadata_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rMetadata), nullptr, IMAGE_LOGE("Empty native rMetadata"));
    if (argCount != NUM_0) {
        IMAGE_LOGE("ArgCount mismatch");
        return nullptr;
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    GetJsProperties(env, thisVar, static_cast<void*>((asyncContext).get()));

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CloneExif",
        CloneExifExecute, CloneExifMetadataComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

napi_value MetadataNapi::CloneHeifsMetadata(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;
    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor), nullptr,
                         IMAGE_LOGE("Fail to unwrap context"));

    asyncContext->rMetadata = asyncContext->nConstructor->nativeMetadata_;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rMetadata), nullptr, IMAGE_LOGE("Empty native rMetadata"));
    if (argCount != NUM_0) {
        IMAGE_LOGE("ArgCount mismatch");
        return nullptr;
    }

    napi_create_promise(env, &(asyncContext->deferred), &result);
    GetJsProperties(env, thisVar, static_cast<void*>((asyncContext).get()));

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "CloneHeifsMetadata",
        CloneHeifsMetadataExecute, CloneHeifsMetadataComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

void MetadataNapi::release()
{
    if (!isRelease) {
        if (nativeMetadata_ != nullptr) {
            nativeMetadata_ = nullptr;
        }
        isRelease = true;
    }
}

static void GetBlobComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
 
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

napi_value MetadataNapi::GetBlob(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_0;

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to get argments from info"));

    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));

    asyncContext->rMetadata = asyncContext->nConstructor->GetNativeMetadata();

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rMetadata), nullptr, IMAGE_LOGE("Empty native rMetadata"));

    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetBlob",
        [](napi_env env, void *data) {
            auto context = static_cast<MetadataNapiAsyncContext*>(data);
            context->arrayBufferSize = context->rMetadata->GetBlobSize();
            context->arrayBuffer = new uint8_t[context->arrayBufferSize];
            if (context->arrayBuffer != nullptr) {
                context->status = context->rMetadata->GetBlob(
                    context->arrayBufferSize, static_cast<uint8_t*>(context->arrayBuffer));
            } else {
                context->status = ERR_MEDIA_MALLOC_FAILED;
            }
        }, GetBlobComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

static void SetBlobComplete(napi_env env, napi_status status, void *data)
{
    napi_value valueParam = nullptr;
    napi_get_undefined(env, &valueParam);
    auto context = static_cast<MetadataNapiAsyncContext*>(data);
    napi_value result[NUM_2] = {0};
    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    if (context->status == SUCCESS) {
        result[NUM_1] = valueParam;
    } else {
        ImageNapiUtils::CreateErrorObj(env, result[0], IMAGE_SOURCE_UNSUPPORTED_METADATA,
                                       "There is generic napi failure!");
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred) {
        if (context->status == SUCCESS) {
            napi_resolve_deferred(env, context->deferred, result[NUM_1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[NUM_0]);
        }
    }

    napi_delete_async_work(env, context->work);
    delete context;
    context = nullptr;
}

napi_value MetadataNapi::SetBlob(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = NUM_1;
    napi_value argValue[NUM_1] = {0};

    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("Fail to napi_get_cb_info"));

    std::unique_ptr<MetadataNapiAsyncContext> asyncContext = std::make_unique<MetadataNapiAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->nConstructor));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->nConstructor),
        nullptr, IMAGE_LOGE("Fail to unwrap context"));

    asyncContext->rMetadata = asyncContext->nConstructor->GetNativeMetadata();
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rMetadata), nullptr, IMAGE_LOGE("Empty native rMetadata"));
    status = napi_get_arraybuffer_info(env, argValue[NUM_0],
        &(asyncContext->arrayBuffer), &(asyncContext->arrayBufferSize));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        ImageNapiUtils::ThrowExceptionError(env, IMAGE_BAD_PARAMETER,
            "Invalid args."), IMAGE_LOGE("Fail to get blob info"));
    
    napi_create_promise(env, &(asyncContext->deferred), &result);

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "SetBlob",
        [](napi_env env, void *data) {
            auto context = static_cast<MetadataNapiAsyncContext*>(data);
            context->status = context->rMetadata->SetBlob(
                static_cast<uint8_t*>(context->arrayBuffer), static_cast<uint32_t>(context->arrayBufferSize));
        }, SetBlobComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("Fail to create async work"));
    return result;
}

napi_value MetadataNapi::CreateInstance(napi_env env, napi_callback_info info)
{
    IMAGE_LOGD("MetadataNapi::CreateInstance IN");
    napi_value result = nullptr;
    napi_value constructor = nullptr;
    napi_status status;
    
    status = napi_get_reference_value(env, sExifConstructor_, &constructor);
    if (status != napi_ok || constructor == nullptr) {
        IMAGE_LOGE("Failed to get constructor reference, status: %{public}d", status);
        napi_get_undefined(env, &result);
        return result;
    }
    auto metadata = ExifMetadata::InitExifMetadata();
    if (!metadata) {
        IMAGE_LOGE("Failed to create ExifMetadata instance");
        napi_get_undefined(env, &result);
        return result;
    }
    status = napi_new_instance(env, constructor, 0, nullptr, &result);
    if (status != napi_ok) {
        IMAGE_LOGE("Failed to create new instance, status: %{public}d", status);
        napi_get_undefined(env, &result);
        return result;
    }
    MetadataNapi* metadataNapi = nullptr;
    status = napi_unwrap(env, result, reinterpret_cast<void**>(&metadataNapi));
    if (status != napi_ok || metadataNapi == nullptr) {
        IMAGE_LOGE("Failed to unwrap metadataNapi, status: %{public}d", status);
        napi_get_undefined(env, &result);
        return result;
    }
    metadataNapi->nativeMetadata_ = metadata;
    IMAGE_LOGD("MetadataNapi::CreateInstance OUT");
    return result;
}


napi_value MetadataNapi::CreateHeifsMetadataInstance(napi_env env, napi_callback_info info)
{
    IMAGE_LOGD("MetadataNapi::CreateHeifsMetadataInstance IN");
    napi_value result = nullptr;
    napi_value constructor = nullptr;
    napi_status status;
    
    status = napi_get_reference_value(env, sHeifsMetadataConstructor_, &constructor);
    if (status != napi_ok || constructor == nullptr) {
        IMAGE_LOGE("Failed to get constructor reference, status: %{public}d", status);
        napi_get_undefined(env, &result);
        return result;
    }
    auto metadata = std::make_shared<HeifsMetadata>();
    if (!metadata) {
        IMAGE_LOGE("Failed to create ExifMetadata instance");
        napi_get_undefined(env, &result);
        return result;
    }
    status = napi_new_instance(env, constructor, 0, nullptr, &result);
    if (status != napi_ok) {
        IMAGE_LOGE("Failed to create new instance, status: %{public}d", status);
        napi_get_undefined(env, &result);
        return result;
    }
    MetadataNapi* metadataNapi = nullptr;
    status = napi_unwrap(env, result, reinterpret_cast<void**>(&metadataNapi));
    if (status != napi_ok || metadataNapi == nullptr) {
        IMAGE_LOGE("Failed to unwrap metadataNapi, status: %{public}d", status);
        napi_get_undefined(env, &result);
        return result;
    }
    metadataNapi->nativeMetadata_ = metadata;
    IMAGE_LOGD("MetadataNapi::CreateHeifsMetadataInstance OUT");
    return result;
}
} // namespace Media
} // namespace OHOS