/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "image_packer_napi.h"

#include "image_common.h"
#include "image_log.h"
#include "image_napi_utils.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_source_napi.h"
#include "image_trace.h"
#include "media_errors.h"
#include "pixel_map_napi.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImagePackerNapi"

namespace {
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
    constexpr int32_t INVALID_FD = -1;
    constexpr int32_t SIZE_256 = 256;
    constexpr int32_t SIZE_512 = 512;
    constexpr int32_t SIZE_1024 = 1024;
    constexpr int32_t SIZE_1440 = 1440;
    constexpr int32_t SIZE_1920 = 1920;
    constexpr int64_t FILE_SIZE_300K = 300 * 1024;
    constexpr int64_t FILE_SIZE_1M = 1 * 1024 * 1024;
    constexpr int64_t FILE_SIZE_4M = 4 * 1024 * 1024;
    constexpr int64_t FILE_SIZE_10M = 10 * 1024 * 1024;
}

namespace OHOS {
namespace Media {
static const std::string CLASS_NAME_IMAGEPACKER = "ImagePacker";
thread_local std::shared_ptr<ImagePacker> ImagePackerNapi::sImgPck_ = nullptr;
thread_local napi_ref ImagePackerNapi::sConstructor_ = nullptr;
struct ImageEnum {
    std::string name;
    int32_t numVal;
    std::string strVal;
};
static std::vector<struct ImageEnum> sPackingDynamicRangeMap = {
    {"AUTO", 0, ""},
    {"SDR", 1, ""},
};

const int ARGS_THREE = 3;
const int ARGS_FOUR = 4;
const int PARAM0 = 0;
const int PARAM1 = 1;
const int PARAM2 = 2;
const int PARAM3 = 3;
const int PARAM4 = 4;
const uint8_t BYTE_FULL = 0xFF;
const int32_t SIZE = 100;
const int32_t TYPE_IMAGE_SOURCE = 1;
const int32_t TYPE_PIXEL_MAP = 2;
const int32_t TYPE_PICTURE = 3;
const int32_t TYPE_ARRAY = 4;
const int32_t TYPE_INVALID = 5;
const int64_t DEFAULT_BUFFER_SIZE = 25 * 1024 * 1024; // 25M is the maximum default packedSize
const int MASK_3 = 0x3;
const int MASK_16 = 0xffff;

struct ImagePackerError {
    bool hasErrorCode = false;
    int32_t errorCode = SUCCESS;
    std::string msg;
};

struct ImagePackerAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef = nullptr;
    ImagePackerNapi *constructor_;
    bool status = false;
    std::shared_ptr<ImageSource> rImageSource;
    PackOption packOption;
    std::shared_ptr<ImagePacker> rImagePacker;
    std::shared_ptr<PixelMap> rPixelMap;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    std::shared_ptr<Picture> rPicture;
#endif
    std::shared_ptr<std::vector<std::shared_ptr<PixelMap>>> rPixelMaps;
    std::unique_ptr<uint8_t[]> resultBuffer;
    int32_t packType = TYPE_IMAGE_SOURCE;
    int64_t resultBufferSize = 0;
    int64_t packedSize = 0;
    int fd = INVALID_FD;
    ImagePackerError error;
    bool needReturnErrorCode = true;
    uint32_t frameCount;
};

struct PackingOption {
    std::string format;
    uint8_t quality = 100;
};

static const std::map<uint32_t, std::string> ERROR_CODE_MESSAGE_MAP = {
    {COMMON_ERR_INVALID_PARAMETER, "Parameter error.Possible causes: 1.Mandatory parameters are left unspecified."
        "2.Incorrect parameter types;3.Parameter verification failed."},
    {ERROR, "The operation failed. Possible cause: 1.Image upload exception. 2. Decoding process exception. 3. "
        "Insufficient memory."},
    {ERR_IMAGE_DATA_ABNORMAL, "The image data is abnormal."},
    {ERR_IMAGE_TOO_LARGE, "The image data is too large. This status code is thrown when an error occurs during"
        "the process of checking size."},
    {ERR_IMAGE_UNKNOWN_FORMAT, "Unknown image format."},
    {ERR_IMAGE_INVALID_PARAMETER, "Invalid input parameter. Possible causes: 1. Format paramter in PackingOption is"
        "invalid; 2. Invalid fd; 3. Other parameter mismatch."},
    {ERR_IMAGE_ENCODE_FAILED, "Failed to encode the image."},
    {ERR_IMAGE_ADD_PIXEL_MAP_FAILED, "Add pixelmap out of range."},
    {ERR_IMAGE_ENCODE_ICC_FAILED, "Failed to encode icc."},
    {IMAGE_RESULT_CREATE_SURFAC_FAILED, "Failed to create surface."}
};

static std::string GetErrorCodeMsg(uint32_t errorCode)
{
    std::string errMsg = "Failed to encode image.";
    auto iter = ERROR_CODE_MESSAGE_MAP.find(errorCode);
    if (iter != ERROR_CODE_MESSAGE_MAP.end()) {
        errMsg = iter->second;
    }
    return errMsg;
}

ImagePackerNapi::ImagePackerNapi():env_(nullptr)
{}

ImagePackerNapi::~ImagePackerNapi()
{
    IMAGE_LOGD("%{public}s IN", __func__);
    release();
}

static bool IsImagePackerErrorOccur(ImagePackerAsyncContext *ctx)
{
    if (ctx == nullptr) {
        return true;
    }
    if (ctx->error.hasErrorCode) {
        return ctx->error.errorCode != SUCCESS;
    }
    return !ctx->error.msg.empty();
}

static void ImagePackerErrorToNapiError(napi_env env, ImagePackerAsyncContext *ctx, napi_value &out)
{
    if (ctx == nullptr || ctx->status == SUCCESS) {
        napi_get_undefined(env, &out);
        return;
    }

    auto msg = (ctx->error.msg.empty()) ? "Internal error" : ctx->error.msg;
    if (!ctx->error.hasErrorCode) {
        if (napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &out) != napi_ok) {
            IMAGE_LOGE("Create error msg only error");
        }
        return;
    }

    auto errorCode = (ctx->error.errorCode != SUCCESS) ? ctx->error.errorCode : ctx->status;
    napi_value message;
    napi_value code;
    if (napi_create_object(env, &out) != napi_ok) {
        IMAGE_LOGE("Create error object error");
        return;
    }
    if (napi_create_int32(env, errorCode, &code) != napi_ok ||
        napi_set_named_property(env, out, "code", code) != napi_ok) {
        IMAGE_LOGE("Create error code error");
        return;
    }
    if (napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &message) != napi_ok ||
        napi_set_named_property(env, out, "message", message) != napi_ok) {
        IMAGE_LOGE("Create error msg error");
        return;
    }
}

static void CommonCallbackRoutine(napi_env env, ImagePackerAsyncContext* &connect, const napi_value &valueParam)
{
    if (connect == nullptr) {
        return;
    }
    napi_value result[NUM_2] = {0};
    napi_value retVal;
    napi_value callback = nullptr;

    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    if (connect->status == SUCCESS) {
        result[NUM_1] = valueParam;
    } else {
        ImagePackerErrorToNapiError(env, connect, result[NUM_0]);
    }

    if (connect->deferred) {
        if (connect->status == SUCCESS) {
            napi_resolve_deferred(env, connect->deferred, result[NUM_1]);
        } else {
            napi_reject_deferred(env, connect->deferred, result[NUM_0]);
        }
    } else {
        napi_get_reference_value(env, connect->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, PARAM2, result, &retVal);
        napi_delete_reference(env, connect->callbackRef);
    }

    napi_delete_async_work(env, connect->work);

    delete connect;
    connect = nullptr;
}

static void BuildMsgOnError(ImagePackerAsyncContext* ctx, bool assertion,
    const std::string msg, int32_t errorCode)
{
    if (ctx == nullptr || assertion) {
        return;
    }
    IMAGE_LOGE("%{public}s", msg.c_str());
    ctx->error.hasErrorCode = ctx->needReturnErrorCode;
    ctx->error.errorCode = errorCode;
    ctx->error.msg = msg;
}

static int64_t getDefaultBufferSize(int32_t width, int32_t height)
{
    if (width <= SIZE_256 && height <= SIZE_256) {
        return FILE_SIZE_300K;
    }
    if (width <= SIZE_512 && height <= SIZE_512) {
        return FILE_SIZE_1M;
    }
    if (width <= SIZE_1024 && height <= SIZE_1024) {
        return FILE_SIZE_4M;
    }
    if (width <= SIZE_1440 && height <= SIZE_1920) {
        return FILE_SIZE_10M;
    }
    return DEFAULT_BUFFER_SIZE;
}

static int64_t getDefaultBufferSize(ImagePackerAsyncContext *context)
{
    if (context == nullptr) {
        return DEFAULT_BUFFER_SIZE;
    }
    ImageInfo imageInfo {};
    if (context->packType == TYPE_IMAGE_SOURCE) {
        if (context->rImageSource == nullptr) {
            return DEFAULT_BUFFER_SIZE;
        }
        context->rImageSource->GetImageInfo(imageInfo);
    } else if (context->packType == TYPE_PIXEL_MAP) {
        if (context->rPixelMap == nullptr) {
            return DEFAULT_BUFFER_SIZE;
        }
        context->rPixelMap->GetImageInfo(imageInfo);
    }
    if (imageInfo.size.width <= 0 || imageInfo.size.height <= 0) {
        return DEFAULT_BUFFER_SIZE;
    }
    return getDefaultBufferSize(imageInfo.size.width, imageInfo.size.height);
}

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
bool SetPicture(ImagePackerAsyncContext *context)
{
    IMAGE_LOGD("ImagePacker set picture");
    if (context->rPicture == nullptr) {
        BuildMsgOnError(context, context->rImageSource == nullptr,
            "Picture is nullptr", IMAGE_BAD_PARAMETER);
        return false;
    }
    context->rImagePacker->AddPicture(*(context->rPicture));
    return true;
}
#endif

bool SetArrayPixel(ImagePackerAsyncContext *context)
{
    IMAGE_LOGD("ImagePacker set pixelmap array");
    if (!context->rPixelMaps) {
        BuildMsgOnError(context, false, "PixelmapList is nullptr", COMMON_ERR_INVALID_PARAMETER);
        return false;
    }
    for (auto &pixelMap : *context->rPixelMaps.get()) {
        context->rImagePacker->AddImage(*(pixelMap.get()));
    }
    return true;
}

STATIC_EXEC_FUNC(Packing)
{
    int64_t packedSize = 0;
    auto context = static_cast<ImagePackerAsyncContext*>(data);
    IMAGE_LOGD("ImagePacker BufferSize %{public}" PRId64, context->resultBufferSize);
    context->resultBuffer = std::make_unique<uint8_t[]>(
        (context->resultBufferSize <= 0) ? getDefaultBufferSize(context) : context->resultBufferSize);
    int32_t innerEncodeErrorCode = static_cast<int32_t>(
        context->packType == TYPE_PICTURE ? IMAGE_ENCODE_FAILED : ERR_IMAGE_ENCODE_FAILED);
    if (context->resultBuffer == nullptr) {
        BuildMsgOnError(context, false, "ImagePacker buffer alloc error", innerEncodeErrorCode);
        return;
    }
    auto startRes = context->rImagePacker->StartPacking(context->resultBuffer.get(),
        context->resultBufferSize, context->packOption);
    if (startRes != SUCCESS) {
        context->status = ERROR;
        BuildMsgOnError(context, false, "Packing start packing failed",
            startRes == ERR_IMAGE_INVALID_PARAMETER ? COMMON_ERR_INVALID_PARAMETER : innerEncodeErrorCode);
        return;
    }
    if (context->packType == TYPE_IMAGE_SOURCE) {
        IMAGE_LOGI("ImagePacker set image source");
        if (context->rImageSource == nullptr) {
            BuildMsgOnError(context, false, "ImageSource is nullptr", COMMON_ERR_INVALID_PARAMETER);
            return;
        }
        context->rImagePacker->AddImage(*(context->rImageSource));
    } else if (context->packType == TYPE_PIXEL_MAP) {
        IMAGE_LOGD("ImagePacker set pixelmap");
        if (context->rPixelMap == nullptr) {
            BuildMsgOnError(context, false, "Pixelmap is nullptr", COMMON_ERR_INVALID_PARAMETER);
            return;
        }
        context->rImagePacker->AddImage(*(context->rPixelMap));
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    } else if (context->packType == TYPE_PICTURE) {
        if (!SetPicture(context)) {
            return;
        }
#endif
    } else if (context->packType == TYPE_ARRAY) {
        if (!SetArrayPixel(context)) {
            return;
        }
    }
    auto packRes = context->rImagePacker->FinalizePacking(packedSize);
    IMAGE_LOGD("packedSize=%{public}" PRId64, packedSize);
    if (packRes == SUCCESS) {
        context->packedSize = packedSize;
        context->status = SUCCESS;
    } else if (packedSize == context->resultBufferSize) {
        context->status = ERROR;
        if (context->packType == TYPE_PICTURE) {
            BuildMsgOnError(context, false, "output buffer is not enough", IMAGE_ENCODE_FAILED);
        } else {
            BuildMsgOnError(context, false, "output buffer is not enough", ERR_IMAGE_TOO_LARGE);
        }
        IMAGE_LOGE("output buffer is not enough.");
    } else {
        context->status = ERROR;
        IMAGE_LOGE("Packing failed, packedSize outside size.");
        BuildMsgOnError(context, false, "Packing failed",
            packRes == ERR_IMAGE_INVALID_PARAMETER ? COMMON_ERR_INVALID_PARAMETER : innerEncodeErrorCode);
    }
}

static bool PackingErrorSendEvent(napi_env env, ImagePackerAsyncContext* context,
                                  napi_event_priority prio, const char* taskName)
{
    auto task = [env, context]() {
        napi_value result = nullptr;
        napi_get_undefined(env, &result);
        context->status = ERROR;
        CommonCallbackRoutine(env, const_cast<ImagePackerAsyncContext *&>(context), result);
    };
    if (napi_status::napi_ok != napi_send_event(env, task, prio, taskName)) {
        IMAGE_LOGE("PackingErrorSendEvent: failed to SendEvent!");
        return false;
    }
    return true;
}

STATIC_COMPLETE_FUNC(Packing)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<ImagePackerAsyncContext*>(data);

    if (!ImageNapiUtils::CreateArrayBuffer(env, context->resultBuffer.get(),
                                           context->packedSize, &result)) {
        context->status = ERROR;
        IMAGE_LOGE("napi_create_arraybuffer failed!");
        napi_get_undefined(env, &result);
    } else {
        context->status = SUCCESS;
    }
    context->resultBuffer = nullptr;
    context->resultBufferSize = 0;
    CommonCallbackRoutine(env, context, result);
}

static napi_value CreateEnumTypeObject(napi_env env,
    napi_valuetype type, std::vector<struct ImageEnum> imageEnumMap)
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

        return result;
    }
    IMAGE_LOGE("CreateEnumTypeObject is Failed!");
    napi_get_undefined(env, &result);
    return result;
}

napi_value ImagePackerNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor props[] = {
        DECLARE_NAPI_FUNCTION("packing", Packing),
        DECLARE_NAPI_FUNCTION("packToData", PackToData),
        DECLARE_NAPI_FUNCTION("packToFile", PackToFile),
        DECLARE_NAPI_FUNCTION("packingFromPixelMap", Packing),
        DECLARE_NAPI_FUNCTION("packToDataFromPixelmapSequence", PackToData),
        DECLARE_NAPI_FUNCTION("packToFileFromPixelmapSequence", PackToFile),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_GETTER("supportedFormats", GetSupportedFormats),
    };
    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createImagePacker", CreateImagePacker),
        DECLARE_NAPI_STATIC_FUNCTION("getImagePackerSupportedFormats", GetImagePackerSupportedFormats),
        DECLARE_NAPI_PROPERTY("PackingDynamicRange",
            CreateEnumTypeObject(env, napi_number, sPackingDynamicRangeMap)),
    };

    napi_value constructor = nullptr;

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_class(env, CLASS_NAME_IMAGEPACKER.c_str(), NAPI_AUTO_LENGTH, Constructor,
        nullptr, IMG_ARRAY_SIZE(props), props, &constructor)), nullptr,
        IMAGE_LOGE("define class fail")
    );

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_create_reference(env, constructor, 1, &sConstructor_)),
        nullptr,
        IMAGE_LOGE("create reference fail")
    );
    auto ctorContext = new NapiConstructorContext();
    ctorContext->env_ = env;
    ctorContext->ref_ = sConstructor_;
    napi_add_env_cleanup_hook(env, ImageNapiUtils::CleanUpConstructorContext, ctorContext);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_set_named_property(env, exports, CLASS_NAME_IMAGEPACKER.c_str(), constructor)),
        nullptr,
        IMAGE_LOGE("set named property fail")
    );
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(
        napi_define_properties(env, exports, IMG_ARRAY_SIZE(static_prop), static_prop)),
        nullptr,
        IMAGE_LOGE("define properties fail")
    );

    IMAGE_LOGD("Init success");
    return exports;
}

napi_value ImagePackerNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineVar = nullptr;
    napi_get_undefined(env, &undefineVar);

    napi_status status;
    napi_value thisVar = nullptr;

    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<ImagePackerNapi> pImgPackerNapi = std::make_unique<ImagePackerNapi>();
        if (pImgPackerNapi != nullptr) {
            pImgPackerNapi->env_ = env;
            pImgPackerNapi->nativeImgPck = sImgPck_;
            sImgPck_ = nullptr;
            status = napi_wrap(env, thisVar, reinterpret_cast<void *>(pImgPackerNapi.get()),
                               ImagePackerNapi::Destructor, nullptr, nullptr);
            if (status == napi_ok) {
                pImgPackerNapi.release();
                return thisVar;
            } else {
                IMAGE_LOGE("Failure wrapping js to native napi");
            }
        }
    }

    return undefineVar;
}

napi_value ImagePackerNapi::CreateImagePacker(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("ImagePackerNapi::CreateImagePacker");
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_status status;

    std::shared_ptr<ImagePacker> imagePacker = std::make_shared<ImagePacker>();
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        sImgPck_ = imagePacker;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        if (status == napi_ok) {
            return result;
        } else {
            IMAGE_LOGE("New instance could not be obtained");
        }
    }
    return result;
}

napi_value ImagePackerNapi::CreateImagePackerNapi(napi_env env, std::shared_ptr<ImagePacker> imagePacker)
{
    if (sConstructor_ == nullptr) {
        napi_value exports = nullptr;
        napi_create_object(env, &exports);
        ImagePackerNapi::Init(env, exports);
    }
    napi_value constructor = nullptr;
    napi_value result = nullptr;
    napi_status status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        if (imagePacker != nullptr) {
            sImgPck_ = std::move(imagePacker);
            status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
        } else {
            status = napi_invalid_arg;
            IMAGE_LOGE("New ImagePackerNapi Instance imagePacker is nullptr");
            napi_get_undefined(env, &result);
        }
    }
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("CreateImagePacker | New instance could not be obtained");
        napi_get_undefined(env, &result);
    }
    return result;
}

extern "C" {
napi_value GetImagePackerNapi(napi_env env, std::shared_ptr<ImagePacker> imagePacker)
{
    return ImagePackerNapi::CreateImagePackerNapi(env, imagePacker);
}

bool GetNativeImagePacker(void *imagePackerNapi, std::shared_ptr<ImagePacker> &imagePacker)
{
    if (imagePackerNapi == nullptr) {
        IMAGE_LOGE("%{public}s imagePackerNapi is nullptr", __func__);
        return false;
    }
    imagePacker = ImagePackerNapi::GetNative(reinterpret_cast<ImagePackerNapi*>(imagePackerNapi));
    return true;
}
}

void ImagePackerNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
}

static EncodeDynamicRange parseDynamicRange(napi_env env, napi_value root)
{
    uint32_t tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "desiredDynamicRange", tmpNumber)) {
        return EncodeDynamicRange::SDR;
    }
    if (tmpNumber <= static_cast<uint32_t>(EncodeDynamicRange::SDR)) {
        return EncodeDynamicRange(tmpNumber);
    }
    return EncodeDynamicRange::SDR;
}

static bool parseNeedsPackProperties(napi_env env, napi_value root)
{
    bool tmpNeedsPackProperties = false;
    if (!GET_BOOL_BY_NAME(root, "needsPackProperties", tmpNeedsPackProperties)) {
        IMAGE_LOGD("No needsPackProperties in pack option");
    }
    return tmpNeedsPackProperties;
}

static int64_t parseBufferSize(napi_env env, napi_value root, ImagePackerAsyncContext *context = nullptr)
{
    napi_value tempValue = nullptr;
    int64_t defaultSize = getDefaultBufferSize(context);
    int64_t tmpNumber = defaultSize;
    if (napi_get_named_property(env, root, "bufferSize", &tempValue) != napi_ok) {
        IMAGE_LOGI("No bufferSize, Using default");
        return tmpNumber;
    }
    napi_get_value_int64(env, tempValue, &tmpNumber);
    IMAGE_LOGD("BufferSize is %{public}" PRId64, tmpNumber);
    if (tmpNumber < 0) {
        return defaultSize;
    }
    return tmpNumber;
}

static bool handlePixelMapList(ImagePackerAsyncContext* context)
{
    if (context->frameCount == 0) {
        IMAGE_LOGE("Parameter input error, invalid frameCount");
        return false;
    }
    if (context->rPixelMaps == nullptr || context->rPixelMaps->empty()) {
        IMAGE_LOGE("Parameter input error, pixelmaplist is empty");
        return false;
    }
    uint32_t pixelMapListLength = context->rPixelMaps->size();
    if (pixelMapListLength > context->frameCount) {
        for (uint32_t i = pixelMapListLength; i > context->frameCount; i--) {
            context->rPixelMaps->pop_back();
        }
    } else if (pixelMapListLength < context->frameCount) {
        for (uint32_t i = pixelMapListLength; i < context->frameCount; i++) {
            context->rPixelMaps->push_back((*context->rPixelMaps)[pixelMapListLength - 1]);
        }
    }
    return true;
}

static bool parsePackOptionOfdelayTimes(napi_env env, napi_value root, ImagePackerAsyncContext* context)
{
    napi_value tmpValue = nullptr;
    if (!GET_NODE_BY_NAME(root, "delayTimeList", tmpValue)) {
        IMAGE_LOGE("No delayTimeList in pack option");
        return false;
    }
    bool isDelayTimesArray = false;
    napi_is_array(env, tmpValue, &isDelayTimesArray);
    if (isDelayTimesArray) {
        int32_t num;
        uint32_t len = 0;
        if (napi_get_array_length(env, tmpValue, &len) != napi_ok || len == 0) {
            IMAGE_LOGE("Parse pack napi_get_array_length failed");
            return false;
        }
        for (size_t i = 0; i < len; i++) {
            napi_value item;
            napi_get_element(env, tmpValue, i, &item);
            if (napi_get_value_int32(env, item, &num) != napi_ok) {
                IMAGE_LOGE("Parse delayTime in item failed %{public}zu", i);
                return false;
            }
            if (num <= 0 || num > MASK_16) {
                IMAGE_LOGE("Invalid delayTime, out of range");
                return false;
            }
            context->packOption.delayTimes.push_back(static_cast<uint16_t>(num) & static_cast<uint16_t>(MASK_16));
        }
        if (len < context->frameCount) {
            for (uint32_t i = len; i < context->frameCount; i++) {
                context->packOption.delayTimes.push_back(static_cast<uint16_t>(num) & static_cast<uint16_t>(MASK_16));
            }
        }
    }
    return true;
}

static bool parsePackOptionOfFrameCout(napi_env env, napi_value root, ImagePackerAsyncContext* context)
{
    napi_value tmpValue = nullptr;
    if (!GET_NODE_BY_NAME(root, "frameCount", tmpValue)) {
        IMAGE_LOGE("No frameCount in pack option");
        return false;
    }
    uint32_t count = 0;
    napi_get_value_uint32(env, tmpValue, &count);
    context->frameCount = count;
    if (!handlePixelMapList(context)) {
        return false;
    }
    return parsePackOptionOfdelayTimes(env, root, context);
}

static bool parsePackOptionOfdisposalTypes(napi_env env, napi_value root, PackOption* opts)
{
    napi_value tmpValue = nullptr;
    GET_NODE_BY_NAME(root, "disposalTypes", tmpValue);
    bool isDisposalTypesArray = false;
    napi_is_array(env, tmpValue, &isDisposalTypesArray);
    if (isDisposalTypesArray) {
        int32_t num;
        uint32_t len = 0;
        if (napi_get_array_length(env, tmpValue, &len) != napi_ok) {
            IMAGE_LOGE("Parse pack napi_get_array_length failed");
            return false;
        }
        for (size_t i = 0; i < len; i++) {
            napi_value item;
            napi_get_element(env, tmpValue, i, &item);
            if (napi_get_value_int32(env, item, &num) != napi_ok) {
                IMAGE_LOGE("Parse disposalTypes in item failed %{public}zu", i);
                return false;
            }
            if (num < 0 || num > MASK_3) {
                IMAGE_LOGE("Invalid disposalTypes, out of range");
                return false;
            }
            opts->disposalTypes.push_back(static_cast<uint8_t>(num) & static_cast<uint8_t>(MASK_3));
        }
    }
    return true;
}

static bool parsePackOptionOfLoop(napi_env env, napi_value root, ImagePackerAsyncContext* context)
{
    napi_value nullValue;
    napi_get_null(env, &nullValue);
    if (root == nullValue) {
        IMAGE_LOGE("PackingOptionsForSequence is null");
        return false;
    }
    context->packOption.format = "image/gif";
    int32_t tmpNumber = 0;
    if (!GET_INT32_BY_NAME(root, "loopCount", tmpNumber)) {
        tmpNumber = 1;
    }
    if (tmpNumber < 0 || tmpNumber > MASK_16) {
        IMAGE_LOGE("Invalid loopCount");
        return false;
    }
    context->packOption.loop = static_cast<uint16_t>(tmpNumber) & static_cast<uint16_t>(MASK_16);
    return parsePackOptionOfFrameCout(env, root, context);
}

static bool parsePackOptionOfQuality(napi_env env, napi_value root, PackOption* opts)
{
    uint32_t tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "quality", tmpNumber)) {
        IMAGE_LOGE("No quality in pack option");
        return false;
    }
    if (tmpNumber > SIZE) {
        IMAGE_LOGE("Invalid quality");
        opts->quality = BYTE_FULL;
    } else {
        opts->quality = static_cast<uint8_t>(tmpNumber & 0xff);
    }
    return true;
}

static bool parsePackOptions(napi_env env, napi_value root, PackOption* opts)
{
    napi_value tmpValue = nullptr;

    if (!GET_NODE_BY_NAME(root, "format", tmpValue)) {
        IMAGE_LOGE("No format in pack option");
        return false;
    }

    bool isFormatArray = false;
    napi_is_array(env, tmpValue, &isFormatArray);
    auto formatType = ImageNapiUtils::getType(env, tmpValue);

    IMAGE_LOGD("parsePackOptions format type %{public}d, is array %{public}d",
        formatType, isFormatArray);

    char buffer[SIZE] = {0};
    size_t res = 0;
    if (napi_string == formatType) {
        if (napi_get_value_string_utf8(env, tmpValue, buffer, SIZE, &res) != napi_ok) {
            IMAGE_LOGE("Parse pack option format failed");
            return false;
        }
        opts->format = std::string(buffer);
    } else if (isFormatArray) {
        uint32_t len = 0;
        if (napi_get_array_length(env, tmpValue, &len) != napi_ok) {
            IMAGE_LOGE("Parse pack napi_get_array_length failed");
            return false;
        }
        IMAGE_LOGD("Parse pack array_length=%{public}u", len);
        for (size_t i = 0; i < len; i++) {
            napi_value item;
            napi_get_element(env, tmpValue, i, &item);
            if (napi_get_value_string_utf8(env, item, buffer, SIZE, &res) != napi_ok) {
                IMAGE_LOGE("Parse format in item failed %{public}zu", i);
                continue;
            }
            opts->format = std::string(buffer);
            IMAGE_LOGD("format is %{public}s.", opts->format.c_str());
        }
    } else {
        IMAGE_LOGE("Invalid pack option format type");
        return false;
    }
    opts->desiredDynamicRange = parseDynamicRange(env, root);
    IMAGE_LOGD("parsePackOptions format:[%{public}s]", opts->format.c_str());
    opts->needsPackProperties = parseNeedsPackProperties(env, root);
    return parsePackOptionOfQuality(env, root, opts);
}

static int32_t ParserPackingArgumentType(napi_env env, napi_value argv)
{
    napi_value constructor = nullptr;
    napi_value global = nullptr;
    bool isInstance = false;
    napi_status ret = napi_invalid_arg;

    ret = napi_is_array(env, argv, &isInstance);
    if (ret == napi_ok && isInstance) {
        IMAGE_LOGD("This is Array type!");
        return TYPE_ARRAY;
    }
    napi_get_global(env, &global);

    ret = napi_get_named_property(env, global, "ImageSource", &constructor);
    if (ret != napi_ok) {
        IMAGE_LOGE("Get ImageSourceNapi property failed!");
    }

    ret = napi_instanceof(env, argv, constructor, &isInstance);
    if (ret == napi_ok && isInstance) {
        IMAGE_LOGD("This is ImageSourceNapi type!");
        return TYPE_IMAGE_SOURCE;
    }

    ret = napi_get_named_property(env, global, "PixelMap", &constructor);
    if (ret != napi_ok) {
        IMAGE_LOGE("Get PixelMapNapi property failed!");
    }

    ret = napi_instanceof(env, argv, constructor, &isInstance);
    if (ret == napi_ok && isInstance) {
        IMAGE_LOGD("This is PixelMapNapi type!");
        return TYPE_PIXEL_MAP;
    }

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    ret = napi_get_named_property(env, global, "Picture", &constructor);
    if (ret != napi_ok) {
        IMAGE_LOGE("Get PictureNapi property failed!");
    }

    ret = napi_instanceof(env, argv, constructor, &isInstance);
    if (ret == napi_ok && isInstance) {
        IMAGE_LOGD("This is PictureNapi type!");
        return TYPE_PICTURE;
    }
#endif

    IMAGE_LOGE("Invalid type!");
    return TYPE_INVALID;
}

static std::shared_ptr<ImageSource> GetImageSourceFromNapi(napi_env env, napi_value value)
{
    if (env == nullptr || value == nullptr) {
        IMAGE_LOGE("GetImageSourceFromNapi input is null");
        return nullptr;
    }
    std::unique_ptr<ImageSourceNapi> imageSourceNapi = std::make_unique<ImageSourceNapi>();
    napi_status status = napi_unwrap(env, value, reinterpret_cast<void**>(&imageSourceNapi));
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("GetImageSourceFromNapi napi unwrap failed");
        return nullptr;
    }
    if (imageSourceNapi == nullptr) {
        IMAGE_LOGE("GetImageSourceFromNapi imageSourceNapi is nullptr");
        return nullptr;
    }
    return imageSourceNapi.release()->nativeImgSrc;
}

static void ParserPackingArguments(napi_env env,
    napi_value* argv, size_t argc, ImagePackerAsyncContext* context)
{
    int32_t refCount = 1;
    if (argc < PARAM1 || argc > PARAM3) {
        BuildMsgOnError(context, false, "Arguments Count error", COMMON_ERR_INVALID_PARAMETER);
    }
    context->packType = ParserPackingArgumentType(env, argv[PARAM0]);
    if (context->packType == TYPE_PICTURE || context->packType == TYPE_ARRAY) {
        context->needReturnErrorCode = true;
    }
    if (context->packType == TYPE_IMAGE_SOURCE) {
        context->rImageSource = GetImageSourceFromNapi(env, argv[PARAM0]);
        BuildMsgOnError(context, context->rImageSource != nullptr, "ImageSource mismatch",
            COMMON_ERR_INVALID_PARAMETER);
    } else if (context->packType == TYPE_PIXEL_MAP) {
        context->rPixelMap = PixelMapNapi::GetPixelMap(env, argv[PARAM0]);
        BuildMsgOnError(context, context->rPixelMap != nullptr, "Pixelmap is released",
            COMMON_ERR_INVALID_PARAMETER);
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    } else if (context->packType == TYPE_PICTURE) {
        context->rPicture = PictureNapi::GetPicture(env, argv[PARAM0]);
        BuildMsgOnError(context, context->rPicture != nullptr, "Picture mismatch",
            COMMON_ERR_INVALID_PARAMETER);
#endif
    } else if (context->packType == TYPE_ARRAY) {
        context->needReturnErrorCode = true;
        context->rPixelMaps = PixelMapNapi::GetPixelMaps(env, argv[PARAM0]);
        BuildMsgOnError(context, context->rPixelMaps != nullptr,
            "PixelMap mismatch", COMMON_ERR_INVALID_PARAMETER);
    } else {
        BuildMsgOnError(context, false, "Invalid Parameter", COMMON_ERR_INVALID_PARAMETER);
    }
    if (argc > PARAM1 && ImageNapiUtils::getType(env, argv[PARAM1]) == napi_object) {
        if (context->packType == TYPE_ARRAY) {
            BuildMsgOnError(context,
                parsePackOptionOfLoop(env, argv[PARAM1], context),
                "PackOptions mismatch", COMMON_ERR_INVALID_PARAMETER);
            context->resultBufferSize = parseBufferSize(env, argv[PARAM1]);
            BuildMsgOnError(context,
                parsePackOptionOfdisposalTypes(env, argv[PARAM1], &(context->packOption)),
                "PackOptions mismatch", COMMON_ERR_INVALID_PARAMETER);
        } else {
            BuildMsgOnError(context, parsePackOptions(env, argv[PARAM1], &(context->packOption)),
                "PackOptions mismatch", COMMON_ERR_INVALID_PARAMETER);
            context->resultBufferSize = parseBufferSize(env, argv[PARAM1], context);
        }
    }
    if (argc > PARAM2 && ImageNapiUtils::getType(env, argv[PARAM2]) == napi_function) {
        napi_create_reference(env, argv[PARAM2], refCount, &(context->callbackRef));
    }
}

napi_value ImagePackerNapi::Packing(napi_env env, napi_callback_info info, bool needReturnError,
    const char* taskName)
{
    ImageTrace imageTrace("ImagePackerNapi::Packing");
    IMAGE_LOGD("PackingFromNapi IN");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_THREE;
    napi_value argv[ARGS_THREE] = {0};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);

    IMG_JS_ARGS(env, info, status, argc, argv, thisVar);
    NAPI_ASSERT(env, IMG_IS_OK(status), "fail to napi_get_cb_info");

    std::unique_ptr<ImagePackerAsyncContext> asyncContext = std::make_unique<ImagePackerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->constructor_));
    NAPI_ASSERT(env, IMG_IS_READY(status, asyncContext->constructor_), "fail to unwrap constructor_");
    asyncContext->needReturnErrorCode = needReturnError;

    asyncContext->rImagePacker = asyncContext->constructor_->nativeImgPck;
    ParserPackingArguments(env, argv, argc, asyncContext.get());
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    }

    ImageNapiUtils::HicheckerReport();

    if (IsImagePackerErrorOccur(asyncContext.get())) {
        if (PackingErrorSendEvent(env, asyncContext.get(), napi_eprio_high, taskName)) {
            asyncContext.release();
        }
    } else {
        IMG_CREATE_CREATE_ASYNC_WORK_WITH_QOS(env, status, "Packing",
            PackingExec, PackingComplete, asyncContext, asyncContext->work, napi_qos_user_initiated);
    }

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value ImagePackerNapi::Packing(napi_env env, napi_callback_info info)
{
    return Packing(env, info, false, "ImagePacker.packing");
}

napi_value ImagePackerNapi::PackToData(napi_env env, napi_callback_info info)
{
    return Packing(env, info, true, "ImagePacker.packToData");
}

napi_value ImagePackerNapi::GetSupportedFormats(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<ImagePackerAsyncContext> context = std::make_unique<ImagePackerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&context->constructor_));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->constructor_),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
    std::set<std::string> formats;
    uint32_t ret = context->constructor_->nativeImgPck->GetSupportedFormats(formats);

    IMG_NAPI_CHECK_RET_D((ret == SUCCESS),
        nullptr, IMAGE_LOGE("fail to get supported formats"));

    napi_create_array(env, &result);
    size_t i = 0;
    for (const std::string& formatStr: formats) {
        napi_value format = nullptr;
        napi_create_string_latin1(env, formatStr.c_str(), formatStr.length(), &format);
        napi_set_element(env, result, i, format);
        i++;
    }
    return result;
}

STATIC_EXEC_FUNC(Release)
{
    IMAGE_LOGD("%{public}s IN", __func__);
    auto context = static_cast<ImagePackerAsyncContext*>(data);
    if (context != nullptr && context->constructor_ != nullptr) {
        delete context->constructor_;
        context->constructor_ = nullptr;
    }
}

STATIC_COMPLETE_FUNC(Release)
{
    IMAGE_LOGD("%{public}s IN", __func__);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<ImagePackerAsyncContext*>(data);
    CommonCallbackRoutine(env, const_cast<ImagePackerAsyncContext *&>(context), result);
}

napi_value ImagePackerNapi::Release(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("ImagePackerNapi::Release");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = 1;

    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMAGE_LOGD("Release argCount is [%{public}zu]", argCount);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<ImagePackerAsyncContext> context = std::make_unique<ImagePackerAsyncContext>();
    status = napi_remove_wrap(env, thisVar, reinterpret_cast<void**>(&context->constructor_));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->constructor_), result,
        IMAGE_LOGE("fail to unwrap context"));
    IMAGE_LOGD("Release argCount is [%{public}zu]", argCount);
    if (argCount == 1 && ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_function) {
        napi_create_reference(env, argValue[NUM_0], refCount, &context->callbackRef);
    }

    if (context->callbackRef == nullptr) {
        napi_create_promise(env, &(context->deferred), &result);
    }

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "Release", ReleaseExec, ReleaseComplete, context, context->work);
    return result;
}

static void ParserPackToFileArguments(napi_env env,
    napi_value* argv, size_t argc, ImagePackerAsyncContext* context)
{
    int32_t refCount = 1;
    if (argc < PARAM1 || argc > PARAM4) {
        BuildMsgOnError(context, false, "Arguments Count error", ERR_IMAGE_INVALID_PARAMETER);
    }
    context->packType = ParserPackingArgumentType(env, argv[PARAM0]);
    if (context->packType == TYPE_IMAGE_SOURCE) {
        context->rImageSource = GetImageSourceFromNapi(env, argv[PARAM0]);
        BuildMsgOnError(context, context->rImageSource != nullptr,
            "ImageSource mismatch", ERR_IMAGE_INVALID_PARAMETER);
    } else if (context->packType == TYPE_PIXEL_MAP) {
        context->rPixelMap = PixelMapNapi::GetPixelMap(env, argv[PARAM0]);
        BuildMsgOnError(context, context->rPixelMap != nullptr,
            "Pixelmap is released", ERR_IMAGE_INVALID_PARAMETER);
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    } else if (context->packType == TYPE_PICTURE) {
        context->rPicture = PictureNapi::GetPicture(env, argv[PARAM0]);
        BuildMsgOnError(context, context->rPicture != nullptr,
            "Picture mismatch", COMMON_ERR_INVALID_PARAMETER);
#endif
    } else if (context->packType == TYPE_ARRAY) {
        context->rPixelMaps = PixelMapNapi::GetPixelMaps(env, argv[PARAM0]);
        BuildMsgOnError(context, context->rPixelMaps != nullptr, "PixelMap mismatch", COMMON_ERR_INVALID_PARAMETER);
    } else {
        BuildMsgOnError(context, false, "Invalid Parameter", COMMON_ERR_INVALID_PARAMETER);
    }
    if (argc > PARAM1 && ImageNapiUtils::getType(env, argv[PARAM1]) == napi_number) {
        uint32_t errorCode = ((context->packType == TYPE_PICTURE ||
            context->packType == TYPE_ARRAY)) ? IMAGE_BAD_PARAMETER : ERR_IMAGE_INVALID_PARAMETER;
        BuildMsgOnError(context, (napi_get_value_int32(env, argv[PARAM1], &(context->fd)) == napi_ok &&
            context->fd > INVALID_FD), "fd mismatch", errorCode);
    }
    if (argc > PARAM2 && ImageNapiUtils::getType(env, argv[PARAM2]) == napi_object) {
        if (context->packType == TYPE_ARRAY) {
            BuildMsgOnError(context, parsePackOptionOfLoop(env, argv[PARAM2], context),
                "PackOptions mismatch", COMMON_ERR_INVALID_PARAMETER);
            BuildMsgOnError(context, parsePackOptionOfdisposalTypes(env, argv[PARAM2], &(context->packOption)),
                "PackOptions mismatch", COMMON_ERR_INVALID_PARAMETER);
        } else {
            BuildMsgOnError(context, parsePackOptions(env, argv[PARAM2], &(context->packOption)),
                "PackOptions mismatch", ERR_IMAGE_INVALID_PARAMETER);
        }
    }
    if (argc > PARAM3 && ImageNapiUtils::getType(env, argv[PARAM3]) == napi_function) {
        napi_create_reference(env, argv[PARAM3], refCount, &(context->callbackRef));
    }
}

static void FinalizePacking(ImagePackerAsyncContext* context)
{
    int64_t packedSize = 0;
    auto packRes = context->rImagePacker->FinalizePacking(packedSize);
    IMAGE_LOGD("packRes=%{public}d packedSize=%{public}" PRId64, packRes, packedSize);
    if (packRes == SUCCESS && packedSize > 0) {
        context->packedSize = packedSize;
        context->status = SUCCESS;
    } else {
        context->status = ERROR;
        std::string errorMsg = GetErrorCodeMsg(packRes);
        BuildMsgOnError(context, packRes == SUCCESS, errorMsg, packRes);
        IMAGE_LOGE("Packing failed, packedSize outside size.");
        if (context->packType == TYPE_PICTURE) {
            BuildMsgOnError(context, packRes == SUCCESS, "Failed to encode image.",
                packRes == ERR_IMAGE_INVALID_PARAMETER ? IMAGE_BAD_PARAMETER : IMAGE_ENCODE_FAILED);
        }
    }
}

STATIC_EXEC_FUNC(PackToFile)
{
    auto context = static_cast<ImagePackerAsyncContext*>(data);
    if (context->fd <= INVALID_FD) {
        uint32_t errorCode = ((context->packType == TYPE_PICTURE) ||
            (context->packType == TYPE_ARRAY)) ? IMAGE_BAD_PARAMETER : ERR_IMAGE_INVALID_PARAMETER;
        BuildMsgOnError(context, false, "ImagePacker invalid fd", errorCode);
        return;
    }

    auto startRes = context->rImagePacker->StartPacking(context->fd, context->packOption);
    if (startRes != SUCCESS) {
        context->status = ERROR;
        if (context->packType == TYPE_PICTURE) {
            BuildMsgOnError(context, startRes == SUCCESS, "PackToFile start packing failed",
                startRes == ERR_IMAGE_INVALID_PARAMETER ? IMAGE_BAD_PARAMETER : IMAGE_ENCODE_FAILED);
            return;
        }
        BuildMsgOnError(context, startRes == SUCCESS, "Start packing failed", startRes);
        return;
    }
    if (context->packType == TYPE_IMAGE_SOURCE) {
        IMAGE_LOGD("ImagePacker set image source");
        if (!context->rImageSource) {
            BuildMsgOnError(context, !context->rImageSource, "ImageSource is nullptr", ERR_IMAGE_INVALID_PARAMETER);
            return;
        }
        context->rImagePacker->AddImage(*(context->rImageSource));
    } else if (context->packType == TYPE_PIXEL_MAP) {
        IMAGE_LOGD("ImagePacker set pixelmap");
        if (!context->rPixelMap) {
            BuildMsgOnError(context, !context->rImageSource, "Pixelmap is nullptr", ERR_IMAGE_INVALID_PARAMETER);
            return;
        }
        context->rImagePacker->AddImage(*(context->rPixelMap));
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    } else if (context->packType == TYPE_PICTURE) {
        if (!SetPicture(context)) {
            return;
        }
#endif
    } else if (context->packType == TYPE_ARRAY) {
        if (!SetArrayPixel(context)) {
            return;
        }
    }
    FinalizePacking(context);
}

STATIC_COMPLETE_FUNC(PackToFile)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    auto context = static_cast<ImagePackerAsyncContext*>(data);
    CommonCallbackRoutine(env, context, result);
}

napi_value ImagePackerNapi::PackToFile(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("ImagePackerNapi::PackToFile");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_FOUR;
    napi_value argv[ARGS_FOUR] = {0};
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &result);

    IMG_JS_ARGS(env, info, status, argc, argv, thisVar);
    NAPI_ASSERT(env, IMG_IS_OK(status), "fail to napi_get_cb_info");

    std::unique_ptr<ImagePackerAsyncContext> asyncContext = std::make_unique<ImagePackerAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->constructor_));
    NAPI_ASSERT(env, IMG_IS_READY(status, asyncContext->constructor_), "fail to unwrap constructor_");

    asyncContext->rImagePacker = asyncContext->constructor_->nativeImgPck;
    ParserPackToFileArguments(env, argv, argc, asyncContext.get());
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    }

    ImageNapiUtils::HicheckerReport();

    if (IsImagePackerErrorOccur(asyncContext.get())) {
        if (PackingErrorSendEvent(env, asyncContext.get(), napi_eprio_high, "ImagePacker.packToFile")) {
            asyncContext.release();
        }
    } else {
        IMG_CREATE_CREATE_ASYNC_WORK_WITH_QOS(env, status, "PackToFile",
            PackToFileExec, PackToFileComplete, asyncContext, asyncContext->work, napi_qos_user_initiated);
    }

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}
void ImagePackerNapi::release()
{
    if (!isRelease) {
        nativeImgPck = nullptr;
        isRelease = true;
    }
}
std::shared_ptr<ImagePacker> ImagePackerNapi::GetNative(ImagePackerNapi* napi)
{
    if (napi != nullptr) {
        return napi->nativeImgPck;
    }
    return nullptr;
}

napi_value ImagePackerNapi::GetImagePackerSupportedFormats(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    std::set<std::string> formats;
    uint32_t ret = ImagePacker::GetSupportedFormats(formats);
    IMG_NAPI_CHECK_RET_D((ret == SUCCESS), result, IMAGE_LOGE("Fail to get encode supported formats"));
    napi_create_array(env, &result);
    size_t count = 0;
    for (const std::string& formatStr: formats) {
        napi_value format = nullptr;
        napi_create_string_latin1(env, formatStr.c_str(), formatStr.length(), &format);
        napi_set_element(env, result, count, format);
        count++;
    }
    return result;
}
}  // namespace Media
}  // namespace OHOS
