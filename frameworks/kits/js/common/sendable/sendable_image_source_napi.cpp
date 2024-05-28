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
#include "sendable_image_source_napi.h"
#include <fcntl.h>
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "color_space_object_convertor.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "SendableImageSourceNapi"

namespace {
    constexpr int INVALID_FD = -1;
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
}

namespace OHOS {
namespace Media {
thread_local napi_ref SendableImageSourceNapi::sConstructor_ = nullptr;
thread_local std::shared_ptr<ImageSource> SendableImageSourceNapi::sImgSrc_ = nullptr;
std::shared_ptr<IncrementalPixelMap> SendableImageSourceNapi::sIncPixelMap_ = nullptr;
static const std::string CLASS_NAME = "ImageSourceSendable";
static const std::string FILE_URL_PREFIX = "file://";
std::string SendableImageSourceNapi::filePath_ = "";
int SendableImageSourceNapi::fileDescriptor_ = -1;
void* SendableImageSourceNapi::fileBuffer_ = nullptr;
size_t SendableImageSourceNapi::fileBufferSize_ = 0;
napi_ref SendableImageSourceNapi::pixelMapFormatRef_ = nullptr;
napi_ref SendableImageSourceNapi::propertyKeyRef_ = nullptr;
napi_ref SendableImageSourceNapi::imageFormatRef_ = nullptr;
napi_ref SendableImageSourceNapi::alphaTypeRef_ = nullptr;
napi_ref SendableImageSourceNapi::scaleModeRef_ = nullptr;
napi_ref SendableImageSourceNapi::componentTypeRef_ = nullptr;
napi_ref SendableImageSourceNapi::decodingDynamicRangeRef_ = nullptr;
napi_ref SendableImageSourceNapi::decodingResolutionQualityRef_ = nullptr;

struct RawFileDescriptorInfo {
    int32_t fd = INVALID_FD;
    int32_t offset;
    int32_t length;
};

struct ImageSourceAsyncContext {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef = nullptr;
    SendableImageSourceNapi *constructor_;
    uint32_t status;
    std::string pathName = "";
    int fdIndex = INVALID_FD;
    void* sourceBuffer = nullptr;
    size_t sourceBufferSize = NUM_0;
    std::string keyStr;
    std::string valueStr;
    std::vector<std::string> keyStrArray;
    std::vector<std::pair<std::string, std::string>> kVStrArray;
    std::string defaultValueStr;
    int32_t valueInt;
    int32_t deufltValueInt;
    void *updataBuffer;
    size_t updataBufferSize;
    uint32_t updataBufferOffset = 0;
    uint32_t updataLength = 0;
    bool isCompleted = false;
    bool isSuccess = false;
    bool isBatch = false;
    size_t pathNameLength;
    SourceOptions opts;
    uint32_t index = 0;
    ImageInfo imageInfo;
    DecodeOptions decodeOpts;
    std::shared_ptr<ImageSource> rImageSource;
    std::shared_ptr<PixelMap> rPixelMap;
    std::string errMsg;
    std::multimap<std::int32_t, std::string> errMsgArray;
    std::unique_ptr<std::vector<std::unique_ptr<PixelMap>>> pixelMaps;
    std::unique_ptr<std::vector<int32_t>> delayTimes;
    std::unique_ptr<std::vector<int32_t>> disposalType;
    uint32_t frameCount = 0;
    struct RawFileDescriptorInfo rawFileInfo;
};

struct ImageEnum {
    std::string name;
    int32_t numVal;
    std::string strVal;
};

static std::vector<struct ImageEnum> sPixelMapFormatMap = {
    {"UNKNOWN", 0, ""},
    {"ARGB_8888", 1, ""},
    {"RGB_565", 2, ""},
    {"RGBA_8888", 3, ""},
    {"BGRA_8888", 4, ""},
    {"RGB_888", 5, ""},
    {"ALPHA_8", 6, ""},
    {"RGBA_F16", 7, ""},
    {"NV21", 8, ""},
    {"NV12", 9, ""},
};

static std::vector<struct ImageEnum> sPropertyKeyMap = {
    {"BITS_PER_SAMPLE", 0, "BitsPerSample"},
    {"ORIENTATION", 0, "Orientation"},
    {"IMAGE_LENGTH", 0, "ImageLength"},
    {"IMAGE_WIDTH", 0, "ImageWidth"},
    {"GPS_LATITUDE", 0, "GPSLatitude"},
    {"GPS_LONGITUDE", 0, "GPSLongitude"},
    {"GPS_LATITUDE_REF", 0, "GPSLatitudeRef"},
    {"GPS_LONGITUDE_REF", 0, "GPSLongitudeRef"},
    {"DATE_TIME_ORIGINAL", 0, "DateTimeOriginal"},
    {"EXPOSURE_TIME", 0, "ExposureTime"},
    {"SCENE_TYPE", 0, "SceneType"},
    {"ISO_SPEED_RATINGS", 0, "ISOSpeedRatings"},
    {"F_NUMBER", 0, "FNumber"},
    {"COMPRESSED_BITS_PER_PIXEL", 0, "CompressedBitsPerPixel"},
    {"DATE_TIME", 0, "DateTime"},
    {"GPS_TIME_STAMP", 0, "GPSTimeStamp"},
    {"GPS_DATE_STAMP", 0, "GPSDateStamp"},
    {"IMAGE_DESCRIPTION", 0, "ImageDescription"},
    {"MAKE", 0, "Make"},
    {"MODEL", 0, "Model"},
    {"PHOTO_MODE", 0, "PhotoMode"},
    {"SENSITIVITY_TYPE", 0, "SensitivityType"},
    {"STANDARD_OUTPUT_SENSITIVITY", 0, "StandardOutputSensitivity"},
    {"RECOMMENDED_EXPOSURE_INDEX", 0, "RecommendedExposureIndex"},
    {"ISO_SPEED", 0, "ISOSpeedRatings"},
    {"APERTURE_VALUE", 0, "ApertureValue"},
    {"EXPOSURE_BIAS_VALUE", 0, "ExposureBiasValue"},
    {"METERING_MODE", 0, "MeteringMode"},
    {"LIGHT_SOURCE", 0, "LightSource"},
    {"FLASH", 0, "Flash"},
    {"FOCAL_LENGTH", 0, "FocalLength"},
    {"USER_COMMENT", 0, "UserComment"},
    {"PIXEL_X_DIMENSION", 0, "PixelXDimension"},
    {"PIXEL_Y_DIMENSION", 0, "PixelYDimension"},
    {"WHITE_BALANCE", 0, "WhiteBalance"},
    {"FOCAL_LENGTH_IN_35_MM_FILM", 0, "FocalLengthIn35mmFilm"},
    {"CAPTURE_MODE", 0, "HwMnoteCaptureMode"},
    {"PHYSICAL_APERTURE", 0, "HwMnotePhysicalAperture"},
    {"ROLL_ANGLE", 0, "HwMnoteRollAngle"},
    {"PITCH_ANGLE", 0, "HwMnotePitchAngle"},
    {"SCENE_FOOD_CONF", 0, "HwMnoteSceneFoodConf"},
    {"SCENE_STAGE_CONF", 0, "HwMnoteSceneStageConf"},
    {"SCENE_BLUE_SKY_CONF", 0, "HwMnoteSceneBlueSkyConf"},
    {"SCENE_GREEN_PLANT_CONF", 0, "HwMnoteSceneGreenPlantConf"},
    {"SCENE_BEACH_CONF", 0, "HwMnoteSceneBeachConf"},
    {"SCENE_SNOW_CONF", 0, "HwMnoteSceneSnowConf"},
    {"SCENE_SUNSET_CONF", 0, "HwMnoteSceneSunsetConf"},
    {"SCENE_FLOWERS_CONF", 0, "HwMnoteSceneFlowersConf"},
    {"SCENE_NIGHT_CONF", 0, "HwMnoteSceneNightConf"},
    {"SCENE_TEXT_CONF", 0, "HwMnoteSceneTextConf"},
    {"FACE_COUNT", 0, "HwMnoteFaceCount"},
    {"FOCUS_MODE", 0, "HwMnoteFocusMode"},
};
static std::vector<struct ImageEnum> sImageFormatMap = {
    {"YCBCR_422_SP", 1000, ""},
    {"JPEG", 2000, ""},
};
static std::vector<struct ImageEnum> sAlphaTypeMap = {
    {"UNKNOWN", 0, ""},
    {"OPAQUE", 1, ""},
    {"PREMUL", 2, ""},
    {"UNPREMUL", 3, ""},
};
static std::vector<struct ImageEnum> sScaleModeMap = {
    {"FIT_TARGET_SIZE", 0, ""},
    {"CENTER_CROP", 1, ""},
};
static std::vector<struct ImageEnum> sComponentTypeMap = {
    {"YUV_Y", 1, ""},
    {"YUV_U", 2, ""},
    {"YUV_V", 3, ""},
    {"JPEG", 4, ""},
};
static std::vector<struct ImageEnum> sDecodingDynamicRangeMap = {
    {"AUTO", 0, ""},
    {"SDR", 1, ""},
    {"HDR", 2, ""},
};
static std::vector<struct ImageEnum> sDecodingResolutionQualityMap = {
    {"LOW", 1, ""},
    {"MEDIUM", 2, ""},
    {"HIGH", 3, ""},
};

static bool ParseSize(napi_env env, napi_value root, Size* size)
{
    if (size == nullptr) {
        IMAGE_LOGE("size is nullptr");
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

static void parseSourceOptions(napi_env env, napi_value root, SourceOptions* opts)
{
    if (!ImageNapiUtils::GetInt32ByName(env, root, "sourceDensity", &(opts->baseDensity))) {
        IMAGE_LOGD("no sourceDensity");
    }

    int32_t pixelFormat = 0;
    if (!ImageNapiUtils::GetInt32ByName(env, root, "sourcePixelFormat", &pixelFormat)) {
        IMAGE_LOGD("no sourcePixelFormat");
    } else {
        opts->pixelFormat = static_cast<PixelFormat>(pixelFormat);
        IMAGE_LOGI("sourcePixelFormat:%{public}d", static_cast<int32_t>(opts->pixelFormat));
    }

    napi_value tmpValue = nullptr;
    if (!GET_NODE_BY_NAME(root, "sourceSize", tmpValue)) {
        IMAGE_LOGD("no sourceSize");
    } else {
        if (!ParseSize(env, tmpValue, &(opts->size))) {
            IMAGE_LOGD("ParseSize error");
        }
        IMAGE_LOGI("sourceSize:(%{public}d, %{public}d)", opts->size.width, opts->size.height);
    }
}

static void PrepareNapiEnv(napi_env env)
{
    napi_value globalValue;
    napi_get_global(env, &globalValue);
    napi_value func;
    napi_get_named_property(env, globalValue, "requireNapi", &func);

    napi_value imageInfo;
    napi_create_string_utf8(env, "multimedia.sendableimage", NAPI_AUTO_LENGTH, &imageInfo);
    napi_value funcArgv[1] = { imageInfo };
    napi_value returnValue;
    napi_call_function(env, globalValue, func, 1, funcArgv, &returnValue);
}

static bool hasNamedProperty(napi_env env, napi_value object, const std::string& name)
{
    bool res = false;
    return (napi_has_named_property(env, object, name.c_str(), &res) == napi_ok) && res;
}

static bool parseRawFileItem(napi_env env, napi_value argValue, const std::string& item, int32_t* value)
{
    napi_value nItem;
    if (napi_get_named_property(env, argValue, item.c_str(), &nItem) != napi_ok) {
        IMAGE_LOGE("Failed to parse RawFileDescriptor item %{public}s", item.c_str());
        return false;
    }
    if (napi_get_value_int32(env, nItem, value) != napi_ok) {
        IMAGE_LOGE("Failed to get RawFileDescriptor item %{public}s value", item.c_str());
        return false;
    }
    return true;
}

static bool isRawFileDescriptor(napi_env env, napi_value argValue, ImageSourceAsyncContext* context)
{
    if (env == nullptr || argValue == nullptr || context == nullptr) {
        IMAGE_LOGE("isRawFileDescriptor invalid input");
        return false;
    }
    if (!hasNamedProperty(env, argValue, "fd") ||
        !hasNamedProperty(env, argValue, "offset") ||
        !hasNamedProperty(env, argValue, "length")) {
        IMAGE_LOGD("RawFileDescriptor mismatch");
        return false;
    }
    if (parseRawFileItem(env, argValue, "fd", &(context->rawFileInfo.fd)) &&
        parseRawFileItem(env, argValue, "offset", &(context->rawFileInfo.offset)) &&
        parseRawFileItem(env, argValue, "length", &(context->rawFileInfo.length))) {
        return true;
    }

    IMAGE_LOGE("Failed to parse RawFileDescriptor item");
    return false;
}

static std::string FileUrlToRawPath(const std::string &path)
{
    if (path.size() > FILE_URL_PREFIX.size() &&
        (path.compare(0, FILE_URL_PREFIX.size(), FILE_URL_PREFIX) == 0)) {
        return path.substr(FILE_URL_PREFIX.size());
    }
    return path;
}

static bool ParseRegion(napi_env env, napi_value root, Rect* region)
{
    napi_value tmpValue = nullptr;

    if (region == nullptr) {
        IMAGE_LOGE("region is nullptr");
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

static bool IsSupportPixelFormat(int32_t val)
{
    if (val >= static_cast<int32_t>(PixelFormat::UNKNOWN) &&
        val <= static_cast<int32_t>(PixelFormat::NV12)) {
        return true;
    }

    return false;
}

static PixelFormat ParsePixlForamt(int32_t val)
{
    if (val <= static_cast<int32_t>(PixelFormat::CMYK)) {
        return PixelFormat(val);
    }

    return PixelFormat::UNKNOWN;
}

static ResolutionQuality ParseResolutionQuality(napi_env env, napi_value root)
{
    uint32_t resolutionQuality = NUM_0;
    if (!GET_UINT32_BY_NAME(root, "resolutionQuality", resolutionQuality)) {
        IMAGE_LOGD("no resolutionQuality");
        return ResolutionQuality::LOW;
    }
    if (resolutionQuality <= static_cast<uint32_t>(ResolutionQuality::HIGH)) {
        return ResolutionQuality(resolutionQuality);
    }
    return ResolutionQuality::LOW;
}

static DecodeDynamicRange ParseDynamicRange(napi_env env, napi_value root)
{
    uint32_t tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "desiredDynamicRange", tmpNumber)) {
        IMAGE_LOGD("no desiredDynamicRange");
        return DecodeDynamicRange::SDR;
    }
    if (tmpNumber <= static_cast<uint32_t>(DecodeDynamicRange::HDR)) {
        return DecodeDynamicRange(tmpNumber);
    }
    return DecodeDynamicRange::SDR;
}

static bool ParseDecodeOptions2(napi_env env, napi_value root, DecodeOptions* opts, std::string &error)
{
    uint32_t tmpNumber = 0;
    if (!GET_UINT32_BY_NAME(root, "desiredPixelFormat", tmpNumber)) {
        IMAGE_LOGD("no desiredPixelFormat");
    } else {
        if (IsSupportPixelFormat(tmpNumber)) {
            opts->desiredPixelFormat = ParsePixlForamt(tmpNumber);
        } else {
            IMAGE_LOGD("Invalid desiredPixelFormat %{public}d", tmpNumber);
            error = "DecodeOptions mismatch";
            return false;
        }
    }

    if (!GET_INT32_BY_NAME(root, "fitDensity", opts->fitDensity)) {
        IMAGE_LOGD("no fitDensity");
    }

    if (GET_UINT32_BY_NAME(root, "fillColor", opts->SVGOpts.fillColor.color)) {
        opts->SVGOpts.fillColor.isValidColor = true;
        IMAGE_LOGD("fillColor %{public}x", opts->SVGOpts.fillColor.color);
    } else {
        IMAGE_LOGD("no fillColor");
    }

    if (GET_UINT32_BY_NAME(root, "SVGResize", opts->SVGOpts.SVGResize.resizePercentage)) {
        opts->SVGOpts.SVGResize.isValidPercentage = true;
        IMAGE_LOGD("SVGResize percentage %{public}x", opts->SVGOpts.SVGResize.resizePercentage);
    } else {
        IMAGE_LOGD("no SVGResize percentage");
    }
    napi_value nDesiredColorSpace = nullptr;
    if (napi_get_named_property(env, root, "desiredColorSpace", &nDesiredColorSpace) == napi_ok) {
        opts->desiredColorSpaceInfo = OHOS::ColorManager::GetColorSpaceByJSObject(env, nDesiredColorSpace);
        IMAGE_LOGD("desiredColorSpace parse finished");
    }
    if (opts->desiredColorSpaceInfo == nullptr) {
        IMAGE_LOGD("no desiredColorSpace");
    }
    opts->desiredDynamicRange = ParseDynamicRange(env, root);
    opts->resolutionQuality = ParseResolutionQuality(env, root);
    return true;
}

static bool ParseDecodeOptions(napi_env env, napi_value root, DecodeOptions* opts,
    uint32_t* pIndex, std::string &error)
{
    napi_value tmpValue = nullptr;

    if (!ImageNapiUtils::GetUint32ByName(env, root, "index", pIndex)) {
        IMAGE_LOGD("no index");
    }

    if (opts == nullptr) {
        IMAGE_LOGE("opts is nullptr");
        return false;
    }

    if (!GET_UINT32_BY_NAME(root, "sampleSize", opts->sampleSize)) {
        IMAGE_LOGD("no sampleSize");
    }

    if (!GET_UINT32_BY_NAME(root, "rotate", opts->rotateNewDegrees)) {
        IMAGE_LOGD("no rotate");
    } else {
        if (opts->rotateNewDegrees >= 0 &&
            opts->rotateNewDegrees <= 360) { // 360 is the maximum rotation angle.
            opts->rotateDegrees = static_cast<float>(opts->rotateNewDegrees);
        } else {
            IMAGE_LOGD("Invalid rotate %{public}d", opts->rotateNewDegrees);
            error = "DecodeOptions mismatch";
            return false;
        }
    }

    if (!GET_BOOL_BY_NAME(root, "editable", opts->editable)) {
        IMAGE_LOGD("no editable");
    }

    if (!GET_NODE_BY_NAME(root, "desiredSize", tmpValue)) {
        IMAGE_LOGD("no desiredSize");
    } else {
        if (!ParseSize(env, tmpValue, &(opts->desiredSize))) {
            IMAGE_LOGD("ParseSize error");
        }
    }

    if (!GET_NODE_BY_NAME(root, "desiredRegion", tmpValue)) {
        IMAGE_LOGD("no desiredRegion");
    } else {
        if (!ParseRegion(env, tmpValue, &(opts->CropRect))) {
            IMAGE_LOGD("ParseRegion error");
        }
    }
    return ParseDecodeOptions2(env, root, opts, error);
}

static void ImageSourceCallbackRoutine(napi_env env, ImageSourceAsyncContext* &context, const napi_value &valueParam)
{
    napi_value result[NUM_2] = {0};
    napi_value retVal;
    napi_value callback = nullptr;

    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    if (context == nullptr) {
        IMAGE_LOGE("context is nullptr");
        return;
    }

    if (context->status == SUCCESS) {
        result[NUM_1] = valueParam;
    } else if (context->errMsg.size() > 0) {
        napi_create_string_utf8(env, context->errMsg.c_str(), NAPI_AUTO_LENGTH, &result[NUM_0]);
    } else {
        IMAGE_LOGD("error status, no message");
        napi_create_string_utf8(env, "error status, no message", NAPI_AUTO_LENGTH, &result[NUM_0]);
    }

    if (context->deferred) {
        if (context->status == SUCCESS) {
            napi_resolve_deferred(env, context->deferred, result[NUM_1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[NUM_0]);
        }
    } else {
        IMAGE_LOGD("call callback function");
        napi_get_reference_value(env, context->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, NUM_2, result, &retVal);
        napi_delete_reference(env, context->callbackRef);
    }

    napi_delete_async_work(env, context->work);

    delete context;
    context = nullptr;
}

static std::shared_ptr<PixelMap> CreatePixelMapInner(SendableImageSourceNapi *thisPtr,
    std::shared_ptr<ImageSource> imageSource, uint32_t index, DecodeOptions decodeOpts, uint32_t &status)
{
    if (thisPtr == nullptr || imageSource == nullptr) {
        IMAGE_LOGE("Invailed args");
        status = ERROR;
        return nullptr;
    }

    std::shared_ptr<PixelMap> pixelMap;
    auto incPixelMap = thisPtr->GetIncrementalPixelMap();
    if (incPixelMap != nullptr) {
        IMAGE_LOGD("Get Incremental PixelMap!!!");
        pixelMap = incPixelMap;
    } else {
        decodeOpts.invokeType = JS_INTERFACE;
        pixelMap = imageSource->CreatePixelMapEx(index, decodeOpts, status);
    }

    if (status != SUCCESS || !IMG_NOT_NULL(pixelMap)) {
        IMAGE_LOGE("Create PixelMap error");
    }

    return pixelMap;
}

static void CreatePixelMapExecute(napi_env env, void *data)
{
    IMAGE_LOGD("CreatePixelMapExecute IN");
    if (data == nullptr) {
        IMAGE_LOGE("data is nullptr");
        return;
    }
    auto context = static_cast<ImageSourceAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("empty context");
        return;
    }

    if (context->errMsg.size() > 0) {
        IMAGE_LOGE("mismatch args");
        context->status = ERROR;
        return;
    }

    context->rPixelMap = CreatePixelMapInner(context->constructor_, context->rImageSource,
        context->index, context->decodeOpts, context->status);

    if (context->status != SUCCESS) {
        context->errMsg = "Create PixelMap error";
        IMAGE_LOGE("Create PixelMap error");
    }
    IMAGE_LOGD("CreatePixelMapExecute OUT");
}

static void CreatePixelMapComplete(napi_env env, napi_status status, void *data)
{
    IMAGE_LOGD("CreatePixelMapComplete IN");
    napi_value result = nullptr;
    auto context = static_cast<ImageSourceAsyncContext*>(data);

    if (context->status == SUCCESS) {
        result = SendablePixelMapNapi::CreateSendablePixelMap(env, context->rPixelMap);
    } else {
        napi_get_undefined(env, &result);
    }
    IMAGE_LOGD("CreatePixelMapComplete OUT");
    ImageSourceCallbackRoutine(env, context, result);
}

static std::unique_ptr<ImageSource> CreateNativeImageSource(napi_env env, napi_value argValue,
    SourceOptions &opts, ImageSourceAsyncContext* context)
{
    std::unique_ptr<ImageSource> imageSource = nullptr;
    uint32_t errorCode = ERR_MEDIA_INVALID_VALUE;
    napi_status status;

    auto inputType = ImageNapiUtils::getType(env, argValue);
    if (napi_string == inputType) { // File Path
        if (!ImageNapiUtils::GetUtf8String(env, argValue, context->pathName)) {
            IMAGE_LOGE("fail to get pathName");
            return imageSource;
        }
        context->pathName = FileUrlToRawPath(context->pathName);
        context->pathNameLength = context->pathName.size();
        IMAGE_LOGD("pathName is [%{public}s]", context->pathName.c_str());
        imageSource = ImageSource::CreateImageSource(context->pathName, opts, errorCode);
    } else if (napi_number == inputType) { // Fd
        napi_get_value_int32(env, argValue, &context->fdIndex);
        IMAGE_LOGD("CreateImageSource fdIndex is [%{public}d]", context->fdIndex);
        imageSource = ImageSource::CreateImageSource(context->fdIndex, opts, errorCode);
    } else if (isRawFileDescriptor(env, argValue, context)) {
        IMAGE_LOGE(
            "CreateImageSource RawFileDescriptor fd: %{public}d, offset: %{public}d, length: %{public}d",
            context->rawFileInfo.fd, context->rawFileInfo.offset, context->rawFileInfo.length);
        int32_t fileSize = context->rawFileInfo.offset + context->rawFileInfo.length;
        imageSource = ImageSource::CreateImageSource(context->rawFileInfo.fd,
            context->rawFileInfo.offset, fileSize, opts, errorCode);
    } else { // Input Buffer
        uint32_t refCount = NUM_1;
        napi_ref arrayRef = nullptr;
        napi_create_reference(env, argValue, refCount, &arrayRef);
        status = napi_get_arraybuffer_info(env, argValue, &(context->sourceBuffer), &(context->sourceBufferSize));
        if (status != napi_ok) {
            napi_delete_reference(env, arrayRef);
            IMAGE_LOGE("fail to get arraybufferinfo");
            return nullptr;
        }
        imageSource = ImageSource::CreateImageSource(static_cast<uint8_t *>(context->sourceBuffer),
            context->sourceBufferSize, opts, errorCode);
        napi_delete_reference(env, arrayRef);
    }
    return imageSource;
}

napi_value SendableImageSourceNapi::CreatePixelMap(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, thisVar), nullptr, IMAGE_LOGE("fail to get thisVar"));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<ImageSourceAsyncContext> asyncContext = std::make_unique<ImageSourceAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->constructor_));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->constructor_),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->constructor_->nativeImgSrc),
        nullptr, IMAGE_LOGE("fail to unwrap nativeImgSrc"));
    asyncContext->rImageSource = asyncContext->constructor_->nativeImgSrc;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rImageSource),
        nullptr, IMAGE_LOGE("empty native rImageSource"));

    if (argCount == NUM_0) {
        IMAGE_LOGD("CreatePixelMap with no arg");
    } else if (argCount == NUM_1 || argCount == NUM_2) {
        if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_object) {
            if (!ParseDecodeOptions(env, argValue[NUM_0], &(asyncContext->decodeOpts),
                                    &(asyncContext->index), asyncContext->errMsg)) {
                IMAGE_LOGE("DecodeOptions mismatch");
            }
        }
        if (ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
            napi_create_reference(env, argValue[argCount - 1], refCount, &asyncContext->callbackRef);
        }
    } else {
        IMAGE_LOGE("argCount mismatch");
        return result;
    }
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    ImageNapiUtils::HicheckerReport();
    IMG_CREATE_CREATE_ASYNC_WORK_WITH_QOS(env, status, "CreatePixelMap", CreatePixelMapExecute,
        CreatePixelMapComplete, asyncContext, asyncContext->work, napi_qos_user_initiated);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value SendableImageSourceNapi::CreateImageSource(napi_env env, napi_callback_info info)
{
    PrepareNapiEnv(env);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = 2;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    NAPI_ASSERT(env, argCount > 0, "No arg!");

    std::unique_ptr<ImageSourceAsyncContext> asyncContext = std::make_unique<ImageSourceAsyncContext>();
    SourceOptions opts;
    if (argCount > NUM_1) {
        parseSourceOptions(env, argValue[NUM_1], &opts);
    }
    std::unique_ptr<ImageSource> imageSource = CreateNativeImageSource(env, argValue[NUM_0],
        opts, asyncContext.get());
    if (imageSource == nullptr) {
        IMAGE_LOGE("CreateImageSourceExec error");
        napi_get_undefined(env, &result);
        return result;
    }
    filePath_ = asyncContext->pathName;
    fileDescriptor_ = asyncContext->fdIndex;
    fileBuffer_ = asyncContext->sourceBuffer;
    fileBufferSize_ = asyncContext->sourceBufferSize;

    napi_value constructor = nullptr;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        sImgSrc_ = std::move(imageSource);
        status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
    }
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("New instance could not be obtained");
        napi_get_undefined(env, &result);
    }
    return result;
}

struct ImageConstructorInfo {
    std::string className;
    napi_ref* classRef;
    napi_callback constructor;
    const napi_property_descriptor* property;
    size_t propertyCount;
    const napi_property_descriptor* staticProperty;
    size_t staticPropertyCount;
};

SendableImageSourceNapi::SendableImageSourceNapi():env_(nullptr)
{   }

SendableImageSourceNapi::~SendableImageSourceNapi()
{
    release();
}

static napi_value DoInit(napi_env env, napi_value exports, struct ImageConstructorInfo info)
{
    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, info.className.c_str(), NAPI_AUTO_LENGTH,
        info.constructor, nullptr, info.propertyCount, info.property, &constructor);
    if (status != napi_ok) {
        IMAGE_LOGE("define class fail");
        return nullptr;
    }

    status = napi_create_reference(env, constructor, NUM_1, info.classRef);
    if (status != napi_ok) {
        IMAGE_LOGE("create reference fail");
        return nullptr;
    }

    napi_value global = nullptr;
    status = napi_get_global(env, &global);
    if (status != napi_ok) {
        IMAGE_LOGE("Init:get global fail");
        return nullptr;
    }

    status = napi_set_named_property(env, global, info.className.c_str(), constructor);
    if (status != napi_ok) {
        IMAGE_LOGE("Init:set global named property fail");
        return nullptr;
    }

    status = napi_define_properties(env, exports, info.staticPropertyCount, info.staticProperty);
    if (status != napi_ok) {
        IMAGE_LOGE("define properties fail");
        return nullptr;
    }
    return exports;
}

napi_value SendableImageSourceNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("createPixelMap", CreatePixelMap),
        DECLARE_NAPI_FUNCTION("release", Release),
    };

    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createImageSource", CreateImageSource),
    };

    struct ImageConstructorInfo info = {
        .className = CLASS_NAME,
        .classRef = &sConstructor_,
        .constructor = Constructor,
        .property = properties,
        .propertyCount = sizeof(properties) / sizeof(properties[NUM_0]),
        .staticProperty = static_prop,
        .staticPropertyCount = sizeof(static_prop) / sizeof(static_prop[NUM_0]),
    };

    if (DoInit(env, exports, info)) {
        return nullptr;
    }
    return exports;
}

napi_value SendableImageSourceNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineValue = nullptr;
    napi_get_undefined(env, &undefineValue);

    napi_status status;
    napi_value thisVar = nullptr;
    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<SendableImageSourceNapi> pImgSrcNapi = std::make_unique<SendableImageSourceNapi>();
        if (pImgSrcNapi != nullptr) {
            pImgSrcNapi->env_ = env;
            pImgSrcNapi->nativeImgSrc = sImgSrc_;
            if (pImgSrcNapi->nativeImgSrc == nullptr) {
                IMAGE_LOGE("Failed to set nativeImageSource with null. Maybe a reentrancy error");
            }
            pImgSrcNapi->navIncPixelMap_ = sIncPixelMap_;
            sIncPixelMap_ = nullptr;
            sImgSrc_ = nullptr;
            status = napi_wrap(env, thisVar, reinterpret_cast<void *>(pImgSrcNapi.get()),
                               SendableImageSourceNapi::Destructor, nullptr, nullptr);
            if (status == napi_ok) {
                pImgSrcNapi.release();
                return thisVar;
            } else {
                IMAGE_LOGE("Failure wrapping js to native napi");
            }
        }
    }

    return undefineValue;
}

void SendableImageSourceNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    reinterpret_cast<SendableImageSourceNapi *>(nativeObject)->nativeImgSrc = nullptr;
    IMAGE_LOGD("ImageSourceNapi::Destructor");
}

static void ReleaseComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto context = static_cast<ImageSourceAsyncContext*>(data);
    delete context->constructor_;
    context->constructor_ = nullptr;
    ImageSourceCallbackRoutine(env, context, result);
}

napi_value SendableImageSourceNapi::Release(napi_env env, napi_callback_info info)
{
    IMAGE_LOGD("Release enter");
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

    std::unique_ptr<ImageSourceAsyncContext> asyncContext = std::make_unique<ImageSourceAsyncContext>();
    status = napi_remove_wrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->constructor_));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->constructor_), result,
        IMAGE_LOGE("fail to unwrap context"));

    IMAGE_LOGD("Release argCount is [%{public}zu]", argCount);
    if (argCount == 1 && ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_function) {
        napi_create_reference(env, argValue[NUM_0], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    }

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "Release",
        [](napi_env env, void *data) {}, ReleaseComplete, asyncContext, asyncContext->work);
    IMAGE_LOGD("Release exit");
    return result;
}

void SendableImageSourceNapi::release()
{
    if (!isRelease) {
        nativeImgSrc = nullptr;
        isRelease = true;
    }
}

}
}