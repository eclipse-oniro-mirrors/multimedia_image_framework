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

#include "image_source_napi.h"
#include <fcntl.h>
#include "image_log.h"
#include "image_napi_utils.h"
#include "media_errors.h"
#include "string_ex.h"
#include "image_trace.h"
#include "hitrace_meter.h"
#include "exif_metadata_formatter.h"
#include "image_dfx.h"
#include "color_space_object_convertor.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSourceNapi"

namespace {
    constexpr int INVALID_FD = -1;
    constexpr uint32_t NUM_0 = 0;
    constexpr uint32_t NUM_1 = 1;
    constexpr uint32_t NUM_2 = 2;
    constexpr uint32_t NUM_3 = 3;
    constexpr uint32_t NUM_4 = 4;
    constexpr uint32_t NUM_5 = 5;
}

namespace OHOS {
namespace Media {
thread_local napi_ref ImageSourceNapi::sConstructor_ = nullptr;
thread_local std::shared_ptr<ImageSource> ImageSourceNapi::sImgSrc_ = nullptr;
std::shared_ptr<IncrementalPixelMap> ImageSourceNapi::sIncPixelMap_ = nullptr;
static const std::string CLASS_NAME = "ImageSource";
static const std::string FILE_URL_PREFIX = "file://";
std::string ImageSourceNapi::filePath_ = "";
int ImageSourceNapi::fileDescriptor_ = -1;
void* ImageSourceNapi::fileBuffer_ = nullptr;
size_t ImageSourceNapi::fileBufferSize_ = 0;

napi_ref ImageSourceNapi::pixelMapFormatRef_ = nullptr;
napi_ref ImageSourceNapi::propertyKeyRef_ = nullptr;
napi_ref ImageSourceNapi::imageFormatRef_ = nullptr;
napi_ref ImageSourceNapi::alphaTypeRef_ = nullptr;
napi_ref ImageSourceNapi::scaleModeRef_ = nullptr;
napi_ref ImageSourceNapi::componentTypeRef_ = nullptr;
napi_ref ImageSourceNapi::decodingDynamicRangeRef_ = nullptr;

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
    ImageSourceNapi *constructor_;
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

struct ImageSourceSyncContext {
    ImageSourceNapi *constructor_;
    uint32_t status;
    uint32_t index = 0;
    DecodeOptions decodeOpts;
    std::shared_ptr<PixelMap> rPixelMap;
    std::string errMsg;
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
    {"COMPRESSION", 0, "Compression"},
    {"PHOTOMETRIC_INTERPRETATION", 0, "PhotometricInterpretation"},
    {"STRIP_OFFSETS", 0, "StripOffsets"},
    {"SAMPLES_PER_PIXEL", 0, "SamplesPerPixel"},
    {"ROWS_PER_STRIP", 0, "RowsPerStrip"},
    {"STRIP_BYTE_COUNTS", 0, "StripByteCounts"},
    {"X_RESOLUTION", 0, "XResolution"},
    {"Y_RESOLUTION", 0, "YResolution"},
    {"PLANAR_CONFIGURATION", 0, "PlanarConfiguration"},
    {"RESOLUTION_UNIT", 0, "ResolutionUnit"},
    {"TRANSFER_FUNCTION", 0, "TransferFunction"},
    {"SOFTWARE", 0, "Software"},
    {"ARTIST", 0, "Artist"},
    {"WHITE_POINT", 0, "WhitePoint"},
    {"PRIMARY_CHROMATICITIES", 0, "PrimaryChromaticities"},
    {"YCBCR_COEFFICIENTS", 0, "YCbCrCoefficients"},
    {"YCBCR_SUB_SAMPLING", 0, "YCbCrSubSampling"},
    {"YCBCR_POSITIONING", 0, "YCbCrPositioning"},
    {"REFERENCE_BLACK_WHITE", 0, "ReferenceBlackWhite"},
    {"COPYRIGHT", 0, "Copyright"},
    {"JPEG_INTERCHANGE_FORMAT", 0, "JPEGInterchangeFormat"},
    {"JPEG_INTERCHANGE_FORMAT_LENGTH", 0, "JPEGInterchangeFormatLength"},
    {"EXPOSURE_PROGRAM", 0, "ExposureProgram"},
    {"SPECTRAL_SENSITIVITY", 0, "SpectralSensitivity"},
    {"OECF", 0, "OECF"},
    {"EXIF_VERSION", 0, "ExifVersion"},
    {"DATE_TIME_DIGITIZED", 0, "DateTimeDigitized"},
    {"COMPONENTS_CONFIGURATION", 0, "ComponentsConfiguration"},
    {"SHUTTER_SPEED", 0, "ShutterSpeedValue"},
    {"BRIGHTNESS_VALUE", 0, "BrightnessValue"},
    {"MAX_APERTURE_VALUE", 0, "MaxApertureValue"},
    {"SUBJECT_DISTANCE", 0, "SubjectDistance"},
    {"SUBJECT_AREA", 0, "SubjectArea"},
    {"MAKER_NOTE", 0, "MakerNote"},
    {"SUBSEC_TIME", 0, "SubsecTime"},
    {"SUBSEC_TIME_ORIGINAL", 0, "SubsecTimeOriginal"},
    {"SUBSEC_TIME_DIGITIZED", 0, "SubsecTimeDigitized"},
    {"FLASHPIX_VERSION", 0, "FlashpixVersion"},
    {"COLOR_SPACE", 0, "ColorSpace"},
    {"RELATED_SOUND_FILE", 0, "RelatedSoundFile"},
    {"FLASH_ENERGY", 0, "FlashEnergy"},
    {"SPATIAL_FREQUENCY_RESPONSE", 0, "SpatialFrequencyResponse"},
    {"FOCAL_PLANE_X_RESOLUTION", 0, "FocalPlaneXResolution"},
    {"FOCAL_PLANE_Y_RESOLUTION", 0, "FocalPlaneYResolution"},
    {"FOCAL_PLANE_RESOLUTION_UNIT", 0, "FocalPlaneResolutionUnit"},
    {"SUBJECT_LOCATION", 0, "SubjectLocation"},
    {"EXPOSURE_INDEX", 0, "ExposureIndex"},
    {"SENSING_METHOD", 0, "SensingMethod"},
    {"FILE_SOURCE", 0, "FileSource"},
    {"CFA_PATTERN", 0, "CFAPattern"},
    {"CUSTOM_RENDERED", 0, "CustomRendered"},
    {"EXPOSURE_MODE", 0, "ExposureMode"},
    {"DIGITAL_ZOOM_RATIO", 0, "DigitalZoomRatio"},
    {"SCENE_CAPTURE_TYPE", 0, "SceneCaptureType"},
    {"GAIN_CONTROL", 0, "GainControl"},
    {"CONTRAST", 0, "Contrast"},
    {"SATURATION", 0, "Saturation"},
    {"SHARPNESS", 0, "Sharpness"},
    {"DEVICE_SETTING_DESCRIPTION", 0, "DeviceSettingDescription"},
    {"SUBJECT_DISTANCE_RANGE", 0, "SubjectDistanceRange"},
    {"IMAGE_UNIQUE_ID", 0, "ImageUniqueID"},
    {"GPS_VERSION_ID", 0, "GPSVersionID"},
    {"GPS_ALTITUDE_REF", 0, "GPSAltitudeRef"},
    {"GPS_ALTITUDE", 0, "GPSAltitude"},
    {"GPS_SATELLITES", 0, "GPSSatellites"},
    {"GPS_STATUS", 0, "GPSStatus"},
    {"GPS_MEASURE_MODE", 0, "GPSMeasureMode"},
    {"GPS_DOP", 0, "GPSDOP"},
    {"GPS_SPEED_REF", 0, "GPSSpeedRef"},
    {"GPS_SPEED", 0, "GPSSpeed"},
    {"GPS_TRACK_REF", 0, "GPSTrackRef"},
    {"GPS_TRACK", 0, "GPSTrack"},
    {"GPS_IMG_DIRECTION_REF", 0, "GPSImgDirectionRef"},
    {"GPS_IMG_DIRECTION", 0, "GPSImgDirection"},
    {"GPS_MAP_DATUM", 0, "GPSMapDatum"},
    {"GPS_DEST_LATITUDE_REF", 0, "GPSDestLatitudeRef"},
    {"GPS_DEST_LATITUDE", 0, "GPSDestLatitude"},
    {"GPS_DEST_LONGITUDE_REF", 0, "GPSDestLongitudeRef"},
    {"GPS_DEST_LONGITUDE", 0, "GPSDestLongitude"},
    {"GPS_DEST_BEARING_REF", 0, "GPSDestBearingRef"},
    {"GPS_DEST_BEARING", 0, "GPSDestBearing"},
    {"GPS_DEST_DISTANCE_REF", 0, "GPSDestDistanceRef"},
    {"GPS_DEST_DISTANCE", 0, "GPSDestDistance"},
    {"GPS_PROCESSING_METHOD", 0, "GPSProcessingMethod"},
    {"GPS_AREA_INFORMATION", 0, "GPSAreaInformation"},
    {"GPS_DIFFERENTIAL", 0, "GPSDifferential"},
    {"BODY_SERIAL_NUMBER", 0, "BodySerialNumber"},
    {"CAMERA_OWNER_NAME", 0, "CameraOwnerName"},
    {"COMPOSITE_IMAGE", 0, "CompositeImage"},
    {"COMPRESSED_BITS_PER_PIXEL", 0, "CompressedBitsPerPixel"},
    {"DNG_VERSION", 0, "DNGVersion"},
    {"DEFAULT_CROP_SIZE", 0, "DefaultCropSize"},
    {"GAMMA", 0, "Gamma"},
    {"ISO_SPEED_LATITUDE_YYY", 0, "ISOSpeedLatitudeyyy"},
    {"ISO_SPEED_LATITUDE_ZZZ", 0, "ISOSpeedLatitudezzz"},
    {"LENS_MAKE", 0, "LensMake"},
    {"LENS_MODEL", 0, "LensModel"},
    {"LENS_SERIAL_NUMBER", 0, "LensSerialNumber"},
    {"LENS_SPECIFICATION", 0, "LensSpecification"},
    {"NEW_SUBFILE_TYPE", 0, "NewSubfileType"},
    {"OFFSET_TIME", 0, "OffsetTime"},
    {"OFFSET_TIME_DIGITIZED", 0, "OffsetTimeDigitized"},
    {"OFFSET_TIME_ORIGINAL", 0, "OffsetTimeOriginal"},
    {"SOURCE_EXPOSURE_TIMES_OF_COMPOSITE_IMAGE", 0, "SourceExposureTimesOfCompositeImage"},
    {"SOURCE_IMAGE_NUMBER_OF_COMPOSITE_IMAGE", 0, "SourceImageNumberOfCompositeImage"},
    {"SUBFILE_TYPE", 0, "SubfileType"},
    {"GPS_H_POSITIONING_ERROR", 0, "GPSHPositioningError"},
    {"PHOTOGRAPHIC_SENSITIVITY", 0, "PhotographicSensitivity"},
    {"BURST_NUMBER", 0, "HwMnoteBurstNumber"},
    {"FACE_CONF", 0, "HwMnoteFaceConf"},
    {"FACE_LEYE_CENTER", 0, "HwMnoteFaceLeyeCenter"},
    {"FACE_MOUTH_CENTER", 0, "HwMnoteFaceMouthCenter"},
    {"FACE_POINTER", 0, "HwMnoteFacePointer"},
    {"FACE_RECT", 0, "HwMnoteFaceRect"},
    {"FACE_REYE_CENTER", 0, "HwMnoteFaceReyeCenter"},
    {"FACE_SMILE_SCORE", 0, "HwMnoteFaceSmileScore"},
    {"FACE_VERSION", 0, "HwMnoteFaceVersion"},
    {"FRONT_CAMERA", 0, "HwMnoteFrontCamera"},
    {"SCENE_POINTER", 0, "HwMnoteScenePointer"},
    {"SCENE_VERSION", 0, "HwMnoteSceneVersion"},
    {"GIF_LOOP_COUNT", 0, "GIFLoopCount"},
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

static void ImageSourceCallbackWithErrorObj(napi_env env,
    ImageSourceAsyncContext* &context, const napi_value &val)
{
    napi_value result[NUM_2] = {0};

    if (context == nullptr) {
        IMAGE_LOGE("context is nullptr");
        return;
    }

    if (context->status == SUCCESS) {
        napi_get_undefined(env, &result[NUM_0]);
        result[NUM_1] = val;
    } else {
        std::string errMsg = (context->errMsg.size() > 0) ? context->errMsg : "error status, no message";
        IMAGE_LOGD("Operation failed code:%{public}d, msg:%{public}s",
            context->status, errMsg.c_str());
        ImageNapiUtils::CreateErrorObj(env, result[NUM_0], context->status, errMsg);
        napi_get_undefined(env, &result[NUM_1]);
    }

    if (context->deferred) {
        if (context->status == SUCCESS) {
            napi_resolve_deferred(env, context->deferred, result[NUM_1]);
        } else {
            napi_reject_deferred(env, context->deferred, result[NUM_0]);
        }
    } else {
        napi_value retVal;
        napi_value callback = nullptr;
        IMAGE_LOGD("call callback function");
        napi_get_reference_value(env, context->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, NUM_2, result, &retVal);
        napi_delete_reference(env, context->callbackRef);
    }

    napi_delete_async_work(env, context->work);

    delete context;
    context = nullptr;
}

static napi_value CreateEnumTypeObject(napi_env env,
    napi_valuetype type, napi_ref* ref, std::vector<struct ImageEnum> imageEnumMap)
{
    napi_value result = nullptr;
    napi_status status;
    int32_t refCount = 1;
    std::string propName;
    status = napi_create_object(env, &result);
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

std::vector<std::string> GetStringArrayArgument(napi_env env, napi_value object)
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

std::vector<std::pair<std::string, std::string>> GetRecordArgument(napi_env env, napi_value object)
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

napi_status SetValueString(napi_env env, std::string keyStr, std::string valueStr, napi_value &object)
{
    napi_value value = nullptr;
    napi_status status;
    if (valueStr != "") {
        status = napi_create_string_utf8(env, valueStr.c_str(), valueStr.length(), &value);
        if (status != napi_ok) {
            IMAGE_LOGE("Set Value failed %{public}d", status);
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

napi_value SetRecordParametersInfo(napi_env env, std::vector<std::pair<std::string, std::string>> recordParameters)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status = napi_create_array_with_length(env, recordParameters.size(), &result);
    if (status != napi_ok) {
        IMAGE_LOGE("Malloc array buffer failed %{public}d", status);
        return result;
    }

    for (size_t index = 0; index < recordParameters.size(); ++index) {
        napi_value object = nullptr;
        status = napi_create_object(env, &object);
        if (status != napi_ok) {
            IMAGE_LOGE("Create object failed %{public}d", status);
            continue;
        }
        status = SetValueString(env, recordParameters[index].first, recordParameters[index].second, object);
        if (status != napi_ok) {
            IMAGE_LOGE("Set current record parameter failed %{public}d", status);
            continue;
        }
        status = napi_set_element(env, result, index, object);
        if (status != napi_ok) {
            IMAGE_LOGE("Add current record parameter failed %{public}d", status);
            continue;
        }
    }

    IMAGE_LOGD("Set record parameters info success.");
    return result;
}

napi_value CreateModifyErrorArray(napi_env env, std::multimap<std::int32_t, std::string> errMsgArray)
{
    napi_value result = nullptr;
    napi_status status = napi_create_array_with_length(env, errMsgArray.size(), &result);
    if (status != napi_ok) {
        IMAGE_LOGE("Malloc array buffer failed %{public}d", status);
        return result;
    }

    uint32_t index = 0;
    for (auto it = errMsgArray.begin(); it != errMsgArray.end(); ++it) {
        napi_value errMsgVal;
        napi_get_undefined(env, &errMsgVal);
        if (it->first == ERR_MEDIA_WRITE_PARCEL_FAIL) {
            ImageNapiUtils::CreateErrorObj(env, errMsgVal, it->first,
                "Create Fd without write permission! exif key: " + it->second);
        } else if (it->first == ERR_MEDIA_OUT_OF_RANGE) {
            ImageNapiUtils::CreateErrorObj(env, errMsgVal, it->first,
                "The given buffer size is too small to add new exif data! exif key: " + it->second);
        } else if (it->first == ERR_IMAGE_DECODE_EXIF_UNSUPPORT) {
            ImageNapiUtils::CreateErrorObj(env, errMsgVal, it->first,
                "The exif data format is not standard! exif key: " + it->second);
        } else if (it->first == ERR_MEDIA_VALUE_INVALID) {
            ImageNapiUtils::CreateErrorObj(env, errMsgVal, it->first, it->second);
        } else {
            ImageNapiUtils::CreateErrorObj(env, errMsgVal, ERROR,
                "There is generic napi failure! exif key: " + it->second);
        }
        status = napi_set_element(env, result, index, errMsgVal);
        if (status != napi_ok) {
            IMAGE_LOGE("Add error message to array failed %{public}d", status);
            continue;
        }
        ++index;
    }

    IMAGE_LOGD("Create modify error array success.");
    return result;
}

napi_value CreateObtainErrorArray(napi_env env, std::multimap<std::int32_t, std::string> errMsgArray)
{
    napi_value result = nullptr;
    napi_status status = napi_create_array_with_length(env, errMsgArray.size(), &result);
    if (status != napi_ok) {
        IMAGE_LOGE("Malloc array buffer failed %{public}d", status);
        return result;
    }

    uint32_t index = 0;
    for (auto it = errMsgArray.begin(); it != errMsgArray.end(); ++it) {
        napi_value errMsgVal;
        napi_get_undefined(env, &errMsgVal);
        if (it->first == ERR_IMAGE_DECODE_ABNORMAL) {
            ImageNapiUtils::CreateErrorObj(env, errMsgVal, it->first,
                "The image source data is incorrect! exif key: " + it->second);
        } else if (it->first == ERR_IMAGE_UNKNOWN_FORMAT) {
            ImageNapiUtils::CreateErrorObj(env, errMsgVal, it->first,
                "Unknown image format! exif key: " + it->second);
        } else if (it->first == ERR_IMAGE_DECODE_FAILED) {
            ImageNapiUtils::CreateErrorObj(env, errMsgVal, it->first,
                "Failed to decode the image! exif key: " + it->second);
        } else {
            ImageNapiUtils::CreateErrorObj(env, errMsgVal, ERROR,
                "There is generic napi failure! exif key: " + it->second);
        }
        status = napi_set_element(env, result, index, errMsgVal);
        if (status != napi_ok) {
            IMAGE_LOGE("Add error message to array failed %{public}d", status);
            continue;
        }
        ++index;
    }

    IMAGE_LOGD("Create obtain error array success.");
    return result;
}

ImageSourceNapi::ImageSourceNapi():env_(nullptr)
{   }

ImageSourceNapi::~ImageSourceNapi()
{
    release();
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

    status = napi_set_named_property(env, exports, info.className.c_str(), constructor);
    if (status != napi_ok) {
        IMAGE_LOGE("set named property fail");
        return nullptr;
    }

    status = napi_define_properties(env, exports, info.staticPropertyCount, info.staticProperty);
    if (status != napi_ok) {
        IMAGE_LOGE("define properties fail");
        return nullptr;
    }
    return exports;
}

napi_value ImageSourceNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getImageInfo", GetImageInfo),
        DECLARE_NAPI_FUNCTION("getImageInfoSync", GetImageInfoSync),
        DECLARE_NAPI_FUNCTION("modifyImageProperty", ModifyImageProperty),
        DECLARE_NAPI_FUNCTION("modifyImageProperties", ModifyImageProperty),
        DECLARE_NAPI_FUNCTION("getImageProperty", GetImageProperty),
        DECLARE_NAPI_FUNCTION("getImageProperties", GetImageProperty),
        DECLARE_NAPI_FUNCTION("getDelayTimeList", GetDelayTime),
        DECLARE_NAPI_FUNCTION("getDisposalTypeList", GetDisposalType),
        DECLARE_NAPI_FUNCTION("getFrameCount", GetFrameCount),
        DECLARE_NAPI_FUNCTION("createPixelMapList", CreatePixelMapList),
        DECLARE_NAPI_FUNCTION("createPixelMap", CreatePixelMap),
        DECLARE_NAPI_FUNCTION("createPixelMapSync", CreatePixelMapSync),
        DECLARE_NAPI_FUNCTION("updateData", UpdateData),
        DECLARE_NAPI_FUNCTION("release", Release),
        DECLARE_NAPI_GETTER("supportedFormats", GetSupportedFormats),
    };

    napi_property_descriptor static_prop[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createImageSource", CreateImageSource),
        DECLARE_NAPI_STATIC_FUNCTION("CreateIncrementalSource", CreateIncrementalSource),
        DECLARE_NAPI_PROPERTY("PixelMapFormat",
            CreateEnumTypeObject(env, napi_number, &pixelMapFormatRef_, sPixelMapFormatMap)),
        DECLARE_NAPI_PROPERTY("PropertyKey", CreateEnumTypeObject(env, napi_string, &propertyKeyRef_, sPropertyKeyMap)),
        DECLARE_NAPI_PROPERTY("ImageFormat", CreateEnumTypeObject(env, napi_number, &imageFormatRef_, sImageFormatMap)),
        DECLARE_NAPI_PROPERTY("AlphaType", CreateEnumTypeObject(env, napi_number, &alphaTypeRef_, sAlphaTypeMap)),
        DECLARE_NAPI_PROPERTY("ScaleMode", CreateEnumTypeObject(env, napi_number, &scaleModeRef_, sScaleModeMap)),
        DECLARE_NAPI_PROPERTY("ComponentType",
            CreateEnumTypeObject(env, napi_number, &componentTypeRef_, sComponentTypeMap)),
        DECLARE_NAPI_PROPERTY("DecodingDynamicRange",
            CreateEnumTypeObject(env, napi_number, &decodingDynamicRangeRef_, sDecodingDynamicRangeMap)),
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

napi_value ImageSourceNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value undefineValue = nullptr;
    napi_get_undefined(env, &undefineValue);

    napi_status status;
    napi_value thisVar = nullptr;
    status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<ImageSourceNapi> pImgSrcNapi = std::make_unique<ImageSourceNapi>();
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
                               ImageSourceNapi::Destructor, nullptr, nullptr);
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

void ImageSourceNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    reinterpret_cast<ImageSourceNapi *>(nativeObject)->nativeImgSrc = nullptr;
    IMAGE_LOGD("ImageSourceNapi::Destructor");
}

napi_value ImageSourceNapi::GetSupportedFormats(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    size_t argCount = 0;
    IMAGE_LOGD("GetSupportedFormats IN");

    IMG_JS_ARGS(env, info, status, argCount, nullptr, thisVar);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), result, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<ImageSourceAsyncContext> asyncContext = std::make_unique<ImageSourceAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->constructor_));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->constructor_),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
    std::set<std::string> formats;
    uint32_t ret = asyncContext->constructor_->nativeImgSrc->GetSupportedFormats(formats);

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

STATIC_NAPI_VALUE_FUNC(GetImageInfo)
{
    napi_value result = nullptr;
    auto imageInfo = static_cast<ImageInfo*>(data);
    auto rImageSource = static_cast<ImageSource*>(ptr);
    napi_create_object(env, &result);

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
    napi_value encodedFormatValue = nullptr;
    napi_create_string_utf8(env, imageInfo->encodedFormat.c_str(), NAPI_AUTO_LENGTH,
        &encodedFormatValue);
    napi_set_named_property(env, result, "mimeType", encodedFormatValue);

    if (rImageSource != nullptr) {
        napi_value isHdrValue = nullptr;
        napi_get_boolean(env, rImageSource->IsHdrImage(), &isHdrValue);
        napi_set_named_property(env, result, "isHdr", isHdrValue);
    }
    return result;
}

STATIC_COMPLETE_FUNC(GetImageInfo)
{
    napi_value result = nullptr;
    auto context = static_cast<ImageSourceAsyncContext*>(data);
    if (context->status == SUCCESS) {
        result = GetImageInfoNapiValue(env, &(context->imageInfo), context->rImageSource.get());
        if (!IMG_IS_OK(status)) {
            context->status = ERROR;
            IMAGE_LOGE("napi_create_int32 failed!");
            napi_get_undefined(env, &result);
        } else {
            context->status = SUCCESS;
        }
    } else {
        napi_get_undefined(env, &result);
    }

    ImageSourceCallbackRoutine(env, context, result);
}

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

static std::string FileUrlToRawPath(const std::string &path)
{
    if (path.size() > FILE_URL_PREFIX.size() &&
        (path.compare(0, FILE_URL_PREFIX.size(), FILE_URL_PREFIX) == 0)) {
        return path.substr(FILE_URL_PREFIX.size());
    }
    return path;
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
    napi_create_string_utf8(env, "multimedia.image", NAPI_AUTO_LENGTH, &imageInfo);
    napi_value funcArgv[1] = { imageInfo };
    napi_value returnValue;
    napi_call_function(env, globalValue, func, 1, funcArgv, &returnValue);
}

static bool hasNamedProperty(napi_env env, napi_value object, std::string name)
{
    bool res = false;
    return (napi_has_named_property(env, object, name.c_str(), &res) == napi_ok) && res;
}

static bool parseRawFileItem(napi_env env, napi_value argValue, std::string item, int32_t* value)
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

napi_value ImageSourceNapi::CreateImageSource(napi_env env, napi_callback_info info)
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

napi_value ImageSourceNapi::CreateImageSourceComplete(napi_env env, napi_status status, void *data)
{
    napi_value constructor = nullptr;
    napi_value result = nullptr;

    IMAGE_LOGD("CreateImageSourceComplete IN");
    auto context = static_cast<ImageSourceAsyncContext*>(data);
    if (context == nullptr) {
        return result;
    }
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        sImgSrc_ = context->rImageSource;
        status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
    }

    if (!IMG_IS_OK(status)) {
        context->status = ERROR;
        IMAGE_LOGE("New instance could not be obtained");
        napi_get_undefined(env, &result);
    }
    return result;
}

napi_value ImageSourceNapi::CreateIncrementalSource(napi_env env, napi_callback_info info)
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

    napi_status status;
    IMAGE_LOGD("CreateIncrementalSource IN");

    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = NUM_2;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    if (argCount == NUM_2) {
        parseSourceOptions(env, argValue[NUM_1], &(incOpts.sourceOptions));
    }

    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    DecodeOptions decodeOpts;
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(0, decodeOpts, errorCode);
    IMAGE_LOGD("CreateIncrementalImageSource end");
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("CreateIncrementalImageSource error");
        napi_get_undefined(env, &result);
        return result;
    }
    napi_value constructor = nullptr;
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (IMG_IS_OK(status)) {
        sImgSrc_ = std::move(imageSource);
        sIncPixelMap_ = std::move(incPixelMap);
        status = napi_new_instance(env, constructor, NUM_0, nullptr, &result);
    }
    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("New instance could not be obtained");
        napi_get_undefined(env, &result);
    }
    return result;
}

napi_value ImageSourceNapi::GetImageInfo(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("ImageSourceNapi::GetImageInfo");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_2] = {0};
    size_t argCount = 2;
    IMAGE_LOGD("GetImageInfo IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMAGE_LOGD("GetImageInfo argCount is [%{public}zu]", argCount);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<ImageSourceAsyncContext> asyncContext = std::make_unique<ImageSourceAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->constructor_));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->constructor_),
        nullptr, IMAGE_LOGE("fail to unwrap context"));

    asyncContext->rImageSource = asyncContext->constructor_->nativeImgSrc;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rImageSource),
        nullptr, IMAGE_LOGE("empty native pixelmap"));
    IMAGE_LOGD("GetImageInfo argCount is [%{public}zu]", argCount);
    if (argCount == NUM_1 && ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_function) {
        IMAGE_LOGD("GetImageInfo arg0 getType is [%{public}u]", ImageNapiUtils::getType(env, argValue[NUM_0]));
        napi_create_reference(env, argValue[NUM_0], refCount, &asyncContext->callbackRef);
    } else if (argCount == NUM_1 && ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_number) {
        napi_get_value_uint32(env, argValue[NUM_0], &asyncContext->index);
    } else if (argCount == NUM_2 && ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_number
                && ImageNapiUtils::getType(env, argValue[NUM_1]) == napi_function) {
        IMAGE_LOGD("GetImageInfo arg0 getType is [%{public}u]", ImageNapiUtils::getType(env, argValue[NUM_0]));
        IMAGE_LOGD("GetImageInfo arg1 getType is [%{public}u]", ImageNapiUtils::getType(env, argValue[NUM_1]));
        napi_get_value_uint32(env, argValue[NUM_0], &asyncContext->index);
        napi_create_reference(env, argValue[NUM_1], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetImageInfo",
        [](napi_env env, void *data) {
            auto context = static_cast<ImageSourceAsyncContext*>(data);
            int index = (context->index >= NUM_0) ? context->index : NUM_0;
            context->status = context->rImageSource->GetImageInfo(index, context->imageInfo);
        }, GetImageInfoComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value ImageSourceNapi::GetImageInfoSync(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    uint32_t index = 0;
    uint32_t ret = SUCCESS;

    IMAGE_LOGD("GetImageInfoSync IN");
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMAGE_LOGD("GetImageInfoSync argCount is [%{public}zu]", argCount);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<ImageSourceNapi> imageSourceNapi = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&imageSourceNapi));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, imageSourceNapi),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, imageSourceNapi->nativeImgSrc),
        nullptr, IMAGE_LOGE("empty native pixelmap"));

    if (argCount == NUM_1 && ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_number) {
        napi_get_value_uint32(env, argValue[NUM_0], &index);
    }

    if (imageSourceNapi->nativeImgSrc != nullptr) {
        ImageInfo imageinfo;
        ret = imageSourceNapi->nativeImgSrc->GetImageInfo(index, imageinfo);
        if (ret == SUCCESS) {
            result = GetImageInfoNapiValue(env, &imageinfo, imageSourceNapi->nativeImgSrc.get());
        }
    } else {
        IMAGE_LOGE("native imageSourceNapi is nullptr!");
    }
    imageSourceNapi.release();
    return result;
}

static std::shared_ptr<PixelMap> CreatePixelMapInner(ImageSourceNapi *thisPtr,
    std::shared_ptr<ImageSource> imageSource, uint32_t index, DecodeOptions decodeOpts, uint32_t &status)
{
    if (thisPtr == nullptr || imageSource == nullptr) {
        IMAGE_LOGE("Invailed args");
        status = ERROR;
    }

    std::shared_ptr<PixelMap> pixelMap;
    auto incPixelMap = thisPtr->GetIncrementalPixelMap();
    if (incPixelMap != nullptr) {
        IMAGE_LOGD("Get Incremental PixelMap!!!");
        pixelMap = incPixelMap;
    } else {
        decodeOpts.invokeType = JS_INTERFACE;
        pixelMap = imageSource->CreatePixelMapEx((index >= NUM_0) ? index : NUM_0,
            decodeOpts, status);
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
        result = PixelMapNapi::CreatePixelMap(env, context->rPixelMap);
    } else {
        napi_get_undefined(env, &result);
    }
    IMAGE_LOGD("CreatePixelMapComplete OUT");
    ImageSourceCallbackRoutine(env, context, result);
}

static napi_value CreatePixelMapCompleteSync(napi_env env, napi_status status, ImageSourceSyncContext *context)
{
    IMAGE_LOGD("CreatePixelMapCompleteSync IN");
    napi_value result = nullptr;

    if (context->status == SUCCESS) {
        result = PixelMapNapi::CreatePixelMap(env, context->rPixelMap);
    } else {
        napi_get_undefined(env, &result);
    }
    IMAGE_LOGD("CreatePixelMapCompleteSync OUT");
    return result;
}

napi_value ImageSourceNapi::CreatePixelMap(napi_env env, napi_callback_info info)
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

napi_value ImageSourceNapi::CreatePixelMapSync(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_1] = {0};
    size_t argCount = NUM_1;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, thisVar), nullptr, IMAGE_LOGE("fail to get thisVar"));
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<ImageSourceSyncContext> syncContext = std::make_unique<ImageSourceSyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&syncContext->constructor_));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, syncContext->constructor_),
        nullptr, IMAGE_LOGE("fail to unwrap context"));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, syncContext->constructor_->nativeImgSrc),
        nullptr, IMAGE_LOGE("fail to unwrap nativeImgSrc"));

    if (argCount == NUM_0) {
        IMAGE_LOGD("CreatePixelMap with no arg");
    } else if (argCount == NUM_1) {
        if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_object) {
            if (!ParseDecodeOptions(env, argValue[NUM_0], &(syncContext->decodeOpts),
                                    &(syncContext->index), syncContext->errMsg)) {
                IMAGE_LOGE("DecodeOptions mismatch");
                syncContext->errMsg = "DecodeOptions mismatch";
                return result;
            }
        }
    }

    syncContext->rPixelMap = CreatePixelMapInner(syncContext->constructor_, syncContext->constructor_->nativeImgSrc,
        syncContext->index, syncContext->decodeOpts, syncContext->status);

    if (syncContext->status != SUCCESS) {
        syncContext->errMsg = "Create PixelMap error";
        IMAGE_LOGE("Create PixelMap error");
    }
    result = CreatePixelMapCompleteSync(env, status, static_cast<ImageSourceSyncContext*>((syncContext).get()));

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create PixelMap"));
    return result;
}

static bool ParsePropertyOptions(napi_env env, napi_value root, ImageSourceAsyncContext* context)
{
    napi_value tmpValue = nullptr;
    if (!GET_UINT32_BY_NAME(root, "index", context->index)) {
        IMAGE_LOGD("no index");
        return false;
    }
    if (!GET_NODE_BY_NAME(root, "defaultValue", tmpValue)) {
        IMAGE_LOGD("no defaultValue");
    } else {
        if (tmpValue != nullptr) {
            context->defaultValueStr = GetStringArgument(env, tmpValue);
        }
    }
    return true;
}

static void ModifyImagePropertyComplete(napi_env env, napi_status status, ImageSourceAsyncContext *context)
{
    if (context == nullptr) {
        IMAGE_LOGE("context is nullptr");
        return;
    }

    napi_value result[NUM_2] = {0};
    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);
    napi_value retVal;
    napi_value callback = nullptr;
    if (context->isBatch) {
        result[NUM_0] = CreateModifyErrorArray(env, context->errMsgArray);
    } else {
        if (context->status == ERR_MEDIA_WRITE_PARCEL_FAIL) {
            if (context->fdIndex != -1) {
                ImageNapiUtils::CreateErrorObj(env, result[NUM_0], context->status,
                    "Create Fd without write permission!");
            } else {
                ImageNapiUtils::CreateErrorObj(env, result[0], context->status,
                    "The EXIF data failed to be written to the file.");
            }
        } else if (context->status == ERR_MEDIA_OUT_OF_RANGE) {
            ImageNapiUtils::CreateErrorObj(env, result[NUM_0], context->status,
                "The given buffer size is too small to add new exif data!");
        } else if (context->status == ERR_IMAGE_DECODE_EXIF_UNSUPPORT) {
            ImageNapiUtils::CreateErrorObj(env, result[NUM_0], context->status,
                "The exif data format is not standard, so modify it failed!");
        } else if (context->status == ERR_MEDIA_VALUE_INVALID) {
            ImageNapiUtils::CreateErrorObj(env, result[NUM_0], context->status, context->errMsg);
        }
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

static void GetImagePropertyComplete(napi_env env, napi_status status, ImageSourceAsyncContext *context)
{
    if (context == nullptr) {
        IMAGE_LOGE("context is nullptr");
        return;
    }

    napi_value result[NUM_2] = {0};
    napi_value retVal;
    napi_value callback = nullptr;

    napi_get_undefined(env, &result[NUM_0]);
    napi_get_undefined(env, &result[NUM_1]);

    if (context->status == SUCCESS) {
        if (context->isBatch) {
            result[NUM_1] = SetRecordParametersInfo(env, context->kVStrArray);
        } else {
            napi_create_string_utf8(env, context->valueStr.c_str(), context->valueStr.length(), &result[NUM_1]);
        }
    } else {
        if (context->isBatch) {
            result[NUM_0] = CreateObtainErrorArray(env, context->errMsgArray);
        } else {
            std::string errMsg = context->status == ERR_IMAGE_DECODE_EXIF_UNSUPPORT ? "Unsupport EXIF info key!" :
                "There is generic napi failure!";
            ImageNapiUtils::CreateErrorObj(env, result[NUM_0], context->status, errMsg);

            if (!context->defaultValueStr.empty()) {
                napi_create_string_utf8(env, context->defaultValueStr.c_str(),
                    context->defaultValueStr.length(), &result[NUM_1]);
                context->status = SUCCESS;
            }
        }
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

static std::unique_ptr<ImageSourceAsyncContext> UnwrapContext(napi_env env, napi_callback_info info)
{
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_3] = {0};
    size_t argCount = NUM_3;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMAGE_LOGD("GetImageProperty argCount is [%{public}zu]", argCount);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<ImageSourceAsyncContext> context = std::make_unique<ImageSourceAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&context->constructor_));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->constructor_),
        nullptr, IMAGE_LOGE("fail to unwrap context"));

    context->rImageSource = context->constructor_->nativeImgSrc;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->rImageSource),
        nullptr, IMAGE_LOGE("empty native rImageSource"));

    if (argCount < NUM_1 || argCount > NUM_3) {
        IMAGE_LOGE("argCount mismatch");
        return nullptr;
    }
    if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_string) {
        context->keyStr = GetStringArgument(env, argValue[NUM_0]);
    } else if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_object) {
        context->keyStrArray = GetStringArrayArgument(env, argValue[NUM_0]);
        if (context->keyStrArray.size() == 0) return nullptr;
        context->isBatch = true;
    } else {
        IMAGE_LOGE("arg 0 type mismatch");
        return nullptr;
    }
    if (argCount == NUM_2 || argCount == NUM_3) {
        if (ImageNapiUtils::getType(env, argValue[NUM_1]) == napi_object) {
            IMG_NAPI_CHECK_RET_D(ParsePropertyOptions(env, argValue[NUM_1], context.get()),
                                 nullptr, IMAGE_LOGE("PropertyOptions mismatch"));
        }
        if (ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
            napi_create_reference(env, argValue[argCount - 1], refCount, &context->callbackRef);
        }
    }
    return context;
}

static uint32_t CheckExifDataValue(const std::string &key, const std::string &value, std::string &errorInfo)
{
    auto status = static_cast<uint32_t>(ExifMetadatFormatter::Validate(key, value));
    if (status != SUCCESS) {
        errorInfo = key + "has invalid exif value: ";
        errorInfo.append(value);
    }
    return status;
}

static void ModifyImagePropertiesExecute(napi_env env, void *data)
{
    auto context = static_cast<ImageSourceAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("empty context");
        return;
    }
    uint32_t status = SUCCESS;
    for (auto recordIterator = context->kVStrArray.begin(); recordIterator != context->kVStrArray.end();
        ++recordIterator) {
        IMAGE_LOGD("CheckExifDataValue");
        status = CheckExifDataValue(recordIterator->first, recordIterator->second, context->errMsg);
        IMAGE_LOGD("Check ret status: %{public}d", status);
        if (status != SUCCESS) {
            IMAGE_LOGE("There is invalid exif data parameter");
            context->errMsgArray.insert(std::make_pair(status, context->errMsg));
            continue;
        }
        if (!IsSameTextStr(context->pathName, "")) {
            status = context->rImageSource->ModifyImageProperty(0, recordIterator->first,
                recordIterator->second, context->pathName);
        } else if (context->fdIndex != -1) {
            status = context->rImageSource->ModifyImageProperty(0, recordIterator->first,
                recordIterator->second, context->fdIndex);
        } else if (context->sourceBuffer != nullptr) {
            status = context->rImageSource->ModifyImageProperty(0, recordIterator->first,
                recordIterator->second, static_cast<uint8_t *>(context->sourceBuffer),
                context->sourceBufferSize);
        } else {
            context->errMsgArray.insert(std::make_pair(ERROR, recordIterator->first));
            IMAGE_LOGE("There is no image source!");
            continue;
        }
        if (status != SUCCESS) {
            context->errMsgArray.insert(std::make_pair(status, recordIterator->first));
        }
    }
    context->status = context->errMsgArray.size() > 0 ? ERROR : SUCCESS;
}

static void ModifyImagePropertyExecute(napi_env env, void *data)
{
    auto context = static_cast<ImageSourceAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("empty context");
        return;
    }
    IMAGE_LOGD("ModifyImagePropertyExecute CheckExifDataValue");
    uint32_t status = CheckExifDataValue(context->keyStr, context->valueStr, context->errMsg);
    IMAGE_LOGD("ModifyImagePropertyExecute Check ret status: %{public}d", status);
    if (status != SUCCESS) {
        IMAGE_LOGE("There is invalid exif data parameter");
        context->status = status;
        return;
    }
    if (!IsSameTextStr(context->pathName, "")) {
        context->status = context->rImageSource->ModifyImageProperty(context->index,
            context->keyStr, context->valueStr, context->pathName);
    } else if (context->fdIndex != -1) {
        context->status = context->rImageSource->ModifyImageProperty(context->index,
            context->keyStr, context->valueStr, context->fdIndex);
    } else if (context->sourceBuffer != nullptr) {
        context->status = context->rImageSource->ModifyImageProperty(context->index,
            context->keyStr, context->valueStr, static_cast<uint8_t *>(context->sourceBuffer),
            context->sourceBufferSize);
    } else {
        context->status = ERROR;
        IMAGE_LOGE("There is no image source!");
    }
}

static void GetImagePropertiesExecute(napi_env env, void *data)
{
    auto context = static_cast<ImageSourceAsyncContext*>(data);
    if (context == nullptr) {
        IMAGE_LOGE("empty context");
        return;
    }
    uint32_t status = SUCCESS;
    for (auto keyStrIt = context->keyStrArray.begin(); keyStrIt != context->keyStrArray.end(); ++keyStrIt) {
        std::string valueStr = "";
        status = context->rImageSource->GetImagePropertyString(0, *keyStrIt, valueStr);
        if (status == SUCCESS) {
            context->kVStrArray.emplace_back(std::make_pair(*keyStrIt, valueStr));
        } else {
            context->kVStrArray.emplace_back(std::make_pair(*keyStrIt, ""));
            context->errMsgArray.insert(std::make_pair(status, *keyStrIt));
            IMAGE_LOGE("errCode: %{public}u , exif key: %{public}s", status, keyStrIt->c_str());
        }
    }
     context->status = context->kVStrArray.size() == context->errMsgArray.size() ? ERROR : SUCCESS;
}

static std::unique_ptr<ImageSourceAsyncContext> UnwrapContextForModify(napi_env env, napi_callback_info info)
{
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_4] = {0};
    size_t argCount = NUM_4;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));
    std::unique_ptr<ImageSourceAsyncContext> context = std::make_unique<ImageSourceAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&context->constructor_));
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->constructor_), nullptr, IMAGE_LOGE("fail to unwrap context"));
    context->rImageSource = context->constructor_->nativeImgSrc;
    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->rImageSource), nullptr, IMAGE_LOGE("empty native rImageSource"));
    if (argCount < NUM_1 || argCount > NUM_4) {
        IMAGE_LOGE("argCount mismatch");
        return nullptr;
    }
    if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_string) {
        context->keyStr = GetStringArgument(env, argValue[NUM_0]);
    } else if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_object) {
        context->kVStrArray = GetRecordArgument(env, argValue[NUM_0]);
        if (context->kVStrArray.size() == 0) return nullptr;
        context->isBatch = true;
    } else {
        IMAGE_LOGE("arg 0 type mismatch");
        return nullptr;
    }
    if (argCount == NUM_2 || argCount == NUM_3 || argCount == NUM_4) {
        if (ImageNapiUtils::getType(env, argValue[NUM_1]) == napi_string) {
            context->valueStr = GetStringArgument(env, argValue[NUM_1]);
        } else {
            IMAGE_LOGE("arg 1 type mismatch");
            return nullptr;
        }
    }
    if (argCount == NUM_3 || argCount == NUM_4) {
        if (ImageNapiUtils::getType(env, argValue[NUM_2]) == napi_object) {
            IMG_NAPI_CHECK_RET_D(ParsePropertyOptions(env, argValue[NUM_2], context.get()),
                nullptr, IMAGE_LOGE("PropertyOptions mismatch"));
        }
        if (ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
            napi_create_reference(env, argValue[argCount - 1], refCount, &context->callbackRef);
        }
    }
    context->pathName = ImageSourceNapi::filePath_;
    context->fdIndex = ImageSourceNapi::fileDescriptor_;
    context->sourceBuffer = ImageSourceNapi::fileBuffer_;
    context->sourceBufferSize = ImageSourceNapi::fileBufferSize_;
    return context;
}

napi_value ImageSourceNapi::ModifyImageProperty(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    std::unique_ptr<ImageSourceAsyncContext> asyncContext = UnwrapContextForModify(env, info);
    if (asyncContext == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "async context unwrap failed");
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }
    if (asyncContext->isBatch) {
        IMG_CREATE_CREATE_ASYNC_WORK(env, status, "ModifyImageProperties",
            ModifyImagePropertiesExecute,
            reinterpret_cast<napi_async_complete_callback>(ModifyImagePropertyComplete),
            asyncContext,
            asyncContext->work);
    } else {
        IMG_CREATE_CREATE_ASYNC_WORK(env, status, "ModifyImageProperty",
            ModifyImagePropertyExecute,
            reinterpret_cast<napi_async_complete_callback>(ModifyImagePropertyComplete),
            asyncContext,
            asyncContext->work);
    }

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

napi_value ImageSourceNapi::GetImageProperty(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("ImageSourceNapi::GetImageProperty");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_status status;
    std::unique_ptr<ImageSourceAsyncContext> asyncContext = UnwrapContext(env, info);
    if (asyncContext == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, COMMON_ERR_INVALID_PARAMETER, "async context unwrap failed");
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    if (asyncContext->isBatch) {
        IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetImageProperties",
            GetImagePropertiesExecute,
            reinterpret_cast<napi_async_complete_callback>(GetImagePropertyComplete),
            asyncContext,
            asyncContext->work);
    } else {
        IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetImageProperty",
            [](napi_env env, void *data) {
                auto context = static_cast<ImageSourceAsyncContext*>(data);
                context->status = context->rImageSource->GetImagePropertyString(context->index,
                                                                                context->keyStr,
                                                                                context->valueStr);
            },
            reinterpret_cast<napi_async_complete_callback>(GetImagePropertyComplete),
            asyncContext,
            asyncContext->work);
    }

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
}

static void UpdateDataExecute(napi_env env, void *data)
{
    auto context = static_cast<ImageSourceAsyncContext*>(data);
    uint8_t *buffer = static_cast<uint8_t*>(context->updataBuffer);
    if (context->updataBufferOffset < context->updataBufferSize) {
        buffer = buffer + context->updataBufferOffset;
    }

    uint32_t lastSize = context->updataBufferSize - context->updataBufferOffset;
    uint32_t size = context->updataLength < lastSize ? context->updataLength : lastSize;

    uint32_t res = context->rImageSource->UpdateData(buffer, size,
                                                     context->isCompleted);
    context->isSuccess = res == 0;
    if (context->isSuccess && context->constructor_ != nullptr) {
        auto incPixelMap = context->constructor_->GetIncrementalPixelMap();
        if (incPixelMap != nullptr) {
            uint8_t decodeProgress = 0;
            uint32_t err = incPixelMap->PromoteDecoding(decodeProgress);
            if (!(err == SUCCESS || (err == ERR_IMAGE_SOURCE_DATA_INCOMPLETE && !context->isCompleted))) {
                IMAGE_LOGE("UpdateData PromoteDecoding error");
                context->isSuccess = false;
            }
            if (context->isCompleted) {
                incPixelMap->DetachFromDecoding();
            }
        }
    }
}

static void UpdateDataComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    auto context = static_cast<ImageSourceAsyncContext*>(data);

    napi_get_boolean(env, context->isSuccess, &result);
    ImageSourceCallbackRoutine(env, context, result);
}

static bool isNapiTypedArray(napi_env env, napi_value val)
{
    bool res = false;
    napi_is_typedarray(env, val, &res);
    IMAGE_LOGD("isNapiTypedArray %{public}d", res);
    return res;
}

napi_value ImageSourceNapi::UpdateData(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_5] = {0};
    size_t argCount = 5;
    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMAGE_LOGD("UpdateData argCount is [%{public}zu]", argCount);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<ImageSourceAsyncContext> asyncContext = std::make_unique<ImageSourceAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->constructor_));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->constructor_),
        nullptr, IMAGE_LOGE("fail to unwrap context"));

    asyncContext->rImageSource = asyncContext->constructor_->nativeImgSrc;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, asyncContext->rImageSource),
        nullptr, IMAGE_LOGE("empty native rImageSource"));
    IMAGE_LOGD("UpdateData argCount %{public}zu", argCount);
    if (argCount > NUM_0 && isNapiTypedArray(env, argValue[NUM_0])) {
        IMAGE_LOGI("UpdateData napi_get_arraybuffer_info ");
        napi_typedarray_type type;
        napi_value arraybuffer;
        size_t offset;
        status = napi_get_typedarray_info(env, argValue[NUM_0], &type,
            &(asyncContext->updataBufferSize), &(asyncContext->updataBuffer),
            &arraybuffer, &offset);
    }

    if (argCount >= NUM_2 && ImageNapiUtils::getType(env, argValue[NUM_1]) == napi_boolean) {
        status = napi_get_value_bool(env, argValue[NUM_1], &(asyncContext->isCompleted));
    }

    if (argCount >= NUM_3 && ImageNapiUtils::getType(env, argValue[NUM_2]) == napi_number) {
        asyncContext->updataBufferOffset = 0;
        status = napi_get_value_uint32(env, argValue[NUM_2], &(asyncContext->updataBufferOffset));
        IMAGE_LOGD("asyncContext->updataBufferOffset is [%{public}u]", asyncContext->updataBufferOffset);
    }

    if (argCount >= NUM_4 && ImageNapiUtils::getType(env, argValue[NUM_3]) == napi_number) {
        asyncContext->updataLength = 0;
        status = napi_get_value_uint32(env, argValue[NUM_3], &(asyncContext->updataLength));
        IMAGE_LOGD("asyncContext->updataLength is [%{public}u]", asyncContext->updataLength);
    }

    if (!IMG_IS_OK(status)) {
        IMAGE_LOGE("fail to UpdateData");
        napi_get_undefined(env, &result);
        return result;
    }

    if (argCount == NUM_5 && ImageNapiUtils::getType(env, argValue[NUM_4]) == napi_function) {
        napi_create_reference(env, argValue[NUM_4], refCount, &asyncContext->callbackRef);
    }

    if (argCount == NUM_3 && ImageNapiUtils::getType(env, argValue[NUM_2]) == napi_function) {
        napi_create_reference(env, argValue[NUM_2], refCount, &asyncContext->callbackRef);
    }

    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "UpdateData",
        UpdateDataExecute, UpdateDataComplete, asyncContext, asyncContext->work);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status),
        nullptr, IMAGE_LOGE("fail to create async work"));
    return result;
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

napi_value ImageSourceNapi::Release(napi_env env, napi_callback_info info)
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

void ImageSourceNapi::release()
{
    if (!isRelease) {
        if (nativeImgSrc != nullptr) {
            nativeImgSrc = nullptr;
        }
        isRelease = true;
    }
}

static std::unique_ptr<ImageSourceAsyncContext> UnwrapContextForList(napi_env env, napi_callback_info info)
{
    int32_t refCount = 1;
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value argValue[NUM_3] = {0};
    size_t argCount = NUM_3;

    IMG_JS_ARGS(env, info, status, argCount, argValue, thisVar);
    IMAGE_LOGD("UnwrapContextForList argCount is [%{public}zu]", argCount);

    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to napi_get_cb_info"));

    std::unique_ptr<ImageSourceAsyncContext> context = std::make_unique<ImageSourceAsyncContext>();
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&context->constructor_));

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->constructor_),
        nullptr, IMAGE_LOGE("fail to unwrap context"));

    context->rImageSource = context->constructor_->nativeImgSrc;

    IMG_NAPI_CHECK_RET_D(IMG_IS_READY(status, context->rImageSource),
        nullptr, IMAGE_LOGE("empty native rImageSource"));

    if (argCount > NUM_2) {
        IMAGE_LOGE("argCount mismatch");
        return nullptr;
    }

    if (argCount > NUM_0) {
        if (ImageNapiUtils::getType(env, argValue[NUM_0]) == napi_object) {
            IMAGE_LOGD("UnwrapContextForList object");
            if (!ParseDecodeOptions(env, argValue[NUM_0], &(context->decodeOpts),
                                    &(context->index), context->errMsg)) {
                IMAGE_LOGE("DecodeOptions mismatch");
            }
        }

        if (ImageNapiUtils::getType(env, argValue[argCount - 1]) == napi_function) {
            IMAGE_LOGD("UnwrapContextForList function");
            napi_create_reference(env, argValue[argCount - 1], refCount, &context->callbackRef);
        }
    }

    return context;
}

static ImageSourceAsyncContext* CheckAsyncContext(ImageSourceAsyncContext* context, bool check)
{
    if (context == nullptr) {
        IMAGE_LOGE("context is nullptr");
        return nullptr;
    }

    if (check) {
        if (context->errMsg.size() > 0) {
            IMAGE_LOGE("mismatch args");
            context->status = ERROR;
            return nullptr;
        }

        if (context->rImageSource == nullptr) {
            IMAGE_LOGE("empty context rImageSource");
            context->status = ERROR;
            return nullptr;
        }
    }

    return context;
}

STATIC_EXEC_FUNC(CreatePixelMapList)
{
    if (data == nullptr) {
        IMAGE_LOGE("data is nullptr");
        return;
    }

    auto context = CheckAsyncContext(static_cast<ImageSourceAsyncContext*>(data), true);
    if (context == nullptr) {
        IMAGE_LOGE("check async context fail");
        return;
    }

    context->pixelMaps = nullptr;
    uint32_t errorCode = 0;
    uint32_t frameCount = context->rImageSource->GetFrameCount(errorCode);
    if ((errorCode == SUCCESS) && (context->index >= NUM_0) && (context->index < frameCount)) {
        context->decodeOpts.invokeType = JS_INTERFACE;
        context->pixelMaps = context->rImageSource->CreatePixelMapList(context->decodeOpts, errorCode);
    }
    if ((errorCode == SUCCESS) && IMG_NOT_NULL(context->pixelMaps)) {
        context->status = SUCCESS;
    } else {
        IMAGE_LOGE("Create PixelMap List error, error=%{public}u", errorCode);
        context->errMsg = "Create PixelMap List error";
        context->status = (errorCode != SUCCESS) ? errorCode : ERROR;
    }
}

STATIC_COMPLETE_FUNC(CreatePixelMapList)
{
    if (data == nullptr) {
        IMAGE_LOGE("data is nullptr");
        return;
    }

    auto context = CheckAsyncContext(static_cast<ImageSourceAsyncContext*>(data), false);
    if (context == nullptr) {
        IMAGE_LOGE("check async context fail");
        return;
    }

    napi_value result = nullptr;
    if ((context->status == SUCCESS) && IMG_NOT_NULL(context->pixelMaps)) {
        IMAGE_LOGD("CreatePixelMapListComplete array");
        napi_create_array(env, &result);
        size_t i = 0;
        for (auto &pixelMap : *context->pixelMaps.get()) {
            auto napiPixelMap = PixelMapNapi::CreatePixelMap(env, std::move(pixelMap));
            napi_set_element(env, result, i, napiPixelMap);
            i++;
        }
    } else {
        IMAGE_LOGD("CreatePixelMapListComplete undefined");
        napi_get_undefined(env, &result);
    }

    IMAGE_LOGD("CreatePixelMapListComplete set to nullptr");
    context->pixelMaps = nullptr;

    ImageSourceCallbackWithErrorObj(env, context, result);
}

napi_value ImageSourceNapi::CreatePixelMapList(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("ImageSourceNapi::CreatePixelMapList");

    auto asyncContext = UnwrapContextForList(env, info);
    if (asyncContext == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_DATA_ABNORMAL,
            "async context unwrap failed");
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    ImageNapiUtils::HicheckerReport();

    napi_status status;
    IMG_CREATE_CREATE_ASYNC_WORK_WITH_QOS(env, status, "CreatePixelMapList", CreatePixelMapListExec,
        CreatePixelMapListComplete, asyncContext, asyncContext->work, napi_qos_user_initiated);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to create async work"));

    return result;
}

STATIC_EXEC_FUNC(GetDelayTime)
{
    if (data == nullptr) {
        IMAGE_LOGE("data is nullptr");
        return;
    }

    auto context = CheckAsyncContext(static_cast<ImageSourceAsyncContext*>(data), true);
    if (context == nullptr) {
        IMAGE_LOGE("check async context fail");
        return;
    }

    uint32_t errorCode = 0;
    context->delayTimes = context->rImageSource->GetDelayTime(errorCode);
    if ((errorCode == SUCCESS) && IMG_NOT_NULL(context->delayTimes)) {
        context->status = SUCCESS;
    } else {
        IMAGE_LOGE("Get DelayTime error, error=%{public}u", errorCode);
        context->errMsg = "Get DelayTime error";
        context->status = (errorCode != SUCCESS) ? errorCode : ERROR;
    }
}

STATIC_COMPLETE_FUNC(GetDelayTime)
{
    if (data == nullptr) {
        IMAGE_LOGE("data is nullptr");
        return;
    }

    auto context = CheckAsyncContext(static_cast<ImageSourceAsyncContext*>(data), false);
    if (context == nullptr) {
        IMAGE_LOGE("check async context fail");
        return;
    }

    napi_value result = nullptr;
    if (context->status == SUCCESS && IMG_NOT_NULL(context->delayTimes)) {
        IMAGE_LOGD("GetDelayTimeComplete array");
        napi_create_array(env, &result);
        size_t i = 0;
        for (auto delayTime : *context->delayTimes) {
            napi_value napiDelayTime = nullptr;
            napi_create_uint32(env, delayTime, &napiDelayTime);
            napi_set_element(env, result, i, napiDelayTime);
            i++;
        }
    } else {
        IMAGE_LOGD("GetDelayTimeComplete undefined");
        napi_get_undefined(env, &result);
    }

    IMAGE_LOGD("GetDelayTimeComplete set to nullptr");
    context->delayTimes = nullptr;
    ImageSourceCallbackWithErrorObj(env, context, result);
}

napi_value ImageSourceNapi::GetDelayTime(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("ImageSourceNapi::GetDelayTime");

    auto asyncContext = UnwrapContextForList(env, info);
    if (asyncContext == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_DATA_ABNORMAL,
            "async context unwrap failed");
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_status status;
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetDelayTime", GetDelayTimeExec,
        GetDelayTimeComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to create async work"));

    return result;
}

STATIC_EXEC_FUNC(GetDisposalType)
{
    if (data == nullptr) {
        IMAGE_LOGE("data is nullptr");
        return;
    }

    auto context = CheckAsyncContext(static_cast<ImageSourceAsyncContext*>(data), true);
    if (context == nullptr) {
        IMAGE_LOGE("check async context fail");
        return;
    }

    uint32_t errorCode = 0;
    context->disposalType = context->rImageSource->GetDisposalType(errorCode);
    if ((errorCode == SUCCESS) && IMG_NOT_NULL(context->disposalType)) {
        context->status = SUCCESS;
    } else {
        IMAGE_LOGE("Get DisposalType error, error=%{public}u", errorCode);
        context->errMsg = "Get DisposalType error";
        context->status = (errorCode != SUCCESS) ? errorCode : ERROR;
    }
}

STATIC_COMPLETE_FUNC(GetDisposalType)
{
    if (data == nullptr) {
        IMAGE_LOGE("data is nullptr");
        return;
    }

    auto context = CheckAsyncContext(static_cast<ImageSourceAsyncContext*>(data), false);
    if (context == nullptr) {
        IMAGE_LOGE("check async context fail");
        return;
    }

    napi_value result = nullptr;
    if (context->status == SUCCESS && IMG_NOT_NULL(context->disposalType)) {
        IMAGE_LOGD("GetDisposalTypeComplete array");
        napi_create_array(env, &result);
        size_t i = 0;
        for (auto disposalType : *context->disposalType) {
            napi_value napiDisposalType = nullptr;
            napi_create_uint32(env, disposalType, &napiDisposalType);
            napi_set_element(env, result, i, napiDisposalType);
            i++;
        }
    } else {
        IMAGE_LOGD("GetDisposalTypeComplete undefined");
        napi_get_undefined(env, &result);
    }

    IMAGE_LOGD("GetDisposalTypeComplete set to nullptr");
    context->disposalType = nullptr;
    ImageSourceCallbackWithErrorObj(env, context, result);
}

napi_value ImageSourceNapi::GetDisposalType(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("ImageSourceNapi::GetDisposalType");

    auto asyncContext = UnwrapContextForList(env, info);
    if (asyncContext == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_DATA_ABNORMAL,
            "async context unwrap failed");
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_status status;
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetDisposalType", GetDisposalTypeExec,
        GetDisposalTypeComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to create async work"));

    return result;
}

STATIC_EXEC_FUNC(GetFrameCount)
{
    if (data == nullptr) {
        IMAGE_LOGE("data is nullptr");
        return;
    }

    auto context = CheckAsyncContext(static_cast<ImageSourceAsyncContext*>(data), true);
    if (context == nullptr) {
        IMAGE_LOGE("check async context fail");
        return;
    }

    uint32_t errorCode = 0;
    context->frameCount = context->rImageSource->GetFrameCount(errorCode);
    IMAGE_LOGD("GetFrameCountExec count=%{public}u, error=%{public}u", context->frameCount, errorCode);
    if (errorCode == SUCCESS) {
        context->status = SUCCESS;
    } else {
        IMAGE_LOGE("Get FrameCount error, error=%{public}u", errorCode);
        context->errMsg = "Get FrameCount error";
        context->status = errorCode;
    }
}

STATIC_COMPLETE_FUNC(GetFrameCount)
{
    if (data == nullptr) {
        IMAGE_LOGE("data is nullptr");
        return;
    }

    auto context = CheckAsyncContext(static_cast<ImageSourceAsyncContext*>(data), false);
    if (context == nullptr) {
        IMAGE_LOGE("check async context fail");
        return;
    }

    napi_value result = nullptr;
    if (context->status == SUCCESS) {
        IMAGE_LOGD("GetFrameCountComplete uint");
        napi_create_uint32(env, context->frameCount, &result);
    } else {
        IMAGE_LOGD("GetFrameCountComplete undefined");
        napi_get_undefined(env, &result);
    }

    context->frameCount = 0;
    ImageSourceCallbackWithErrorObj(env, context, result);
}

napi_value ImageSourceNapi::GetFrameCount(napi_env env, napi_callback_info info)
{
    ImageTrace imageTrace("ImageSourceNapi::GetFrameCount");

    auto asyncContext = UnwrapContextForList(env, info);
    if (asyncContext == nullptr) {
        return ImageNapiUtils::ThrowExceptionError(env, ERR_IMAGE_DATA_ABNORMAL,
            "async context unwrap failed");
    }

    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    if (asyncContext->callbackRef == nullptr) {
        napi_create_promise(env, &(asyncContext->deferred), &result);
    } else {
        napi_get_undefined(env, &result);
    }

    napi_status status;
    IMG_CREATE_CREATE_ASYNC_WORK(env, status, "GetFrameCount", GetFrameCountExec,
        GetFrameCountComplete, asyncContext, asyncContext->work);
    IMG_NAPI_CHECK_RET_D(IMG_IS_OK(status), nullptr, IMAGE_LOGE("fail to create async work"));

    return result;
}

int32_t ImageSourceNapi::CreateImageSourceNapi(napi_env env, napi_value* result)
{
    napi_value constructor = nullptr;
    napi_status status = napi_ok;
    PrepareNapiEnv(env);

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok && constructor != nullptr) {
        status = napi_new_instance(env, constructor, NUM_0, nullptr, result);
    }

    if (status != napi_ok || result == nullptr) {
        IMAGE_LOGE("CreateImageSourceNapi new instance failed");
        napi_get_undefined(env, result);
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    return SUCCESS;
}

void ImageSourceNapi::SetIncrementalPixelMap(std::shared_ptr<IncrementalPixelMap> incrementalPixelMap)
{
    navIncPixelMap_ = incrementalPixelMap;
}

void ImageSourceNapi::SetNativeImageSource(std::shared_ptr<ImageSource> imageSource)
{
    nativeImgSrc = imageSource;
}

void ImageSourceNapi::SetImageResource(ImageResource resource)
{
    resource_.type = resource.type;
    resource_.fd = resource.fd;
    resource_.path = resource.path;
    resource_.buffer = resource.buffer;
    resource_.bufferSize = resource.bufferSize;
}

ImageResource ImageSourceNapi::GetImageResource()
{
    return resource_;
}
}  // namespace Media
}  // namespace OHOS
