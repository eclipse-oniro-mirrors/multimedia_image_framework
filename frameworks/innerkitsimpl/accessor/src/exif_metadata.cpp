/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <map>
#include <numeric>
#include <ostream>
#include <set>
#include <sstream>
#include <vector>
#include <string_view>
#include <charconv>

#include "exif_metadata.h"
#include "exif_metadata_formatter.h"
#include "image_log.h"
#include "image_utils.h"
#include "libexif/exif-format.h"
#include "libexif/exif-mem.h"
#include "libexif/exif-tag.h"
#include "libexif/huawei/exif-mnote-data-huawei.h"
#include "libexif/huawei/mnote-huawei-entry.h"
#include "libexif/huawei/mnote-huawei-tag.h"
#include "libexif/huawei/mnote-huawei-data-type.h"
#include "media_errors.h"
#include "securec.h"
#include "string_ex.h"
#include "tiff_parser.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ExifMetadata"

namespace OHOS {
namespace Media {
const auto KEY_SIZE = 2;
const auto TAG_VALUE_SIZE = 1024;
const auto MAX_TAG_VALUE_SIZE_FOR_STR = 64 * 1024;
const auto TERMINATOR_SIZE = 1;
const auto EXIF_HEAD_SIZE = 6;
const int NUMERATOR_SIZE = 4; // 4 bytes for numeratior
const static std::string DEFAULT_EXIF_VALUE = "default_exif_value";
const static std::string HW_CAPTURE_MODE = "HwMnoteCaptureMode";
const static std::string HW_FOCUS_MODE_EXIF = "HwMnoteFocusModeExif";
const static std::string MAKER_NOTE_TAG = "MakerNote";
const static uint64_t MAX_EXIFMETADATA_MAX_SIZE = 1024 * 1024;
const std::set<std::string_view> HW_SPECIAL_KEYS = {
    "MovingPhotoId",
    "MovingPhotoVersion",
    "MicroVideoPresentationTimestampUS",
    "HwUnknow",
};
const unsigned char INIT_HW_DATA[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x55, 0x41, 0x57, 0x45, 0x49, 0x00,
    0x00, 0x4D, 0x4D, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x02, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
};

static const int GET_SUPPORT_MAKERNOTE_COUNT = 1;
static const int INIT_HW_DATA_HEAD_LENGTH = 8;

const std::map<std::string, PropertyValueType>& ExifMetadata::GetExifMetadataMap()
{
    static const std::map<std::string, PropertyValueType> exifMetadataMap = {
        {"NewSubfileType", PropertyValueType::INT},
        {"SubfileType", PropertyValueType::INT},
        {"ImageWidth", PropertyValueType::INT},
        {"ImageLength", PropertyValueType::INT},
        {"BitsPerSample", PropertyValueType::INT_ARRAY},
        {"Compression", PropertyValueType::INT},
        {"PhotometricInterpretation", PropertyValueType::INT},
        {"ImageDescription", PropertyValueType::STRING},
        {"Make", PropertyValueType::STRING},
        {"Model", PropertyValueType::STRING},
        {"StripOffsets", PropertyValueType::INT_ARRAY},
        {"Orientation", PropertyValueType::INT},
        {"SamplesPerPixel", PropertyValueType::INT},
        {"RowsPerStrip", PropertyValueType::INT},
        {"StripByteCounts", PropertyValueType::INT_ARRAY},
        {"XResolution", PropertyValueType::DOUBLE},
        {"YResolution", PropertyValueType::DOUBLE},
        {"PlanarConfiguration", PropertyValueType::INT},
        {"ResolutionUnit", PropertyValueType::INT},
        {"TransferFunction", PropertyValueType::STRING},
        {"Software", PropertyValueType::STRING},
        {"DateTime", PropertyValueType::STRING},
        {"Artist", PropertyValueType::STRING},
        {"WhitePoint", PropertyValueType::DOUBLE_ARRAY},
        {"PrimaryChromaticities", PropertyValueType::DOUBLE_ARRAY},
        {"PhotoMode", PropertyValueType::INT},
        {"JPEGInterchangeFormat", PropertyValueType::INT},
        {"JPEGInterchangeFormatLength", PropertyValueType::INT},
        {"YCbCrCoefficients", PropertyValueType::DOUBLE_ARRAY},
        {"YCbCrSubSampling", PropertyValueType::INT_ARRAY},
        {"YCbCrPositioning", PropertyValueType::INT},
        {"ReferenceBlackWhite", PropertyValueType::DOUBLE_ARRAY},
        {"Copyright", PropertyValueType::STRING},
        {"ExposureTime", PropertyValueType::DOUBLE},
        {"FNumber", PropertyValueType::DOUBLE},
        {"ExposureProgram", PropertyValueType::INT},
        {"SpectralSensitivity", PropertyValueType::STRING},
        {"GPSVersionID", PropertyValueType::INT_ARRAY},
        {"GPSLatitudeRef", PropertyValueType::STRING},
        {"GPSLatitude", PropertyValueType::DOUBLE_ARRAY},
        {"GPSLongitudeRef", PropertyValueType::STRING},
        {"GPSLongitude", PropertyValueType::DOUBLE_ARRAY},
        {"GPSAltitudeRef", PropertyValueType::INT},
        {"GPSAltitude", PropertyValueType::DOUBLE},
        {"GPSTimeStamp", PropertyValueType::DOUBLE_ARRAY},
        {"GPSSatellites", PropertyValueType::STRING},
        {"GPSStatus", PropertyValueType::STRING},
        {"GPSMeasureMode", PropertyValueType::STRING},
        {"GPSDOP", PropertyValueType::DOUBLE},
        {"GPSSpeedRef", PropertyValueType::STRING},
        {"GPSSpeed", PropertyValueType::DOUBLE},
        {"GPSTrackRef", PropertyValueType::STRING},
        {"GPSTrack", PropertyValueType::DOUBLE},
        {"GPSImgDirectionRef", PropertyValueType::STRING},
        {"GPSImgDirection", PropertyValueType::DOUBLE},
        {"GPSMapDatum", PropertyValueType::STRING},
        {"GPSDestLatitudeRef", PropertyValueType::STRING},
        {"GPSDestLatitude", PropertyValueType::DOUBLE_ARRAY},
        {"GPSDestLongitudeRef", PropertyValueType::STRING},
        {"GPSDestLongitude", PropertyValueType::DOUBLE_ARRAY},
        {"GPSDestBearingRef", PropertyValueType::STRING},
        {"GPSDestBearing", PropertyValueType::DOUBLE},
        {"GPSDestDistanceRef", PropertyValueType::STRING},
        {"GPSDestDistance", PropertyValueType::DOUBLE},
        {"GPSProcessingMethod", PropertyValueType::STRING},
        {"GPSAreaInformation", PropertyValueType::STRING},
        {"GPSDateStamp", PropertyValueType::STRING},
        {"GPSDifferential", PropertyValueType::INT},
        {"GPSHPositioningError", PropertyValueType::DOUBLE},
        {"ISOSpeedRatings", PropertyValueType::INT},
        {"PhotographicSensitivity", PropertyValueType::INT_ARRAY},
        {"OECF", PropertyValueType::BLOB},
        {"SensitivityType", PropertyValueType::INT},
        {"StandardOutputSensitivity", PropertyValueType::INT},
        {"RecommendedExposureIndex", PropertyValueType::INT},
        {"ISOSpeedLatitudeyyy", PropertyValueType::INT},
        {"ISOSpeedLatitudezzz", PropertyValueType::INT},
        {"ExifVersion", PropertyValueType::STRING},
        {"DateTimeOriginal", PropertyValueType::STRING},
        {"DateTimeDigitized", PropertyValueType::STRING},
        {"OffsetTime", PropertyValueType::STRING},
        {"OffsetTimeOriginal", PropertyValueType::STRING},
        {"OffsetTimeDigitized", PropertyValueType::STRING},
        {"ComponentsConfiguration", PropertyValueType::STRING},
        {"CompressedBitsPerPixel", PropertyValueType::DOUBLE},
        {"ShutterSpeedValue", PropertyValueType::DOUBLE},
        {"ApertureValue", PropertyValueType::DOUBLE},
        {"BrightnessValue", PropertyValueType::DOUBLE},
        {"ExposureBiasValue", PropertyValueType::DOUBLE},
        {"MaxApertureValue", PropertyValueType::DOUBLE},
        {"SubjectDistance", PropertyValueType::DOUBLE},
        {"MeteringMode", PropertyValueType::INT},
        {"LightSource", PropertyValueType::INT},
        {"Flash", PropertyValueType::INT},
        {"FocalLength", PropertyValueType::DOUBLE},
        {"SubjectArea", PropertyValueType::INT_ARRAY},
        {"MakerNote", PropertyValueType::BLOB},
        {"UserComment", PropertyValueType::STRING},
        {"SubsecTime", PropertyValueType::STRING},
        {"SubsecTimeOriginal", PropertyValueType::STRING},
        {"SubsecTimeDigitized", PropertyValueType::STRING},
        {"FlashpixVersion", PropertyValueType::STRING},
        {"ColorSpace", PropertyValueType::INT},
        {"PixelXDimension", PropertyValueType::INT},
        {"PixelYDimension", PropertyValueType::INT},
        {"RelatedSoundFile", PropertyValueType::STRING},
        {"FlashEnergy", PropertyValueType::DOUBLE},
        {"SpatialFrequencyResponse", PropertyValueType::BLOB},
        {"FocalPlaneXResolution", PropertyValueType::DOUBLE},
        {"FocalPlaneYResolution", PropertyValueType::DOUBLE},
        {"FocalPlaneResolutionUnit", PropertyValueType::INT},
        {"SubjectLocation", PropertyValueType::INT_ARRAY},
        {"ExposureIndex", PropertyValueType::DOUBLE},
        {"SensingMethod", PropertyValueType::INT},
        {"FileSource", PropertyValueType::BLOB},
        {"SceneType", PropertyValueType::BLOB},
        {"CFAPattern", PropertyValueType::BLOB},
        {"CustomRendered", PropertyValueType::INT},
        {"ExposureMode", PropertyValueType::INT},
        {"WhiteBalance", PropertyValueType::INT},
        {"DigitalZoomRatio", PropertyValueType::DOUBLE},
        {"FocalLengthIn35mmFilm", PropertyValueType::INT},
        {"SceneCaptureType", PropertyValueType::INT},
        {"GainControl", PropertyValueType::INT},
        {"Contrast", PropertyValueType::INT},
        {"Saturation", PropertyValueType::INT},
        {"Sharpness", PropertyValueType::INT},
        {"DeviceSettingDescription", PropertyValueType::BLOB},
        {"SubjectDistanceRange", PropertyValueType::INT},
        {"ImageUniqueID", PropertyValueType::STRING},
        {"CameraOwnerName", PropertyValueType::STRING},
        {"BodySerialNumber", PropertyValueType::STRING},
        {"LensSpecification", PropertyValueType::DOUBLE_ARRAY},
        {"LensMake", PropertyValueType::STRING},
        {"LensModel", PropertyValueType::STRING},
        {"LensSerialNumber", PropertyValueType::STRING},
        {"CompositeImage", PropertyValueType::INT},
        {"SourceImageNumberOfCompositeImage", PropertyValueType::INT_ARRAY},
        {"SourceExposureTimesOfCompositeImage", PropertyValueType::BLOB},
        {"Gamma", PropertyValueType::DOUBLE},
        {"DNGVersion", PropertyValueType::INT_ARRAY},
        {"DefaultCropSize", PropertyValueType::INT_ARRAY},
    };
    return exifMetadataMap;
}

const std::map<std::string, PropertyValueType>& ExifMetadata::GetHwMetadataMap()
{
    static const std::map<std::string, PropertyValueType> hwMetadataMap = {
        {"HwMnoteIsXmageSupported", PropertyValueType::INT},
        {"HwMnoteXmageMode", PropertyValueType::INT},
        {"HwMnoteXmageLeft", PropertyValueType::INT},
        {"HwMnoteXmageTop", PropertyValueType::INT},
        {"HwMnoteXmageRight", PropertyValueType::INT},
        {"HwMnoteXmageBottom", PropertyValueType::INT},
        {"HwMnoteXmageColorMode", PropertyValueType::INT},
        {"HwMnoteCloudEnhancementMode", PropertyValueType::INT},
        {"HwMnoteWindSnapshotMode", PropertyValueType::INT},
        {"HwMnoteSceneVersion", PropertyValueType::INT},
        {"HwMnoteSceneFoodConf", PropertyValueType::INT},
        {"HwMnoteSceneStageConf", PropertyValueType::INT},
        {"HwMnoteSceneBlueSkyConf", PropertyValueType::INT},
        {"HwMnoteSceneGreenPlantConf", PropertyValueType::INT},
        {"HwMnoteSceneBeachConf", PropertyValueType::INT},
        {"HwMnoteSceneSnowConf", PropertyValueType::INT},
        {"HwMnoteSceneSunsetConf", PropertyValueType::INT},
        {"HwMnoteSceneFlowersConf", PropertyValueType::INT},
        {"HwMnoteSceneNightConf", PropertyValueType::INT},
        {"HwMnoteSceneTextConf", PropertyValueType::INT},
        {"HwMnoteFaceCount", PropertyValueType::INT},
        {"HwMnoteFaceConf", PropertyValueType::INT_ARRAY},
        {"HwMnoteFaceSmileScore", PropertyValueType::INT_ARRAY},
        {"HwMnoteCaptureMode", PropertyValueType::INT},
        {"HwMnoteBurstNumber", PropertyValueType::INT},
        {"HwMnoteFrontCamera", PropertyValueType::INT},
        {"HwMnoteRollAngle", PropertyValueType::INT},
        {"HwMnotePitchAngle", PropertyValueType::INT},
        {"HwMnotePhysicalAperture", PropertyValueType::INT},
        {"HwMnoteFocusMode", PropertyValueType::INT},
        {"HwMnoteXtStyleVignetting", PropertyValueType::DOUBLE},
        {"HwMnoteXtStyleNoise", PropertyValueType::DOUBLE}
    };
    return hwMetadataMap;
}

const std::map<std::string, PropertyValueType>& ExifMetadata::GetHeifsMetadataMap()
{
    static const std::map<std::string, PropertyValueType> heifsMetadataMap = {
        {"HeifsDelayTime", PropertyValueType::INT},
    };
    return heifsMetadataMap;
}

const std::map<std::string, PropertyValueType>& ExifMetadata::GetFragmentMetadataMap()
{
    static const std::map<std::string, PropertyValueType> fragmentMetadataMap = {
        {"XInOriginal", PropertyValueType::INT},
        {"YInOriginal", PropertyValueType::INT},
        {"FragmentImageWidth", PropertyValueType::INT},
        {"FragmentImageHeight", PropertyValueType::INT},
    };
    return fragmentMetadataMap;
}

const std::map<std::string, PropertyValueType>& ExifMetadata::GetGifMetadataMap()
{
    static const std::map<std::string, PropertyValueType> gifMetadataMap = {
        {"GifDelayTime", PropertyValueType::INT},
        {"GifDisposalType", PropertyValueType::INT},
    };
    return gifMetadataMap;
}

const std::map<NapiMetadataType, std::map<std::string, PropertyValueType>>& ExifMetadata::GetPropertyTypeMapping()
{
    static const std::map<NapiMetadataType, std::map<std::string, PropertyValueType>> propertyTypeMap = {
        {NapiMetadataType::EXIF_METADATA, GetExifMetadataMap()},
        {NapiMetadataType::HWMAKERNOTE_METADATA, GetHwMetadataMap()},
        {NapiMetadataType::HEIFS_METADATA, GetHeifsMetadataMap()},
        {NapiMetadataType::FRAGMENT_METADATA, GetFragmentMetadataMap()},
        {NapiMetadataType::GIF_METADATA, GetGifMetadataMap()},
    };
    return propertyTypeMap;
}

const std::unordered_map<std::string, std::string>& ExifMetadata::GetPropertyKeyMap()
{
    static const std::unordered_map<std::string, std::string> propertyKeyMap = {
        // ============ ExifMetadata ============
        {"newSubfileType", "NewSubfileType"},
        {"subfileType", "SubfileType"},
        {"imageWidth", "ImageWidth"},
        {"imageLength", "ImageLength"},
        {"bitsPerSample", "BitsPerSample"},
        {"compression", "Compression"},
        {"photometricInterpretation", "PhotometricInterpretation"},
        {"imageDescription", "ImageDescription"},
        {"make", "Make"},
        {"model", "Model"},
        {"stripOffsets", "StripOffsets"},
        {"orientation", "Orientation"},
        {"samplesPerPixel", "SamplesPerPixel"},
        {"rowsPerStrip", "RowsPerStrip"},
        {"stripByteCounts", "StripByteCounts"},
        {"xResolution", "XResolution"},
        {"yResolution", "YResolution"},
        {"planarConfiguration", "PlanarConfiguration"},
        {"resolutionUnit", "ResolutionUnit"},
        {"transferFunction", "TransferFunction"},
        {"software", "Software"},
        {"dateTime", "DateTime"},
        {"artist", "Artist"},
        {"whitePoint", "WhitePoint"},
        {"primaryChromaticities", "PrimaryChromaticities"},
        {"photoMode", "PhotoMode"},
        {"jpegInterchangeFormat", "JPEGInterchangeFormat"},
        {"jpegInterchangeFormatLength", "JPEGInterchangeFormatLength"},
        {"yCbCrCoefficients", "YCbCrCoefficients"},
        {"yCbCrSubSampling", "YCbCrSubSampling"},
        {"yCbCrPositioning", "YCbCrPositioning"},
        {"referenceBlackWhite", "ReferenceBlackWhite"},
        {"copyright", "Copyright"},
        {"exposureTime", "ExposureTime"},
        {"fNumber", "FNumber"},
        {"exposureProgram", "ExposureProgram"},
        {"spectralSensitivity", "SpectralSensitivity"},
        {"gpsVersionID", "GPSVersionID"},
        {"gpsLatitudeRef", "GPSLatitudeRef"},
        {"gpsLatitude", "GPSLatitude"},
        {"gpsLongitudeRef", "GPSLongitudeRef"},
        {"gpsLongitude", "GPSLongitude"},
        {"gpsAltitudeRef", "GPSAltitudeRef"},
        {"gpsAltitude", "GPSAltitude"},
        {"gpsTimestamp", "GPSTimeStamp"},
        {"gpsSatellites", "GPSSatellites"},
        {"gpsStatus", "GPSStatus"},
        {"gpsMeasureMode", "GPSMeasureMode"},
        {"gpsDop", "GPSDOP"},
        {"gpsSpeedRef", "GPSSpeedRef"},
        {"gpsSpeed", "GPSSpeed"},
        {"gpsTrackRef", "GPSTrackRef"},
        {"gpsTrack", "GPSTrack"},
        {"gpsImgDirectionRef", "GPSImgDirectionRef"},
        {"gpsImgDirection", "GPSImgDirection"},
        {"gpsMapDatum", "GPSMapDatum"},
        {"gpsDestLatitudeRef", "GPSDestLatitudeRef"},
        {"gpsDestLatitude", "GPSDestLatitude"},
        {"gpsDestLongitudeRef", "GPSDestLongitudeRef"},
        {"gpsDestLongitude", "GPSDestLongitude"},
        {"gpsDestBearingRef", "GPSDestBearingRef"},
        {"gpsDestBearing", "GPSDestBearing"},
        {"gpsDestDistanceRef", "GPSDestDistanceRef"},
        {"gpsDestDistance", "GPSDestDistance"},
        {"gpsProcessingMethod", "GPSProcessingMethod"},
        {"gpsAreaInformation", "GPSAreaInformation"},
        {"gpsDateStamp", "GPSDateStamp"},
        {"gpsDifferential", "GPSDifferential"},
        {"gpsHPositioningError", "GPSHPositioningError"},
        {"isoSpeedRatings", "ISOSpeedRatings"},
        {"photographicSensitivity", "PhotographicSensitivity"},
        {"oecf", "OECF"},
        {"sensitivityType", "SensitivityType"},
        {"standardOutputSensitivity", "StandardOutputSensitivity"},
        {"recommendedExposureIndex", "RecommendedExposureIndex"},
        {"isoSpeedLatitudeyyy", "ISOSpeedLatitudeyyy"},
        {"isoSpeedLatitudezzz", "ISOSpeedLatitudezzz"},
        {"exifVersion", "ExifVersion"},
        {"dateTimeOriginal", "DateTimeOriginal"},
        {"dateTimeDigitized", "DateTimeDigitized"},
        {"offsetTime", "OffsetTime"},
        {"offsetTimeOriginal", "OffsetTimeOriginal"},
        {"offsetTimeDigitized", "OffsetTimeDigitized"},
        {"componentsConfiguration", "ComponentsConfiguration"},
        {"compressedBitsPerPixel", "CompressedBitsPerPixel"},
        {"shutterSpeedValue", "ShutterSpeedValue"},
        {"apertureValue", "ApertureValue"},
        {"brightnessValue", "BrightnessValue"},
        {"exposureBiasValue", "ExposureBiasValue"},
        {"maxApertureValue", "MaxApertureValue"},
        {"subjectDistance", "SubjectDistance"},
        {"meteringMode", "MeteringMode"},
        {"lightSource", "LightSource"},
        {"flash", "Flash"},
        {"focalLength", "FocalLength"},
        {"subjectArea", "SubjectArea"},
        {"makerNote", "MakerNote"},
        {"userComment", "UserComment"},
        {"subsecTime", "SubsecTime"},
        {"subsecTimeOriginal", "SubsecTimeOriginal"},
        {"subsecTimeDigitized", "SubsecTimeDigitized"},
        {"flashpixVersion", "FlashpixVersion"},
        {"colorSpace", "ColorSpace"},
        {"pixelXDimension", "PixelXDimension"},
        {"pixelYDimension", "PixelYDimension"},
        {"relatedSoundFile", "RelatedSoundFile"},
        {"flashEnergy", "FlashEnergy"},
        {"spatialFrequencyResponse", "SpatialFrequencyResponse"},
        {"focalPlaneXResolution", "FocalPlaneXResolution"},
        {"focalPlaneYResolution", "FocalPlaneYResolution"},
        {"focalPlaneResolutionUnit", "FocalPlaneResolutionUnit"},
        {"subjectLocation", "SubjectLocation"},
        {"exposureIndex", "ExposureIndex"},
        {"sensingMethod", "SensingMethod"},
        {"fileSource", "FileSource"},
        {"sceneType", "SceneType"},
        {"cfaPattern", "CFAPattern"},
        {"customRendered", "CustomRendered"},
        {"exposureMode", "ExposureMode"},
        {"whiteBalance", "WhiteBalance"},
        {"digitalZoomRatio", "DigitalZoomRatio"},
        {"focalLengthIn35mmFilm", "FocalLengthIn35mmFilm"},
        {"sceneCaptureType", "SceneCaptureType"},
        {"gainControl", "GainControl"},
        {"contrast", "Contrast"},
        {"saturation", "Saturation"},
        {"sharpness", "Sharpness"},
        {"deviceSettingDescription", "DeviceSettingDescription"},
        {"subjectDistanceRange", "SubjectDistanceRange"},
        {"imageUniqueId", "ImageUniqueID"},
        {"cameraOwnerName", "CameraOwnerName"},
        {"bodySerialNumber", "BodySerialNumber"},
        {"lensSpecification", "LensSpecification"},
        {"lensMake", "LensMake"},
        {"lensModel", "LensModel"},
        {"lensSerialNumber", "LensSerialNumber"},
        {"compositeImage", "CompositeImage"},
        {"sourceImageNumberOfCompositeImage", "SourceImageNumberOfCompositeImage"},
        {"sourceExposureTimesOfCompositeImage", "SourceExposureTimesOfCompositeImage"},
        {"gamma", "Gamma"},
        {"dngVersion", "DNGVersion"},
        {"defaultCropSize", "DefaultCropSize"},
        
        // ============ MakerNoteHuaweiMetadata ============
        {"isXmageSupported", "HwMnoteIsXmageSupported"},
        {"xmageWatermarkMode", "HwMnoteXmageMode"},
        {"xmageLeft", "HwMnoteXmageLeft"},
        {"xmageTop", "HwMnoteXmageTop"},
        {"xmageRight", "HwMnoteXmageRight"},
        {"xmageBottom", "HwMnoteXmageBottom"},
        {"xmageColorMode", "HwMnoteXmageColorMode"},
        {"isCloudEnhanced", "HwMnoteCloudEnhancementMode"},
        {"isWindSnapshot", "HwMnoteWindSnapshotMode"},
        {"sceneVersion", "HwMnoteSceneVersion"},
        {"sceneFoodConfidence", "HwMnoteSceneFoodConf"},
        {"sceneStageConfidence", "HwMnoteSceneStageConf"},
        {"sceneBlueSkyConfidence", "HwMnoteSceneBlueSkyConf"},
        {"sceneGreenPlantConfidence", "HwMnoteSceneGreenPlantConf"},
        {"sceneBeachConfidence", "HwMnoteSceneBeachConf"},
        {"sceneSnowConfidence", "HwMnoteSceneSnowConf"},
        {"sceneSunsetConfidence", "HwMnoteSceneSunsetConf"},
        {"sceneFlowersConfidence", "HwMnoteSceneFlowersConf"},
        {"sceneNightConfidence", "HwMnoteSceneNightConf"},
        {"sceneTextConfidence", "HwMnoteSceneTextConf"},
        {"faceCount", "HwMnoteFaceCount"},
        {"faceConfidences", "HwMnoteFaceConf"},
        {"faceSmileScores", "HwMnoteFaceSmileScore"},
        {"captureMode", "HwMnoteCaptureMode"},
        {"burstNumber", "HwMnoteBurstNumber"},
        {"isFrontCamera", "HwMnoteFrontCamera"},
        {"rollAngle", "HwMnoteRollAngle"},
        {"pitchAngle", "HwMnotePitchAngle"},
        {"physicalAperture", "HwMnotePhysicalAperture"},
        {"focusMode", "HwMnoteFocusMode"},
        {"xtStyleVignetting", "HwMnoteXtStyleVignetting"},
        {"xtStyleNoise", "HwMnoteXtStyleNoise"},

        // ============ HeifsMetadata ============
        {"heifsDelayTime", "HeifsDelayTime"},

        // ============ FragmentMetadata ============
        {"xInOriginal", "XInOriginal"},
        {"yInOriginal", "YInOriginal"},
        {"fragmentImageWidth", "FragmentImageWidth"},
        {"fragmentImageHeight", "FragmentImageHeight"},

        // ============ GifMetadata ============
        {"gifDelayTime", "GifDelayTime"},
        {"gifDisposalType", "GifDisposalType"},
    };
    return propertyKeyMap;
}

template <typename T, typename U> std::istream &OutputRational(std::istream &is, T &r)
{
    U nominator = 0;
    U denominator = 0;
    char c('\0');
    is >> nominator >> c >> denominator;
    if (c != '/') {
        is.setstate(std::ios::failbit);
    }
    if (is) {
        r = { nominator, denominator };
    }
    return is;
}

std::istream &operator >> (std::istream &is, ExifRational &r)
{
    return OutputRational<ExifRational, uint32_t>(is, r);
}

std::istream &operator >> (std::istream &is, ExifSRational &r)
{
    return OutputRational<ExifSRational, int32_t>(is, r);
}

std::set<ExifTag> UndefinedByte = { EXIF_TAG_SCENE_TYPE, EXIF_TAG_COMPONENTS_CONFIGURATION, EXIF_TAG_FILE_SOURCE };

ExifMetadata::ExifMetadata() : exifData_(nullptr) {}

ExifMetadata::ExifMetadata(ExifData *exifData) : exifData_(exifData) {}

ExifMetadata::~ExifMetadata()
{
    if (exifData_ != nullptr) {
        exif_data_unref(exifData_);
        exifData_ = nullptr;
    }
}

int ExifMetadata::GetValue(const std::string &key, std::string &value) const
{
    value.clear();
    IMAGE_LOGD("Retrieving value for key: %{public}s", key.c_str());
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT,
                               "Exif data is null for key: %{public}s", key.c_str());
    if (!ExifMetadatFormatter::IsKeySupported(key)) {
        IMAGE_LOGD("Key is not supported.");
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    if (key == MAKER_NOTE_TAG) {
        return HandleMakerNote(value);
    }
    
    if ((key.size() > KEY_SIZE && key.substr(0, KEY_SIZE) == "Hw") || IsSpecialHwKey(key)) {
        return HandleHwMnote(key, value);
    } else {
        auto tag = exif_tag_from_name(key.c_str());
        ExifEntry *entry = GetEntry(key);
        if (entry == nullptr) {
            IMAGE_LOGD("Exif data entry returned null for key: %{public}s, tag: %{public}d", key.c_str(), tag);
            return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
        }
        IMAGE_LOGD("Using exif_entry_get_value for key: %{public}s, tag: %{public}d", key.c_str(), entry->tag);
        
        unsigned int tagValueSizeTmp = 0;
        if (entry->size >= TAG_VALUE_SIZE && (entry->format == EXIF_FORMAT_ASCII ||
            entry->format == EXIF_FORMAT_UNDEFINED)) {
            tagValueSizeTmp = entry->size + TERMINATOR_SIZE > MAX_TAG_VALUE_SIZE_FOR_STR ?
                MAX_TAG_VALUE_SIZE_FOR_STR : entry->size + TERMINATOR_SIZE;
        } else {
            tagValueSizeTmp = TAG_VALUE_SIZE;
        }
        char tagValueChar[tagValueSizeTmp];

        exif_entry_get_value(entry, tagValueChar, sizeof(tagValueChar));
        value = tagValueChar;
    }
    if (ExifMetadatFormatter::IsSensitiveInfo(key)) {
        IMAGE_LOGD("Retrieved value for key: %{public}s success", key.c_str());
    } else {
        IMAGE_LOGD("Retrieved value for key: %{public}s is: %{public}s", key.c_str(), value.c_str());
    }
    return SUCCESS;
}

static unsigned int CalculateTagValueSize(ExifEntry *entry)
{
    CHECK_ERROR_RETURN_RET(entry == nullptr, TAG_VALUE_SIZE);
    if (entry->size >= TAG_VALUE_SIZE &&
        (entry->format == EXIF_FORMAT_ASCII || entry->format == EXIF_FORMAT_UNDEFINED)) {
        if (entry->size + TERMINATOR_SIZE > MAX_TAG_VALUE_SIZE_FOR_STR) {
            return MAX_TAG_VALUE_SIZE_FOR_STR;
        } else {
            return entry->size + TERMINATOR_SIZE;
        }
    }
    return TAG_VALUE_SIZE;
}

static void GetIntValue(EntryBasicInfo info, MetadataValue &result)
{
    CHECK_ERROR_RETURN_LOG(info.components == 0 || info.components > MAX_TAG_VALUE_SIZE_FOR_STR ||
        info.data == nullptr, "%{public}s, data is nullptr or components is 0", __func__);
    result.intArrayValue.clear();
    result.intArrayValue.reserve(info.components);
    size_t formatSize = exif_format_get_size(info.format);
    const unsigned int comp = info.components;
    for (unsigned int i = 0; i < comp; i++) {
        int64_t value = 0;
        const unsigned char *dataPtr = info.data + formatSize * i;
        switch (info.format) {
            case EXIF_FORMAT_SHORT:
                value = static_cast<int64_t>(exif_get_short(dataPtr, info.byteOrder));
                break;
            case EXIF_FORMAT_LONG:
                value = static_cast<int64_t>(exif_get_long(dataPtr, info.byteOrder));
                break;
            case EXIF_FORMAT_SSHORT:
                value = static_cast<int64_t>(exif_get_sshort(dataPtr, info.byteOrder));
                break;
            case EXIF_FORMAT_SLONG:
                value = static_cast<int64_t>(exif_get_slong(dataPtr, info.byteOrder));
                break;
            case EXIF_FORMAT_BYTE:
                value = *reinterpret_cast<const uint8_t*>(dataPtr);
                break;
            case EXIF_FORMAT_SBYTE:
                value = *reinterpret_cast<const int8_t*>(dataPtr);
                break;
            default:
                IMAGE_LOGE("%{public}s, unsupported exif type:%{public}d", __func__, info.format);
                break;
        }
        result.intArrayValue.push_back(value);
    }
}

static void GetRationalValue(EntryBasicInfo info, MetadataValue &result)
{
    CHECK_ERROR_RETURN_LOG(info.components == 0 || info.components > MAX_TAG_VALUE_SIZE_FOR_STR ||
        info.data == nullptr, "%{public}s, data is nullptr or components is 0", __func__);
    result.doubleArrayValue.clear();
    result.doubleArrayValue.reserve(info.components);
    size_t formatSize = exif_format_get_size(info.format);
    const unsigned int comp = info.components;
    for (unsigned int i = 0; i < comp; ++i) {
        const unsigned char* dataPtr = info.data + formatSize * i;
        if (info.format == EXIF_FORMAT_RATIONAL) {
            ExifRational vRat = exif_get_rational(dataPtr, info.byteOrder);
            if (vRat.denominator) {
                result.doubleArrayValue.push_back(static_cast<double>(vRat.numerator) / vRat.denominator);
            }
        } else if (info.format == EXIF_FORMAT_SRATIONAL) {
            ExifSRational vSrat = exif_get_srational(dataPtr, info.byteOrder);
            if (vSrat.denominator) {
                result.doubleArrayValue.push_back(static_cast<double>(vSrat.numerator) / vSrat.denominator);
            }
        }
    }
}

static void GetStringValueFromExifEntry(ExifEntry *entry, MetadataValue &result,
                                        unsigned int tagValueSize)
{
    std::vector<char> buffer(tagValueSize);
    exif_entry_get_value(entry, buffer.data(), buffer.size());
    result.stringValue = std::string(buffer.data());
}

static void GetUnsupportedFormatValue(ExifEntry *entry, MetadataValue &result)
{
    CHECK_ERROR_RETURN(entry == nullptr);
    result.stringValue = std::to_string(entry->size) + " bytes unsupported data type";
}

static uint32_t GetBlobValueFromExifEntry(ExifEntry *entry, MetadataValue &result)
{
    CHECK_ERROR_RETURN_RET_LOG(entry == nullptr || !entry->parent || !entry->parent->parent,
        ERR_IMAGE_DECODE_METADATA_FAILED, "Invalid EXIF entry structure");
    CHECK_ERROR_RETURN_RET_LOG(entry->size <= 0 || entry->size > MAX_TAG_VALUE_SIZE_FOR_STR ||
        entry->data == nullptr, ERR_IMAGE_DECODE_METADATA_FAILED, "data is nullptr or size is invalid");
    result.bufferValue.resize(entry->size);
    CHECK_ERROR_RETURN_RET(result.bufferValue.size() != entry->size, ERR_IMAGE_DECODE_METADATA_FAILED);
    errno_t err = memcpy_s(result.bufferValue.data(), result.bufferValue.size(), entry->data, entry->size);
    CHECK_ERROR_RETURN_RET_LOG(err != EOK, ERR_IMAGE_DECODE_METADATA_FAILED,
        "memcpy_s failed: %{public}d", err);
    IMAGE_LOGD("Copied %{public}zu bytes", result.bufferValue.size());
    return SUCCESS;
}

static void GetValueByExifType(ExifEntry *entry, MetadataValue &result, unsigned int tagValueSize)
{
    CHECK_ERROR_RETURN_LOG(entry == nullptr || !entry->parent || !entry->parent->parent || entry->data == nullptr,
        "Invalid EXIF entry structure");
    const ExifByteOrder byteOrder = exif_data_get_byte_order(entry->parent->parent);
    EntryBasicInfo info = {entry->format, entry->components, entry->data, byteOrder};
    switch (entry->format) {
        case EXIF_FORMAT_SHORT:
        case EXIF_FORMAT_LONG:
        case EXIF_FORMAT_SSHORT:
        case EXIF_FORMAT_SLONG:
        case EXIF_FORMAT_BYTE:
        case EXIF_FORMAT_SBYTE:
            GetIntValue(info, result);
            break;
        case EXIF_FORMAT_RATIONAL:
        case EXIF_FORMAT_SRATIONAL:
            GetRationalValue(info, result);
            break;
        case EXIF_FORMAT_UNDEFINED:
            GetBlobValueFromExifEntry(entry, result);
            break;
        case EXIF_FORMAT_ASCII:
            GetStringValueFromExifEntry(entry, result, tagValueSize);
            break;
        case EXIF_FORMAT_DOUBLE:
        case EXIF_FORMAT_FLOAT:
            GetUnsupportedFormatValue(entry, result);
            break;
        default:
            IMAGE_LOGE("Unsupported exif format: %{public}d", entry->format);
            break;
    }
}

static void ParseHwUndefinedData(MnoteHuaweiEntry *entry, MetadataValue &result)
{
    CHECK_ERROR_RETURN(entry == nullptr);
    if (entry->size > 0 && entry->size < MAX_TAG_VALUE_SIZE_FOR_STR) {
        result.bufferValue.resize(entry->size);
        bool cond = memcpy_s(result.bufferValue.data(), entry->size, entry->data, entry->size);
        CHECK_ERROR_RETURN_LOG(cond != EOK, "%{public}s, memory copy failed.", __func__);
    }
}

static void ParseHwAsciiData(MnoteHuaweiEntry *entry, MetadataValue &result)
{
    CHECK_ERROR_RETURN(entry == nullptr);
    size_t len = entry->size;
    if (len > 0 && entry->data[len-1] == '\0') {
        len--;
    }
    result.stringValue.assign(reinterpret_cast<const char*>(entry->data), len);
}

static void ParseEntryByFormat(MnoteHuaweiEntry *entry, MetadataValue &result, const std::string &key)
{
    CHECK_ERROR_RETURN_LOG(entry == nullptr || entry->data == nullptr, "Invalid EXIF entry structure");
    const ExifByteOrder byteOrder = entry->order;
    EntryBasicInfo info = {entry->format, entry->components, entry->data, byteOrder};
    switch (entry->format) {
        case EXIF_FORMAT_BYTE:
        case EXIF_FORMAT_SBYTE:
        case EXIF_FORMAT_SHORT:
        case EXIF_FORMAT_SSHORT:
        case EXIF_FORMAT_LONG:
        case EXIF_FORMAT_SLONG:
            GetIntValue(info, result);
            break;
        case EXIF_FORMAT_RATIONAL:
        case EXIF_FORMAT_SRATIONAL:
            GetRationalValue(info, result);
            break;
        case EXIF_FORMAT_UNDEFINED:
            ParseHwUndefinedData(entry, result);
            break;
        case EXIF_FORMAT_ASCII:
            ParseHwAsciiData(entry, result);
            break;
        default:
            IMAGE_LOGW("Unsupported format:%{public}d for key:%{public}s", entry->format, key.c_str());
            ParseHwUndefinedData(entry, result);
            break;
    }
}

static int ParseMatchingHwEntry(const std::string &key, MnoteHuaweiEntryCount *ec, MetadataValue &result)
{
    CHECK_ERROR_RETURN_RET(ec == nullptr, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    for (unsigned int i = 0; i < ec->size; i++) {
        MnoteHuaweiEntry *entry = ec->entries[i];
        if (!entry || !entry->data) {
            continue;
        }
        const char* entryKey = mnote_huawei_tag_get_name(entry->tag);
        if (!entryKey || key != entryKey) {
            continue;
        }
        if (entry->components > entry->size) {
            continue;
        }
        if (key == "HwMnoteFaceConf" || key == "HwMnoteFaceSmileScore") {
            std::vector<int64_t> intValue;
            for (uint32_t j = 0; j < entry->components; j++) {
                uint8_t value = *(reinterpret_cast<const uint8_t*>(entry->data + j));
                intValue.push_back(value);
            }
            result.intArrayValue = intValue;
        }
        ParseEntryByFormat(entry, result, key);
        return SUCCESS;
    }
    return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
}

static int GetHwEntryCount(ExifMnoteData *md, MnoteHuaweiEntryCount **ec)
{
    CHECK_ERROR_RETURN_RET_LOG(!is_huawei_md(md), ERR_IMAGE_DECODE_EXIF_UNSUPPORT, "Not Huawei maker note");
    mnote_huawei_get_entry_count(reinterpret_cast<ExifMnoteDataHuawei *>(md), ec);
    CHECK_ERROR_RETURN_RET_LOG(*ec == nullptr, ERR_IMAGE_DECODE_EXIF_UNSUPPORT, "Huawei entry count null");
    return SUCCESS;
}

int ExifMetadata::HandleHwMnoteByType(const std::string &key, MetadataValue &result) const
{
    MetadataValue tmpResult;
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);
    CHECK_ERROR_RETURN_RET_LOG(md == nullptr, ERR_IMAGE_DECODE_EXIF_UNSUPPORT, "Exif mnote data null");
    MnoteHuaweiEntryCount *ec = nullptr;
    int retCode = GetHwEntryCount(md, &ec);
    CHECK_ERROR_RETURN_RET_LOG(retCode != SUCCESS, retCode, "Invalid Huawei metadata");
    retCode = ParseMatchingHwEntry(key, ec, tmpResult);
    result = tmpResult;
    
    mnote_huawei_free_entry_count(ec);
    return retCode;
}

bool IsSpecialKey(std::string key)
{
    return key == "ExifVersion" || key == "ComponentsConfiguration" || key == "UserComment" ||
        key == "FlashpixVersion" || key == "TransferFunction" || key == "GPSProcessingMethod" ||
        key == "GPSAreaInformation";
}

int ExifMetadata::GetValueByType(const std::string &key, MetadataValue &value) const
{
    IMAGE_LOGD("Retrieving value for key: %{public}s", key.c_str());
    MetadataValue tmpValue;
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT,
        "Exif data is null for key: %{public}s", key.c_str());
    if (!ExifMetadatFormatter::IsKeySupported(key)) {
        IMAGE_LOGD("Key is not supported.");
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    
    if ((key.size() > KEY_SIZE && key.substr(0, KEY_SIZE) == "Hw") || IsSpecialHwKey(key)) {
        int errorCode = HandleHwMnoteByType(key, tmpValue);
        value = tmpValue;
        return errorCode;
    } else {
        auto tag = exif_tag_from_name(key.c_str());
        ExifEntry *entry = GetEntry(key);
        CHECK_DEBUG_RETURN_RET_LOG(entry == nullptr, ERR_IMAGE_DECODE_EXIF_UNSUPPORT,
            "Exif data entry returned null for key: %{public}s, tag: %{public}d", key.c_str(), tag);
        IMAGE_LOGD("Using exif_entry_get_value for key: %{public}s, tag: %{public}d", key.c_str(), entry->tag);
        unsigned int tagValueSize = CalculateTagValueSize(entry);
        if (IsSpecialKey(key)) {
            char tagValueChar[tagValueSize];
            exif_entry_get_value(entry, tagValueChar, sizeof(tagValueChar));
            value.stringValue = tagValueChar;
            return SUCCESS;
        }
        GetValueByExifType(entry, tmpValue, tagValueSize);
    }
    IMAGE_LOGD("Retrieved value for key: %{public}s", key.c_str());
    value = tmpValue;
    return SUCCESS;
}

const ImageMetadata::PropertyMapPtr ExifMetadata::GetAllProperties()
{
    ImageMetadata::PropertyMapPtr result = std::make_shared<ImageMetadata::PropertyMap>();
    std::string value;
    auto rwKeys = ExifMetadatFormatter::GetRWKeys();
    for (const auto& key : rwKeys) {
        if (GetValue(key, value) == SUCCESS) {
            result->insert(std::make_pair(key, value));
        }
    }
    auto roKeys = ExifMetadatFormatter::GetROKeys();
    for (const auto& key : roKeys) {
        if (GetValue(key, value) == SUCCESS) {
            result->insert(std::make_pair(key, value));
        }
    }
    IMAGE_LOGD("Get record arguments success.");
    return result;
}

std::shared_ptr<ImageMetadata> ExifMetadata::CloneMetadata()
{
    return Clone();
}

int ExifMetadata::HandleMakerNote(std::string &value) const
{
    value.clear();
    std::vector<char> tagValueChar(TAG_VALUE_SIZE, 0);
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);
    bool cond = false;
    if (md == nullptr) {
        IMAGE_LOGD("Exif data mnote data md is a nullptr.");
    }
    if (!is_huawei_md(md)) {
        return GetUserMakerNote(value);
    }
    MnoteHuaweiEntryCount *ec = nullptr;
    mnote_huawei_get_entry_count(reinterpret_cast<ExifMnoteDataHuawei *>(md), &ec);
    cond = ec == nullptr;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    for (unsigned int i = 0; i < ec->size; i++) {
        MnoteHuaweiEntry *entry = ec->entries[i];
        const char *mnoteKey = mnote_huawei_tag_get_name(entry->tag);
        if (HW_SPECIAL_KEYS.find(mnoteKey) != HW_SPECIAL_KEYS.end()) {
            continue;
        }
        mnote_huawei_entry_get_value(entry, tagValueChar.data(), tagValueChar.size());
        value += std::string(mnoteKey) + ":" + tagValueChar.data() + ",";
    }

    // Check if the last character of value is a comma and remove it
    if (value.length() > 1 && value[value.length() - 1] == ',') {
        value = value.substr(0, value.length() - 1);
    }
    mnote_huawei_free_entry_count(ec);

    return SUCCESS;
}

int ExifMetadata::HandleHwMnote(const std::string &key, std::string &value) const
{
    value = DEFAULT_EXIF_VALUE;
    char tagValueChar[TAG_VALUE_SIZE];
    if (key == HW_FOCUS_MODE_EXIF) {
        auto entry = exif_data_get_entry_ext(exifData_, EXIF_TAG_MAKER_NOTE);
        exif_entry_get_value(entry, tagValueChar, sizeof(tagValueChar));
        value = tagValueChar;
        bool cond = value.empty();
        CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
        return SUCCESS;
    }
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);
    bool cond = false;
    cond = md == nullptr;
    CHECK_DEBUG_RETURN_RET_LOG(cond, SUCCESS, "Exif data mnote data md is nullptr");
    cond = !is_huawei_md(md);
    CHECK_ERROR_RETURN_RET_LOG(cond, SUCCESS, "Exif data returned null for key: %{public}s", key.c_str());
    MnoteHuaweiEntryCount *ec = nullptr;
    mnote_huawei_get_entry_count(reinterpret_cast<ExifMnoteDataHuawei *>(md), &ec);
    cond = ec == nullptr;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    for (unsigned int i = 0; i < ec->size; i++) {
        MnoteHuaweiEntry *entry = ec->entries[i];
        if (entry == nullptr) {
            continue;
        }
        if (key == mnote_huawei_tag_get_name(entry->tag)) {
            mnote_huawei_entry_get_value(entry, tagValueChar, sizeof(tagValueChar));
            value = tagValueChar;
            break;
        }
    }
    mnote_huawei_free_entry_count(ec);
    return SUCCESS;
}

ExifData *ExifMetadata::GetExifData()
{
    return exifData_;
}

bool ExifMetadata::CreateExifdata()
{
    if (exifData_ != nullptr) {
        exif_data_unref(exifData_);
        exifData_ = nullptr;
        exifData_ = exif_data_new();
        if (exifData_ == nullptr) {
            IMAGE_LOGE("Failed to recreate exif data after unref.");
            return false;
        }

        // Set the image options
        exif_data_set_option(exifData_, EXIF_DATA_OPTION_FOLLOW_SPECIFICATION);
        exif_data_set_data_type(exifData_, EXIF_DATA_TYPE_COMPRESSED);
        exif_data_set_byte_order(exifData_, EXIF_BYTE_ORDER_INTEL);

        // Create the mandatory EXIF fields with default data
        exif_data_fix(exifData_);
        return true;
    }
    exifData_ = exif_data_new();
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Failed to create new exif data.");

    // Set the image options
    exif_data_set_option(exifData_, EXIF_DATA_OPTION_FOLLOW_SPECIFICATION);
    exif_data_set_data_type(exifData_, EXIF_DATA_TYPE_COMPRESSED);
    exif_data_set_byte_order(exifData_, EXIF_BYTE_ORDER_INTEL);

    // Create the mandatory EXIF fields with default data
    exif_data_fix(exifData_);
    IMAGE_LOGD("New exif data created.");
    return true;
}

std::shared_ptr<ExifMetadata> ExifMetadata::Clone()
{
    ExifData *exifData = this->GetExifData();

    unsigned char *dataBlob = nullptr;
    uint32_t size = 0;
    TiffParser::Encode(&dataBlob, size, exifData);
    if (dataBlob == nullptr) {
        return nullptr;
    }

    if (size > MAX_EXIFMETADATA_MAX_SIZE) {
        IMAGE_LOGE("Failed to clone, the size of exif metadata exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_EXIFMETADATA_MAX_SIZE));
        return nullptr;
    }
    ExifData *newExifData = nullptr;
    TiffParser::Decode(dataBlob, size, &newExifData);
    bool cond = newExifData == nullptr;
    CHECK_ERROR_RETURN_RET(cond, nullptr);
    std::shared_ptr<ExifMetadata> exifDataPtr = std::make_shared<ExifMetadata>(newExifData);
    if (dataBlob != nullptr) {
        free(dataBlob);
        dataBlob = nullptr;
    }
    return exifDataPtr;
}

bool ExifMetadata::GetDataSize(uint32_t &size, bool withThumbnail, bool isJpeg)
{
    CHECK_ERROR_RETURN_RET_LOG(exifData_ == nullptr, false, "%{public}s: exifData_ is nullptr", __func__);

    ScopeRestorer<unsigned char *> thumbDataRestorer(exifData_->data);
    ScopeRestorer<unsigned int> thumbSizeRestorer(exifData_->size);

    // remove thumbnail data temporarily
    if (!withThumbnail) {
        thumbDataRestorer.SetValue(nullptr);
        thumbSizeRestorer.SetValue(0);
    }

    unsigned char *dataBlob = nullptr;
    uint32_t dataSize = 0;
    if (isJpeg) {
        TiffParser::EncodeJpegExif(&dataBlob, dataSize, exifData_);
    } else {
        TiffParser::Encode(&dataBlob, dataSize, exifData_);
    }

    CHECK_ERROR_RETURN_RET_LOG(dataBlob == nullptr, false, "%{public}s: TiffParser encode failed", __func__);
    size = dataSize;

    // release encoded data blob
    if (dataBlob != nullptr) {
        free(dataBlob);
        dataBlob = nullptr;
    }

    IMAGE_LOGD("%{public}s: exif data size: %{public}u", __func__, size);
    return true;
}

bool ExifMetadata::HasThumbnail()
{
    CHECK_ERROR_RETURN_RET_LOG(exifData_ == nullptr, false, "%{public}s: exifData_ is nullptr", __func__);
    return exifData_->data != nullptr && exifData_->size != 0;
}

bool ExifMetadata::GetThumbnail(uint8_t *&data, uint32_t &size)
{
    CHECK_ERROR_RETURN_RET_LOG(exifData_ == nullptr, false, "%{public}s: exifData_ is nullptr", __func__);
    data = reinterpret_cast<uint8_t *>(exifData_->data);
    size = static_cast<uint32_t>(exifData_->size);
    IMAGE_LOGD("%{public}s: size: %{public}u", __func__, size);
    CHECK_ERROR_RETURN_RET(data == nullptr || size == 0, false);
    return true;
}

bool ExifMetadata::SetThumbnail(uint8_t *data, const uint32_t &size)
{
    CHECK_ERROR_RETURN_RET_LOG(exifData_ == nullptr, false, "%{public}s: exifData_ is nullptr", __func__);
    CHECK_ERROR_RETURN_RET_LOG(data == nullptr || size == 0, false, "%{public}s: data or size is invalid", __func__);

    // Free old thumbnail memory if it exists
    CHECK_ERROR_RETURN_RET_LOG(!DropThumbnail(), false, "%{public}s: Drop thumbnail failed", __func__);
    // Allocate a new memory for thumbnail.
    ExifMem* mem = exif_data_get_priv_mem(exifData_);
    CHECK_ERROR_RETURN_RET_LOG(mem == nullptr, false, "%{public}s: GetExif mem allocator failed", __func__);
    exifData_->data = static_cast<unsigned char *>(exif_mem_alloc(mem, size));
    CHECK_ERROR_RETURN_RET_LOG(exifData_->data == nullptr, false,
        "%{public}s: exif_mem_alloc failed, size: %{public}u", __func__, size);
    memcpy_s(exifData_->data, size, data, size);
    exifData_->size = size;
    IMAGE_LOGI("%{public}s success! size: %{public}u", __func__, size);
    return true;
}

bool ExifMetadata::DropThumbnail()
{
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s: exifData_ is nullptr", __func__);
    if (!HasThumbnail()) {
        IMAGE_LOGD("%{public}s: No thumbnail to drop", __func__);
        return true;
    }
    ExifMem* mem = exif_data_get_priv_mem(exifData_);
    CHECK_ERROR_RETURN_RET_LOG(mem == nullptr, false, "%{public}s: GetExif mem allocator failed", __func__);
    exif_mem_free(mem, exifData_->data);
    exifData_->data = nullptr;
    exifData_->size = 0;
    IMAGE_LOGD("%{public}s: Drop thumbnail success", __func__);
    return true;
}

ExifEntry *ExifMetadata::CreateEntry(const std::string &key, const ExifTag &tag, const size_t valueLen)
{
    ExifEntry *entry = exif_entry_new();
    bool cond = false;
    cond = entry == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Failed to create new ExifEntry.");
    entry->tag = tag; // tag must be set before calling exif_content_add_entry
    auto ifdindex = exif_ifd_from_name(key.c_str());
    exif_content_add_entry(exifData_->ifd[ifdindex], entry);
    exif_entry_initialize(entry, tag);

    if (entry->format == EXIF_FORMAT_UNDEFINED && entry->size != valueLen) {
        exif_content_remove_entry(exifData_->ifd[ifdindex], entry);

        // Create a memory allocator to manage this ExifEntry
        ExifMem *exifMem = exif_mem_new_default();
        cond = exifMem == nullptr;
        CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Failed to create memory allocator for ExifEntry.");

        // Create a new ExifEntry using our allocator
        entry = exif_entry_new_mem(exifMem);
        if (entry == nullptr) {
            IMAGE_LOGE("Failed to create new ExifEntry using memory allocator.");
            exif_mem_unref(exifMem);
            return nullptr;
        }

        // Allocate memory to use for holding the tag data
        void *buffer = exif_mem_alloc(exifMem, valueLen);
        if (buffer == nullptr) {
            IMAGE_LOGE("Failed to allocate memory for tag data.");
            exif_entry_unref(entry);
            exif_mem_unref(exifMem);
            return nullptr;
        }

        // Fill in the entry
        entry->data = static_cast<unsigned char *>(buffer);
        entry->size = valueLen;
        entry->tag = tag;
        entry->components = valueLen;
        entry->format = EXIF_FORMAT_UNDEFINED;

        // Attach the ExifEntry to an IFD
        exif_content_add_entry(exifData_->ifd[ifdindex], entry);

        // The ExifMem and ExifEntry are now owned elsewhere
        exif_mem_unref(exifMem);
        exif_entry_unref(entry);
    }
    return entry;
}

MnoteHuaweiEntry *ExifMetadata::CreateHwEntry(const std::string &key)
{
    ExifMnoteData *md = exif_data_get_mnote_data (exifData_);
    bool cond = false;
    cond = !is_huawei_md(md);
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Failed to create MnoteHuaweiEntry is not Huawei MakeNote.");

    ExifByteOrder order = exif_mnote_data_huawei_get_byte_order(md);
    MnoteHuaweiEntry* entry = mnote_huawei_entry_new(md);
    cond = !entry;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Failed to create MnoteHuaweiEntry.");

    MnoteHuaweiTag tag = mnote_huawei_tag_from_name(key.c_str());
    mnote_huawei_entry_initialize(entry, tag, order);
    return entry;
}

void ExifMetadata::ReallocEntry(ExifEntry *ptrEntry, const size_t valueLen)
{
    // Create a memory allocator to manage this ExifEntry
    ExifMem *exifMem = exif_mem_new_default();
    bool cond = exifMem == nullptr;
    CHECK_ERROR_RETURN_LOG(cond, "Failed to create memory allocator for ExifEntry. Value length: %{public}zu",
                           valueLen);
    auto buf = exif_mem_realloc(exifMem, ptrEntry->data, valueLen);
    if (buf != nullptr) {
        ptrEntry->data = static_cast<unsigned char *>(buf);
        ptrEntry->size = exif_format_get_size(ptrEntry->format) * valueLen;
        ptrEntry->components = exif_format_get_size(ptrEntry->format) * valueLen;
    } else {
        IMAGE_LOGE("Failed to reallocate memory for ExifEntry. Requested size: %{public}zu", valueLen);
    }
    exif_mem_unref(exifMem);
}

ExifEntry *ExifMetadata::GetEntry(const std::string &key, const size_t valueLen)
{
    IMAGE_LOGD("GetEntry key is %{public}s.", key.c_str());
    ExifTag tag = exif_tag_from_name(key.c_str());
    ExifEntry *entry;
    if (tag == 0x0001 || tag == 0x0002) {
        ExifIfd ifd = exif_ifd_from_name(key.c_str());
        entry = exif_content_get_entry(exifData_->ifd[ifd], tag);
    } else {
        entry = exif_data_get_entry(exifData_, tag);
    }

    if (entry == nullptr) {
        IMAGE_LOGD("GetEntry entry is nullptr and try to create entry.");
        entry = CreateEntry(key, tag, valueLen);
    }

    bool cond = entry == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "GetEntry entry is nullptr fail.");

    if ((entry->format == EXIF_FORMAT_UNDEFINED || entry->format == EXIF_FORMAT_ASCII) &&
        (entry->size != static_cast<unsigned int>(valueLen))) {
        ReallocEntry(entry, valueLen);
    }
    return entry;
}

ExifEntry *ExifMetadata::GetEntry(const std::string &key) const
{
    IMAGE_LOGD("GetEntry by key is %{public}s.", key.c_str());
    ExifTag tag = exif_tag_from_name(key.c_str());
    ExifEntry *entry = nullptr;
    if (tag == 0x0001 || tag == 0x0002) {
        ExifIfd ifd = exif_ifd_from_name(key.c_str());
        entry = exif_content_get_entry(exifData_->ifd[ifd], tag);
    } else {
        entry = exif_data_get_entry(exifData_, tag);
    }
    return entry;
}

bool ExifMetadata::SetShort(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifShort tmp;
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifShort from string. Current count: %{public}lu", icount);
        exif_set_short(ptrEntry->data + icount * exif_format_get_size(ptrEntry->format), order, tmp);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetLong(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifLong tmp;
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifLong from string. Current count: %{public}lu", icount);
        exif_set_long(ptrEntry->data + icount * exif_format_get_size(ptrEntry->format), order, tmp);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetSShort(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifSShort tmp;
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifSShort from string. Current count: %{public}lu", icount);
        exif_set_sshort(ptrEntry->data + icount * exif_format_get_size(ptrEntry->format), order, tmp);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetSLong(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifSLong tmp;
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> tmp;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifSLong from string. Current count: %{public}lu", icount);
        exif_set_slong(ptrEntry->data + icount * exif_format_get_size(ptrEntry->format), order, tmp);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetRational(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifRational rat;
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> rat;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifRational from string. Current count: %{public}lu", icount);
        unsigned long offset = icount * exif_format_get_size(ptrEntry->format);
        exif_set_rational(ptrEntry->data + offset, order, rat);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetSRational(ExifEntry *ptrEntry, const ExifByteOrder &order, const std::string &value)
{
    std::istringstream is(value);
    unsigned long icount = 0;
    ExifSRational rat;
    bool cond = false;
    while (!is.eof() && ptrEntry->components > icount) {
        is >> rat;
        cond = is.fail();
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
                                   "Failed to read ExifSRational from string. Current count: %{public}lu", icount);
        unsigned long offset = icount * exif_format_get_size(ptrEntry->format);
        exif_set_srational(ptrEntry->data + offset, order, rat);
        icount++;
    }
    return true;
}

bool ExifMetadata::SetByte(ExifEntry *ptrEntry, const std::string &value)
{
    std::string result = std::accumulate(value.begin(), value.end(), std::string(), [](std::string res, char a) {
        if (a != ' ') {
            return res += a;
        }
        return res;
    });
    const char *p = result.c_str();
    int valueLen = static_cast<int>(result.length());
    for (int i = 0; i < valueLen && i < static_cast<int>(ptrEntry->size); i++) {
        *(ptrEntry->data + i) = p[i] - '0';
    }
    return true;
}

bool ExifMetadata::SetMem(ExifEntry *ptrEntry, const std::string &value, const size_t valueLen)
{
    if (UndefinedByte.find(ptrEntry->tag) != UndefinedByte.end()) {
        return SetByte(ptrEntry, value);
    }
    if (memcpy_s((ptrEntry)->data, valueLen, value.c_str(), valueLen) != 0) {
        IMAGE_LOGE("Failed to copy memory for ExifEntry. Requested size: %{public}zu", valueLen);
        return false;
    }
    return true;
}

bool ExifMetadata::SetValue(const std::string &key, const std::string &value)
{
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Exif data is null. Cannot set value for key: %{public}s", key.c_str());
    if (value.empty()) {
        IMAGE_LOGE("Set empty value.");
        return false;
    }
    auto result = ExifMetadatFormatter::Format(key, value);
    if (result.first) {
        IMAGE_LOGE("Failed to validate and convert value for key: %{public}s", key.c_str());
        return false;
    }

    if ((key.size() > KEY_SIZE && key.substr(0, KEY_SIZE) == "Hw") ||
        IsSpecialHwKey(key)) {
        IMAGE_LOGD("Set HwMoteValue %{public}s", value.c_str());
        return SetHwMoteValue(key, result.second);
    }
    if (key == MAKER_NOTE_TAG) {
        IMAGE_LOGD("Set MakerNote %{public}s", value.c_str());
        return SetMakerNoteValue(value);
    }

    return SetCommonValue(key, result.second);
}

bool ExifMetadata::SetMakerNoteValue(const std::string &value)
{
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "exifData_ is nullptr");
    cond = value.length() >= MAX_TAG_VALUE_SIZE_FOR_STR;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "value length is too long. length: %{public}zu", value.length());
    //clear all makernote data.
    ExifEntry *entry = nullptr;
    do {
        entry = exif_data_get_entry(exifData_, EXIF_TAG_MAKER_NOTE);
        if (entry != nullptr) {
            exif_content_remove_entry(entry->parent, entry);
        }
    } while (entry != nullptr);

    auto md = exif_data_get_mnote_data(exifData_);
    if (md != nullptr) {
        exif_mnote_data_unref(md);
        exif_data_set_priv_md(exifData_, nullptr);
    }

    size_t valueLen = value.length();
    entry = CreateEntry(MAKER_NOTE_TAG, EXIF_TAG_MAKER_NOTE, valueLen);
    cond = entry == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Create entry is nullptr");
    if (memcpy_s(entry->data, entry->size, value.c_str(), valueLen) != 0) {
        IMAGE_LOGE("Failed to copy memory for ExifEntry. Requested size: %{public}zu", valueLen);
        return false;
    }

    bool isHwHead = entry->size > INIT_HW_DATA_HEAD_LENGTH &&
                        memcmp(entry->data, INIT_HW_DATA + EXIF_HEAD_SIZE, INIT_HW_DATA_HEAD_LENGTH) == 0;
    if (isHwHead) {
        uint32_t tempSize = EXIF_HEAD_SIZE + entry->size;
        std::vector<unsigned char> tempData(tempSize, 0);
        cond = memcpy_s(tempData.data() + EXIF_HEAD_SIZE, tempSize - EXIF_HEAD_SIZE, entry->data, entry->size) != EOK;
        CHECK_ERROR_RETURN_RET_LOG(cond, false, "memcpy is failed");
        auto mem = exif_data_get_priv_mem(exifData_);
        auto hwMd = exif_mnote_data_huawei_new(mem);
        if (hwMd != nullptr) {
            exif_data_set_priv_md(exifData_, hwMd);
            exif_mnote_data_set_offset(hwMd, 0);
            exif_mnote_data_load(hwMd, tempData.data(), tempSize);
            IMAGE_LOGD("value is hw makernote data. load finished! res:%{public}d", is_huawei_md(hwMd));
        }
    }
    return true;
}

bool ExifMetadata::SetHwMoteValue(const std::string &key, const std::string &value)
{
    bool isNewMaker = false;
    if (key == HW_FOCUS_MODE_EXIF) {
        auto entry = exif_data_get_entry_ext(exifData_, EXIF_TAG_MAKER_NOTE);
        if (entry == nullptr) {
            entry = CreateEntry(key, EXIF_TAG_MAKER_NOTE, value.size() + 1);
        }
        if (entry != nullptr) {
            if ((entry->format == EXIF_FORMAT_UNDEFINED || entry->format == EXIF_FORMAT_ASCII) &&
            (entry->size != static_cast<unsigned int>(value.size() + 1))) {
                ReallocEntry(entry, value.size() + 1);
            }
            SetMem(entry, value, value.size() + 1);
        }
    }
    ExifMnoteData *md = GetHwMnoteData(isNewMaker);
    bool cond = false;
    cond = !is_huawei_md(md);
    CHECK_DEBUG_RETURN_RET_LOG(cond, false, "Makernote is not huawei makernote.");

    MnoteHuaweiTag hwTag = mnote_huawei_tag_from_name(key.c_str());
    cond = hwTag == MNOTE_HUAWEI_INFO;
    CHECK_DEBUG_RETURN_RET_LOG(cond, false, "The key: %{public}s is unknow hwTag", key.c_str());

    auto *entry = exif_mnote_data_huawei_get_entry_by_tag(reinterpret_cast<ExifMnoteDataHuawei *>(md), hwTag);
    if (!entry) {
        entry = CreateHwEntry(key);
        cond = !entry;
        CHECK_ERROR_RETURN_RET(cond, false);
        auto ret = exif_mnote_data_add_entry(md, entry);
        if (ret) {
            mnote_huawei_entry_free(entry);
            IMAGE_LOGE("Add new hw entry failed.");
            return false;
        }

        mnote_huawei_entry_free_contour(entry);
        entry = exif_mnote_data_huawei_get_entry_by_tag(reinterpret_cast<ExifMnoteDataHuawei *>(md), hwTag);
    }

    const char *data = value.c_str();
    if (value.length() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        IMAGE_LOGE("Value length inavlid.length = %{public}d", static_cast<int>(value.length()));
        return false;
    }
    int dataLen = static_cast<int>(value.length());
    int ret = mnote_huawei_entry_set_value(entry, data, dataLen);
    if (ret == 0 && isNewMaker && hwTag != MNOTE_HUAWEI_CAPTURE_MODE) {
        IMAGE_LOGD("Remve default initialized hw entry.");
        RemoveEntry(HW_CAPTURE_MODE);
    }
    return ret == 0 ? true : false;
}

ExifMnoteData* ExifMetadata::GetHwMnoteData(bool &isNewMaker)
{
    bool cond = false;
    cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET(cond, nullptr);
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);
    if (md != nullptr) {
        return md;
    }
    IMAGE_LOGD("Makenote not exist & ready to init makernote with hw entry.");
    ExifMem *mem = exif_data_get_priv_mem(exifData_);
    cond = mem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "GetHwMnoteData exif data with no ExifMem.");
    md = exif_mnote_data_huawei_new(mem);
    cond = md == nullptr || md->methods.load == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "GetHwMnoteData new mnote hw data failed.");
    exif_data_set_priv_md(exifData_, (ExifMnoteData *)md);
    unsigned long hwsize = sizeof(INIT_HW_DATA) / sizeof(INIT_HW_DATA[0]);
    md->methods.load(md, INIT_HW_DATA, hwsize);
    auto makernote = CreateEntry(MAKER_NOTE_TAG, EXIF_TAG_MAKER_NOTE, hwsize);
    cond = makernote == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "GetHwMnoteData create maker note failed.");
    cond = memcpy_s(makernote->data, hwsize - EXIF_HEAD_SIZE, INIT_HW_DATA + EXIF_HEAD_SIZE,
                    hwsize - EXIF_HEAD_SIZE) != 0;
    CHECK_ERROR_PRINT_LOG(cond, "Failed to copy memory for ExifEntry. Requested size: %{public}lu", hwsize);
    isNewMaker = true;
    return md;
}

bool ExifMetadata::SetBlobValue(const MetadataValue &properties)
{
    std::string key = properties.key;
    const std::vector<uint8_t>& blobData = properties.bufferValue;
    size_t blobSize = blobData.size();
    ExifEntry* entry = GetEntry(key, blobSize);
    bool cond = entry == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Failed to get/create entry for key: %{public}s", key.c_str());

    cond = entry->parent == nullptr || entry->parent->parent == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Invalid EXIF hierarchy for key: %{public}s", key.c_str());
    CHECK_ERROR_RETURN_RET_LOG(entry->format != EXIF_FORMAT_UNDEFINED, false,
        "Unsupported format for blob data, key: %{public}s (format: %{public}d)", key.c_str(), entry->format);
    CHECK_ERROR_RETURN_RET_LOG(blobSize == 0 || blobSize > MAX_TAG_VALUE_SIZE_FOR_STR, false,
        "Set invalid blob for key: %{public}s", key.c_str());
    if (entry->data != nullptr) {
        free(entry->data);
        entry->data = nullptr;
    }
    entry->data = reinterpret_cast<unsigned char*>(malloc(blobSize));
    cond = entry->data == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Memory allocation failed for blob data. Size: %zu", blobSize);
    cond = memcpy_s(entry->data, blobSize, blobData.data(), blobSize);
    CHECK_ERROR_RETURN_RET_LOG(cond != EOK, false, "Memory copy failed data.");
    entry->size = static_cast<uint32_t>(blobSize);
    IMAGE_LOGD("Set blob data for key: %{public}s, size: %zu", key.c_str(), blobSize);
    return true;
}

bool ExifMetadata::SetCommonValue(const std::string &key, const std::string &value)
{
    size_t valueLen = value.length();
    ExifEntry *ptrEntry = GetEntry(key, valueLen);
    bool cond = ptrEntry == nullptr;
    CHECK_ERROR_RETURN_RET(cond, false);
    cond = ptrEntry->parent == nullptr;
    CHECK_ERROR_RETURN_RET(cond, false);
    ExifByteOrder order = exif_data_get_byte_order(ptrEntry->parent->parent);
    bool isSetSuccess = false;
    switch (ptrEntry->format) {
        case EXIF_FORMAT_SHORT:
            isSetSuccess = SetShort(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_LONG:
            isSetSuccess = SetLong(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_SSHORT:
            isSetSuccess = SetSShort(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_SLONG:
            isSetSuccess = SetSLong(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_RATIONAL:
            isSetSuccess = SetRational(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_SRATIONAL:
            isSetSuccess = SetSRational(ptrEntry, order, value);
            break;
        case EXIF_FORMAT_BYTE:
            isSetSuccess = SetByte(ptrEntry, value);
            break;
        case EXIF_FORMAT_UNDEFINED:
        case EXIF_FORMAT_ASCII:
            isSetSuccess = SetMem(ptrEntry, value, valueLen);
            break;
        default:
            IMAGE_LOGE("Unsupported Exif format for key: %{public}s", key.c_str());
            break;
    }
    return isSetSuccess;
}

bool ExifMetadata::RemoveEntry(const std::string &key)
{
    bool isSuccess = false;
    bool cond = false;
    cond = !(exifData_ && ExifMetadatFormatter::IsModifyAllowed(key));
    CHECK_DEBUG_RETURN_RET_LOG(cond, isSuccess,
                               "RemoveEntry failed, can not remove entry for key: %{public}s", key.c_str());

    if ((key.size() > KEY_SIZE && key.substr(0, KEY_SIZE) == "Hw") ||
        IsSpecialHwKey(key)) {
        return RemoveHwEntry(key);
    }

    ExifEntry *entry = GetEntry(key);
    cond = !entry;
    CHECK_DEBUG_RETURN_RET_LOG(cond, isSuccess,
                               "RemoveEntry failed, can not find entry for key: %{public}s", key.c_str());

    IMAGE_LOGD("RemoveEntry for key: %{public}s", key.c_str());
    exif_content_remove_entry(entry->parent, entry);
    isSuccess = true;
    return isSuccess;
}

bool ExifMetadata::RemoveHwEntry(const std::string &key)
{
    ExifMnoteData *md = exif_data_get_mnote_data(exifData_);

    bool cond = false;
    cond = !is_huawei_md(md);
    CHECK_DEBUG_RETURN_RET_LOG(cond, false, "Exif makernote is not huawei makernote");

    MnoteHuaweiTag tag = mnote_huawei_tag_from_name(key.c_str());
    auto *entry = exif_mnote_data_huawei_get_entry_by_tag((ExifMnoteDataHuawei*) md, tag);
    cond = !entry;
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
                               "Get entry by tag failed, there is no entry for key: %{public}s", key.c_str());

    exif_mnote_data_remove_entry(md, entry);
    return true;
}

bool ExifMetadata::IsSpecialHwKey(const std::string &key) const
{
    auto iter = HW_SPECIAL_KEYS.find(key);
    return (iter != HW_SPECIAL_KEYS.end());
}

void ExifMetadata::GetFilterArea(const std::vector<std::string> &exifKeys,
                                 std::vector<std::pair<uint32_t, uint32_t>> &ranges)
{
    if (exifData_ == nullptr) {
        IMAGE_LOGD("Exif data is null");
        return ;
    }
    auto size = exifKeys.size();
    for (unsigned long keySize = 0; keySize < size; keySize++) {
        ExifTag tag = exif_tag_from_name(exifKeys[keySize].c_str());
        FindRanges(tag, ranges);
    }
}

// If the tag is a rational or srational, we need to store the offset and size of the numerator
void ExifMetadata::FindRationalRanges(ExifContent *content,
    std::vector<std::pair<uint32_t, uint32_t>> &ranges, int index)
{
    for (unsigned long i = 0; i < content->entries[index]->components; i++) {
        std::pair<uint32_t, uint32_t> range =
            std::make_pair(content->entries[index]->offset +
            static_cast<unsigned long>(exif_format_get_size(content->entries[index]->format)) * i, NUMERATOR_SIZE);
        ranges.push_back(range);
    }
    return;
}

void ExifMetadata::FindRanges(const ExifTag &tag, std::vector<std::pair<uint32_t, uint32_t>> &ranges)
{
    bool hasRange = false;

    int ifd = 0;
    while (ifd < EXIF_IFD_COUNT && !hasRange) {
        ExifContent *content = exifData_->ifd[ifd];
        if (!content) {
            IMAGE_LOGD("IFD content is null, ifd: %{public}d.", ifd);
            return ;
        }

        int i = 0;
        while (i < static_cast<int>(content->count) && !hasRange) {
            if (tag == content->entries[i]->tag) {
                (content->entries[i]->format == EXIF_FORMAT_RATIONAL ||
                    content->entries[i]->format == EXIF_FORMAT_SRATIONAL)
                    ? FindRationalRanges(content, ranges, i)
                    : ranges.push_back(std::make_pair(content->entries[i]->offset, content->entries[i]->size));
                hasRange = true;
            }
            ++i;
        }
        ++ifd;
    }
}

bool ExifMetadata::Marshalling(Parcel &parcel) const
{
    if (exifData_ == nullptr) {
        return false;
    }

    unsigned char *data = nullptr;
    unsigned int size = 0;
    exif_data_save_data(exifData_, &data, &size);
    bool cond = false;

    if (!parcel.WriteBool(data != nullptr && size != 0)) {
        IMAGE_LOGE("Failed to write exif data buffer existence value.");
        return false;
    }

    cond = size > MAX_EXIFMETADATA_MAX_SIZE;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "The size of exif metadata exceeds the maximum limit.");

    if (data != nullptr && size != 0) {
        std::unique_ptr<unsigned char[]> exifData(data);
        if (!parcel.WriteUint32(static_cast<uint32_t>(size))) {
            return false;
        }
        cond = !parcel.WriteUnpadBuffer(exifData.get(), size);
        CHECK_ERROR_RETURN_RET(cond, false);
        return true;
    }
    return false;
}

ExifMetadata *ExifMetadata::Unmarshalling(Parcel &parcel)
{
    PICTURE_ERR error;
    ExifMetadata* dstExifMetadata = ExifMetadata::Unmarshalling(parcel, error);
    if (dstExifMetadata == nullptr || error.errorCode != SUCCESS) {
        IMAGE_LOGE("unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
            error.errorCode, error.errorInfo.c_str());
    }
    return dstExifMetadata;
}

ExifMetadata *ExifMetadata::Unmarshalling(Parcel &parcel, PICTURE_ERR &error)
{
    bool hasExifDataBuffer = parcel.ReadBool();
    bool cond = false;
    if (hasExifDataBuffer) {
        uint32_t size = 0;
        if (!parcel.ReadUint32(size)) {
            return nullptr;
        }

        cond = size > MAX_EXIFMETADATA_MAX_SIZE;
        CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "The size of exif metadata exceeds the maximum limit.");
        
        const uint8_t *data = parcel.ReadUnpadBuffer(static_cast<size_t>(size));
        if (!data) {
            return nullptr;
        }
        ExifData *ptrData = exif_data_new();
        cond = ptrData == nullptr;
        CHECK_ERROR_RETURN_RET(cond, nullptr);
        exif_data_unset_option(ptrData, EXIF_DATA_OPTION_IGNORE_UNKNOWN_TAGS);
        exif_data_load_data(ptrData, static_cast<const unsigned char *>(data), static_cast<unsigned int>(size));
        ExifMetadata *exifMetadata = new(std::nothrow) ExifMetadata(ptrData);
        return exifMetadata;
    }
    return nullptr;
}

bool ExifMetadata::RemoveExifThumbnail()
{
    bool cond = exifData_ == nullptr;
    CHECK_ERROR_RETURN_RET(cond, false);
    exifData_->remove_thumbnail = 1;
    IMAGE_LOGD("%{public}s set remove exif thumbnail flag", __func__);
    return true;
}

int ExifMetadata::GetUserMakerNote(std::string& value) const
{
    bool cond{false};
    std::vector<char> userValueChar(MAX_TAG_VALUE_SIZE_FOR_STR, 0);
    int count = exif_data_get_maker_note_entry_count(exifData_);
    cond = count != GET_SUPPORT_MAKERNOTE_COUNT;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    ExifEntry *entry = exif_data_get_entry(exifData_, EXIF_TAG_MAKER_NOTE);
    cond = entry == nullptr;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    cond = entry->size >= MAX_TAG_VALUE_SIZE_FOR_STR;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    exif_entry_get_value(entry, userValueChar.data(), userValueChar.size());
    value.assign(userValueChar.data(), entry->size);
    return SUCCESS;
}

bool ExifMetadata::ParseExifCoordinate(const std::string& fieldName, uint32_t& outputValue) const
{
    // Use GetValue to read the field as a string
    std::string valueStr;
    int ret = GetValue(fieldName, valueStr);
    if (ret != SUCCESS) {
        IMAGE_LOGE("Exif_metadata:ExtractXMageCoordinates Failed to read %s from EXIF metadata",
            fieldName.c_str());
        return false;
    }
    // Log the retrieved value for debugging
    IMAGE_LOGI("Exif_metadata:ExtractXMageCoordinates HDR-IMAGE Exif %s: %{public}s",
        fieldName.c_str(), valueStr.c_str());
    // Check if the value is empty or a known default placeholder
    if (valueStr.empty() || valueStr == "default_exif_value") {
        IMAGE_LOGE(
            "Exif_metadata:ExtractXMageCoordinates Failed to parse %s: value is empty or default",
            fieldName.c_str());
        return false;
    }
    // Convert the string to an integer using std::from_chars for robust parsing
    auto result = std::from_chars(valueStr.data(), valueStr.data() + valueStr.size(), outputValue);
    if (result.ec != std::errc()) {
        IMAGE_LOGE("Exif_metadata:ExtractXMageCoordinates Failed to parse %s: %s (error code: %{public}d)",
            fieldName.c_str(), valueStr.c_str(), static_cast<uint32_t>(result.ec));
        return false;
    }

    return true;
}

bool ExifMetadata::ExtractXmageCoordinates(XmageCoordinateMetadata& coordMetadata) const
{
    if (exifData_ == nullptr) {
        IMAGE_LOGE(
            "Exif_metadata:ExtractXMageCoordinates HDR-IMAGE Exif metadata is null, cannot read XMAGE coordinates");
        return false;
    }
    bool allParsedSuccessfully = ParseExifCoordinate("HwMnoteXmageLeft", coordMetadata.left) &&
        ParseExifCoordinate("HwMnoteXmageTop", coordMetadata.top) &&
        ParseExifCoordinate("HwMnoteXmageRight", coordMetadata.right) &&
        ParseExifCoordinate("HwMnoteXmageBottom", coordMetadata.bottom) &&
        ParseExifCoordinate("ImageWidth", coordMetadata.imageWidth) &&
        ParseExifCoordinate("ImageLength", coordMetadata.imageLength);
    if (allParsedSuccessfully) {
        IMAGE_LOGI(
            "Exif_metadata:ExtractXMageCoordinates Successfully extracted XMAGE coordinates: "
            "left=%{public}d, top=%{public}d, right=%{public}d, bottom=%{public}d",
            coordMetadata.left, coordMetadata.top, coordMetadata.right, coordMetadata.bottom);
        return true; // only return true if all fields were parsed successfully
    } else {
        IMAGE_LOGE(
            "Exif_metadata:ExtractXMageCoordinates Failed to extract valid XMAGE coordinates from EXIF data. "
            "Some fields are missing or invalid.");
        return false; // If any field is invalid, return false
    }
}

uint32_t ExifMetadata::GetBlobSize()
{
    CHECK_ERROR_RETURN_RET_LOG(exifData_ == nullptr, 0, "Exif data is null");
    unsigned int size = 0;
    unsigned char* data = nullptr;
    exif_data_save_data(exifData_, &data, &size);
    if (data != nullptr) {
        free(data);
    }
    return static_cast<uint32_t>(size);
}

uint32_t ExifMetadata::GetBlob(uint32_t bufferSize, uint8_t* dst)
{
    CHECK_ERROR_RETURN_RET_LOG(exifData_ == nullptr || dst == nullptr, ERR_IMAGE_INVALID_PARAMETER,
        "GetBlob failed: exifData_ is null or dst is null");
    unsigned char* exifBlob = nullptr;
    unsigned int exifSize = 0;
    exif_data_save_data(exifData_, &exifBlob, &exifSize);
    const uint32_t blobSize = static_cast<uint32_t>(exifSize);
    if (exifBlob == nullptr || blobSize == 0) {
        IMAGE_LOGW("GetBlob failed: empty EXIF data");
        if (exifBlob) {
            free(exifBlob);
        }
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    if (bufferSize < blobSize) {
        IMAGE_LOGE("Buffer too small for blob data (%u < %u)", bufferSize, blobSize);
        free(exifBlob);
        return ERR_MEDIA_BUFFER_TOO_SMALL;
    }
    errno_t copyResult = memcpy_s(dst, bufferSize, exifBlob, blobSize);
    free(exifBlob);
    CHECK_ERROR_RETURN_RET_LOG(copyResult != EOK, ERR_IMAGE_INVALID_PARAMETER,
        "Failed to copy blob data: %{public}d", copyResult);
    return SUCCESS;
}

uint32_t ExifMetadata::SetBlob(const uint8_t* source, uint32_t bufferSize)
{
    CHECK_ERROR_RETURN_RET_LOG(source == nullptr, ERR_IMAGE_INVALID_PARAMETER, "SetBlob failed: source is null");
    CHECK_ERROR_RETURN_RET_LOG(bufferSize == 0 || bufferSize > MAX_TAG_VALUE_SIZE_FOR_STR, ERR_IMAGE_INVALID_PARAMETER,
        "Invalid blob size: %{public}u (max: %{public}u)", bufferSize, MAX_TAG_VALUE_SIZE_FOR_STR);
    if (exifData_ != nullptr) {
        exif_data_unref(exifData_);
        exifData_ = nullptr;
    }
    IMAGE_LOGD("SetBlob: Input buffer size = %u bytes", bufferSize);
    exifData_ = exif_data_new();
    CHECK_ERROR_RETURN_RET_LOG(exifData_ == nullptr, ERR_MEDIA_MALLOC_FAILED,
        "Failed to create EXIF data structure");
    exif_data_unset_option(exifData_, EXIF_DATA_OPTION_FOLLOW_SPECIFICATION);
    exif_data_unset_option(exifData_, EXIF_DATA_OPTION_IGNORE_UNKNOWN_TAGS);
    exif_data_load_data(exifData_, source, bufferSize);
    return SUCCESS;
}

PropertyValueType ExifMetadata::GetPropertyValueType(const std::string& key)
{
    for (const auto& typeMapPair : GetPropertyTypeMapping()) {
        const auto& valueMap = typeMapPair.second;
        auto iter = valueMap.find(key);
        if (iter != valueMap.end()) {
            return iter->second;
        }
    }
    return PropertyValueType::UNKNOWN;
}

std::shared_ptr<ExifMetadata> ExifMetadata::InitExifMetadata()
{
    ExifData* exifData = exif_data_new();
    CHECK_ERROR_RETURN_RET(exifData == nullptr, nullptr);
    return std::make_shared<ExifMetadata>(exifData);
}
} // namespace Media
} // namespace OHOS
