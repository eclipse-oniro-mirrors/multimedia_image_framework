/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "dng/dng_sdk_info.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>

#include "dng_memory.h"
#include "image_log.h"
#include "image_utils.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
// undefined tag code in dng_sdk
static constexpr uint16_t TAG_CODE_OFFSET_TIME = 0x9010;
static constexpr uint16_t TAG_CODE_OFFSET_TIME_ORIGINAL = 0x9011;
static constexpr uint16_t TAG_CODE_OFFSET_TIME_DIGITIZED = 0x9012;
static constexpr uint16_t TAG_CODE_COMPOSITE_IMAGE = 0xA460;
static constexpr uint16_t TAG_CODE_SOURCE_IMAGE_NUMBER_OF_COMPOSITE_IMAGE = 0xA461;
static constexpr uint16_t TAG_CODE_SOURCE_EXPOSURE_TIMES_OF_COMPOSITE_IMAGE = 0xA462;

static constexpr uint32_t GPS_COORD_ELEMENTS = 3;
static constexpr uint32_t UNDEFINED_PREFIX_LEN = 8;
static constexpr uint32_t BYTE_MASK = 0xFF;
static constexpr uint32_t BYTE3_SHIFT = 24; // 3 * BITS_PER_BYTE
static constexpr uint32_t BYTE2_SHIFT = 16; // 2 * BITS_PER_BYTE
static constexpr uint32_t BYTE1_SHIFT = 8;  // 1 * BITS_PER_BYTE

std::map<std::string, std::tuple<uint16_t, uint32_t, DngSdkInfo::ExifGetType>> DngSdkInfo::exifPropertyMap_ = {
    {"ImageDescription", {tcImageDescription, 0, DngSdkInfo::GetExifImageDescription}},
    {"GPSVersionID", {tcGPSVersionID, tcGPSInfo, DngSdkInfo::GetExifGPSVersionID}},
    {"GPSLatitudeRef", {tcGPSLatitudeRef, tcGPSInfo, DngSdkInfo::GetExifGPSLatitudeRef}},
    {"GPSLatitude", {tcGPSLatitude, tcGPSInfo, DngSdkInfo::GetExifGPSLatitude}},
    {"GPSLongitudeRef", {tcGPSLongitudeRef, tcGPSInfo, DngSdkInfo::GetExifGPSLongitudeRef}},
    {"GPSLongitude", {tcGPSLongitude, tcGPSInfo, DngSdkInfo::GetExifGPSLongitude}},
    {"GPSAltitudeRef", {tcGPSAltitudeRef, tcGPSInfo, DngSdkInfo::GetExifGPSAltitudeRef}},
    {"GPSAltitude", {tcGPSAltitude, tcGPSInfo, DngSdkInfo::GetExifGPSAltitude}},
    {"GPSTimeStamp", {tcGPSTimeStamp, tcGPSInfo, DngSdkInfo::GetExifGPSTimeStamp}},
    {"GPSSatellites", {tcGPSSatellites, tcGPSInfo, DngSdkInfo::GetExifGPSSatellites}},
    {"GPSStatus", {tcGPSStatus, tcGPSInfo, DngSdkInfo::GetExifGPSStatus}},
    {"GPSMeasureMode", {tcGPSMeasureMode, tcGPSInfo, DngSdkInfo::GetExifGPSMeasureMode}},
    {"GPSDOP", {tcGPSDOP, tcGPSInfo, DngSdkInfo::GetExifGPSDOP}},
    {"GPSSpeedRef", {tcGPSSpeedRef, tcGPSInfo, DngSdkInfo::GetExifGPSSpeedRef}},
    {"GPSSpeed", {tcGPSSpeed, tcGPSInfo, DngSdkInfo::GetExifGPSSpeed}},
    {"GPSTrackRef", {tcGPSTrackRef, tcGPSInfo, DngSdkInfo::GetExifGPSTrackRef}},
    {"GPSTrack", {tcGPSTrack, tcGPSInfo, DngSdkInfo::GetExifGPSTrack}},
    {"GPSImgDirectionRef", {tcGPSImgDirectionRef, tcGPSInfo, DngSdkInfo::GetExifGPSImgDirectionRef}},
    {"GPSImgDirection", {tcGPSImgDirection, tcGPSInfo, DngSdkInfo::GetExifGPSImgDirection}},
    {"GPSMapDatum", {tcGPSMapDatum, tcGPSInfo, DngSdkInfo::GetExifGPSMapDatum}},
    {"GPSDestLatitudeRef", {tcGPSDestLatitudeRef, tcGPSInfo, DngSdkInfo::GetExifGPSDestLatitudeRef}},
    {"GPSDestLatitude", {tcGPSDestLatitude, tcGPSInfo, DngSdkInfo::GetExifGPSDestLatitude}},
    {"GPSDestLongitudeRef", {tcGPSDestLongitudeRef, tcGPSInfo, DngSdkInfo::GetExifGPSDestLongitudeRef}},
    {"GPSDestLongitude", {tcGPSDestLongitude, tcGPSInfo, DngSdkInfo::GetExifGPSDestLongitude}},
    {"GPSDestBearingRef", {tcGPSDestBearingRef, tcGPSInfo, DngSdkInfo::GetExifGPSDestBearingRef}},
    {"GPSDestBearing", {tcGPSDestBearing, tcGPSInfo, DngSdkInfo::GetExifGPSDestBearing}},
    {"GPSDestDistanceRef", {tcGPSDestDistanceRef, tcGPSInfo, DngSdkInfo::GetExifGPSDestDistanceRef}},
    {"GPSDestDistance", {tcGPSDestDistance, tcGPSInfo, DngSdkInfo::GetExifGPSDestDistance}},
    {"GPSProcessingMethod", {tcGPSProcessingMethod, tcGPSInfo, DngSdkInfo::GetExifGPSProcessingMethod}},
    {"GPSAreaInformation", {tcGPSAreaInformation, tcGPSInfo, DngSdkInfo::GetExifGPSAreaInformation}},
    {"GPSDateStamp", {tcGPSDateStamp, tcGPSInfo, DngSdkInfo::GetExifGPSDateStamp}},
    {"GPSDifferential", {tcGPSDifferential, tcGPSInfo, DngSdkInfo::GetExifGPSDifferential}},
    {"GPSHPositioningError", {tcGPSHPositioningError, tcGPSInfo, DngSdkInfo::GetExifGPSHPositioningError}},
    {"Make", {tcMake, 0, DngSdkInfo::GetExifMake}},
    {"Model", {tcModel, 0, DngSdkInfo::GetExifModel}},
    {"Software", {tcSoftware, 0, DngSdkInfo::GetExifSoftware}},
    {"DateTime", {tcDateTime, 0, DngSdkInfo::GetExifDateTime}},
    {"Artist", {tcArtist, 0, DngSdkInfo::GetExifArtist}},
    {"Copyright", {tcCopyright, 0, DngSdkInfo::GetExifCopyright}},
    {"FNumber", {tcFNumber, tcExifIFD, DngSdkInfo::GetExifFNumber}},
    {"ExposureProgram", {tcExposureProgram, tcExifIFD, DngSdkInfo::GetExifExposureProgram}},
    {"ISOSpeedRatings", {tcISOSpeedRatings, tcExifIFD, DngSdkInfo::GetExifISOSpeedRatings}},
    {"SensitivityType", {tcSensitivityType, tcExifIFD, DngSdkInfo::GetExifSensitivityType}},
    {"StandardOutputSensitivity", {tcStandardOutputSensitivity, tcExifIFD,
        DngSdkInfo::GetExifStandardOutputSensitivity}},
    {"RecommendedExposureIndex", {tcRecommendedExposureIndex, tcExifIFD, DngSdkInfo::GetExifRecommendedExposureIndex}},
    {"ISOSpeedLatitudeyyy", {tcISOSpeedLatitudeyyy, tcExifIFD, DngSdkInfo::GetExifISOSpeedLatitudeyyy}},
    {"ISOSpeedLatitudezzz", {tcISOSpeedLatitudezzz, tcExifIFD, DngSdkInfo::GetExifISOSpeedLatitudezzz}},
    {"ExifVersion", {tcExifVersion, tcExifIFD, DngSdkInfo::GetExifExifVersion}},
    {"DateTimeOriginal", {tcDateTimeOriginal, tcExifIFD, DngSdkInfo::GetExifDateTimeOriginal}},
    {"DateTimeDigitized", {tcDateTimeDigitized, tcExifIFD, DngSdkInfo::GetExifDateTimeDigitized}},
    {"ComponentsConfiguration", {tcComponentsConfiguration, tcExifIFD, DngSdkInfo::GetExifComponentsConfiguration}},
    {"CompressedBitsPerPixel", {tcCompressedBitsPerPixel, tcExifIFD, DngSdkInfo::GetExifCompressedBitsPerPixel}},
    {"BrightnessValue", {tcBrightnessValue, tcExifIFD, DngSdkInfo::GetExifBrightnessValue}},
    {"ExposureBiasValue", {tcExposureBiasValue, tcExifIFD, DngSdkInfo::GetExifExposureBiasValue}},
    {"MeteringMode", {tcMeteringMode, tcExifIFD, DngSdkInfo::GetExifMeteringMode}},
    {"LightSource", {tcLightSource, tcExifIFD, DngSdkInfo::GetExifLightSource}},
    {"Flash", {tcFlash, tcExifIFD, DngSdkInfo::GetExifFlash}},
    {"FocalLength", {tcFocalLength, tcExifIFD, DngSdkInfo::GetExifFocalLength}},
    {"UserComment", {tcUserComment, tcExifIFD, DngSdkInfo::GetExifUserComment}},
    {"SubsecTimeOriginal", {tcSubsecTimeOriginal, tcExifIFD, DngSdkInfo::GetExifSubsecTimeOriginal}},
    {"SubsecTimeDigitized", {tcSubsecTimeDigitized, tcExifIFD, DngSdkInfo::GetExifSubsecTimeDigitized}},
    {"FlashpixVersion", {tcFlashPixVersion, tcExifIFD, DngSdkInfo::GetExifFlashPixVersion}},
    {"ColorSpace", {tcColorSpace, tcExifIFD, DngSdkInfo::GetExifColorSpace}},
    {"PixelXDimension", {tcPixelXDimension, tcExifIFD, DngSdkInfo::GetExifPixelXDimension}},
    {"PixelYDimension", {tcPixelYDimension, tcExifIFD, DngSdkInfo::GetExifPixelYDimension}},
    {"FocalPlaneXResolution", {tcFocalPlaneXResolutionExif, tcExifIFD, DngSdkInfo::GetExifFocalPlaneXResolution}},
    {"FocalPlaneYResolution", {tcFocalPlaneYResolutionExif, tcExifIFD, DngSdkInfo::GetExifFocalPlaneYResolution}},
    {"FocalPlaneResolutionUnit", {tcFocalPlaneResolutionUnitExif, tcExifIFD,
        DngSdkInfo::GetExifFocalPlaneResolutionUnit}},
    {"ExposureIndex", {tcExposureIndexExif, tcExifIFD, DngSdkInfo::GetExifExposureIndex}},
    {"SensingMethod", {tcSensingMethodExif, tcExifIFD, DngSdkInfo::GetExifSensingMethod}},
    {"FileSource", {tcFileSource, tcExifIFD, DngSdkInfo::GetExifFileSource}},
    {"SceneType", {tcSceneType, tcExifIFD, DngSdkInfo::GetExifSceneType}},
    {"CustomRendered", {tcCustomRendered, tcExifIFD, DngSdkInfo::GetExifCustomRendered}},
    {"ExposureMode", {tcExposureMode, tcExifIFD, DngSdkInfo::GetExifExposureMode}},
    {"WhiteBalance", {tcWhiteBalance, tcExifIFD, DngSdkInfo::GetExifWhiteBalance}},
    {"DigitalZoomRatio", {tcDigitalZoomRatio, tcExifIFD, DngSdkInfo::GetExifDigitalZoomRatio}},
    {"FocalLengthIn35mmFilm", {tcFocalLengthIn35mmFilm, tcExifIFD, DngSdkInfo::GetExifFocalLengthIn35mmFilm}},
    {"SceneCaptureType", {tcSceneCaptureType, tcExifIFD, DngSdkInfo::GetExifSceneCaptureType}},
    {"GainControl", {tcGainControl, tcExifIFD, DngSdkInfo::GetExifGainControl}},
    {"Contrast", {tcContrast, tcExifIFD, DngSdkInfo::GetExifContrast}},
    {"Saturation", {tcSaturation, tcExifIFD, DngSdkInfo::GetExifSaturation}},
    {"Sharpness", {tcSharpness, tcExifIFD, DngSdkInfo::GetExifSharpness}},
    {"SubjectDistanceRange", {tcSubjectDistanceRange, tcExifIFD, DngSdkInfo::GetExifSubjectDistanceRange}},
    {"ImageUniqueID", {tcImageUniqueID, tcExifIFD, DngSdkInfo::GetExifImageUniqueID}},
    {"CameraOwnerName", {tcCameraOwnerNameExif, tcExifIFD, DngSdkInfo::GetExifCameraOwnerName}},
    {"BodySerialNumber", {tcCameraSerialNumberExif, tcExifIFD, DngSdkInfo::GetExifCameraSerialNumber}},
    {"LensSpecification", {tcLensSpecificationExif, tcExifIFD, DngSdkInfo::GetExifLensSpecification}},
    {"LensMake", {tcLensMakeExif, tcExifIFD, DngSdkInfo::GetExifLensMake}},
    {"LensModel", {tcLensModelExif, tcExifIFD, DngSdkInfo::GetExifLensModel}},
    {"LensSerialNumber", {tcLensSerialNumberExif, tcExifIFD, DngSdkInfo::GetExifLensSerialNumber}},
    {"Gamma", {tcGamma, tcExifIFD, DngSdkInfo::GetExifGamma}},
};

std::map<std::string, std::tuple<uint16_t, uint32_t, DngSdkInfo::SharedGetType>> DngSdkInfo::sharedPropertyMap_ = {
    {"DNGVersion", {tcDNGVersion, 0, DngSdkInfo::GetSharedDNGVersion}},
};

std::map<std::string, std::tuple<uint16_t, uint32_t, DngSdkInfo::IfdGetType>> DngSdkInfo::ifdPropertyMap_ = {
    {"NewSubfileType", {tcNewSubFileType, 0, DngSdkInfo::GetIfdNewSubfileType}},
    {"ImageWidth", {tcImageWidth, 0, DngSdkInfo::GetIfdImageWidth}},
    {"ImageLength", {tcImageLength, 0, DngSdkInfo::GetIfdImageLength}},
    {"Compression", {tcCompression, 0, DngSdkInfo::GetIfdCompression}},
    {"PhotometricInterpretation", {tcPhotometricInterpretation, 0, DngSdkInfo::GetIfdPhotometricInterpretation}},
    {"Orientation", {tcOrientation, 0, DngSdkInfo::GetIfdOrientation}},
    {"SamplesPerPixel", {tcSamplesPerPixel, 0, DngSdkInfo::GetIfdSamplesPerPixel}},
    {"RowsPerStrip", {tcRowsPerStrip, 0, DngSdkInfo::GetIfdRowsPerStrip}},
    {"XResolution", {tcXResolution, 0, DngSdkInfo::GetIfdXResolution}},
    {"YResolution", {tcYResolution, 0, DngSdkInfo::GetIfdYResolution}},
    {"PlanarConfiguration", {tcPlanarConfiguration, 0, DngSdkInfo::GetIfdPlanarConfiguration}},
    {"ResolutionUnit", {tcResolutionUnit, 0, DngSdkInfo::GetIfdResolutionUnit}},
    {"YCbCrCoefficients", {tcYCbCrCoefficients, 0, DngSdkInfo::GetIfdYCbCrCoefficients}},
    {"YCbCrSubSampling", {tcYCbCrSubSampling, 0, DngSdkInfo::GetIfdYCbCrSubSampling}},
    {"YCbCrPositioning", {tcYCbCrPositioning, 0, DngSdkInfo::GetIfdYCbCrPositioning}},
    {"ReferenceBlackWhite", {tcReferenceBlackWhite, 0, DngSdkInfo::GetIfdReferenceBlackWhite}},
    {"DefaultCropSize", {tcDefaultCropSize, 0, DngSdkInfo::GetIfdDefaultCropSize}},
    {"JPEGInterchangeFormat", {tcJPEGInterchangeFormat, 0, DngSdkInfo::GetIfdJPEGInterchangeFormat}},
    {"JPEGInterchangeFormatLength", {tcJPEGInterchangeFormatLength, 0, DngSdkInfo::GetIfdJPEGInterchangeFormatLength}},
};

std::map<std::string, uint16_t> DngSdkInfo::specialTagNameMap_ = {
    {"SubfileType", tcSubFileType},
    {"TransferFunction", tcTransferFunction},
    {"WhitePoint", tcWhitePoint},
    {"PrimaryChromaticities", tcPrimaryChromaticities},
    {"PhotoMode", tcJPEGProc},
    {"OECF", tcOECF},
    {"RelatedSoundFile", tcRelatedSoundFile},
    {"FlashEnergy", tcFlashEnergyExif},
    {"SpatialFrequencyResponse", tcSpatialFrequencyResponseExif},
    {"DeviceSettingDescription", tcDeviceSettingDescription},
    {"SpectralSensitivity", tcSpectralSensitivity},
    {"MakerNote", tcMakerNote},
    {"SubsecTime", tcSubsecTime},
    {"ShutterSpeedValue", tcShutterSpeedValue},
    {"ApertureValue", tcApertureValue},
    {"SubjectArea", tcSubjectArea},
    {"SubjectLocation", tcSubjectLocation},
    {"MaxApertureValue", tcMaxApertureValue},
    {"SubjectDistance", tcSubjectDistance},
    {"CFAPattern", tcCFAPatternExif},
    {"ExposureTime", tcExposureTime},
    {"StripOffsets", tcStripOffsets},
    {"PhotographicSensitivity", tcISOSpeedRatings},
    {"BitsPerSample", tcBitsPerSample},
    {"StripByteCounts", tcStripByteCounts},
    {"OffsetTime", TAG_CODE_OFFSET_TIME},
    {"OffsetTimeOriginal", TAG_CODE_OFFSET_TIME_ORIGINAL},
    {"OffsetTimeDigitized", TAG_CODE_OFFSET_TIME_DIGITIZED},
    {"CompositeImage", TAG_CODE_COMPOSITE_IMAGE},
    {"SourceImageNumberOfCompositeImage", TAG_CODE_SOURCE_IMAGE_NUMBER_OF_COMPOSITE_IMAGE},
    {"SourceExposureTimesOfCompositeImage", TAG_CODE_SOURCE_EXPOSURE_TIMES_OF_COMPOSITE_IMAGE},
};

std::map<uint16_t, DngSdkInfo::ParseTagType> DngSdkInfo::specialTagParseMap_ = {
    {tcSubFileType, DngSdkInfo::ParseIntTag},
    {tcTransferFunction, DngSdkInfo::ParseShortTagToString},
    {tcWhitePoint, DngSdkInfo::ParseRationalTag},
    {tcPrimaryChromaticities, DngSdkInfo::ParseRationalTag},
    {tcJPEGProc, DngSdkInfo::ParseIntTag},
    {tcOECF, DngSdkInfo::ParseUndefinedTag},
    {tcRelatedSoundFile, DngSdkInfo::ParseAsciiTag},
    {tcFlashEnergyExif, DngSdkInfo::ParseDoubleTag},
    {tcSpatialFrequencyResponseExif, DngSdkInfo::ParseUndefinedTag},
    {tcDeviceSettingDescription, DngSdkInfo::ParseUndefinedTag},
    {tcMakerNote, DngSdkInfo::ParseUndefinedTag},
    {tcSpectralSensitivity, DngSdkInfo::ParseAsciiTag},
    {tcSubsecTime, DngSdkInfo::ParseAsciiTag},
    {tcShutterSpeedValue, DngSdkInfo::ParseDoubleTag},
    {tcApertureValue, DngSdkInfo::ParseDoubleTag},
    {tcSubjectArea, DngSdkInfo::ParseIntArrayTag},
    {tcSubjectLocation, DngSdkInfo::ParseIntArrayTag},
    {tcMaxApertureValue, DngSdkInfo::ParseDoubleTag},
    {tcSubjectDistance, DngSdkInfo::ParseDoubleTag},
    {tcCFAPatternExif, DngSdkInfo::ParseUndefinedTag},
    {tcExposureTime, DngSdkInfo::ParseDoubleTag},
    {tcStripOffsets, DngSdkInfo::ParseIntArrayTag},
    {tcISOSpeedRatings, DngSdkInfo::ParseIntArrayTag},
    {tcBitsPerSample, DngSdkInfo::ParseIntArrayTag},
    {tcStripByteCounts, DngSdkInfo::ParseIntArrayTag},
    {TAG_CODE_OFFSET_TIME, DngSdkInfo::ParseAsciiTag},
    {TAG_CODE_OFFSET_TIME_ORIGINAL, DngSdkInfo::ParseAsciiTag},
    {TAG_CODE_OFFSET_TIME_DIGITIZED, DngSdkInfo::ParseAsciiTag},
    {TAG_CODE_COMPOSITE_IMAGE, DngSdkInfo::ParseIntTag},
    {TAG_CODE_SOURCE_IMAGE_NUMBER_OF_COMPOSITE_IMAGE, DngSdkInfo::ParseIntArrayTag},
    {TAG_CODE_SOURCE_EXPOSURE_TIMES_OF_COMPOSITE_IMAGE, DngSdkInfo::ParseUndefinedTag},
};

static uint32_t GetDngUint32(uint32 in, MetadataValue& out)
{
    out.type = PropertyValueType::INT;
    out.intArrayValue.push_back(static_cast<int64_t>(in));
    return SUCCESS;
}

static std::string FormatUndefinedExifString(const dng_string& input)
{
    dng_memory_data buffer;
    constexpr uint32_t maxTagValueSizeForStr = 64 * 1024;
    constexpr const char* undefinedPrefixAscii = "ASCII\0\0\0";
    constexpr const char* undefinedPrefixUnicode = "UNICODE\0";
    constexpr const char* undefinedPrefixJis = "JIS\0\0\0\0\0";
    uint32_t length = input.Get_SystemEncoding(buffer);
    if (length == 0) {
        return "";
    }
    const uint8_t* raw = buffer.Buffer_uint8();
    if (raw == nullptr) {
        return "";
    }

    uint32_t maxlen = length + 1 > maxTagValueSizeForStr ? maxTagValueSizeForStr : length + 1;
    if (length >= UNDEFINED_PREFIX_LEN) {
        if (std::memcmp(raw, undefinedPrefixAscii, UNDEFINED_PREFIX_LEN) == 0) {
            const char* asciiData = reinterpret_cast<const char*>(raw + UNDEFINED_PREFIX_LEN);
            size_t dataLen = std::min(length - UNDEFINED_PREFIX_LEN, maxlen - 1);
            const char* nullPos = static_cast<const char*>(std::memchr(asciiData, '\0', dataLen));
            return std::string(asciiData, nullPos != nullptr ? nullPos - asciiData : dataLen);
        }
        if (std::memcmp(raw, undefinedPrefixUnicode, UNDEFINED_PREFIX_LEN) == 0) {
            return "Unsupported UNICODE string";
        }
        if (std::memcmp(raw, undefinedPrefixJis, UNDEFINED_PREFIX_LEN) == 0) {
            return "Unsupported JIS string";
        }
    }

    // Check if there is really some information in the tag
    const char* data = reinterpret_cast<const char*>(raw);
    size_t i = 0;
    for (; i < length && (data[i] == '\0' || data[i] == ' '); i++) {
        if (i == length) {
            return "";
        }
    }
    // If we reach this point, the tag does not comply with the standard but seems to contain data.
    // Print as much as possible, replacing non-printable characters with '.'
    std::string result;
    for (size_t j = 0; (i < length) && (j < maxlen - 1); i++, j++) {
        result.push_back(std::isprint(static_cast<unsigned char>(data[i])) ? data[i] : '.');
    }
    return result;
}

static uint32_t GetDngString(const dng_string& in, MetadataValue& out)
{
    out.type = PropertyValueType::STRING;
    out.stringValue = std::string(in.Get());
    return SUCCESS;
}

static uint32_t GetDngURational(const dng_urational& in, MetadataValue& out)
{
    out.type = PropertyValueType::DOUBLE;
    out.doubleArrayValue.clear();
    out.doubleArrayValue.push_back(in.As_real64());
    return SUCCESS;
}

static uint32_t GetDngSRational(const dng_srational& in, MetadataValue& out)
{
    out.type = PropertyValueType::DOUBLE;
    out.doubleArrayValue.clear();
    out.doubleArrayValue.push_back(in.As_real64());
    return SUCCESS;
}

static uint32_t GetDngReal64(real64 in, MetadataValue& out)
{
    out.type = PropertyValueType::DOUBLE;
    out.doubleArrayValue.clear();
    out.doubleArrayValue.reserve(1);
    out.doubleArrayValue.push_back(static_cast<double>(in));
    return SUCCESS;
}

static uint32_t GetDngReal64Array(const real64* in, uint32_t count, MetadataValue& out)
{
    out.type = PropertyValueType::DOUBLE_ARRAY;
    out.doubleArrayValue.clear();
    if (in == nullptr || count == 0) {
        return SUCCESS;
    }
    out.doubleArrayValue.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        out.doubleArrayValue.push_back(static_cast<double>(in[i]));
    }
    return SUCCESS;
}

static uint32_t GetDngURationalArray(const dng_urational* in, uint32_t count, MetadataValue& out)
{
    out.type = PropertyValueType::DOUBLE_ARRAY;
    out.doubleArrayValue.clear();
    if (count == 0 || in == nullptr) {
        return SUCCESS;
    }
    out.doubleArrayValue.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        out.doubleArrayValue.push_back(in[i].As_real64());
    }
    return SUCCESS;
}

static uint32_t GetDngDateTime(const dng_date_time& in, MetadataValue& out)
{
    out.type = PropertyValueType::STRING;
    constexpr uint32_t yearWidth = 4;
    constexpr uint32_t dateTimeFieldWidth = 2;
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(yearWidth) << in.fYear << ":"
        << std::setw(dateTimeFieldWidth) << in.fMonth << ":" << std::setw(dateTimeFieldWidth) << in.fDay << " "
        << std::setw(dateTimeFieldWidth) << in.fHour << ":" << std::setw(dateTimeFieldWidth) << in.fMinute << ":"
        << std::setw(dateTimeFieldWidth) << in.fSecond;
    out.stringValue = oss.str();
    return SUCCESS;
}

static uint32_t GetDngFingerprint(const dng_fingerprint& in, MetadataValue& out)
{
    constexpr uint32_t hexCharsPerByte = 2;
    out.type = PropertyValueType::STRING;
    if (!in.IsValid()) {
        IMAGE_LOGD("%{public}s, dng_fingerprint is invalid", __func__);
        out.stringValue = "";
        return SUCCESS;
    }

    char hexString[hexCharsPerByte * dng_fingerprint::kDNGFingerprintSize + 1];
    in.ToUtf8HexString(hexString);
    out.stringValue = std::string(hexString);
    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifImageDescription(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fImageDescription, value);
}

uint32_t DngSdkInfo::GetExifGPSVersionID(const dng_exif& fExif, MetadataValue& value)
{
    value.type = PropertyValueType::INT_ARRAY;
    constexpr uint32_t intArrayReserveSize = 4;
    value.intArrayValue.clear();
    value.intArrayValue.reserve(intArrayReserveSize);
    uint32_t versionID = fExif.fGPSVersionID;

    value.intArrayValue.push_back((versionID >> BYTE3_SHIFT) & BYTE_MASK);
    value.intArrayValue.push_back((versionID >> BYTE2_SHIFT) & BYTE_MASK);
    value.intArrayValue.push_back((versionID >> BYTE1_SHIFT) & BYTE_MASK);
    value.intArrayValue.push_back(versionID & BYTE_MASK);
    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifGPSLatitudeRef(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSLatitudeRef, value);
}

uint32_t DngSdkInfo::GetExifGPSLatitude(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURationalArray(fExif.fGPSLatitude, GPS_COORD_ELEMENTS, value);
}

uint32_t DngSdkInfo::GetExifGPSLongitudeRef(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSLongitudeRef, value);
}

uint32_t DngSdkInfo::GetExifGPSLongitude(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURationalArray(fExif.fGPSLongitude, GPS_COORD_ELEMENTS, value);
}

uint32_t DngSdkInfo::GetExifGPSAltitudeRef(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fGPSAltitudeRef, value);
}

uint32_t DngSdkInfo::GetExifGPSAltitude(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fGPSAltitude, value);
}

uint32_t DngSdkInfo::GetExifGPSTimeStamp(const dng_exif& fExif, MetadataValue& value)
{
    constexpr uint32_t gpsTimeStampElements = 3;
    return GetDngURationalArray(fExif.fGPSTimeStamp, gpsTimeStampElements, value);
}

uint32_t DngSdkInfo::GetExifGPSSatellites(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSSatellites, value);
}

uint32_t DngSdkInfo::GetExifGPSStatus(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSStatus, value);
}

uint32_t DngSdkInfo::GetExifGPSMeasureMode(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSMeasureMode, value);
}

uint32_t DngSdkInfo::GetExifGPSDOP(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fGPSDOP, value);
}

uint32_t DngSdkInfo::GetExifGPSSpeedRef(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSSpeedRef, value);
}

uint32_t DngSdkInfo::GetExifGPSSpeed(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fGPSSpeed, value);
}

uint32_t DngSdkInfo::GetExifGPSTrackRef(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSTrackRef, value);
}

uint32_t DngSdkInfo::GetExifGPSTrack(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fGPSTrack, value);
}

uint32_t DngSdkInfo::GetExifGPSImgDirectionRef(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSImgDirectionRef, value);
}

uint32_t DngSdkInfo::GetExifGPSImgDirection(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fGPSImgDirection, value);
}

uint32_t DngSdkInfo::GetExifGPSMapDatum(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSMapDatum, value);
}

uint32_t DngSdkInfo::GetExifGPSDestLatitudeRef(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSDestLatitudeRef, value);
}

uint32_t DngSdkInfo::GetExifGPSDestLatitude(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURationalArray(fExif.fGPSDestLatitude, GPS_COORD_ELEMENTS, value);
}

uint32_t DngSdkInfo::GetExifGPSDestLongitudeRef(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSDestLongitudeRef, value);
}

uint32_t DngSdkInfo::GetExifGPSDestLongitude(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURationalArray(fExif.fGPSDestLongitude, GPS_COORD_ELEMENTS, value);
}

uint32_t DngSdkInfo::GetExifGPSDestBearingRef(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSDestBearingRef, value);
}

uint32_t DngSdkInfo::GetExifGPSDestBearing(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fGPSDestBearing, value);
}

uint32_t DngSdkInfo::GetExifGPSDestDistanceRef(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSDestDistanceRef, value);
}

uint32_t DngSdkInfo::GetExifGPSDestDistance(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fGPSDestDistance, value);
}

uint32_t DngSdkInfo::GetExifGPSProcessingMethod(const dng_exif& fExif, MetadataValue& value)
{
    value.type = PropertyValueType::STRING;
    value.stringValue = FormatUndefinedExifString(fExif.fGPSProcessingMethod);
    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifGPSAreaInformation(const dng_exif& fExif, MetadataValue& value)
{
    value.type = PropertyValueType::STRING;
    value.stringValue = FormatUndefinedExifString(fExif.fGPSAreaInformation);
    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifGPSDateStamp(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fGPSDateStamp, value);
}

uint32_t DngSdkInfo::GetExifGPSDifferential(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fGPSDifferential, value);
}

uint32_t DngSdkInfo::GetExifGPSHPositioningError(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fGPSHPositioningError, value);
}

uint32_t DngSdkInfo::GetExifMake(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fMake, value);
}

uint32_t DngSdkInfo::GetExifModel(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fModel, value);
}

uint32_t DngSdkInfo::GetExifSoftware(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fSoftware, value);
}

uint32_t DngSdkInfo::GetExifDateTime(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngDateTime(fExif.fDateTime.DateTime(), value);
}

uint32_t DngSdkInfo::GetExifArtist(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fArtist, value);
}

static bool HasVisibleCharacter(std::string_view text)
{
    for (char c : text) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            return true;
        }
    }
    return false;
}

static std::string NormalizeCopyrightField(const dng_string& input)
{
    const char* raw = input.Get();
    if (raw == nullptr || !HasVisibleCharacter(raw)) {
        return "";
    }
    return std::string(raw);
}

uint32_t DngSdkInfo::GetExifCopyright(const dng_exif& fExif, MetadataValue& value)
{
    value.type = PropertyValueType::STRING;
    const std::string photographer = NormalizeCopyrightField(fExif.fCopyright);
    const std::string editor = NormalizeCopyrightField(fExif.fCopyright2);

    constexpr const char* NONE_PLACEHOLDER = "[None]";
    constexpr const char* PHOTOGRAPHER_SUFFIX = " (Photographer)";
    constexpr const char* EDITOR_SUFFIX = " (Editor)";
    constexpr const char* SEPARATOR = " - ";
    constexpr uint32_t copyrightReservePadding = 32;

    const std::string photographerText = photographer.empty() ? std::string(NONE_PLACEHOLDER) : photographer;
    const std::string editorText = editor.empty() ? std::string(NONE_PLACEHOLDER) : editor;

    value.stringValue.reserve(photographerText.size() + editorText.size() + copyrightReservePadding);
    value.stringValue.append(photographerText);
    value.stringValue.append(PHOTOGRAPHER_SUFFIX);
    value.stringValue.append(SEPARATOR);
    value.stringValue.append(editorText);
    value.stringValue.append(EDITOR_SUFFIX);
    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifFNumber(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fFNumber, value);
}

uint32_t DngSdkInfo::GetExifExposureProgram(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fExposureProgram, value);
}

uint32_t DngSdkInfo::GetExifISOSpeedRatings(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fISOSpeedRatings[0], value);
}

uint32_t DngSdkInfo::GetExifExifVersion(const dng_exif& fExif, MetadataValue& value)
{
    value.type = PropertyValueType::STRING;
    value.stringValue = "Unknown Exif Version";
    constexpr size_t exifVersionSize = 4;

    std::vector<uint8_t> versionBytes(exifVersionSize);
    uint32_t offset = 0;
    ImageUtils::Uint32ToBytes(fExif.fExifVersion, versionBytes, offset, true);

    std::string_view versionView(reinterpret_cast<const char*>(versionBytes.data()), versionBytes.size());

    static const std::map<std::string, std::string> exifVersionMap = {
        {"0110", "Exif Version 1.1"},
        {"0120", "Exif Version 1.2"},
        {"0200", "Exif Version 2.0"},
        {"0210", "Exif Version 2.1"},
        {"0220", "Exif Version 2.2"},
        {"0221", "Exif Version 2.21"},
        {"0230", "Exif Version 2.3"},
        {"0231", "Exif Version 2.31"},
        {"0232", "Exif Version 2.32"},
    };

    std::string versionStr(versionView);
    auto it = exifVersionMap.find(versionStr);
    if (it != exifVersionMap.end()) {
        value.stringValue = it->second;
    }

    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifSensitivityType(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fSensitivityType, value);
}

uint32_t DngSdkInfo::GetExifStandardOutputSensitivity(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fStandardOutputSensitivity, value);
}

uint32_t DngSdkInfo::GetExifRecommendedExposureIndex(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fRecommendedExposureIndex, value);
}

uint32_t DngSdkInfo::GetExifISOSpeedLatitudeyyy(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fISOSpeedLatitudeyyy, value);
}

uint32_t DngSdkInfo::GetExifISOSpeedLatitudezzz(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fISOSpeedLatitudezzz, value);
}

uint32_t DngSdkInfo::GetExifDateTimeOriginal(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngDateTime(fExif.fDateTimeOriginal.DateTime(), value);
}

uint32_t DngSdkInfo::GetExifDateTimeDigitized(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngDateTime(fExif.fDateTimeDigitized.DateTime(), value);
}

uint32_t DngSdkInfo::GetExifComponentsConfiguration(const dng_exif& fExif, MetadataValue& value)
{
    static constexpr const char* COMPONENT_LABELS[] = {
        "-", "Y", "Cb", "Cr", "R", "G", "B"
    };
    constexpr uint32_t bitsPerByte = 8;
    constexpr uint32_t componentConfigCount = 4;
    constexpr uint32_t componentConfigLastIndex = 3;
    constexpr uint32_t componentLabelMaxIndex = 6;
    constexpr uint32_t componentStringReserveSize = 35;

    value.type = PropertyValueType::STRING;
    value.stringValue.clear();
    value.stringValue.reserve(componentStringReserveSize);

    const uint32_t config = fExif.fComponentsConfiguration;
    for (int i = 0; i < componentConfigCount; i++) {
        const uint8_t component = static_cast<uint8_t>(
            (config >> ((componentConfigCount - 1 - i) * bitsPerByte)) & BYTE_MASK);
        const char* label = "Reserved";
        if (component <= componentLabelMaxIndex) {
            label = COMPONENT_LABELS[component];
        }
        if (i < componentConfigLastIndex) {
            value.stringValue.push_back(' ');
        }
        value.stringValue.append(label);
    }
    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifCompressedBitsPerPixel(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fCompresssedBitsPerPixel, value);
}

uint32_t DngSdkInfo::GetExifBrightnessValue(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngSRational(fExif.fBrightnessValue, value);
}

uint32_t DngSdkInfo::GetExifExposureBiasValue(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngSRational(fExif.fExposureBiasValue, value);
}

uint32_t DngSdkInfo::GetExifMeteringMode(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fMeteringMode, value);
}

uint32_t DngSdkInfo::GetExifLightSource(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fLightSource, value);
}

uint32_t DngSdkInfo::GetExifFlash(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fFlash, value);
}

uint32_t DngSdkInfo::GetExifFocalLength(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fFocalLength, value);
}

uint32_t DngSdkInfo::GetExifUserComment(const dng_exif& fExif, MetadataValue& value)
{
    value.type = PropertyValueType::STRING;
    value.stringValue = FormatUndefinedExifString(fExif.fUserComment);
    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifSubsecTimeOriginal(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fDateTimeOriginal.Subseconds(), value);
}

uint32_t DngSdkInfo::GetExifSubsecTimeDigitized(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fDateTimeDigitized.Subseconds(), value);
}

uint32_t DngSdkInfo::GetExifFlashPixVersion(const dng_exif& fExif, MetadataValue& value)
{
    value.type = PropertyValueType::STRING;
    value.stringValue = "Unknown FlashPix Version";
    constexpr size_t flashVersionSize = 4;
    std::vector<uint8_t> versionBytes(flashVersionSize);
    uint32_t offset = 0;
    ImageUtils::Uint32ToBytes(fExif.fFlashPixVersion, versionBytes, offset, true);

    std::string_view versionView(reinterpret_cast<const char*>(versionBytes.data()), versionBytes.size());

    static const std::map<std::string, std::string> flashPixVersionMap = {
        {"0100", "FlashPix Version 1.0"},
        {"0101", "FlashPix Version 1.01"},
    };

    std::string versionStr(versionView);
    auto it = flashPixVersionMap.find(versionStr);
    if (it != flashPixVersionMap.end()) {
        value.stringValue = it->second;
    }

    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifColorSpace(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fColorSpace, value);
}

uint32_t DngSdkInfo::GetExifPixelXDimension(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fPixelXDimension, value);
}

uint32_t DngSdkInfo::GetExifPixelYDimension(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fPixelYDimension, value);
}

uint32_t DngSdkInfo::GetExifFocalPlaneXResolution(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fFocalPlaneXResolution, value);
}

uint32_t DngSdkInfo::GetExifFocalPlaneYResolution(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fFocalPlaneYResolution, value);
}

uint32_t DngSdkInfo::GetExifFocalPlaneResolutionUnit(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fFocalPlaneResolutionUnit, value);
}

uint32_t DngSdkInfo::GetExifExposureIndex(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fExposureIndex, value);
}

uint32_t DngSdkInfo::GetExifSensingMethod(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fSensingMethod, value);
}

uint32_t DngSdkInfo::GetExifFileSource(const dng_exif& fExif, MetadataValue& value)
{
    value.type = PropertyValueType::BLOB;
    value.bufferValue.clear();
    value.bufferValue.push_back(static_cast<uint8_t>(fExif.fFileSource));
    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifSceneType(const dng_exif& fExif, MetadataValue& value)
{
    value.type = PropertyValueType::BLOB;
    value.bufferValue.clear();
    value.bufferValue.push_back(static_cast<uint8_t>(fExif.fSceneType));
    return SUCCESS;
}

uint32_t DngSdkInfo::GetExifCustomRendered(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fCustomRendered, value);
}

uint32_t DngSdkInfo::GetExifExposureMode(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fExposureMode, value);
}

uint32_t DngSdkInfo::GetExifWhiteBalance(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fWhiteBalance, value);
}

uint32_t DngSdkInfo::GetExifDigitalZoomRatio(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fDigitalZoomRatio, value);
}

uint32_t DngSdkInfo::GetExifFocalLengthIn35mmFilm(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fFocalLengthIn35mmFilm, value);
}

uint32_t DngSdkInfo::GetExifSceneCaptureType(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fSceneCaptureType, value);
}

uint32_t DngSdkInfo::GetExifGainControl(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fGainControl, value);
}

uint32_t DngSdkInfo::GetExifContrast(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fContrast, value);
}

uint32_t DngSdkInfo::GetExifSaturation(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fSaturation, value);
}

uint32_t DngSdkInfo::GetExifSharpness(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fSharpness, value);
}

uint32_t DngSdkInfo::GetExifSubjectDistanceRange(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngUint32(fExif.fSubjectDistanceRange, value);
}

uint32_t DngSdkInfo::GetExifImageUniqueID(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngFingerprint(fExif.fImageUniqueID, value);
}

uint32_t DngSdkInfo::GetExifCameraOwnerName(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fOwnerName, value);
}

uint32_t DngSdkInfo::GetExifCameraSerialNumber(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fCameraSerialNumber, value);
}

uint32_t DngSdkInfo::GetExifLensSpecification(const dng_exif& fExif, MetadataValue& value)
{
    constexpr uint32_t lensInfoElements = 4;
    return GetDngURationalArray(fExif.fLensInfo, lensInfoElements, value);
}

uint32_t DngSdkInfo::GetExifLensMake(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fLensMake, value);
}

uint32_t DngSdkInfo::GetExifLensModel(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fLensName, value);
}

uint32_t DngSdkInfo::GetExifLensSerialNumber(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngString(fExif.fLensSerialNumber, value);
}

uint32_t DngSdkInfo::GetExifGamma(const dng_exif& fExif, MetadataValue& value)
{
    return GetDngURational(fExif.fGamma, value);
}

uint32_t DngSdkInfo::GetSharedDNGVersion(const dng_shared& fShared, MetadataValue& value)
{
    value.type = PropertyValueType::INT_ARRAY;
    value.intArrayValue.clear();
    value.intArrayValue.push_back((fShared.fDNGVersion >> BYTE3_SHIFT) & BYTE_MASK);
    value.intArrayValue.push_back((fShared.fDNGVersion >> BYTE2_SHIFT) & BYTE_MASK);
    value.intArrayValue.push_back((fShared.fDNGVersion >> BYTE1_SHIFT) & BYTE_MASK);
    value.intArrayValue.push_back(fShared.fDNGVersion & BYTE_MASK);
    return SUCCESS;
}

uint32_t DngSdkInfo::GetIfdNewSubfileType(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fNewSubFileType, value);
}

uint32_t DngSdkInfo::GetIfdImageWidth(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fImageWidth, value);
}

uint32_t DngSdkInfo::GetIfdImageLength(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fImageLength, value);
}

uint32_t DngSdkInfo::GetIfdCompression(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fCompression, value);
}

uint32_t DngSdkInfo::GetIfdPhotometricInterpretation(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fPhotometricInterpretation, value);
}

uint32_t DngSdkInfo::GetIfdOrientation(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fOrientation, value);
}

uint32_t DngSdkInfo::GetIfdSamplesPerPixel(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fSamplesPerPixel, value);
}

uint32_t DngSdkInfo::GetIfdRowsPerStrip(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fTileLength, value);
}

uint32_t DngSdkInfo::GetIfdXResolution(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngReal64(fIFD.fXResolution, value);
}

uint32_t DngSdkInfo::GetIfdYResolution(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngReal64(fIFD.fYResolution, value);
}

uint32_t DngSdkInfo::GetIfdPlanarConfiguration(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fPlanarConfiguration, value);
}

uint32_t DngSdkInfo::GetIfdResolutionUnit(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fResolutionUnit, value);
}

uint32_t DngSdkInfo::GetIfdYCbCrCoefficients(const dng_ifd& fIFD, MetadataValue& value)
{
    constexpr uint32_t ycbcrCoefficientElements = 3;
    value.type = PropertyValueType::DOUBLE_ARRAY;
    value.doubleArrayValue.reserve(ycbcrCoefficientElements);
    value.doubleArrayValue.push_back(fIFD.fYCbCrCoefficientR);
    value.doubleArrayValue.push_back(fIFD.fYCbCrCoefficientG);
    value.doubleArrayValue.push_back(fIFD.fYCbCrCoefficientB);
    return SUCCESS;
}

uint32_t DngSdkInfo::GetIfdYCbCrSubSampling(const dng_ifd& fIFD, MetadataValue& value)
{
    value.type = PropertyValueType::INT_ARRAY;
    constexpr uint32_t ycbcrSubSampleElements = 2;
    value.intArrayValue.reserve(ycbcrSubSampleElements);
    value.intArrayValue.push_back(static_cast<int64_t>(fIFD.fYCbCrSubSampleH));
    value.intArrayValue.push_back(static_cast<int64_t>(fIFD.fYCbCrSubSampleV));
    return SUCCESS;
}

uint32_t DngSdkInfo::GetIfdYCbCrPositioning(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fYCbCrPositioning, value);
}

uint32_t DngSdkInfo::GetIfdReferenceBlackWhite(const dng_ifd& fIFD, MetadataValue& value)
{
    constexpr uint32_t referenceBlackWhiteElements = 6;
    return GetDngReal64Array(fIFD.fReferenceBlackWhite, referenceBlackWhiteElements, value);
}

uint32_t DngSdkInfo::GetIfdDefaultCropSize(const dng_ifd& fIFD, MetadataValue& value)
{
    value.type = PropertyValueType::INT_ARRAY;
    constexpr uint32_t defaultCropElements = 2;
    value.intArrayValue.clear();
    value.intArrayValue.reserve(defaultCropElements);

    // Convert dng_urational to integer: numerator / denominator
    uint32_t cropH = (fIFD.fDefaultCropSizeH.d != 0) ?
        (fIFD.fDefaultCropSizeH.n / fIFD.fDefaultCropSizeH.d) : 0;
    uint32_t cropV = (fIFD.fDefaultCropSizeV.d != 0) ?
        (fIFD.fDefaultCropSizeV.n / fIFD.fDefaultCropSizeV.d) : 0;

    value.intArrayValue.push_back(static_cast<int64_t>(cropH));
    value.intArrayValue.push_back(static_cast<int64_t>(cropV));
    return SUCCESS;
}

uint32_t DngSdkInfo::GetIfdJPEGInterchangeFormat(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fJPEGInterchangeFormat, value);
}

uint32_t DngSdkInfo::GetIfdJPEGInterchangeFormatLength(const dng_ifd& fIFD, MetadataValue& value)
{
    return GetDngUint32(fIFD.fJPEGInterchangeFormatLength, value);
}

void DngSdkInfo::ParseTag(dng_host& host, dng_stream& stream, dng_exif* exif, dng_shared* shared, dng_ifd* ifd,
    uint32 parentCode, uint32 tagCode, uint32 tagType, uint32 tagCount, uint64 tagOffset, int64 offsetDelta)
{
    dng_info::ParseTag(host, stream, exif, shared, ifd,
        parentCode, tagCode, tagType, tagCount, tagOffset, offsetDelta);

    UniqueTagKey tagKey = std::make_pair(parentCode, static_cast<uint16_t>(tagCode));
    bool ret = SaveParsedTag(tagKey, static_cast<uint16_t>(tagType), tagCount, tagOffset);
    if (ret) {
        ProcessSpecialTag(tagKey, stream);
    }
}

static uint32_t GetTagValueSize(uint16_t tagType, uint16_t tagCount)
{
    uint32_t unitSize = TagTypeSize(static_cast<uint32_t>(tagType));
    if (tagCount == 0 || unitSize == 0 || ImageUtils::HasOverflowed(unitSize, static_cast<uint32_t>(tagCount))) {
        return 0;
    }
    return unitSize * tagCount;
}

bool DngSdkInfo::SaveParsedTag(const UniqueTagKey& tagKey, uint16_t tagType, uint32_t tagCount, uint64_t tagOffset)
{
    if (tagKey.first >= tcFirstMakerNoteIFD) {
        IMAGE_LOGD("Storing maker note fields is not supported");
        return false;
    }
    parsedParentCode_.insert(tagKey.first);

    uint32_t tagValueSize = GetTagValueSize(tagType, tagCount);
    if (tagValueSize == 0) {
        IMAGE_LOGD("Parse invalid tagCode:%{public}u tagType:%{public}u tagCount:%{public}u",
            tagKey.second, tagType, tagCount);
    }

    DngTagRecord record = {
        .tagCode = tagKey.second,
        .tagType = tagType,
        .tagCount = tagCount,
        .tagValueOffset = tagOffset,
        .tagValueSize = tagValueSize,
    };

    parsedTagRecordMap_[tagKey] = record;
    return true;
}

uint32_t DngSdkInfo::ParseAsciiTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value)
{
    value.type = PropertyValueType::STRING;
    if (tagRecord.tagCount > 0) {
        std::vector<char> buffer(tagRecord.tagCount);
        stream.Get(buffer.data(), tagRecord.tagCount);
        size_t len = tagRecord.tagCount;
        while (len > 0 && buffer[len - 1] == '\0') {
            len--;
        }
        value.stringValue.assign(buffer.data(), len);
    }
    return SUCCESS;
}

uint32_t DngSdkInfo::ParseShortTagToString(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value)
{
    value.type = PropertyValueType::STRING;
    value.stringValue.clear();
    if (tagRecord.tagCount == 0) {
        return SUCCESS;
    }
    
    std::vector<uint16_t> shortValues;
    shortValues.reserve(tagRecord.tagCount);
    for (uint32_t i = 0; i < tagRecord.tagCount; i++) {
        uint16_t shortVal = stream.Get_uint16();
        shortValues.push_back(shortVal);
    }

    for (uint32_t i = 0; i < shortValues.size(); i++) {
        value.stringValue += std::to_string(shortValues[i]);
    }
    return SUCCESS;
}

uint32_t DngSdkInfo::ParseIntArrayTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value)
{
    value.type = PropertyValueType::INT_ARRAY;
    value.intArrayValue.clear();
    value.intArrayValue.reserve(tagRecord.tagCount);
    for (uint32_t i = 0; i < tagRecord.tagCount; i++) {
        uint32_t longVal = stream.TagValue_uint32(static_cast<uint32_t>(tagRecord.tagType));
        value.intArrayValue.push_back(static_cast<int64_t>(longVal));
    }
    return SUCCESS;
}

uint32_t DngSdkInfo::ParseRationalTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value)
{
    value.type = PropertyValueType::DOUBLE_ARRAY;
    value.doubleArrayValue.clear();
    value.doubleArrayValue.reserve(tagRecord.tagCount);
    for (uint32_t i = 0; i < tagRecord.tagCount; i++) {
        double rationalVal = stream.TagValue_real64(static_cast<uint32_t>(tagRecord.tagType));
        value.doubleArrayValue.push_back(rationalVal);
    }
    return SUCCESS;
}

uint32_t DngSdkInfo::ParseUndefinedTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value)
{
    value.type = PropertyValueType::BLOB;
    value.bufferValue.clear();
    value.bufferValue.reserve(tagRecord.tagCount);
    for (uint32_t i = 0; i < tagRecord.tagCount; i++) {
        uint8_t byteVal = stream.Get_uint8();
        value.bufferValue.push_back(byteVal);
    }
    return SUCCESS;
}

uint32_t DngSdkInfo::ParseIntTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value)
{
    value.type = PropertyValueType::INT;
    value.intArrayValue.clear();
    for (uint32_t i = 0; i < tagRecord.tagCount; i++) {
        int64_t tagValue = static_cast<int64_t>(stream.TagValue_uint32(static_cast<uint32_t>(tagRecord.tagType)));
        value.intArrayValue.push_back(tagValue);
    }
    return SUCCESS;
}

uint32_t DngSdkInfo::ParseDoubleTag(const DngTagRecord& tagRecord, dng_stream& stream, MetadataValue& value)
{
    value.type = PropertyValueType::DOUBLE;
    value.doubleArrayValue.clear();
    if (tagRecord.tagCount == 0) {
        return SUCCESS;
    }
    value.doubleArrayValue.push_back(stream.TagValue_real64(static_cast<uint32_t>(tagRecord.tagType)));
    return SUCCESS;
}

void DngSdkInfo::ProcessSpecialTag(const UniqueTagKey& tagKey, dng_stream& stream)
{
    uint16_t tagCode = tagKey.second;
    auto parseIter = specialTagParseMap_.find(tagCode);
    CHECK_DEBUG_RETURN_LOG(parseIter == specialTagParseMap_.end(),
        "%{public}s: Not need to parse tagCode: %{public}u", __func__, tagCode);

    auto tagRecordIter = parsedTagRecordMap_.find(tagKey);
    CHECK_DEBUG_RETURN_LOG(tagRecordIter == parsedTagRecordMap_.end(),
        "%{public}s: Not found parsed tagCode: %{public}u", __func__, tagCode);

    const DngTagRecord& tagRecord = tagRecordIter->second;
    auto parseFunc = parseIter->second;
    MetadataValue value;

    bool cond = tagRecord.tagValueOffset + tagRecord.tagValueSize > stream.Length();
    CHECK_DEBUG_RETURN_LOG(cond,
        "%{public}s: Invalid value offset(%{public}d) and size(%{public}u) for tagCode: %{public}u",
        __func__, static_cast<uint32_t>(tagRecord.tagValueOffset), tagRecord.tagValueSize, tagCode);

    uint64_t savedPosition = stream.Position();
    stream.SetReadPosition(tagRecord.tagValueOffset);
    uint32_t ret = parseFunc(tagRecord, stream, value);
    stream.SetReadPosition(savedPosition);

    CHECK_ERROR_RETURN_LOG(ret != SUCCESS, "%{public}s: parse tagCode: %{public}u failed ", __func__, tagCode);
    parsedSpecialTagMap_[tagKey] = value;
}

uint32_t DngSdkInfo::GetOrSetExifProperty(dng_exif& fExif, MetadataValue& value, UniqueTagKey& tagKey, bool isGet)
{
    auto iter = exifPropertyMap_.find(value.key);
    if (iter == exifPropertyMap_.end()) {
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    uint16_t tagCode = std::get<TAG_CODE_INDEX>(iter->second);
    uint32_t tagParentCode = std::get<PARENT_CODE_INDEX>(iter->second);
    tagKey = std::make_pair(tagParentCode, tagCode);

    uint32_t result = ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    if (isGet) {
        auto getFunc = std::get<GET_FUNC_INDEX>(iter->second);
        result = getFunc(fExif, value);
    }
    return result;
}

uint32_t DngSdkInfo::GetOrSetSharedProperty(dng_shared& fShared, MetadataValue& value,
    UniqueTagKey& tagKey, bool isGet)
{
    auto iter = sharedPropertyMap_.find(value.key);
    if (iter == sharedPropertyMap_.end()) {
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    uint16_t tagCode = std::get<TAG_CODE_INDEX>(iter->second);
    uint32_t tagParentCode = std::get<PARENT_CODE_INDEX>(iter->second);
    tagKey = std::make_pair(tagParentCode, tagCode);

    uint32_t result = ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    if (isGet) {
        auto getFunc = std::get<GET_FUNC_INDEX>(iter->second);
        result = getFunc(fShared, value);
    }
    return result;
}

uint32_t DngSdkInfo::GetOrSetIfdProperty(dng_ifd& fIFD, MetadataValue& value, UniqueTagKey& tagKey, bool isGet)
{
    auto iter = ifdPropertyMap_.find(value.key);
    if (iter == ifdPropertyMap_.end()) {
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    uint16_t tagCode = std::get<TAG_CODE_INDEX>(iter->second);
    uint32_t tagParentCode = std::get<PARENT_CODE_INDEX>(iter->second);
    tagKey = std::make_pair(tagParentCode, tagCode);

    uint32_t result = ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    if (isGet) {
        auto getFunc = std::get<GET_FUNC_INDEX>(iter->second);
        result = getFunc(fIFD, value);
    }
    return result;
}

uint32_t DngSdkInfo::GetOrSetProperty(MetadataValue& value, const DngPropertyOption& option,
    UniqueTagKey& tagKey, bool isGet)
{
    uint32_t result = ERR_IMAGE_INVALID_PARAMETER;
    if (option.type == DngMetaSourceType::EXIF) {
        CHECK_ERROR_RETURN_RET(fExif.Get() == nullptr, ERR_MEDIA_NO_EXIF_DATA);
        result = GetOrSetExifProperty(*(fExif.Get()), value, tagKey, isGet);
    } else if (option.type == DngMetaSourceType::SHARED) {
        CHECK_ERROR_RETURN_RET(fShared.Get() == nullptr, ERR_MEDIA_NO_EXIF_DATA);
        result = GetOrSetSharedProperty(*(fShared.Get()), value, tagKey, isGet);
    } else if (option.type == DngMetaSourceType::SUB_PREVIEW_IFD) {
        CHECK_ERROR_RETURN_RET(option.ifdIndex >= fIFDCount, IMAGE_RESULT_INDEX_INVALID);
        CHECK_ERROR_RETURN_RET(fIFD[option.ifdIndex].Get() == nullptr, ERR_MEDIA_NO_EXIF_DATA);
        result = GetOrSetIfdProperty(*(fIFD[option.ifdIndex].Get()), value, tagKey, isGet);
        if (option.ifdIndex > 0) {
            tagKey.first = tcFirstSubIFD + option.ifdIndex - 1;
        }
    } else if (option.type == DngMetaSourceType::CHAINED_IFD) {
        CHECK_ERROR_RETURN_RET(option.ifdIndex >= fChainedIFDCount, IMAGE_RESULT_INDEX_INVALID);
        CHECK_ERROR_RETURN_RET(fChainedIFD[option.ifdIndex].Get() == nullptr, ERR_MEDIA_NO_EXIF_DATA);
        result = GetOrSetIfdProperty(*(fChainedIFD[option.ifdIndex].Get()), value, tagKey, isGet);
        tagKey.first = tcFirstChainedIFD + option.ifdIndex;
    }
    return result;
}

uint32_t DngSdkInfo::GetSpecialProperty(MetadataValue& value, const DngPropertyOption& option)
{
    const std::string tagName = value.key;
    UniqueTagKey tagKey = GetSpecialUniqueTagKey(tagName, option);
    auto specialTagIter = parsedSpecialTagMap_.find(tagKey);
    if (specialTagIter == parsedSpecialTagMap_.end()) {
        IMAGE_LOGD("%{public}s: key[%{public}s] is not exist in sourceType[%{public}d][%{public}u]",
            __func__, tagName.c_str(), option.type, option.ifdIndex);
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    value = specialTagIter->second;
    value.key = tagName;
    return SUCCESS;
}

static void ClearMetadataValue(MetadataValue& value)
{
    value.stringValue = "";
    value.intArrayValue.clear();
    value.doubleArrayValue.clear();
    value.bufferValue.clear();
}

uint32_t DngSdkInfo::GetProperty(MetadataValue& value, const DngPropertyOption& option)
{
    if (IsSpecialTagName(value.key)) {
        return GetSpecialProperty(value, option);
    }

    UniqueTagKey tagKey;
    uint32_t result = GetOrSetProperty(value, option, tagKey, true);
    IMAGE_LOGD("%{public}s: key[%{public}s] from sourceType[%{public}d][%{public}u] result: %{public}u",
        __func__, value.key.c_str(), option.type, option.ifdIndex, result);
    CHECK_ERROR_RETURN_RET(result != SUCCESS, result);

    if (!IsInvalidParsedTag(tagKey)) {
        IMAGE_LOGE("%{public}s: key[%{public}s] is not exist in sourceType[%{public}d][%{public}u]",
            __func__, value.key.c_str(), option.type, option.ifdIndex);
        ClearMetadataValue(value);
        return ERR_MEDIA_NO_EXIF_DATA;
    }
    return result;
}

uint32_t DngSdkInfo::SetProperty(const MetadataValue& value, const DngPropertyOption& option)
{
    MetadataValue copiedValue = value;
    UniqueTagKey tagKey;
    uint32_t result = GetOrSetProperty(copiedValue, option, tagKey, false);
    IMAGE_LOGD("%{public}s: key[%{public}s] to sourceType[%{public}d][%{public}u] result: %{public}u",
        __func__, value.key.c_str(), option.type, option.ifdIndex, result);
    CHECK_ERROR_RETURN_RET(result != SUCCESS, result);

    if (!IsParsedParentCode(tagKey.first)) {
        IMAGE_LOGE("%{public}s: sourceType[%{public}d][%{public}u] is not exist",
            __func__, option.type, option.ifdIndex);
        return ERR_IMAGE_DATA_UNSUPPORT;
    }

    bool isParsed = IsInvalidParsedTag(tagKey);
    DngUpdateTagItem tagItem = {
        .operation = isParsed ? DngPropertyOperation::MODIFY : DngPropertyOperation::ADD,
        .value = std::move(copiedValue),
    };
    updateTagMap_[tagKey] = tagItem;
    return SUCCESS;
}

uint32_t DngSdkInfo::RemoveProperty(const std::string& key, const DngPropertyOption& option)
{
    MetadataValue value = {
        .key = key,
    };
    UniqueTagKey tagKey;
    uint32_t result = GetOrSetProperty(value, option, tagKey, true);
    IMAGE_LOGD("%{public}s: key[%{public}s] to sourceType[%{public}d][%{public}u] result: %{public}u",
        __func__, key.c_str(), option.type, option.ifdIndex, result);
    CHECK_ERROR_RETURN_RET(result != SUCCESS, result);

    if (!IsInvalidParsedTag(tagKey)) {
        return ERR_MEDIA_NO_EXIF_DATA;
    }
    DngUpdateTagItem tagItem = {
        .operation = DngPropertyOperation::DELETE,
    };
    updateTagMap_[tagKey] = tagItem;
    return SUCCESS;
}

bool DngSdkInfo::IsInvalidParsedTag(const UniqueTagKey& tagKey)
{
    auto iter = parsedTagRecordMap_.find(tagKey);
    if (iter == parsedTagRecordMap_.end()) {
        return false;
    }

    const DngTagRecord& record = iter->second;
    if (record.tagCount <= 0) {
        return false;
    }
    return true;
}

bool DngSdkInfo::IsParsedParentCode(uint32_t parentCode)
{
    return parsedParentCode_.count(parentCode) != 0;
}

bool DngSdkInfo::IsSpecialTagName(const std::string& tagName)
{
    return specialTagNameMap_.find(tagName) != specialTagNameMap_.end();
}

DngSdkInfo::UniqueTagKey DngSdkInfo::GetSpecialUniqueTagKey(const std::string& tagName,
    const DngPropertyOption& option)
{
    uint32_t parentCode = 0;
    if (option.type == DngMetaSourceType::EXIF) {
        parentCode = tcExifIFD;
    } else if (option.type == DngMetaSourceType::SUB_PREVIEW_IFD) {
        parentCode = option.ifdIndex > 0 ? tcFirstSubIFD + option.ifdIndex - 1 : 0;
    } else if (option.type == DngMetaSourceType::CHAINED_IFD) {
        parentCode = tcFirstChainedIFD + option.ifdIndex;
    }

    uint16_t tagCode = 0xFFFF;
    auto iter = specialTagNameMap_.find(tagName);
    if (iter != specialTagNameMap_.end()) {
        tagCode = iter->second;
    }

    IMAGE_LOGD("%{public}s: parse tagName[%{public}s] to parentCode:%{public}u tagCode:%{public}u",
        __func__, tagName.c_str(), parentCode, tagCode);
    return {parentCode, tagCode};
}

std::set<std::string> DngSdkInfo::GetAllPropertyKeys()
{
    std::set<std::string> allKeys;

    for (const auto& pair : exifPropertyMap_) {
        allKeys.insert(pair.first);
    }

    for (const auto& pair : sharedPropertyMap_) {
        allKeys.insert(pair.first);
    }

    for (const auto& pair : ifdPropertyMap_) {
        allKeys.insert(pair.first);
    }

    for (const auto& pair : specialTagNameMap_) {
        allKeys.insert(pair.first);
    }

    return allKeys;
}
} // namespace Media
} // namespace OHOS
