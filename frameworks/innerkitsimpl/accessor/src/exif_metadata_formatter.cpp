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

#include <cmath>
#include <iostream>
#include <regex>
#include <string_view>
#include <set>
#include <string>
#include <sstream>
#include <utility>
#include <charconv>
#include <system_error>

#include "exif_metadata_formatter.h"
#include "hilog/log_cpp.h"
#include "hilog/log.h"
#include "image_log.h"
#include "media_errors.h"
#include "string_ex.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ExifMetadatFormatter"

namespace OHOS {
namespace Media {

const auto GPS_DEGREE_SIZE = 2;
const auto GPS_NORMAL_SIZE = 3;
const double GPS_MAX_LATITUDE = 90.0;
const double GPS_MIN_LATITUDE = 0.0;
const double GPS_MAX_LONGITUDE = 180.0;
const double GPS_MIN_LONGITUDE = 0.0;
const int CONSTANT_0 = 0;
const int CONSTANT_1 = 1;
const int CONSTANT_2 = 2;

const static std::set<std::string> READ_WRITE_KEYS = {
    "BitsPerSample",
    "Orientation",
    "ImageLength",
    "ImageWidth",
    "GPSLatitude",
    "GPSLongitude",
    "GPSLatitudeRef",
    "GPSLongitudeRef",
    "DateTimeOriginal",
    "ExposureTime",
    "SceneType",
    "ISOSpeedRatings",
    "FNumber",
    "DateTime",
    "GPSTimeStamp",
    "GPSDateStamp",
    "ImageDescription",
    "Make",
    "Model",
    "PhotoMode",
    "SensitivityType",
    "StandardOutputSensitivity",
    "RecommendedExposureIndex",
    "ISOSpeed",
    "ApertureValue",
    "ExposureBiasValue",
    "MeteringMode",
    "LightSource",
    "Flash",
    "FocalLength",
    "UserComment",
    "PixelXDimension",
    "PixelYDimension",
    "WhiteBalance",
    "FocalLengthIn35mmFilm",
    "CompressedBitsPerPixel",
    "JPEGProc",
    "Compression",
    "PhotometricInterpretation",
    "StripOffsets",
    "SamplesPerPixel",
    "RowsPerStrip",
    "StripByteCounts",
    "XResolution",
    "YResolution",
    "PlanarConfiguration",
    "ResolutionUnit",
    "TransferFunction",
    "Software",
    "Artist",
    "WhitePoint",
    "PrimaryChromaticities",
    "YCbCrCoefficients",
    "YCbCrSubSampling",
    "YCbCrPositioning",
    "ReferenceBlackWhite",
    "Copyright",
    "SubsecTime",
    "SubsecTimeOriginal",
    "SubsecTimeDigitized",
    "FlashpixVersion",
    "ColorSpace",
    "RelatedSoundFile",
    "FlashEnergy",
    "SpatialFrequencyResponse",
    "FocalPlaneXResolution",
    "FocalPlaneYResolution",
    "FocalPlaneResolutionUnit",
    "SubjectLocation",
    "ExposureIndex",
    "SensingMethod",
    "FileSource",
    "CFAPattern",
    "CustomRendered",
    "ExposureMode",
    "DigitalZoomRatio",
    "SceneCaptureType",
    "GainControl",
    "Contrast",
    "Saturation",
    "Sharpness",
    "DeviceSettingDescription",
    "SubjectDistanceRange",
    "ImageUniqueID",
    "GPSVersionID",
    "GPSAltitudeRef",
    "GPSAltitude",
    "GPSSatellites",
    "GPSStatus",
    "GPSMeasureMode",
    "GPSDOP",
    "GPSSpeedRef",
    "GPSSpeed",
    "GPSTrackRef",
    "GPSTrack",
    "GPSImgDirectionRef",
    "GPSImgDirection",
    "GPSMapDatum",
    "GPSDestLatitudeRef",
    "GPSDestLatitude",
    "GPSDestLongitudeRef",
    "GPSDestLongitude",
    "GPSDestBearingRef",
    "GPSDestBearing",
    "GPSDestDistanceRef",
    "GPSDestDistance",
    "GPSProcessingMethod",
    "GPSAreaInformation",
    "GPSDifferential",
    "ComponentsConfiguration",
    "ISOSpeedLatitudeyyy",
    "ISOSpeedLatitudezzz",
    "SubjectDistance",
    "DefaultCropSize",
    "LensSpecification",
    "SubjectArea",
    "DNGVersion",
    "SubfileType",
    "NewSubfileType",
    "LensMake",
    "LensModel",
    "LensSerialNumber",
    "OffsetTimeDigitized",
    "OffsetTimeOriginal",
    "SourceExposureTimesOfCompositeImage",
    "SourceImageNumberOfCompositeImage",
    "GPSHPositioningError",
    "Orientation",
    "GPSLongitudeRef",
    "ExposureProgram",
    "SpectralSensitivity",
    "OECF",
    "ExifVersion",
    "DateTimeDigitized",
    "ShutterSpeedValue",
    "BrightnessValue",
    "MaxApertureValue",
    "BodySerialNumber",
    "CameraOwnerName",
    "CompositeImage",
    "Gamma",
    "OffsetTime",
    "PhotographicSensitivity",
    "HwMnoteCaptureMode",
    "HwMnoteIsXmageSupported",
    "HwMnoteXmageMode",
    "HwMnoteXmageLeft",
    "HwMnoteXmageTop",
    "HwMnoteXmageRight",
    "HwMnoteXmageBottom",
    "HwMnoteCloudEnhancementMode",
    "MovingPhotoId",
    "MovingPhotoVersion",
    "MicroVideoPresentationTimestampUS",
    "HwMnoteAiEdit",
    "HwMnoteXtStyleTemplateName",
    "HwMnoteXtStyleCustomLightAndShadow",
    "HwMnoteXtStyleCustomSaturation",
    "HwMnoteXtStyleCustomHue",
    "HwMnoteXtStyleExposureParam",
    "MakerNote",
    "HwMnoteXtStyleAlgoVersion",
    "HwMnoteXtStyleAlgoVideoEnable",
    "HwMnoteIsApertureEditSupported",
};

const static std::set<std::string> READ_ONLY_KEYS = {
    "HwMnotePhysicalAperture",
    "HwMnoteRollAngle",        "HwMnotePitchAngle",
    "HwMnoteSceneFoodConf",    "HwMnoteSceneStageConf",
    "HwMnoteSceneBlueSkyConf", "HwMnoteSceneGreenPlantConf",
    "HwMnoteSceneBeachConf",   "HwMnoteSceneSnowConf",
    "HwMnoteSceneSunsetConf",  "HwMnoteSceneFlowersConf",
    "HwMnoteSceneNightConf",   "HwMnoteSceneTextConf",
    "HwMnoteFaceCount",        "HwMnoteFocusMode",
    "HwMnoteFrontCamera",      "HwMnoteSceneVersion",
    "HwMnoteScenePointer",     "HwMnoteFacePointer",
    "HwMnoteBurstNumber",      "HwMnoteFaceVersion",
    "HwMnoteFaceConf",         "HwMnoteFaceSmileScore",
    "HwMnoteFaceRect",         "HwMnoteFaceLeyeCenter",
    "HwMnoteFaceReyeCenter",   "HwMnoteFaceMouthCenter",
    "JPEGInterchangeFormat",   "JPEGInterchangeFormatLength",
    "HwMnoteWindSnapshotMode", "HwMnoteFocusModeExif",
};

// Orientation, tag 0x0112
constexpr TagDetails exifOrientation[] = {
    {1, "Top-left"},     {2, "Top-right"},   {3, "Bottom-right"},
    {4, "Bottom-left"},  {5, "Left-top"},    {6, "Right-top"},
    {7, "Right-bottom" }, {8, "Left-bottom"},
};

// GPS latitude reference, tag 0x0001; also GPSDestLatitudeRef, tag 0x0013
constexpr TagDetails exifGPSLatitudeRef[] = {
    {78, "North"},
    {83, "South"},
};

constexpr TagDetails exifGPSLongitudeRef[] = {
    {69, "East"},
    {87, "West"},
};

// WhiteBalance, tag 0xa403
constexpr TagDetails exifWhiteBalance[] = {
    {0, "Auto white balance"},
    {1, "Manual white balance"},
};

// Flash, Exif tag 0x9209
constexpr TagDetails exifFlash[] = {
    {0x00, "Flash did not fire"},
    {0x01, "Flash fired"},
    {0x05, "Strobe return light not detected"},
    {0x07, "Strobe return light detected"},
    {0x08, "Flash did not fire"},
    {0x09, "Flash fired, compulsory flash mode"},
    {0x0d, "Flash fired, compulsory flash mode, return light not detected"},
    {0x0f, "Flash fired, compulsory flash mode, return light detected"},
    {0x10, "Flash did not fire, compulsory flash mode"},
    {0x18, "Flash did not fire, auto mode"},
    {0x19, "Flash fired, auto mode"},
    {0x1d, "Flash fired, auto mode, return light not detected"},
    {0x1f, "Flash fired, auto mode, return light detected"},
    {0x20, "No flash function"},
    {0x41, "Flash fired, red-eye reduction mode"},
    {0x45, "Flash fired, red-eye reduction mode, return light not detected"},
    {0x47, "Flash fired, red-eye reduction mode, return light detected"},
    {0x49, "Flash fired, compulsory flash mode, red-eye reduction mode"},
    {0x4d, "Flash fired, compulsory flash mode, red-eye reduction mode, return light not detected"},
    {0x4f, "Flash fired, compulsory flash mode, red-eye reduction mode, return light detected"},
    {0x58, "Flash did not fire, auto mode, red-eye reduction mode"},
    {0x59, "Flash fired, auto mode, red-eye reduction mode"},
    {0x5d, "Flash fired, auto mode, return light not detected, red-eye reduction mode"},
    {0x5f, "Flash fired, auto mode, return light detected, red-eye reduction mode"},
};

// ColorSpace, tag 0xa001
constexpr TagDetails exifColorSpace[] = {
    {1, "sRGB"},
    {2, "Adobe RGB"}, // Not defined to Exif 2.2 spec. But used by a lot of cameras.
    {0xffff, "Uncalibrated"},
};

// LightSource, tag 0x9208
constexpr TagDetails exifLightSource[] = {
    {0, "Unknown"},
    {1, "Daylight"},
    {2, "Fluorescent"},
    {3, "Tungsten incandescent light"},
    {4, "Flash"},
    {9, "Fine weather"},
    {10, "Cloudy weather"},
    {11, "Shade"},
    {12, "Daylight fluorescent"},
    {13, "Day white fluorescent"},
    {14, "Cool white fluorescent"},
    {15, "White fluorescent"},
    {17, "Standard light A"},
    {18, "Standard light B"},
    {19, "Standard light C"},
    {20, "D55"},
    {21, "D65"},
    {22, "D75"},
    {23, "D50"},
    {24, "ISO studio tungsten"},
    {255, "Other"},
};

// MeteringMode, tag 0x9207
constexpr TagDetails exifMeteringMode[] = {
    {0, "Unknown"}, {1, "Average"},    {2, "Center-weighted average"},
    {3, "Spot"},    {4, "Multi spot"}, {5, "Pattern"},
    {6, "Partial"}, {255, "Other"},
};

// SceneType, tag 0xa301
constexpr TagDetails exifSceneType[] = {
    {1, "Directly photographed"},
};

// Compression, tag 0x0103
constexpr TagDetails exifCompression[] = {
    {1, "Uncompressed"},
    {2, "CCITT RLE"},
    {3, "T4/Group 3 Fax"},
    {4, "T6/Group 4 Fax"},
    {5, "LZW compression"},
    {6, "JPEG (old-style) compression"},
    {7, "JPEG compression"},
    {8, "Deflate/ZIP compression"},
    {9, "JBIG B&W"},
    {10, "JBIG Color"},
    {32766, "Next 2-bits RLE"},
    {32767, "Sony ARW Compressed"},
    {32769, "Epson ERF Compressed"},
    {32770, "Samsung SRW Compressed"},
    {32771, "CCITT RLE 1-word"},
    {32773, "PackBits compression"},
    {32809, "Thunderscan RLE"},
    {32895, "IT8 CT Padding"},
    {32896, "IT8 Linework RLE"},
    {32897, "IT8 Monochrome Picture"},
    {32898, "IT8 Binary Lineart"},
    {32908, "Pixar Film (10-bits LZW)"},
    {32909, "Pixar Log (11-bits ZIP)"},
    {32946, "Pixar Deflate"},
    {32947, "Kodak DCS Encoding"},
    {34661, "ISO JBIG"},
    {34676, "SGI Log Luminance RLE"},
    {34677, "SGI Log 24-bits packed"},
    {34712, "Leadtools JPEG 2000"},
    {34713, "Nikon NEF Compressed"},
    {34892, "JPEG (lossy)"}, // DNG 1.4
    {52546, "JPEG XL"},      // DNG 1.7
    {65000, "Kodak DCR Compressed"},
    {65535, "Pentax PEF Compressed"},
};

// PhotometricInterpretation, tag 0x0106
constexpr TagDetails exifPhotometricInterpretation[] = {
    {0, "Reversed mono"},
    {1, "Normal mono"},
    {2, "RGB"},
    {3, "Palette"},
    {5, "CMYK"},
    {6, "YCbCr"},
    {8, "CieLAB"},
};

// PlanarConfiguration, tag 0x011c
constexpr TagDetails exifPlanarConfiguration[] = {
    {1, "Chunky format"},
    {2, "Planar format"},
};

// Units for measuring X and Y resolution, tags 0x0128, 0xa210
constexpr TagDetails exifUnit[] = {
    {2, "Inch"},
    {3, "Centimeter"},
};

// YCbCrPositioning, tag 0x0213
constexpr TagDetails exifYCbCrPositioning[] = {
    {1, "Centered"},
    {2, "Co-sited"},
};

// ExposureProgram, tag 0x8822
constexpr TagDetails exifExposureProgram[] = {
    {0, "Not defined"},       {1, "Manual"},           {2, "Normal program"},
    {3, "Aperture priority"}, {4, "Shutter priority"}, {5, "Creative program (biased toward depth of field)"},
    {6, "Creative program (biased toward fast shutter speed)"},
    {7, "Portrait mode (for closeup photos with the background out of focus)"},
    {8, "Landscape mode (for landscape photos with the background in focus)"},
};

// SensingMethod, TIFF/EP tag 0x9217
constexpr TagDetails tiffSensingMethod[] = {
    {0, ""},           {1, "Not defined"},       {2, "One-chip color area sensor"},
    {3, "Two-chip color area sensor"}, {4, "Three-chip color area sensor"}, {5, "Color sequential area sensor"},
    {6, "Monochrome linear"},   {7, "Trilinear sensor"},      {8, "Color sequential linear sensor"},
};

// CustomRendered, tag 0xa401
constexpr TagDetails exifCustomRendered[] = {
    {0, "Normal process"},
    {1, "Custom process"},
};

// ExposureMode, tag 0xa402
constexpr TagDetails exifExposureMode[] = {
    {0, "Auto exposure"},
    {1, "Manual exposure"},
    {2, "Auto bracket"},
};

// SceneCaptureType, tag 0xa406
constexpr TagDetails exifSceneCaptureType[] = {
    {0, "Standard"},
    {1, "Landscape"},
    {2, "Portrait"},
    {3, "Night scene"}
};

// GainControl, tag 0xa407
constexpr TagDetails exifGainControl[] = {
    {0, "Normal"},          {1, "Low gain up"},    {2, "High gain up"},
    {3, "Low gain down"}, {4, "High gain down"},
};

// Contrast, tag 0xa408 and Sharpness, tag 0xa40a
constexpr TagDetails exifNormalSoftHard[] = {
    {0, "Normal"},
    {1, "Soft"},
    {2, "Hard"},
};

// Saturation, tag 0xa409
constexpr TagDetails exifSaturation[] = {
    {0, "Normal"},
    {1, "Low saturation"},
    {2, "High saturation"},
};

// SubjectDistanceRange, tag 0xa40c
constexpr TagDetails exifSubjectDistanceRange[] = {
    {0, "Unknown"},
    {1, "Macro"},
    {2, "Close view"},
    {3, "Distant view"}
};

// GPS altitude reference, tag 0x0005
constexpr TagDetails exifGPSAltitudeRef[] = {
    {0, "Sea level"},
    {1, "Sea level reference"},
};

// NewSubfileType, TIFF tag 0x00fe - this is actually a bitmask
constexpr TagDetails exifNewSubfileType[] = {
    {0, "Primary image"},
    {1, "Thumbnail/Preview image"},
    {2, "Primary image, Multi page file"},
    {3, "Thumbnail/Preview image, Multi page file"},
    {4, "Primary image, Transparency mask"},
    {5, "Thumbnail/Preview image, Transparency mask"},
    {6, "Primary image, Multi page file, Transparency mask"},
    {7, "Thumbnail/Preview image, Multi page file, Transparency mask"},
    {8, "Primary image, Depth map"},                 // DNG 1.5
    {9, "Thumbnail/Preview image, Depth map"},       // DNG 1.5
    {16, "Enhanced image"},                          // DNG 1.5 (clashes w/ TIFF-FX)
    {65537, "Thumbnail/Preview image, Alternative"}, // DNG 1.2
    {65540, "Primary image, Semantic mask"}          // DNG 1.6
};

// SubfileType, TIFF tag 0x00ff
constexpr TagDetails exifSubfileType[] = {
    {1, "Full-resolution image data"},
    {2, "Reduced-resolution image data"},
    {3, "A single page of a multi-page image"},
};

// GPS status, tag 0x0009
constexpr TagDetails exifGpsStatus[] = {
    {'A', "Measurement in progress"},
    {'V', "Measurement interrupted"},
};

// GPS measurement mode, tag 0x000a
constexpr TagDetails exifGPSMeasureMode[] = {
    {2, "2-dimensional measurement"},
    {3, "3-dimensional measurement"},
};

// GPS speed reference, tag 0x000c
constexpr TagDetails exifGPSSpeedRef[] = {
    {'K', "km/h"},
    {'M', "mph"},
    {'N', "knots"},
};

// GPS direction reference, tags 0x000e, 0x0010, 0x0017
constexpr TagDetails exifGPSDirRef[] = {
    {'T', "True direction"},
    {'M', "Magnetic direction"},
};

// GPS destination distance reference, tag 0x0019
constexpr TagDetails exifGPSDestDistanceRef[] = {
    {'K', "km"},
    {'M', "miles"},
    {'N', "nautical miles"},
};

// GPS differential correction, tag 0x001e
constexpr TagDetails exifGPSDifferential[] = {
    {0, "Without correction"},
    {1, "Correction applied"},
};

// CompositeImage, tag 0xa460
constexpr TagDetails exifCompositeImage[] = {
    {0, "Unknown"},
    {1, "NonComposite"},
    {2, "GeneralComposite"},
    {3, "CompositeCapturedWhenShooting"},
};

// exifSensitivityType, tag 0x8830
constexpr TagDetails exifSensitivityType[] = {
    {0, "Unknown"},
    {1, "Standard output sensitivity (SOS)"},
    {2, "Recommended exposure index (REI)"},
    {3, "ISO speed"},
    {4, "Standard output sensitivity (SOS) and recommended exposure index (REI)"},
    {5, "Standard output sensitivity (SOS) and ISO speed"},
    {6, "Recommended exposure index (REI) and ISO speed"},
    {7, "Standard output sensitivity (SOS) and recommended exposure index (REI) and ISO speed"},
};

ExifMetadatFormatter &ExifMetadatFormatter::GetInstance()
{
    static ExifMetadatFormatter instance;
    return instance;
}

ExifMetadatFormatter::ExifMetadatFormatter()
{
    InitDelegates();
    InitValueRangeValidateConfig();
    InitValueFormatConvertConfig();
    InitValueTemplateConfig();
}

// configuratioin for value range validation. For example GPSLatitudeRef the value must be 'N' or 'S'.
void ExifMetadatFormatter::InitValueRangeValidateConfig()
{
    valueRangeValidateConfig_ = std::map<std::string, std::tuple<const TagDetails*, const size_t>>{
        { "Orientation", std::make_tuple(exifOrientation, std::size(exifOrientation)) },
        { "GPSLatitudeRef", std::make_tuple(exifGPSLatitudeRef, std::size(exifGPSLatitudeRef)) },
        { "GPSDestLatitudeRef", std::make_tuple(exifGPSLatitudeRef, std::size(exifGPSLatitudeRef)) },
        { "GPSLongitudeRef", std::make_tuple(exifGPSLongitudeRef, std::size(exifGPSLongitudeRef)) },
        { "GPSDestLongitudeRef", std::make_tuple(exifGPSLongitudeRef, std::size(exifGPSLongitudeRef)) },
        { "WhiteBalance", std::make_tuple(exifWhiteBalance, std::size(exifWhiteBalance)) },
        { "Flash", std::make_tuple(exifFlash, std::size(exifFlash)) },
        { "LightSource", std::make_tuple(exifLightSource, std::size(exifLightSource)) },
        { "MeteringMode", std::make_tuple(exifMeteringMode, std::size(exifMeteringMode)) },
        { "SceneType", std::make_tuple(exifSceneType, std::size(exifSceneType)) },
        { "Compression", std::make_tuple(exifCompression, std::size(exifCompression)) },
        { "PhotometricInterpretation",
        std::make_tuple(exifPhotometricInterpretation, std::size(exifPhotometricInterpretation)) },
        { "PlanarConfiguration", std::make_tuple(exifPlanarConfiguration, std::size(exifPlanarConfiguration)) },
        { "ResolutionUnit", std::make_tuple(exifUnit, std::size(exifUnit)) },
        { "YCbCrPositioning", std::make_tuple(exifYCbCrPositioning, std::size(exifYCbCrPositioning)) },
        { "ExposureProgram", std::make_tuple(exifExposureProgram, std::size(exifExposureProgram)) },
        { "ColorSpace", std::make_tuple(exifColorSpace, std::size(exifColorSpace)) },
        { "FocalPlaneResolutionUnit", std::make_tuple(exifUnit, std::size(exifUnit)) },
        { "SensingMethod", std::make_tuple(tiffSensingMethod, std::size(tiffSensingMethod)) },
        { "CustomRendered", std::make_tuple(exifCustomRendered, std::size(exifCustomRendered)) },
        { "ExposureMode", std::make_tuple(exifExposureMode, std::size(exifExposureMode)) },
        { "SceneCaptureType", std::make_tuple(exifSceneCaptureType, std::size(exifSceneCaptureType)) },
        { "GainControl", std::make_tuple(exifGainControl, std::size(exifGainControl)) },
        { "Contrast", std::make_tuple(exifNormalSoftHard, std::size(exifNormalSoftHard)) },
        { "Saturation", std::make_tuple(exifSaturation, std::size(exifSaturation)) },
        { "Sharpness", std::make_tuple(exifNormalSoftHard, std::size(exifNormalSoftHard)) },
        { "SubjectDistanceRange", std::make_tuple(exifSubjectDistanceRange, std::size(exifSubjectDistanceRange)) },
        { "GPSAltitudeRef", std::make_tuple(exifGPSAltitudeRef, std::size(exifGPSAltitudeRef)) },
        { "NewSubfileType", std::make_tuple(exifNewSubfileType, std::size(exifNewSubfileType)) },
        { "SubfileType", std::make_tuple(exifSubfileType, std::size(exifSubfileType)) },
        { "GPSStatus", std::make_tuple(exifGpsStatus, std::size(exifGpsStatus)) },
        { "GPSMeasureMode", std::make_tuple(exifGPSMeasureMode, std::size(exifGPSMeasureMode)) },
        { "GPSSpeedRef", std::make_tuple(exifGPSSpeedRef, std::size(exifGPSSpeedRef)) },
        { "GPSImgDirectionRef", std::make_tuple(exifGPSDirRef, std::size(exifGPSDirRef)) },
        { "GPSTrackRef", std::make_tuple(exifGPSDirRef, std::size(exifGPSDirRef)) },
        { "GPSDestBearingRef", std::make_tuple(exifGPSDirRef, std::size(exifGPSDirRef)) },
        { "GPSDestDistanceRef", std::make_tuple(exifGPSDestDistanceRef, std::size(exifGPSDestDistanceRef)) },
        { "GPSDifferential", std::make_tuple(exifGPSDifferential, std::size(exifGPSDifferential)) },
        { "CompositeImage", std::make_tuple(exifCompositeImage, std::size(exifCompositeImage)) },
        { "SensitivityType", std::make_tuple(exifSensitivityType, std::size(exifSensitivityType)) },
    };
}

// configuration for value format validation. For example BitPerSample the value format should be 9 9 9 or 9,9,9
void ExifMetadatFormatter::InitValueFormatConvertConfig()
{
    valueFormatConvertConfig_ = {
        {"BitsPerSample", tribleIntWithBlank_},
        {"BitsPerSample", tribleIntWithComma_},
        {"CompressedBitsPerPixel", singleRational_},
        {"CompressedBitsPerPixel", singleIntToRational_},
        {"CompressedBitsPerPixel", singleDecimalToRational_},
        {"GPSLatitude", doubleIntToOneRationalWithComma_},
        {"GPSLatitude", tribleRationalWithBlank_},
        {"GPSLatitude", tribleIntToRationalWithBlank_},
        {"GPSLatitude", tribleIntToRationalWithComma_},
        {"GPSLatitude", tribleMixToRationalWithComma_},
        {"GPSLongitude", doubleIntToOneRationalWithComma_},
        {"GPSLongitude", tribleRationalWithBlank_},
        {"GPSLongitude", tribleIntToRationalWithBlank_},
        {"GPSLongitude", tribleIntToRationalWithComma_},
        {"GPSLongitude", tribleMixToRationalWithComma_},
        {"ApertureValue", singleRational_},
        {"ApertureValue", singleIntToRational_},
        {"ApertureValue", singleDecimalToRational_},
        {"DateTimeOriginal", dateTimeValidation_},
        {"DateTimeOriginal", dateValidation_},
        {"DateTime", dateTimeValidation_},
        {"DateTime", dateValidation_},
        {"ExposureBiasValue", singleRational_},
        {"ExposureBiasValue", singleIntToRational_},
        {"ExposureBiasValue", singleDecimalToRational_},
        {"ExposureTime", singleRational_},
        {"ExposureTime", singleIntToRational_},
        {"ExposureTime", singleDecimalToRational_},
        {"FNumber", singleRational_},
        {"FNumber", singleIntToRational_},
        {"FNumber", singleDecimalToRational_},
        {"FocalLength", singleRational_},
        {"FocalLength", singleIntToRational_},
        {"FocalLength", singleDecimalToRational_},
        {"GPSTimeStamp", tribleRationalWithBlank_},
        {"GPSTimeStamp", tribleIntToRationalWithBlank_},
        {"GPSTimeStamp", tribleIntToRationalWithColon_},
        {"GPSTimeStamp", timeStamp_},
        {"GPSDateStamp", dateValidation_},
        {"XResolution", singleRational_},
        {"XResolution", singleIntToRational_},
        {"XResolution", singleDecimalToRational_},
        {"YResolution", singleRational_},
        {"YResolution", singleIntToRational_},
        {"YResolution", singleDecimalToRational_},
        {"WhitePoint", singleRational_},
        {"WhitePoint", singleIntToRational_},
        {"WhitePoint", singleDecimalToRational_},
        {"WhitePoint", doubleValueToRational_},
        {"PrimaryChromaticities", singleRational_},
        {"PrimaryChromaticities", singleIntToRational_},
        {"PrimaryChromaticities", singleDecimalToRational_},
        {"YCbCrCoefficients", tribleRationalWithBlank_},
        {"YCbCrCoefficients", tribleIntToRationalWithBlank_},
        {"YCbCrCoefficients", tribleIntToRationalWithComma_},
        {"YCbCrCoefficients", tribleDecimalToRationalWithBlank_},
        {"YCbCrCoefficients", tribleDecimalToRatiionalWithComma_},
        {"ReferenceBlackWhite", singleRational_},
        {"ReferenceBlackWhite", singleIntToRational_},
        {"ReferenceBlackWhite", singleDecimalToRational_},
        {"ReferenceBlackWhite", sixDecimalToRationalWithComma_},
        {"ShutterSpeedValue", singleRational_},
        {"ShutterSpeedValue", singleIntToRational_},
        {"ShutterSpeedValue", singleDecimalToRational_},
        {"BrightnessValue", singleRational_},
        {"BrightnessValue", singleIntToRational_},
        {"BrightnessValue", singleDecimalToRational_},
        {"MaxApertureValue", singleRational_},
        {"MaxApertureValue", singleIntToRational_},
        {"MaxApertureValue", singleDecimalToRational_},
        {"SubjectDistance", singleRational_},
        {"SubjectDistance", singleIntToRational_},
        {"SubjectDistance", singleDecimalToRational_},
        {"FlashEnergy", singleRational_},
        {"FlashEnergy", singleIntToRational_},
        {"FlashEnergy", singleDecimalToRational_},
        {"FocalPlaneXResolution", singleRational_},
        {"FocalPlaneXResolution", singleIntToRational_},
        {"FocalPlaneXResolution", singleDecimalToRational_},
        {"FocalPlaneYResolution", singleRational_},
        {"FocalPlaneYResolution", singleIntToRational_},
        {"FocalPlaneYResolution", singleDecimalToRational_},
        {"ExposureIndex", singleRational_},
        {"ExposureIndex", singleIntToRational_},
        {"ExposureIndex", singleDecimalToRational_},
        {"DigitalZoomRatio", singleRational_},
        {"DigitalZoomRatio", singleIntToRational_},
        {"DigitalZoomRatio", singleDecimalToRational_},
        {"GPSAltitude", singleRational_},
        {"GPSAltitude", singleIntToRational_},
        {"GPSAltitude", singleDecimalToRational_},
        {"GPSDOP", singleRational_},
        {"GPSDOP", singleIntToRational_},
        {"GPSDOP", singleDecimalToRational_},
        {"GPSSpeed", singleRational_},
        {"GPSSpeed", singleIntToRational_},
        {"GPSSpeed", singleDecimalToRational_},
        {"GPSTrack", singleRational_},
        {"GPSTrack", singleIntToRational_},
        {"GPSTrack", singleDecimalToRational_},
        {"GPSImgDirection", singleRational_},
        {"GPSImgDirection", singleIntToRational_},
        {"GPSImgDirection", singleDecimalToRational_},
        {"GPSDestLatitude", tribleRationalWithBlank_},
        {"GPSDestLatitude", tribleIntToRationalWithBlank_},
        {"GPSDestLatitude", tribleIntToRationalWithComma_},
        {"GPSDestLongitude", tribleRationalWithBlank_},
        {"GPSDestLongitude", tribleIntToRationalWithBlank_},
        {"GPSDestLongitude", tribleIntToRationalWithComma_},
        {"GPSDestBearing", singleRational_},
        {"GPSDestBearing", singleIntToRational_},
        {"GPSDestBearing", singleDecimalToRational_},
        {"GPSDestDistance", singleRational_},
        {"GPSDestDistance", singleIntToRational_},
        {"GPSDestDistance", singleDecimalToRational_},
        {"GPSVersionID", fourIntWithDot_},
        {"CompressedBitsPerPixel", singleRational_},
        {"CompressedBitsPerPixel", singleIntToRational_},
        {"CompressedBitsPerPixel", singleDecimalToRational_},
        {"DNGVersion", fourIntWithBlank_},
        {"DNGVersion", fourIntWithComma_},
        {"DefaultCropSize", doubleIntWithBlank_},
        {"DefaultCropSize", doubleIntWithComma_},
        {"Gamma", singleRational_},
        {"Gamma", singleIntToRational_},
        {"Gamma", singleDecimalToRational_},
        {"GPSHPositioningError", singleRational_},
        {"GPSHPositioningError", singleIntToRational_},
        {"GPSHPositioningError", singleDecimalToRational_},
        {"LensSpecification", fourRationalWithBlank_},
        {"LensSpecification", fourIntToRationalWithBlank_},
        {"LensSpecification", fourIntToRationalWithComma_},
        {"LensSpecification", fourDecimalToRationalWithBlank_},
        {"LensSpecification", fourDecimalToRationalWithComma_},
        {"ReferenceBlackWhite", sixDecimalToRationalWithBlank_},
        {"SubjectLocation", doubleIntWithBlank_},
        {"SubjectLocation", doubleIntWithComma_},
        {"ImageLength", singleInt_},
        {"ImageWidth", singleInt_},
        {"ISOSpeedRatings", singleInt_},
        {"StandardOutputSensitivity", singleInt_},
        {"RecommendedExposureIndex", singleInt_},
        {"ISOSpeed", singleInt_},
        {"PixelXDimension", singleInt_},
        {"PixelYDimension", singleInt_},
        {"FocalLengthIn35mmFilm", singleInt_},
        {"StripOffsets", singleInt_},
        {"SamplesPerPixel", singleInt_},
        {"RowsPerStrip", singleInt_},
        {"StripByteCounts", singleInt_},
        {"ExifVersion", singleInt_},
        {"ExifVersion", version_},
        {"ISOSpeedLatitudeyyy", singleInt_},
        {"ISOSpeedLatitudezzz", singleInt_},
        {"ComponentsConfiguration", singleInt_},
        {"ComponentsConfiguration", channel_},
        {"PhotographicSensitivity", singleInt_},
        {"FlashpixVersion", singleInt_},
        {"FlashpixVersion", version_},
        {"PhotoMode", singleInt_},
        {"JPEGProc", singleInt_},
        {"HwMnoteCaptureMode", singleInt_},
        {"HwMnoteIsXmageSupported", singleInt_},
        {"HwMnoteXmageMode", singleInt_},
        {"HwMnoteXmageLeft", singleInt_},
        {"HwMnoteXmageTop", singleInt_},
        {"HwMnoteXmageRight", singleInt_},
        {"HwMnoteXmageBottom", singleInt_},
        {"HwMnoteCloudEnhancementMode", singleInt_},
        {"HwMnoteAiEdit", singleInt_},
        {"DateTimeDigitized", dateTimeValidation_},
        {"DateTimeDigitized", dateValidation_},
        {"OffsetTime", dateTimeValidation_},
        {"OffsetTime", dateValidation_},
        {"SubjectArea", doubleIntWithBlank_},
        {"SubjectArea", doubleIntWithComma_},
        {"SourceImageNumberOfCompositeImage", doubleIntWithBlank_},
        {"SourceImageNumberOfCompositeImage", doubleIntWithComma_},
        {"YCbCrSubSampling", doubleIntWithBlank_},
        {"YCbCrSubSampling", doubleIntWithComma_},
        {"MovingPhotoVersion", singleInt_},
        {"MicroVideoPresentationTimestampUS", singleInt_},
    };
}

void ExifMetadatFormatter::InitValueTemplateConfig()
{
    valueTemplateConfig_ = {
        {"ExposureTime", "(\\d+/\\d+) sec\\."},
        {"ExposureTime", "(\\d+\\.\\d+|\\d+) sec\\."},
        {"FNumber", "f/(\\d+\\.\\d+)"},
        {"ApertureValue", "(\\d+\\.\\d+) EV \\(f/\\d+\\.\\d+\\)"},
        {"ExposureBiasValue", "(\\d+\\.\\d+) EV"},
        {"FocalLength", "(\\d+\\.\\d+) mm"},
        {"ShutterSpeedValue", "(\\d+\\.\\d+) EV \\(\\d+/\\d+ sec\\.\\)"},
        {"BrightnessValue", "(\\d+\\.\\d+) EV \\(\\d+\\.\\d+ cd/m\\^\\d+\\)"},
        {"MaxApertureValue", "(\\d+\\.\\d+) EV \\(f/\\d+\\.\\d+\\)"},
        {"SubjectDistance", "(\\d+\\.\\d+) m"},
        {"SubjectArea", "\\(x,y\\) = \\((\\d+,\\d+)\\)"},
        {"ExifVersion", "Exif Version ([0-9]{1,2}\\.[0-9]{1,2})"},
        {"FlashpixVersion", "FlashPix Version ([0-9]{1,2}\\.[0-9]{1,2})"},
        {"Copyright", "^(.*) \\(Photographer\\) \\- \\[None\\] \\(Editor\\)$"},
    };
}

const size_t DECIMAL_BASE = 10;
const std::string COMMA_REGEX("\\,"), COLON_REGEX("\\:"), DOT_REGEX("\\.");
const std::set<std::string> UINT16_KEYS = {
    "ImageLength", "ImageWidth", "ISOSpeedRatings", "ISOSpeedRatings",
    "FocalLengthIn35mmFilm", "SamplesPerPixel", "PhotographicSensitivity"
};

const auto SINGLE_RATIONAL_REGEX = R"(^[0-9]+/[1-9][0-9]*$)";
const auto SINGLE_INT_REGEX = R"(^\s*[0-9]+$)";
const auto SINGLE_DECIMAL_REGEX = "\\s*(\\d+)(\\.\\d+)?";
const auto DOUBLE_INT_WITH_BLANK_REGEX = R"(^[0-9]+\s*[0-9]+$)";
const auto DOUBLE_INT_WITH_COMMA_REGEX = R"(^[0-9]+,\s*[0-9]+$)";
const auto DOUBLE_VALUE_REGEX = "(\\d+)(\\.\\d+)?(/\\d+)?(,)?\\s*(\\d+)(\\.\\d+)?(/\\d+)?";
const auto TRIBLE_INT_WITH_BLANK_REGEX = R"(^[0-9]+\s[0-9]+\s[0-9]+$)";
const auto TRIBLE_INT_WITH_COMMA_REGEX = R"(^\s*[0-9]+,\s*[0-9]+,\s*[0-9]+$)";
const auto TRIBLE_RATIONAL_WITH_BLANK_REGEX = R"(^[0-9]+/[1-9][0-9]*\s[0-9]+/[1-9][0-9]*\s[0-9]+/[1-9][0-9]*$)";
const auto TRIBLE_DECIMAL_WITH_BLANK_REGEX = "(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?";
const auto TRIBLE_DECIMAL_WITH_COMMA_REGEX = "(\\d+)(\\.\\d+)?,\\s*(\\d+)(\\.\\d+)?,\\s*(\\d+)(\\.\\d+)?";
const auto TRIBLE_MIX_WITH_COMMA_REGEX = "^\\s*\\d+(\\.\\d+)?(,\\s*\\d+(\\.\\d+)?)*\\s*$";
const auto TRIBLE_INT_WITH_COLON_REGEX = R"(^[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*$)";
const auto TRIBLE_INT_WITH_DOT_REGEX = R"(^[0-9]+.[0-9]+.[0-9]+.[0-9]+$)";
const auto FOUR_INT_WITH_BLANK_REGEX = R"(^[0-9]+\s[0-9]+\s[0-9]+\s[0-9]+$)";
const auto FOUR_INT_WITH_COMMA_REGEX = R"(^[0-9]+,\s*[0-9]+,\s*[0-9]+,\s*[0-9]+$)";
const auto FOUR_RATIONAL_WITH_BLANK_REGEX =
    R"(^[0-9]+/[1-9][0-9]*\s[0-9]+/[1-9][0-9]*\s[0-9]+/[1-9][0-9]*\s[0-9]+/[1-9][0-9]*$)";
const auto FOUR_DECIMAL_WITH_BLANK_REGEX = "(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?";
const auto FOUR_DECIMAL_WITH_COMMA_REGEX = "(\\d+)(\\.\\d+)?(,\\s*(\\d+)(\\.\\d+)?){3}";
const auto SIX_DECIMAL_WITH_BLANK_REGEX =
    "(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?";
const auto SIX_DECIMAL_WITH_COMMA_REGEX = "\\s*(\\d+)(\\.\\d+)?(,\\s*(\\d+)(\\.\\d+)?){5}";
const auto TIMESTAMP_REGEX = "^\\d+:\\d+:\\d+(\\.\\d+)$";
const auto DATETIME_REGEX =
    R"(^[0-9]{4}:(0[1-9]|1[012]):(0[1-9]|[12][0-9]|3[01])\s([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$)";
const auto DATE_REGEX = R"(^[0-9]{4}:(0[1-9]|1[012]):(0[1-9]|[12][0-9]|3[01])$)";
const auto VERSION_REGEX = R"(^[0-9]+\.[0-9]+$)";
const auto CHANNEL_REGEX = R"(^[-YCbCrRGB]+(\s[-YCbCrRGB]+)+$)";
const auto SENSITIVE_REGEX = R"(gps|lati|longi)";

/*
 * validate the key is in value range array.
 * For example GPSLatitudeRef value should be 'N' or 'S' in exifGPSLatitudeRef array.
 */
bool ExifMetadatFormatter::IsValidValue(const TagDetails *array, const size_t &size, const int64_t &key)
{
    if (array == nullptr) {
        return false;
    }

    for (size_t i = 0; i < size; i++) {
        if (array[i].val_ == key) {
            return true;
        }
    }
    return false;
}

// validate regex only
bool ExifMetadatFormatter::ValidRegex(const std::string &value, const std::string &regex)
{
    IMAGE_LOGD("Validating against regex: %{public}s", regex.c_str());
    std::regex ratPattern(regex);
    if (!std::regex_match(value, ratPattern)) {
        IMAGE_LOGD("Validation failed.Regex: %{public}s", regex.c_str());
        return false;
    }
    return true;
}

// replace as space according to regex
void ExifMetadatFormatter::ReplaceAsSpace(std::string &value, const std::string &regex)
{
    std::regex pattern(regex);
    value = std::regex_replace(value, pattern, " ");
}

void ExifMetadatFormatter::ReplaceAsContent(std::string &value, const std::string &regex, const std::string &content)
{
    std::regex pattern(regex);
    value = std::regex_replace(value, pattern, content);
}

// validate the regex & replace comma as space
bool ExifMetadatFormatter::ValidRegexWithComma(std::string &value, const std::string &regex)
{
    IMAGE_LOGD("Validating comma against regex: %{public}s", regex.c_str());
    if (!ValidRegex(value, regex)) {
        return false;
    }
    ReplaceAsSpace(value, COMMA_REGEX);
    return true;
}

// convert integer to rational format. For example 23 15 83 --> 23/1 15/1 83/1
void ExifMetadatFormatter::RationalFormat(std::string &value)
{
    std::regex pattern("\\d+"); // regex for integer
    std::string result;
    int icount = 0;
    while (std::regex_search(value, pattern)) {
        std::smatch match;
        if (!std::regex_search(value, match, pattern)) {
            break; // break since there is no matched value
        }
        if (icount != 0) {
            result += " ";
        }
        result += match.str() + "/1"; // appending '/1' to integer
        value = match.suffix().str(); // skip handled value part
        icount++;
    }
    value = result;
}

static bool ConvertToDouble(const std::string& str, double& value)
{
    errno = 0;
    char* endPtr = nullptr;
    value = strtod(str.c_str(), &endPtr);
    if (errno == ERANGE && *endPtr != '\0') {
        return false;
    }
    return true;
}

// convert decimal to rational string. 2.5 -> 5/2
std::string ExifMetadatFormatter::GetFractionFromStr(const std::string &decimal, bool &isOutRange)
{
    // check int part out of range
    std::string inPareStr = decimal.substr(0, decimal.find("."));
    int intPart = 0;
    auto [p, ec] = std::from_chars(inPareStr.data(), inPareStr.data() + inPareStr.size(), intPart);
    if (ec != std::errc()) {
        IMAGE_LOGE("GetFractionFromStr failed, value is out of range");
        isOutRange = true;
        return "";
    }

    double decPart = 0.0;
    std::string decPartStr = decimal.substr(decimal.find("."));
    if (!ConvertToDouble(decPartStr, decPart)) {
        IMAGE_LOGE("%{public}s failed, value out of range", __func__);
        isOutRange = true;
        return "";
    }

    int numerator = decPart * pow(DECIMAL_BASE, decimal.length() - decimal.find(".") - 1);
    int denominator = pow(DECIMAL_BASE, decimal.length() - decimal.find(".") - 1);

    int gcdVal = ExifMetadatFormatter::Gcd(numerator, denominator);
    if (gcdVal == 0) {
        return std::to_string(numerator + intPart * denominator) + "/" + std::to_string(denominator);
    }
    numerator /= gcdVal;
    denominator /= gcdVal;

    numerator += intPart * denominator;

    return std::to_string(numerator) + "/" + std::to_string(denominator);
}

// convert decimal to rational format. For example 2.5 -> 5/2
bool ExifMetadatFormatter::ValidDecimalRationalFormat(std::string &value)
{
    std::string result;
    int icount = 0;
    std::regex parPattern("(\\d+)(\\.\\d+)?");

    // with partial regex For 2.5 26 1.2 to iterator each segment 2.5->5/2
    for (std::sregex_iterator it = std::sregex_iterator(value.begin(), value.end(), parPattern);
        it != std::sregex_iterator(); ++it) {
        std::smatch match = *it;

        // add a space at begin of each segment except the first segment
        if (icount != 0) {
            result += " ";
        }

        // 1.if segment is integer type 123->123/1
        if (ValidRegex(match[0], "\\d+")) {
            // append '/1' to integer 23 -> 23/1
            result += match.str() + "/1";
        }
        if (ValidRegex(match[0], "\\d+\\.\\d+")) {
            // segment is decimal call decimalToFraction 2.5 -> 5/2
            bool isOutRange = false;
            auto tmpRes = GetFractionFromStr(match[0], isOutRange);
            if (isOutRange) {
                return false;
            }
            result += tmpRes;
        }
        icount++;
    }
    value = result;
    return true;
}

bool ExifMetadatFormatter::ValidConvertRationalFormat(std::string &value)
{
    std::string result;
    int icount = 0;
    std::regex parPattern("\\d+(\\.\\d+)?(/\\d+)?");

    // with partial regex For 2.5 26 1.2 to iterator each segment 2.5->5/2
    for (std::sregex_iterator it = std::sregex_iterator(value.begin(), value.end(), parPattern);
        it != std::sregex_iterator(); ++it) {
        std::smatch match = *it;

        // add a space at begin of each segment except the first segment
        if (icount != 0) {
            result += " ";
        }

        // 1.if segment is integer type 123->123/1
        if (ValidRegex(match[0], "\\d+")) {
            // append '/1' to integer 23 -> 23/1
            result += match.str() + "/1";
        }
        if (ValidRegex(match[0], "\\d+/\\d+")) {
            result += match.str();
        }
        if (ValidRegex(match[0], "\\d+\\.\\d+")) {
            // segment is decimal call decimalToFraction 2.5 -> 5/2
            bool isOutRange = false;
            auto tmpRes = GetFractionFromStr(match[0], isOutRange);
            if (isOutRange) {
                return false;
            }
            result += tmpRes;
        }
        icount++;
    }
    value = result;
    return true;
}

// validate regex & convert integer to rational format. For example 23 15 83 --> 23/1 15/1 83
bool ExifMetadatFormatter::ValidRegexWithRationalFormat(std::string &value, const std::string &regex)
{
    // 1.validate regex
    if (!ValidRegex(value, regex)) {
        return false;
    }

    // 2.convert integer to rational format. 9 9 9 -> 9/1 9/1 9/1
    RationalFormat(value);
    return true;
}

// validate regex & convert value to rational format. For example 9,9,9 -> 9 9 9 -> 9/1 9/1 9/1
bool ExifMetadatFormatter::ValidRegexWithCommaRationalFormat(std::string &value, const std::string &regex)
{
    // 1.validate regex
    if (!ValidRegex(value, regex)) {
        return false;
    }

    // 2.replace comma as a space
    ReplaceAsSpace(value, COMMA_REGEX);

    // 3.convert integer to rational format. 9 9 9 -> 9/1 9/1 9/1
    RationalFormat(value);
    return true;
}

// validate regex & convert value to rational format. For example 9:9:9 -> 9 9 9 -> 9/1 9/1 9/1
bool ExifMetadatFormatter::ValidRegexWithColonRationalFormat(std::string &value, const std::string &regex)
{
    // 1.validate regex
    if (!ValidRegex(value, regex)) {
        return false;
    }

    // 2.replace colon as a space
    ReplaceAsSpace(value, COLON_REGEX);

    // 3.convert integer to rational format. 9 9 9 -> 9/1 9/1 9/1
    RationalFormat(value);
    return true;
}

// validate regex & convert value to integer format.
bool ExifMetadatFormatter::ValidRegexWithDot(std::string &value, const std::string &regex)
{
    if (!ValidRegex(value, regex)) {
        return false;
    }
    ReplaceAsContent(value, DOT_REGEX, "");
    return true;
}

// regex validation & convert decimal to rational. For example GPSLatitude 2.5,23,3.4 -> 2.5 23 3.4 -> 5/2 23/1 17/5
bool ExifMetadatFormatter::ValidRegxWithCommaDecimalRationalFormat(std::string &value, const std::string &regex)
{
    if (!ValidRegex(value, regex)) {
        return false;
    }

    // replace comma with a space 1.5,2.5.3 -> 1.5 2.5 3
    ReplaceAsSpace(value, COMMA_REGEX);

    // convert decimal to rationl 2.5 -> 5/2
    return ValidDecimalRationalFormat(value);
}

bool ExifMetadatFormatter::ValidRegxAndConvertRationalFormat(std::string &value, const std::string &regex)
{
    if (!ValidRegex(value, regex)) {
        return false;
    }

    // replace comma with a space 1.5,2.5.3 -> 1.5 2.5 3
    ReplaceAsSpace(value, COMMA_REGEX);

    // replace colon
    ReplaceAsSpace(value, COLON_REGEX);

    return ValidConvertRationalFormat(value);
}


// regex validation & convert decimal to rational. For example GPSLatitude 2.5 23 3.4 -> 5/2 23/1 17/5
bool ExifMetadatFormatter::ValidRegexWithDecimalRationalFormat(std::string &value, const std::string &regex)
{
    if (!ValidRegex(value, regex)) {
        return false;
    }

    // convert decimal to rationl 2.5 -> 5/2
    return ValidDecimalRationalFormat(value);
}

bool ExifMetadatFormatter::ValidRegexWithVersionFormat(std::string &value, const std::string &regex)
{
    if (!ValidRegex(value, regex)) {
        return false;
    }

    std::string result;
    std::regex parPattern("[0-9]{1,2}");

    int icount = 0;
    for (std::sregex_iterator it = std::sregex_iterator(value.begin(), value.end(), parPattern);
        it != std::sregex_iterator(); ++it) {
        std::smatch match = *it;
        std::string tmp = match[0].str();
        if (icount == 0 && tmp.length() == 1) {
            result += "0" + tmp;
        } else if (icount == 1 && tmp.length() == 1) {
            result += tmp + "0";
        } else {
            result += tmp;
        }
        icount++;
    }
    value = result;
    return true;
}

bool ExifMetadatFormatter::ValidRegexWithChannelFormat(std::string &value, const std::string &regex)
{
    if (!ValidRegex(value, regex)) {
        return false;
    }

    std::string result;
    std::regex parPattern("[-YCbCrRGB]+");

    for (std::sregex_iterator it = std::sregex_iterator(value.begin(), value.end(), parPattern);
        it != std::sregex_iterator(); ++it) {
        std::smatch match = *it;
        std::string tmp = match[0].str();
        if (tmp == "-") {
            result += "0";
        } else if (tmp == "Y") {
            result += "1";
        } else if (tmp == "Cb") {
            result += "2";
        } else if (tmp == "Cr") {
            result += "3";
        } else if (tmp == "R") {
            result += "4";
        } else if (tmp == "G") {
            result += "5";
        } else if (tmp == "B") {
            result += "6";
        }
    }
    value = result;
    return true;
}

void ExifMetadatFormatter::InitDelegates()
{
    singleInt_ = std::make_pair(ValidRegex, SINGLE_INT_REGEX);

    // regex validation for two integer like DefaultCropSize 9 9 the format is [0-9]+ [0-9]+
    doubleIntWithBlank_ = std::make_pair(ValidRegex, DOUBLE_INT_WITH_BLANK_REGEX);

    // regex validation for two integer with comma like BitPerSample 9,9 the format is [0-9]+,[0-9]+,[0-9]+
    doubleIntWithComma_ = std::make_pair(ValidRegexWithComma, DOUBLE_INT_WITH_COMMA_REGEX);

    // regex validation for three integer like BitPerSample 9 9 9 the format is [0-9]+ [0-9]+ [0-9]+
    tribleIntWithBlank_ = std::make_pair(ValidRegex, TRIBLE_INT_WITH_BLANK_REGEX);

    // regex validation for three integer with comma like BitPerSample 9,9,0 the format is [0-9]+,[0-9]+,[0-9]+,[0-9]+
    tribleIntWithComma_ = std::make_pair(ValidRegexWithComma, TRIBLE_INT_WITH_COMMA_REGEX);

    // regex validation for four integer like DNGVersion 9 9 9 9 the format is [0-9]+ [0-9]+ [0-9]+ [0-9]+
    fourIntWithBlank_ = std::make_pair(ValidRegex, FOUR_INT_WITH_BLANK_REGEX);

    // regex validation for four integer with comma like DNGVersion tag encodes the DNG four-tier version number
    fourIntWithComma_ = std::make_pair(ValidRegexWithComma, FOUR_INT_WITH_COMMA_REGEX);

    // regex validation for one rational like ApertureValue 4/1 the format is [0-9]+/[1-9][0-9]
    singleRational_ = std::make_pair(ValidRegex, SINGLE_RATIONAL_REGEX);

    // regex validation for integer and convert it to rational like ApertureValue 4 --> 4/1
    singleIntToRational_ = std::make_pair(ValidRegexWithRationalFormat, SINGLE_INT_REGEX);

    singleDecimalToRational_ = std::make_pair(ValidRegexWithDecimalRationalFormat, SINGLE_DECIMAL_REGEX);

    doubleIntToOneRationalWithComma_ = std::make_pair(ValidRegexWithGpsOneRationalFormat, DOUBLE_INT_WITH_COMMA_REGEX);

    doubleValueToRational_ = std::make_pair(ValidRegxAndConvertRationalFormat, DOUBLE_VALUE_REGEX);

    // regex validation for three rational like GPSLatitude 39/1 54/1 20/1
    tribleRationalWithBlank_ = std::make_pair(ValidRegex, TRIBLE_RATIONAL_WITH_BLANK_REGEX);

    // regex validation for three integer and convert to three rational like GPSLatitude 39 54 20 --> 39/1 54/1 20/1
    tribleIntToRationalWithBlank_ = std::make_pair(ValidRegexWithRationalFormat, TRIBLE_INT_WITH_BLANK_REGEX);

    // regex validation for three integer with comma like GPSLatitude 39,54,20 --> 39/1 54/1 20/1
    tribleIntToRationalWithComma_ = std::make_pair(ValidRegexWithCommaRationalFormat, TRIBLE_INT_WITH_COMMA_REGEX);

    // regex validation for three decimal like YCbCrCoefficients 39.0 54 20.0 --> 39/1 54/1 20/1
    tribleDecimalToRationalWithBlank_ =
        std::make_pair(ValidRegexWithDecimalRationalFormat, TRIBLE_DECIMAL_WITH_BLANK_REGEX);

    // regex validation for three decimal like YCbCrCoefficients 39.0,54,20.0 --> 39.0 54 20.0 --> 39/1 54/1 20/1
    tribleDecimalToRatiionalWithComma_ =
        std::make_pair(ValidRegxWithCommaDecimalRationalFormat, TRIBLE_DECIMAL_WITH_COMMA_REGEX);

    // regex validation for three decimal like GPS 10, 20, 20.123 --> 10 20 20.123 --> 10/1 20/1 20.123/1
    tribleMixToRationalWithComma_ =
        std::make_pair(ValidRegxWithCommaDecimalRationalFormat, TRIBLE_MIX_WITH_COMMA_REGEX);

    // regex validation for four rational like LensSpecification 1/1 3/2 1/1 2/1
    fourRationalWithBlank_ = std::make_pair(ValidRegex, FOUR_RATIONAL_WITH_BLANK_REGEX);

    // regex validation for four integer and convert to four rational like LensSpecification 1 3 1 2 --> 1/1 3/2 1/1 2/1
    fourIntToRationalWithBlank_ = std::make_pair(ValidRegexWithRationalFormat, FOUR_INT_WITH_BLANK_REGEX);

    // regex validation for four integer like LensSpecification 1,3,1,2 --> 1/1 3/2 1/1 2/1
    fourIntToRationalWithComma_ = std::make_pair(ValidRegexWithCommaRationalFormat, FOUR_INT_WITH_COMMA_REGEX);

    // regex validation for four decimal like LensSpecification 1.0 3.0 1.0 2.0 --> 1/1 3/1 2/1
    fourDecimalToRationalWithBlank_ =
        std::make_pair(ValidRegexWithDecimalRationalFormat, FOUR_DECIMAL_WITH_BLANK_REGEX);

    // regex validation for four decimal like LensSpecification 1.0,3.0,1.0,2.0 --> 1/1 3/1 2/1
    fourDecimalToRationalWithComma_ =
        std::make_pair(ValidRegxWithCommaDecimalRationalFormat, FOUR_DECIMAL_WITH_COMMA_REGEX);

    // regex validation for datetime format like DateTimeOriginal 2022:06:02 15:51:34
    dateTimeValidation_ = std::make_pair(ValidRegex, DATETIME_REGEX);

    // regex validation for datetime format like DateTimeOriginal 2022:06:02
    dateValidation_ = std::make_pair(ValidRegex, DATE_REGEX);

    // regex validation for three integer like GPSLatitude 39,54,21 --> 39/1 54/1 21/1
    tribleIntToRationalWithColon_ =
        std::make_pair(ValidRegexWithColonRationalFormat, TRIBLE_INT_WITH_COLON_REGEX);

    timeStamp_ = std::make_pair(ValidRegexWithDecimalRationalFormat, TIMESTAMP_REGEX);

    // regex validation for fou integer with pointer like GPSVersionID
    fourIntWithDot_ = std::make_pair(ValidRegexWithDot, TRIBLE_INT_WITH_DOT_REGEX);

    sixDecimalToRationalWithBlank_ = std::make_pair(ValidRegexWithDecimalRationalFormat, SIX_DECIMAL_WITH_BLANK_REGEX);

    sixDecimalToRationalWithComma_ = std::make_pair(ValidRegexWithDecimalRationalFormat, SIX_DECIMAL_WITH_COMMA_REGEX);

    version_ = std::make_pair(ValidRegexWithVersionFormat, VERSION_REGEX);

    channel_ = std::make_pair(ValidRegexWithChannelFormat, CHANNEL_REGEX);
}

bool ExifMetadatFormatter::ValidRegexWithGpsOneRationalFormat(std::string &value, const std::string &regex)
{
    IMAGE_LOGD("validate gps with one rational.");
    if (!ValidRegex(value, regex)) {
        return false;
    }
    std::vector<std::string> vec;
    SplitStr(value, ",", vec);
    if (vec.size() != GPS_DEGREE_SIZE) {
        IMAGE_LOGD("Gps degree data size is invalid.");
        return false;
    }
    value = vec[0] + "/" + vec[1] + " 0/1 0/1";
    return true;
}

// validate the value range. For example GPSLatitudeRef the value must be 'N' or 'S'.
int32_t ExifMetadatFormatter::ValidateValueRange(const std::string &keyName, const std::string &value)
{
    // 1. to find if any value range validation configuratiion according to exif tag in std::map container
    auto iter = ExifMetadatFormatter::GetInstance().valueRangeValidateConfig_.find(keyName);
    if (iter == ExifMetadatFormatter::GetInstance().valueRangeValidateConfig_.end()) {
        // if no range validation for key default is success.
        return Media::SUCCESS;
    }

    // get value range array & size
    auto &[arrRef, arrSize] = iter->second;
    if (arrRef == nullptr) {
        return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    int32_t ivalue = -1;

    // validate value if integer or char 2.char ascii
    std::regex regNum(R"(^[0-9]+$)");    // regex for integer value. For example WhiteBalance support 0 or 1
    std::regex regChar(R"(^[a-zA-Z]$)"); // regex for char value. For example GPSLatitudeRef support N or S
    if (std::regex_match(value, regNum)) {
        // convert string to integer such as "15" -> 15  and check ll out of range
        auto [p, ec] = std::from_chars(value.data(), value.data() + value.size(), ivalue);
        if (ec != std::errc()) {
            return Media::ERR_MEDIA_OUT_OF_RANGE;
        }
    }
    if (std::regex_match(value, regChar)) {
        // convert char to integer such as "N" -> 78
        ivalue = static_cast<int32_t>(value[0]);
    }

    // if ivalue is not converted then return FAIL
    if (ivalue == -1) {
        return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    // validate the ivalue is in value range array.
    auto isValid = IsValidValue(arrRef, arrSize, ivalue);
    if (!isValid) {
        return Media::ERR_MEDIA_OUT_OF_RANGE;
    } else {
        return Media::SUCCESS;
    }
    return Media::SUCCESS;
}

void ExifMetadatFormatter::ConvertRangeValue(const std::string &keyName, std::string &value)
{
    if (keyName == "FileSource" && value == "DSC") {
        value = "3";
        return;
    }
    auto iter = ExifMetadatFormatter::GetInstance().valueRangeValidateConfig_.find(keyName);
    if (iter == ExifMetadatFormatter::GetInstance().valueRangeValidateConfig_.end()) {
        return;
    }

    // get value range array & size
    auto &[arrRef, arrSize] = iter->second;
    if (arrRef == nullptr) {
        return;
    }
    // iterator arrRef to get value
    for (size_t i = 0; i < arrSize; i++) {
        if (arrRef[i].label_ == value) {
            value = std::to_string(arrRef[i].val_);
            break;
        }
    }
}

const std::set<std::string> FORBIDDEN_VALUE = {
    "^Internal error \\(unknown value \\d+\\)$",
    "^\\d+ bytes undefined data$",
    "Unknown FlashPix Version",
    "Unknown Exif Version",
    "Unknown value \\d+",
};

bool ExifMetadatFormatter::IsForbiddenValue(const std::string &value)
{
    for (const auto &regex : FORBIDDEN_VALUE) {
        std::regex ratPattern(regex);
        if (std::regex_match(value, ratPattern)) {
            return true;
        }
    }
    return false;
}

void ExifMetadatFormatter::ExtractValue(const std::string &keyName, std::string &value)
{
    auto it = ExifMetadatFormatter::GetInstance().valueTemplateConfig_.find(keyName);
    if (it == ExifMetadatFormatter::GetInstance().valueTemplateConfig_.end()) {
        return;
    }
    for (; it != ExifMetadatFormatter::GetInstance().valueTemplateConfig_.end() &&
        it != ExifMetadatFormatter::GetInstance().valueTemplateConfig_.upper_bound(keyName);
        it++) {
        std::regex pattern(it->second);
        for (std::sregex_iterator i = std::sregex_iterator(value.begin(), value.end(), pattern);
            i != std::sregex_iterator();
            ++i) {
            std::smatch match = *i;
            std::string subStr = match[1].str();
            if (!subStr.empty()) {
                value = subStr;
            }
        }
    }
}


// validate value format. For example BitPerSample the value format should be 9 9 9 or 9,9,9
int32_t ExifMetadatFormatter::ConvertValueFormat(const std::string &keyName, std::string &value)
{
    if (IsSensitiveInfo(keyName)) {
        IMAGE_LOGD("ConvertValueFormat keyName is [%{public}s].", keyName.c_str());
    } else {
        IMAGE_LOGD("ConvertValueFormat keyName is [%{public}s] value is [%{public}s].", keyName.c_str(), value.c_str());
    }

    auto it = ExifMetadatFormatter::GetInstance().valueFormatConvertConfig_.find(keyName);
    if (it == ExifMetadatFormatter::GetInstance().valueFormatConvertConfig_.end()) {
        IMAGE_LOGD("No format validation needed. Defaulting to success.");
        return Media::SUCCESS;
    }
    IMAGE_LOGD("Validating value format. Key: %{public}s", keyName.c_str());

    // get first iterator according to keyName
    for (; it != ExifMetadatFormatter::GetInstance().valueFormatConvertConfig_.end() &&
        it != ExifMetadatFormatter::GetInstance().valueFormatConvertConfig_.upper_bound(keyName);
        it++) {
        IMAGE_LOGD("Validating value format in loop. Key: %{public}s, Regex: %{public}s", (it->first).c_str(),
            (it->second).second.c_str());
        auto func = (it->second).first;

        // call each value format function with value and regex
        int32_t isValid = func(value, (it->second).second);
        IMAGE_LOGD("Validation result: %{public}d", isValid);
        if (isValid) {
            IMAGE_LOGD("Validation successful.");
            return Media::SUCCESS;
        }
    }

    IMAGE_LOGD("Validation failed. Unsupported EXIF format.");
    return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
}

bool ExifMetadatFormatter::IsKeySupported(const std::string &keyName)
{
    auto wit = READ_WRITE_KEYS.find(keyName);
    auto rit = READ_ONLY_KEYS.find(keyName);
    return (wit != READ_WRITE_KEYS.end() || rit != READ_ONLY_KEYS.end());
}

const std::set<std::string> &ExifMetadatFormatter::GetRWKeys()
{
    return READ_WRITE_KEYS;
}

const std::set<std::string> &ExifMetadatFormatter::GetROKeys()
{
    return READ_ONLY_KEYS;
}

bool ExifMetadatFormatter::IsModifyAllowed(const std::string &keyName)
{
    auto it = READ_WRITE_KEYS.find(keyName);
    return (it != READ_WRITE_KEYS.end());
}

std::pair<int32_t, std::string> ExifMetadatFormatter::Format(const std::string &keyName, const std::string &value)
{
    if (IsSensitiveInfo(keyName)) {
        IMAGE_LOGD("Processing. Key: %{public}s.", keyName.c_str());
    } else {
        IMAGE_LOGD("Processing. Key: %{public}s, Value: %{public}s.", keyName.c_str(), value.c_str());
    }
    std::string tmpValue = value;

    if (!ExifMetadatFormatter::IsKeySupported(keyName)) {
        IMAGE_LOGD("Key is not supported.");
        return std::make_pair(Media::ERR_MEDIA_WRITE_PARCEL_FAIL, "");
    }

    if (!ExifMetadatFormatter::IsModifyAllowed(keyName)) {
        IMAGE_LOGD("Key is not allowed to modify.");
        return std::make_pair(Media::ERR_MEDIA_WRITE_PARCEL_FAIL, "");
    }

    if (ExifMetadatFormatter::IsForbiddenValue(tmpValue)) {
        return std::make_pair(Media::ERR_MEDIA_VALUE_INVALID, "");
    }
    ExifMetadatFormatter::ConvertRangeValue(keyName, tmpValue);
    ExifMetadatFormatter::ExtractValue(keyName, tmpValue);

    // 1.validate value format
    if (ExifMetadatFormatter::ConvertValueFormat(keyName, tmpValue)) {
        IMAGE_LOGD("Invalid value format for key：%{public}s.", keyName.c_str());
        // value format validate does not pass
        return std::make_pair(Media::ERR_MEDIA_VALUE_INVALID, "");
    }
    IMAGE_LOGD("Processed format value. Key: %{public}s", keyName.c_str());

    // 2.validate value range
    if (ExifMetadatFormatter::ValidateValueRange(keyName, tmpValue)) {
        IMAGE_LOGD("Invalid value range for Key: %{public}s.", keyName.c_str());
        // value range validate does not pass
        return std::make_pair(Media::ERR_MEDIA_VALUE_INVALID, "");
    }
    return std::make_pair(Media::SUCCESS, tmpValue);
}

static bool ConvertToInt(const std::string& str, int& value)
{
    auto [ptr, errCode] = std::from_chars(str.data(), str.data() + str.size(), value);
    bool ret = errCode == std::errc{} && (ptr == str.data() + str.size());
    return ret;
}

static bool StrToDouble(const std::string &value, double &output)
{
    if (value.empty()) {
        return false;
    }
    size_t slashPos = value.find('/');
    if (slashPos == std::string::npos) {
        IMAGE_LOGE("StrToDouble split error");
        return false;
    }
    std::string numeratorStr = value.substr(0, slashPos);
    std::string denominatorStr = value.substr(slashPos + 1);
    int numerator = 0;
    if (!ConvertToInt(numeratorStr, numerator)) {
        IMAGE_LOGI("numeratorStr = %{public}s convert convert string to int failed", numeratorStr.c_str());
        return false;
    }
    int denominator = 0;
    if (!ConvertToInt(denominatorStr, denominator)) {
        IMAGE_LOGI("denominatorStr = %{public}s convert convert string to int failed", denominatorStr.c_str());
        return false;
    }
    if (denominator == 0) {
        return false;
    }
    output = static_cast<double>(numerator) / denominator;
    return true;
}

static bool ValidLatLong(const std::string &key, const std::string &value)
{
    IMAGE_LOGD("ValidLatLong key is %{public}s", key.c_str());

    double degree = 0.0;
    double minute = 0.0;
    double second = 0.0;

    std::vector<std::string> tokens;
    SplitStr(value, " ", tokens);
    if (tokens.size() != GPS_NORMAL_SIZE) {
        IMAGE_LOGE("value size is not 3. token size %{public}lu", static_cast<unsigned long>(tokens.size()));
        return false;
    }
    if (!StrToDouble(tokens[CONSTANT_0], degree) || !StrToDouble(tokens[CONSTANT_1], minute) ||
        !StrToDouble(tokens[CONSTANT_2], second)) {
        IMAGE_LOGE("Convert gps data to double type failed.");
        return false;
    }
    constexpr uint32_t timePeriod = 60;
    double latOrLong = degree + minute / timePeriod + second / (timePeriod * timePeriod);

    if (key == "GPSLatitude" && (latOrLong > GPS_MAX_LATITUDE || latOrLong < GPS_MIN_LATITUDE)) {
        IMAGE_LOGE("GPSLatitude is out of range.");
        return false;
    }
    if (key == "GPSLongitude" && (latOrLong > GPS_MAX_LONGITUDE || latOrLong < GPS_MIN_LONGITUDE)) {
        IMAGE_LOGE("GPSLongitude is out of range.");
        return false;
    }
    return true;
}

static bool IsUint16(const std::string &s)
{
    std::istringstream iss(s);
    uint16_t num;
    iss >> num;
    return !iss.fail() && iss.eof();
}

// exif validation portal
int32_t ExifMetadatFormatter::Validate(const std::string &keyName, const std::string &value)
{
    if (IsSensitiveInfo(keyName)) {
        IMAGE_LOGD("Validating. Key: %{public}s", keyName.c_str());
    } else {
        IMAGE_LOGD("Validating. Key: %{public}s, Value: %{public}s.", keyName.c_str(), value.c_str());
    }
    auto result = ExifMetadatFormatter::Format(keyName, value);
    if (result.first) {
        IMAGE_LOGE("Validating Error %{public}d", result.first);
        return result.first;
    }

    if ((keyName == "GPSLatitude" || keyName == "GPSLongitude") &&
        !ValidLatLong(keyName, result.second)) {
        IMAGE_LOGE("Validating GPSLatLong Error");
        return ERR_MEDIA_VALUE_INVALID;
    }

    if ((UINT16_KEYS.find(keyName) != UINT16_KEYS.end()) &&
        !IsUint16(result.second)) {
        IMAGE_LOGE("Validating uint16 Error %{public}s", result.second.c_str());
        return ERR_MEDIA_VALUE_INVALID;
    }
    IMAGE_LOGD("Validate ret: %{public}d", result.first);
    return result.first;
}

bool ExifMetadatFormatter::IsSensitiveInfo(const std::string &keyName)
{
    std::regex pattern(SENSITIVE_REGEX, std::regex::icase);
    return std::regex_search(keyName, pattern);
}
} // namespace Media
} // namespace OHOS
