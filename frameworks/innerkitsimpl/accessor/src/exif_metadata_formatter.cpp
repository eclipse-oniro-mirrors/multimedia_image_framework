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
    "MovingPhotoId",
    "MovingPhotoVersion",
    "MicroVideoPresentationTimestampUS",
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
    "MakerNote",
};

// Orientation, tag 0x0112
constexpr TagDetails exifOrientation[] = {
    {1, "top, left"},     {2, "top, right"},   {3, "bottom, right"},
    {4, "bottom, left"},  {5, "left, top"},    {6, "right, top"},
    {7, "right, bottom" }, {8, "left, bottom"},
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
    {0, "Auto"},
    {1, "Manual"},
};

// Flash, Exif tag 0x9209
constexpr TagDetails exifFlash[] = {
    {0x00, "No flash"},
    {0x01, "Fired"},
    {0x05, "Fired, return light not detected"},
    {0x07, "Fired, return light detected"},
    {0x08, "Yes, did not fire"},
    {0x09, "Yes, compulsory"},
    {0x0d, "Yes, compulsory, return light not detected"},
    {0x0f, "Yes, compulsory, return light detected"},
    {0x10, "No, compulsory"},
    {0x14, "No, did not fire, return light not detected"},
    {0x18, "No, auto"},
    {0x19, "Yes, auto"},
    {0x1d, "Yes, auto, return light not detected"},
    {0x1f, "Yes, auto, return light detected"},
    {0x20, "No flash function"},
    {0x20, "No, no flash function"},
    {0x41, "Yes, red-eye reduction"},
    {0x45, "Yes, red-eye reduction, return light not detected"},
    {0x47, "Yes, red-eye reduction, return light detected"},
    {0x49, "Yes, compulsory, red-eye reduction"},
    {0x4d, "Yes, compulsory, red-eye reduction, return light not detected"},
    {0x4f, "Yes, compulsory, red-eye reduction, return light detected"},
    {0x50, "No, red-eye reduction"},
    {0x58, "No, auto, red-eye reduction"},
    {0x59, "Yes, auto, red-eye reduction"},
    {0x5d, "Yes, auto, red-eye reduction, return light not detected"},
    {0x5f, "Yes, auto, red-eye reduction, return light detected"},
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
    {3, "Tungsten (incandescent light)"},
    {4, "Flash"},
    {9, "Fine weather"},
    {10, "Cloudy weather"},
    {11, "Shade"},
    {12, "Daylight fluorescent (D 5700 - 7100K)"},
    {13, "Day white fluorescent (N 4600 - 5400K)"},
    {14, "Cool white fluorescent (W 3900 - 4500K)"},
    {15, "White fluorescent (WW 3200 - 3700K)"},
    {17, "Standard light A"},
    {18, "Standard light B"},
    {19, "Standard light C"},
    {20, "D55"},
    {21, "D65"},
    {22, "D75"},
    {23, "D50"},
    {24, "ISO studio tungsten"},
    {255, "Other light source"},
};

// MeteringMode, tag 0x9207
constexpr TagDetails exifMeteringMode[] = {
    {0, "Unknown"}, {1, "Average"},    {2, "Center weighted average"},
    {3, "Spot"},    {4, "Multi-spot"}, {5, "Multi-segment"},
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
    {5, "LZW"},
    {6, "JPEG (old-style)"},
    {7, "JPEG"},
    {8, "Adobe Deflate"},
    {9, "JBIG B&W"},
    {10, "JBIG Color"},
    {32766, "Next 2-bits RLE"},
    {32767, "Sony ARW Compressed"},
    {32769, "Epson ERF Compressed"},
    {32770, "Samsung SRW Compressed"},
    {32771, "CCITT RLE 1-word"},
    {32773, "PackBits (Macintosh RLE)"},
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
    {0, "White Is Zero"},
    {1, "Black Is Zero"},
    {2, "RGB"},
    {3, "RGB Palette"},
    {4, "Transparency Mask"},
    {5, "CMYK"},
    {6, "YCbCr"},
    {8, "CIELab"},
    {9, "ICCLab"},
    {10, "ITULab"},
    {32803, "Color Filter Array"},
    {32844, "Pixar LogL"},
    {32845, "Pixar LogLuv"},
    {34892, "Linear Raw"},
    {51177, "Depth Map"},        // DNG 1.5
    {52527, "Photometric Mask"}, // DNG 1.6
};

// PlanarConfiguration, tag 0x011c
constexpr TagDetails exifPlanarConfiguration[] = {
    {1, "Chunky"},
    {2, "Planar"},
};

// Units for measuring X and Y resolution, tags 0x0128, 0xa210
constexpr TagDetails exifUnit[] = {
    {1, "none"},
    {2, "inch"},
    {3, "cm"},
};

// YCbCrPositioning, tag 0x0213
constexpr TagDetails exifYCbCrPositioning[] = {
    {1, "Centered"},
    {2, "Co-sited"},
};

// ExposureProgram, tag 0x8822
constexpr TagDetails exifExposureProgram[] = {
    {0, "Not defined"},       {1, "Manual"},           {2, "Auto"},
    {3, "Aperture priority"}, {4, "Shutter priority"}, {5, "Creative program"},
    {6, "Action program"},    {7, "Portrait mode"},    {8, "Landscape mode"},
};

// SensingMethod, TIFF/EP tag 0x9217
constexpr TagDetails tiffSensingMethod[] = {
    {0, "Undefined"},           {1, "Monochrome area"},       {2, "One-chip color area"},
    {3, "Two-chip color area"}, {4, "Three-chip color area"}, {5, "Color sequential area"},
    {6, "Monochrome linear"},   {7, "Trilinear sensor"},      {8, "Color sequential linear"},
};

// CustomRendered, tag 0xa401
constexpr TagDetails exifCustomRendered[] = {
    {0, "Normal process"},
    {1, "Custom process"},
};

// ExposureMode, tag 0xa402
constexpr TagDetails exifExposureMode[] = {
    {0, "Auto"},
    {1, "Manual"},
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
    {0, "None"},          {1, "Low gain up"},    {2, "High gain up"},
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
    {1, "Low"},
    {2, "High"},
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
    {0, "Above sea level"},
    {1, "Below sea level"},
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

// configuratioin for value range validation. For example GPSLatitudeRef the value must be 'N' or 'S'.
std::map<std::string, std::tuple<const TagDetails *, const size_t>> ExifMetadatFormatter::valueRangeValidateConfig = {
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

const size_t DECIMAL_BASE = 10;
const std::string COMMA_REGEX("\\,"), COLON_REGEX("\\:"), DOT_REGEX("\\.");
const std::set<std::string> UINT16_KEYS = {
    "ImageLength", "ImageWidth", "ISOSpeedRatings", "ISOSpeedRatings",
    "FocalLengthIn35mmFilm", "SamplesPerPixel", "PhotographicSensitivity"
};

const auto SINGLE_RATIONAL_REGEX = R"(^[0-9]+/[1-9][0-9]*$)";
const auto SINGLE_INT_REGEX = R"(^[0-9]+$)";
const auto SINGLE_DECIMAL_REGEX = "(\\d+)(\\.\\d+)?";
const auto DOUBLE_INT_WITH_BLANK_REGEX = R"(^[0-9]+\s[0-9]+$)";
const auto DOUBLE_INT_WITH_COMMA_REGEX = R"(^[0-9]+,[0-9]+$)";
const auto TRIBLE_INT_WITH_BLANK_REGEX = R"(^[0-9]+\s[0-9]+\s[0-9]+$)";
const auto TRIBLE_INT_WITH_COMMA_REGEX = R"(^[0-9]+,(\s)?[0-9]+,(\s)?[0-9]+$)";
const auto TRIBLE_RATIONAL_WITH_BLANK_REGEX = R"(^[0-9]+/[1-9][0-9]*\s[0-9]+/[1-9][0-9]*\s[0-9]+/[1-9][0-9]*$)";
const auto TRIBLE_DECIMAL_WITH_BLANK_REGEX = "(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?";
const auto TRIBLE_DECIMAL_WITH_COMMA_REGEX = "(\\d+)(\\.\\d+)?,(\\d+)(\\.\\d+)?,(\\d+)(\\.\\d+)?";
const auto TRIBLE_MIX_WITH_COMMA_REGEX = "^\\s*\\d+(\\.\\d+)?(,\\s*\\d+(\\.\\d+)?)*\\s*$";
const auto TRIBLE_INT_WITH_COLON_REGEX = R"(^[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*$)";
const auto TRIBLE_INT_WITH_DOT_REGEX = R"(^[0-9]+.[0-9]+.[0-9]+.[0-9]+$)";
const auto FOUR_INT_WITH_BLANK_REGEX = R"(^[0-9]+\s[0-9]+\s[0-9]+\s[0-9]+$)";
const auto FOUR_INT_WITH_COMMA_REGEX = R"(^[0-9]+,[0-9]+,[0-9]+,[0-9]+$)";
const auto FOUR_RATIONAL_WITH_BLANK_REGEX =
    R"(^[0-9]+/[1-9][0-9]*\s[0-9]+/[1-9][0-9]*\s[0-9]+/[1-9][0-9]*\s[0-9]+/[1-9][0-9]*$)";
const auto FOUR_DECIMAL_WITH_BLANK_REGEX = "(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?";
const auto FOUR_DECIMAL_WITH_COMMA_REGEX = "(\\d+)(\\.\\d+)?,(\\d+)(\\.\\d+)?,(\\d+)(\\.\\d+)?,(\\d+)(\\.\\d+)?";
const auto SIX_DECIMAL_WITH_BLANK_REGEX =
    "(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?\\s(\\d+)(\\.\\d+)?";
const auto DATETIME_REGEX =
    R"(^[0-9]{4}:(0[1-9]|1[012]):(0[1-9]|[12][0-9]|3[01])\s([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$)";
const auto DATE_REGEX = R"(^[0-9]{4}:(0[1-9]|1[012]):(0[1-9]|[12][0-9]|3[01])$)";

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
    IMAGE_LOGD("Validating value: %{public}s against regex: %{public}s", value.c_str(), regex.c_str());
    std::regex ratPattern(regex);
    if (!std::regex_match(value, ratPattern)) {
        IMAGE_LOGD("Validation failed. Value: %{public}s, Regex: %{public}s", value.c_str(), regex.c_str());
        return false;
    }
    return true;
}

// replace as space according to regex
void ExifMetadatFormatter::ReplaceAsSpace(std::string &value, const std::string &regex)
{
    std::regex pattern(regex);
    value = std::regex_replace(value, pattern, " ");
    IMAGE_LOGD("Value after replacing with space: %{public}s", value.c_str());
}

void ExifMetadatFormatter::ReplaceAsContent(std::string &value, const std::string &regex, const std::string &content)
{
    std::regex pattern(regex);
    value = std::regex_replace(value, pattern, content);
    IMAGE_LOGD("ReplaceAsContent [%{public}s]", value.c_str());
}

// validate the regex & replace comma as space
bool ExifMetadatFormatter::ValidRegexWithComma(std::string &value, const std::string &regex)
{
    IMAGE_LOGD("Validating value: %{public}s with comma against regex: %{public}s", value.c_str(), regex.c_str());
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

// convert decimal to rational string. 2.5 -> 5/2
std::string ExifMetadatFormatter::GetFractionFromStr(const std::string &decimal)
{
    int intPart = stoi(decimal.substr(0, decimal.find(".")));
    double decPart = stod(decimal.substr(decimal.find(".")));

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
void ExifMetadatFormatter::DecimalRationalFormat(std::string &value)
{
    std::string result;
    int icount = 0;
    std::regex parPattern("(\\d+)(\\.\\d+)?");

    // with partial regex For 2.5 26 1.2 to iterator each segment 2.5->5/2
    for (std::sregex_iterator it = std::sregex_iterator(value.begin(), value.end(), parPattern);
        it != std::sregex_iterator(); ++it) {
        std::smatch match = *it;
        IMAGE_LOGD("Matched value: %{public}s", ((std::string)match[0]).c_str());

        // add a space at begin of each segment except the first segment
        if (icount != 0) {
            result += " ";
        }

        // 1.if segment is integer type 123->123/1
        if (ValidRegex(match[0], "\\d+")) {
            // append '/1' to integer 23 -> 23/1
            result += match.str() + "/1";
            IMAGE_LOGD("Matched integer value: %{public}s", ((std::string)match[0]).c_str());
        }
        if (ValidRegex(match[0], "\\d+\\.\\d+")) {
            // segment is decimal call decimalToFraction 2.5 -> 5/2
            result += GetFractionFromStr(match[0]);
            IMAGE_LOGD("Matched decimal value: %{public}s", ((std::string)match[0]).c_str());
        }
        icount++;
    }
    value = result;
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
    DecimalRationalFormat(value);
    return true;
}

// regex validation & convert decimal to rational. For example GPSLatitude 2.5 23 3.4 -> 5/2 23/1 17/5
bool ExifMetadatFormatter::ValidRegexWithDecimalRationalFormat(std::string &value, const std::string &regex)
{
    if (!ValidRegex(value, regex)) {
        return false;
    }

    // convert decimal to rationl 2.5 -> 5/2
    DecimalRationalFormat(value);
    return true;
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

ValueFormatDelegate ExifMetadatFormatter::singleInt =
    std::make_pair(ExifMetadatFormatter::ValidRegex, SINGLE_INT_REGEX);

// regex validation for two integer like DefaultCropSize 9 9 the format is [0-9]+ [0-9]+
ValueFormatDelegate ExifMetadatFormatter::doubleIntWithBlank =
    std::make_pair(ExifMetadatFormatter::ValidRegex, DOUBLE_INT_WITH_BLANK_REGEX);

// regex validation for two integer with comma like BitPerSample 9,9 the format is [0-9]+,[0-9]+,[0-9]+
ValueFormatDelegate ExifMetadatFormatter::doubleIntWithComma =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithComma, DOUBLE_INT_WITH_COMMA_REGEX);

// regex validation for three integer like BitPerSample 9 9 9 the format is [0-9]+ [0-9]+ [0-9]+
ValueFormatDelegate ExifMetadatFormatter::tribleIntWithBlank =
    std::make_pair(ExifMetadatFormatter::ValidRegex, TRIBLE_INT_WITH_BLANK_REGEX);

// regex validation for three integer with comma like BitPerSample 9,9,0 the format is [0-9]+,[0-9]+,[0-9]+,[0-9]+
ValueFormatDelegate ExifMetadatFormatter::tribleIntWithComma =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithComma, TRIBLE_INT_WITH_COMMA_REGEX);

// regex validation for four integer like DNGVersion 9 9 9 9 the format is [0-9]+ [0-9]+ [0-9]+ [0-9]+
ValueFormatDelegate ExifMetadatFormatter::fourIntWithBlank =
    std::make_pair(ExifMetadatFormatter::ValidRegex, FOUR_INT_WITH_BLANK_REGEX);

// regex validation for four integer with comma like DNGVersion tag encodes the DNG four-tier version number
ValueFormatDelegate ExifMetadatFormatter::fourIntWithComma =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithComma, FOUR_INT_WITH_COMMA_REGEX);

// regex validation for one rational like ApertureValue 4/1 the format is [0-9]+/[1-9][0-9]
ValueFormatDelegate ExifMetadatFormatter::singleRational =
    std::make_pair(ExifMetadatFormatter::ValidRegex, SINGLE_RATIONAL_REGEX);

// regex validation for integer and convert it to rational like ApertureValue 4 --> 4/1
ValueFormatDelegate ExifMetadatFormatter::singleIntToRational =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithRationalFormat, SINGLE_INT_REGEX);

ValueFormatDelegate ExifMetadatFormatter::singleDecimalToRational =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithDecimalRationalFormat, SINGLE_DECIMAL_REGEX);

ValueFormatDelegate ExifMetadatFormatter::doubleIntToOneRationalWithComma =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithGpsOneRationalFormat, DOUBLE_INT_WITH_COMMA_REGEX);

// regex validation for three rational like GPSLatitude 39/1 54/1 20/1
ValueFormatDelegate ExifMetadatFormatter::tribleRationalWithBlank =
    std::make_pair(ExifMetadatFormatter::ValidRegex, TRIBLE_RATIONAL_WITH_BLANK_REGEX);

// regex validation for three integer and convert to three rational like GPSLatitude 39 54 20 --> 39/1 54/1 20/1
ValueFormatDelegate ExifMetadatFormatter::tribleIntToRationalWithBlank =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithRationalFormat, TRIBLE_INT_WITH_BLANK_REGEX);

// regex validation for three integer with comma like GPSLatitude 39,54,20 --> 39/1 54/1 20/1
ValueFormatDelegate ExifMetadatFormatter::tribleIntToRationalWithComma =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithCommaRationalFormat, TRIBLE_INT_WITH_COMMA_REGEX);

// regex validation for three decimal like YCbCrCoefficients 39.0 54 20.0 --> 39/1 54/1 20/1
ValueFormatDelegate ExifMetadatFormatter::tribleDecimalToRationalWithBlank =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithDecimalRationalFormat, TRIBLE_DECIMAL_WITH_BLANK_REGEX);

// regex validation for three decimal like YCbCrCoefficients 39.0,54,20.0 --> 39.0 54 20.0 --> 39/1 54/1 20/1
ValueFormatDelegate ExifMetadatFormatter::tribleDecimalToRatiionalWithComma =
    std::make_pair(ExifMetadatFormatter::ValidRegxWithCommaDecimalRationalFormat, TRIBLE_DECIMAL_WITH_COMMA_REGEX);

// regex validation for three decimal like GPS 10, 20, 20.123 --> 10 20 20.123 --> 10/1 20/1 20.123/1
ValueFormatDelegate ExifMetadatFormatter::tribleMixToRationalWithComma =
    std::make_pair(ExifMetadatFormatter::ValidRegxWithCommaDecimalRationalFormat, TRIBLE_MIX_WITH_COMMA_REGEX);

// regex validation for four rational like LensSpecification 1/1 3/2 1/1 2/1
ValueFormatDelegate ExifMetadatFormatter::fourRationalWithBlank =
    std::make_pair(ExifMetadatFormatter::ValidRegex, FOUR_RATIONAL_WITH_BLANK_REGEX);

// regex validation for four integer and convert to four rational like LensSpecification 1 3 1 2 --> 1/1 3/2 1/1 2/1
ValueFormatDelegate ExifMetadatFormatter::fourIntToRationalWithBlank =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithRationalFormat, FOUR_INT_WITH_BLANK_REGEX);

// regex validation for four integer like LensSpecification 1,3,1,2 --> 1/1 3/2 1/1 2/1
ValueFormatDelegate ExifMetadatFormatter::fourIntToRationalWithComma =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithCommaRationalFormat, FOUR_INT_WITH_COMMA_REGEX);

// regex validation for four decimal like LensSpecification 1.0 3.0 1.0 2.0 --> 1/1 3/1 2/1
ValueFormatDelegate ExifMetadatFormatter::fourDecimalToRationalWithBlank =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithDecimalRationalFormat, FOUR_DECIMAL_WITH_BLANK_REGEX);

// regex validation for four decimal like LensSpecification 1.0,3.0,1.0,2.0 --> 1/1 3/1 2/1
ValueFormatDelegate ExifMetadatFormatter::fourDecimalToRationalWithComma =
    std::make_pair(ExifMetadatFormatter::ValidRegxWithCommaDecimalRationalFormat, FOUR_DECIMAL_WITH_COMMA_REGEX);

// regex validation for datetime format like DateTimeOriginal 2022:06:02 15:51:34
ValueFormatDelegate ExifMetadatFormatter::dateTimeValidation =
    std::make_pair(ExifMetadatFormatter::ValidRegex, DATETIME_REGEX);

// regex validation for datetime format like DateTimeOriginal 2022:06:02
ValueFormatDelegate ExifMetadatFormatter::dateValidation = std::make_pair(ExifMetadatFormatter::ValidRegex, DATE_REGEX);

// regex validation for three integer like GPSLatitude 39,54,21 --> 39/1 54/1 21/1
ValueFormatDelegate ExifMetadatFormatter::tribleIntToRationalWithColon =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithColonRationalFormat, TRIBLE_INT_WITH_COLON_REGEX);

// regex validation for fou integer with pointer like GPSVersionID
ValueFormatDelegate ExifMetadatFormatter::fourIntWithDot =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithDot, TRIBLE_INT_WITH_DOT_REGEX);

ValueFormatDelegate ExifMetadatFormatter::sixDecimalToRationalWithBlank =
    std::make_pair(ExifMetadatFormatter::ValidRegexWithDecimalRationalFormat, SIX_DECIMAL_WITH_BLANK_REGEX);

// configuration for value format validation. For example BitPerSample the value format should be 9 9 9 or 9,9,9
std::multimap<std::string, ValueFormatDelegate> ExifMetadatFormatter::valueFormatConvertConfig = {
    {"BitsPerSample", tribleIntWithBlank},
    {"BitsPerSample", tribleIntWithComma},
    {"CompressedBitsPerPixel", singleRational},
    {"CompressedBitsPerPixel", singleIntToRational},
    {"CompressedBitsPerPixel", singleDecimalToRational},
    {"GPSLatitude", doubleIntToOneRationalWithComma},
    {"GPSLatitude", tribleRationalWithBlank},
    {"GPSLatitude", tribleIntToRationalWithBlank},
    {"GPSLatitude", tribleIntToRationalWithComma},
    {"GPSLatitude", tribleMixToRationalWithComma},
    {"GPSLongitude", doubleIntToOneRationalWithComma},
    {"GPSLongitude", tribleRationalWithBlank},
    {"GPSLongitude", tribleIntToRationalWithBlank},
    {"GPSLongitude", tribleIntToRationalWithComma},
    {"GPSLongitude", tribleMixToRationalWithComma},
    {"ApertureValue", singleRational},
    {"ApertureValue", singleIntToRational},
    {"ApertureValue", singleDecimalToRational},
    {"DateTimeOriginal", dateTimeValidation},
    {"DateTimeOriginal", dateValidation},
    {"DateTime", dateTimeValidation},
    {"DateTime", dateValidation},
    {"ExposureBiasValue", singleRational},
    {"ExposureBiasValue", singleIntToRational},
    {"ExposureBiasValue", singleDecimalToRational},
    {"ExposureTime", singleRational},
    {"ExposureTime", singleIntToRational},
    {"ExposureTime", singleDecimalToRational},
    {"FNumber", singleRational},
    {"FNumber", singleIntToRational},
    {"FNumber", singleDecimalToRational},
    {"FocalLength", singleRational},
    {"FocalLength", singleIntToRational},
    {"FocalLength", singleDecimalToRational},
    {"GPSTimeStamp", tribleRationalWithBlank},
    {"GPSTimeStamp", tribleIntToRationalWithBlank},
    {"GPSTimeStamp", tribleIntToRationalWithColon},
    {"GPSDateStamp", dateValidation},
    {"XResolution", singleRational},
    {"XResolution", singleIntToRational},
    {"XResolution", singleDecimalToRational},
    {"YResolution", singleRational},
    {"YResolution", singleIntToRational},
    {"YResolution", singleDecimalToRational},
    {"WhitePoint", singleRational},
    {"WhitePoint", singleIntToRational},
    {"WhitePoint", singleDecimalToRational},
    {"PrimaryChromaticities", singleRational},
    {"PrimaryChromaticities", singleIntToRational},
    {"PrimaryChromaticities", singleDecimalToRational},
    {"YCbCrCoefficients", tribleRationalWithBlank},
    {"YCbCrCoefficients", tribleIntToRationalWithBlank},
    {"YCbCrCoefficients", tribleIntToRationalWithComma},
    {"YCbCrCoefficients", tribleDecimalToRationalWithBlank},
    {"YCbCrCoefficients", tribleDecimalToRatiionalWithComma},
    {"ReferenceBlackWhite", singleRational},
    {"ReferenceBlackWhite", singleIntToRational},
    {"ReferenceBlackWhite", singleDecimalToRational},
    {"ShutterSpeedValue", singleRational},
    {"ShutterSpeedValue", singleIntToRational},
    {"ShutterSpeedValue", singleDecimalToRational},
    {"BrightnessValue", singleRational},
    {"BrightnessValue", singleIntToRational},
    {"BrightnessValue", singleDecimalToRational},
    {"MaxApertureValue", singleRational},
    {"MaxApertureValue", singleIntToRational},
    {"MaxApertureValue", singleDecimalToRational},
    {"SubjectDistance", singleRational},
    {"SubjectDistance", singleIntToRational},
    {"SubjectDistance", singleDecimalToRational},
    {"FlashEnergy", singleRational},
    {"FlashEnergy", singleIntToRational},
    {"FlashEnergy", singleDecimalToRational},
    {"FocalPlaneXResolution", singleRational},
    {"FocalPlaneXResolution", singleIntToRational},
    {"FocalPlaneXResolution", singleDecimalToRational},
    {"FocalPlaneYResolution", singleRational},
    {"FocalPlaneYResolution", singleIntToRational},
    {"FocalPlaneYResolution", singleDecimalToRational},
    {"ExposureIndex", singleRational},
    {"ExposureIndex", singleIntToRational},
    {"ExposureIndex", singleDecimalToRational},
    {"DigitalZoomRatio", singleRational},
    {"DigitalZoomRatio", singleIntToRational},
    {"DigitalZoomRatio", singleDecimalToRational},
    {"GPSAltitude", singleRational},
    {"GPSAltitude", singleIntToRational},
    {"GPSAltitude", singleDecimalToRational},
    {"GPSDOP", singleRational},
    {"GPSDOP", singleIntToRational},
    {"GPSDOP", singleDecimalToRational},
    {"GPSSpeed", singleRational},
    {"GPSSpeed", singleIntToRational},
    {"GPSSpeed", singleDecimalToRational},
    {"GPSTrack", singleRational},
    {"GPSTrack", singleIntToRational},
    {"GPSTrack", singleDecimalToRational},
    {"GPSImgDirection", singleRational},
    {"GPSImgDirection", singleIntToRational},
    {"GPSImgDirection", singleDecimalToRational},
    {"GPSDestLatitude", tribleRationalWithBlank},
    {"GPSDestLatitude", tribleIntToRationalWithBlank},
    {"GPSDestLatitude", tribleIntToRationalWithComma},
    {"GPSDestLongitude", tribleRationalWithBlank},
    {"GPSDestLongitude", tribleIntToRationalWithBlank},
    {"GPSDestLongitude", tribleIntToRationalWithComma},
    {"GPSDestBearing", singleRational},
    {"GPSDestBearing", singleIntToRational},
    {"GPSDestBearing", singleDecimalToRational},
    {"GPSDestDistance", singleRational},
    {"GPSDestDistance", singleIntToRational},
    {"GPSDestDistance", singleDecimalToRational},
    {"GPSVersionID", fourIntWithDot},
    {"CompressedBitsPerPixel", singleRational},
    {"CompressedBitsPerPixel", singleIntToRational},
    {"CompressedBitsPerPixel", singleDecimalToRational},
    {"DNGVersion", fourIntWithBlank},
    {"DNGVersion", fourIntWithComma},
    {"DefaultCropSize", doubleIntWithBlank},
    {"DefaultCropSize", doubleIntWithComma},
    {"Gamma", singleRational},
    {"Gamma", singleIntToRational},
    {"Gamma", singleDecimalToRational},
    {"GPSHPositioningError", singleRational},
    {"GPSHPositioningError", singleIntToRational},
    {"GPSHPositioningError", singleDecimalToRational},
    {"LensSpecification", fourRationalWithBlank},
    {"LensSpecification", fourIntToRationalWithBlank},
    {"LensSpecification", fourIntToRationalWithComma},
    {"LensSpecification", fourDecimalToRationalWithBlank},
    {"LensSpecification", fourDecimalToRationalWithComma},
    {"ReferenceBlackWhite", sixDecimalToRationalWithBlank},
    {"SubjectLocation", doubleIntWithBlank},
    {"ImageLength", singleInt},
    {"ImageWidth", singleInt},
    {"ISOSpeedRatings", singleInt},
    {"StandardOutputSensitivity", singleInt},
    {"RecommendedExposureIndex", singleInt},
    {"ISOSpeed", singleInt},
    {"PixelXDimension", singleInt},
    {"PixelYDimension", singleInt},
    {"FocalLengthIn35mmFilm", singleInt},
    {"StripOffsets", singleInt},
    {"SamplesPerPixel", singleInt},
    {"RowsPerStrip", singleInt},
    {"StripByteCounts", singleInt},
    {"ExifVersion", singleInt},
    {"ISOSpeedLatitudeyyy", singleInt},
    {"ISOSpeedLatitudezzz", singleInt},
    {"ComponentsConfiguration", singleInt},
    {"PhotographicSensitivity", singleInt},
    {"FlashpixVersion", singleInt},
    {"PhotoMode", singleInt},
    {"JPEGProc", singleInt},
    {"HwMnoteCaptureMode", singleInt},
    {"DateTimeDigitized", dateTimeValidation},
    {"DateTimeDigitized", dateValidation},
    {"OffsetTime", dateTimeValidation},
    {"OffsetTime", dateValidation},
    {"SubjectArea", doubleIntWithBlank},
    {"SubjectArea", doubleIntWithComma},
    {"SourceImageNumberOfCompositeImage", doubleIntWithBlank},
    {"SourceImageNumberOfCompositeImage", doubleIntWithComma},
    {"YCbCrSubSampling", doubleIntWithBlank},
    {"YCbCrSubSampling", doubleIntWithComma},
    {"MovingPhotoVersion", singleInt},
    {"MicroVideoPresentationTimestampUS", singleInt},
};

// validate the value range. For example GPSLatitudeRef the value must be 'N' or 'S'.
int32_t ExifMetadatFormatter::ValidateValueRange(const std::string &keyName, const std::string &value)
{
    // 1. to find if any value range validation configuratiion according to exif tag in std::map container
    auto iter = valueRangeValidateConfig.find(keyName);
    if (iter == valueRangeValidateConfig.end()) {
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
        // convert string to integer such as "15" -> 15
        ivalue = std::stoll(value);
        IMAGE_LOGD("Converted string to integer. Value: %{public}d", ivalue);
    }
    if (std::regex_match(value, regChar)) {
        // convert char to integer such as "N" -> 78
        ivalue = static_cast<int32_t>(value[0]);
        IMAGE_LOGD("Converted char to integer. Value: %{public}d", ivalue);
    }

    // if ivalue is not converted then return FAIL
    if (ivalue == -1) {
        IMAGE_LOGD("Invalid value: %{public}s", value.c_str());
        return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    // validate the ivalue is in value range array.
    auto isValid = IsValidValue(arrRef, arrSize, ivalue);
    if (!isValid) {
        IMAGE_LOGD("Invalid value: %{public}s", value.c_str());
        return Media::ERR_MEDIA_OUT_OF_RANGE;
    } else {
        IMAGE_LOGD("Valid value: %{public}s", value.c_str());
        return Media::SUCCESS;
    }
    return Media::SUCCESS;
}

// validate value format. For example BitPerSample the value format should be 9 9 9 or 9,9,9
int32_t ExifMetadatFormatter::ConvertValueFormat(const std::string &keyName, std::string &value)
{
    IMAGE_LOGD("ConvertValueFormat keyName is [%{public}s] value is [%{public}s].", keyName.c_str(), value.c_str());

    auto it = ExifMetadatFormatter::valueFormatConvertConfig.find(keyName);
    if (it == ExifMetadatFormatter::valueFormatConvertConfig.end()) {
        IMAGE_LOGD("No format validation needed. Defaulting to success.");
        return Media::SUCCESS;
    }
    IMAGE_LOGD("Validating value format. Key: %{public}s, Value: %{public}s", keyName.c_str(), value.c_str());

    // get first iterator according to keyName
    for (; it != ExifMetadatFormatter::valueFormatConvertConfig.end() &&
        it != ExifMetadatFormatter::valueFormatConvertConfig.upper_bound(keyName);
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

bool ExifMetadatFormatter::IsModifyAllowed(const std::string &keyName)
{
    auto it = READ_WRITE_KEYS.find(keyName);
    return (it != READ_WRITE_KEYS.end());
}

std::pair<int32_t, std::string> ExifMetadatFormatter::Format(const std::string &keyName, const std::string &value)
{
    IMAGE_LOGD("Processing. Key: %{public}s, Value: %{public}s.", keyName.c_str(), value.c_str());
    std::string tmpValue = value;

    if (!ExifMetadatFormatter::IsKeySupported(keyName)) {
        IMAGE_LOGD("Key is not supported.");
        return std::make_pair(Media::ERR_MEDIA_WRITE_PARCEL_FAIL, "");
    }

    if (!ExifMetadatFormatter::IsModifyAllowed(keyName)) {
        IMAGE_LOGD("Key is not allowed to modify.");
        return std::make_pair(Media::ERR_MEDIA_WRITE_PARCEL_FAIL, "");
    }

    // 1.validate value format
    if (ExifMetadatFormatter::ConvertValueFormat(keyName, tmpValue)) {
        IMAGE_LOGD("Invalid value format. Key: %{public}s, Value: %{public}s.", keyName.c_str(), value.c_str());
        // value format validate does not pass
        return std::make_pair(Media::ERR_MEDIA_VALUE_INVALID, "");
    }
    IMAGE_LOGD("Processed format value. Key: %{public}s, Value: %{public}s.", keyName.c_str(), value.c_str());

    // 2.validate value range
    if (ExifMetadatFormatter::ValidateValueRange(keyName, value)) {
        IMAGE_LOGD("Invalid value range. Key: %{public}s, Value: %{public}s.", keyName.c_str(), value.c_str());
        // value range validate does not pass
        return std::make_pair(Media::ERR_MEDIA_VALUE_INVALID, "");
    }
    return std::make_pair(Media::SUCCESS, tmpValue);
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
    int numerator = stoi(numeratorStr);
    int denominator = stoi(denominatorStr);
    if (denominator == 0) {
        return false;
    }
    output = static_cast<double>(numerator) / denominator;
    return true;
}

static bool ValidLatLong(const std::string &key, const std::string &value)
{
    IMAGE_LOGD("ValidLatLong key is %{public}s value is %{public}s", key.c_str(), value.c_str());

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
    IMAGE_LOGD("IsUint16 %{publich}s", s.c_str());
    std::istringstream iss(s);
    uint16_t num;
    iss >> num;
    return !iss.fail() && iss.eof();
}

// exif validation portal
int32_t ExifMetadatFormatter::Validate(const std::string &keyName, const std::string &value)
{
    IMAGE_LOGD("Validating. Key: %{public}s, Value: %{public}s.", keyName.c_str(), value.c_str());

    auto result = ExifMetadatFormatter::Format(keyName, value);
    if (result.first) {
        IMAGE_LOGE("Validating Error %{public}d", result.first);
        return result.first;
    }

    IMAGE_LOGD("format result: %{public}s", result.second.c_str());
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
    IMAGE_LOGD("Validate ret: %{result.first}d", result.first);
    return result.first;
}
} // namespace Media
} // namespace OHOS
