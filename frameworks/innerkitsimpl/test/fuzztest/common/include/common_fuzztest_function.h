/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_INNERKITSIMPL_TEST_FUZZTEST_COMMON_FUZZTEST_FUNCTION_H
#define FRAMEWORKS_INNERKITSIMPL_TEST_FUZZTEST_COMMON_FUZZTEST_FUNCTION_H

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <stddef.h>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
namespace OHOS {
namespace Media {
    class PixelMap;
    struct DecodeOptions;
}
namespace ImagePlugin {
    struct PixelDecodeOptions;
}
}

const static std::vector<std::pair<std::string, std::vector<std::string>>> KEY_VALUE_MAPS = {
    {"BitsPerSample", {"9, 7, 8", "8, 8, 8"}},
    {"Orientation", {"Top-right", "Unknown value 0"}},
    {"ImageLength", {"1000", "4000"}},
    {"ImageWidth", {"500", "3000"}},
    {"GPSLatitude", {"39, 54, 20", ""}},
    {"GPSLongitude", {"120, 52, 26", ""}},
    {"GPSLatitudeRef", {"N", ""}},
    {"GPSLongitudeRef", {"E", ""}},
    {"DateTimeOriginal", {"2024,01,25 05,51,34", "2024,01,11 09,39,58", "2023,01,19 10,39,58"}},
    {"ExposureTime", {"1/34 sec.", "1/590 sec."}},
    {"SceneType", {"Directly photographed"}},
    {"ISOSpeedRatings", {"160"}},
    {"FNumber", {"f/3.0", "f/2.0"}},
    {"DateTime", {""}},
    {"GPSTimeStamp", {"11,37,58.00", "01,39,58.00"}},
    {"GPSDateStamp", {"2025,01,11", "2024,01,11"}},
    {"ImageDescription", {"_cuva"}},
    {"Make", {""}},
    {"Model", {"TNY-AL00", "", "xx", "xxx"}},
    {"SensitivityType", {"Standard output sensitivity (SOS) and ISO speed", ""}},
    {"StandardOutputSensitivity", {"5", ""}},
    {"RecommendedExposureIndex", {"241", ""}},
    {"ApertureValue", {"4.00 EV (f/4.0)", "2.00 EV (f/2.0)"}},
    {"ExposureBiasValue", {"23.00 EV", "0.00 EV"}},
    {"MeteringMode", {"Pattern"}},
    {"LightSource", {"Fluorescent", "Daylight"}},
    {"Flash", {"Strobe return light not detected", "Flash did not fire"}},
    {"FocalLength", {"31.0 mm", "6.3 mm"}},
    {"UserComment", {"comm", ""}},
    {"PixelXDimension", {"1000", "4000"}},
    {"PixelYDimension", {"2000", "3000"}},
    {"WhiteBalance", {"Manual white balance", "Auto white balance"}},
    {"FocalLengthIn35mmFilm", {"26", "27"}},
    {"JPEGProc", {"252", ""}},
    {"MaxApertureValue", {"0.08 EV (f/1.0)"}},
    {"Artist", {"Joseph.Xu"}},
    {"NewSubfileType", {"1"}},
    {"OECF", {"1 bytes undefined data"}},
    {"PlanarConfiguration", {"Chunky format"}},
    {"PrimaryChromaticities", {"124"}},
    {"ReferenceBlackWhite", {"221"}},
    {"ResolutionUnit", {"Inch"}},
    {"SamplesPerPixel", {"23"}},
    {"Compression", {"JPEG compression"}},
    {"Software", {"MNA-AL00 4.0.0.120(C00E116R3P7)"}},
    {"Copyright", {"xxxxxx (Photographer) - {None} (Editor)"}},
    {"SpectralSensitivity", {"sensitivity"}},
    {"DNGVersion", {"0x01, 0x01, 0x02, 0x03"}},
    {"SubjectDistance", {""}},
    {"DefaultCropSize", {"12, 1"}},
    {"SubjectLocation", {"3"}},
    {"TransferFunction", {"2"}},
    {"WhitePoint", {"124.2"}},
    {"XResolution", {"72"}},
    {"YCbCrCoefficients", {"0.299, 0.587, 0.114"}},
    {"YCbCrPositioning", {"Centered"}},
    {"YCbCrSubSampling", {"3, 2"}},
    {"YResolution", {"72"}},
    {"Gamma", {"1.5"}},
    {"ISOSpeed", {"200"}},
    {"ISOSpeedLatitudeyyy", {"3"}},
    {"ISOSpeedLatitudezzz", {"3"}},
    {"ImageUniqueID", {"FXIC012"}},
    {"JPEGInterchangeFormat", {""}},
    {"JPEGInterchangeFormatLength", {""}},
    {"GPSAltitude", {"0.00"}},
    {"GPSAltitudeRef", {"Sea level reference"}},
    {"GPSAreaInformation", {"23...15...57"}},
    {"GPSDOP", {"182"}},
    {"GPSDestBearing", {"2.6"}},
    {"GPSDestBearingRef", {"T"}},
    {"GPSDestDistance", {"10"}},
    {"GPSDestDistanceRef", {"N"}},
    {"GPSDestLatitude", {"33, 22, 11"}},
    {"GPSDestLatitudeRef", {"N"}},
    {"GPSDestLongitude", {"33, 22, 11"}},
    {"GPSDestLongitudeRef", {"E"}},
    {"GPSDifferential", {"1"}},
    {"GPSImgDirection", {"2.23214"}},
    {"GPSImgDirectionRef", {"M"}},
    {"GPSMapDatum", {"xxxx"}},
    {"GPSMeasureMode", {"2"}},
    {"GPSProcessingMethod", {"CELLID"}},
    {"GPSSatellites", {"xxx"}},
    {"GPSSpeed", {"150"}},
    {"GPSSpeedRef", {"K"}},
    {"GPSStatus", {"V"}},
    {"GPSTrack", {"56"}},
    {"GPSTrackRef", {"T"}},
    {"GPSVersionID", {"2.2.0.0"}},
    {"GPSHPositioningError", {" 3"}},
    {"LensMake", {"xxx"}},
    {"LensModel", {"xxx"}},
    {"LensSerialNumber", {"xxx"}},
    {"LensSpecification", {" 1, 1.5,  1,  2"}},
    {"GainControl", {"Normal"}},
    {"OffsetTime", {"xx"}},
    {"OffsetTimeDigitized", {"xx"}},
    {"OffsetTimeOriginal", {"xx"}},
    {"PhotometricInterpretation", {""}},
    {"RelatedSoundFile", {"/usr/home/sound/sea.wav"}},
    {"RowsPerStrip", {""}},
    {"Saturation", {"Normal"}},
    {"SceneCaptureType", {"Standard"}},
    {"SensingMethod", {"Two-chip color area sensor"}},
    {"Sharpness", {"Normal"}},
    {"ShutterSpeedValue", {"13.00 EV (1/8192 sec.)"}},
    {"SourceExposureTimesOfCompositeImage", {"."}},
    {"SourceImageNumberOfCompositeImage", {"1234"}},
    {"SpatialFrequencyResponse", {"."}},
    {"StripByteCounts", {""}},
    {"StripOffsets", {""}},
    {"SubsecTime", {"427000"}},
    {"SubsecTimeDigitized", {"427000"}},
    {"SubsecTimeOriginal", {"427000"}},
    {"SubfileType", {""}},
    {"SubjectArea", {"Within rectangle (width 183, height 259) around (x,y) = (10,20)"}},
    {"SubjectDistanceRange", {"Unknown"}},
    {"BodySerialNumber", {"xx"}},
    {"BrightnessValue", {"2.50 EV (19.38 cd/m^2)"}},
    {"CFAPattern", {"1 bytes undefined data"}},
    {"CameraOwnerName", {"xx"}},
    {"ColorSpace", {"Adobe RGB"}},
    {"ComponentsConfiguration", {""}},
    {"CompositeImage", {"1"}},
    {"CompressedBitsPerPixel", {"1.5"}},
    {"Contrast", {"Normal"}},
    {"CustomRendered", {"Custom process"}},
    {"DateTimeDigitized", {"2023,01,19 10,39,58"}},
    {"DeviceSettingDescription", {"."}},
    {"DigitalZoomRatio", {"321"}},
    {"ExifVersion", {""}},
    {"ExposureIndex", {"1.5"}},
    {"ExposureMode", {"Auto exposure"}},
    {"ExposureProgram", {"Normal program"}},
    {"FileSource", {"DSC"}},
    {"FlashEnergy", {"832"}},
    {"FlashpixVersion", {""}},
    {"FocalPlaneResolutionUnit", {"Centimeter"}},
    {"FocalPlaneXResolution", {"1080"}},
    {"FocalPlaneYResolution", {"880"}}
};

// create pixelMap by data, and encode to the file descriptor
int ConvertDataToFd(const uint8_t* data, size_t size, std::string encodeFormat = "image/jpeg");

std::string GetNowTimeStr();

bool WriteDataToFile(const uint8_t* data, size_t size, const std::string& filename);

void PixelMapTest001(OHOS::Media::PixelMap* pixelMap);

void PixelMapTest002(OHOS::Media::PixelMap* pixelMap);

void PixelYuvTest001(OHOS::Media::PixelMap* pixelMap);

void PixelYuvTest002(OHOS::Media::PixelMap* pixelMap);

void SetFdpDecodeOptions(FuzzedDataProvider* fdp, OHOS::Media::DecodeOptions &decodeOpts);

std::string GetRandomKey(FuzzedDataProvider* fdp);

void SetFdpPixelDecodeOptions(FuzzedDataProvider* fdp, OHOS::ImagePlugin::PixelDecodeOptions &plOpts);
#endif