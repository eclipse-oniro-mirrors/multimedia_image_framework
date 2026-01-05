/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <fuzzer/FuzzedDataProvider.h>
#include <fcntl.h>
#include <memory>
#include "dng_area_task.h"
#include "dng/dng_exif_metadata.h"
#include "dng_errors.h"
#include "dng_host.h"
#include "dng_sdk_helper.h"
#include "dng_stream.h"
#include "file_metadata_stream.h"

namespace OHOS {
namespace Media {

static const std::vector<std::string> HW_KEYS = {
    "ImageDescription", "GPSVersionID", "GPSLatitudeRef", "GPSLatitude", "GPSLongitudeRef", "GPSLongitude",
    "GPSAltitudeRef", "GPSAltitude", "GPSTimeStamp", "GPSSatellites", "GPSStatus",
    "GPSMeasureMode", "GPSDOP", "GPSSpeedRef", "GPSSpeed", "GPSTrackRef", "GPSTrack",
    "GPSImgDirectionRef", "GPSImgDirection", "GPSMapDatum", "GPSDestLatitudeRef",
    "GPSDestLatitude", "GPSDestLongitudeRef", "GPSDestLongitude", "GPSDestBearingRef",
    "GPSDestBearing", "GPSDestDistanceRef", "GPSDestDistance", "GPSProcessingMethod",
    "GPSAreaInformation", "GPSDateStamp", "GPSDifferential", "GPSHPositioningError",
    "Make", "Model", "Software", "DateTime", "Artist", "SubsecTime", "Copyright", "ExposureTime",
    "FNumber", "ExposureProgram", "ISOSpeedRatings", "PhotographicSensitivity", "SensitivityType",
    "StandardOutputSensitivity", "RecommendedExposureIndex", "ISOSpeedLatitudeyyy", "ISOSpeedLatitudezzz",
    "ExifVersion", "DateTimeOriginal", "DateTimeDigitized", "ComponentsConfiguration", "CompressedBitsPerPixel",
    "ShutterSpeedValue", "ApertureValue", "BrightnessValue", "ExposureBiasValue", "MaxApertureValue",
    "SubjectDistance", "MeteringMode", "LightSource", "Flash", "FocalLength", "SubjectArea",
    "UserComment", "SubsecTimeOriginal", "SubsecTimeDigitized", "FlashpixVersion", "ColorSpace",
    "PixelXDimension", "PixelYDimension", "FocalPlaneXResolution", "FocalPlaneYResolution",
    "FocalPlaneResolutionUnit", "SubjectLocation", "ExposureIndex", "SensingMethod", "FileSource",
    "SceneType", "CFAPattern", "CustomRendered", "ExposureMode", "WhiteBalance", "DigitalZoomRatio",
    "FocalLengthIn35mmFilm", "SceneCaptureType", "GainControl", "Contrast", "Saturation",
    "Sharpness", "SubjectDistanceRange", "ImageUniqueID", "CameraOwnerName", "BodySerialNumber",
    "LensSpecification", "LensMake", "LensModel", "LensSerialNumber", "Gamma", "NewSubfileType",
    "ImageWidth", "ImageLength", "BitsPerSample", "Compression", "PhotometricInterpretation",
    "StripOffsets", "Orientation", "SamplesPerPixel", "RowsPerStrip", "StripByteCounts", "XResolution",
    "YResolution", "PlanarConfiguration", "ResolutionUnit", "YCbCrCoefficients", "YCbCrSubSampling",
    "YCbCrPositioning", "ReferenceBlackWhite", "MakerNote", "DNGVersion", "DefaultCropSize",
    "JPEGInterchangeFormatLength", "JPEGInterchangeFormat", "SubfileType", "TransferFunction", "WhitePoint",
    "PrimaryChromaticities", "PhotoMode", "SpectralSensitivity", "OECF", "RelatedSoundFile", "FlashEnergy",
    "SpatialFrequencyResponse", "DeviceSettingDescription", "OffsetTime", "OffsetTimeOriginal",
    "OffsetTimeDigitized", "CompositeImage", "SourceImageNumberOfCompositeImage", "HwMnotePitchAngle",
    "HwMnoteCaptureMode", "HwMnotePhysicalAperture", "HwMnoteRollAngle", "SourceExposureTimesOfCompositeImage",
    "HwMnoteSceneFoodConf", "HwMnoteSceneStageConf", "HwMnoteSceneBlueSkyConf", "HwMnoteSceneGreenPlantConf",
    "HwMnoteSceneBeachConf", "HwMnoteSceneSnowConf", "HwMnoteSceneSunsetConf", "HwMnoteSceneFlowersConf",
    "HwMnoteSceneNightConf", "HwMnoteSceneTextConf", "HwMnoteFaceCount", "HwMnoteFocusMode",
    "HwMnoteFocusModeExif", "HwMnoteBurstNumber", "HwMnoteFaceConf", "HwMnoteFaceLeyeCenter",
    "HwMnoteFaceMouthCenter", "HwMnoteFacePointer", "HwMnoteFaceRect", "HwMnoteFaceReyeCenter",
    "HwMnoteFaceSmileScore", "HwMnoteFaceVersion", "HwMnoteFrontCamera", "HwMnoteScenePointer",
    "HwMnoteSceneVersion", "HwMnoteIsXmageSupported", "HwMnoteXmageMode", "HwMnoteXmageLeft",
    "HwMnoteXmageTop", "HwMnoteXmageRight", "HwMnoteXmageBottom", "HwMnoteCloudEnhancementMode",
    "HwMnoteWindSnapshotMode", "HwMnoteXtStyleTemplateName", "HwMnoteXtStyleCustomLightAndShadow",
    "HwMnoteXtStyleCustomSaturation", "HwMnoteXtStyleCustomHue", "HwMnoteXtStyleExposureParam"
};

static const std::string IMAGE_INPUT1_DNG_PATH = "/data/local/tmp/image/test_dng_readmetadata001.dng";

FuzzedDataProvider* FDP;

void ImageDngSdkHelperParseInfoFromStreamFuzzTest()
{
    int fd = open(IMAGE_INPUT1_DNG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return;
    }
    std::shared_ptr<FileMetadataStream> fileStream =
        std::make_shared<FileMetadataStream>(fd, METADATA_STREAM_INVALID_FD);
    if (fileStream == nullptr) {
        close(fd);
        return;
    }
    bool isOpen = fileStream->Open(OpenMode::ReadWrite);
    if (!isOpen) {
        close(fd);
        return;
    }
    std::shared_ptr<MetadataStream> stream = fileStream;
    DngSdkHelper::ParseInfoFromStream(stream);
    close(fd);
}

void ImageDngSdkHelperGetExifPropertyFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_DNG_PATH);
    if (stream == nullptr) {
        return;
    }
    bool openSuccess = stream->Open(OpenMode::ReadWrite);
    if (!openSuccess) {
        return;
    }
    auto dngInfo = DngSdkHelper::ParseInfoFromStream(stream);
    if (dngInfo == nullptr) {
        return;
    }

    MetadataValue value{};
    if (HW_KEYS.empty()) {
        return;
    }
    uint8_t randomIdx = FDP->ConsumeIntegral<uint8_t>() % HW_KEYS.size();
    value.key = HW_KEYS[randomIdx];
    DngSdkHelper::GetExifProperty(dngInfo, value);
}

void ImageDngSdkHelperSetExifPropertyFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_DNG_PATH);
    if (stream == nullptr) {
        return;
    }
    bool openSuccess = stream->Open(OpenMode::ReadWrite);
    if (!openSuccess) {
        return;
    }
    auto dngInfo = DngSdkHelper::ParseInfoFromStream(stream);
    if (dngInfo == nullptr) {
        return;
    }

    MetadataValue value{};
    if (HW_KEYS.empty()) {
        return;
    }
    uint8_t randomIdx = FDP->ConsumeIntegral<uint8_t>() % HW_KEYS.size();
    value.key = HW_KEYS[randomIdx];
    DngSdkHelper::SetExifProperty(dngInfo, value);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::ImageDngSdkHelperParseInfoFromStreamFuzzTest();
    OHOS::Media::ImageDngSdkHelperGetExifPropertyFuzzTest();
    OHOS::Media::ImageDngSdkHelperSetExifPropertyFuzzTest();
    return 0;
}