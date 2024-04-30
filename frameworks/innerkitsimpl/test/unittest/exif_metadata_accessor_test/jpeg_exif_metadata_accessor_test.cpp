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

#include <gtest/gtest.h>
#include <memory>

#include "file_metadata_stream.h"
#include "jpeg_exif_metadata_accessor.h"
#include "log_tags.h"
#include "media_errors.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {

namespace {
static const std::string IMAGE_INPUT1_JPEG_PATH = "/data/local/tmp/image/test_jpeg_readmetadata001.jpg";
static const std::string IMAGE_INPUT2_JPEG_PATH = "/data/local/tmp/image/test_jpeg_readmetadata003.jpg";
static const std::string IMAGE_INPUT3_JPEG_PATH = "/data/local/tmp/image/test_jpeg_readmetadata004.jpg";
static const std::string IMAGE_ERROR1_JPEG_PATH = "/data/local/tmp/image/test_jpeg_readexifblob002.jpg";
static const std::string IMAGE_ERROR2_JPEG_PATH = "/data/local/tmp/image/test_jpeg_readexifblob003.jpg";
static const std::string IMAGE_INPUT_WRITE1_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata001.jpg";
static const std::string IMAGE_INPUT_WRITE3_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata003.jpg";
static const std::string IMAGE_INPUT_WRITE5_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata005.jpg";
static const std::string IMAGE_INPUT_WRITE7_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata007.jpg";
static const std::string IMAGE_INPUT_WRITE9_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata009.jpg";
static const std::string IMAGE_INPUT_WRITE11_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata011.jpg";
static const std::string IMAGE_INPUT_WRITE13_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata013.jpg";
static const std::string IMAGE_INPUT_WRITE15_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata015.jpg";
static const std::string IMAGE_INPUT_WRITE17_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata017.jpg";
static const std::string IMAGE_INPUT_WRITE19_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata019.jpg";
static const std::string IMAGE_INPUT_WRITE21_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata021.jpg";
static const std::string IMAGE_INPUT_WRITE23_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata023.jpg";
static const std::string IMAGE_INPUT_WRITE25_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata025.jpg";
static const std::string IMAGE_INPUT_WRITE27_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata027.jpg";
static const std::string IMAGE_INPUT_WRITE29_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata029.jpg";
static const std::string IMAGE_INPUT_WRITE31_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata031.jpg";
static const std::string IMAGE_INPUT_WRITE2_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writeexifblob001.jpg";
static const std::string IMAGE_INPUT_WRITE4_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writeexifblob003.jpg";
static const std::string IMAGE_OUTPUT_WRITE1_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writemetadata002.jpg";
static const std::string IMAGE_OUTPUT_WRITE2_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writeexifblob002.jpg";
static const std::string IMAGE_OUTPUT_WRITE4_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writeexifblob004.jpg";
static const std::string IMAGE_OUTPUT_WRITE6_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writeexifblob006.jpg";
constexpr auto EXIF_ID = "Exif\0\0";
constexpr auto EXIF_ID_SIZE = 6;
}

class JpegExifMetadataAccessorTest : public testing::Test {
public:
    JpegExifMetadataAccessorTest() {}
    ~JpegExifMetadataAccessorTest() {}
    std::string GetProperty(const std::shared_ptr<ExifMetadata> &metadata, const std::string &prop);
};

/**
 * @tc.name: Read001
 * @tc.desc: test the jpegDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Read001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "9, 7, 8");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-right");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "1000");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "500");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitude"), "39, 54, 20");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitude"), "120, 52, 26");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "E");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2024:01:25 05:51:34");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/34 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "160");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/3.0");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTimeStamp"), "11:37:58.00");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "2025:01:11");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageDescription"), "_cuva");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "TNY-AL00");
    ASSERT_EQ(GetProperty(exifMetadata, "SensitivityType"), "Standard output sensitivity (SOS) and ISO speed");
    ASSERT_EQ(GetProperty(exifMetadata, "StandardOutputSensitivity"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "RecommendedExposureIndex"), "241");
    ASSERT_EQ(GetProperty(exifMetadata, "ApertureValue"), "4.00 EV (f/4.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "23.00 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Pattern");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Fluorescent");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Strobe return light not detected");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "31.0 mm");
    ASSERT_EQ(GetProperty(exifMetadata, "UserComment"), "comm");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "1000");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "2000");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Manual white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "26");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGProc"), "252");
}

/**
 * @tc.name: Read002
 * @tc.desc: test the jpegDecoded Exif Image properties
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Read002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "0.08 EV (f/1.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "Joseph.Xu");
    ASSERT_EQ(GetProperty(exifMetadata, "NewSubfileType"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "OECF"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "PlanarConfiguration"), "Chunky format");
    ASSERT_EQ(GetProperty(exifMetadata, "PrimaryChromaticities"), "124");
    ASSERT_EQ(GetProperty(exifMetadata, "ReferenceBlackWhite"), "221");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "SamplesPerPixel"), "23");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "JPEG compression");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "MNA-AL00 4.0.0.120(C00E116R3P7)");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "xxxxxx (Photographer) - [None] (Editor)");
    ASSERT_EQ(GetProperty(exifMetadata, "SpectralSensitivity"), "sensitivity");
    ASSERT_EQ(GetProperty(exifMetadata, "DNGVersion"), "0x01, 0x01, 0x02, 0x03");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistance"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "12, 1");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "TransferFunction"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "WhitePoint"), "124.2");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "0.299, 0.587, 0.114");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Centered");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrSubSampling"), "3, 2");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "1.5");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeed"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudeyyy"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudezzz"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "FXIC012");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGInterchangeFormat"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGInterchangeFormatLength"), "");
}

/**
 * @tc.name: Read003
 * @tc.desc: test the jpegDecoded Exif GPSInfo properties
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Read003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitude"), "0.00");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitudeRef"), "Sea level reference");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAreaInformation"), "23...15...57");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDOP"), "182");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearing"), "2.6");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearingRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistance"), "10");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistanceRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitudeRef"), "E");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDifferential"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirection"), "2.23214");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirectionRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMapDatum"), "xxxx");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMeasureMode"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSProcessingMethod"), "CELLID");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSatellites"), "xxx");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "150");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeedRef"), "K");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSStatus"), "V");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrack"), "56");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrackRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSVersionID"), "2.2.0.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSHPositioningError"), " 3");
    ASSERT_EQ(GetProperty(exifMetadata, "LensMake"), "xxx");
    ASSERT_EQ(GetProperty(exifMetadata, "LensModel"), "xxx");
    ASSERT_EQ(GetProperty(exifMetadata, "LensSerialNumber"), "xxx");
    ASSERT_EQ(GetProperty(exifMetadata, "LensSpecification"), " 1, 1.5,  1,  2");
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "HwMnoteCaptureMode:123");
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTime"), "xx");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeDigitized"), "xx");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeOriginal"), "xx");
    ASSERT_EQ(GetProperty(exifMetadata, "PhotometricInterpretation"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "RelatedSoundFile"), "/usr/home/sound/sea.wav");
    ASSERT_EQ(GetProperty(exifMetadata, "RowsPerStrip"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Normal");
}

/**
 * @tc.name: Read004
 * @tc.desc: test the jpegDecoded Exif photo properties
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Read004, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Standard");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "Two-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "ShutterSpeedValue"), "13.00 EV (1/8192 sec.)");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceExposureTimesOfCompositeImage"), ".");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceImageNumberOfCompositeImage"), "1234");
    ASSERT_EQ(GetProperty(exifMetadata, "SpatialFrequencyResponse"), ".");
    ASSERT_EQ(GetProperty(exifMetadata, "StripByteCounts"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "StripOffsets"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTime"), "427000");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "427000");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeOriginal"), "427000");
    ASSERT_EQ(GetProperty(exifMetadata, "SubfileType"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectArea"),
        "Within rectangle (width 183, height 259) around (x,y) = (10,20)");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Unknown");
    ASSERT_EQ(GetProperty(exifMetadata, "BodySerialNumber"), "xx");
    ASSERT_EQ(GetProperty(exifMetadata, "BrightnessValue"), "2.50 EV (19.38 cd/m^2)");
    ASSERT_EQ(GetProperty(exifMetadata, "CFAPattern"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "CameraOwnerName"), "xx");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "Adobe RGB");
    ASSERT_EQ(GetProperty(exifMetadata, "ComponentsConfiguration"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "CompositeImage"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "CompressedBitsPerPixel"), "1.5");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Custom process");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2023:01:19 10:39:58");
    ASSERT_EQ(GetProperty(exifMetadata, "DeviceSettingDescription"), ".");
    ASSERT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), "321");
    ASSERT_EQ(GetProperty(exifMetadata, "ExifVersion"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureIndex"), "1.5");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Normal program");
    ASSERT_EQ(GetProperty(exifMetadata, "FileSource"), "DSC");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashEnergy"), "832");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashpixVersion"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneResolutionUnit"), "Centimeter");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneXResolution"), "1080");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneYResolution"), "880");
}

/**
 * @tc.name: Read005
 * @tc.desc: test the jpegDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Read005, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT2_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "8, 8, 8");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Unknown value 0");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "4000");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "3000");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitude"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitude"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2024:01:11 09:39:58");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/590 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "160");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/2.0");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTimeStamp"), "01:39:58.00");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "2024:01:11");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageDescription"), "_cuva");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SensitivityType"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "StandardOutputSensitivity"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "RecommendedExposureIndex"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "ApertureValue"), "2.00 EV (f/2.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "0.00 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Pattern");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Daylight");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Flash did not fire");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "6.3 mm");
    ASSERT_EQ(GetProperty(exifMetadata, "UserComment"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "4000");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "3000");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "27");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGProc"), "");
}

/**
 * @tc.name: Read006
 * @tc.desc: test Read
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Read006, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT3_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteBurstNumber"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteCaptureMode"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceConf"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceCount"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceLeyeCenter"), "1 2 3 4");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceMouthCenter"), "1 2 3 4 5 6 7 8");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFacePointer"), "122");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceRect"), "1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceReyeCenter"), "5 6 7 8");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceSmileScore"), "1 2 3 4 5 6 7 8");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceVersion"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFocusMode"), "7");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFrontCamera"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnotePhysicalAperture"), "6");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnotePitchAngle"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteRollAngle"), "4");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneBeachConf"), "6");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneBlueSkyConf"), "4");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneFlowersConf"), "9");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneFoodConf"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneGreenPlantConf"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneNightConf"), "10");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteScenePointer"), "256");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneSnowConf"), "7");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneStageConf"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneSunsetConf"), "8");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneTextConf"), "11");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneVersion"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "HwMnoteCaptureMode:1,HwMnoteBurstNumber:2,HwMnoteFrontCamera:3,"
        "HwMnoteRollAngle:4,HwMnotePitchAngle:5,HwMnotePhysicalAperture:6,"
        "HwMnoteFocusMode:7,HwMnoteFacePointer:122,HwMnoteFaceVersion:1,"
        "HwMnoteFaceCount:2,HwMnoteFaceConf:3,HwMnoteFaceSmileScore:1 2 3 4 5 6 7 8,"
        "HwMnoteFaceRect:1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8,"
        "HwMnoteFaceLeyeCenter:1 2 3 4,HwMnoteFaceReyeCenter:5 6 7 8,"
        "HwMnoteFaceMouthCenter:1 2 3 4 5 6 7 8,HwMnoteScenePointer:256,"
        "HwMnoteSceneVersion:1,HwMnoteSceneFoodConf:2,HwMnoteSceneStageConf:3,"
        "HwMnoteSceneBlueSkyConf:4,HwMnoteSceneGreenPlantConf:5,HwMnoteSceneBeachConf:6,"
        "HwMnoteSceneSnowConf:7,HwMnoteSceneSunsetConf:8,HwMnoteSceneFlowersConf:9,"
        "HwMnoteSceneNightConf:10,HwMnoteSceneTextConf:11");
}

/**
 * @tc.name: Read007
 * @tc.desc: test Read
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Read007, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT2_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"),
              "HwMnoteScenePointer:170,"
              "HwMnoteSceneVersion:1207959808,"
              "HwMnoteFacePointer:188,"
              "HwMnoteFaceVersion:1207959808,"
              "HwMnoteCaptureMode:0,"
              "HwMnoteFrontCamera:0,"
              "HwMnoteRollAngle:26,"
              "HwMnotePitchAngle:-83,"
              "HwMnotePhysicalAperture:1");
}


/**
 * @tc.name: ReadBlob002
 * @tc.desc: test ReadBlob from error jpeg image1 which does not have 0xff, return false
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, ReadBlob001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_ERROR1_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    DataBuf exifBuf;
    ASSERT_FALSE(imageAccessor.ReadBlob(exifBuf));
}

/**
 * @tc.name: ReadBlob003
 * @tc.desc: test ReadBlob from error jpeg image2 which does not have APP1, return false
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, ReadBlob002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_ERROR2_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    DataBuf exifBuf;
    ASSERT_FALSE(imageAccessor.ReadBlob(exifBuf));
}

/**
 * @tc.name: ReadBlob004
 * @tc.desc: test ReadBlob from right jpeg image, return true and the length of exifBlob
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, ReadBlob003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    DataBuf exifBuf;
    ASSERT_TRUE(imageAccessor.ReadBlob(exifBuf));
    ASSERT_EQ(exifBuf.Size(), 0x0930);
}

/**
 * @tc.name: Write001
 * @tc.desc: test Write from right jpeg image, modify "BitsPerSample" propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE1_JPEG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("BitsPerSample", "8,8,8"));
    ASSERT_TRUE(exifMetadata->SetValue("Orientation", "8"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageLength", "4000"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageWidth", "3000"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTimeOriginal", "2024:01:11 09:39:58"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureTime", "1/590"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedRatings", "160"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTimeStamp", "11/1 37/1 56/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDateStamp", "2024:01:11"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageDescription", "_cuva"));
    ASSERT_TRUE(exifMetadata->SetValue("Flash", "7"));
    ASSERT_TRUE(exifMetadata->SetValue("PixelXDimension", "4000"));
    ASSERT_TRUE(exifMetadata->SetValue("PixelYDimension", "3000"));
    ASSERT_TRUE(exifMetadata->SetValue("WhiteBalance", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalLengthIn35mmFilm", "28"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "8, 8, 8");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Left-bottom");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "4000");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "3000");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2024:01:11 09:39:58");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/590 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "160");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTimeStamp"), "11:37:56.00");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "2024:01:11");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageDescription"), "_cuva");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Strobe return light detected");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "4000");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "3000");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Manual white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "28");
}

/**
 * @tc.name: Write002
 * @tc.desc: test Write from nonexisting image file, return error number
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE3_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "9, 7, 8");

    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_WRITE1_JPEG_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageWriteAccessor(writeStream);
    ASSERT_EQ(imageWriteAccessor.Write(), ERR_MEDIA_VALUE_INVALID);
}

/**
 * @tc.name: Write003
 * @tc.desc: test Write from right jpeg image, modify "GPSLongitudeRef" propert set value "W"
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE5_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("GPSLongitudeRef", "W"));
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "W");
    ASSERT_EQ(imageAccessor.Write(), 0);
    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "W");
}

/**
 * @tc.name: Write004
 * @tc.desc: test Write from right jpeg image,read and write
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write004, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE7_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(imageAccessor.Write(), 0);
    ASSERT_EQ(imageAccessor.Read(), 0);
}

/**
 * @tc.name: Write005
 * @tc.desc: test Write from right jpeg image, modify Image propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write005, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE9_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "NewSubfileType"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "500");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "1000");
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "9, 7, 8");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "JPEG compression");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageDescription"), "_cuva");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "TNY-AL00");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-right");
    ASSERT_EQ(GetProperty(exifMetadata, "SamplesPerPixel"), "23");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "PlanarConfiguration"), "Chunky format");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");

    ASSERT_TRUE(exifMetadata->SetValue("NewSubfileType", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageWidth", "501"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageLength", "1001"));
    ASSERT_TRUE(exifMetadata->SetValue("BitsPerSample", "8,6,7"));
    ASSERT_TRUE(exifMetadata->SetValue("Compression", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageDescription", "_CUVA"));
    ASSERT_TRUE(exifMetadata->SetValue("Model", "tny-al00"));
    ASSERT_TRUE(exifMetadata->SetValue("Orientation", "8"));
    ASSERT_TRUE(exifMetadata->SetValue("SamplesPerPixel", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("XResolution", "180"));
    ASSERT_TRUE(exifMetadata->SetValue("YResolution", "180"));
    ASSERT_TRUE(exifMetadata->SetValue("PlanarConfiguration", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("ResolutionUnit", "3"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "NewSubfileType"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "501");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "1001");
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "8, 6, 7");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "Uncompressed");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageDescription"), "_CUVA");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "tny-al00");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Left-bottom");
    ASSERT_EQ(GetProperty(exifMetadata, "SamplesPerPixel"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "180");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "180");
    ASSERT_EQ(GetProperty(exifMetadata, "PlanarConfiguration"), "Planar format");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Centimeter");
}

/**
 * @tc.name: Write006
 * @tc.desc: test Write from right jpeg image, modify Image propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write006, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE11_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "TransferFunction"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "MNA-AL00 4.0.0.120(C00E116R3P7)");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "Joseph.Xu");
    ASSERT_EQ(GetProperty(exifMetadata, "WhitePoint"), "124.2");
    ASSERT_EQ(GetProperty(exifMetadata, "PrimaryChromaticities"), "124");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGProc"), "252");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "0.299, 0.587, 0.114");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrSubSampling"), "3, 2");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Centered");
    ASSERT_EQ(GetProperty(exifMetadata, "ReferenceBlackWhite"), "221");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "xxxxxx (Photographer) - [None] (Editor)");
    ASSERT_EQ(GetProperty(exifMetadata, "SpectralSensitivity"), "sensitivity");

    ASSERT_TRUE(exifMetadata->SetValue("TransferFunction", "4"));
    ASSERT_TRUE(exifMetadata->SetValue("Software", "LNA-AL00"));
    ASSERT_TRUE(exifMetadata->SetValue("Artist", "Jane.Zhu"));
    ASSERT_TRUE(exifMetadata->SetValue("WhitePoint", "1282/10"));
    ASSERT_TRUE(exifMetadata->SetValue("PrimaryChromaticities", "128/1"));
    ASSERT_TRUE(exifMetadata->SetValue("JPEGProc", "254"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrCoefficients", "300/1000 600/1000 120/1000"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrSubSampling", "4 3"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrPositioning", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("ReferenceBlackWhite", "222/1"));
    ASSERT_TRUE(exifMetadata->SetValue("Copyright", "XXXXXX"));
    ASSERT_TRUE(exifMetadata->SetValue("SpectralSensitivity", "Sensitivity"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "TransferFunction"), "4");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "LNA-AL00");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "Jane.Zhu");
    ASSERT_EQ(GetProperty(exifMetadata, "WhitePoint"), "128.2");
    ASSERT_EQ(GetProperty(exifMetadata, "PrimaryChromaticities"), "128");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGProc"), "254");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "0.300, 0.600, 0.120");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrSubSampling"), "4, 3");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Co-sited");
    ASSERT_EQ(GetProperty(exifMetadata, "ReferenceBlackWhite"), "222");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "XXXXXX (Photographer) - [None] (Editor)");
    ASSERT_EQ(GetProperty(exifMetadata, "SpectralSensitivity"), "Sensitivity");
}

/**
 * @tc.name: Write007
 * @tc.desc: test Write from right jpeg image, modify Image propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write007, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE13_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "OECF"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "0.08 EV (f/1.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistance"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "DNGVersion"), "0x01, 0x01, 0x02, 0x03");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "12, 1");
    ASSERT_EQ(GetProperty(exifMetadata, "SubfileType"), "");

    ASSERT_TRUE(exifMetadata->SetValue("OECF", "1 bytes"));
    ASSERT_TRUE(exifMetadata->SetValue("MaxApertureValue", "9/100"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectDistance", "25/1"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectLocation", "5 12"));
    ASSERT_TRUE(exifMetadata->SetValue("DNGVersion", "1 1 0 0"));
    ASSERT_TRUE(exifMetadata->SetValue("DefaultCropSize", "1 1"));
    ASSERT_TRUE(exifMetadata->SetValue("SubfileType", "1"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "OECF"), "7 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "0.09 EV (f/1.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistance"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "DNGVersion"), "0x01, 0x01, 0x00, 0x00");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "1, 1");
    ASSERT_EQ(GetProperty(exifMetadata, "SubfileType"), "1");
}

/**
 * @tc.name: Write008
 * @tc.desc: test Write from right jpeg image, modify GPSInfo propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write008, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE15_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSVersionID"), "2.2.0.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitude"), "39, 54, 20");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "E");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitude"), "120, 52, 26");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitudeRef"), "Sea level reference");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitude"), "0.00");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSatellites"), "xxx");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSStatus"), "V");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMeasureMode"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDOP"), "182");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeedRef"), "K");

    ASSERT_TRUE(exifMetadata->SetValue("GPSVersionID", "1.1.0.0"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLatitudeRef", "S"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLatitude", "38/1 53/1 19/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLongitudeRef", "W"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLongitude", "121/1 51/1 25/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAltitudeRef", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAltitude", "1/1000"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSatellites", "XXX"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSStatus", "A"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSMeasureMode", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDOP", "200/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeedRef", "M"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSVersionID"), "1.1.0.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "S");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitude"), "38, 53, 19");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "W");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitude"), "121, 51, 25");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitudeRef"), "Sea level");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitude"), "0.001");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSatellites"), "XXX");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSStatus"), "A");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMeasureMode"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDOP"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeedRef"), "M");
}

/**
 * @tc.name: Write009
 * @tc.desc: test Write from right jpeg image, modify GPSInfo propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write009, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE17_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "150");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrackRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrack"), "56");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirectionRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirection"), "2.23214");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMapDatum"), "xxxx");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitudeRef"), "E");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearingRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearing"), "2.6");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistanceRef"), "N");

    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeed", "151/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTrackRef", "M"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTrack", "60/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSImgDirectionRef", "T"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSImgDirection", "223218/100000"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSMapDatum", "XXXX"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLatitudeRef", "S"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLatitude", "32/1 21/1 10/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLongitudeRef", "W"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLongitude", "32/1 21/1 10/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestBearingRef", "M"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestBearing", "28/10"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestDistanceRef", "K"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "151");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrackRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrack"), "60");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirectionRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirection"), "2.23218");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMapDatum"), "XXXX");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitudeRef"), "S");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitude"), "32, 21, 10");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitudeRef"), "W");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitude"), "32, 21, 10");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearingRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearing"), "2.8");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistanceRef"), "K");
}

/**
 * @tc.name: Write010
 * @tc.desc: test Write from right jpeg image, modify GPSInfo propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write010, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE19_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistance"), "10");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSProcessingMethod"), "CELLID");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAreaInformation"), "23...15...57");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "2025:01:11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDifferential"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSHPositioningError"), " 3");

    ASSERT_TRUE(exifMetadata->SetValue("GPSDestDistance", "11/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSProcessingMethod", "14 bytes"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAreaInformation", "20 bytes"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDateStamp", "2025:01:12"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDifferential", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSHPositioningError", "5/1"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistance"), "11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSProcessingMethod"), "14 bytes");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAreaInformation"), "20 bytes");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "2025:01:12");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDifferential"), "0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSHPositioningError"), " 5");
}

/**
 * @tc.name: Write011
 * @tc.desc: test Write from right jpeg image, modify Photo propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write011, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE21_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/34 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/3.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Normal program");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "160");
    ASSERT_EQ(GetProperty(exifMetadata, "SensitivityType"), "Standard output sensitivity (SOS) and ISO speed");
    ASSERT_EQ(GetProperty(exifMetadata, "StandardOutputSensitivity"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "RecommendedExposureIndex"), "241");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeed"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudeyyy"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudezzz"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "ExifVersion"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2024:01:25 05:51:34");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2023:01:19 10:39:58");

    ASSERT_TRUE(exifMetadata->SetValue("ExposureTime", "1/44"));
    ASSERT_TRUE(exifMetadata->SetValue("FNumber", "4/1"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureProgram", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedRatings", "180"));
    ASSERT_TRUE(exifMetadata->SetValue("SensitivityType", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("StandardOutputSensitivity", "8"));
    ASSERT_TRUE(exifMetadata->SetValue("RecommendedExposureIndex", "261"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeed", "100"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedLatitudeyyy", "100"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedLatitudezzz", "100"));
    ASSERT_TRUE(exifMetadata->SetValue("ExifVersion", "0210"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTimeOriginal", "2024:01:25 05:51:35"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTimeDigitized", "2023:01:19 10:39:59"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/44 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/4.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Manual");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "180");
    ASSERT_EQ(GetProperty(exifMetadata, "SensitivityType"), "Recommended exposure index (REI)");
    ASSERT_EQ(GetProperty(exifMetadata, "StandardOutputSensitivity"), "8");
    ASSERT_EQ(GetProperty(exifMetadata, "RecommendedExposureIndex"), "261");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeed"), "100");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudeyyy"), "100");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudezzz"), "100");
    ASSERT_EQ(GetProperty(exifMetadata, "ExifVersion"), "Exif Version 2.1");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2024:01:25 05:51:35");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2023:01:19 10:39:59");
}

/**
 * @tc.name: Write012
 * @tc.desc: test Write from right jpeg image, modify Photo propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write012, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE23_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTime"), "xx");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeOriginal"), "xx");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeDigitized"), "xx");
    ASSERT_EQ(GetProperty(exifMetadata, "ComponentsConfiguration"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "CompressedBitsPerPixel"), "1.5");
    ASSERT_EQ(GetProperty(exifMetadata, "ShutterSpeedValue"), "13.00 EV (1/8192 sec.)");
    ASSERT_EQ(GetProperty(exifMetadata, "ApertureValue"), "4.00 EV (f/4.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "BrightnessValue"), "2.50 EV (19.38 cd/m^2)");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "23.00 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Pattern");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Fluorescent");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Strobe return light not detected");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "31.0 mm");

    ASSERT_TRUE(exifMetadata->SetValue("OffsetTime", "2024:04:11"));
    ASSERT_TRUE(exifMetadata->SetValue("OffsetTimeOriginal", "XX"));
    ASSERT_TRUE(exifMetadata->SetValue("OffsetTimeDigitized", "XX"));
    ASSERT_TRUE(exifMetadata->SetValue("ComponentsConfiguration", "1456"));
    ASSERT_TRUE(exifMetadata->SetValue("CompressedBitsPerPixel", "25/10"));
    ASSERT_TRUE(exifMetadata->SetValue("ShutterSpeedValue", "15/1"));
    ASSERT_TRUE(exifMetadata->SetValue("ApertureValue", "5/1"));
    ASSERT_TRUE(exifMetadata->SetValue("BrightnessValue", "27/10"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureBiasValue", "25/1"));
    ASSERT_TRUE(exifMetadata->SetValue("MeteringMode", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("LightSource", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("Flash", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalLength", "35/1"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTime"), "2024:04:11");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeOriginal"), "XX");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeDigitized"), "XX");
    ASSERT_EQ(GetProperty(exifMetadata, "ComponentsConfiguration"), "Y R G B");
    ASSERT_EQ(GetProperty(exifMetadata, "CompressedBitsPerPixel"), "2.5");
    ASSERT_EQ(GetProperty(exifMetadata, "ShutterSpeedValue"), "15.00 EV (1/32768 sec.)");
    ASSERT_EQ(GetProperty(exifMetadata, "ApertureValue"), "5.00 EV (f/5.7)");
    ASSERT_EQ(GetProperty(exifMetadata, "BrightnessValue"), "2.70 EV (22.26 cd/m^2)");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "25.00 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Average");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Daylight");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Flash fired");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "35.0 mm");
}

/**
 * @tc.name: Write013
 * @tc.desc: test Write from right jpeg image, modify Photo propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write013, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE25_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "HwMnoteCaptureMode:123");
    ASSERT_EQ(GetProperty(exifMetadata, "UserComment"), "comm");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTime"), "427000");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeOriginal"), "427000");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "427000");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashpixVersion"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "Adobe RGB");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "1000");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "2000");
    ASSERT_EQ(GetProperty(exifMetadata, "RelatedSoundFile"), "/usr/home/sound/sea.wav");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashEnergy"), "832");
    ASSERT_EQ(GetProperty(exifMetadata, "SpatialFrequencyResponse"), ".");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneXResolution"), "1080");

    ASSERT_TRUE(exifMetadata->SetValue("UserComment", "Comm"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTime", "4280000"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTimeOriginal", "4280000"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTimeDigitized", "4280000"));
    ASSERT_TRUE(exifMetadata->SetValue("FlashpixVersion", "0100"));
    ASSERT_TRUE(exifMetadata->SetValue("ColorSpace", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("PixelXDimension", "1001"));
    ASSERT_TRUE(exifMetadata->SetValue("PixelYDimension", "2002"));
    ASSERT_TRUE(exifMetadata->SetValue("RelatedSoundFile", "/usr/home/sound/sea1.wav"));
    ASSERT_TRUE(exifMetadata->SetValue("FlashEnergy", "800/1"));
    ASSERT_TRUE(exifMetadata->SetValue("SpatialFrequencyResponse", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneXResolution", "1081/1"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "HwMnoteCaptureMode:123");
    ASSERT_EQ(GetProperty(exifMetadata, "UserComment"), "Comm");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTime"), "4280000");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeOriginal"), "4280000");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "4280000");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashpixVersion"), "FlashPix Version 1.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "sRGB");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "1001");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "2002");
    ASSERT_EQ(GetProperty(exifMetadata, "RelatedSoundFile"), "/usr/home/sound/sea1.wav");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashEnergy"), "800");
    ASSERT_EQ(GetProperty(exifMetadata, "SpatialFrequencyResponse"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneXResolution"), "1081");
}

/**
 * @tc.name: Write014
 * @tc.desc: test Write from right jpeg image, modify Photo propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write014, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE27_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneYResolution"), "880");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneResolutionUnit"), "Centimeter");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureIndex"), "1.5");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "Two-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "FileSource"), "DSC");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    ASSERT_EQ(GetProperty(exifMetadata, "CFAPattern"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Custom process");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Manual white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), "321");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "26");

    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneYResolution", "881/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneResolutionUnit", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectLocation", "5 12"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureIndex", "5/2"));
    ASSERT_TRUE(exifMetadata->SetValue("SensingMethod", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("FileSource", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("SceneType", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("CFAPattern", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("CustomRendered", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureMode", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("WhiteBalance", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("DigitalZoomRatio", "123/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalLengthIn35mmFilm", "30"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneYResolution"), "881");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureIndex"), "2.5");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "One-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "FileSource"), "Internal error (unknown value 2)");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    ASSERT_EQ(GetProperty(exifMetadata, "CFAPattern"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Normal process");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto bracket");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), "123");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "30");
}

/**
 * @tc.name: Write015
 * @tc.desc: test Write from right jpeg image, modify Photo propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write015, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE29_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Standard");
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "DeviceSettingDescription"), ".");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Unknown");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "FXIC012");
    ASSERT_EQ(GetProperty(exifMetadata, "CameraOwnerName"), "xx");
    ASSERT_EQ(GetProperty(exifMetadata, "BodySerialNumber"), "xx");
    ASSERT_EQ(GetProperty(exifMetadata, "LensSpecification"), " 1, 1.5,  1,  2");
    ASSERT_EQ(GetProperty(exifMetadata, "LensMake"), "xxx");
    ASSERT_EQ(GetProperty(exifMetadata, "LensModel"), "xxx");

    ASSERT_TRUE(exifMetadata->SetValue("SceneCaptureType", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("GainControl", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("Contrast", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("Saturation", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("Sharpness", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("DeviceSettingDescription", "1 bytes"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectDistanceRange", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageUniqueID", "fxic012"));
    ASSERT_TRUE(exifMetadata->SetValue("CameraOwnerName", "XX"));
    ASSERT_TRUE(exifMetadata->SetValue("BodySerialNumber", "XX"));
    ASSERT_TRUE(exifMetadata->SetValue("LensSpecification", "1/1 5/2 3/1 2/1"));
    ASSERT_TRUE(exifMetadata->SetValue("LensMake", "XXX"));
    ASSERT_TRUE(exifMetadata->SetValue("LensModel", "XXX"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Portrait");
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "High gain up");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Hard");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Low saturation");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Soft");
    ASSERT_EQ(GetProperty(exifMetadata, "DeviceSettingDescription"), "1 bytes");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Distant view");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "fxic012");
    ASSERT_EQ(GetProperty(exifMetadata, "CameraOwnerName"), "XX");
    ASSERT_EQ(GetProperty(exifMetadata, "BodySerialNumber"), "XX");
    ASSERT_EQ(GetProperty(exifMetadata, "LensSpecification"), " 1, 2.5,  3,  2");
    ASSERT_EQ(GetProperty(exifMetadata, "LensMake"), "XXX");
    ASSERT_EQ(GetProperty(exifMetadata, "LensModel"), "XXX");
}

/**
 * @tc.name: Write016
 * @tc.desc: test Write from right jpeg image, modify Photo propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, Write016, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE31_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "LensSerialNumber"), "xxx");
    ASSERT_EQ(GetProperty(exifMetadata, "CompositeImage"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceImageNumberOfCompositeImage"), "1234");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceExposureTimesOfCompositeImage"), ".");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "1.5");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGInterchangeFormat"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGInterchangeFormatLength"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "PhotometricInterpretation"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "RowsPerStrip"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "StripByteCounts"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "StripOffsets"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectArea"),
        "Within rectangle (width 183, height 259) around (x,y) = (10,20)");

    ASSERT_TRUE(exifMetadata->SetValue("LensSerialNumber", "XXX"));
    ASSERT_TRUE(exifMetadata->SetValue("CompositeImage", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("SourceImageNumberOfCompositeImage", "34 56"));
    ASSERT_TRUE(exifMetadata->SetValue("SourceExposureTimesOfCompositeImage", "1 bytes"));
    ASSERT_TRUE(exifMetadata->SetValue("Gamma", "25/10"));
    ASSERT_TRUE(exifMetadata->SetValue("PhotometricInterpretation", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("RowsPerStrip", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("StripByteCounts", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("StripOffsets", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectArea", "11 21"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "LensSerialNumber"), "XXX");
    ASSERT_EQ(GetProperty(exifMetadata, "CompositeImage"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceImageNumberOfCompositeImage"), "34");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceExposureTimesOfCompositeImage"), "1 bytes");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "2.5");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGInterchangeFormat"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGInterchangeFormatLength"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "PhotometricInterpretation"), "Reversed mono");
    ASSERT_EQ(GetProperty(exifMetadata, "RowsPerStrip"), "0");
    ASSERT_EQ(GetProperty(exifMetadata, "StripByteCounts"), "0");
    ASSERT_EQ(GetProperty(exifMetadata, "StripOffsets"), "0");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectArea"),
        "Within rectangle (width 183, height 259) around (x,y) = (11,21)");
}

/**
 * @tc.name: WriteBlob001
 * @tc.desc: test WriteBlob from right jpeg image, modify propert
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, WriteBlob001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE2_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageReadAccessor(readStream);
    DataBuf inputBuf;
    ASSERT_TRUE(imageReadAccessor.ReadBlob(inputBuf));

    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_WRITE2_JPEG_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageWriteAccessor(writeStream);
    ASSERT_EQ(imageWriteAccessor.WriteBlob(inputBuf), 0);

    DataBuf outputBuf;
    ASSERT_TRUE(imageWriteAccessor.ReadBlob(outputBuf));
    ASSERT_EQ(outputBuf.Size(), inputBuf.Size());
}

/**
 * @tc.name: WriteBlob002
 * @tc.desc: test WriteBlob from empty data buffer, return error number
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, WriteBlob002, TestSize.Level3)
{
    DataBuf inputBuf;
    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_WRITE4_JPEG_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageWriteAccessor(writeStream);
    ASSERT_EQ(imageWriteAccessor.WriteBlob(inputBuf), ERR_MEDIA_VALUE_INVALID);
}

/**
 * @tc.name: WriteBlob003
 * @tc.desc: test WriteBlob from right jpeg image, Data buffer not container "EXIF\0\0"
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, WriteBlob003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE2_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageReadAccessor(readStream);
    DataBuf inputBuf;
    ASSERT_TRUE(imageReadAccessor.ReadBlob(inputBuf));

    auto length = 0;
    if (inputBuf.CmpBytes(0, EXIF_ID, EXIF_ID_SIZE) == 0) {
        length = EXIF_ID_SIZE;
    }

    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_WRITE6_JPEG_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageWriteAccessor(writeStream);
    DataBuf dataBlob(inputBuf.CData(length), (inputBuf.Size() - length));
    ASSERT_EQ(imageWriteAccessor.WriteBlob(dataBlob), 0);

    DataBuf outputBuf;
    ASSERT_TRUE(imageWriteAccessor.ReadBlob(outputBuf));
    ASSERT_EQ(outputBuf.Size(), inputBuf.Size());
}

std::string JpegExifMetadataAccessorTest::GetProperty(const std::shared_ptr<ExifMetadata> &metadata,
    const std::string &prop)
{
    std::string value;
    metadata->GetValue(prop, value);
    return value;
}

/**
 * @tc.name: testGPSFormat001
 * @tc.desc: test GPSLatitude, GPSLongitude Format
 * @tc.type: FUNC
 */
HWTEST_F(JpegExifMetadataAccessorTest, testGPSFormat001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE5_JPEG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    JpegExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    bool ret = exifMetadata->SetValue("GPSLatitude", " 10, 20, 25.16513");
    ASSERT_EQ(ret, true);
    ret = exifMetadata->SetValue("GPSLongitude", " 10.0, 20, 25.16513");
    ASSERT_EQ(ret, true);

    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitude"), "10, 20, 25.16513");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitude"), "10, 20, 25.16513");
}

} // namespace Multimedia
} // namespace OHOS