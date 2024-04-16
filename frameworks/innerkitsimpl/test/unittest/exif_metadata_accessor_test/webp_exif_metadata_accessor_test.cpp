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
#include <map>

#include "file_metadata_stream.h"
#include "log_tags.h"
#include "media_errors.h"
#include "webp_exif_metadata_accessor.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {

namespace {
constexpr auto IMAGE_INPUT_READ1_WEBP_SIZE = 25294;
constexpr auto IMAGE_INPUT_READ6_WEBP_SIZE = 570;
constexpr auto IMAGE_INPUT_READ8_WEBP_SIZE = 4244;
static const std::string IMAGE_INPUT_READ1_WEBP_PATH = "/data/local/tmp/image/test_webp_readexifblob001.webp";
static const std::string IMAGE_INPUT_READ2_WEBP_PATH = "/data/local/tmp/image/test_webp_readexifblob002.webp";
static const std::string IMAGE_INPUT_READ3_WEBP_PATH = "/data/local/tmp/image/test_webp_readmetadata001.webp";
static const std::string IMAGE_INPUT_READ4_WEBP_PATH = "/data/local/tmp/image/test_webp_readmetadata002.webp";
static const std::string IMAGE_INPUT_READ5_WEBP_PATH = "/data/local/tmp/image/test_webp_readmetadata003.webp";
static const std::string IMAGE_INPUT_READ6_WEBP_PATH = "/data/local/tmp/image/test_webp_readmetadata004.webp";
static const std::string IMAGE_INPUT_READ7_WEBP_PATH = "/data/local/tmp/image/test_webp_readmetadata005.webp";
static const std::string IMAGE_INPUT_READ8_WEBP_PATH = "/data/local/tmp/image/test_webp_readmetadata006.webp";
static const std::string IMAGE_INPUT_READ9_WEBP_PATH = "/data/local/tmp/image/test_webp_readmetadata007.webp";
static const std::string IMAGE_INPUT_READ10_WEBP_PATH = "/data/local/tmp/image/test_webp_readmetadata008.webp";

static const std::string IMAGE_INPUT_WRITE1_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata001.webp";
static const std::string IMAGE_INPUT_WRITE2_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata002.webp";
static const std::string IMAGE_INPUT_WRITE3_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata003.webp";
static const std::string IMAGE_INPUT_WRITE4_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata004.webp";
static const std::string IMAGE_INPUT_WRITE5_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata005.webp";
static const std::string IMAGE_INPUT_WRITE6_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata006.webp";
static const std::string IMAGE_INPUT_WRITE7_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata007.webp";
static const std::string IMAGE_INPUT_WRITE8_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata008.webp";
static const std::string IMAGE_INPUT_WRITE9_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata009.webp";
static const std::string IMAGE_INPUT_WRITE10_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata010.webp";

static const std::string IMAGE_INPUT_WRITE11_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata011.webp";
static const std::string IMAGE_INPUT_WRITE12_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata012.webp";
static const std::string IMAGE_INPUT_WRITE13_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata013.webp";
static const std::string IMAGE_INPUT_WRITE14_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata014.webp";
static const std::string IMAGE_INPUT_WRITE15_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata015.webp";

static const std::string IMAGE_INPUT_WRITE16_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata016.webp";
static const std::string IMAGE_INPUT_WRITE17_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata017.webp";
static const std::string IMAGE_INPUT_WRITE18_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata018.webp";
static const std::string IMAGE_INPUT_WRITE19_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata019.webp";
static const std::string IMAGE_INPUT_WRITE20_WEBP_PATH = "/data/local/tmp/image/test_webp_writemetadata020.webp";

static const std::string IMAGE_INPUT_WRITE22_WEBP_PATH = "/data/local/tmp/image/test_webp_writeexifblob001.webp";
static const std::string IMAGE_INPUT_WRITE23_WEBP_PATH = "/data/local/tmp/image/test_webp_writeexifblob002.webp";
}

class WebpExifMetadataAccessorTest : public testing::Test {
public:
    WebpExifMetadataAccessorTest() {}
    ~WebpExifMetadataAccessorTest() {}
    std::string GetProperty(const std::shared_ptr<ExifMetadata>& metadata, const std::string& prop);
};

std::string WebpExifMetadataAccessorTest::GetProperty(const std::shared_ptr<ExifMetadata>& metadata,
    const std::string& prop)
{
    std::string value;
    metadata->GetValue(prop, value);
    return value;
}

/**
 * @tc.name: ReadBlob001
 * @tc.desc: test ReadExifBlob001 from right webp image, Data buffer not container "EXIF"
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, ReadBlob001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ1_WEBP_PATH);
    EXPECT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageReadAccessor(readStream);
    DataBuf exifBuf;
    bool result = imageReadAccessor.ReadBlob(exifBuf);
    EXPECT_TRUE(result);
    EXPECT_EQ(exifBuf.Size(), IMAGE_INPUT_READ1_WEBP_SIZE);
}

/**
 * @tc.name: ReadBlob002
 * @tc.desc: test ReadExifBlob from error webp image1 which does not have exifinfo, return false
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, ReadBlob002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ2_WEBP_PATH);
    EXPECT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    EXPECT_FALSE(result);
    EXPECT_EQ(exifBuf.Size(), 0);
}

/**
 * @tc.name: Read001
 * @tc.desc: test the webpDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Read001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ3_WEBP_PATH);
    EXPECT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    EXPECT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    EXPECT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "8, 8, 8");
    EXPECT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-right");
    EXPECT_EQ(GetProperty(exifMetadata, "ImageLength"), "4608");
    EXPECT_EQ(GetProperty(exifMetadata, "ImageWidth"), "3456");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSLatitude"),
        "38.0, 0.4706822422, 2.690550837, 0.1649189067, 0.7691442537, 1755226327/0, 0.0000000000, 553648128/0");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSLongitude"),
        "9.0, 0.1579694976, 0.6649895060, 7.623856795, 0.0000000000, 0.3402061856, 0.5869612838, 3.176445880");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "N");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "W");
    EXPECT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2022:06:02 15:51:35");
    EXPECT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/33 sec.");
    EXPECT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    EXPECT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "400");
    EXPECT_EQ(GetProperty(exifMetadata, "FNumber"), "f/1.8");
    EXPECT_EQ(GetProperty(exifMetadata, "DateTime"), "2022:06:02 15:51:35");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSTimeStamp"), "11:37:58.00");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "2025:01:11");
    EXPECT_EQ(GetProperty(exifMetadata, "ImageDescription"), "_cuva");
    EXPECT_EQ(GetProperty(exifMetadata, "Make"), "HUA");
    EXPECT_EQ(GetProperty(exifMetadata, "Model"), "TNY-AL00");
    EXPECT_EQ(GetProperty(exifMetadata, "SensitivityType"), "Unknown");
    EXPECT_EQ(GetProperty(exifMetadata, "StandardOutputSensitivity"), "5");
    EXPECT_EQ(GetProperty(exifMetadata, "RecommendedExposureIndex"), "241");
    EXPECT_EQ(GetProperty(exifMetadata, "ApertureValue"), "1.69 EV (f/1.8)");
    EXPECT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "0.00 EV");
    EXPECT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Pattern");
    EXPECT_EQ(GetProperty(exifMetadata, "LightSource"), "Daylight");
    EXPECT_EQ(GetProperty(exifMetadata, "Flash"), "Flash did not fire, auto mode");
    EXPECT_EQ(GetProperty(exifMetadata, "FocalLength"), "4.0 mm");
    EXPECT_EQ(GetProperty(exifMetadata, "UserComment"), "place for user comments.");
    EXPECT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "3456");
    EXPECT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "4608");
    EXPECT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");
    EXPECT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "27");
    EXPECT_EQ(GetProperty(exifMetadata, "JPEGProc"), "252");
}

/**
 * @tc.name: Read002
 * @tc.desc: test the webpDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Read002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ3_WEBP_PATH);
    EXPECT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    EXPECT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "1.69 EV (f/1.8)");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "mmm.Xu");
    ASSERT_EQ(GetProperty(exifMetadata, "NewSubfileType"), "0");
    ASSERT_EQ(GetProperty(exifMetadata, "OECF"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "PlanarConfiguration"), "Chunky format");
    ASSERT_EQ(GetProperty(exifMetadata, "PrimaryChromaticities"), "124");
    ASSERT_EQ(GetProperty(exifMetadata, "ReferenceBlackWhite"), "221");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "SamplesPerPixel"), "23");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "JPEG compression");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "TNY-AL00 2.0.0.232(C00E230R2P4)");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "zhongguancun (Photographer) - [None] (Editor)");
    ASSERT_EQ(GetProperty(exifMetadata, "SpectralSensitivity"), "sensitivity");
    ASSERT_EQ(GetProperty(exifMetadata, "DNGVersion"), "0x01, 0x02, 0x03, 0x04");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistance"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "2, 3");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "TransferFunction"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "WhitePoint"), "124");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "0.299, 0.587, 0.114");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Centered");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrSubSampling"), "3, 2");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "25");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeed"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudeyyy"), "10");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudezzz"), "20");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "FXIC012");
}

/**
 * @tc.name: Read003
 * @tc.desc: test the webpDecoded Exif GPSInfo properties
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Read003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ4_WEBP_PATH);
    EXPECT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    EXPECT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitude"), "0.00");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitudeRef"), "Sea level reference");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAreaInformation"), "23...15...57");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDOP"), "182");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearing"), "2.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearingRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistance"), "10");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistanceRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitudeRef"), "E");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDifferential"), "0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirection"), "2.23, 0.67");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirectionRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMapDatum"), "test test test");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMeasureMode"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSProcessingMethod"), "CELLID");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSatellites"), "5 8 20");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "150");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeedRef"), "K");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSStatus"), "1 3");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrack"), "38.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrackRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSVersionID"), "2.2.0.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSHPositioningError"), "20");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGInterchangeFormat"), "1954");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGInterchangeFormatLength"), "24042");
    ASSERT_EQ(GetProperty(exifMetadata, "LensMake"), "www");
    ASSERT_EQ(GetProperty(exifMetadata, "LensModel"), "H1");
    ASSERT_EQ(GetProperty(exifMetadata, "LensSerialNumber"), "21mm");
    ASSERT_EQ(GetProperty(exifMetadata, "LensSpecification"), "33, 22, 11, 10");
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTime"), "2023:01:19 10:39:58");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeDigitized"), "2023:01:20 10:39:00");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeOriginal"), "2023:01:21 10:39:09");
    ASSERT_EQ(GetProperty(exifMetadata, "PhotometricInterpretation"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "RelatedSoundFile"), "/home/abc/include");
    ASSERT_EQ(GetProperty(exifMetadata, "RowsPerStrip"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Normal");
}

/**
 * @tc.name: Read004
 * @tc.desc: test the webpDecoded Exif photo properties
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Read004, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ5_WEBP_PATH);
    EXPECT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    EXPECT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    EXPECT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Standard");
    EXPECT_EQ(GetProperty(exifMetadata, "SensingMethod"), "One-chip color area sensor");
    EXPECT_EQ(GetProperty(exifMetadata, "Sharpness"), "Normal");
    EXPECT_EQ(GetProperty(exifMetadata, "ShutterSpeedValue"), "29.90 EV (1/999963365 sec.)");
    EXPECT_EQ(GetProperty(exifMetadata, "SourceExposureTimesOfCompositeImage"), "o");
    EXPECT_EQ(GetProperty(exifMetadata, "SourceImageNumberOfCompositeImage"), "33, 22");
    EXPECT_EQ(GetProperty(exifMetadata, "SpatialFrequencyResponse"), ".");
    EXPECT_EQ(GetProperty(exifMetadata, "StripByteCounts"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "StripOffsets"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "SubsecTime"), "427000");
    EXPECT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "427000");
    EXPECT_EQ(GetProperty(exifMetadata, "SubsecTimeOriginal"), "427000");
    EXPECT_EQ(GetProperty(exifMetadata, "SubfileType"), "1");
    EXPECT_EQ(GetProperty(exifMetadata, "SubjectArea"),
        "Within rectangle (width 183, height 259) around (x,y) = (10,20)");
    EXPECT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Unknown");
    EXPECT_EQ(GetProperty(exifMetadata, "BodySerialNumber"), "bodyserialnumber");
    EXPECT_EQ(GetProperty(exifMetadata, "BrightnessValue"), "0.00 EV (3.43 cd/m^2)");
    EXPECT_EQ(GetProperty(exifMetadata, "CFAPattern"), "1 bytes undefined data");
    EXPECT_EQ(GetProperty(exifMetadata, "CameraOwnerName"), "cameraownername");
    EXPECT_EQ(GetProperty(exifMetadata, "ColorSpace"), "sRGB");
    EXPECT_EQ(GetProperty(exifMetadata, "ComponentsConfiguration"), "Y Cb Cr -");
    EXPECT_EQ(GetProperty(exifMetadata, "CompositeImage"), "10");
    EXPECT_EQ(GetProperty(exifMetadata, "CompressedBitsPerPixel"), "0.95");
    EXPECT_EQ(GetProperty(exifMetadata, "Contrast"), "Normal");
    EXPECT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Custom process");
    EXPECT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2022:06:02 15:51:35");
    EXPECT_EQ(GetProperty(exifMetadata, "DeviceSettingDescription"), ".");
    EXPECT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), "1.00");
    EXPECT_EQ(GetProperty(exifMetadata, "ExifVersion"), "Exif Version 2.1");
    EXPECT_EQ(GetProperty(exifMetadata, "ExposureIndex"), "1.5");
    EXPECT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto exposure");
    EXPECT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Normal program");
    EXPECT_EQ(GetProperty(exifMetadata, "FileSource"), "DSC");
    EXPECT_EQ(GetProperty(exifMetadata, "FlashEnergy"), "832");
    EXPECT_EQ(GetProperty(exifMetadata, "FlashpixVersion"), "FlashPix Version 1.0");
    EXPECT_EQ(GetProperty(exifMetadata, "FocalPlaneResolutionUnit"), "Centimeter");
    EXPECT_EQ(GetProperty(exifMetadata, "FocalPlaneXResolution"), "1080");
    EXPECT_EQ(GetProperty(exifMetadata, "FocalPlaneYResolution"), "880");
}

/**
 * @tc.name: Read005
 * @tc.desc: test the webpDecoded Exif HW properties
 * @tc.type: FUNC
 */

HWTEST_F(WebpExifMetadataAccessorTest, Read005, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ6_WEBP_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);

    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    DataBuf exifBuf;
    EXPECT_TRUE(imageAccessor.ReadBlob(exifBuf));
    EXPECT_EQ(exifBuf.Size(), IMAGE_INPUT_READ6_WEBP_SIZE);
    auto exifMetadata = imageAccessor.Get();
    EXPECT_NE(exifMetadata, nullptr);

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

    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteCaptureMode", "0"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteCaptureMode"), "0");
}

/**
 * @tc.name: Read006
 * @tc.desc: test the webpDecoded Exif and all chunks exist
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Read006, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ7_WEBP_PATH);
    EXPECT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    EXPECT_EQ(result, 0);

    DataBuf exifBuf;
    EXPECT_TRUE(imageAccessor.ReadBlob(exifBuf));
    auto exifMetadata = imageAccessor.Get();
    EXPECT_NE(exifMetadata, nullptr);

    EXPECT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "8, 8, 8");
    EXPECT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-right");
    EXPECT_EQ(GetProperty(exifMetadata, "ImageLength"), "4608");
    EXPECT_EQ(GetProperty(exifMetadata, "ImageWidth"), "3456");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSLatitude"),
        "38.0, 0.4706822422, 2.690550837, 0.1649189067, 0.7691442537, 1755226327/0, 0.0000000000, 553648128/0");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSLongitude"),
        "9.0, 0.1579694976, 0.6649895060, 7.623856795, 0.0000000000, 0.3402061856, 0.5869612838, 3.176445880");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "N");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "W");
    EXPECT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2022:06:02 15:51:35");
    EXPECT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/33 sec.");
    EXPECT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    EXPECT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "400");
    EXPECT_EQ(GetProperty(exifMetadata, "FNumber"), "f/1.8");
    EXPECT_EQ(GetProperty(exifMetadata, "DateTime"), "2022:06:02 15:51:35");
    EXPECT_EQ(GetProperty(exifMetadata, "Make"), "HUA");
    EXPECT_EQ(GetProperty(exifMetadata, "Model"), "TNY-AL00");
    EXPECT_EQ(GetProperty(exifMetadata, "ApertureValue"), "1.69 EV (f/1.8)");
    EXPECT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "0.00 EV");
    EXPECT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Pattern");
    EXPECT_EQ(GetProperty(exifMetadata, "LightSource"), "Daylight");
    EXPECT_EQ(GetProperty(exifMetadata, "Flash"), "Flash did not fire, auto mode");
    EXPECT_EQ(GetProperty(exifMetadata, "FocalLength"), "4.0 mm");
    EXPECT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "3456");
    EXPECT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "4608");
    EXPECT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");
    EXPECT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "27");
}

/**
 * @tc.name: Read007
 * @tc.desc: test the webpDecoded Exif and XMP chunk exist
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Read007, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ8_WEBP_PATH);
    EXPECT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    EXPECT_EQ(result, 0);

    DataBuf exifBuf;
    EXPECT_TRUE(imageAccessor.ReadBlob(exifBuf));
    EXPECT_EQ(exifBuf.Size(), IMAGE_INPUT_READ8_WEBP_SIZE);
    auto exifMetadata = imageAccessor.Get();
    EXPECT_NE(exifMetadata, nullptr);

    EXPECT_EQ(GetProperty(exifMetadata, "Orientation"), "Unknown value 0");
    EXPECT_EQ(GetProperty(exifMetadata, "DateTime"), "2015:11:05 23:04:30");
    EXPECT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "1080");
    EXPECT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "1920");
}

/**
 * @tc.name: Read008
 * @tc.desc: test webpDecoded for different chunk features
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Read008, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ9_WEBP_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "3456");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "4608");
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "8, 8, 8");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "TNY-AL00");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-right");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "TNY-AL00 2.0.0.232(C00E230R2P4)");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "2022:06:02 15:51:35");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Centered");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/1.8");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Normal program");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "400");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "1.69 EV (f/1.8)");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "3456");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "4608");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");
}

/**
 * @tc.name: Read009
 * @tc.desc: test webpDecoded for different chunk features
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Read009, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ10_WEBP_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);
}


/**
 * @tc.name: WriteBlob001
 * @tc.desc: test WriteBlob from webp image and rewrite file to full chunks
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, WriteBlob001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ1_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageReadAccessor(readStream);

    DataBuf inputBuf;
    ASSERT_TRUE(imageReadAccessor.ReadBlob(inputBuf));

    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE22_WEBP_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageWriteAccessor(writeStream);
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
HWTEST_F(WebpExifMetadataAccessorTest, WriteBlob002, TestSize.Level3)
{
    DataBuf inputBuf;
    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE22_WEBP_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageWriteAccessor(writeStream);

    ASSERT_EQ(imageWriteAccessor.WriteBlob(inputBuf), ERR_MEDIA_VALUE_INVALID);
}

/**
 * @tc.name: WriteBlob003
 * @tc.desc: test WriteBlob from webp image and rewrite file xmp chunk exist
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, WriteBlob003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_READ1_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageReadAccessor(readStream);

    DataBuf inputBuf;
    ASSERT_TRUE(imageReadAccessor.ReadBlob(inputBuf));

    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE23_WEBP_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageWriteAccessor(writeStream);
    DataBuf dataBlob(inputBuf.CData(), (inputBuf.Size()));
    ASSERT_EQ(imageWriteAccessor.WriteBlob(dataBlob), 0);

    DataBuf outputBuf;
    ASSERT_TRUE(imageWriteAccessor.ReadBlob(outputBuf));
    ASSERT_EQ(outputBuf.Size(), inputBuf.Size());
}


/**
 * @tc.name: Write001
 * @tc.desc: Add exif feature to webp images without any exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE1_WEBP_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(stream);

    EXPECT_TRUE(imageAccessor.Create());
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("NewSubfileType", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("SubfileType", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageWidth", "3456"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageLength", "4608"));
    ASSERT_TRUE(exifMetadata->SetValue("BitsPerSample", "8,8,8"));
    ASSERT_TRUE(exifMetadata->SetValue("Compression", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageDescription", "cuva"));
    ASSERT_TRUE(exifMetadata->SetValue("Make", "HUA"));
    ASSERT_TRUE(exifMetadata->SetValue("Model", "TNY-AL00"));
    ASSERT_TRUE(exifMetadata->SetValue("Orientation", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("SamplesPerPixel", "23"));
    ASSERT_TRUE(exifMetadata->SetValue("XResolution", "72"));
    ASSERT_TRUE(exifMetadata->SetValue("YResolution", "72"));
    ASSERT_TRUE(exifMetadata->SetValue("PlanarConfiguration", "1"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "NewSubfileType"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "SubfileType"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "3456");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "4608");
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "8, 8, 8");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "Uncompressed");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageDescription"), "cuva");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "HUA");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "TNY-AL00");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-right");
    ASSERT_EQ(GetProperty(exifMetadata, "SamplesPerPixel"), "23");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "PlanarConfiguration"), "Chunky format");
}


/**
 * @tc.name: Write002
 * @tc.desc: Add exif feature to webp images without any exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE2_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);

    EXPECT_TRUE(imageAccessor.Create());
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("ResolutionUnit", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("TransferFunction", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("Software", "TNY-AL00 2.0.0.232(C00E230R2P4)"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTime", "2022:06:02 15:51:35"));
    ASSERT_TRUE(exifMetadata->SetValue("Artist", "AllWebp"));
    ASSERT_TRUE(exifMetadata->SetValue("WhitePoint", "124/1"));
    ASSERT_TRUE(exifMetadata->SetValue("PrimaryChromaticities", "124/1"));
    ASSERT_TRUE(exifMetadata->SetValue("JPEGProc", "252"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrCoefficients", "299/1000 587/1000 114/1000"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrSubSampling", "4 2"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrPositioning", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ReferenceBlackWhite", "221/1"));
    ASSERT_TRUE(exifMetadata->SetValue("Copyright", "Hua"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "TransferFunction"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "TNY-AL00 2.0.0.232(C00E230R2P4)");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "2022:06:02 15:51:35");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "AllWebp");
    ASSERT_EQ(GetProperty(exifMetadata, "WhitePoint"), "124, 0/0");
    ASSERT_EQ(GetProperty(exifMetadata, "PrimaryChromaticities"), "124");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGProc"), "252");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "0.299, 0.587, 0.114");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrSubSampling"), "4, 2");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Centered");
    ASSERT_EQ(GetProperty(exifMetadata, "ReferenceBlackWhite"), "221, 255,  0, 255,  0, 255");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "Hua (Photographer) - [None] (Editor)");
}

/**
 * @tc.name: Write003
 * @tc.desc: Add exif feature to webp images without any exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE3_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);

    EXPECT_TRUE(imageAccessor.Create());
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("ExposureTime", "1/44"));
    ASSERT_TRUE(exifMetadata->SetValue("FNumber", "4/1"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureProgram", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedRatings", "400"));
    ASSERT_TRUE(exifMetadata->SetValue("SensitivityType", "5"));
    ASSERT_TRUE(exifMetadata->SetValue("StandardOutputSensitivity", "5"));
    ASSERT_TRUE(exifMetadata->SetValue("RecommendedExposureIndex", "241"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeed", "200"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedLatitudeyyy", "200"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedLatitudezzz", "200"));
    ASSERT_TRUE(exifMetadata->SetValue("ExifVersion", "0210"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTimeOriginal", "2022:06:02 15:51:35"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTimeDigitized", "2022:06:02 15:51:35"));
    ASSERT_TRUE(exifMetadata->SetValue("OffsetTime", "2024:04:11"));
    ASSERT_TRUE(exifMetadata->SetValue("OffsetTimeOriginal", "00xx"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/44 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/4.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Normal program");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "400");
    ASSERT_EQ(GetProperty(exifMetadata, "SensitivityType"), "Standard output sensitivity (SOS) and ISO speed");
    ASSERT_EQ(GetProperty(exifMetadata, "StandardOutputSensitivity"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "RecommendedExposureIndex"), "241");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeed"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudeyyy"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudezzz"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "ExifVersion"), "Exif Version 2.1");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2022:06:02 15:51:35");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2022:06:02 15:51:35");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTime"), "2024:04:11");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeOriginal"), "00xx");
}

/**
 * @tc.name: Write004
 * @tc.desc: Add exif feature to webp images without any exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write004, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE4_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);

    EXPECT_TRUE(imageAccessor.Create());
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("OffsetTimeDigitized", "abs"));
    ASSERT_TRUE(exifMetadata->SetValue("ComponentsConfiguration", "1456"));
    ASSERT_TRUE(exifMetadata->SetValue("CompressedBitsPerPixel", "95/100"));
    ASSERT_TRUE(exifMetadata->SetValue("ShutterSpeedValue", "14/1"));
    ASSERT_TRUE(exifMetadata->SetValue("ApertureValue", "5/1"));
    ASSERT_TRUE(exifMetadata->SetValue("BrightnessValue", "5"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureBiasValue", "27/10"));
    ASSERT_TRUE(exifMetadata->SetValue("MaxApertureValue", "9/100"));
    ASSERT_TRUE(exifMetadata->SetValue("MeteringMode", "5"));
    ASSERT_TRUE(exifMetadata->SetValue("LightSource", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("Flash", "24"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalLength", "35/1"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectArea", "10 20"));
    ASSERT_TRUE(exifMetadata->SetValue("UserComment", "place for user comments."));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeDigitized"), "abs");
    ASSERT_EQ(GetProperty(exifMetadata, "ComponentsConfiguration"), "Y R G B");
    ASSERT_EQ(GetProperty(exifMetadata, "CompressedBitsPerPixel"), "0.95");
    ASSERT_EQ(GetProperty(exifMetadata, "ShutterSpeedValue"), "14.00 EV (1/16384 sec.)");
    ASSERT_EQ(GetProperty(exifMetadata, "ApertureValue"), "5.00 EV (f/5.7)");
    ASSERT_EQ(GetProperty(exifMetadata, "BrightnessValue"), "5.00 EV (109.64 cd/m^2)");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "2.70 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "0.09 EV (f/1.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Pattern");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Daylight");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Flash did not fire, auto mode");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "35.0 mm");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectArea"), "(x,y) = (10,20)");
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "UserComment"), "place for user comments.");
}

/**
 * @tc.name: Write005
 * @tc.desc: Add exif feature to webp images without any exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write005, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE5_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);

    EXPECT_TRUE(imageAccessor.Create());
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTime", "543792"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTimeOriginal", "543792"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTimeDigitized", "543792"));
    ASSERT_TRUE(exifMetadata->SetValue("FlashpixVersion", "0200"));
    ASSERT_TRUE(exifMetadata->SetValue("ColorSpace", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("PixelXDimension", "3456"));
    ASSERT_TRUE(exifMetadata->SetValue("PixelYDimension", "4608"));
    ASSERT_TRUE(exifMetadata->SetValue("RelatedSoundFile", "abb"));
    ASSERT_TRUE(exifMetadata->SetValue("FlashEnergy", "832/1"));
    ASSERT_TRUE(exifMetadata->SetValue("SpatialFrequencyResponse", "13"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneXResolution", "1081/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneYResolution", "880/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneResolutionUnit", "3"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTime"), "543792");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeOriginal"), "543792");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "543792");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashpixVersion"), "Unknown FlashPix Version");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "sRGB");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "3456");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "4608");
    ASSERT_EQ(GetProperty(exifMetadata, "RelatedSoundFile"), "abb");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashEnergy"), "832");
    ASSERT_EQ(GetProperty(exifMetadata, "SpatialFrequencyResponse"), "13");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneXResolution"), "1081");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneYResolution"), "880");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneResolutionUnit"), "Centimeter");
}

/**
 * @tc.name: Write006
 * @tc.desc: Add exif feature to webp images without any exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write006, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE6_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);

    EXPECT_TRUE(imageAccessor.Create());
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("ExposureIndex", "4/2"));
    ASSERT_TRUE(exifMetadata->SetValue("SensingMethod", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("FileSource", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("SceneType", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("CFAPattern", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("CustomRendered", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureMode", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("WhiteBalance", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("DigitalZoomRatio", "100/100"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalLengthIn35mmFilm", "27"));
    ASSERT_TRUE(exifMetadata->SetValue("SceneCaptureType", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("GainControl", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("Contrast", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("Saturation", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("Sharpness", "2"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureIndex"), "2.0");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "One-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "FileSource"), "DSC");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    ASSERT_EQ(GetProperty(exifMetadata, "CFAPattern"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Custom process");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Manual exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), "1.00");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "27");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Portrait");
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "Low gain up");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Soft");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Low saturation");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Hard");
}

/**
 * @tc.name: Write007
 * @tc.desc: Add exif feature to webp images without any exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write007, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE7_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);

    EXPECT_TRUE(imageAccessor.Create());
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("DeviceSettingDescription", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectDistanceRange", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageUniqueID", "FXIC012"));
    ASSERT_TRUE(exifMetadata->SetValue("CameraOwnerName", "2a"));
    ASSERT_TRUE(exifMetadata->SetValue("BodySerialNumber", "x1"));
    ASSERT_TRUE(exifMetadata->SetValue("LensSpecification", "1/1 5/2 3/1 2/1"));
    ASSERT_TRUE(exifMetadata->SetValue("LensMake", "aaa"));
    ASSERT_TRUE(exifMetadata->SetValue("LensModel", "xxx"));
    ASSERT_TRUE(exifMetadata->SetValue("LensSerialNumber", "111a"));
    ASSERT_TRUE(exifMetadata->SetValue("CompositeImage", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("SourceImageNumberOfCompositeImage", "34 56"));
    ASSERT_TRUE(exifMetadata->SetValue("SourceExposureTimesOfCompositeImage", "byte"));
    ASSERT_TRUE(exifMetadata->SetValue("Gamma", "3/2"));
    ASSERT_TRUE(exifMetadata->SetValue("SpectralSensitivity", "Sensitivity"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "DeviceSettingDescription"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Macro");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "FXIC012");
    ASSERT_EQ(GetProperty(exifMetadata, "CameraOwnerName"), "2a");
    ASSERT_EQ(GetProperty(exifMetadata, "BodySerialNumber"), "x1");
    ASSERT_EQ(GetProperty(exifMetadata, "LensSpecification"), " 1, 2.5,  3,  2");
    ASSERT_EQ(GetProperty(exifMetadata, "LensMake"), "aaa");
    ASSERT_EQ(GetProperty(exifMetadata, "LensModel"), "xxx");
    ASSERT_EQ(GetProperty(exifMetadata, "LensSerialNumber"), "111a");
    ASSERT_EQ(GetProperty(exifMetadata, "CompositeImage"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceImageNumberOfCompositeImage"), "34, 56");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceExposureTimesOfCompositeImage"), "byte");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "1.5");
    ASSERT_EQ(GetProperty(exifMetadata, "SpectralSensitivity"), "Sensitivity");
}

/**
 * @tc.name: Write008
 * @tc.desc: Add exif feature to webp images without any exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write008, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE8_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);

    EXPECT_TRUE(imageAccessor.Create());
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("GPSVersionID", "2.2.0.0"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLatitudeRef", "N"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLatitude", "39/1 54/1 20/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLongitudeRef", "E"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLongitude", "120/1 52/1 26/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAltitudeRef", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAltitude", "1/100"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTimeStamp", "11/1 37/1 58/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSatellites", "BBA"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSStatus", "A"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSMeasureMode", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDOP", "182/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeedRef", "M"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeed", "150/1"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSVersionID"), "2.2.0.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitude"), "39, 54, 20");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "E");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitude"), "120, 52, 26");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitudeRef"), "Sea level reference");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitude"), "0.01");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTimeStamp"), "11:37:58.00");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSatellites"), "BBA");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSStatus"), "A");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMeasureMode"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDOP"), "182");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeedRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "150");
}

/**
 * @tc.name: Write009
 * @tc.desc: Add exif feature to webp images without any exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write009, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE9_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);

    EXPECT_TRUE(imageAccessor.Create());
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("GPSTrackRef", "M"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTrack", "111/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSImgDirectionRef", "T"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSImgDirection", "225218/100000"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSMapDatum", "TEST"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLatitudeRef", "N"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLatitude", "33/1 22/1 11/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLongitudeRef", "W"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLongitude", "33/1 22/1 11/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestBearingRef", "M"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestBearing", "22/11"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSMeasureMode", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestDistanceRef", "K"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestDistance", "2/10"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSProcessingMethod", "bytes"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrackRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrack"), "111");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirectionRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirection"), "2.25218");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMapDatum"), "TEST");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitudeRef"), "W");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearingRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearing"), "2.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMeasureMode"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistanceRef"), "K");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistance"), "0.2");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSProcessingMethod"), "bytes");
}

/**
 * @tc.name: Write010
 * @tc.desc: Add exif feature to webp images without any exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write010, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE10_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);

    EXPECT_TRUE(imageAccessor.Create());
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_FALSE(result);
    ASSERT_EQ(exifBuf.Size(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("GPSAreaInformation", "A bytes"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDateStamp", "2022:01:11"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDifferential", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSHPositioningError", "2/1"));
    ASSERT_TRUE(exifMetadata->SetValue("OECF", "abbs"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectLocation", "5 6"));
    ASSERT_TRUE(exifMetadata->SetValue("DNGVersion", "3 3 0 0"));
    ASSERT_TRUE(exifMetadata->SetValue("DefaultCropSize", "2 2"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAreaInformation"), "A bytes");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "2022:01:11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDifferential"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSHPositioningError"), " 2");
    ASSERT_EQ(GetProperty(exifMetadata, "OECF"), "4 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "5, 6");
    ASSERT_EQ(GetProperty(exifMetadata, "DNGVersion"), "3, 3, 0, 0");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "2, 2");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGInterchangeFormat"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGInterchangeFormatLength"), "");
}

/**
 * @tc.name: Write011
 * @tc.desc: Add exif feature to webp images without exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write011, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE11_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitude"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitudeRef"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAreaInformation"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDOP"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearing"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearingRef"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistance"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistanceRef"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitude"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitudeRef"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitude"), "");

    ASSERT_TRUE(exifMetadata->SetValue("GPSAltitude", "1/100"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAltitudeRef", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAreaInformation", "abcd"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDOP", "185/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDateStamp", "2022:01:11"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestBearing", "20/10"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestBearingRef", "M"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestDistance", "1/10"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestDistanceRef", "K"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLatitude", "33/1 22/1 11/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLatitudeRef", "S"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLongitude", "33/1 22/1 11/1"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitude"), "0.01");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitudeRef"), "Sea level reference");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAreaInformation"), "abcd");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDOP"), "185");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "2022:01:11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearing"), "2.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearingRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistance"), "0.1");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistanceRef"), "K");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitudeRef"), "S");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitude"), "33, 22, 11");
}

/**
 * @tc.name: Write012
 * @tc.desc: Add exif feature to webp images without exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write012, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE12_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitudeRef"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSDifferential"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSHPositioningError"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSImgDirection"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSImgDirectionRef"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSMapDatum"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSMeasureMode"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSProcessingMethod"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSSatellites"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSSpeedRef"), "");
    EXPECT_EQ(GetProperty(exifMetadata, "GPSStatus"), "");

    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLongitudeRef", "W"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDifferential", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSHPositioningError", "3/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSImgDirection", "224218/100000"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSImgDirectionRef", "T"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSMapDatum", "TEST"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSMeasureMode", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSProcessingMethod", "BB"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSatellites", "BBA"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeed", "150/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeedRef", "N"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSStatus", "A"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitudeRef"), "W");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDifferential"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSHPositioningError"), " 3");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirection"), "2.24218");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirectionRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMapDatum"), "TEST");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMeasureMode"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSProcessingMethod"), "BB");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSatellites"), "BBA");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "150");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeedRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSStatus"), "A");
}

/**
 * @tc.name: Write013
 * @tc.desc: Add exif feature to webp images without exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write013, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE13_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTimeStamp"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrack"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrackRef"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSVersionID"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "JPEG compression");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "DNGVersion"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageDescription"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGProc"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "NewSubfileType"), "");

    ASSERT_TRUE(exifMetadata->SetValue("GPSTimeStamp", "11/1 37/1 58/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTrack", "110/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTrackRef", "M"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSVersionID", "2.2.0.0"));
    ASSERT_TRUE(exifMetadata->SetValue("Artist", "AllWebp"));
    ASSERT_TRUE(exifMetadata->SetValue("Compression", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("Copyright", "Only"));
    ASSERT_TRUE(exifMetadata->SetValue("DNGVersion", "2 2 0 0"));
    ASSERT_TRUE(exifMetadata->SetValue("DefaultCropSize", "1 1"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageDescription", "_cuva"));
    ASSERT_TRUE(exifMetadata->SetValue("JPEGProc", "225"));
    ASSERT_TRUE(exifMetadata->SetValue("NewSubfileType", "1"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTimeStamp"), "11:37:58.00");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrack"), "110");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrackRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSVersionID"), "2.2.0.0");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "AllWebp");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "Uncompressed");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "Only (Photographer) - [None] (Editor)");
    ASSERT_EQ(GetProperty(exifMetadata, "DNGVersion"), "2, 2, 0, 0");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "1, 1");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageDescription"), "_cuva");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGProc"), "225");
    ASSERT_EQ(GetProperty(exifMetadata, "NewSubfileType"), "1");
}

/**
 * @tc.name: Write014
 * @tc.desc: Add exif feature to webp images without exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write014, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE14_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "OECF"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "PlanarConfiguration"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "PrimaryChromaticities"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "ReferenceBlackWhite"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SamplesPerPixel"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SpectralSensitivity"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SubfileType"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "TransferFunction"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrSubSampling"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "BodySerialNumber"), "");

    ASSERT_TRUE(exifMetadata->SetValue("OECF", "ccad"));
    ASSERT_TRUE(exifMetadata->SetValue("PlanarConfiguration", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("PrimaryChromaticities", "121/1"));
    ASSERT_TRUE(exifMetadata->SetValue("ReferenceBlackWhite", "221/1"));
    ASSERT_TRUE(exifMetadata->SetValue("SamplesPerPixel", "23"));
    ASSERT_TRUE(exifMetadata->SetValue("SpectralSensitivity", "Sensitivity"));
    ASSERT_TRUE(exifMetadata->SetValue("SubfileType", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectLocation", "5 12"));
    ASSERT_TRUE(exifMetadata->SetValue("TransferFunction", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrCoefficients", "299/1000 587/1000 114/1000"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrSubSampling", "4 2"));
    ASSERT_TRUE(exifMetadata->SetValue("BodySerialNumber", "x1"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "OECF"), "4 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "PlanarConfiguration"), "Planar format");
    ASSERT_EQ(GetProperty(exifMetadata, "PrimaryChromaticities"), "121");
    ASSERT_EQ(GetProperty(exifMetadata, "ReferenceBlackWhite"), "221, 255,  0, 255,  0, 255");
    ASSERT_EQ(GetProperty(exifMetadata, "SamplesPerPixel"), "23");
    ASSERT_EQ(GetProperty(exifMetadata, "SpectralSensitivity"), "Sensitivity");
    ASSERT_EQ(GetProperty(exifMetadata, "SubfileType"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "5, 12");
    ASSERT_EQ(GetProperty(exifMetadata, "TransferFunction"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "0.299, 0.587, 0.114");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrSubSampling"), "4, 2");
    ASSERT_EQ(GetProperty(exifMetadata, "BodySerialNumber"), "x1");
}

/**
 * @tc.name: Write015
 * @tc.desc: Add exif feature to webp images without exif information
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write015, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE15_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "CFAPattern"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "CameraOwnerName"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "CompositeImage"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashEnergy"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneResolutionUnit"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneXResolution"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneYResolution"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeed"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudeyyy"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudezzz"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "");

    ASSERT_TRUE(exifMetadata->SetValue("CFAPattern", "aa"));
    ASSERT_TRUE(exifMetadata->SetValue("CameraOwnerName", "ac"));
    ASSERT_TRUE(exifMetadata->SetValue("CompositeImage", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("FlashEnergy", "830/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneResolutionUnit", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneXResolution", "1081/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneYResolution", "880/1"));
    ASSERT_TRUE(exifMetadata->SetValue("Gamma", "5/2"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeed", "100"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedLatitudeyyy", "100"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedLatitudezzz", "4"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageUniqueID", "x1"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "CFAPattern"), "2 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "CameraOwnerName"), "ac");
    ASSERT_EQ(GetProperty(exifMetadata, "CompositeImage"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashEnergy"), "830");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneXResolution"), "1081");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneYResolution"), "880");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "2.5");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeed"), "100");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudeyyy"), "100");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudezzz"), "4");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "x1");
}

/**
 * @tc.name: Write016
 * @tc.desc: Testing Writemetadata to modify exif features
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write016, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE16_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "8, 8, 8");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitude"),
              "38.0, 0.4706822422, 2.690550837, 0.1649189067, 0.7691442537, 1755226327/0, 0.0000000000, 553648128/0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "4608");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "3456");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "HUA");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "TNY-AL00");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-right");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "TNY-AL00 2.0.0.232(C00E230R2P4)");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "72");

    ASSERT_TRUE(exifMetadata->SetValue("BitsPerSample", "9 6 9"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLatitude", "39/1 54/1 20/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLatitudeRef", "S"));
    ASSERT_TRUE(exifMetadata->SetValue("SceneType", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageLength", "4628"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageWidth", "3476"));
    ASSERT_TRUE(exifMetadata->SetValue("Make", "SAMSUNG"));
    ASSERT_TRUE(exifMetadata->SetValue("Model", "DUN-AL00"));
    ASSERT_TRUE(exifMetadata->SetValue("Orientation", "8"));
    ASSERT_TRUE(exifMetadata->SetValue("ResolutionUnit", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("Software", "LNA-AL00"));
    ASSERT_TRUE(exifMetadata->SetValue("XResolution", "82/1"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "9, 6, 9");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitude"),
              "39, 54, 20, 0.1649189067, 0.7691442537, 1755226327/0, 0.0000000000, 553648128/0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "S");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "4628");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "3476");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "SAMSUNG");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "DUN-AL00");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Left-bottom");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Centimeter");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "LNA-AL00");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "82");
}

/**
 * @tc.name: Write017
 * @tc.desc: Testing Writemetadata to modify exif features
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write017, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE17_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Centered");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "ApertureValue"), "1.69 EV (f/1.8)");
    ASSERT_EQ(GetProperty(exifMetadata, "BrightnessValue"), "0.00 EV (3.43 cd/m^2)");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "sRGB");
    ASSERT_EQ(GetProperty(exifMetadata, "ComponentsConfiguration"), "Y Cb Cr -");
    ASSERT_EQ(GetProperty(exifMetadata, "CompressedBitsPerPixel"), "0.95");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Custom process");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2022:06:02 15:51:35");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2022:06:02 15:51:35");

    ASSERT_TRUE(exifMetadata->SetValue("YCbCrPositioning", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("YResolution", "82/1"));
    ASSERT_TRUE(exifMetadata->SetValue("Sharpness", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ApertureValue", "5/1"));
    ASSERT_TRUE(exifMetadata->SetValue("BrightnessValue", "27/10"));
    ASSERT_TRUE(exifMetadata->SetValue("ColorSpace", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("ComponentsConfiguration", "1456"));
    ASSERT_TRUE(exifMetadata->SetValue("CompressedBitsPerPixel", "25/10"));
    ASSERT_TRUE(exifMetadata->SetValue("Contrast", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("CustomRendered", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTimeDigitized", "2023:01:19 10:39:59"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTimeOriginal", "2024:03:25 19:11:35"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Co-sited");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "82");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Soft");
    ASSERT_EQ(GetProperty(exifMetadata, "ApertureValue"), "5.00 EV (f/5.7)");
    ASSERT_EQ(GetProperty(exifMetadata, "BrightnessValue"), "2.70 EV (22.26 cd/m^2)");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "Adobe RGB");
    ASSERT_EQ(GetProperty(exifMetadata, "ComponentsConfiguration"), "Y R G B");
    ASSERT_EQ(GetProperty(exifMetadata, "CompressedBitsPerPixel"), "2.5");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Hard");
    ASSERT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Normal process");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2023:01:19 10:39:59");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2024:03:25 19:11:35");
}

/**
 * @tc.name: Write018
 * @tc.desc: Testing Writemetadata to modify exif features
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write018, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE18_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), "1.00");
    ASSERT_EQ(GetProperty(exifMetadata, "ExifVersion"), "Exif Version 2.1");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "0.00 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Normal program");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/33 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/1.8");
    ASSERT_EQ(GetProperty(exifMetadata, "FileSource"), "DSC");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Flash did not fire, auto mode");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashpixVersion"), "FlashPix Version 1.0");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "4.0 mm");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "27");

    ASSERT_TRUE(exifMetadata->SetValue("DigitalZoomRatio", "133/1"));
    ASSERT_TRUE(exifMetadata->SetValue("ExifVersion", "0200"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureBiasValue", "3/1"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureMode", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureProgram", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureTime", "1/590"));
    ASSERT_TRUE(exifMetadata->SetValue("FNumber", "4/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FileSource", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("Flash", "7"));
    ASSERT_TRUE(exifMetadata->SetValue("FlashpixVersion", "0200"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalLength", "35/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalLengthIn35mmFilm", "30"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), "133");
    ASSERT_EQ(GetProperty(exifMetadata, "ExifVersion"), "Exif Version 2.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "3.00 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto bracket");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Manual");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/590 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/4.0");
    ASSERT_EQ(GetProperty(exifMetadata, "FileSource"), "Internal error (unknown value 2)");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Strobe return light detected");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashpixVersion"), "Unknown FlashPix Version");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "35.0 mm");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "30");
}

/**
 * @tc.name: Write019
 * @tc.desc: Testing Writemetadata to modify exif features
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write019, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE19_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "400");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "543792");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Daylight");
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "1.69 EV (f/1.8)");
    ASSERT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Pattern");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "3456");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "4608");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "One-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");

    ASSERT_TRUE(exifMetadata->SetValue("GainControl", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedRatings", "300"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTimeDigitized", "4380000"));
    ASSERT_TRUE(exifMetadata->SetValue("LightSource", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("MaxApertureValue", "9/100"));
    ASSERT_TRUE(exifMetadata->SetValue("MeteringMode", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("PixelXDimension", "1000"));
    ASSERT_TRUE(exifMetadata->SetValue("PixelYDimension", "3250"));
    ASSERT_TRUE(exifMetadata->SetValue("SensingMethod", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("Saturation", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("WhiteBalance", "1"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "High gain up");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "300");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "4380000");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Fluorescent");
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "0.09 EV (f/1.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Spot");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "1000");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "3250");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "Two-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Low saturation");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Manual white balance");
}

/**
 * @tc.name: Write020
 * @tc.desc: Testing Writemetadata to modify exif features
 * @tc.type: FUNC
 */
HWTEST_F(WebpExifMetadataAccessorTest, Write020, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE20_WEBP_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    WebpExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "150");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTimeStamp"), "11:37:58.00");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "AllWebp");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "Uncompressed");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "12, 1");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "1.5");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudeyyy"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudezzz"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "FXIC012");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "0.299, 0.587, 0.114");

    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeed", "140/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTimeStamp", "20/1 15/1 56/1"));
    ASSERT_TRUE(exifMetadata->SetValue("Artist", "Xian"));
    ASSERT_TRUE(exifMetadata->SetValue("Compression", "5"));
    ASSERT_TRUE(exifMetadata->SetValue("Copyright", "xingxing"));
    ASSERT_TRUE(exifMetadata->SetValue("DefaultCropSize", "2 2"));
    ASSERT_TRUE(exifMetadata->SetValue("Gamma", "5/2"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedLatitudeyyy", "200"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedLatitudezzz", "100"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectLocation", "15 12"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageUniqueID", "fxic012"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrCoefficients", "200/1000 255/1000 350/1000"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "140");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTimeStamp"), "20:15:56.00");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "Xian");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "LZW compression");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "xingxing (Photographer) - [None] (Editor)");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "2, 2");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "2.5");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudeyyy"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudezzz"), "100");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "15, 12");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "fxic012");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "0.200, 0.255, 0.350");
}
} // namespace Multimedia
} // namespace OHOS
