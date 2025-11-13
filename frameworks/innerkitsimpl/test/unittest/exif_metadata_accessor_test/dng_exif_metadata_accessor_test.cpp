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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <memory>

#include "dng_exif_metadata_accessor.h"
#include "file_metadata_stream.h"
#include "log_tags.h"
#include "media_errors.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
namespace {
    static const std::string IMAGE_INPUT1_DNG_PATH = "/data/local/tmp/image/test_dng_readmetadata001.dng";
    static const std::string IMAGE_INPUT2_DNG_PATH = "/data/local/tmp/image/test_dng_readmetadata002.dng";
    static const std::string IMAGE_INPUT3_DNG_PATH = "/data/local/tmp/image/test_dng_readmetadata003.dng";
    static const std::string IMAGE_INPUT4_DNG_PATH = "/data/local/tmp/image/test_notiff.dng";
    static const std::string IMAGE_INPUT5_DNG_PATH = "/data/local/tmp/image/test_dng_readmetadata004.dng";
}

class DngExifMetadataAccessorTest : public testing::Test {
public:
    DngExifMetadataAccessorTest() {}
    ~DngExifMetadataAccessorTest() {}
};

/**
 * @tc.name: Read001
 * @tc.desc: test the dngDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_DNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("BitsPerSample", value), SUCCESS);
    ASSERT_EQ(value, "8, 8, 8");
    ASSERT_EQ(exifMetadata->GetValue("Orientation", value), SUCCESS);
    ASSERT_EQ(value, "Right-top");
    ASSERT_EQ(exifMetadata->GetValue("ImageLength", value), SUCCESS);
    ASSERT_EQ(value, "3024");
    ASSERT_EQ(exifMetadata->GetValue("ImageWidth", value), SUCCESS);
    ASSERT_EQ(value, "4032");
    ASSERT_EQ(exifMetadata->GetValue("GPSLatitude", value), SUCCESS);
    ASSERT_EQ(value, "34,  3, 34.59");
    ASSERT_EQ(exifMetadata->GetValue("GPSLongitude", value), SUCCESS);
    ASSERT_EQ(value, "84, 40, 54.21");
    ASSERT_EQ(exifMetadata->GetValue("GPSLatitudeRef", value), SUCCESS);
    ASSERT_EQ(value, "N");
    ASSERT_EQ(exifMetadata->GetValue("GPSLongitudeRef", value), SUCCESS);
    ASSERT_EQ(value, "W");
    ASSERT_EQ(exifMetadata->GetValue("DateTimeOriginal", value), SUCCESS);
    ASSERT_EQ(value, "Yesterday at noon");
    ASSERT_EQ(exifMetadata->GetValue("ExposureTime", value), SUCCESS);
    ASSERT_EQ(value, "1/5556 sec.");
    ASSERT_EQ(exifMetadata->GetValue("SceneType", value), SUCCESS);
    ASSERT_EQ(value, "Directly photographed");
    ASSERT_EQ(exifMetadata->GetValue("ISOSpeedRatings", value), SUCCESS);
    ASSERT_EQ(value, "32");
    ASSERT_EQ(exifMetadata->GetValue("FNumber", value), SUCCESS);
    ASSERT_EQ(value, "f/1.6");
    ASSERT_EQ(exifMetadata->GetValue("DateTime", value), SUCCESS);
    ASSERT_EQ(value, "2020:12:29 14:24:45");
    ASSERT_EQ(exifMetadata->GetValue("GPSTimeStamp", value), SUCCESS);
    ASSERT_EQ(value, "01:39:58.00");
    ASSERT_EQ(exifMetadata->GetValue("GPSDateStamp", value), SUCCESS);
    ASSERT_EQ(value, "2020:12:29");
    ASSERT_EQ(exifMetadata->GetValue("ImageDescription", value), SUCCESS);
    ASSERT_EQ(value, "_cuva");
    ASSERT_EQ(exifMetadata->GetValue("Make", value), SUCCESS);
    ASSERT_EQ(value, "Apple");
    ASSERT_EQ(exifMetadata->GetValue("Model", value), SUCCESS);
    ASSERT_EQ(value, "iPhone 12 Pro");
}

/**
 * @tc.name: Read002
 * @tc.desc: test the dngDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_DNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("SensitivityType", value), SUCCESS);
    ASSERT_EQ(value, "Standard output sensitivity (SOS) and ISO speed");
    ASSERT_EQ(exifMetadata->GetValue("StandardOutputSensitivity", value), SUCCESS);
    ASSERT_EQ(value, "5");
    ASSERT_EQ(exifMetadata->GetValue("RecommendedExposureIndex", value), SUCCESS);
    ASSERT_EQ(value, "241");
    ASSERT_EQ(exifMetadata->GetValue("ApertureValue", value), SUCCESS);
    ASSERT_EQ(value, "1.36 EV (f/1.6)");
    ASSERT_EQ(exifMetadata->GetValue("ExposureBiasValue", value), SUCCESS);
    ASSERT_EQ(value, "0.00 EV");
    ASSERT_EQ(exifMetadata->GetValue("MeteringMode", value), SUCCESS);
    ASSERT_EQ(value, "Pattern");
    ASSERT_EQ(exifMetadata->GetValue("LightSource", value), SUCCESS);
    ASSERT_EQ(value, "Fluorescent");
    ASSERT_EQ(exifMetadata->GetValue("Flash", value), SUCCESS);
    ASSERT_EQ(value, "Flash did not fire, compulsory flash mode");
    ASSERT_EQ(exifMetadata->GetValue("FocalLength", value), SUCCESS);
    ASSERT_EQ(value, "4.2 mm");
    ASSERT_EQ(exifMetadata->GetValue("UserComment", value), SUCCESS);
    ASSERT_EQ(value, "comm");
    ASSERT_EQ(exifMetadata->GetValue("PixelXDimension", value), SUCCESS);
    ASSERT_EQ(value, "4032");
    ASSERT_EQ(exifMetadata->GetValue("PixelYDimension", value), SUCCESS);
    ASSERT_EQ(value, "3024");
    ASSERT_EQ(exifMetadata->GetValue("WhiteBalance", value), SUCCESS);
    ASSERT_EQ(value, "Auto white balance");
    ASSERT_EQ(exifMetadata->GetValue("FocalLengthIn35mmFilm", value), SUCCESS);
    ASSERT_EQ(value, "26");
    ASSERT_EQ(exifMetadata->GetValue("JPEGProc", value), SUCCESS);
    ASSERT_EQ(value, "252");
    ASSERT_EQ(exifMetadata->GetValue("MaxApertureValue", value), SUCCESS);
    ASSERT_EQ(value, "0.08 EV (f/1.0)");
    ASSERT_EQ(exifMetadata->GetValue("Artist", value), SUCCESS);
    ASSERT_EQ(value, "Joseph.Xu");
    ASSERT_EQ(exifMetadata->GetValue("NewSubfileType", value), SUCCESS);
    ASSERT_EQ(value, "1");
    ASSERT_EQ(exifMetadata->GetValue("OECF", value), SUCCESS);
    ASSERT_EQ(value, "1 bytes undefined data");
}

/**
 * @tc.name: Read003
 * @tc.desc: test the dngDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_DNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("PlanarConfiguration", value), SUCCESS);
    ASSERT_EQ(value, "Chunky format");
    ASSERT_EQ(exifMetadata->GetValue("PrimaryChromaticities", value), SUCCESS);
    ASSERT_EQ(value, "124");
    ASSERT_EQ(exifMetadata->GetValue("ReferenceBlackWhite", value), SUCCESS);
    ASSERT_EQ(value, "221");
    ASSERT_EQ(exifMetadata->GetValue("ResolutionUnit", value), SUCCESS);
    ASSERT_EQ(value, "Inch");
    ASSERT_EQ(exifMetadata->GetValue("SamplesPerPixel", value), SUCCESS);
    ASSERT_EQ(value, "3");
    ASSERT_EQ(exifMetadata->GetValue("Compression", value), SUCCESS);
    ASSERT_EQ(value, "JPEG compression");
    ASSERT_EQ(exifMetadata->GetValue("Software", value), SUCCESS);
    ASSERT_EQ(value, "14.3");
    ASSERT_EQ(exifMetadata->GetValue("Copyright", value), SUCCESS);
    ASSERT_EQ(value, "XXXXXX (Photographer) - [None] (Editor)");
    ASSERT_EQ(exifMetadata->GetValue("SpectralSensitivity", value), SUCCESS);
    ASSERT_EQ(value, "sensitivity");
    ASSERT_EQ(exifMetadata->GetValue("DNGVersion", value), SUCCESS);
    ASSERT_EQ(value, "0x01, 0x04, 0x00, 0x00");
    ASSERT_EQ(exifMetadata->GetValue("SubjectDistance", value), SUCCESS);
    ASSERT_EQ(value, "2.5 m");
    ASSERT_EQ(exifMetadata->GetValue("DefaultCropSize", value), SUCCESS);
    ASSERT_EQ(value, "1");
    ASSERT_EQ(exifMetadata->GetValue("SubjectLocation", value), SUCCESS);
    ASSERT_EQ(value, "3");
    ASSERT_EQ(exifMetadata->GetValue("TransferFunction", value), SUCCESS);
    ASSERT_EQ(value, "2");
    ASSERT_EQ(exifMetadata->GetValue("WhitePoint", value), SUCCESS);
    ASSERT_EQ(value, "124.2");
    ASSERT_EQ(exifMetadata->GetValue("XResolution", value), SUCCESS);
    ASSERT_EQ(value, "72");
    ASSERT_EQ(exifMetadata->GetValue("YCbCrCoefficients", value), SUCCESS);
    ASSERT_EQ(value, "0.299, 0.587, 0.114");
    ASSERT_EQ(exifMetadata->GetValue("YCbCrPositioning", value), SUCCESS);
    ASSERT_EQ(value, "Centered");
    ASSERT_EQ(exifMetadata->GetValue("YCbCrSubSampling", value), SUCCESS);
    ASSERT_EQ(value, "3, 2");
}

/**
 * @tc.name: Read004
 * @tc.desc: test the dngDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read004, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_DNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("YResolution", value), SUCCESS);
    ASSERT_EQ(value, "72");
    ASSERT_EQ(exifMetadata->GetValue("Gamma", value), SUCCESS);
    ASSERT_EQ(value, "1.5");
    ASSERT_EQ(exifMetadata->GetValue("ISOSpeed", value), SUCCESS);
    ASSERT_EQ(value, "200");
    ASSERT_EQ(exifMetadata->GetValue("ISOSpeedLatitudeyyy", value), SUCCESS);
    ASSERT_EQ(value, "3");
    ASSERT_EQ(exifMetadata->GetValue("ISOSpeedLatitudezzz", value), SUCCESS);
    ASSERT_EQ(value, "3");
    ASSERT_EQ(exifMetadata->GetValue("ImageUniqueID", value), SUCCESS);
    ASSERT_EQ(value, "FXIC012");
    ASSERT_EQ(exifMetadata->GetValue("GPSAltitude", value), SUCCESS);
    ASSERT_EQ(value, "261.0165");
    ASSERT_EQ(exifMetadata->GetValue("GPSAltitudeRef", value), SUCCESS);
    ASSERT_EQ(value, "Sea level");
    ASSERT_EQ(exifMetadata->GetValue("GPSAreaInformation", value), SUCCESS);
    ASSERT_EQ(value, "23...15...57");
    ASSERT_EQ(exifMetadata->GetValue("GPSDOP", value), SUCCESS);
    ASSERT_EQ(value, "182");
    ASSERT_EQ(exifMetadata->GetValue("GPSDestBearing", value), SUCCESS);
    ASSERT_EQ(value, "143.866");
    ASSERT_EQ(exifMetadata->GetValue("GPSDestBearingRef", value), SUCCESS);
    ASSERT_EQ(value, "T");
    ASSERT_EQ(exifMetadata->GetValue("GPSDestDistance", value), SUCCESS);
    ASSERT_EQ(value, "10");
    ASSERT_EQ(exifMetadata->GetValue("GPSDestDistanceRef", value), SUCCESS);
    ASSERT_EQ(value, "N");
    ASSERT_EQ(exifMetadata->GetValue("GPSDestLatitude", value), SUCCESS);
    ASSERT_EQ(value, "33, 22, 11");
    ASSERT_EQ(exifMetadata->GetValue("GPSDestLatitudeRef", value), SUCCESS);
    ASSERT_EQ(value, "N");
    ASSERT_EQ(exifMetadata->GetValue("GPSDestLongitude", value), SUCCESS);
    ASSERT_EQ(value, "33, 22, 11");
    ASSERT_EQ(exifMetadata->GetValue("GPSDestLongitudeRef", value), SUCCESS);
    ASSERT_EQ(value, "E");
    ASSERT_EQ(exifMetadata->GetValue("GPSDifferential", value), SUCCESS);
    ASSERT_EQ(value, "1");
}

/**
 * @tc.name: Read005
 * @tc.desc: test the dngDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read005, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_DNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("GPSImgDirection", value), SUCCESS);
    ASSERT_EQ(value, "143.866");
    ASSERT_EQ(exifMetadata->GetValue("GPSImgDirectionRef", value), SUCCESS);
    ASSERT_EQ(value, "T");
    ASSERT_EQ(exifMetadata->GetValue("GPSMapDatum", value), SUCCESS);
    ASSERT_EQ(value, "xxxx");
    ASSERT_EQ(exifMetadata->GetValue("GPSMeasureMode", value), SUCCESS);
    ASSERT_EQ(value, "2");
    ASSERT_EQ(exifMetadata->GetValue("GPSProcessingMethod", value), SUCCESS);
    ASSERT_EQ(value, "CELLID");
    ASSERT_EQ(exifMetadata->GetValue("GPSSatellites", value), SUCCESS);
    ASSERT_EQ(value, "xxx");
    ASSERT_EQ(exifMetadata->GetValue("GPSSpeed", value), SUCCESS);
    ASSERT_EQ(value, " 0");
    ASSERT_EQ(exifMetadata->GetValue("GPSSpeedRef", value), SUCCESS);
    ASSERT_EQ(value, "K");
    ASSERT_EQ(exifMetadata->GetValue("GPSStatus", value), SUCCESS);
    ASSERT_EQ(value, "V");
    ASSERT_EQ(exifMetadata->GetValue("GPSTrack", value), SUCCESS);
    ASSERT_EQ(value, "56");
    ASSERT_EQ(exifMetadata->GetValue("GPSTrackRef", value), SUCCESS);
    ASSERT_EQ(value, "T");
    ASSERT_EQ(exifMetadata->GetValue("GPSVersionID", value), SUCCESS);
    ASSERT_EQ(value, "2.2.0.0");
    ASSERT_EQ(exifMetadata->GetValue("GPSHPositioningError", value), SUCCESS);
    ASSERT_EQ(value, "4.69662");
    ASSERT_EQ(exifMetadata->GetValue("JPEGInterchangeFormat", value), SUCCESS);
    ASSERT_EQ(value, "0");
    ASSERT_EQ(exifMetadata->GetValue("JPEGInterchangeFormatLength", value), SUCCESS);
    ASSERT_EQ(value, "0");
    ASSERT_EQ(exifMetadata->GetValue("LensMake", value), SUCCESS);
    ASSERT_EQ(value, "Apple");
    ASSERT_EQ(exifMetadata->GetValue("LensModel", value), SUCCESS);
    ASSERT_EQ(value, "iPhone 12 Pro back triple camera 4.2mm f/1.6");
    ASSERT_EQ(exifMetadata->GetValue("LensSerialNumber", value), SUCCESS);
    ASSERT_EQ(value, "xxx");
    ASSERT_EQ(exifMetadata->GetValue("LensSpecification", value), SUCCESS);
    ASSERT_EQ(value, "1.540000,  6, 1.6, 2.4");
}

/**
 * @tc.name: Read006
 * @tc.desc: test the dngDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read006, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_DNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("GainControl", value), SUCCESS);
    ASSERT_EQ(value, "Normal");
    ASSERT_EQ(exifMetadata->GetValue("OffsetTime", value), SUCCESS);
    ASSERT_EQ(value, "-05:00");
    ASSERT_EQ(exifMetadata->GetValue("OffsetTimeDigitized", value), SUCCESS);
    ASSERT_EQ(value, "-05:00");
    ASSERT_EQ(exifMetadata->GetValue("OffsetTimeOriginal", value), SUCCESS);
    ASSERT_EQ(value, "-05:00");
    ASSERT_EQ(exifMetadata->GetValue("PhotometricInterpretation", value), SUCCESS);
    ASSERT_EQ(value, "YCbCr");
    ASSERT_EQ(exifMetadata->GetValue("RelatedSoundFile", value), SUCCESS);
    ASSERT_EQ(value, "/usr/home/sound/sea.wav");
    ASSERT_EQ(exifMetadata->GetValue("RowsPerStrip", value), SUCCESS);
    ASSERT_EQ(value, "3024");
    ASSERT_EQ(exifMetadata->GetValue("Saturation", value), SUCCESS);
    ASSERT_EQ(value, "Normal");
    ASSERT_EQ(exifMetadata->GetValue("SceneCaptureType", value), SUCCESS);
    ASSERT_EQ(value, "Standard");
    ASSERT_EQ(exifMetadata->GetValue("SensingMethod", value), SUCCESS);
    ASSERT_EQ(value, "One-chip color area sensor");
    ASSERT_EQ(exifMetadata->GetValue("Sharpness", value), SUCCESS);
    ASSERT_EQ(value, "Normal");
    ASSERT_EQ(exifMetadata->GetValue("ShutterSpeedValue", value), SUCCESS);
    ASSERT_EQ(value, "12.44 EV (1/5556 sec.)");
    ASSERT_EQ(exifMetadata->GetValue("SourceExposureTimesOfCompositeImage", value), SUCCESS);
    ASSERT_EQ(value, ".");
    ASSERT_EQ(exifMetadata->GetValue("SourceImageNumberOfCompositeImage", value), SUCCESS);
    ASSERT_EQ(value, "1234");
    ASSERT_EQ(exifMetadata->GetValue("SpatialFrequencyResponse", value), SUCCESS);
    ASSERT_EQ(value, ".");
    ASSERT_EQ(exifMetadata->GetValue("StripByteCounts", value), SUCCESS);
    ASSERT_EQ(value, "5364435");
    ASSERT_EQ(exifMetadata->GetValue("StripOffsets", value), SUCCESS);
    ASSERT_EQ(value, "0");
    ASSERT_EQ(exifMetadata->GetValue("SubsecTime", value), SUCCESS);
    ASSERT_EQ(value, "427000");
}

/**
 * @tc.name: Read007
 * @tc.desc: test the dngDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read007, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_DNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("SubsecTimeDigitized", value), SUCCESS);
    ASSERT_EQ(value, "700");
    ASSERT_EQ(exifMetadata->GetValue("SubsecTimeOriginal", value), SUCCESS);
    ASSERT_EQ(value, "700");
    ASSERT_EQ(exifMetadata->GetValue("SubfileType", value), SUCCESS);
    ASSERT_EQ(value, "1");
    ASSERT_EQ(exifMetadata->GetValue("SubjectArea", value), SUCCESS);
    ASSERT_EQ(value, "Within rectangle (width 2318, height 1390) around (x,y) = (2009,1506)");
    ASSERT_EQ(exifMetadata->GetValue("SubjectDistanceRange", value), SUCCESS);
    ASSERT_EQ(value, "Distant view");
    ASSERT_EQ(exifMetadata->GetValue("BodySerialNumber", value), SUCCESS);
    ASSERT_EQ(value, "xx");
    ASSERT_EQ(exifMetadata->GetValue("BrightnessValue", value), SUCCESS);
    ASSERT_EQ(value, "10.46 EV (4810.21 cd/m^2)");
    ASSERT_EQ(exifMetadata->GetValue("CFAPattern", value), SUCCESS);
    ASSERT_EQ(value, "5 bytes undefined data");
    ASSERT_EQ(exifMetadata->GetValue("CameraOwnerName", value), SUCCESS);
    ASSERT_EQ(value, "xx");
    ASSERT_EQ(exifMetadata->GetValue("ColorSpace", value), SUCCESS);
    ASSERT_EQ(value, "Uncalibrated");
    ASSERT_EQ(exifMetadata->GetValue("ComponentsConfiguration", value), SUCCESS);
    ASSERT_EQ(value, "Y Cb G B");
    ASSERT_EQ(exifMetadata->GetValue("CompositeImage", value), SUCCESS);
    ASSERT_EQ(value, "1");
    ASSERT_EQ(exifMetadata->GetValue("CompressedBitsPerPixel", value), SUCCESS);
    ASSERT_EQ(value, "1.5");
    ASSERT_EQ(exifMetadata->GetValue("Contrast", value), SUCCESS);
    ASSERT_EQ(value, "Normal");
    ASSERT_EQ(exifMetadata->GetValue("CustomRendered", value), SUCCESS);
    ASSERT_EQ(value, "Custom process");
    ASSERT_EQ(exifMetadata->GetValue("DateTimeDigitized", value), SUCCESS);
    ASSERT_EQ(value, "2020:12:29 14:24:45");
    ASSERT_EQ(exifMetadata->GetValue("DeviceSettingDescription", value), SUCCESS);
    ASSERT_EQ(value, ".");
    ASSERT_EQ(exifMetadata->GetValue("DigitalZoomRatio", value), SUCCESS);
    ASSERT_EQ(value, "321");
    ASSERT_EQ(exifMetadata->GetValue("ExifVersion", value), SUCCESS);
    ASSERT_EQ(value, "Exif Version 2.32");
}

/**
 * @tc.name: Read008
 * @tc.desc: test the dngDecoded Exif properties
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read008, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT1_DNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("ExposureIndex", value), SUCCESS);
    ASSERT_EQ(value, "1.5");
    ASSERT_EQ(exifMetadata->GetValue("ExposureMode", value), SUCCESS);
    ASSERT_EQ(value, "Auto exposure");
    ASSERT_EQ(exifMetadata->GetValue("ExposureProgram", value), SUCCESS);
    ASSERT_EQ(value, "Normal program");
    ASSERT_EQ(exifMetadata->GetValue("FileSource", value), SUCCESS);
    ASSERT_EQ(value, "DSC");
    ASSERT_EQ(exifMetadata->GetValue("FlashEnergy", value), SUCCESS);
    ASSERT_EQ(value, "832");
    ASSERT_EQ(exifMetadata->GetValue("FlashpixVersion", value), SUCCESS);
    ASSERT_EQ(value, "FlashPix Version 1.0");
    ASSERT_EQ(exifMetadata->GetValue("FocalPlaneResolutionUnit", value), SUCCESS);
    ASSERT_EQ(value, "Centimeter");
    ASSERT_EQ(exifMetadata->GetValue("FocalPlaneXResolution", value), SUCCESS);
    ASSERT_EQ(value, "1080");
    ASSERT_EQ(exifMetadata->GetValue("FocalPlaneYResolution", value), SUCCESS);
    ASSERT_EQ(value, "880");
}

/**
 * @tc.name: Read009
 * @tc.desc: test dng file not open, read fail
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read009, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT2_DNG_PATH);
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA);
}

/**
 * @tc.name: Read010
 * @tc.desc: test read empty file
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read010, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT3_DNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA);
}

/**
 * @tc.name: Read011
 * @tc.desc: test read error file which does not have tiff signature
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read011, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT4_DNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA);
}

/**
 * @tc.name: Read012
 * @tc.desc: test the read, checking if it can correctly initialize
 * a stream from an existing file descriptor
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read012, TestSize.Level3)
{
    int fileDescription = open(IMAGE_INPUT1_DNG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fileDescription, -1);

    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(fileDescription);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("SubsecTimeDigitized", value), SUCCESS);
    ASSERT_EQ(value, "700");
}

/**
 * @tc.name: Read013
 * @tc.desc: test the dngDecoded hw properties
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read013, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT5_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteBurstNumber", value), SUCCESS);
    ASSERT_EQ(value, "2");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteCaptureMode", value), SUCCESS);
    ASSERT_EQ(value, "1");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFaceConf", value), SUCCESS);
    ASSERT_EQ(value, "3");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFaceCount", value), SUCCESS);
    ASSERT_EQ(value, "2");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFaceLeyeCenter", value), SUCCESS);
    ASSERT_EQ(value, "1 2 3 4");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFaceMouthCenter", value), SUCCESS);
    ASSERT_EQ(value, "1 2 3 4 5 6 7 8");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFacePointer", value), SUCCESS);
    ASSERT_EQ(value, "122");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFaceRect", value), SUCCESS);
    ASSERT_EQ(value, "1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFaceReyeCenter", value), SUCCESS);
    ASSERT_EQ(value, "5 6 7 8");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFaceSmileScore", value), SUCCESS);
    ASSERT_EQ(value, "1 2 3 4 5 6 7 8");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFaceVersion", value), SUCCESS);
    ASSERT_EQ(value, "1");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFocusMode", value), SUCCESS);
    ASSERT_EQ(value, "7");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteFrontCamera", value), SUCCESS);
    ASSERT_EQ(value, "3");
    ASSERT_EQ(exifMetadata->GetValue("HwMnotePhysicalAperture", value), SUCCESS);
    ASSERT_EQ(value, "6");
    ASSERT_EQ(exifMetadata->GetValue("HwMnotePitchAngle", value), SUCCESS);
    ASSERT_EQ(value, "5");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteRollAngle", value), SUCCESS);
    ASSERT_EQ(value, "4");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneBeachConf", value), SUCCESS);
    ASSERT_EQ(value, "6");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneBlueSkyConf", value), SUCCESS);
    ASSERT_EQ(value, "4");
}

/**
 * @tc.name: Read014
 * @tc.desc: test the dngDecoded hw properties
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read014, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT5_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    std::string value;
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneFlowersConf", value), SUCCESS);
    ASSERT_EQ(value, "9");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneFoodConf", value), SUCCESS);
    ASSERT_EQ(value, "2");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneGreenPlantConf", value), SUCCESS);
    ASSERT_EQ(value, "5");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneNightConf", value), SUCCESS);
    ASSERT_EQ(value, "10");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteScenePointer", value), SUCCESS);
    ASSERT_EQ(value, "256");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneSnowConf", value), SUCCESS);
    ASSERT_EQ(value, "7");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneStageConf", value), SUCCESS);
    ASSERT_EQ(value, "3");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneSunsetConf", value), SUCCESS);
    ASSERT_EQ(value, "8");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneTextConf", value), SUCCESS);
    ASSERT_EQ(value, "11");
    ASSERT_EQ(exifMetadata->GetValue("HwMnoteSceneVersion", value), SUCCESS);
    ASSERT_EQ(value, "1");
    ASSERT_EQ(exifMetadata->GetValue("MakerNote", value), SUCCESS);
    ASSERT_EQ(value, "HwMnoteCaptureMode:1,HwMnoteBurstNumber:2,HwMnoteFrontCamera:3,"
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
} // namespace Multimedia
} // namespace OHOS