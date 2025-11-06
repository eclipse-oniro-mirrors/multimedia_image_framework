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
    static const std::string IMAGE_INPUT6_DNG_PATH = "/data/local/tmp/image/test_dng_writemetadata001.dng";
}

class DngExifMetadataAccessorTest : public testing::Test {
public:
    DngExifMetadataAccessorTest() {}
    ~DngExifMetadataAccessorTest() {}
    std::string GetProperty(const std::shared_ptr<ExifMetadata>& metadata, const std::string& prop);
};

std::string DngExifMetadataAccessorTest::GetProperty(const std::shared_ptr<ExifMetadata>& metadata,
    const std::string& prop)
{
    std::string value;
    metadata->GetValue(prop, value);
    return value;
}

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

/**
 * @tc.name: Read015
 * @tc.desc: Test reading hw fields from a DNG image.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Read015, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT5_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteWindSnapshotMode"), "default_exif_value");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFocusModeExif"), "");
}

/**
 * @tc.name: Write001
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
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

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
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
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
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
    ASSERT_TRUE(exifMetadata->SetValue("ExposureTime", "1/44"));

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "TransferFunction"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "TNY-AL00 2.0.0.232(C00E230R2P4)");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "2022:06:02 15:51:35");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "AllWebp");
    ASSERT_EQ(GetProperty(exifMetadata, "WhitePoint"), "124");
    ASSERT_EQ(GetProperty(exifMetadata, "PrimaryChromaticities"), "124");
    ASSERT_EQ(GetProperty(exifMetadata, "JPEGProc"), "252");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "0.299, 0.587, 0.114");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrSubSampling"), "4, 2");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Centered");
    ASSERT_EQ(GetProperty(exifMetadata, "ReferenceBlackWhite"), "221");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "Hua (Photographer) - [None] (Editor)");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/44 sec.");
}

/**
 * @tc.name: Write003
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
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

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
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
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write004, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
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
    ASSERT_TRUE(exifMetadata->SetValue("MakerNote", "demo"));
    ASSERT_TRUE(exifMetadata->SetValue("UserComment", "place for user comments."));

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
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
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectArea"),
        "Within rectangle (width 2318, height 1390) around (x,y) = (10,20)");
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "demo");
    ASSERT_EQ(GetProperty(exifMetadata, "UserComment"), "place for user comments.");
}

/**
 * @tc.name: Write005
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write005, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
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
    ASSERT_TRUE(exifMetadata->SetValue("ExposureIndex", "4/2"));

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
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
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureIndex"), "2.0");
}

/**
 * @tc.name: Write006
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write006, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
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

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
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
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write007, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
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

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
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
    ASSERT_EQ(GetProperty(exifMetadata, "SourceImageNumberOfCompositeImage"), "34");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceExposureTimesOfCompositeImage"), "byte");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "1.5");
    ASSERT_EQ(GetProperty(exifMetadata, "SpectralSensitivity"), "Sensitivity");
}

/**
 * @tc.name: Write008
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write008, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
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

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
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
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write009, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
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
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXmageMode", "1"));

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
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
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXmageMode"), "1");
}

/**
 * @tc.name: Write0010
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write0010, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("GPSAreaInformation", "A bytes"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDateStamp", "2022:01:11"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDifferential", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSHPositioningError", "2/1"));
    ASSERT_TRUE(exifMetadata->SetValue("OECF", "abbs"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectLocation", "5 6"));
    ASSERT_TRUE(exifMetadata->SetValue("DNGVersion", "3 3 0 0"));
    ASSERT_TRUE(exifMetadata->SetValue("DefaultCropSize", "2 2"));
    ASSERT_TRUE(exifMetadata->SetValue("PhotoMode", "252"));
    ASSERT_TRUE(exifMetadata->SetValue("StripOffsets", "11"));
    ASSERT_TRUE(exifMetadata->SetValue("RowsPerStrip", "252"));
    ASSERT_TRUE(exifMetadata->SetValue("StripByteCounts", "252"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectDistance", "25/1"));
    ASSERT_TRUE(exifMetadata->SetValue("PhotographicSensitivity", "252"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteIsXmageSupported", "252"));

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAreaInformation"), "A bytes");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "2022:01:11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDifferential"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSHPositioningError"), " 2");
    ASSERT_EQ(GetProperty(exifMetadata, "OECF"), "4 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "DNGVersion"), "0x03, 0x03, 0x00, 0x00");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "PhotoMode"), "252");
    ASSERT_EQ(GetProperty(exifMetadata, "StripOffsets"), "11");
    ASSERT_EQ(GetProperty(exifMetadata, "RowsPerStrip"), "252");
    ASSERT_EQ(GetProperty(exifMetadata, "StripByteCounts"), "252");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistance"), "25.0 m");
    ASSERT_EQ(GetProperty(exifMetadata, "PhotographicSensitivity"), "252");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteIsXmageSupported"), "252");
}

/**
 * @tc.name: Write0011
 * @tc.desc: Test writing fields to a DNG image, then reading them back and comparing with expected values.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write0011, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    std::shared_ptr<ExifMetadata> exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXmageLeft", "11"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXmageTop", "11"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXmageRight", "50"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXmageBottom", "50"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteCloudEnhancementMode", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("MovingPhotoId", "110"));
    ASSERT_TRUE(exifMetadata->SetValue("MovingPhotoVersion", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("MicroVideoPresentationTimestampUS", "123232"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteAiEdit", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXtStyleTemplateName", "123"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXtStyleCustomLightAndShadow", "4/1"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXtStyleCustomSaturation", "2/1"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXtStyleCustomHue", "5/1"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXtStyleExposureParam", "123 456 789"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXtStyleAlgoVersion", "10"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXtStyleAlgoVideoEnable", "10"));

    ASSERT_EQ(imageAccessor.Write(), SUCCESS);
    ASSERT_EQ(imageAccessor.Read(), SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXmageLeft"), "11");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXmageTop"), "11");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXmageRight"), "50");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXmageBottom"), "50");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteCloudEnhancementMode"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "MovingPhotoId"), "110");
    ASSERT_EQ(GetProperty(exifMetadata, "MovingPhotoVersion"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "MicroVideoPresentationTimestampUS"), "123232");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteAiEdit"), "0");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXtStyleTemplateName"), "123");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXtStyleCustomLightAndShadow"), "4.00");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXtStyleCustomSaturation"), "2.00");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXtStyleCustomHue"), "5.00");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXtStyleExposureParam"), "123 456 789");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXtStyleAlgoVersion"), "10");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXtStyleAlgoVideoEnable"), "10");
}

/**
 * @tc.name: Write0012
 * @tc.desc: Test Write when exifMetadata is null.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, Write0012, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT6_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Write(), ERR_MEDIA_VALUE_INVALID);
}

/**
 * @tc.name: GetTiffHeaderPos001
 * @tc.desc: Test GetTiffHeaderPos when the file is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, GetTiffHeaderPos001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT3_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    size_t tiffHeaderPos = 0;
    ASSERT_EQ(imageAccessor.GetTiffHeaderPos(tiffHeaderPos), ERR_IMAGE_SOURCE_DATA);
}

/**
 * @tc.name: GetTiffHeaderPos002
 * @tc.desc: Test GetTiffHeaderPos when the image file does not contain a TIFF header.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, GetTiffHeaderPos002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT4_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    size_t tiffHeaderPos = 0;
    ASSERT_EQ(imageAccessor.GetTiffHeaderPos(tiffHeaderPos), ERR_IMAGE_SOURCE_DATA);
}

/**
 * @tc.name: GetExifEncodedBlob001
 * @tc.desc: Test GetExifEncodedBlob when exifMetadata is null.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, GetExifEncodedBlob001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT4_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint8_t *dataBlob = nullptr;
    uint32_t size = 0;
    ASSERT_EQ(imageAccessor.GetExifEncodedBlob(&dataBlob, size), ERR_MEDIA_VALUE_INVALID);
}

/**
 * @tc.name: GetExifEncodedBlob002
 * @tc.desc: test GetExifEncodedBlob when dataBlob is null.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataAccessorTest, GetExifEncodedBlob002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT4_DNG_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    DngExifMetadataAccessor imageAccessor(stream);
    uint32_t size = 0;
    ASSERT_EQ(imageAccessor.GetExifEncodedBlob(nullptr, size), ERROR);
}
} // namespace Multimedia
} // namespace OHOS