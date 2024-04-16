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

#include <memory>
#include <gtest/gtest.h>

#include "file_metadata_stream.h"
#include "image_log.h"
#include "media_errors.h"
#include "metadata.h"
#include "png_exif_metadata_accessor.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
namespace {
static const std::string IMAGE_INPUT_HW_PNG_PATH = "/data/local/tmp/image/test_hwmnote.png";
static const std::string IMAGE_INPUT_NOEXIF_PNG_PATH = "/data/local/tmp/image/test_noexif.png";
static const std::string IMAGE_INPUT_EXIF_PNG_PATH = "/data/local/tmp/image/test_exif.png";
static const std::string IMAGE_INPUT_CHUNK_ZTXT_PNG_PATH = "/data/local/tmp/image/test_chunk_ztxt.png";
static const std::string IMAGE_INPUT_CHUNK_TEXT_PNG_PATH = "/data/local/tmp/image/test_chunk_text.png";
static const std::string IMAGE_INPUT_ITXT_NOCOMPRESS_PNG_PATH = "/data/local/tmp/image/test_chunk_itxt_nocompress.png";
static const std::string IMAGE_INPUT_ITXT_WITHCOMPRESS_PNG_PATH =
    "/data/local/tmp/image/test_chunk_itxt_withcompress.png";
static const std::string IMAGE_INPUT_WRITE_EXIF_PNG_PATH = "/data/local/tmp/image/test_write_exif.png";
static const std::string IMAGE_OUTPUT_NOEXIF_PNG_PATH = "/data/local/tmp/image/test_out_noexif.png";
static const std::string IMAGE_OUTPUT_EXIF_PNG_PATH = "/data/local/tmp/image/test_out_exif.png";
static const std::string IMAGE_OUTPUT_CHUNK_ZTXT_PNG_PATH = "/data/local/tmp/image/test_out_chunk_ztxt.png";
static const std::string IMAGE_OUTPUT_CHUNK_TEXT_PNG_PATH = "/data/local/tmp/image/test_out_chunk_text.png";
static const std::string IMAGE_OUTPUT_ITXT_NOCOMPRESS_PNG_PATH =
    "/data/local/tmp/image/test_out_chunk_itxt_nocompress.png";
static const std::string IMAGE_OUTPUT_ITXT_WITHCOMPRESS_PNG_PATH =
    "/data/local/tmp/image/test_out_chunk_itxt_withcompress.png";
static const auto TIFF_IFH_LENGTH = 8;
}
class PngExifMetadataAccessorTest : public testing::Test {
public:
    PngExifMetadataAccessorTest() {}
    ~PngExifMetadataAccessorTest() {}
    std::string GetProperty(const std::shared_ptr<ExifMetadata> &metadata, const std::string &prop);
};

std::string PngExifMetadataAccessorTest::GetProperty(const std::shared_ptr<ExifMetadata> &metadata,
    const std::string &prop)
{
    std::string value;
    metadata->GetValue(prop, value);
    return value;
}

/**
 * @tc.name: Read001
 * @tc.desc: test Read using PNG without exif
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Read001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_NOEXIF_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA);
}

/**
 * @tc.name: Read002
 * @tc.desc: test Read using PNG with exif
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Read002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "Adobe Photoshop CS Windows");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "2015:11:05 23:04:30");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Centered");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "Uncalibrated");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "1080");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "1920");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Unknown value 0");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTime"), "140");
}

/**
 * @tc.name: Read003
 * @tc.desc: test Read
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Read003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_CHUNK_ZTXT_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "130");
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "8, 8, 8");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "Uncompressed");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "NIKON CORPORATION");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "NIKON D1X");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-left");
    ASSERT_EQ(GetProperty(exifMetadata, "SamplesPerPixel"), "4");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "300");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "300");
    ASSERT_EQ(GetProperty(exifMetadata, "PlanarConfiguration"), "Chunky format");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "GIMP 2.9.5");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "2016:09:15 06:29:23");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/125 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/5.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Manual");
    ASSERT_EQ(GetProperty(exifMetadata, "ExifVersion"), "Exif Version 2.2");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2004:06:21 23:37:53");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2004:06:21 23:37:53");
    ASSERT_EQ(GetProperty(exifMetadata, "ComponentsConfiguration"), "Y Cb Cr -");
    ASSERT_EQ(GetProperty(exifMetadata, "CompressedBitsPerPixel"), " 4");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "0.33 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "3.00 EV (f/2.8)");
    ASSERT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Center-weighted average");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Cloudy weather");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Flash did not fire");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "42.0 mm");
}

/**
 * @tc.name: Read004
 * @tc.desc: test Read
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Read004, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_CHUNK_ZTXT_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTime"), "06");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeOriginal"), "06");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "06");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashpixVersion"), "FlashPix Version 1.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "sRGB");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "130");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "One-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "FileSource"), "DSC");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    ASSERT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Normal process");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Manual exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Manual white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), " 1");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "63");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Standard");
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Unknown");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "127c1377b054a3f65bf2754ebb24e7f2");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSVersionID"), "2.2.0.0");
    ASSERT_EQ(GetProperty(exifMetadata, "PhotometricInterpretation"), "YCbCr");
}

/**
 * @tc.name: Read005
 * @tc.desc: test Read
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Read005, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_CHUNK_TEXT_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "320");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "211");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "NIKON CORPORATION");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "NIKON D70");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-left");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "300");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "300");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "digiKam-0.9.0-svn");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "2006:02:04 16:09:30");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/4 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/22.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Shutter priority");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2006:02:04 16:09:30");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2006:02:04 16:09:30");
    ASSERT_EQ(GetProperty(exifMetadata, "ShutterSpeedValue"), "2.00 EV (1/4 sec.)");
    ASSERT_EQ(GetProperty(exifMetadata, "ApertureValue"), "8.92 EV (f/22.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "0.33 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "2.97 EV (f/2.8)");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Unknown");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Flash did not fire");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "50.0 mm");
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "320");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "211");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "One-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "75");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Standard");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Unknown");
}

/**
 * @tc.name: Read006
 * @tc.desc: test Read
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Read006, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_ITXT_NOCOMPRESS_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "320");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "211");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "NIKON CORPORATION");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "NIKON D70");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-left");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "300");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "300");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "digiKam-0.9.0-svn");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "2006:02:04 16:09:30");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/4 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/22.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Shutter priority");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2006:02:04 16:09:30");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2006:02:04 16:09:30");
    ASSERT_EQ(GetProperty(exifMetadata, "ShutterSpeedValue"), "2.00 EV (1/4 sec.)");
    ASSERT_EQ(GetProperty(exifMetadata, "ApertureValue"), "8.92 EV (f/22.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "0.33 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "2.97 EV (f/2.8)");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Unknown");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Flash did not fire");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "50.0 mm");
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "320");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "211");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "One-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "75");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Standard");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Unknown");
}

/**
 * @tc.name: Read007
 * @tc.desc: test Read
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Read007, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream =
        std::make_shared<FileMetadataStream>(IMAGE_INPUT_ITXT_WITHCOMPRESS_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "130");
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "8, 8, 8");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "Uncompressed");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "NIKON CORPORATION");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "NIKON D1X");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-left");
    ASSERT_EQ(GetProperty(exifMetadata, "SamplesPerPixel"), "4");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "300");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "300");
    ASSERT_EQ(GetProperty(exifMetadata, "PlanarConfiguration"), "Chunky format");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "GIMP 2.9.5");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "2016:09:15 06:29:23");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/125 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/5.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Manual");
    ASSERT_EQ(GetProperty(exifMetadata, "ExifVersion"), "Exif Version 2.2");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2004:06:21 23:37:53");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2004:06:21 23:37:53");
    ASSERT_EQ(GetProperty(exifMetadata, "ComponentsConfiguration"), "Y Cb Cr -");
    ASSERT_EQ(GetProperty(exifMetadata, "CompressedBitsPerPixel"), " 4");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "0.33 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "3.00 EV (f/2.8)");
    ASSERT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Center-weighted average");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Cloudy weather");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Flash did not fire");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "42.0 mm");
}

/**
 * @tc.name: Read008
 * @tc.desc: test Read
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Read008, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream =
        std::make_shared<FileMetadataStream>(IMAGE_INPUT_ITXT_WITHCOMPRESS_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTime"), "06");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeOriginal"), "06");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "06");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashpixVersion"), "FlashPix Version 1.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "sRGB");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "200");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "130");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "One-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "FileSource"), "DSC");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    ASSERT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Normal process");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Manual exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Manual white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), " 1");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "63");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Standard");
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Unknown");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "127c1377b054a3f65bf2754ebb24e7f2");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSVersionID"), "2.2.0.0");
    ASSERT_EQ(GetProperty(exifMetadata, "PhotometricInterpretation"), "YCbCr");
}

/**
 * @tc.name: Read009
 * @tc.desc: test Read
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Read009, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HW_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    int result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);

    auto exifMetadata = imageAccessor.Get();
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
}

/**
 * @tc.name: ReadBlob001
 * @tc.desc: test ReadBlob using PNG with exif
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, ReadBlob001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_EQ(result, true);
    ASSERT_EQ(exifBuf.Size(), 4244);
}

/**
 * @tc.name: ReadBlob002
 * @tc.desc: test ReadBlob using PNG without exif
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, ReadBlob002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_NOEXIF_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    DataBuf exifBuf;
    bool result = imageAccessor.ReadBlob(exifBuf);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: Write001
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("ApertureValue", "4/1"));
    ASSERT_TRUE(exifMetadata->SetValue("Artist", "Joseph.Xu"));
    ASSERT_TRUE(exifMetadata->SetValue("BitsPerSample", "9,9,8"));
    ASSERT_TRUE(exifMetadata->SetValue("BodySerialNumber", "exoch"));
    ASSERT_TRUE(exifMetadata->SetValue("BrightnessValue", "13/1"));
    ASSERT_TRUE(exifMetadata->SetValue("CameraOwnerName", "c.uec"));
    ASSERT_TRUE(exifMetadata->SetValue("CFAPattern", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ColorSpace", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ComponentsConfiguration", "1456"));
    ASSERT_TRUE(exifMetadata->SetValue("CompositeImage", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("CompressedBitsPerPixel", "24/1"));
    ASSERT_TRUE(exifMetadata->SetValue("Compression", "6"));
    ASSERT_TRUE(exifMetadata->SetValue("Contrast", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("Copyright", "fang"));
    ASSERT_TRUE(exifMetadata->SetValue("CustomRendered", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTime", "2024:01:25 05:51:34"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTimeDigitized", "2023:01:19 10:39:58"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "ApertureValue"), "4.00 EV (f/4.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "Artist"), "Joseph.Xu");
    ASSERT_EQ(GetProperty(exifMetadata, "BitsPerSample"), "9, 9, 8");
    ASSERT_EQ(GetProperty(exifMetadata, "BodySerialNumber"), "exoch");
    ASSERT_EQ(GetProperty(exifMetadata, "BrightnessValue"), "13.00 EV (28067.91 cd/m^2)");
    ASSERT_EQ(GetProperty(exifMetadata, "CameraOwnerName"), "c.uec");
    ASSERT_EQ(GetProperty(exifMetadata, "CFAPattern"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "sRGB");
    ASSERT_EQ(GetProperty(exifMetadata, "ComponentsConfiguration"), "Y R G B");
    ASSERT_EQ(GetProperty(exifMetadata, "CompositeImage"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "CompressedBitsPerPixel"), "24");
    ASSERT_EQ(GetProperty(exifMetadata, "Compression"), "JPEG compression");
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "fang (Photographer) - [None] (Editor)");
    ASSERT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Custom process");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "2024:01:25 05:51:34");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2023:01:19 10:39:58");
}

/**
 * @tc.name: Write002
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("DateTimeOriginal", "2024:01:25 05:51:34"));
    ASSERT_TRUE(exifMetadata->SetValue("DefaultCropSize", "153 841"));
    ASSERT_TRUE(exifMetadata->SetValue("DeviceSettingDescription", "2xxx"));
    ASSERT_TRUE(exifMetadata->SetValue("DigitalZoomRatio", "321/1"));
    ASSERT_TRUE(exifMetadata->SetValue("DNGVersion", "2 2 3 1"));
    ASSERT_TRUE(exifMetadata->SetValue("ExifVersion", "0210"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureBiasValue", "23/1"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureIndex", "3/2"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureMode", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureProgram", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureTime", "1/34"));
    ASSERT_TRUE(exifMetadata->SetValue("FileSource", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("Flash", "5"));
    ASSERT_TRUE(exifMetadata->SetValue("FlashEnergy", "832/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FlashpixVersion", "0100"));
    ASSERT_TRUE(exifMetadata->SetValue("FNumber", "3/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalLength", "31/1"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2024:01:25 05:51:34");
    ASSERT_EQ(GetProperty(exifMetadata, "DefaultCropSize"), "153, 841");
    ASSERT_EQ(GetProperty(exifMetadata, "DeviceSettingDescription"), "2xxx");
    ASSERT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), "321");
    ASSERT_EQ(GetProperty(exifMetadata, "DNGVersion"), "2, 2, 3, 1");
    ASSERT_EQ(GetProperty(exifMetadata, "ExifVersion"), "Exif Version 2.1");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureBiasValue"), "23.00 EV");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureIndex"), "1.5");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Normal program");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureTime"), "1/34 sec.");
    ASSERT_EQ(GetProperty(exifMetadata, "FileSource"), "DSC");
    ASSERT_EQ(GetProperty(exifMetadata, "Flash"), "Strobe return light not detected");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashEnergy"), "832");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashpixVersion"), "FlashPix Version 1.0");
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/3.0");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLength"), "31.0 mm");
}

/**
 * @tc.name: Write003
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_CHUNK_ZTXT_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("FocalLengthIn35mmFilm", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneResolutionUnit", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneXResolution", "1080/1"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneYResolution", "880/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GainControl", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("Gamma", "5/2"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAltitude", "0/100"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAltitudeRef", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAreaInformation", "arexxx"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDateStamp", "2024:01:25"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestBearing", "22/11"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestBearingRef", "T"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestDistance", "10/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestDistanceRef", "N"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLatitude", "33/1 22/1 11/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLatitudeRef", "N"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLongitude", "33/1 22/1 11/1"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "FocalLengthIn35mmFilm"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneResolutionUnit"), "Centimeter");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneXResolution"), "1080");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneYResolution"), "880");
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Gamma"), "2.5");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitude"), "0.00");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitudeRef"), "Sea level reference");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAreaInformation"), "arexxx");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDateStamp"), "2024:01:25");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearing"), "2.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearingRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistance"), "10");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistanceRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitude"), "33, 22, 11");
}

/**
 * @tc.name: Write004
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write004, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_CHUNK_ZTXT_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLongitudeRef", "E"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDifferential", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDOP", "182/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSHPositioningError", "5/2"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSImgDirection", "125/56"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSImgDirectionRef", "M"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLatitude", "39,54,20"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLatitudeRef", "N"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLongitude", "120,52,26"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSLongitudeRef", "E"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSMapDatum", "xxxx"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSMeasureMode", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSProcessingMethod", "CELLID"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSatellites", "xxx"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeed", "150/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeedRef", "K"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSStatus", "A"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitudeRef"), "E");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDifferential"), "0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDOP"), "182");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSHPositioningError"), "2.5");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirection"), "2.23");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirectionRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitude"), "39, 54, 20");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitude"), "120, 52, 26");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "E");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMapDatum"), "xxxx");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMeasureMode"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSProcessingMethod"), "CELLID");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSatellites"), "xxx");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "150");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeedRef"), "K");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSStatus"), "A");
}

/**
 * @tc.name: Write005
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write005, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_CHUNK_TEXT_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("GPSTimeStamp", "11:37:56"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTrack", "114/3"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTrackRef", "T"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSVersionID", "2.2.0.0"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageDescription", "_cuva"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageLength", "1000"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageUniqueID", "FXIC012"));
    ASSERT_TRUE(exifMetadata->SetValue("ImageWidth", "1001"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedLatitudeyyy", "1456"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedLatitudezzz", "1456"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedRatings", "160"));
    ASSERT_TRUE(exifMetadata->SetValue("ISOSpeedRatings", "160"));
    ASSERT_TRUE(exifMetadata->SetValue("LensMake", "xxwx"));
    ASSERT_TRUE(exifMetadata->SetValue("LensModel", "txaw"));
    ASSERT_TRUE(exifMetadata->SetValue("LensSerialNumber", "qxhc"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTimeStamp"), "11:37:56.00");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrack"), "38.0");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrackRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSVersionID"), "2.2.0.0");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageDescription"), "_cuva");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageLength"), "1000");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageUniqueID"), "FXIC012");
    ASSERT_EQ(GetProperty(exifMetadata, "ImageWidth"), "1001");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudeyyy"), "1456");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedLatitudezzz"), "1456");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "160");
    ASSERT_EQ(GetProperty(exifMetadata, "ISOSpeedRatings"), "160");
    ASSERT_EQ(GetProperty(exifMetadata, "LensMake"), "xxwx");
    ASSERT_EQ(GetProperty(exifMetadata, "LensModel"), "txaw");
    ASSERT_EQ(GetProperty(exifMetadata, "LensSerialNumber"), "qxhc");
}

/**
 * @tc.name: Write006
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write006, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_CHUNK_TEXT_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("LensSpecification", "3/4 5/2 3/2 1/2"));
    ASSERT_TRUE(exifMetadata->SetValue("LightSource", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("Make", "5"));
    ASSERT_TRUE(exifMetadata->SetValue("MaxApertureValue", "4/1"));
    ASSERT_TRUE(exifMetadata->SetValue("MeteringMode", "5"));
    ASSERT_TRUE(exifMetadata->SetValue("Model", "TNY-AL00"));
    ASSERT_TRUE(exifMetadata->SetValue("NewSubfileType", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("OECF", "45"));
    ASSERT_TRUE(exifMetadata->SetValue("OffsetTime", "2024:01:25"));
    ASSERT_TRUE(exifMetadata->SetValue("OffsetTimeDigitized", "cfh"));
    ASSERT_TRUE(exifMetadata->SetValue("OffsetTimeOriginal", "chex"));
    ASSERT_TRUE(exifMetadata->SetValue("Orientation", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("PhotometricInterpretation", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("PhotoMode", "252"));
    ASSERT_TRUE(exifMetadata->SetValue("PixelXDimension", "1000"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "LensSpecification"), "0.8, 2.5, 1.5, 0.5");
    ASSERT_EQ(GetProperty(exifMetadata, "LightSource"), "Fluorescent");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "4.00 EV (f/4.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "MeteringMode"), "Pattern");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "TNY-AL00");
    ASSERT_EQ(GetProperty(exifMetadata, "NewSubfileType"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "OECF"), "2 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTime"), "2024:01:25");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeDigitized"), "cfh");
    ASSERT_EQ(GetProperty(exifMetadata, "OffsetTimeOriginal"), "chex");
    ASSERT_EQ(GetProperty(exifMetadata, "Orientation"), "Top-left");
    ASSERT_EQ(GetProperty(exifMetadata, "PhotometricInterpretation"), "Reversed mono");
    ASSERT_EQ(GetProperty(exifMetadata, "PhotoMode"), "252");
    ASSERT_EQ(GetProperty(exifMetadata, "PixelXDimension"), "1000");
}

/**
 * @tc.name: Write007
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write007, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream =
        std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_ITXT_NOCOMPRESS_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("PixelYDimension", "2000"));
    ASSERT_TRUE(exifMetadata->SetValue("PlanarConfiguration", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("PrimaryChromaticities", "124/1"));
    ASSERT_TRUE(exifMetadata->SetValue("RecommendedExposureIndex", "241"));
    ASSERT_TRUE(exifMetadata->SetValue("ReferenceBlackWhite", "221/1"));
    ASSERT_TRUE(exifMetadata->SetValue("RelatedSoundFile", "/usr/home/sound/sea.wav"));
    ASSERT_TRUE(exifMetadata->SetValue("ResolutionUnit", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("RowsPerStrip", "252"));
    ASSERT_TRUE(exifMetadata->SetValue("SamplesPerPixel", "23"));
    ASSERT_TRUE(exifMetadata->SetValue("Saturation", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("SceneCaptureType", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("SceneType", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("SensingMethod", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("SensitivityType", "5"));
    ASSERT_TRUE(exifMetadata->SetValue("Sharpness", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("ShutterSpeedValue", "13/1"));
    ASSERT_TRUE(exifMetadata->SetValue("Software", "MNA-AL00 4.0.0.120(C00E116R3P7)"));
    ASSERT_TRUE(exifMetadata->SetValue("SourceExposureTimesOfCompositeImage", "xxxw"));


    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "PixelYDimension"), "2000");
    ASSERT_EQ(GetProperty(exifMetadata, "PlanarConfiguration"), "Chunky format");
    ASSERT_EQ(GetProperty(exifMetadata, "PrimaryChromaticities"), "124");
    ASSERT_EQ(GetProperty(exifMetadata, "RecommendedExposureIndex"), "241");
    ASSERT_EQ(GetProperty(exifMetadata, "ReferenceBlackWhite"), "221, 255,  0, 255,  0, 255");
    ASSERT_EQ(GetProperty(exifMetadata, "RelatedSoundFile"), "/usr/home/sound/sea.wav");
    ASSERT_EQ(GetProperty(exifMetadata, "ResolutionUnit"), "Inch");
    ASSERT_EQ(GetProperty(exifMetadata, "RowsPerStrip"), "252");
    ASSERT_EQ(GetProperty(exifMetadata, "SamplesPerPixel"), "23");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Standard");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "Two-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "SensitivityType"), "Standard output sensitivity (SOS) and ISO speed");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "ShutterSpeedValue"), "13.00 EV (1/8192 sec.)");
    ASSERT_EQ(GetProperty(exifMetadata, "Software"), "MNA-AL00 4.0.0.120(C00E116R3P7)");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceExposureTimesOfCompositeImage"), "xxxw");
}

/**
 * @tc.name: Write008
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write008, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream =
        std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_ITXT_NOCOMPRESS_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("SpectralSensitivity", "sensitivity"));
    ASSERT_TRUE(exifMetadata->SetValue("StandardOutputSensitivity", "5"));
    ASSERT_TRUE(exifMetadata->SetValue("StripByteCounts", "252"));
    ASSERT_TRUE(exifMetadata->SetValue("StripOffsets", "11"));
    ASSERT_TRUE(exifMetadata->SetValue("SubfileType", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectArea", "10 20"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectDistance", "25/1"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectDistanceRange", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectLocation", "3 12"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTime", "4280000"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTimeDigitized", "4280000"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTimeOriginal", "4280000"));
    ASSERT_TRUE(exifMetadata->SetValue("SourceImageNumberOfCompositeImage", "23 34"));
    ASSERT_TRUE(exifMetadata->SetValue("SpatialFrequencyResponse", "13"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "SpectralSensitivity"), "sensitivity");
    ASSERT_EQ(GetProperty(exifMetadata, "StandardOutputSensitivity"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "StripByteCounts"), "252");
    ASSERT_EQ(GetProperty(exifMetadata, "StripOffsets"), "11");
    ASSERT_EQ(GetProperty(exifMetadata, "SubfileType"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectArea"), "(x,y) = (10,20)");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistance"), "25.0 m");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Unknown");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "3, 12");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTime"), "4280000");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "4280000");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeOriginal"), "4280000");
    ASSERT_EQ(GetProperty(exifMetadata, "SourceImageNumberOfCompositeImage"), "23, 34");
    ASSERT_EQ(GetProperty(exifMetadata, "SpatialFrequencyResponse"), "13");
}

/**
 * @tc.name: Write009
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write009, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream =
        std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_ITXT_WITHCOMPRESS_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_TRUE(exifMetadata->SetValue("TransferFunction", "4"));
    ASSERT_TRUE(exifMetadata->SetValue("UserComment", "comment"));
    ASSERT_TRUE(exifMetadata->SetValue("WhiteBalance", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("WhitePoint", "252/1"));
    ASSERT_TRUE(exifMetadata->SetValue("XResolution", "72/1"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrCoefficients", "299/1000 587/1000 114/1000"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrPositioning", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrSubSampling", "3 2"));
    ASSERT_TRUE(exifMetadata->SetValue("YResolution", "252/1"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);
    ASSERT_EQ(GetProperty(exifMetadata, "TransferFunction"), "1 bytes undefined data");
    ASSERT_EQ(GetProperty(exifMetadata, "UserComment"), "comment");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Manual white balance");
    ASSERT_EQ(GetProperty(exifMetadata, "WhitePoint"), "252, 0/0");
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrCoefficients"), "0.299, 0.587, 0.114");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Centered");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrSubSampling"), "3, 2");
    ASSERT_EQ(GetProperty(exifMetadata, "YResolution"), "252");
}

/**
 * @tc.name: Write010
 * @tc.desc: test Write from png image but exifMetadata_ is null, return error number
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write010, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageWriteAccessor(writeStream);
    ASSERT_EQ(imageWriteAccessor.Write(), ERR_MEDIA_VALUE_INVALID);
}

/**
 * @tc.name: Write011
 * @tc.desc: test Write from right png image, modify "XResolution" propert set value "72"
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write011, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE_EXIF_PNG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_TRUE(exifMetadata->SetValue("XResolution", "72"));
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "72");
    ASSERT_EQ(imageAccessor.Write(), 0);
    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(GetProperty(exifMetadata, "XResolution"), "72");
}

/**
 * @tc.name: Write012
 * @tc.desc: test Write from right png image,read and write
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write012, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_WRITE_EXIF_PNG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(readStream);
    ASSERT_EQ(imageAccessor.Read(), 0);
    ASSERT_EQ(imageAccessor.Write(), 0);
    ASSERT_EQ(imageAccessor.Read(), 0);
}

/**
 * @tc.name: Write013
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write013, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_CHUNK_ZTXT_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrSubSampling", "3 2"));
    ASSERT_TRUE(exifMetadata->SetValue("YCbCrPositioning", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ReferenceBlackWhite", "19"));
    ASSERT_TRUE(exifMetadata->SetValue("Copyright", "20"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureProgram", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("ExifVersion", "0210"));
    ASSERT_TRUE(exifMetadata->SetValue("DateTimeDigitized", "2023:01:19 10:39:58"));
    ASSERT_TRUE(exifMetadata->SetValue("ShutterSpeedValue", "13"));
    ASSERT_TRUE(exifMetadata->SetValue("BrightnessValue", "30"));
    ASSERT_TRUE(exifMetadata->SetValue("MaxApertureValue", "31"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectDistance", "32"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTimeOriginal", "427000"));
    ASSERT_TRUE(exifMetadata->SetValue("SubsecTimeDigitized", "427000"));
    ASSERT_TRUE(exifMetadata->SetValue("ColorSpace", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("FlashEnergy", "41"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneXResolution", "43"));
    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrSubSampling"), "3, 2");
    ASSERT_EQ(GetProperty(exifMetadata, "YCbCrPositioning"), "Centered");
    ASSERT_EQ(GetProperty(exifMetadata, "ReferenceBlackWhite"), "19, 255,  0, 255,  0, 255");
    ASSERT_EQ(GetProperty(exifMetadata, "Copyright"), "20 (Photographer) - [None] (Editor)");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureProgram"), "Normal program");
    ASSERT_EQ(GetProperty(exifMetadata, "ExifVersion"), "Exif Version 2.1");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeDigitized"), "2023:01:19 10:39:58");
    ASSERT_EQ(GetProperty(exifMetadata, "ShutterSpeedValue"), "13.00 EV (1/8192 sec.)");
    ASSERT_EQ(GetProperty(exifMetadata, "BrightnessValue"), "30.00 EV (3678917695.14 cd/m^2)");
    ASSERT_EQ(GetProperty(exifMetadata, "MaxApertureValue"), "31.00 EV (f/46341.0)");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistance"), "32.0 m");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeOriginal"), "427000");
    ASSERT_EQ(GetProperty(exifMetadata, "SubsecTimeDigitized"), "427000");
    ASSERT_EQ(GetProperty(exifMetadata, "ColorSpace"), "Adobe RGB");
    ASSERT_EQ(GetProperty(exifMetadata, "FlashEnergy"), "41");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneXResolution"), "43");
}

/**
 * @tc.name: Write014
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write014, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_CHUNK_TEXT_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneYResolution", "44"));
    ASSERT_TRUE(exifMetadata->SetValue("FocalPlaneResolutionUnit", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectLocation", "3 12"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureIndex", "47"));
    ASSERT_TRUE(exifMetadata->SetValue("SensingMethod", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("FileSource", "3"));
    ASSERT_TRUE(exifMetadata->SetValue("CustomRendered", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("ExposureMode", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("DigitalZoomRatio", "53"));
    ASSERT_TRUE(exifMetadata->SetValue("SceneCaptureType", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("GainControl", "0"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneYResolution"), "44");
    ASSERT_EQ(GetProperty(exifMetadata, "FocalPlaneResolutionUnit"), "Centimeter");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectLocation"), "3, 12");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureIndex"), "47");
    ASSERT_EQ(GetProperty(exifMetadata, "SensingMethod"), "Two-chip color area sensor");
    ASSERT_EQ(GetProperty(exifMetadata, "FileSource"), "DSC");
    ASSERT_EQ(GetProperty(exifMetadata, "CustomRendered"), "Custom process");
    ASSERT_EQ(GetProperty(exifMetadata, "ExposureMode"), "Auto exposure");
    ASSERT_EQ(GetProperty(exifMetadata, "DigitalZoomRatio"), "53");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneCaptureType"), "Standard");
    ASSERT_EQ(GetProperty(exifMetadata, "GainControl"), "Normal");
}

/**
 * @tc.name: Write015
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write015, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream =
        std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_ITXT_NOCOMPRESS_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_TRUE(exifMetadata->SetValue("Contrast", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("Saturation", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("Sharpness", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("SubjectDistanceRange", "0"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSAltitude", "64"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSatellites", "5 8 20"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSStatus", "V"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSMeasureMode", "2"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDOP", "68"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeed", "70"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTrackRef", "T"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSTrack", "72"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSImgDirection", "74"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "Contrast"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Saturation"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "Sharpness"), "Normal");
    ASSERT_EQ(GetProperty(exifMetadata, "SubjectDistanceRange"), "Unknown");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSAltitude"), "64");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSatellites"), "5 8 20");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSStatus"), "V");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMeasureMode"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDOP"), "68");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeed"), "70");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrackRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSTrack"), "72");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirection"), "74");
}

/**
 * @tc.name: Write016
 * @tc.desc: test Write from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, Write016, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream =
        std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_ITXT_WITHCOMPRESS_PNG_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageAccessor(stream);
    ASSERT_EQ(imageAccessor.Read(), 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_TRUE(exifMetadata->SetValue("GPSMapDatum", "75"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLatitudeRef", "N"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLongitudeRef", "E"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestBearingRef", "T"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestBearing", "81"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestDistance", "83"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLatitude", "33/1 22/1 11/1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSImgDirectionRef", "M"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSSpeedRef", "K"));
    ASSERT_TRUE(exifMetadata->SetValue("CompositeImage", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDifferential", "1"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestDistanceRef", "N"));
    ASSERT_TRUE(exifMetadata->SetValue("GPSDestLongitude", "33/1 22/1 11/1"));

    ASSERT_EQ(imageAccessor.Write(), 0);

    ASSERT_EQ(imageAccessor.Read(), 0);
    exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "GPSMapDatum"), "75");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitudeRef"), "E");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearingRef"), "T");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestBearing"), "81");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistance"), "83");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLatitude"), "33, 22, 11");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSImgDirectionRef"), "M");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSSpeedRef"), "K");
    ASSERT_EQ(GetProperty(exifMetadata, "CompositeImage"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDifferential"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestDistanceRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSDestLongitude"), "33, 22, 11");
}

/**
 * @tc.name: WriteBlob001
 * @tc.desc: test WriteBlob from right png image, modify propert
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, WriteBlob001, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageReadAccessor(readStream);
    DataBuf inputBuf;
    ASSERT_TRUE(imageReadAccessor.ReadBlob(inputBuf));

    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageWriteAccessor(writeStream);
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
HWTEST_F(PngExifMetadataAccessorTest, WriteBlob002, TestSize.Level3)
{
    DataBuf inputBuf;
    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageWriteAccessor(writeStream);
    ASSERT_EQ(imageWriteAccessor.WriteBlob(inputBuf), ERR_MEDIA_VALUE_INVALID);
}

/**
 * @tc.name: WriteBlob003
 * @tc.desc: test WriteBlob from right png image, Data buffer not container "EXIF\0\0"
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, WriteBlob003, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageReadAccessor(readStream);
    DataBuf inputBuf;
    ASSERT_TRUE(imageReadAccessor.ReadBlob(inputBuf));

    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageWriteAccessor(writeStream);
    DataBuf dataBlob(inputBuf.CData(TIFF_IFH_LENGTH), (inputBuf.Size() - TIFF_IFH_LENGTH));
    ASSERT_EQ(imageWriteAccessor.WriteBlob(dataBlob), ERR_MEDIA_VALUE_INVALID);
}

/**
 * @tc.name: WriteBlob004
 * @tc.desc: test WriteBlob from right png image
 * @tc.type: FUNC
 */
HWTEST_F(PngExifMetadataAccessorTest, WriteBlob004, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> readStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_EXIF_PNG_PATH);
    ASSERT_TRUE(readStream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageReadAccessor(readStream);
    DataBuf inputBuf;
    ASSERT_TRUE(imageReadAccessor.ReadBlob(inputBuf));

    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_NOEXIF_PNG_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    PngExifMetadataAccessor imageWriteAccessor(writeStream);
    ASSERT_EQ(imageWriteAccessor.WriteBlob(inputBuf), 0);

    DataBuf outputBuf;
    ASSERT_TRUE(imageWriteAccessor.ReadBlob(outputBuf));
    ASSERT_EQ(outputBuf.Size(), inputBuf.Size());
}
} // namespace Multimedia
} // namespace OHOS