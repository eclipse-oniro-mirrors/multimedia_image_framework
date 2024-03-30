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
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "6989 bytes undefined data");
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
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "6989 bytes undefined data");
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
} // namespace Multimedia
} // namespace OHOS