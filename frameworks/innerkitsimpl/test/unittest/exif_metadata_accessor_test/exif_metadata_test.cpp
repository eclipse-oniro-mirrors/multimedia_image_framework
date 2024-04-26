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

#include <gtest/gtest.h>
#include <memory>
#include "libexif/exif-tag.h"
#include "media_errors.h"
#include "tiff_parser.h"
#include "exif_metadata.h"
#include "exif_metadata_formatter.h"
#include "image_log.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_metadata.jpg";
static const std::string IMAGE_INPUT_JPEG_BLANKEXIF_PATH = "/data/local/tmp/image/test_exif_blank.jpg";
static const std::string IMAGE_INPUT_JPEG_HW_PATH = "/data/local/tmp/image/test_hwkey.jpg";
static const std::string IMAGE_INPUT_JPEG_RM_ENTRY_PATH = "/data/local/tmp/image/test_entrys.jpg";

class ExifMetadataTest : public testing::Test {
public:
    ExifMetadataTest() {}
    ~ExifMetadataTest() {}
};

HWTEST_F(ExifMetadataTest, SetValue001, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("BitsPerSample", "9,9,8"));
    ASSERT_TRUE(metadata.SetValue("Orientation", "1"));
    ASSERT_TRUE(metadata.SetValue("ImageLength", "1000"));
    ASSERT_TRUE(metadata.SetValue("ImageWidth", "1001"));
    ASSERT_TRUE(metadata.SetValue("GPSLatitude", "39,54,20"));
    ASSERT_TRUE(metadata.SetValue("GPSLongitude", "120,52,26"));
    ASSERT_TRUE(metadata.SetValue("GPSLatitudeRef", "N"));
    ASSERT_TRUE(metadata.SetValue("GPSLongitudeRef", "E"));
    ASSERT_TRUE(metadata.SetValue("DateTimeOriginal", "2024:01:25 05:51:34"));
    ASSERT_TRUE(metadata.SetValue("ExposureTime", "1/34"));
    ASSERT_TRUE(metadata.SetValue("SceneType", "1"));
    ASSERT_TRUE(metadata.SetValue("ISOSpeedRatings", "160"));
    ASSERT_TRUE(metadata.SetValue("FNumber", "3/1"));
    ASSERT_TRUE(metadata.SetValue("DateTime", "2024:01:25 05:51:34"));
    ASSERT_TRUE(metadata.SetValue("GPSTimeStamp", "11:37:56"));
    ASSERT_TRUE(metadata.SetValue("ImageDescription", "_cuva"));
    ASSERT_TRUE(metadata.SetValue("Model", "TNY-AL00"));
    ASSERT_TRUE(metadata.SetValue("SensitivityType", "5"));
    ASSERT_TRUE(metadata.SetValue("StandardOutputSensitivity", "5"));
    ASSERT_TRUE(metadata.SetValue("RecommendedExposureIndex", "241"));
    ASSERT_TRUE(metadata.SetValue("ISOSpeedRatings", "160"));
    ASSERT_TRUE(metadata.SetValue("ApertureValue", "4/1"));
    ASSERT_TRUE(metadata.SetValue("ExposureBiasValue", "23/1"));
    ASSERT_TRUE(metadata.SetValue("MeteringMode", "5"));
    ASSERT_TRUE(metadata.SetValue("LightSource", "2"));
    ASSERT_TRUE(metadata.SetValue("Flash", "5"));
    ASSERT_TRUE(metadata.SetValue("FocalLength", "31/1"));
    ASSERT_TRUE(metadata.SetValue("UserComment", "comm"));
    ASSERT_TRUE(metadata.SetValue("PixelXDimension", "1000"));
    ASSERT_TRUE(metadata.SetValue("PixelYDimension", "2000"));
    ASSERT_TRUE(metadata.SetValue("WhiteBalance", "1"));
    ASSERT_TRUE(metadata.SetValue("FocalLengthIn35mmFilm", "2"));
}

HWTEST_F(ExifMetadataTest, GetValue001, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("BitsPerSample", "9,9,8"));
    metadata.GetValue("BitsPerSample", value);
    ASSERT_EQ(value, "9, 9, 8");
}

HWTEST_F(ExifMetadataTest, GetValue002, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("Orientation", "1"));
    metadata.GetValue("Orientation", value);
    ASSERT_EQ(value, "Top-left");
}

HWTEST_F(ExifMetadataTest, GetValue003, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("ImageLength", "1000"));
    metadata.GetValue("ImageLength", value);
    ASSERT_EQ(value, "1000");
}

HWTEST_F(ExifMetadataTest, GetValue004, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("ImageWidth", "1001"));
    metadata.GetValue("ImageWidth", value);
    ASSERT_EQ(value, "1001");
}

HWTEST_F(ExifMetadataTest, GetValue005, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("GPSLatitude", "39,54,20"));
    metadata.GetValue("GPSLatitude", value);
    ASSERT_EQ(value, "39, 54, 20");
}

HWTEST_F(ExifMetadataTest, GetValue006, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("GPSLongitude", "120,52,26"));
    metadata.GetValue("GPSLongitude", value);
    ASSERT_EQ(value, "120, 52, 26");
}

HWTEST_F(ExifMetadataTest, GetValue007, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("GPSLatitudeRef", "N"));
    metadata.GetValue("GPSLatitudeRef", value);
    ASSERT_EQ(value, "N");
}

HWTEST_F(ExifMetadataTest, GetValue008, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("GPSLongitudeRef", "E"));
    metadata.GetValue("GPSLongitudeRef", value);
    ASSERT_EQ(value, "E");
}

HWTEST_F(ExifMetadataTest, GetValue009, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("DateTimeOriginal", "2024:01:25 05:51:34"));
    metadata.GetValue("DateTimeOriginal", value);
    ASSERT_EQ(value, "2024:01:25 05:51:34");
}

HWTEST_F(ExifMetadataTest, GetValue010, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("ExposureTime", "1/34"));
    metadata.GetValue("ExposureTime", value);
    ASSERT_EQ(value, "1/34 sec.");
}

HWTEST_F(ExifMetadataTest, GetValue011, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("SceneType", "1"));
    metadata.GetValue("SceneType", value);
    ASSERT_EQ(value, "Directly photographed");
}

HWTEST_F(ExifMetadataTest, GetValue012, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("ISOSpeedRatings", "160"));
    metadata.GetValue("ISOSpeedRatings", value);
    ASSERT_EQ(value, "160");
}

HWTEST_F(ExifMetadataTest, GetValue013, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("FNumber", "3/1"));
    metadata.GetValue("FNumber", value);
    ASSERT_EQ(value, "f/3.0");
}

HWTEST_F(ExifMetadataTest, GetValue014, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("DateTime", "2024:01:25 05:51:34"));
    metadata.GetValue("DateTime", value);
    ASSERT_EQ(value, "2024:01:25 05:51:34");
}

HWTEST_F(ExifMetadataTest, GetValue015, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("GPSTimeStamp", "11:37:56"));
    metadata.GetValue("GPSTimeStamp", value);
    ASSERT_EQ(value, "11:37:56.00");
}

HWTEST_F(ExifMetadataTest, GetValue016, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("ImageDescription", "_cuva"));
    metadata.GetValue("ImageDescription", value);
    ASSERT_EQ(value, "_cuva");
}

HWTEST_F(ExifMetadataTest, GetValue017, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("Model", "TNY-AL00"));
    metadata.GetValue("Model", value);
    ASSERT_EQ(value, "TNY-AL00");
}

HWTEST_F(ExifMetadataTest, GetValue018, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("SensitivityType", "5"));
    metadata.GetValue("SensitivityType", value);
    ASSERT_EQ(value, "Standard output sensitivity (SOS) and ISO speed");
}

HWTEST_F(ExifMetadataTest, GetValue019, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("StandardOutputSensitivity", "5"));
    metadata.GetValue("StandardOutputSensitivity", value);
    ASSERT_EQ(value, "5");
}

HWTEST_F(ExifMetadataTest, GetValue020, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("RecommendedExposureIndex", "241"));
    metadata.GetValue("RecommendedExposureIndex", value);
    ASSERT_EQ(value, "241");
}

HWTEST_F(ExifMetadataTest, GetValue021, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("ISOSpeedRatings", "160"));
    metadata.GetValue("ISOSpeedRatings", value);
    ASSERT_EQ(value, "160");
}

HWTEST_F(ExifMetadataTest, GetValue022, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("ApertureValue", "4/1"));
    metadata.GetValue("ApertureValue", value);
    ASSERT_EQ(value, "4.00 EV (f/4.0)");
}

HWTEST_F(ExifMetadataTest, GetValue023, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("ExposureBiasValue", "23/1"));
    metadata.GetValue("ExposureBiasValue", value);
    ASSERT_EQ(value, "23.00 EV");
}

HWTEST_F(ExifMetadataTest, GetValue024, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("MeteringMode", "5"));
    metadata.GetValue("MeteringMode", value);
    ASSERT_EQ(value, "Pattern");
}

HWTEST_F(ExifMetadataTest, GetValue025, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("LightSource", "2"));
    metadata.GetValue("LightSource", value);
    ASSERT_EQ(value, "Fluorescent");
}

HWTEST_F(ExifMetadataTest, GetValue026, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("Flash", "5"));
    metadata.GetValue("Flash", value);
    ASSERT_EQ(value, "Strobe return light not detected");
}

HWTEST_F(ExifMetadataTest, GetValue027, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("FocalLength", "31/1"));
    metadata.GetValue("FocalLength", value);
    ASSERT_EQ(value, "31.0 mm");
}

HWTEST_F(ExifMetadataTest, GetValue028, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("UserComment", "comm2"));
    metadata.GetValue("UserComment", value);
    ASSERT_EQ(value, "comm2");
}

HWTEST_F(ExifMetadataTest, GetValue029, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("PixelXDimension", "1000"));
    metadata.GetValue("PixelXDimension", value);
    ASSERT_EQ(value, "1000");
}

HWTEST_F(ExifMetadataTest, GetValue030, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("PixelYDimension", "2000"));
    metadata.GetValue("PixelYDimension", value);
    ASSERT_EQ(value, "2000");
}

HWTEST_F(ExifMetadataTest, GetValue031, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("WhiteBalance", "1"));
    metadata.GetValue("WhiteBalance", value);
    ASSERT_EQ(value, "Manual white balance");
}

HWTEST_F(ExifMetadataTest, GetValue032, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("FocalLengthIn35mmFilm", "2"));
    metadata.GetValue("FocalLengthIn35mmFilm", value);
    ASSERT_EQ(value, "2");
}

HWTEST_F(ExifMetadataTest, GetValue033, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_HW_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    metadata.GetValue("HwMnoteScenePointer", value);
    ASSERT_EQ(value, "256");
    metadata.GetValue("HwMnoteSceneVersion", value);
    ASSERT_EQ(value, "1");
    metadata.GetValue("HwMnoteSceneFoodConf", value);
    ASSERT_EQ(value, "2");
    metadata.GetValue("HwMnoteSceneStageConf", value);
    ASSERT_EQ(value, "3");
    metadata.GetValue("HwMnoteSceneBlueSkyConf", value);
    ASSERT_EQ(value, "4");
    metadata.GetValue("HwMnoteSceneGreenPlantConf", value);
    ASSERT_EQ(value, "5");
    metadata.GetValue("HwMnoteSceneBeachConf", value);
    ASSERT_EQ(value, "6");
    metadata.GetValue("HwMnoteSceneSnowConf", value);
    ASSERT_EQ(value, "7");
    metadata.GetValue("HwMnoteSceneSunsetConf", value);
    ASSERT_EQ(value, "8");
    metadata.GetValue("HwMnoteSceneFlowersConf", value);
    ASSERT_EQ(value, "9");
    metadata.GetValue("HwMnoteSceneNightConf", value);
    ASSERT_EQ(value, "10");
    metadata.GetValue("HwMnoteSceneTextConf", value);
    ASSERT_EQ(value, "11");
}

HWTEST_F(ExifMetadataTest, GetValue034, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_HW_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string value;
    ExifMetadata metadata(exifData);
    metadata.GetValue("HwMnoteFacePointer", value);
    ASSERT_EQ(value, "122");
    metadata.GetValue("HwMnoteFaceVersion", value);
    ASSERT_EQ(value, "1");
    metadata.GetValue("HwMnoteFaceCount", value);
    ASSERT_EQ(value, "2");
    metadata.GetValue("HwMnoteFaceConf", value);
    ASSERT_EQ(value, "3");
    metadata.GetValue("HwMnoteFaceSmileScore", value);
    ASSERT_EQ(value, "1 2 3 4 5 6 7 8");
    metadata.GetValue("HwMnoteFaceRect", value);
    ASSERT_EQ(value, "1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8");
    metadata.GetValue("HwMnoteFaceLeyeCenter", value);
    ASSERT_EQ(value, "1 2 3 4");
    metadata.GetValue("HwMnoteFaceReyeCenter", value);
    ASSERT_EQ(value, "5 6 7 8");
    metadata.GetValue("HwMnoteFaceMouthCenter", value);
    ASSERT_EQ(value, "1 2 3 4 5 6 7 8");
    metadata.GetValue("HwMnoteCaptureMode", value);
    ASSERT_EQ(value, "1");
    metadata.GetValue("HwMnoteBurstNumber", value);
    ASSERT_EQ(value, "2");
    metadata.GetValue("HwMnoteFrontCamera", value);
    ASSERT_EQ(value, "3");
    metadata.GetValue("HwMnoteRollAngle", value);
    ASSERT_EQ(value, "4");
    metadata.GetValue("HwMnotePitchAngle", value);
    ASSERT_EQ(value, "5");
    metadata.GetValue("HwMnotePhysicalAperture", value);
    ASSERT_EQ(value, "6");
    metadata.GetValue("HwMnoteFocusMode", value);
    ASSERT_EQ(value, "7");
}

HWTEST_F(ExifMetadataTest, SetValueBatch001, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("BitsPerSample", "9,9,8"));
    ASSERT_TRUE(metadata.SetValue("Orientation", "1"));
    ASSERT_TRUE(metadata.SetValue("ImageLength", "1000"));
    ASSERT_TRUE(metadata.SetValue("ImageWidth", "1001"));
    ASSERT_TRUE(metadata.SetValue("GPSLatitude", "39,54,20"));
    ASSERT_TRUE(metadata.SetValue("GPSLongitude", "120,52,26"));
    ASSERT_TRUE(metadata.SetValue("GPSLatitudeRef", "N"));
    ASSERT_TRUE(metadata.SetValue("GPSLongitudeRef", "E"));
    ASSERT_TRUE(metadata.SetValue("WhiteBalance", "1"));
    ASSERT_TRUE(metadata.SetValue("FocalLengthIn35mmFilm", "2"));
    ASSERT_TRUE(metadata.SetValue("Flash", "5"));
    ASSERT_TRUE(metadata.SetValue("ApertureValue", "4/1"));
    ASSERT_TRUE(metadata.SetValue("DateTimeOriginal", "2024:01:25 05:51:34"));
    ASSERT_TRUE(metadata.SetValue("DateTime", "2024:01:25 05:51:34"));
    ASSERT_TRUE(metadata.SetValue("ExposureBiasValue", "23/1"));
    ASSERT_TRUE(metadata.SetValue("ExposureTime", "1/34"));
    ASSERT_TRUE(metadata.SetValue("FNumber", "3/1"));
    ASSERT_TRUE(metadata.SetValue("FocalLength", "31/1"));
    ASSERT_TRUE(metadata.SetValue("GPSTimeStamp", "11:37:56"));
    ASSERT_TRUE(metadata.SetValue("GPSDateStamp", "2024:01:25"));
    ASSERT_TRUE(metadata.SetValue("ImageDescription", "_cuva"));
    ASSERT_TRUE(metadata.SetValue("ISOSpeedRatings", "160"));
    ASSERT_TRUE(metadata.SetValue("ISOSpeedRatings", "160"));
    ASSERT_TRUE(metadata.SetValue("LightSource", "2"));
    ASSERT_TRUE(metadata.SetValue("Make", "5"));
    ASSERT_TRUE(metadata.SetValue("MeteringMode", "5"));
    ASSERT_TRUE(metadata.SetValue("Model", "TNY-AL00"));
    ASSERT_TRUE(metadata.SetValue("PixelXDimension", "1000"));
    ASSERT_TRUE(metadata.SetValue("PixelYDimension", "2000"));
    ASSERT_TRUE(metadata.SetValue("RecommendedExposureIndex", "241"));
    ASSERT_TRUE(metadata.SetValue("SceneType", "1"));
    ASSERT_TRUE(metadata.SetValue("SensitivityType", "5"));
    ASSERT_TRUE(metadata.SetValue("StandardOutputSensitivity", "5"));
    ASSERT_TRUE(metadata.SetValue("UserComment", "comm"));
    ASSERT_TRUE(metadata.SetValue("JPEGProc", "252"));
    ASSERT_TRUE(metadata.SetValue("Compression", "6"));
    ASSERT_TRUE(metadata.SetValue("PhotometricInterpretation", "0"));
    ASSERT_TRUE(metadata.SetValue("StripOffsets", "11"));
    ASSERT_TRUE(metadata.SetValue("SamplesPerPixel", "23"));
    ASSERT_TRUE(metadata.SetValue("RowsPerStrip", "252"));
    ASSERT_TRUE(metadata.SetValue("StripByteCounts", "252"));
}

HWTEST_F(ExifMetadataTest, SetValueBatch002, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("XResolution", "72/1"));
    ASSERT_TRUE(metadata.SetValue("YResolution", "252/1"));
    ASSERT_TRUE(metadata.SetValue("PlanarConfiguration", "1"));
    ASSERT_TRUE(metadata.SetValue("ResolutionUnit", "2"));
    ASSERT_TRUE(metadata.SetValue("TransferFunction", "2"));
    ASSERT_TRUE(metadata.SetValue("Software", "MNA-AL00 4.0.0.120(C00E116R3P7)"));
    ASSERT_TRUE(metadata.SetValue("Artist", "Joseph.Xu"));
    ASSERT_TRUE(metadata.SetValue("WhitePoint", "252/1"));
    ASSERT_TRUE(metadata.SetValue("PrimaryChromaticities", "124/1"));
    ASSERT_TRUE(metadata.SetValue("YCbCrCoefficients", "299/1000 587/1000 114/1000"));
    ASSERT_TRUE(metadata.SetValue("YCbCrSubSampling", "3 2"));
    ASSERT_TRUE(metadata.SetValue("YCbCrPositioning", "1"));
    ASSERT_TRUE(metadata.SetValue("ReferenceBlackWhite", "221/1"));
    ASSERT_TRUE(metadata.SetValue("Copyright", "Hw"));
    ASSERT_TRUE(metadata.SetValue("ExposureProgram", "2"));
    ASSERT_TRUE(metadata.SetValue("SpectralSensitivity", "sensitivity"));
    ASSERT_TRUE(metadata.SetValue("OECF", "45"));
    ASSERT_TRUE(metadata.SetValue("ExifVersion", "0210"));
    ASSERT_TRUE(metadata.SetValue("DateTimeDigitized", "2023:01:19 10:39:58"));
    ASSERT_TRUE(metadata.SetValue("ComponentsConfiguration", "1456"));
    ASSERT_TRUE(metadata.SetValue("ShutterSpeedValue", "13/1"));
    ASSERT_TRUE(metadata.SetValue("BrightnessValue", "13/1"));
    ASSERT_TRUE(metadata.SetValue("MaxApertureValue", "1/12"));
    ASSERT_TRUE(metadata.SetValue("SubjectDistance", "25/1"));
    ASSERT_TRUE(metadata.SetValue("SubjectArea", "10 20"));
    ASSERT_TRUE(metadata.SetValue("SubsecTime", "427000"));
    ASSERT_TRUE(metadata.SetValue("SubsecTimeOriginal", "427000"));
    ASSERT_TRUE(metadata.SetValue("SubsecTimeDigitized", "427000"));
    ASSERT_TRUE(metadata.SetValue("FlashpixVersion", "1"));
    ASSERT_TRUE(metadata.SetValue("ColorSpace", "1"));
    ASSERT_TRUE(metadata.SetValue("RelatedSoundFile", "/usr/home/sound/sea.wav"));
}

std::string g_modifyData[][3] = {
    {"BitsPerSample", "9 9 8", "9, 9, 8"},
    {"BitsPerSample", "9, 9, 8", "9, 9, 8"},
    {"BitsPerSample", "9,9,8", "9, 9, 8"},
    {"Orientation", "1", "Top-left"},
    {"Orientation", "4", "Bottom-left"},
    {"ImageLength", "1000", "1000"},
    {"ImageWidth", "1001", "1001"},
    {"GPSLatitude", "114,3", "38.0,  0,  0"},
    {"GPSLatitude", "39,54,20", "39, 54, 20"},
    {"GPSLatitude", "39/1 54/1 20/1", "39, 54, 20"},
    {"GPSLongitude", "120,52,26", "120, 52, 26"},
    {"GPSLatitudeRef", "N", "N"},
    {"GPSLongitudeRef", "E", "E"},
    {"DateTimeOriginal", "2024:01:25 05:51:34", "2024:01:25 05:51:34"},
    {"ExposureTime", "1/34", "1/34 sec."},
    {"ExposureTime", "1/3", "1/3 sec."},
    {"SceneType", "1", "Directly photographed"},
    {"ISOSpeedRatings", "160", "160"},
    {"FNumber", "3/1", "f/3.0"},
    {"DateTime", "2024:01:25 05:51:34", "2024:01:25 05:51:34"},
    {"DateTime", "2024:01:25", "2024:01:25"},
    {"GPSTimeStamp", "11/1 37/1 56/1", "11:37:56.00"},
    {"GPSDateStamp", "2023:10:19", "2023:10:19"},
    {"ImageDescription", "_cuva", "_cuva"},
    {"Make", "XiaoMI", "XiaoMI"},
    {"Model", "TNY-AL00", "TNY-AL00"},
    {"PhotoMode", "252", "252"},
    {"SensitivityType", "5", "Standard output sensitivity (SOS) and ISO speed"},
    {"StandardOutputSensitivity", "5", "5"},
    {"RecommendedExposureIndex", "241", "241"},
    {"ISOSpeed", "1456", "1456"},
    {"ApertureValue", "4/1", "4.00 EV (f/4.0)"},
    {"ExposureBiasValue", "23/1", "23.00 EV"},
    {"MeteringMode", "5", "Pattern"},
    {"LightSource", "2", "Fluorescent"},
    {"Flash", "5", "Strobe return light not detected"},
    {"FocalLength", "31/1", "31.0 mm"},
    {"UserComment", "comm", "comm"},
    {"PixelXDimension", "1000", "1000"},
    {"PixelYDimension", "2000", "2000"},
    {"WhiteBalance", "1", "Manual white balance"},
    {"FocalLengthIn35mmFilm", "2", "2"},
    {"CompressedBitsPerPixel", "24/1", "24"},
    {"JPEGProc", "252", "252"},
    {"Compression", "6", "JPEG compression"},
    {"PhotometricInterpretation", "0", "Reversed mono"},
    {"StripOffsets", "11", "11"},
    {"SamplesPerPixel", "23", "23"},
    {"RowsPerStrip", "252", "252"},
    {"StripByteCounts", "252", "252"},
    {"XResolution", "72/1", "72"},
    {"YResolution", "252/1", "252"},
    {"PlanarConfiguration", "1", "Chunky format"},
    {"ResolutionUnit", "2", "Inch"},
    {"TransferFunction", "2", "1 bytes undefined data"},
    {"Software", "MNA-AL00 4.0.0.120(C00E116R3P7)", "MNA-AL00 4.0.0.120(C00E116R3P7)"},
    {"Artist", "Joseph.Xu", "Joseph.Xu"},
    {"WhitePoint", "252/1", "252, 0/0"},
    {"PrimaryChromaticities", "124/1", "124"},
    {"YCbCrCoefficients", "299/1000 587/1000 114/1000", "0.299, 0.587, 0.114"},
    {"YCbCrSubSampling", "3 2", "3, 2"},
    {"YCbCrPositioning", "1", "Centered"},
    {"ReferenceBlackWhite", "222 0 1.5 0 25.2 25.2", "222,  0, 1.5,  0, 25.2, 25.2"},
    {"Copyright", "Hw", "Hw (Photographer) - [None] (Editor)"},
    {"SubsecTime", "427000", "427000"},
    {"SubsecTimeOriginal", "427000", "427000"},
    {"SubsecTimeDigitized", "427000", "427000"},
    {"FlashpixVersion", "0100", "FlashPix Version 1.0"},
    {"ColorSpace", "2", "Adobe RGB"},
    {"RelatedSoundFile", "/usr/home/sound/sea.wav", "/usr/home/sound/sea.wav"},
    {"FlashEnergy", "832/1", "832"},
    {"SpatialFrequencyResponse", "13", "13"},
    {"FocalPlaneXResolution", "1080/1", "1080"},
    {"FocalPlaneYResolution", "880/1", "880"},
    {"FocalPlaneResolutionUnit", "3", "Centimeter"},
    {"SubjectLocation", "3 12", "3, 12"},
    {"ExposureIndex", "3/2", "1.5"},
    {"SensingMethod", "3", "Two-chip color area sensor"},
    {"FileSource", "3", "DSC"},
    {"CFAPattern", "3", "1 bytes undefined data"},
    {"CustomRendered", "1", "Custom process"},
    {"ExposureMode", "0", "Auto exposure"},
    {"DigitalZoomRatio", "321/1", "321"},
    {"SceneCaptureType", "0", "Standard"},
    {"GainControl", "0", "Normal"},
    {"Contrast", "0", "Normal"},
    {"Saturation", "0", "Normal"},
    {"Sharpness", "0", "Normal"},
    {"DeviceSettingDescription", "2xxx", "2xxx"},
    {"SubjectDistanceRange", "0", "Unknown"},
    {"ImageUniqueID", "FXIC012", "FXIC012"},
    {"GPSVersionID", "2.2.0.0", "2.2.0.0"},
    {"GPSAltitudeRef", "1", "Sea level reference"},
    {"GPSAltitude", "0/100", "0.00"},
    {"GPSSatellites", "xxx", "xxx"},
    {"GPSStatus", "A", "A"},
    {"GPSMeasureMode", "2", "2"},
    {"GPSDOP", "182/1", "182"},
    {"GPSSpeedRef", "K", "K"},
    {"GPSSpeed", "150/1", "150"},
    {"GPSTrackRef", "T", "T"},
    {"GPSTrack", "114/3", "38.0"},
    {"GPSImgDirectionRef", "M", "M"},
    {"GPSImgDirection", "125/56", "2.23"},
    {"GPSMapDatum", "xxxx", "xxxx"},
    {"GPSDestLatitudeRef", "N", "N"},
    {"GPSDestLatitude", "33/1 22/1 11/1", "33, 22, 11"},
    {"GPSDestLongitudeRef", "E", "E"},
    {"GPSDestLongitude", "33/1 22/1 11/1", "33, 22, 11"},
    {"GPSDestBearingRef", "T", "T"},
    {"GPSDestBearing", "22/11", "2.0"},
    {"GPSDestDistanceRef", "N", "N"},
    {"GPSDestDistance", "10/1", "10"},
    {"GPSProcessingMethod", "CELLID", "CELLID"},
    {"GPSAreaInformation", "arexxx", "arexxx"},
    {"GPSDifferential", "0", "0"},
    {"ComponentsConfiguration", "1456", "Y R G B"},
    {"ISOSpeedLatitudeyyy", "1456", "1456"},
    {"ISOSpeedLatitudezzz", "1456", "1456"},
    {"SubjectDistance", "5/2", "2.5 m"},
    {"DefaultCropSize", "153 841", "153, 841"},
    {"LensSpecification", "3/4 5/2 3/2 1/2", "0.8, 2.5, 1.5, 0.5"},
    {"SubjectArea", "12 13", "(x,y) = (12,13)"},
    {"DNGVersion", "2 2 3 1", "2, 2, 3, 1"},
    {"SubfileType", "2", "2"},
    {"NewSubfileType", "3", "3"},
    {"LensMake", "xxwx", "xxwx"},
    {"LensModel", "txaw", "txaw"},
    {"LensSerialNumber", "qxhc", "qxhc"},
    {"OffsetTimeDigitized", "cfh", "cfh"},
    {"OffsetTimeOriginal", "chex", "chex"},
    {"SourceExposureTimesOfCompositeImage", "xxxw", "xxxw"},
    {"SourceImageNumberOfCompositeImage", "23 34", "23, 34"},
    {"GPSHPositioningError", "5/2", "2.5"},
    {"Orientation", "4", "Bottom-left"},
    {"GPSLongitudeRef", "W", "W"},
    {"ExposureProgram", "7", "Portrait mode (for closeup photos with the background out of focus)"},
    {"SpectralSensitivity", "xxd", "xxd"},
    {"OECF", "excc", "4 bytes undefined data"},
    {"ExifVersion", "0110", "Exif Version 1.1"},
    {"DateTimeDigitized", "2024:01:25 05:51:34", "2024:01:25 05:51:34"},
    {"ShutterSpeedValue", "5/2", "2.50 EV (1/6 sec.)"},
    {"BrightnessValue", "5/2", "2.50 EV (19.38 cd/m^2)"},
    {"MaxApertureValue", "5/2", "2.50 EV (f/2.4)"},
    {"BodySerialNumber", "exoch", "exoch"},
    {"CameraOwnerName", "c.uec", "c.uec"},
    {"CompositeImage", "2", "2"},
    {"Gamma", "5/2", "2.5"},
    {"OffsetTime", "2024:01:25", "2024:01:25"},
};

HWTEST_F(ExifMetadataTest, SetValueBatch003, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_BLANKEXIF_PATH.c_str());
    ASSERT_NE(exifData, nullptr);

    std::string value;
    ExifMetadata metadata(exifData);

    int rows = sizeof(g_modifyData) / sizeof(g_modifyData[0]);
    for (int i = 0; i < rows; ++i) {
        std::string key = g_modifyData[i][0];
        std::string modifyvalue = g_modifyData[i][1];
        ASSERT_TRUE(metadata.SetValue(key, modifyvalue));

        std::string retvalue;
        metadata.GetValue(key, retvalue);
        ASSERT_EQ(retvalue, g_modifyData[i][2]);
    }
}

std::string g_dirtData[][2] = {
    {"BitsPerSample", "abc,4"},
    {"DateTimeOriginal", "202:01:25 05:51:34"},
};

HWTEST_F(ExifMetadataTest, SetValueBatch004, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_BLANKEXIF_PATH.c_str());
    ASSERT_NE(exifData, nullptr);

    std::string value;
    ExifMetadata metadata(exifData);

    int rows = sizeof(g_dirtData) / sizeof(g_dirtData[0]);
    for (int i = 0; i < rows; ++i) {
        std::string key = g_dirtData[i][0];
        std::string modifyvalue = g_dirtData[i][1];
        ASSERT_NE(metadata.SetValue(key, modifyvalue), true);
    }
}


std::string g_batchData006[][3] = {
    {"BitsPerSample", "65535,65535,65535", "65535, 65535, 65535"},
    {"Orientation", "8", "Left-bottom"},
    {"ImageLength", "65535", "65535"},
    {"ImageWidth", "65535", "65535"},
    {"GPSLatitude", "114,3", "38.0,  0,  0"},
    {"GPSLongitude", "114,3", "38.0,  0,  0"},
    {"GPSLatitudeRef", "S", "S"},
    {"GPSLongitudeRef", "W", "W"},
    {"DateTimeOriginal", "1900:01:01 00:00:00", "1900:01:01 00:00:00"},
    {"ExposureTime", "1/60", "1/60 sec."},
    {"ISOSpeedRatings", "65535", "65535"},
    {"FNumber", "1/30", "f/0.0"},
    {"DateTime", "1900:01:01", "1900:01:01"},
    {"GPSTimeStamp", "12 54 20", "12:54:20.00"},
    {"GPSDateStamp", "1900:01:01", "1900:01:01"},
    {"ImageDescription", "@  @", "@  @"},
    {"Make", "APPLE", "APPLE"},
    {"Model", "%s \\0", "%s \\0"},
    {"PhotoMode", "13", "13"},
    {"JPEGProc", "13", "13"},
    {"SensitivityType", "0", "Unknown"},
    {"StandardOutputSensitivity", "1000", "1000"},
    {"RecommendedExposureIndex", "2147483647", "2147483647"},
    {"ISOSpeedRatings", "65535", "65535"},
    {"ISOSpeed", "65535", "65535"},
    {"ApertureValue", "16", "16.00 EV (f/256.0)"},
    {"ExposureBiasValue", "4", "4.00 EV"},
    {"MeteringMode", "0", "Unknown"},
    {"LightSource", "2", "Fluorescent"},
    {"Flash", "95", "Flash fired, auto mode, return light detected, red-eye reduction mode"},
    {"FocalLength", "31/1", "31.0 mm"},
    {"UserComment", "%s \\0", "%s \\0"},
    {"PixelXDimension", "0", "0"},
    {"PixelYDimension", "0", "0"},
    {"WhiteBalance", "0", "Auto white balance"},
    {"FocalLengthIn35mmFilm", "12", "12"},
    {"Compression", "32773", "PackBits compression"},
    {"PhotometricInterpretation", "1", "Normal mono"},
    {"StripOffsets", "456", "456"},
    {"SamplesPerPixel", "65535", "65535"},
    {"RowsPerStrip", "345", "345"},
    {"StripByteCounts", "345", "345"},
    {"XResolution", "31/1", "31"},
    {"YResolution", "31/1", "31"},
    {"PlanarConfiguration", "2", "Planar format"},
    {"ResolutionUnit", "3", "Centimeter"},
    {"TransferFunction", "123", "3 bytes undefined data"},
    {"Software", "%s \\0", "%s \\0"},
    {"Artist", "%s \\0", "%s \\0"},
    {"WhitePoint", "31/1", "31, 0/0"},
    {"PrimaryChromaticities", "31/1", "31"},
    {"YCbCrCoefficients", "3/2 4/2 9/3", "1.5, 2.0, 3.0"},
    {"YCbCrSubSampling", "4 5", "4, 5"},
    {"YCbCrPositioning", "2", "Co-sited"},
    {"ReferenceBlackWhite", "3", " 3, 255,  0, 255,  0, 255"},
    {"Copyright", "joseph", "joseph (Photographer) - [None] (Editor)"},
    {"ExposureProgram", "8", "Landscape mode (for landscape photos with the background in focus)"},
    {"SpectralSensitivity", "1234", "1234"},
    {"OECF", "ab", "2 bytes undefined data"},
    {"ExifVersion", "0120", "Exif Version 1.2"},
    {"DateTimeDigitized", "1900:01:01 00:00:00", "1900:01:01 00:00:00"},
    {"ComponentsConfiguration", "1256", "Y Cb G B"},
    {"ShutterSpeedValue", "3/2", "1.50 EV (1/3 sec.)"},
    {"BrightnessValue", "6/5", "1.20 EV (7.87 cd/m^2)"},
    {"MaxApertureValue", "8/5", "1.60 EV (f/1.7)"},
    {"SubjectDistance", "1/2", "0.5 m"},
    {"SubjectArea", "45 23", "(x,y) = (45,23)"},
    {"SubsecTime", "427000", "427000"},
    {"SubsecTimeOriginal", "123456", "123456"},
    {"SubsecTimeDigitized", "999999", "999999"},
    {"FlashpixVersion", "0101", "FlashPix Version 1.01"},
    {"ColorSpace", "2", "Adobe RGB"},
    {"RelatedSoundFile", "abc", "abc"},
    {"FlashEnergy", "5/2", "2.5"},
    {"SpatialFrequencyResponse", "corn", "corn"},
    {"FocalPlaneXResolution", "102/1", "102"},
    {"FocalPlaneYResolution", "81/1", "81"},
    {"FocalPlaneResolutionUnit", "3", "Centimeter"},
    {"SubjectLocation", "23 112", "23, 112"},
    {"ExposureIndex", "5/2", "2.5"},
    {"SensingMethod", "8", "Color sequential linear sensor"},
    {"FileSource", "4", "Internal error (unknown value 4)"},
    {"CFAPattern", "ab", "2 bytes undefined data"},
    {"CustomRendered", "1", "Custom process"},
    {"ExposureMode", "2", "Auto bracket"},
    {"DigitalZoomRatio", "23/1", "23"},
    {"SceneCaptureType", "3", "Night scene"},
    {"GainControl", "4", "High gain down"},
    {"Contrast", "2", "Hard"},
    {"Saturation", "2", "High saturation"},
    {"Sharpness", "2", "Hard"},
    {"DeviceSettingDescription", "coxex", "coxex"},
    {"SubjectDistanceRange", "3", "Distant view"},
    {"ImageUniqueID", "xxx", "xxx"},
    {"GPSVersionID", "2.2.0.1", "2.2.0.1"},
    {"GPSAltitudeRef", "1", "Sea level reference"},
    {"GPSAltitude", "100/100", "1.00"},
    {"GPSSatellites", "a b c", "a b c"},
    {"GPSStatus", "V", "V"},
    {"GPSMeasureMode", "3", "3"},
    {"GPSDOP", "100/100", "1.00"},
    {"GPSSpeedRef", "K", "K"},
    {"GPSSpeed", "0/1", " 0"},
    {"GPSTrackRef", "M", "M"},
    {"GPSTrack", "3.5", "3.5"},
    {"GPSImgDirectionRef", "T", "T"},
    {"GPSImgDirection", "2.5", "2.5"},
    {"GPSMapDatum", "%s\\0", "%s\\0"},
    {"GPSDestLatitudeRef", "S", "S"},
    {"GPSDestLatitude", "0/1 0/1 0/1", " 0,  0,  0"},
    {"GPSDestLongitudeRef", "W", "W"},
    {"GPSDestLongitude", "0/1 0/1 0/1", " 0,  0,  0"},
    {"GPSDestBearingRef", "M", "M"},
    {"GPSDestBearing", "2.5", "2.5"},
    {"GPSDestDistanceRef", "K", "K"},
    {"GPSDestDistance", "2.5", "2.5"},
    {"GPSProcessingMethod", "XXX", "XXX"},
    {"GPSAreaInformation", "client", "client"},
    {"GPSDifferential", "1", "1"},
    {"BodySerialNumber", "xoinc", "xoinc"},
    {"CameraOwnerName", "joseph", "joseph"},
    {"CompositeImage", "3", "3"},
    {"CompressedBitsPerPixel", "25", "25"},
    {"DNGVersion", "2 2 3 2", "2, 2, 3, 2"},
    {"DefaultCropSize", "123 654", "123, 654"},
    {"Gamma", "3/2", "1.5"},
    {"ISOSpeedLatitudeyyy", "123", "123"},
    {"ISOSpeedLatitudezzz", "123", "123"},
    {"LensMake", "plex", "plex"},
    {"LensModel", "world", "world"},
    {"LensSerialNumber", "root", "root"},
    {"LensSpecification", "3/4 5/2 3/2 5/2", "0.8, 2.5, 1.5, 2.5"},
    {"NewSubfileType", "5", "5"},
    {"OffsetTime", "2023:01:25", "2023:01:25"},
    {"OffsetTimeDigitized", "cirtize", "cirtize"},
    {"OffsetTimeOriginal", "ject", "ject"},
    {"SourceExposureTimesOfCompositeImage", "xixe", "xixe"},
    {"SourceImageNumberOfCompositeImage", "11 23", "11, 23"},
    {"SubfileType", "3", "3"},
    {"GPSHPositioningError", "1/2", "0.5"},
    {"PhotographicSensitivity", "65535", "65535"},
    {"BitsPerSample", "1,1,1", "1, 1, 1"},
    {"Orientation", "1", "Top-left"},
    {"ImageLength", "0", "0"},
    {"ImageWidth", "0", "0"},
    {"GPSLatitude", "39,54,20", "39, 54, 20"},
    {"GPSLongitude", "120/1 52/1 26/1", "120, 52, 26"},
    {"GPSLatitudeRef", "N", "N"},
    {"GPSLongitudeRef", "E", "E"},
    {"DateTimeOriginal", "2024:01:25 05:51:34", "2024:01:25 05:51:34"},
    {"ExposureTime", "1/34", "1/34 sec."},
    {"SceneType", "1", "Directly photographed"},
    {"ISOSpeedRatings", "1", "1"},
    {"FNumber", "1/1", "f/1.0"},
    {"DateTime", "2024:01:23", "2024:01:23"},
    {"GPSTimeStamp", "11/1 37/1 58/1", "11:37:58.00"},
    {"GPSDateStamp", "2025:01:11", "2025:01:11"},
    {"ImageDescription", "_cuva%s\\d", "_cuva%s\\d"},
    {"Make", "name", "name"},
    {"Model", "TNY-AL00", "TNY-AL00"},
    {"PhotoMode", "252", "252"},
    {"JPEGProc", "252", "252"},
    {"SensitivityType", "5", "Standard output sensitivity (SOS) and ISO speed"},
    {"StandardOutputSensitivity", "5", "5"},
    {"RecommendedExposureIndex", "123", "123"},
    {"ISOSpeedRatings", "745", "745"},
    {"ISOSpeed", "800", "800"},
    {"ApertureValue", "4/1", "4.00 EV (f/4.0)"},
    {"ExposureBiasValue", "23/1", "23.00 EV"},
    {"MeteringMode", "5", "Pattern"},
    {"LightSource", "1", "Daylight"},
    {"Flash", "5", "Strobe return light not detected"},
    {"FocalLength", "0/1", "0.0 mm"},
    {"UserComment", "place for user comments", "place for user comments"},
    {"PixelXDimension", "123", "123"},
    {"PixelYDimension", "234", "234"},
    {"WhiteBalance", "1", "Manual white balance"},
    {"FocalLengthIn35mmFilm", "2", "2"},
    {"Compression", "1", "Uncompressed"},
    {"PhotometricInterpretation", "0", "Reversed mono"},
    {"StripOffsets", "123", "123"},
    {"SamplesPerPixel", "0", "0"},
    {"RowsPerStrip", "123", "123"},
    {"StripByteCounts", "123", "123"},
    {"XResolution", "0/1", " 0"},
    {"YResolution", "0/1", " 0"},
    {"PlanarConfiguration", "1", "Chunky format"},
    {"ResolutionUnit", "2", "Inch"},
    {"TransferFunction", "abc", "3 bytes undefined data"},
    {"Software", "abcdef", "abcdef"},
    {"Artist", "None", "None"},
    {"WhitePoint", "252/1", "252, 0/0"},
    {"PrimaryChromaticities", "0/1", " 0"},
    {"YCbCrCoefficients", "299/1000 587/1000 114/1000", "0.299, 0.587, 0.114"},
    {"YCbCrSubSampling", "3 2", "3, 2"},
    {"YCbCrPositioning", "1", "Centered"},
    {"ReferenceBlackWhite", "222 0 1.5 0 25.2 25.2", "222,  0, 1.5,  0, 25.2, 25.2"},
    {"Copyright", "undefined", "undefined (Photographer) - [None] (Editor)"},
    {"ExposureProgram", "0", "Not defined"},
    {"SpectralSensitivity", "abc", "abc"},
    {"OECF", "excc", "4 bytes undefined data"},
    {"ExifVersion", "0110", "Exif Version 1.1"},
    {"DateTimeDigitized", "2022:06:02 15:51:34", "2022:06:02 15:51:34"},
    {"ComponentsConfiguration", "1456", "Y R G B"},
    {"ShutterSpeedValue", "5/2", "2.50 EV (1/6 sec.)"},
    {"BrightnessValue", "5/2", "2.50 EV (19.38 cd/m^2)"},
    {"MaxApertureValue", "5/2", "2.50 EV (f/2.4)"},
    {"SubjectDistance", "5/2", "2.5 m"},
    {"SubjectArea", "12 13", "(x,y) = (12,13)"},
    {"SubsecTime", "123456", "123456"},
    {"SubsecTimeOriginal", "427000", "427000"},
    {"SubsecTimeDigitized", "427000", "427000"},
    {"FlashpixVersion", "0100", "FlashPix Version 1.0"},
    {"ColorSpace", "1", "sRGB"},
    {"RelatedSoundFile", "/usr/home", "/usr/home"},
    {"FlashEnergy", "832/1", "832"},
    {"SpatialFrequencyResponse", "13", "13"},
    {"FocalPlaneXResolution", "1080/1", "1080"},
    {"FocalPlaneYResolution", "880/1", "880"},
    {"FocalPlaneResolutionUnit", "2", "Inch"},
    {"SubjectLocation", "0 1", "0, 1"},
    {"ExposureIndex", "3/2", "1.5"},
    {"SensingMethod", "3", "Two-chip color area sensor"},
    {"FileSource", "3", "DSC"},
    {"CFAPattern", "3", "1 bytes undefined data"},
    {"CustomRendered", "0", "Normal process"},
    {"ExposureMode", "0", "Auto exposure"},
    {"DigitalZoomRatio", "321/1", "321"},
    {"SceneCaptureType", "0", "Standard"},
    {"GainControl", "0", "Normal"},
    {"Contrast", "0", "Normal"},
    {"Saturation", "0", "Normal"},
    {"Sharpness", "0", "Normal"},
    {"DeviceSettingDescription", "2xxx", "2xxx"},
    {"SubjectDistanceRange", "0", "Unknown"},
    {"ImageUniqueID", "FXIC012", "FXIC012"},
    {"GPSVersionID", "2.2.0.0", "2.2.0.0"},
    {"GPSAltitudeRef", "0", "Sea level"},
    {"GPSAltitude", "0/100", "0.00"},
    {"GPSSatellites", "xxx", "xxx"},
    {"GPSStatus", "A", "A"},
    {"GPSMeasureMode", "2", "2"},
    {"GPSDOP", "182/1", "182"},
    {"GPSSpeedRef", "N", "N"},
    {"GPSSpeed", "150/1", "150"},
    {"GPSTrackRef", "T", "T"},
    {"GPSTrack", "114/3", "38.0"},
    {"GPSImgDirectionRef", "M", "M"},
    {"GPSImgDirection", "125/56", "2.23"},
    {"GPSMapDatum", "xxx", "xxx"},
    {"GPSDestLatitudeRef", "N", "N"},
    {"GPSDestLatitude", "33/1 22/1 11/1", "33, 22, 11"},
    {"GPSDestLongitudeRef", "E", "E"},
    {"GPSDestLongitude", "33/1 22/1 11/1", "33, 22, 11"},
    {"GPSDestBearingRef", "T", "T"},
    {"GPSDestBearing", "22/11", "2.0"},
    {"GPSDestDistanceRef", "N", "N"},
    {"GPSDestDistance", "10/1", "10"},
    {"GPSProcessingMethod", "CELLID", "CELLID"},
    {"GPSAreaInformation", "arexxx", "arexxx"},
    {"GPSDifferential", "0", "0"},
    {"BodySerialNumber", "exoch", "exoch"},
    {"CameraOwnerName", "c.uec", "c.uec"},
    {"CompositeImage", "2", "2"},
    {"CompressedBitsPerPixel", "24/1", "24"},
    {"DNGVersion", "2 2 3 1", "2, 2, 3, 1"},
    {"DefaultCropSize", "153 841", "153, 841"},
    {"Gamma", "5/2", "2.5"},
    {"ISOSpeedLatitudeyyy", "1456", "1456"},
    {"ISOSpeedLatitudezzz", "1456", "1456"},
    {"LensMake", "xxwx", "xxwx"},
    {"LensModel", "txaw", "txaw"},
    {"LensSerialNumber", "qxhc", "qxhc"},
    {"LensSpecification", "3/4 5/2 3/2 1/2", "0.8, 2.5, 1.5, 0.5"},
    {"NewSubfileType", "3", "3"},
    {"OffsetTime", "2024:01:25", "2024:01:25"},
    {"OffsetTimeDigitized", "cfh", "cfh"},
    {"OffsetTimeOriginal", "chex", "chex"},
    {"SourceExposureTimesOfCompositeImage", "xxxw", "xxxw"},
    {"SourceImageNumberOfCompositeImage", "23 34", "23, 34"},
    {"SubfileType", "2", "2"},
    {"GPSHPositioningError", "5/2", "2.5"},
    {"PhotographicSensitivity", "1", "1"},
    {"HwMnoteCaptureMode", "121", "121"},
    {"MovingPhotoId", "110", "110"},
    {"MovingPhotoVersion", "1", "1"},
    {"MicroVideoPresentationTimestampUS", "123232", "123232"},
};

HWTEST_F(ExifMetadataTest, SetValueBatch006, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_BLANKEXIF_PATH.c_str());
    ASSERT_NE(exifData, nullptr);

    std::string value;
    ExifMetadata metadata(exifData);

    int rows = sizeof(g_batchData006) / sizeof(g_batchData006[0]);
    for (int i = 0; i < rows; ++i) {
        printf("set tag: %s\n", g_batchData006[i][0].c_str());
        std::string key = g_batchData006[i][0];
        std::string modifyvalue = g_batchData006[i][1];
        auto iv = ExifMetadatFormatter::Validate(key, modifyvalue);
        bool isValidateSuccess = (iv == Media::SUCCESS);
        ASSERT_TRUE(isValidateSuccess);

        auto isSetValueSuccess = metadata.SetValue(key, modifyvalue);
        ASSERT_TRUE(isSetValueSuccess);

        std::string retvalue;
        metadata.GetValue(key, retvalue);
        ASSERT_EQ(retvalue, g_batchData006[i][2]);
    }
}

std::string g_error[][2] = {
    {"BitsPerSample", "8,8"},
    {"Orientation", "0"},
    {"ImageLength", "abc"},
    {"ImageWidth", "@@@"},
    {"GPSLatitude", "abc,3"},
    {"GPSLongitude", "12,a"},
    {"GPSLatitudeRef", "W"},
    {"GPSLongitudeRef", "S"},
    {"DateTimeOriginal", "05:61:34"},
    {"ExposureTime", "1/0"},
    {"SceneType", "abc"},
    {"ISOSpeedRatings", "-1"},
    {"FNumber", "1/0"},
    {"DateTime", "2024:13"},
    {"GPSTimeStamp", "37/0,58/0"},
    {"GPSDateStamp", "2023:01"},
    {"SensitivityType", "a"},
    {"StandardOutputSensitivity", "abc"},
    {"RecommendedExposureIndex", "-123"},
    {"ISOSpeed", "a"},
    {"ApertureValue", "a"},
    {"ExposureBiasValue", "a"},
    {"MeteringMode", "256"},
    {"LightSource", "256"},
    {"Flash", "999"},
    {"FocalLength", "a"},
    {"UserComment", ""},
    {"PixelXDimension", "abc"},
    {"PixelYDimension", "!!!"},
    {"WhiteBalance", "2"},
    {"FocalLengthIn35mmFilm", "abc"},
    {"Compression", "11"},
    {"PhotometricInterpretation", "a"},
    {"StripOffsets", "abc"},
    {"SamplesPerPixel", "-1"},
    {"RowsPerStrip", "abc"},
    {"StripByteCounts", "abc"},
    {"XResolution", "a"},
    {"YResolution", "b"},
    {"PlanarConfiguration", "a"},
    {"ResolutionUnit", "4"},
    {"WhitePoint", "abc"},
    {"PrimaryChromaticities", "abc"},
    {"YCbCrCoefficients", "123,345"},
    {"YCbCrSubSampling", "4"},
    {"YCbCrPositioning", "3"},
    {"ReferenceBlackWhite", "undefined"},
    {"ExposureProgram", "-1"},
    {"ExifVersion", "a"},
    {"DateTimeDigitized", "a"},
    {"ComponentsConfiguration", "a"},
    {"ShutterSpeedValue", "0/0"},
    {"BrightnessValue", "12000000/0"},
    {"MaxApertureValue", "-1/0"},
    {"SubjectDistance", "meter"},
    {"SubjectArea", "abc"},
    {"FlashpixVersion", "abc"},
    {"ColorSpace", "abc"},
    {"FlashEnergy", "abc"},
    {"SpatialFrequencyResponse", ""},
    {"FocalPlaneXResolution", "abc"},
    {"FocalPlaneYResolution", "abc"},
    {"FocalPlaneResolutionUnit", "255"},
    {"SubjectLocation", "2"},
    {"ExposureIndex", "-1/1"},
    {"SensingMethod", "9"},
    {"CustomRendered", "2"},
    {"ExposureMode", "3"},
    {"DigitalZoomRatio", "a"},
    {"SceneCaptureType", "4"},
    {"GainControl", "5"},
    {"Contrast", "3"},
    {"Saturation", "65536"},
    {"Sharpness", "65535"},
    {"DeviceSettingDescription", ""},
    {"SubjectDistanceRange", "a"},
    {"GPSVersionID", "23"},
    {"GPSAltitudeRef", "2"},
    {"GPSAltitude", "abc"},
    {"GPSStatus", "C"},
    {"GPSMeasureMode", "4"},
    {"GPSDOP", "-1"},
    {"GPSSpeedRef", "AA"},
    {"GPSSpeed", "a"},
    {"GPSTrack", "a"},
    {"GPSImgDirectionRef", "C"},
    {"GPSImgDirection", "a"},
    {"GPSDestLatitudeRef", "W"},
    {"GPSDestLatitude", "abc"},
    {"GPSDestLongitudeRef", "S"},
    {"GPSDestLongitude", "none"},
    {"GPSDestBearing", "x"},
    {"GPSDestDistanceRef", "C"},
    {"GPSDestDistance", "B"},
    {"GPSDifferential", "4"},
    {"CompositeImage", "5"},
    {"CompressedBitsPerPixel", "diry"},
    {"DNGVersion", "2 3"},
    {"DefaultCropSize", "hi xic"},
    {"Gamma", "rat"},
    {"ISOSpeedLatitudeyyy", "a"},
    {"ISOSpeedLatitudezzz", "bc"},
    {"LensSpecification", "a b c"},
    {"NewSubfileType", "a"},
    {"SourceImageNumberOfCompositeImage", "a"},
    {"SubfileType", "5"},
    {"GPSHPositioningError", "a"},
    {"PhotographicSensitivity", "-1"},
    {"GPSLatitude", "100,20,10"},
    {"GPSLongitude", "200,20,10"},
    {"DateTime", "2024:01:23 25:10:10"},
    {"ImageLength", "65538"},
};


HWTEST_F(ExifMetadataTest, SetValueBatch007, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_BLANKEXIF_PATH.c_str());
    ASSERT_NE(exifData, nullptr);

    std::string value;
    ExifMetadata metadata(exifData);

    int rows = sizeof(g_error) / sizeof(g_error[0]);
    for (int i = 0; i < rows; ++i) {
        std::string key = g_error[i][0];
        std::string modifyvalue = g_error[i][1];
        auto iv = ExifMetadatFormatter::Validate(key, modifyvalue);
        bool isValidateSuccess = (iv == Media::SUCCESS);
        auto isSetValueSuccess = metadata.SetValue(key, modifyvalue);
        ASSERT_FALSE(isValidateSuccess && isSetValueSuccess);
    }
}


std::map<std::string, ExifIfd> IFDTable = {
    { "BitsPerSample", EXIF_IFD_0 },
    { "Orientation", EXIF_IFD_0 },
    { "ImageLength", EXIF_IFD_0 },
    { "ImageWidth", EXIF_IFD_0 },
    { "Compression", EXIF_IFD_0 },
    { "StripOffsets", EXIF_IFD_0 },
    { "PhotoMode", EXIF_IFD_0},
    { "JPEGProc", EXIF_IFD_0},
    { "PhotometricInterpretation", EXIF_IFD_0},
    { "SamplesPerPixel", EXIF_IFD_0},
    { "RowsPerStrip", EXIF_IFD_0},
    { "StripByteCounts", EXIF_IFD_0},
    { "XResolution", EXIF_IFD_0},
    { "YResolution", EXIF_IFD_0},
    { "PlanarConfiguration", EXIF_IFD_0},
    { "ResolutionUnit", EXIF_IFD_0},
    { "TransferFunction", EXIF_IFD_0},
    { "Software", EXIF_IFD_0},
    { "Artist", EXIF_IFD_0},
    { "WhitePoint", EXIF_IFD_0},
    { "PrimaryChromaticities", EXIF_IFD_0},
    { "YCbCrCoefficients", EXIF_IFD_0},
    { "YCbCrSubSampling", EXIF_IFD_0},
    { "YCbCrPositioning", EXIF_IFD_0},
    { "ReferenceBlackWhite", EXIF_IFD_0},
    { "Copyright", EXIF_IFD_0},
    { "JPEGInterchangeFormat", EXIF_IFD_1},
    { "JPEGInterchangeFormatLength", EXIF_IFD_1},
    { "NewSubfileType", EXIF_IFD_0},
    { "DateTime", EXIF_IFD_0 },
    { "ImageDescription", EXIF_IFD_0 },
    { "Make", EXIF_IFD_0 },
    { "Model", EXIF_IFD_0 },
    { "DefaultCropSize", EXIF_IFD_0 },
    { "DNGVersion", EXIF_IFD_0 },
    { "SubfileType", EXIF_IFD_0 },
    { "DateTimeOriginal", EXIF_IFD_EXIF },
    { "ExposureTime", EXIF_IFD_EXIF },
    { "FNumber", EXIF_IFD_EXIF },
    { "ISOSpeedRatings", EXIF_IFD_EXIF },
    { "ISOSpeed", EXIF_IFD_EXIF},
    { "DeviceSettingDescription", EXIF_IFD_EXIF},
    { "SceneType", EXIF_IFD_EXIF },
    { "CompressedBitsPerPixel", EXIF_IFD_EXIF },
    { "SensitivityType", EXIF_IFD_EXIF },
    { "StandardOutputSensitivity", EXIF_IFD_EXIF },
    { "RecommendedExposureIndex", EXIF_IFD_EXIF },
    { "ApertureValue", EXIF_IFD_EXIF },
    { "ExposureBiasValue", EXIF_IFD_EXIF },
    { "MeteringMode", EXIF_IFD_EXIF },
    { "FocalLength", EXIF_IFD_EXIF },
    { "ExposureProgram", EXIF_IFD_EXIF },
    { "SpectralSensitivity", EXIF_IFD_EXIF },
    { "OECF", EXIF_IFD_EXIF },
    { "ExifVersion", EXIF_IFD_EXIF },
    { "DateTimeDigitized", EXIF_IFD_EXIF },
    { "ComponentsConfiguration", EXIF_IFD_EXIF },
    { "ShutterSpeedValue", EXIF_IFD_EXIF },
    { "BrightnessValue", EXIF_IFD_EXIF },
    { "MaxApertureValue", EXIF_IFD_EXIF },
    { "SubjectDistance", EXIF_IFD_EXIF },
    { "SubjectArea", EXIF_IFD_EXIF },
    { "MakerNote", EXIF_IFD_EXIF },
    { "SubsecTime", EXIF_IFD_EXIF },
    { "SubsecTimeOriginal", EXIF_IFD_EXIF },
    { "SubsecTimeDigitized", EXIF_IFD_EXIF },
    { "FlashpixVersion", EXIF_IFD_EXIF },
    { "ColorSpace", EXIF_IFD_EXIF },
    { "RelatedSoundFile", EXIF_IFD_EXIF },
    { "FlashEnergy", EXIF_IFD_EXIF },
    { "FocalPlaneXResolution", EXIF_IFD_EXIF },
    { "FocalPlaneYResolution", EXIF_IFD_EXIF },
    { "FocalPlaneResolutionUnit", EXIF_IFD_EXIF },
    { "SubjectLocation", EXIF_IFD_EXIF },
    { "ExposureIndex", EXIF_IFD_EXIF },
    { "SensingMethod", EXIF_IFD_EXIF },
    { "FileSource", EXIF_IFD_EXIF },
    { "CFAPattern", EXIF_IFD_EXIF },
    { "CustomRendered", EXIF_IFD_EXIF },
    { "ExposureMode", EXIF_IFD_EXIF },
    { "DigitalZoomRatio", EXIF_IFD_EXIF },
    { "SceneCaptureType", EXIF_IFD_EXIF },
    { "GainControl", EXIF_IFD_EXIF },
    { "Contrast", EXIF_IFD_EXIF },
    { "Saturation", EXIF_IFD_EXIF },
    { "Sharpness", EXIF_IFD_EXIF },
    { "SubjectDistanceRange", EXIF_IFD_EXIF },
    { "ImageUniqueID", EXIF_IFD_EXIF },
    { "BodySerialNumber", EXIF_IFD_EXIF },
    { "CameraOwnerName", EXIF_IFD_EXIF },
    { "CompositeImage", EXIF_IFD_EXIF },
    { "Gamma", EXIF_IFD_EXIF },
    { "ISOSpeedLatitudeyyy", EXIF_IFD_EXIF },
    { "ISOSpeedLatitudezzz", EXIF_IFD_EXIF },
    { "SpatialFrequencyResponse", EXIF_IFD_EXIF},
    { "LensMake", EXIF_IFD_EXIF },
    { "LensModel", EXIF_IFD_EXIF },
    { "LensSerialNumber", EXIF_IFD_EXIF },
    { "LensSpecification", EXIF_IFD_EXIF },
    { "OffsetTime", EXIF_IFD_EXIF },
    { "OffsetTimeDigitized", EXIF_IFD_EXIF },
    { "OffsetTimeOriginal", EXIF_IFD_EXIF },
    { "SourceExposureTimesOfCompositeImage", EXIF_IFD_EXIF },
    { "SourceImageNumberOfCompositeImage", EXIF_IFD_EXIF },
    { "LightSource", EXIF_IFD_EXIF },
    { "Flash", EXIF_IFD_EXIF },
    { "FocalLengthIn35mmFilm", EXIF_IFD_EXIF },
    { "UserComment", EXIF_IFD_EXIF },
    { "PixelXDimension", EXIF_IFD_EXIF },
    { "PixelYDimension", EXIF_IFD_EXIF },
    { "WhiteBalance", EXIF_IFD_EXIF },
    { "GPSVersionID", EXIF_IFD_GPS },
    { "GPSLatitudeRef", EXIF_IFD_GPS },
    { "GPSLatitude", EXIF_IFD_GPS },
    { "GPSLongitudeRef", EXIF_IFD_GPS },
    { "GPSLongitude", EXIF_IFD_GPS },
    { "GPSAltitudeRef", EXIF_IFD_GPS },
    { "GPSAltitude", EXIF_IFD_GPS },
    { "GPSTimeStamp", EXIF_IFD_GPS },
    { "GPSSatellites", EXIF_IFD_GPS },
    { "GPSStatus", EXIF_IFD_GPS },
    { "GPSMeasureMode", EXIF_IFD_GPS },
    { "GPSDOP", EXIF_IFD_GPS },
    { "GPSSpeedRef", EXIF_IFD_GPS },
    { "GPSSpeed", EXIF_IFD_GPS },
    { "GPSTrackRef", EXIF_IFD_GPS },
    { "GPSTrack", EXIF_IFD_GPS },
    { "GPSImgDirectionRef", EXIF_IFD_GPS },
    { "GPSImgDirection", EXIF_IFD_GPS },
    { "GPSMapDatum", EXIF_IFD_GPS },
    { "GPSDestLatitudeRef", EXIF_IFD_GPS },
    { "GPSDestLatitude", EXIF_IFD_GPS },
    { "GPSDestLongitudeRef", EXIF_IFD_GPS },
    { "GPSDestLongitude", EXIF_IFD_GPS },
    { "GPSDestBearingRef", EXIF_IFD_GPS },
    { "GPSDestBearing", EXIF_IFD_GPS },
    { "GPSDestDistanceRef", EXIF_IFD_GPS },
    { "GPSDestDistance", EXIF_IFD_GPS },
    { "GPSProcessingMethod", EXIF_IFD_GPS },
    { "GPSAreaInformation", EXIF_IFD_GPS },
    { "GPSDateStamp", EXIF_IFD_GPS },
    { "GPSDifferential", EXIF_IFD_GPS },
    { "GPSHPositioningError", EXIF_IFD_GPS }
};
HWTEST_F(ExifMetadataTest, GetIFD001, TestSize.Level3)
{
    for (const auto &it : IFDTable) {
        auto ifd = exif_ifd_from_name(it.first.c_str());
        ASSERT_EQ(ifd, it.second);
    }
}

std::string g_RemoveBatch001[] = {
    {"ImageLength"},
    {"HwMnoteCaptureMode"},
    {"MovingPhotoId"},
    {"MovingPhotoVersion"},
    {"MicroVideoPresentationTimestampUS"},
};

HWTEST_F(ExifMetadataTest, RemoveBatch001, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_RM_ENTRY_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::string DEFAULT_EXIF_VALUE = "default_exif_value";
    ExifMetadata metadata(exifData);
    int rows = sizeof(g_RemoveBatch001) / sizeof(g_RemoveBatch001[0]);
    for (int i = 0; i < rows; ++i) {
        std::string value;
        int ret = metadata.GetValue(g_RemoveBatch001[i], value);
        printf("remove entry '%s' before, get value: %s\n", g_RemoveBatch001[i].c_str(), value.c_str());
        ASSERT_NE(value, DEFAULT_EXIF_VALUE);

        printf("remove entry: %s\n", g_RemoveBatch001[i].c_str());
        auto isRemoved = metadata.RemoveEntry(g_RemoveBatch001[i]);
        ASSERT_TRUE(isRemoved);

        ret = metadata.GetValue(g_RemoveBatch001[i], value);
        printf("remove entry '%s' after, get value: %s\n", g_RemoveBatch001[i].c_str(), value.c_str());
        if (i == 0) {
            ASSERT_EQ(value, "");
        } else {
            ASSERT_EQ(value, DEFAULT_EXIF_VALUE);
        }
    }
}

} // namespace Multimedia
} // namespace OHOS
