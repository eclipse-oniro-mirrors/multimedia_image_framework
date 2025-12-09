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

#define private public
#include <gtest/gtest.h>
#include <memory>
#include "exif_metadata_formatter.h"
#include "image_log.h"
#include "media_errors.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";

class ExifMetadataFormatterTest : public testing::Test {
public:
    ExifMetadataFormatterTest() {}
    ~ExifMetadataFormatterTest() {}
};

std::string g_modifyData[][3] = {
    {"BitsPerSample", "9 9 8", "9, 9, 8"},
    {"BitsPerSample", "9,9,8", "9, 9, 8"},
    {"Orientation", "1", "Top-left"},
    {"ImageLength", "1000", "1000"},
    {"ImageWidth", "1001", "1001"},
    {"CompressedBitsPerPixel", "24/1", "24"},
    {"GPSLatitude", "39,54,20", "39, 54, 20"},
    {"GPSLatitude", "39/1 54/1 20/1", "39, 54, 20"},
    {"GPSLongitude", "120,52,26", "120, 52, 26"},
    {"GPSLatitudeRef", "N", "N"},
    {"GPSLongitudeRef", "E", "E"},
    {"WhiteBalance", "1", "Manual white balance"},
    {"FocalLengthIn35mmFilm", "2", "2"},
    {"Flash", "5", "Strobe return light not detected"},
    {"ApertureValue", "4/1", "4.00 EV (f/4.0)"},
    {"DateTimeOriginal", "2024:01:25 05:51:34", "2024:01:25 05:51:34"},
    {"DateTime", "2024:01:25 05:51:34", "2024:01:25 05:51:34"},
    {"DateTime", "2024:01:25", "2024:01:25"},
    {"ExposureBiasValue", "23/1", "23.00 EV"},
    {"ExposureTime", "1/34", "1/34 sec."},
    {"FNumber", "3/1", "f/3.0"},
    {"FocalLength", "31/1", "31.0 mm"},
    {"GPSTimeStamp", "11/1 37/1 56/1", "11:37:56.00"},
    {"ImageDescription", "_cuva", "_cuva"},
    {"ISOSpeedRatings", "160", "160"},
    {"LightSource", "2", "Fluorescent"},
    {"MeteringMode", "5", "Pattern"},
    {"Model", "TNY-AL00", "TNY-AL00"},
    {"PixelXDimension", "1000", "1000"},
    {"PixelYDimension", "2000", "2000"},
    {"RecommendedExposureIndex", "241", "241"},
    {"SceneType", "1", "Internal error (unknown value 49)"},
    {"SensitivityType", "5", "Standard output sensitivity (SOS) and ISO speed"},
    {"StandardOutputSensitivity", "5", "5"},
    {"UserComment", "comm", "comm"},
};

HWTEST_F(ExifMetadataFormatterTest, Validate001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate001 start";
    ASSERT_EQ(ExifMetadatFormatter::Validate("BitsPerSample", "9,9,8"), 0);
    ASSERT_EQ(ExifMetadatFormatter::Validate("Orientation", "1"), 0);
    ASSERT_EQ(ExifMetadatFormatter::Validate("ImageLength", "100"), 0);
    ASSERT_EQ(ExifMetadatFormatter::Validate("ImageWidth", "100"), 0);
    ASSERT_EQ(ExifMetadatFormatter::Validate("GPSLatitude", "39,54"), 0);
    ASSERT_EQ(ExifMetadatFormatter::Validate("GPSLatitude", "39,54,20"), 0);
    ASSERT_EQ(ExifMetadatFormatter::Validate("GPSLongitude", "39,54"), 0);
    ASSERT_EQ(ExifMetadatFormatter::Validate("GPSLongitude", "39,54,20"), 0);
    ASSERT_EQ(ExifMetadatFormatter::Validate("GPSLatitudeRef", "N"), 0);
    ASSERT_EQ(ExifMetadatFormatter::Validate("GPSLongitudeRef", "E"), 0);
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate001 end";
}

HWTEST_F(ExifMetadataFormatterTest, Validate002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate002 start";
    ASSERT_NE(ExifMetadatFormatter::Validate("BitsPerSample", "xx"), 0);
    ASSERT_NE(ExifMetadatFormatter::Validate("ImageLength", "XXX"), 0);
    ASSERT_NE(ExifMetadatFormatter::Validate("GPSLatitudeRef", "C"), 0);
    ASSERT_NE(ExifMetadatFormatter::Validate("GPSLongitudeRef", "C"), 0);
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate002 end";
}

/**
 * @tc.name: Validate003
 * @tc.desc: test the Validate when GPSLatitude value has double spaces between fractions
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, Validate003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate003 start";
    std::string keyName = "GPSLatitude";
    std::string value1 = "123/1  456/1 789/1";
    int32_t result = ExifMetadatFormatter::Validate(keyName, value1);
    ASSERT_NE(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate003 end";
}

/**
 * @tc.name: Validate004
 * @tc.desc: test the Validate when GPSLatitude value has no fraction format
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, Validate004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate004 start";
    std::string keyName = "GPSLatitude";
    std::string value1 = "123 456 789";
    int32_t result = ExifMetadatFormatter::Validate(keyName, value1);
    ASSERT_NE(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate004 end";
}

/**
 * @tc.name: Validate005
 * @tc.desc: test the Validate when GPSLatitude value has invalid numerator
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, Validate005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate005 start";
    std::string keyName = "GPSLatitude";
    std::string value1 = "abc/1 456/1 789/1";
    int32_t result = ExifMetadatFormatter::Validate(keyName, value1);
    ASSERT_NE(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate005 end";
}

/**
 * @tc.name: Validate006
 * @tc.desc: test the Validate when GPSLatitude value has invalid denominator
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, Validate006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate006 start";
    std::string keyName = "GPSLatitude";
    std::string value1 = "123/abc 456/1 789/1";
    int32_t result = ExifMetadatFormatter::Validate(keyName, value1);
    ASSERT_NE(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate006 end";
}

/**
 * @tc.name: Validate007
 * @tc.desc: test the Validate when GPSLatitude value has zero denominators
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, Validate007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate007 start";
    std::string keyName = "GPSLatitude";
    std::string value1 = "123/0 456/0 789/1";
    int32_t result = ExifMetadatFormatter::Validate(keyName, value1);
    ASSERT_NE(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate007 end";
}

/**
 * @tc.name: Validate008
 * @tc.desc: test the Validate when GPSLatitude value has insufficient components
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, Validate008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate008 start";
    std::string keyName = "GPSLatitude";
    std::string value1 = "123/1";
    int32_t result = ExifMetadatFormatter::Validate(keyName, value1);
    ASSERT_EQ(result, ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate008 end";
}

/**
 * @tc.name: Validate009
 * @tc.desc: test the Validate when GPSLatitude value has zero denominator in last component
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, Validate009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate009 start";
    std::string keyName = "GPSLatitude";
    std::string value1 = "123/1 456/1 789/0";
    int32_t result = ExifMetadatFormatter::Validate(keyName, value1);
    ASSERT_EQ(result, ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "ExifMetadataFormatterTest: Validate009 end";
}

/**
 * @tc.name: IsValidValueTest001
 * @tc.desc: test the IsValidValue when array is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, IsValidValueTest001, TestSize.Level3)
{
    ASSERT_FALSE(ExifMetadatFormatter::IsValidValue(nullptr, 0, 0));
}

/**
 * @tc.name: RationalFormat001
 * @tc.desc: test the RationalFormat for nomatched value
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, RationalFormat001, TestSize.Level3)
{
    std::string value = "12 abc";
    ExifMetadatFormatter::RationalFormat(value);
    EXPECT_EQ(value, "12/1");
}

/**
 * @tc.name: GetFractionFromStrTest001
 * @tc.desc: Test GetFractionFromStr when int part out of range
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, GetFractionFromStrTest001, TestSize.Level3)
{
    bool isOutRange = false;
    std::string result = ExifMetadatFormatter::GetFractionFromStr("abc.5", isOutRange);
    EXPECT_EQ(result, "");
    EXPECT_TRUE(isOutRange);
}

/**
 * @tc.name: GetFractionFromStrTest002
 * @tc.desc: Test GetFractionFromStr when the input is a valid decimal number
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, GetFractionFromStrTest002, TestSize.Level3)
{
    bool isOutRange = false;
    std::string result = ExifMetadatFormatter::GetFractionFromStr("2.5", isOutRange);
    EXPECT_EQ(result, "5/2");
    EXPECT_FALSE(isOutRange);

    result = ExifMetadatFormatter::GetFractionFromStr("10.25", isOutRange);
    EXPECT_EQ(result, "41/4");
    EXPECT_FALSE(isOutRange);

    result = ExifMetadatFormatter::GetFractionFromStr("7.0", isOutRange);
    EXPECT_EQ(result, "7/1");
    EXPECT_FALSE(isOutRange);
}

/**
 * @tc.name: GetFractionFromStrTest003
 * @tc.desc: test the GetFractionFromStr when decimal part is extremely long
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, GetFractionFromStrTest003, TestSize.Level3)
{
    bool isOutRange = false;
    std::string testValue = "111111111111111111.1111111111111111111111";
    std::string result = ExifMetadatFormatter::GetFractionFromStr(testValue, isOutRange);
    EXPECT_EQ(result, "");
    EXPECT_TRUE(isOutRange);
}

/**
 * @tc.name: GetFractionFromStrTest004
 * @tc.desc: test the GetFractionFromStr when decimal value contains non-numeric suffix
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, GetFractionFromStrTest004, TestSize.Level3)
{
    bool isOutRange = false;
    std::string testValue = "1.17976abc";
    std::string result = ExifMetadatFormatter::GetFractionFromStr(testValue, isOutRange);
    EXPECT_EQ(result, "14747/12500");
    EXPECT_FALSE(isOutRange);
}

/**
 * @tc.name: GetFractionFromStrTest005
 * @tc.desc: test the GetFractionFromStr when input is integer decimal value
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, GetFractionFromStrTest005, TestSize.Level3)
{
    bool isOutRange = false;
    std::string testValue = "3.0";
    std::string result = ExifMetadatFormatter::GetFractionFromStr(testValue, isOutRange);
    EXPECT_EQ(result, "3/1");
    EXPECT_FALSE(isOutRange);
}

/**
 * @tc.name: GetFractionFromStrTest006
 * @tc.desc: test the GetFractionFromStr when decimal value contains non-numeric suffix
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, GetFractionFromStrTest006, TestSize.Level3)
{
    bool isOutRange = false;
    std::string testValue = "a1.abcabc";
    std::string result = ExifMetadatFormatter::GetFractionFromStr(testValue, isOutRange);
    EXPECT_EQ(result, "");
    EXPECT_TRUE(isOutRange);
}

/**
 * @tc.name: ValidDecimalRationalFormatTest001
 * @tc.desc: test the ValidDecimalRationalFormat when value is very small scientific notation
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, ValidDecimalRationalFormatTest001, TestSize.Level3)
{
    bool res = false;
    std::string testValue = "1.1e-400";
    res = ExifMetadatFormatter::ValidDecimalRationalFormat(testValue);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: ValidDecimalRationalFormatTest002
 * @tc.desc: test the ValidDecimalRationalFormat when value is very large scientific notation
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, ValidDecimalRationalFormatTest002, TestSize.Level3)
{
    bool res = false;
    std::string testValue = "1.1e400";
    res = ExifMetadatFormatter::ValidDecimalRationalFormat(testValue);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: ValidConvertRationalFormatTest001
 * @tc.desc: test the ValidConvertRationalFormat when value is extremely large scientific notation
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, ValidConvertRationalFormatTest001, TestSize.Level3)
{
    bool res = false;
    std::string testValue = "2.5e400";
    res = ExifMetadatFormatter::ValidConvertRationalFormat(testValue);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: ValidRegexWithChannelFormatTest001
 * @tc.desc: test the ValidRegexWithChannelFormat when testValue is valid single dash
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, ValidRegexWithChannelFormatTest001, TestSize.Level3)
{
    bool res = false;
    std::string testValue = "-";
    std::string regex = "[-YCbCrRGB]+";
    res = ExifMetadatFormatter::ValidRegexWithChannelFormat(testValue, regex);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: ValidRegexWithChannelFormatTest002
 * @tc.desc: test the ValidRegexWithChannelFormat when testValue does not match regex pattern
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, ValidRegexWithChannelFormatTest002, TestSize.Level3)
{
    bool res = false;
    std::string testValue = "InvalidString";
    std::string regex = "[-YCbCrRGB]+";
    res = ExifMetadatFormatter::ValidRegexWithChannelFormat(testValue, regex);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: ValidRegexWithGpsOneRationalFormatTest001
 * @tc.desc: test the ValidRegexWithGpsOneRationalFormat when testValue is numeric string
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, ValidRegexWithGpsOneRationalFormatTest001, TestSize.Level3)
{
    bool res = false;
    std::string testValue = "123";
    std::string regex = "\\d+";
    res = ExifMetadatFormatter::ValidRegexWithGpsOneRationalFormat(testValue, regex);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: ValidRegexWithGpsOneRationalFormatTest002
 * @tc.desc: test the ValidateValueRange when value is extremely large for Orientation
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, ValidRegexWithGpsOneRationalFormatTest002, TestSize.Level3)
{
    std::string keyName = "Orientation";
    std::string largeValue = "9999999999999999999";
    int32_t res = ExifMetadatFormatter::ValidateValueRange(keyName, largeValue);
    EXPECT_EQ(res, Media::ERR_MEDIA_OUT_OF_RANGE);
}

/**
 * @tc.name: ValidRegexWithGpsOneRationalFormatTest003
 * @tc.desc: test the ValidateValueRange when value is large for Orientation
 * @tc.type: FUNC
 */
HWTEST_F(ExifMetadataFormatterTest, ValidRegexWithGpsOneRationalFormatTest003, TestSize.Level3)
{
    std::string keyName = "Orientation";
    std::string largeValue = "9999999999999999999";
    int32_t res = ExifMetadatFormatter::ValidateValueRange(keyName, largeValue);
    EXPECT_EQ(res, Media::ERR_MEDIA_OUT_OF_RANGE);
}
} // namespace Multimedia
} // namespace OHOS
