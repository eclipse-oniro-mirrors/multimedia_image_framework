/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "buffer_source_stream.h"
#include "exif_info.h"
#include "image_packer.h"
#include "jpeg_decoder.h"
#include "mock_data_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
static constexpr size_t STREAM_SIZE = 1000;
const std::string ORIENTATION = "Orientation";
const std::string IMAGE_LENGTH = "ImageLength";
const std::string SCENE_TYPE = "SceneType";
const std::string COMPRESSED_BITS_PER_PIXEL = "CompressedBitsPerPixel";
const std::string DATE_TIME = "DateTime";
const std::string GPS_TIME_STAMP = "GPSTimeStamp";
const std::string GPS_DATE_STAMP = "GPSDateStamp";
const std::string IMAGE_DESCRIPTION = "ImageDescription";
const std::string MAKE = "Make";
const std::string MODEL = "Model";
const std::string PHOTO_MODE = "PhotoMode";
const std::string SENSITIVITY_TYPE = "SensitivityType";
const std::string STANDARD_OUTPUT_SENSITIVITY = "StandardOutputSensitivity";
const std::string RECOMMENDED_EXPOSURE_INDEX = "RecommendedExposureIndex";
const std::string ISO_SPEED = "ISOSpeedRatings";
const std::string APERTURE_VALUE = "ApertureValue";
const std::string EXPOSURE_BIAS_VALUE = "ExposureBiasValue";
const std::string METERING_MODE = "MeteringMode";
const std::string LIGHT_SOURCE = "LightSource";
const std::string FLASH = "Flash";
const std::string FOCAL_LENGTH = "FocalLength";
const std::string USER_COMMENT = "UserComment";
const std::string PIXEL_X_DIMENSION = "PixelXDimension";
const std::string PIXEL_Y_DIMENSION = "PixelYDimension";
const std::string WHITE_BALANCE = "WhiteBalance";
const std::string FOCAL_LENGTH_IN_35_MM_FILM = "FocalLengthIn35mmFilm";
const std::string HW_MNOTE_CAPTURE_MODE = "HwMnoteCaptureMode";
const std::string HW_MNOTE_PHYSICAL_APERTURE = "HwMnotePhysicalAperture";
class JpegDecoderTest : public testing::Test {
public:
    JpegDecoderTest() {}
    ~JpegDecoderTest() {}
};

/**
 * @tc.name: GetImagePropertyStringTest016
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest016 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = COMPRESSED_BITS_PER_PIXEL;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.compressedBitsPerPixel_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest016 end";
}

/**
 * @tc.name: GetImagePropertyStringTest017
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest017 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = DATE_TIME;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.dateTime_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest017 end";
}

/**
 * @tc.name: GetImagePropertyStringTest018
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest018 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = GPS_TIME_STAMP;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.gpsTimeStamp_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest018 end";
}

/**
 * @tc.name: GetImagePropertyStringTest019
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest019 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = GPS_DATE_STAMP;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.gpsDateStamp_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest019 end";
}

/**
 * @tc.name: GetImagePropertyStringTest020
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest020 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = IMAGE_DESCRIPTION;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.imageDescription_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest020 end";
}

/**
 * @tc.name: GetImagePropertyStringTest021
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest021, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest021 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = MAKE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.make_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest021 end";
}

/**
 * @tc.name: GetImagePropertyStringTest022
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest022, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest022 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = MODEL;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.model_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest022 end";
}

/**
 * @tc.name: GetImagePropertyStringTest023
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest023 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = PHOTO_MODE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.photoMode_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest023 end";
}

/**
 * @tc.name: GetImagePropertyStringTest024
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest024 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = SENSITIVITY_TYPE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.sensitivityType_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest024 end";
}

/**
 * @tc.name: GetImagePropertyStringTest025
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest025 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = STANDARD_OUTPUT_SENSITIVITY;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.standardOutputSensitivity_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest025 end";
}

/**
 * @tc.name: GetImagePropertyStringTest026
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest026 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = RECOMMENDED_EXPOSURE_INDEX;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.recommendedExposureIndex_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest026 end";
}

/**
 * @tc.name: GetImagePropertyStringTest027
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest027 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = APERTURE_VALUE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.apertureValue_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest027 end";
}

/**
 * @tc.name: GetImagePropertyStringTest028
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest028, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest028 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = EXPOSURE_BIAS_VALUE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.exposureBiasValue_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest028 end";
}

/**
 * @tc.name: GetImagePropertyStringTest029
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest029, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest029 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = METERING_MODE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.meteringMode_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest029 end";
}

/**
 * @tc.name: GetImagePropertyStringTest030
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest030, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest030 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = LIGHT_SOURCE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.lightSource_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest030 end";
}

/**
 * @tc.name: GetImagePropertyStringTest031
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest031, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest031 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = FLASH;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.flash_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest031 end";
}

/**
 * @tc.name: GetImagePropertyStringTest032
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest032, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest032 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = FOCAL_LENGTH;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.focalLength_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest032 end";
}

/**
 * @tc.name: GetImagePropertyStringTest033
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest033, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest033 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = USER_COMMENT;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.userComment_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest033 end";
}

/**
 * @tc.name: GetImagePropertyStringTest034
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest034, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest034 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = PIXEL_X_DIMENSION;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.pixelXDimension_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest034 end";
}

/**
 * @tc.name: GetImagePropertyStringTest035
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest035, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest035 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = PIXEL_Y_DIMENSION;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.pixelYDimension_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest035 end";
}

/**
 * @tc.name: GetImagePropertyStringTest036
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest036, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest036 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = WHITE_BALANCE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.whiteBalance_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest036 end";
}

/**
 * @tc.name: GetImagePropertyStringTest037
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest037, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest037 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = FOCAL_LENGTH_IN_35_MM_FILM;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.focalLengthIn35mmFilm_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest037 end";
}

/**
 * @tc.name: GetImagePropertyStringTest038
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest038, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest038 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = HW_MNOTE_CAPTURE_MODE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.hwMnoteCaptureMode_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest038 end";
}

/**
 * @tc.name: GetImagePropertyStringTest039
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest039, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest039 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = HW_MNOTE_PHYSICAL_APERTURE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.hwMnotePhysicalAperture_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest039 end";
}

/**
 * @tc.name: GetImagePropertyStringTest040
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest040, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest040 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ISO_SPEED;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.isoSpeedRatings_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest040 end";
}

/**
 * @tc.name: SetSourceTest001
 * @tc.desc: Test of SetSource
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetSourceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetSourceTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    bool result = (jpegDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetSourceTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest001
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    // goto : return ret
    uint32_t result = jpegDecoder->SetDecodeOptions(0, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest002
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t result = jpegDecoder->SetDecodeOptions(JPEG_IMAGE_NUM, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest002 end";
}

/**
 * @tc.name: SetDecodeOptionsTest003
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t result = jpegDecoder->SetDecodeOptions(0, opts, info);
    // goto DecoderHeader return ERR_IMAGE_SOURCE_DATA_INCOMPLETE
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest003 end";
}

/**
 * @tc.name: SetDecodeOptionsTest004
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t result = jpegDecoder->SetDecodeOptions(1, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest004 end";
}

/**
 * @tc.name: SetDecodeOptionsTest005
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t result = jpegDecoder->SetDecodeOptions(0, opts, info);
    // goto DecoderHeader return ERR_IMAGE_SOURCE_DATA_INCOMPLETE
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest005 end";
}

/**
 * @tc.name: GetImageSizeTest001
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    // goto DecodeHeader return ERR_IMAGE_SOURCE_DATA_INCOMPLETE
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest001 end";
}

/**
 * @tc.name: GetImageSizeTest002
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::PlSize plSize;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    // goto DecodeHeader return ERR_IMAGE_DECODE_ABNORMAL
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest002 end";
}

/**
 * @tc.name: GetImageSizeTest004
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::PlSize plSize;
    jpegDecoder->SetSource(*streamPtr.release());
    // check input parameter, index = JPEG_IMAGE_NUM
    uint32_t result = jpegDecoder->GetImageSize(JPEG_IMAGE_NUM, plSize);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest004 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    uint32_t result = jpegDecoder->Decode(0, context);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: DecodeTest002
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    uint32_t result = jpegDecoder->Decode(JPEG_IMAGE_NUM, context);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest002 end";
}

/**
 * @tc.name: GetImagePropertyIntTest001
 * @tc.desc: Test of GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyIntTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyIntTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "Orientation";
    int32_t value = 0;
    uint32_t result = jpegDecoder->GetImagePropertyInt(0, key, value);
    ASSERT_EQ(result, Media::ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyIntTest001 end";
}

/**
 * @tc.name: GetImagePropertyIntTest002
 * @tc.desc: Test of GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyIntTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyIntTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "ImageLength";
    int32_t value = 0;
    uint32_t result = jpegDecoder->GetImagePropertyInt(0, key, value);
    ASSERT_EQ(result, Media::ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyIntTest002 end";
}

/**
 * @tc.name: GetImagePropertyIntTest003
 * @tc.desc: Test of GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyIntTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyIntTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ACTUAL_IMAGE_ENCODED_FORMAT;
    int32_t value = 0;
    uint32_t result = jpegDecoder->GetImagePropertyInt(0, key, value);
    ASSERT_EQ(result, Media::ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyIntTest003 end";
}

/**
 * @tc.name: GetImagePropertyStringTest001
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "BitsPerSample";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.bitsPerSample_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest001 end";
}

/**
 * @tc.name: GetImagePropertyStringTest002
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "Orientation";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.orientation_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest002 end";
}

/**
 * @tc.name: GetImagePropertyStringTest003
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "ImageLength";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.imageLength_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest003 end";
}

/**
 * @tc.name: GetImagePropertyStringTest004
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "ImageWidth";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.imageWidth_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest004 end";
}

/**
 * @tc.name: GetImagePropertyStringTest005
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "GPSLatitude";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.gpsLatitude_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest005 end";
}

/**
 * @tc.name: GetImagePropertyStringTest006
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest006 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "GPSLongitude";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.gpsLongitude_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest006 end";
}

/**
 * @tc.name: GetImagePropertyStringTest007
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest007 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "GPSLatitudeRef";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.gpsLatitudeRef_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest007 end";
}


/**
 * @tc.name: GetImagePropertyStringTest008
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest008 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "GPSLongitudeRef";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.gpsLongitudeRef_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest008 end";
}

/**
 * @tc.name: GetImagePropertyStringTest009
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest009 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "DateTimeOriginal";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.dateTimeOriginal_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest009 end";
}

/**
 * @tc.name: GetImagePropertyStringTest010
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest010 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "DateTimeOriginalForMedia";
    std::string value = "";
    EXIFInfo exifInfo_;
    int32_t result = jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest010 end";
}

/**
 * @tc.name: GetImagePropertyStringTest011
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest011 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "ExposureTime";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.exposureTime_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest011 end";
}

/**
 * @tc.name: GetImagePropertyStringTest012
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest012 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "FNumber";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.fNumber_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest012 end";
}

/**
 * @tc.name: GetImagePropertyStringTest013
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest013 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "ISOSpeedRatings";
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.isoSpeedRatings_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest013 end";
}

/**
 * @tc.name: GetImagePropertyStringTest014
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest014 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = SCENE_TYPE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.sceneType_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest014 end";
}

/**
 * @tc.name: GetImagePropertyStringTest015
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringTest015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest015 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "";
    std::string value = "";
    int32_t result = jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(result, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest015 end";
}

/**
 * @tc.name: ModifyImagePropertyTest001
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "";
    std::string path = "";
    std::string value = "";
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, path);
    ASSERT_EQ(result, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest001 end";
}

/**
 * @tc.name: ModifyImagePropertyTest002
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ORIENTATION;
    std::string path = "";
    std::string value = "";
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, path);
    ASSERT_EQ(result, Media::ERR_MEDIA_IO_ABNORMAL);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest002 end";
}

/**
 * @tc.name: ModifyImagePropertyTest003
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = IMAGE_LENGTH;
    std::string path = "";
    std::string value = "";
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, path);
    ASSERT_EQ(result, ERR_MEDIA_IO_ABNORMAL);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest003 end";
}

/**
 * @tc.name: ModifyImagePropertyTest004
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = IMAGE_LENGTH;
    std::string path = "";
    std::string value = "";
    int fd = 0;
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, fd);
    ASSERT_EQ(result, Media::ERR_MEDIA_BUFFER_TOO_SMALL);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest004 end";
}

/**
 * @tc.name: ModifyImagePropertyTest005
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "";
    std::string path = "";
    std::string value = "";
    int fd = 0;
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, fd);
    ASSERT_EQ(result, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest005 end";
}

/**
 * @tc.name: GetImageSizeTest003
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ImagePlugin::PlSize plSize;
    ErrCodeOffset(2, 0);
    jpegDecoder->GetImageSize(1, plSize);
    jpegDecoder->GetImageSize(0, plSize);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest003 end";
}

/**
 * @tc.name: GetRowBytesTest001
 * @tc.desc: Test of GetRowBytes
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetRowBytesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetRowBytesTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    jpegDecoder->GetRowBytes();
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetRowBytesTest001 end";
}

/**
 * @tc.name: ResetTest001
 * @tc.desc: Test of Reset
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ResetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ResetTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    jpegDecoder->JpegDecoder::Reset();
    GTEST_LOG_(INFO) << "JpegDecoderTest: ResetTest001 end";
}

/**
 * @tc.name: FinishOldDecompressTest001
 * @tc.desc: Test of FinishOldDecompress
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FinishOldDecompressTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FinishOldDecompressTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    jpegDecoder->FinishOldDecompress();
    GTEST_LOG_(INFO) << "JpegDecoderTest: FinishOldDecompressTest001 end";
}

/**
 * @tc.name: FormatTimeStampTest001
 * @tc.desc: Test of FormatTimeStamp
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FormatTimeStampTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    std::string value = "";
    std::string src = "2023-10-15 12:34:56";
    jpegDecoder->FormatTimeStamp(value, src);
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest001 end";
}

/**
 * @tc.name: getExifTagFromKeyTest001
 * @tc.desc: Test of getExifTagFromKey
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, getExifTagFromKeyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: getExifTagFromKeyTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    const std::string key1 ="BitsPerSample";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key1);
    const std::string key2 ="Orientation";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key2);
    const std::string key3 ="ImageLength";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key3);
    const std::string key4 ="ImageWidth";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key4);
    const std::string key5 ="GPSLatitude";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key5);
    const std::string key6 ="GPSLongitude";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key6);
    const std::string key7 ="GPSLatitudeRef";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key7);
    const std::string key8 ="GPSLongitudeRef";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key8);
    const std::string key9 ="DateTimeOriginal";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key9);
    const std::string key10 ="ExposureTime";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key10);
    const std::string key11 ="FNumber";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key11);
    const std::string key12 ="ISOSpeedRatings";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key12);
    const std::string key13 ="SceneType";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key13);
    const std::string key14 ="CompressedBitsPerPixel";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key14);
    const std::string key15 ="GPSTimeStamp";
    jpegDecoder->JpegDecoder::getExifTagFromKey(key15);
    GTEST_LOG_(INFO) << "JpegDecoderTest: getExifTagFromKeyTest001 end";
}

/**
 * @tc.name: ModifyImagePropertyTest006
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest006 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    uint32_t index = 1;
    const std::string key = "GPSTimeStamp";
    const std::string value = "111";
    const std::string path = " ";
    int32_t result = jpegDecoder->ModifyImageProperty(index, key, value, path);
    ASSERT_EQ(result, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest006 end";
}

/**
 * @tc.name: GetFilterAreaTest001
 * @tc.desc: Test of GetFilterArea
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetFilterAreaTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetFilterAreaTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = jpegDecoder->GetFilterArea(1, ranges);
    EXPECT_EQ(ret, Media::ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetFilterAreaTest001 end";
}
}
}