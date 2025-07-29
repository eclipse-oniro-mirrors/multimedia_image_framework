/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <gtest/gtest.h>
#include "jpeg_decoder.h"
#include "image_packer.h"
#include "buffer_source_stream.h"
#include "exif_info.h"
#include "mock_data_stream.h"
#include "attr_data.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
static constexpr size_t STREAM_SIZE = 1000;
const std::string BITS_PER_SAMPLE = "BitsPerSample";
const std::string ORIENTATION = "Orientation";
const std::string IMAGE_LENGTH = "ImageLength";
const std::string IMAGE_WIDTH = "ImageWidth";
const std::string GPS_LATITUDE = "GPSLatitude";
const std::string GPS_LONGITUDE = "GPSLongitude";
const std::string GPS_LATITUDE_REF = "GPSLatitudeRef";
const std::string GPS_LONGITUDE_REF = "GPSLongitudeRef";
const std::string DATE_TIME_ORIGINAL = "DateTimeOriginal";
const std::string DATE_TIME_ORIGINAL_MEDIA = "DateTimeOriginalForMedia";
const std::string EXPOSURE_TIME = "ExposureTime";
const std::string F_NUMBER = "FNumber";
const std::string ISO_SPEED_RATINGS = "ISOSpeedRatings";
const std::string SCENE_TYPE = "SceneType";
const std::string USER_COMMENT = "UserComment";
const std::string PIXEL_X_DIMENSION = "PixelXDimension";
const std::string PIXEL_Y_DIMENSION = "PixelYDimension";
const std::string WHITE_BALANCE = "WhiteBalance";
const std::string FOCAL_LENGTH_IN_35_MM_FILM = "FocalLengthIn35mmFilm";
const std::string HW_MNOTE_CAPTURE_MODE = "HwMnoteCaptureMode";
const std::string HW_MNOTE_PHYSICAL_APERTURE = "HwMnotePhysicalAperture";
const std::string DATE_TIME = "DateTime";
constexpr uint8_t JPG_MARKER_PREFIX = 0XFF;
constexpr uint8_t JPG_MARKER_RST = 0XD0;
constexpr uint8_t JPG_MARKER_RST0 = 0XD0;
constexpr uint8_t JPG_MARKER_APP = 0XE0;
constexpr uint8_t JPG_MARKER_APP0 = 0XE0;
static const std::string IMAGE_INPUT_JPG_PATH = "/data/local/tmp/image/800-500.jpg";
static constexpr int32_t IMAGE_INPUT_JPG_WIDTH = 800;
static constexpr int32_t IMAGE_INPUT_JPG_HEIGHT = 500;
static constexpr int32_t NUM_4 = 4;
static constexpr int PERMISSION_GPS_TYPE = 1;
static const std::string IMAGE_INPUT_EXIF_PATH = "/data/local/tmp/image/test_exif.jpg";
class JpegDecoderTest : public testing::Test {
public:
    JpegDecoderTest() {}
    ~JpegDecoderTest() {}
};

/**
 * @tc.name: JpegDecoderTest001
 * @tc.desc: Test of SetSource
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    bool result = (jpegDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest001 end";
}

/**
 * @tc.name: JpegDecoderTest002
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    jpegDecoder->state_ = JpegDecodingState::IMAGE_DECODING;
    uint32_t result = jpegDecoder->SetDecodeOptions(0, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest002 end";
}

/**
 * @tc.name: JpegDecoderTest003
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t result = jpegDecoder->SetDecodeOptions(JPEG_IMAGE_NUM, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest003 end";
}

/**
 * @tc.name: JpegDecoderTest004
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    jpegDecoder->state_ = JpegDecodingState::UNDECIDED;
    uint32_t result = jpegDecoder->SetDecodeOptions(0, opts, info);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest004 end";
}

/**
 * @tc.name: JpegDecoderTest005
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    jpegDecoder->SetSource(*mock.get());
    ImagePlugin::Size plSize;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest005 end";
}

/**
 * @tc.name: JpegDecoderTest006
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest006 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    jpegDecoder->SetSource(*mock.get());
    ImagePlugin::Size plSize;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest006 end";
}

/**
 * @tc.name: JpegDecoderTest007
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest007 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::Size plSize;
    jpegDecoder->SetSource(*streamPtr.release());
    uint32_t result = jpegDecoder->GetImageSize(2, plSize);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest007 end";
}

/**
 * @tc.name: JpegDecoderTest008
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest008 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::Size plSize;
    jpegDecoder->SetSource(*streamPtr.release());
    // check input parameter, index = JPEG_IMAGE_NUM
    uint32_t result = jpegDecoder->GetImageSize(JPEG_IMAGE_NUM, plSize);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest008 end";
}

/**
 * @tc.name: JpegDecoderTest009
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest009 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(true);
    jpegDecoder->SetSource(*mock.get());
    ImagePlugin::Size plSize;
    jpegDecoder->state_ = JpegDecodingState::UNDECIDED;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest009 end";
}

/**
 * @tc.name: JpegDecoderTest0010
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0010 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    ImagePlugin::Size plSize;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0010 end";
}

/**
 * @tc.name: JpegDecoderTest0011
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0011 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    uint32_t result = jpegDecoder->Decode(2, context);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0011 end";
}

/**
 * @tc.name: JpegDecoderTest0012
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0012 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    uint32_t result = jpegDecoder->Decode(JPEG_IMAGE_NUM, context);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0012 end";
}

/**
 * @tc.name: JpegDecoderTest0013
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0013 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    uint32_t result = jpegDecoder->Decode(0, context);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0013 end";
}

/**
 * @tc.name: JpegDecoderTest0014
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0014 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    DecodeContext context;
    jpegDecoder->state_ = JpegDecodingState::IMAGE_ERROR;
    uint32_t ret = jpegDecoder->Decode(0, context);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0014 end";
}

/**
 * @tc.name: JpegDecoderTest0015
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0015 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    ProgDecodeContext context;
    uint32_t result = jpegDecoder->PromoteIncrementalDecode(2, context);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0015 end";
}

/**
 * @tc.name: JpegDecoderTest0016
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0016 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    ProgDecodeContext context;
    uint32_t result = jpegDecoder->PromoteIncrementalDecode(JPEG_IMAGE_NUM, context);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0016 end";
}
/**
 * @tc.name: JpegDecoderTest0017
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0017 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    uint32_t result = jpegDecoder->PromoteIncrementalDecode(0, context);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0017 end";
}

/**
 * @tc.name: JpegDecoderTest0018
 * @tc.desc: Test of GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0018 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ORIENTATION;
    int32_t value = 0;
    uint32_t result = jpegDecoder->GetImagePropertyInt(0, key, value);
    ASSERT_EQ(result, ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0018 end";
}

/**
 * @tc.name: JpegDecoderTest0019
 * @tc.desc: Test of GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0019 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = IMAGE_LENGTH;
    int32_t value = 0;
    uint32_t result = jpegDecoder->GetImagePropertyInt(0, key, value);
    ASSERT_EQ(result, ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0019 end";
}

/**
 * @tc.name: JpegDecoderTest0020
 * @tc.desc: Test of GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0020 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ACTUAL_IMAGE_ENCODED_FORMAT;
    int32_t value = 0;
    uint32_t result = jpegDecoder->GetImagePropertyInt(0, key, value);
    ASSERT_EQ(result, Media::ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0020 end";
}

/**
 * @tc.name: JpegDecoderTest0021
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0021, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0021 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = BITS_PER_SAMPLE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.bitsPerSample_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0021 end";
}

/**
 * @tc.name: JpegDecoderTest0022
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0022, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0022 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ORIENTATION;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.orientation_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0022 end";
}

/**
 * @tc.name: JpegDecoderTest0023
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0023 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = IMAGE_LENGTH;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.imageLength_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0023 end";
}

/**
 * @tc.name: JpegDecoderTest0024
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0024 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = IMAGE_WIDTH;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.imageWidth_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0024 end";
}

/**
 * @tc.name: JpegDecoderTest0025
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0025 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = GPS_LATITUDE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.gpsLatitude_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0025 end";
}

/**
 * @tc.name: JpegDecoderTest0026
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0026 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = GPS_LONGITUDE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.gpsLongitude_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0026 end";
}

/**
 * @tc.name: JpegDecoderTest0027
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0027 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = GPS_LATITUDE_REF;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.gpsLatitudeRef_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0027 end";
}


/**
 * @tc.name: JpegDecoderTest0028
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0028, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0028 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = GPS_LONGITUDE_REF;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.gpsLongitudeRef_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0028 end";
}

/**
 * @tc.name: JpegDecoderTest0029
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0029, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0029 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = DATE_TIME_ORIGINAL;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.dateTimeOriginal_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0029 end";
}

/**
 * @tc.name: JpegDecoderTest0030
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0030, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0030 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = DATE_TIME_ORIGINAL_MEDIA;
    std::string value = "";
    uint32_t ret = jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(ret, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0030 end";
}

/**
 * @tc.name: JpegDecoderTest0031
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0031, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0031 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = EXPOSURE_TIME;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.exposureTime_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0031 end";
}

/**
 * @tc.name: JpegDecoderTest0032
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0032, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0032 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = F_NUMBER;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.fNumber_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0032 end";
}

/**
 * @tc.name: JpegDecoderTest0033
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0033, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0033 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ISO_SPEED_RATINGS;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.isoSpeedRatings_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0033 end";
}

/**
 * @tc.name: JpegDecoderTest0034
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0034, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0034 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0034 end";
}

/**
 * @tc.name: JpegDecoderTest0035
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0035, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0035 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "";
    std::string value = "";
    int32_t result = jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(result, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0035 end";
}

/**
 * @tc.name: JpegDecoderTest0036
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0036, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0036 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ACTUAL_IMAGE_ENCODED_FORMAT;
    std::string value = "";
    int32_t result = jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(result, Media::ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0036 end";
}


/**
 * @tc.name: JpegDecoderTest0037
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0037, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0037 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "";
    std::string value = "";
    int32_t result = jpegDecoder->GetImagePropertyStringEx(key, value);
    ASSERT_EQ(result, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0037 end";
}

/**
 * @tc.name: JpegDecoderTest0038
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0038, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0038 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = USER_COMMENT;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(key, value);
    ASSERT_EQ(value, exifInfo_.userComment_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0038 end";
}

/**
 * @tc.name: JpegDecoderTest0039
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0039, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0039 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = PIXEL_X_DIMENSION;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(key, value);
    ASSERT_EQ(value, exifInfo_.pixelXDimension_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0039 end";
}

/**
 * @tc.name: JpegDecoderTest0040
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0040, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0040 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = PIXEL_Y_DIMENSION;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(key, value);
    ASSERT_EQ(value, exifInfo_.pixelYDimension_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0040 end";
}

/**
 * @tc.name: JpegDecoderTest0041
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0041, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0041 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = WHITE_BALANCE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(key, value);
    ASSERT_EQ(value, exifInfo_.whiteBalance_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0041 end";
}

/**
 * @tc.name: JpegDecoderTest0042
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0042, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0042 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = FOCAL_LENGTH_IN_35_MM_FILM;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(key, value);
    ASSERT_EQ(value, exifInfo_.focalLengthIn35mmFilm_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0042 end";
}

/**
 * @tc.name: JpegDecoderTest0043
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0043, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0043 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = HW_MNOTE_CAPTURE_MODE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(key, value);
    ASSERT_EQ(value, exifInfo_.hwMnoteCaptureMode_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0043 end";
}

/**
 * @tc.name: JpegDecoderTest0044
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0044, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0044 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = HW_MNOTE_PHYSICAL_APERTURE;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(key, value);
    ASSERT_EQ(value, exifInfo_.hwMnotePhysicalAperture_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0044 end";
}

/**
 * @tc.name: JpegDecoderTest0045
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0045, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0045 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0045 end";
}

/**
 * @tc.name: JpegDecoderTest0046
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0046, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0046 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ORIENTATION;
    std::string path = "";
    std::string value = "";
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, path);
    ASSERT_EQ(result, ERR_MEDIA_IO_ABNORMAL);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0046 end";
}

/**
 * @tc.name: JpegDecoderTest0047
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0047, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0047 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0047 end";
}

/**
 * @tc.name: JpegDecoderTest0048
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0048, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0048 start";
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
    ASSERT_EQ(result, ERR_MEDIA_BUFFER_TOO_SMALL);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0048 end";
}

/**
 * @tc.name: JpegDecoderTest0049
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0049, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0049 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0049 end";
}

/**
 * @tc.name: JpegDecoderTest0050
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0050, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0050 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    uint32_t index = 0;
    std::string key = DATE_TIME;
    uint8_t *data1 = nullptr;
    std::string value = "";
    uint32_t usize = 0;
    int32_t result = jpegDecoder->ModifyImageProperty(index, key, value, data1, usize);
    ASSERT_EQ(result, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0050 end";
}

/**
 * @tc.name: JpegDecoderTest0051
 * @tc.desc: Test of IsMarker
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0051, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0051 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    uint8_t rawMarkerPrefix = JPG_MARKER_PREFIX;
    uint8_t rawMarkderCode = JPG_MARKER_RST0;
    uint8_t markerCode = JPG_MARKER_RST;
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    ranges.push_back(std::make_pair(0, 0));
    int32_t result = jpegDecoder->IsMarker(rawMarkerPrefix, rawMarkderCode, markerCode);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0051 end";
}

/**
 * @tc.name: JpegDecoderTest0052
 * @tc.desc: Test of IsMarker
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0052, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0052 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    uint8_t rawMarkerPrefix = JPG_MARKER_PREFIX;
    uint8_t rawMarkderCode = JPG_MARKER_APP0;
    uint8_t markerCode = JPG_MARKER_APP;
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    ranges.push_back(std::make_pair(0, 0));
    int32_t result = jpegDecoder->IsMarker(rawMarkerPrefix, rawMarkderCode, markerCode);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0052 end";
}

/**
 * @tc.name: JpegDecoderTest0053
 * @tc.desc: Test of GetDecodeFormat
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0053, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0053 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    PixelFormat outputFormat;
    jpegDecoder->GetDecodeFormat(PixelFormat::UNKNOWN, outputFormat);
    ASSERT_EQ(outputFormat, PixelFormat::RGBA_8888);
    jpegDecoder->GetDecodeFormat(PixelFormat::RGBA_8888, outputFormat);
    ASSERT_EQ(outputFormat, PixelFormat::RGBA_8888);
    jpegDecoder->GetDecodeFormat(PixelFormat::BGRA_8888, outputFormat);
    ASSERT_EQ(outputFormat, PixelFormat::BGRA_8888);
    jpegDecoder->GetDecodeFormat(PixelFormat::ARGB_8888, outputFormat);
    jpegDecoder->GetDecodeFormat(PixelFormat::ALPHA_8, outputFormat);
    jpegDecoder->GetDecodeFormat(PixelFormat::RGB_565, outputFormat);
    ASSERT_EQ(outputFormat, PixelFormat::RGB_888);
    jpegDecoder->GetDecodeFormat(PixelFormat::RGB_888, outputFormat);
    jpegDecoder->GetDecodeFormat(PixelFormat::ASTC_8x8, outputFormat);
    ASSERT_EQ(outputFormat, PixelFormat::RGBA_8888);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0053 end";
}

/**
 * @tc.name: JpegDecoderTest0054
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0054, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0054 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    uint32_t index = 0;
    Size size;
    jpegDecoder->state_ = JpegDecodingState::IMAGE_DECODED;
    uint32_t ret = jpegDecoder->GetImageSize(index, size);
    ASSERT_EQ(ret, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0054 end";
}

/**
 * @tc.name: JpegDecoderTest0055
 * @tc.desc: Test of IsMarker
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0055, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0055 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    uint8_t rawMarkerPrefix = JPG_MARKER_RST;
    uint8_t rawMarkderCode = JPG_MARKER_RST;
    uint8_t markerCode = 0;
    bool ret = jpegDecoder->IsMarker(rawMarkerPrefix, rawMarkderCode, markerCode);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0055 end";
}

/**
 * @tc.name: JpegDecoderTest0056
 * @tc.desc: Test of GetMakerImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0056, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0056 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    std::string key = "test";
    std::string value = "test";
    EXIFInfo ei;
    jpegDecoder->exifInfo_ = ei;
    jpegDecoder->exifInfo_.makerInfoTagValueMap.insert(std::make_pair(key, value));
    uint32_t ret = jpegDecoder->GetMakerImagePropertyString(key, value);
    ASSERT_EQ(ret, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0056 end";
}

/**
 * @tc.name: JpegDecoderTest0057
 * @tc.desc: Test of GetImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0057, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0057 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ISO_SPEED_RATINGS;
    std::string value = "";
    EXIFInfo ei;
    jpegDecoder->exifInfo_ = ei;
    jpegDecoder->exifInfo_.isoSpeedRatings_ = "ISOSpeedRatings";
    jpegDecoder->GetImagePropertyString(key, value);
    ASSERT_EQ(value, jpegDecoder->exifInfo_.isoSpeedRatings_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0057 end";
}

/**
 * @tc.name: JpegDecoderTest0058
 * @tc.desc: Test of GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, JpegDecoderTest0058, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0058 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = ORIENTATION;
    int32_t value = 0;
    uint32_t index = 0;
    EXIFInfo ei;
    jpegDecoder->exifInfo_ = ei;
    jpegDecoder->exifInfo_.isExifDataParsed_ = true;
    jpegDecoder->exifInfo_.orientation_ = "Right-top";
    uint32_t ret = jpegDecoder->GetImagePropertyInt(index, key, value);
    ASSERT_EQ(value, 90);
    ASSERT_EQ(ret, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0058 end";
}

/**
 * @tc.name: JpegDecoderTest_SetDecodeOptionsTest001
 * @tc.desc: Verify that JpegDecoder decodes image when desired size is smaller than the actual size.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest006 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    uint32_t errorCode = -1;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);
    jpegDecoder->SetSource(*(imageSource->sourceStreamPtr_.get()));

    PixelDecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::ARGB_8888;
    decodeOpts.editable = true;
    decodeOpts.desiredSize.width = IMAGE_INPUT_JPG_WIDTH / NUM_4;
    decodeOpts.desiredSize.height = IMAGE_INPUT_JPG_HEIGHT / NUM_4;

    PlImageInfo plInfo;
    errorCode = jpegDecoder->SetDecodeOptions(0, decodeOpts, plInfo);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest006 end";
}

/**
 * @tc.name: JpegDecoderTest_DecodeTest003
 * @tc.desc: Verify that JpegDecoder decodes image and using DMA_ALLOC allocator type.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    uint32_t errorCode = -1;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);
    jpegDecoder->SetSource(*(imageSource->sourceStreamPtr_.get()));

    PixelDecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    decodeOpts.editable = true;
    decodeOpts.desiredSize.width = IMAGE_INPUT_JPG_WIDTH;
    decodeOpts.desiredSize.height = IMAGE_INPUT_JPG_HEIGHT;
    PlImageInfo plInfo;

    errorCode = jpegDecoder->SetDecodeOptions(0, decodeOpts, plInfo);
    ASSERT_EQ(errorCode, SUCCESS);

    DecodeContext decodeContext;
    decodeContext.allocatorType = AllocatorType::DMA_ALLOC;
    errorCode = jpegDecoder->Decode(0, decodeContext);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest003 end";
}

/**
 * @tc.name: JpegDecoderTest_DecodeTest004
 * @tc.desc: Verify that JpegDecoder decodes image double.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    uint32_t errorCode = -1;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);
    jpegDecoder->SetSource(*(imageSource->sourceStreamPtr_.get()));

    PixelDecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    decodeOpts.editable = true;
    decodeOpts.desiredSize.width = IMAGE_INPUT_JPG_WIDTH;
    decodeOpts.desiredSize.height = IMAGE_INPUT_JPG_HEIGHT;

    PlImageInfo plInfo;
    errorCode = jpegDecoder->SetDecodeOptions(0, decodeOpts, plInfo);
    ASSERT_EQ(errorCode, SUCCESS);

    DecodeContext decodeContext;
    decodeContext.allocatorType = AllocatorType::HEAP_ALLOC;
    errorCode = jpegDecoder->Decode(0, decodeContext);
    ASSERT_EQ(errorCode, SUCCESS);

    DecodeContext decodeContext_double;
    errorCode = jpegDecoder->Decode(0, decodeContext_double);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest004 end";
}

/**
 * @tc.name: JpegDecoderTest_DecodeTest005
 * @tc.desc: Verify that JpegDecoder decodes image double.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    uint32_t errorCode = -1;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);
    jpegDecoder->SetSource(*(imageSource->sourceStreamPtr_.get()));

    PixelDecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    decodeOpts.editable = true;
    decodeOpts.desiredSize.width = IMAGE_INPUT_JPG_WIDTH;
    decodeOpts.desiredSize.height = IMAGE_INPUT_JPG_HEIGHT;

    PlImageInfo plInfo;
    errorCode = jpegDecoder->SetDecodeOptions(0, decodeOpts, plInfo);
    ASSERT_EQ(errorCode, SUCCESS);

    DecodeContext decodeContext;
    decodeContext.allocatorType = AllocatorType::HEAP_ALLOC;
    std::map<std::string, MultimediaPlugin::AttrData> capabilites;
    capabilites.insert(std::map<std::string, MultimediaPlugin::AttrData>::value_type("encodeFormat",
        MultimediaPlugin::AttrData(sourceOpts.formatHint)));
    jpegDecoder->hwJpegDecompress_ = JpegDecoder::pluginServer_.CreateObject<AbsImageDecompressComponent>(
        AbsImageDecompressComponent::SERVICE_DEFAULT, capabilites);
    errorCode = jpegDecoder->Decode(0, decodeContext);
    ASSERT_EQ(errorCode, SUCCESS);

    DecodeContext decodeContext_double;
    errorCode = jpegDecoder->Decode(0, decodeContext_double);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest005 end";
}

/**
 * @tc.name: JpegDecoderTest_StartDecompressTest001
 * @tc.desc: Verify that JpegDecoder call StartDecompress jpeg_color_space == JCS_CMYK and
 *           desiredPixelFormat == PixelFormat::ALPHA_8.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, StartDecompressTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: StartDecompressTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    uint32_t errorCode = -1;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);
    jpegDecoder->SetSource(*(imageSource->sourceStreamPtr_.get()));

    PixelDecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = PixelFormat::ALPHA_8;
    decodeOpts.editable = true;
    decodeOpts.desiredSize.width = IMAGE_INPUT_JPG_WIDTH;
    decodeOpts.desiredSize.height = IMAGE_INPUT_JPG_HEIGHT;

    jpegDecoder->CreateDecoder();
    jpegDecoder->decodeInfo_.jpeg_color_space = JCS_CMYK;
    errorCode = jpegDecoder->StartDecompress(decodeOpts);
    ASSERT_EQ(errorCode, ERR_IMAGE_UNKNOWN_FORMAT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: StartDecompressTest001 end";
}

/**
 * @tc.name: JpegDecoderTest_FormatTimeStampTest002
 * @tc.desc: Verify that JpegDecoder call FormatTimeStamp when input is all numbers.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FormatTimeStampTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    std::string src{"123456789"}, des;
    jpegDecoder->FormatTimeStamp(des, src);
    src += "-01-01 00:00:00";
    ASSERT_EQ(des, src);
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest002 end";
}

/**
 * @tc.name: JpegDecoderTest_FormatTimeStampTest003
 * @tc.desc: Verify that JpegDecoder call FormatTimeStamp when input is 123456789-.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FormatTimeStampTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    std::string src{"123456789-"}, des;
    jpegDecoder->FormatTimeStamp(des, src);
    src = "123456789--01 00:00:00";
    ASSERT_EQ(des, src);
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest003 end";
}

/**
 * @tc.name: JpegDecoderTest_FormatTimeStampTest004
 * @tc.desc: Verify that JpegDecoder call FormatTimeStamp when input is 12345 6789.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FormatTimeStampTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    std::string src{"12345 6789"}, des;
    jpegDecoder->FormatTimeStamp(des, src);
    src = "12345-01-01 6789:00:00";
    ASSERT_EQ(des, src);
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest004 end";
}

/**
 * @tc.name: JpegDecoderTest_FormatTimeStampTest005
 * @tc.desc: Verify that JpegDecoder call FormatTimeStamp when input is 123-45 6789:.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FormatTimeStampTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    std::string src{"123-45 6789:"}, des;
    jpegDecoder->FormatTimeStamp(des, src);
    src = "123-45-01 6789::00";
    ASSERT_EQ(des, src);
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest005 end";
}

/**
 * @tc.name: JpegDecoderTest_GetFilterAreaTest002
 * @tc.desc: Verify that JpegDecoder call GetFileterArea.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetFilterAreaTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetFilterAreaTest002 start";
    uint32_t errorCode = -1;
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_PATH, sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);
    jpegDecoder->SetSource(*(imageSource->sourceStreamPtr_.get()));

    int privacyType = PERMISSION_GPS_TYPE;
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    errorCode = jpegDecoder->GetFilterArea(privacyType, ranges);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetFilterAreaTest002 end";
}

/**
 * @tc.name: JpegDecoderTest_ModifyImagePropertyTest007
 * @tc.desc: Verify that JpegDecoder call ModifyImageProperty.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest007 start";
    uint32_t errorCode = -1;
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_PATH, sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);
    jpegDecoder->SetSource(*(imageSource->sourceStreamPtr_.get()));

    std::string key{SCENE_TYPE}, value{"t"};
    errorCode = jpegDecoder->ModifyImageProperty(0, key, value,
        imageSource->sourceStreamPtr_->GetDataPtr(), imageSource->sourceStreamPtr_->GetStreamSize());
    ASSERT_EQ(errorCode, SUCCESS);

    errorCode = jpegDecoder->exifInfo_.ModifyExifData(key, value,
        imageSource->sourceStreamPtr_->GetDataPtr(), imageSource->sourceStreamPtr_->GetStreamSize());
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest007 end";
}

/**
 * @tc.name: JpegDecoderTest_ModifyImagePropertyTest008
 * @tc.desc: Verify that JpegDecoder call ModifyImageProperty.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest008 start";
    uint32_t errorCode = -1;
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);

    std::string key{SCENE_TYPE}, value{"t"};
    uint8_t* data = nullptr;
    uint32_t size = 0;

    errorCode = jpegDecoder->ModifyImageProperty(0, key, value, data, size);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest008 end";
}

/**
 * @tc.name: JpegDecoderTest_ModifyImagePropertyTest009
 * @tc.desc: Verify that JpegDecoder call ModifyImageProperty.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest009 start";
    uint32_t errorCode = -1;
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);

    std::string key{SCENE_TYPE}, value{"t"};
    errorCode = jpegDecoder->ModifyImageProperty(0, key, value, IMAGE_INPUT_EXIF_PATH);
    ASSERT_EQ(errorCode, SUCCESS);

    errorCode = jpegDecoder->exifInfo_.ModifyExifData(key, value, IMAGE_INPUT_EXIF_PATH);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest009 end";
}

/**
 * @tc.name: JpegDecoderTest_ModifyImagePropertyTest010
 * @tc.desc: Verify that JpegDecoder call ModifyImageProperty.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest010 start";
    uint32_t errorCode = -1;
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);

    std::string key{SCENE_TYPE}, value{"t"};
    int fd = open(IMAGE_INPUT_EXIF_PATH.c_str(), O_RDWR, S_IRUSR | S_IWUSR);
    bool exifOpenFailed = (fd < 0);
    ASSERT_EQ(exifOpenFailed, false);

    errorCode = jpegDecoder->ModifyImageProperty(0, key, value, fd);
    ASSERT_EQ(errorCode, SUCCESS);

    errorCode = jpegDecoder->exifInfo_.ModifyExifData(key, value, fd);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest010 end";
}

/**
 * @tc.name: JpegDecoderTest_ModifyImagePropertyTest011
 * @tc.desc: Verify that JpegDecoder call ModifyImageProperty that modify latitude property.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest011 start";
    uint32_t errorCode = -1;
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);

    std::string key{GPS_LATITUDE}, value{"38,51,6"};
    errorCode = jpegDecoder->ModifyImageProperty(0, key, value, IMAGE_INPUT_EXIF_PATH);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest011 end";
}

/**
 * @tc.name: JpegDecoderTest_GetExifDataTest001
 * @tc.desc: Verify that JpegDecoder's exifInfo_ call GetExifData to get DATE_TIME_ORIGINAL_MEDIA.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetExifDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetExifDataTest001 start";
    uint32_t errorCode = -1;
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);

    errorCode = jpegDecoder->ModifyImageProperty(0, "DateTimeOriginal", "1234-5-6 12:00:00", IMAGE_INPUT_EXIF_PATH);
    std::string key{"DateTimeOriginalForMedia"}, value;
    errorCode = jpegDecoder->exifInfo_.GetExifData(key, value);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetExifDataTest001 end";
}

/**
 * @tc.name: JpegDecoderTest_GetExifDataTest002
 * @tc.desc: Verify that JpegDecoder's exifInfo_ call GetExifData to get TAG_ORIENTATION_INT.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetExifDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetExifDataTest002 start";
    uint32_t errorCode = -1;
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ASSERT_NE(jpegDecoder, nullptr);

    errorCode = jpegDecoder->ModifyImageProperty(0, "Orientation", "Right-top", IMAGE_INPUT_EXIF_PATH);
    std::string key{"OrientationInt"}, value;
    errorCode = jpegDecoder->exifInfo_.GetExifData(key, value);
    ASSERT_EQ(errorCode, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetExifDataTest002 end";
}

/**
 * @tc.name: CheckInputDataValidTest001
 * @tc.desc: Verify JPEG header validation logic. Test cases: null buffer, size=0, invalid magic bytes,
 *           valid magic bytes.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, CheckInputDataValidTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: CheckInputDataValidTest001 start";
    EXIFInfo exifInfo;
    uint32_t result = exifInfo.CheckInputDataValid(nullptr, 10);
    EXPECT_EQ(result, Media::ERR_IMAGE_SOURCE_DATA);
    unsigned char dummy[2] = {0xFF, 0xD8};
    result = exifInfo.CheckInputDataValid(dummy, 0);
    EXPECT_EQ(result, Media::ERR_MEDIA_BUFFER_TOO_SMALL);
    unsigned char notFFButD8[2] = {0x00, 0xD8};
    result = exifInfo.CheckInputDataValid(notFFButD8, 2);
    EXPECT_EQ(result, Media::ERR_IMAGE_MISMATCHED_FORMAT);
    unsigned char ffButNotD8[2] = {0xFF, 0x00};
    result = exifInfo.CheckInputDataValid(ffButNotD8, 2);
    EXPECT_EQ(result, Media::ERR_IMAGE_MISMATCHED_FORMAT);
    unsigned char notFFAndNotD8[2] = {0x00, 0x00};
    result = exifInfo.CheckInputDataValid(notFFAndNotD8, 2);
    EXPECT_EQ(result, Media::ERR_IMAGE_MISMATCHED_FORMAT);
    unsigned char validJpeg[2] = {0xFF, 0xD8};
    result = exifInfo.CheckInputDataValid(validJpeg, 2);
    EXPECT_EQ(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: CheckInputDataValidTest001 end";
}

/**
 * @tc.name: CreateExifDataTest001
 * @tc.desc: Verify EXIF data creation logic. Test cases: null input, buffer with "Exif" tag, buffer without "Exif" tag
 *           (auto-create new EXIF data).
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, CreateExifDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: CreateExifDataTest001 start";
    EXIFInfo exifInfo;
    ExifData* ptrData = nullptr;
    bool isNewExifData = false;
    bool ret = exifInfo.CreateExifData(nullptr, 10, &ptrData, isNewExifData);
    EXPECT_FALSE(ret);
    unsigned char bufExif[16] = {0};
    bufExif[6] = 'E'; bufExif[7] = 'x'; bufExif[8] = 'i'; bufExif[9] = 'f';
    ret = exifInfo.CreateExifData(bufExif, 16, &ptrData, isNewExifData);
    EXPECT_TRUE(ret);
    ptrData = nullptr;
    ret = exifInfo.CreateExifData(bufExif, 16, &ptrData, isNewExifData);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(isNewExifData);
    unsigned char bufNoExif[16] = {0};
    ptrData = nullptr;
    ret = exifInfo.CreateExifData(bufNoExif, 16, &ptrData, isNewExifData);
    EXPECT_TRUE(ret);
    ptrData = nullptr;
    ret = exifInfo.CreateExifData(bufNoExif, 16, &ptrData, isNewExifData);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(isNewExifData);
    GTEST_LOG_(INFO) << "JpegDecoderTest: CreateExifDataTest001 end";
}
}
}