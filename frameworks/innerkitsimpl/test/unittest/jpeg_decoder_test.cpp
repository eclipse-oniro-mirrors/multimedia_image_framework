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
#include <gtest/gtest.h>
#include "jpeg_decoder.h"
#include "image_packer.h"
#include "buffer_source_stream.h"
#include "exif_info.h"
#include "mock_data_stream.h"

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
    ImagePlugin::PlSize plSize;
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
    ImagePlugin::PlSize plSize;
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
    ImagePlugin::PlSize plSize;
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
    ImagePlugin::PlSize plSize;
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
    ImagePlugin::PlSize plSize;
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
    ImagePlugin::PlSize plSize;
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
    PlPixelFormat outputFormat;
    jpegDecoder->GetDecodeFormat(PlPixelFormat::UNKNOWN, outputFormat);
    ASSERT_EQ(outputFormat, PlPixelFormat::RGBA_8888);
    jpegDecoder->GetDecodeFormat(PlPixelFormat::RGBA_8888, outputFormat);
    ASSERT_EQ(outputFormat, PlPixelFormat::RGBA_8888);
    jpegDecoder->GetDecodeFormat(PlPixelFormat::BGRA_8888, outputFormat);
    ASSERT_EQ(outputFormat, PlPixelFormat::BGRA_8888);
    jpegDecoder->GetDecodeFormat(PlPixelFormat::ARGB_8888, outputFormat);
    jpegDecoder->GetDecodeFormat(PlPixelFormat::ALPHA_8, outputFormat);
    jpegDecoder->GetDecodeFormat(PlPixelFormat::RGB_565, outputFormat);
    ASSERT_EQ(outputFormat, PlPixelFormat::RGB_888);
    jpegDecoder->GetDecodeFormat(PlPixelFormat::RGB_888, outputFormat);
    jpegDecoder->GetDecodeFormat(PlPixelFormat::ASTC_8X8, outputFormat);
    ASSERT_EQ(outputFormat, PlPixelFormat::RGBA_8888);
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
    PlSize size;
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
}
}