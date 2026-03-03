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
static constexpr int32_t SETJMP_ERR_RETURN = 1;
static constexpr int32_t WIDTH_SMALL = 1;
static constexpr int32_t HEIGHT_SMALL = 2;
static constexpr int JPEG_TEST_MIN_STREAM_SIZE = 1;
static constexpr int JPEG_TEST_INVALID_EXIF_CODE = -1;
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
    int size = 1;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ASSERT_NE(streamPtr, nullptr);
    jpegDecoder->SetSource(*streamPtr.release());
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
    int size = 1;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ASSERT_NE(streamPtr, nullptr);
    jpegDecoder->SetSource(*streamPtr.release());
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
    int size = 1;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ASSERT_NE(streamPtr, nullptr);
    jpegDecoder->SetSource(*streamPtr.release());
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
    int size = 1;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ASSERT_NE(streamPtr, nullptr);
    jpegDecoder->SetSource(*streamPtr.release());
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
    int size = 1;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ASSERT_NE(streamPtr, nullptr);
    jpegDecoder->SetSource(*streamPtr.release());
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
    int size = 1;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ASSERT_NE(streamPtr, nullptr);
    jpegDecoder->SetSource(*streamPtr.release());
    ProgDecodeContext context;
    uint32_t result = jpegDecoder->PromoteIncrementalDecode(0, context);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: JpegDecoderTest0017 end";
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
 * @tc.name: SetDecodeOptionsTest005
 * @tc.desc: Test SetDecodeOptions when image width or height is 0.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());

    jpegDecoder->state_ = JpegDecodingState::BASE_INFO_PARSED;
    jpegDecoder->decodeInfo_.image_width = 0;
    jpegDecoder->decodeInfo_.image_height = IMAGE_INPUT_JPG_HEIGHT;
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t ret = jpegDecoder->SetDecodeOptions(0, opts, info);
    ASSERT_EQ(ret, Media::ERR_IMAGE_INVALID_PARAMETER);

    jpegDecoder->decodeInfo_.image_width = IMAGE_INPUT_JPG_WIDTH;
    jpegDecoder->decodeInfo_.image_height = 0;
    ret = jpegDecoder->SetDecodeOptions(0, opts, info);
    ASSERT_EQ(ret, Media::ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest005 end";
}

/**
 * @tc.name: SetDecodeOptionsTest007
 * @tc.desc: Test SetDecodeOptions when StartDecompress return ERR_IMAGE_UNKNOWN_FORMAT.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetDecodeOptionsTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest007 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());

    jpegDecoder->state_ = JpegDecodingState::BASE_INFO_PARSED;
    jpegDecoder->decodeInfo_.image_width = IMAGE_INPUT_JPG_WIDTH;
    jpegDecoder->decodeInfo_.image_height = IMAGE_INPUT_JPG_HEIGHT;
    jpegDecoder->decodeInfo_.jpeg_color_space = JCS_CMYK;
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PixelFormat::ALPHA_8;
    PlImageInfo info;
    uint32_t ret = jpegDecoder->SetDecodeOptions(0, opts, info);
    ASSERT_EQ(ret, Media::ERR_IMAGE_UNKNOWN_FORMAT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest007 end";
}

/**
 * @tc.name: DoSwDecodeTest001
 * @tc.desc: Test DoSwDecode expect return ERR_IMAGE_DECODE_ABNORMAL when CheckMulOverflow returns true.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DoSwDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DoSwDecodeTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());

    jpegDecoder->decodeInfo_.out_color_space = JCS_EXT_ABGR;
    jpegDecoder->decodeInfo_.out_color_components = UINT32_MAX;
    jpegDecoder->decodeInfo_.output_width = WIDTH_SMALL;
    jpegDecoder->decodeInfo_.output_height = HEIGHT_SMALL;
    DecodeContext context;
    uint32_t ret = jpegDecoder->DoSwDecode(context);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DoSwDecodeTest001 end";
}

/**
 * @tc.name: DoSwDecodeTest002
 * @tc.desc: Test DoSwDecode when context.pixelsBuffer.buffer is not nullptr and decodeInfo_.src is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DoSwDecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DoSwDecodeTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());

    DecodeContext context;
    auto pixelBufHolder = std::unique_ptr<uint8_t, decltype(&free)>(static_cast<uint8_t*>(malloc(NUM_4)), &free);
    ASSERT_NE(pixelBufHolder.get(), nullptr);
    context.pixelsBuffer.buffer = pixelBufHolder.get();
    jpegDecoder->decodeInfo_.src = nullptr;
    uint32_t ret = jpegDecoder->DoSwDecode(context);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DoSwDecodeTest002 end";
}

/**
 * @tc.name: DecodeTest006
 * @tc.desc: Test Decode when state_ is IMAGE_DECODING hwJpegDecompress_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest006 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";

    uint32_t index = 0;
    DecodeContext context;
    jpegDecoder->state_ = JpegDecodingState::IMAGE_DECODING;
    std::map<std::string, MultimediaPlugin::AttrData> capabilites;
    capabilites.insert(std::map<std::string, MultimediaPlugin::AttrData>::value_type("encodeFormat",
        MultimediaPlugin::AttrData(sourceOpts.formatHint)));
    jpegDecoder->hwJpegDecompress_ = JpegDecoder::pluginServer_.CreateObject<AbsImageDecompressComponent>(
        AbsImageDecompressComponent::SERVICE_DEFAULT, capabilites);
    uint32_t ret = jpegDecoder->Decode(index, context);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest006 end";
}

/**
 * @tc.name: FindMarkerTest001
 * @tc.desc: Test FindMarker when readSize is not equal MARKER_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FindMarkerTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FindMarkerTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = JPEG_TEST_MIN_STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());

    uint8_t marker = 0;
    bool ret = jpegDecoder->FindMarker(*jpegDecoder->srcMgr_.inputStream, marker);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "JpegDecoderTest: FindMarkerTest001 end";
}

/**
 * @tc.name: DecodeHeaderTest001
 * @tc.desc: Test DecodeHeader when setjmp not returns zero.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeHeaderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeHeaderTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());

    jpegDecoder->jerr_.error_exit = [](j_common_ptr cinfo) {
        JpegDecoder* decoder = reinterpret_cast<JpegDecoder*>(cinfo->client_data);
        longjmp(decoder->jerr_.setjmp_buffer, SETJMP_ERR_RETURN);
    };
    jpegDecoder->decodeInfo_.client_data = jpegDecoder.get();
    uint32_t ret = jpegDecoder->DecodeHeader();
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeHeaderTest001 end";
}

/**
 * @tc.name: DecodeHeaderTest002
 * @tc.desc: Test DecodeHeader expect return ERR_IMAGE_SOURCE_DATA_INCOMPLETE when the input stream is too short.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeHeaderTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeHeaderTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = JPEG_TEST_MIN_STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());

    uint32_t ret = jpegDecoder->DecodeHeader();
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeHeaderTest002 end";
}

/**
 * @tc.name: StartDecompressTest002
 * @tc.desc: Test StartDecompress when setjmp not returns zero.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, StartDecompressTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: StartDecompressTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());

    jpegDecoder->jerr_.error_exit = [](j_common_ptr cinfo) {
        JpegDecoder* decoder = reinterpret_cast<JpegDecoder*>(cinfo->client_data);
        longjmp(decoder->jerr_.setjmp_buffer, SETJMP_ERR_RETURN);
    };
    jpegDecoder->decodeInfo_.client_data = jpegDecoder.get();
    PixelDecodeOptions opts;
    uint32_t ret = jpegDecoder->StartDecompress(opts);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "JpegDecoderTest: StartDecompressTest002 end";
}

/**
 * @tc.name: StartDecompressTest003
 * @tc.desc: Test StartDecompress when the JPEG color space is CMYK and the desired pixel format is NV21.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, StartDecompressTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: StartDecompressTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    uint32_t errorCode = JPEG_TEST_INVALID_EXIF_CODE;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);
    jpegDecoder->SetSource(*(imageSource->sourceStreamPtr_.get()));

    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PixelFormat::NV21;
    opts.editable = true;
    opts.desiredSize.width = IMAGE_INPUT_JPG_WIDTH;
    opts.desiredSize.height = IMAGE_INPUT_JPG_HEIGHT;
    jpegDecoder->CreateDecoder();

    jpegDecoder->decodeInfo_.jpeg_color_space = JCS_CMYK;
    uint32_t ret = jpegDecoder->StartDecompress(opts);
    ASSERT_NE(ret, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: StartDecompressTest003 end";
}

/**
 * @tc.name: FormatTimeStampTest006
 * @tc.desc: Test FormatTimeStamp when input src is empty.
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FormatTimeStampTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest006 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());

    std::string value = "123456789";
    std::string src = "";
    jpegDecoder->FormatTimeStamp(value, src);
    ASSERT_EQ(value, "");
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest006 end";
}
}
}