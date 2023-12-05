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
#include <gtest/gtest.h>
#include "jpeg_decoder.h"
#include "image_packer.h"
#include "buffer_source_stream.h"
#include "exif_info.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
static constexpr size_t STREAM_SIZE_ONE = 1;
static constexpr size_t STREAM_SIZE_TWO = 2;
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
class JpegDecoderTest : public testing::Test {
public:
    JpegDecoderTest() {}
    ~JpegDecoderTest() {}
};

class MockInputDataStream : public SourceStream {
public:
    MockInputDataStream() = default;

    uint32_t UpdateData(const uint8_t *data, uint32_t size, bool isCompleted) override
    {
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    bool Read(uint32_t desiredSize, DataStreamBuffer &outData) override
    {
        if (streamSize == STREAM_SIZE_ONE) {
            streamBuffer = std::make_shared<uint8_t>(streamSize);
            outData.inputStreamBuffer = streamBuffer.get();
        } else if (streamSize == STREAM_SIZE_TWO) {
            outData.dataSize = streamSize;
        }
        return returnValue_;
    }

    bool Read(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
    {
        return returnValue_;
    }

    bool Peek(uint32_t desiredSize, DataStreamBuffer &outData) override
    {
        return returnValue_;
    }

    bool Peek(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
    {
        return returnValue_;
    }

    uint32_t Tell() override
    {
        return 0;
    }

    bool Seek(uint32_t position) override
    {
        return returnValue_;
    }

    uint32_t GetStreamType()
    {
        return -1;
    }

    uint8_t *GetDataPtr()
    {
        return nullptr;
    }

    bool IsStreamCompleted()
    {
        return returnValue_;
    }

    size_t GetStreamSize()
    {
        return streamSize;
    }

    void SetReturn(bool returnValue)
    {
        returnValue_ = returnValue;
    }

    void SetStreamSize(size_t size)
    {
        streamSize = size;
    }

    ~MockInputDataStream() {}
private:
    bool returnValue_ = false;
    size_t streamSize = 0;
    std::shared_ptr<uint8_t> streamBuffer = nullptr;
};

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
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t result = jpegDecoder->SetDecodeOptions(0, opts, info);
    ASSERT_EQ(result, Media::SUCCESS);
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
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetDecodeOptionsTest003 end";
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
    jpegDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, Media::SUCCESS);
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
    jpegDecoder->SetSource(*streamPtr.release());
    jpegDecoder->GetImageSize(1, plSize);
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest002 end";
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
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::PlSize plSize;
    jpegDecoder->SetSource(*streamPtr.release());
    uint32_t result = jpegDecoder->GetImageSize(2, plSize);
    ASSERT_EQ(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest003 end";
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
 * @tc.name: GetImageSizeTest005
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(true);
    jpegDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest005 end";
}

/**
 * @tc.name: GetImageSizeTest006
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest006 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(true);
    jpegDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest006 end";
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
    uint32_t result = jpegDecoder->Decode(2, context);
    ASSERT_EQ(result, Media::SUCCESS);
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
 * @tc.name: DecodeTest003
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    uint32_t result = jpegDecoder->Decode(2, context);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest003 end";
}

/**
 * @tc.name: DecodeTest004
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DecodeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    uint32_t ret = jpegDecoder->Decode(context);
    ASSERT_EQ(ret, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DecodeTest004 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest001
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, PromoteIncrementalDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: PromoteIncrementalDecodeTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    ProgDecodeContext context;
    uint32_t result = jpegDecoder->PromoteIncrementalDecode(2, context);
    ASSERT_EQ(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: PromoteIncrementalDecodeTest001 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest002
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, PromoteIncrementalDecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: PromoteIncrementalDecodeTest002 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    ProgDecodeContext context;
    uint32_t result = jpegDecoder->PromoteIncrementalDecode(JPEG_IMAGE_NUM, context);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "JpegDecoderTest: PromoteIncrementalDecodeTest002 end";
}
/**
 * @tc.name: PromoteIncrementalDecodeTest003
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, PromoteIncrementalDecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: PromoteIncrementalDecodeTest003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    jpegDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    uint32_t result = jpegDecoder->PromoteIncrementalDecode(0, context);
    ASSERT_EQ(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: PromoteIncrementalDecodeTest003 end";
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
    std::string key = ORIENTATION;
    int32_t value = 0;
    uint32_t result = jpegDecoder->GetImagePropertyInt(0, key, value);
    ASSERT_EQ(result, Media::SUCCESS);
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
    std::string key = IMAGE_LENGTH;
    int32_t value = 0;
    uint32_t result = jpegDecoder->GetImagePropertyInt(0, key, value);
    ASSERT_EQ(result, Media::SUCCESS);
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
    std::string key = BITS_PER_SAMPLE;
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
    std::string key = ORIENTATION;
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
    std::string key = IMAGE_LENGTH;
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
    std::string key = IMAGE_WIDTH;
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
    std::string key = GPS_LATITUDE;
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
    std::string key = GPS_LONGITUDE;
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
    std::string key = GPS_LATITUDE_REF;
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
    std::string key = GPS_LONGITUDE_REF;
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
    std::string key = DATE_TIME_ORIGINAL;
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
    std::string key = DATE_TIME_ORIGINAL_MEDIA;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(value, exifInfo_.dateTimeOriginal_);
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
    std::string key = EXPOSURE_TIME;
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
    std::string key = F_NUMBER;
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
    std::string key = ISO_SPEED_RATINGS;
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
    std::string key = ACTUAL_IMAGE_ENCODED_FORMAT;
    std::string value = "";
    int32_t result = jpegDecoder->GetImagePropertyString(0, key, value);
    ASSERT_EQ(result, Media::ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringTest016 end";
}


/**
 * @tc.name: GetImagePropertyStringExTest01
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringExTest01, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest01 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "";
    std::string value = "";
    int32_t result = jpegDecoder->GetImagePropertyStringEx(key, value);
    ASSERT_EQ(result, Media::Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest01 end";
}

/**
 * @tc.name: GetImagePropertyStringExTest002
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringExTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest002 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest002 end";
}

/**
 * @tc.name: GetImagePropertyStringExTest003
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringExTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest003 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest003 end";
}

/**
 * @tc.name: GetImagePropertyStringExTest004
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringExTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest004 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest004 end";
}

/**
 * @tc.name: GetImagePropertyStringExTest005
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringExTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = WHITE_BALANC;
    std::string value = "";
    EXIFInfo exifInfo_;
    jpegDecoder->GetImagePropertyString(key, value);
    ASSERT_EQ(value, exifInfo_.whiteBalance_);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest005 end";
}

/**
 * @tc.name: GetImagePropertyStringExTest006
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringExTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest006 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest006 end";
}

/**
 * @tc.name: GetImagePropertyStringExTest007
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringExTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest007 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest007 end";
}

/**
 * @tc.name: GetImagePropertyStringExTest008
 * @tc.desc: Test of GetImagePropertyStringEx
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImagePropertyStringExTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest008 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImagePropertyStringExTest008 end";
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
    std::string value = 0;
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
    std::string value = 0;
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, path);
    ASSERT_EQ(result, Media::SUCCESS);
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
    std::string value = 0;
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, path);
    ASSERT_EQ(result, Media::SUCCESS);
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
    std::string value = 0;
    int fd = 0;
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, fd);
    ASSERT_EQ(result, Media::SUCCESS);
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
    std::string value = 0;
    int fd = 0;
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, fd);
    ASSERT_EQ(result, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest005 end";
}

/**
 * @tc.name: ModifyImagePropertyTest006
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    std::string key = "";
    std::string path = "";
    std::string value = 0;
    uint32_t size = 0;
    int32_t result = jpegDecoder->ModifyImageProperty(0, key, value, size);
    ASSERT_EQ(result, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest005 end";
}

/**
 * @tc.name: GetRedactionAreaTest001
 * @tc.desc: Test of GetRedactionArea
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetRedactionAreaTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetRedactionAreaTest001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int size = STREAM_SIZE;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    jpegDecoder->SetSource(*streamPtr.release());
    int fd = 0;
    int redactionType = 0;
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    ranges.push_back(std::make_pair(0, 0));
    int32_t result = jpegDecoder->GetRedactionArea(fd, redactionType, ranges);
    ASSERT_EQ(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetRedactionAreaTest001 end";
}

/**
 * @tc.name: IsMarkerTest001
 * @tc.desc: Test of IsMarker
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, IsMarkerTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: IsMarkerTest001 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: IsMarkerTest001 end";
}

/**
 * @tc.name: IsMarkerTest002
 * @tc.desc: Test of IsMarker
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, IsMarkerTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: IsMarkerTest002 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: IsMarkerTest002 end";
}

/**
 * @tc.name: GetImageSizeTest0001
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetImageSizeTest0001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest0001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    ImagePlugin::PlSize plSize;
    ErrCodeOffset(2, 0);
    jpegDecoder->GetImageSize(1, plSize);
    jpegDecoder->GetImageSize(0, plSize);
    ImagePlugin::JpegDecoder::state_ = ImagePlugin::JpegDecodingState::IMAGE_DECODING;
    uint32_t result = jpegDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, Media::SUCCESS);
    ImagePlugin::JpegDecoder::state_ = ImagePlugin::JpegDecodingState::BASE_INFO_PARSING;
    jpegDecoder->GetImageSize(0, plSize);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetImageSizeTest0001 end";
}

/**
 * @tc.name: GetScaledFractionTest0002
 * @tc.desc: Test of GetScaledFraction
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetScaledFractionTest0002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetScaledFractionTest0001 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    int inSampleSize;
    jpeg_decompress_struct dInfo;
    jpegDecoder->GetScaledFraction(inSampleSize, dInfo);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetScaledFractionTest0002 end";
}

/**
 * @tc.name: GetRowBytesTest0003
 * @tc.desc: Test of GetRowBytes
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetRowBytesTest0003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetRowBytesTest0003 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    jpegDecoder->JpegDecoder::GetRowBytes();
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetRowBytesTest0003 end";
}

/**
 * @tc.name: ResetTest0004
 * @tc.desc: Test of Reset
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ResetTest0004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ResetTest0004 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    jpegDecoder->JpegDecoder::Reset();
    GTEST_LOG_(INFO) << "JpegDecoderTest: ResetTest0004 end";
}

/**
 * @tc.name: FinishOldDecompressTest0005
 * @tc.desc: Test of FinishOldDecompress
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FinishOldDecompressTest0005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FinishOldDecompressTest0005 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    jpegDecoder->JpegDecoder::FinishOldDecompress();
    ImagePlugin::JpegDecoder::state_ = ImagePlugin::JpegDecodingState::BASE_INFO_PARSED;
    jpegDecoder->JpegDecoder::FinishOldDecompress();
    GTEST_LOG_(INFO) << "JpegDecoderTest: FinishOldDecompressTest0005 end";
}

/**
 * @tc.name: SetOriginalTimesTest0006
 * @tc.desc: Test of SetOriginalTimes
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SetOriginalTimesTest0006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetOriginalTimesTest0006 start";
    std::string dataTime1 = "2023-10-15";
    std::string result1 = SetOriginalTimes(dataTime1);
    ASSERT_EQ(result1, "2023-10-15 00:00:00");
    std::string dataTime2 = "2023-10-15 ";
    std::string result2 = SetOriginalTimes(dataTime2);
    ASSERT_EQ(result2, "2023-10-15 00:00:00");
    std::string dataTime3 = "2023-10-15 12:34:56 ";
    std::string result3 = SetOriginalTimes(dataTime3);
    ASSERT_EQ(result3, "2023-10-15 12:34:56");
    std::string dataTime4 = "2023-10-15";
    std::string result4 = SetOriginalTimes(dataTime4);
    ASSERT_EQ(result4, "2023-10-15 00:00:00");
    std::string dataTime5 = "2023-10-15 12:34";
    std::string result5 = SetOriginalTimes(dataTime5);
    ASSERT_EQ(result5, "2023-10-15 12:34:00");
    std::string dataTime6 = "2023-10-15 12:34:56.789";
    std::string result6 = SetOriginalTimes(dataTime6);
    ASSERT_EQ(result6, "2023-10-15 12:34:56");
    GTEST_LOG_(INFO) << "JpegDecoderTest: SetOriginalTimesTest0006 end";
}

/**
 * @tc.name: FormatTimeStampTest0007
 * @tc.desc: Test of FormatTimeStamp
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FormatTimeStampTest0007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest0007 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    std::string value = "";
    std::string src = "2023-10-15 12:34:56";
    jpegDecoder->JpegDecoder::FormatTimeStamp(value, src);
    GTEST_LOG_(INFO) << "JpegDecoderTest: FormatTimeStampTest0007 end";
}

/**
 * @tc.name: getExifTagFromKeyTest0008
 * @tc.desc: Test of getExifTagFromKey
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, getExifTagFromKeyTest0008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: getExifTagFromKeyTest0008 start";
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
    GTEST_LOG_(INFO) << "JpegDecoderTest: getExifTagFromKeyTest0008 end";
}

/**
 * @tc.name: ModifyImagePropertyTest0009
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, ModifyImagePropertyTest0009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest0009 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    uint32_t index = 1;
    const std::string key = "GPSTimeStamp";
    const std::string value = "111";
    const std::string path = " ";
    int32_t result = JpegDecoder::ModifyImageProperty(index, key, value, path);
    ASSERT_EQ(result, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "JpegDecoderTest: ModifyImagePropertyTest0009 end";
}

/**
 * @tc.name: GetFilterAreaTest0010
 * @tc.desc: Test of GetFilterArea
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, GetFilterAreaTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetFilterAreaTest0010 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = JpegDecoder->GetFilterArea(1, ranges);
    EXPECT_EQ(ret, Media::ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "JpegDecoderTest: GetFilterAreaTest0010 end";
}

/**
 * @tc.name: FillInputBufferTest0011
 * @tc.desc: Test of FillInputBuffer
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, FillInputBufferTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: FillInputBufferTest0011 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    j_decompress_ptr dinfo = nullptr;
    boolean ret = JpegDecoder->FillInputBuffer(dinfo);
    EXPECT_EQ(ret, FALSE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: FillInputBufferTest0011 end";
}

/**
 * @tc.name: SkipInputDataTest0012
 * @tc.desc: Test of SkipInputData
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, SkipInputDataTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: SkipInputDataTest0012 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    j_decompress_ptr dinfo = nullptr;
    long numBytes;
    JpegDecoder->SkipInputData(dinfo,numBytes);
    GTEST_LOG_(INFO) << "JpegDecoderTest: SkipInputDataTest0012 end";
}

/**
 * @tc.name: TermSrcStreamTest0013
 * @tc.desc: Test of TermSrcStream
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, TermSrcStreamTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: TermSrcStreamTest0013 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    JpegDecoder->TermSrcStream();
    GTEST_LOG_(INFO) << "JpegDecoderTest: TermSrcStreamTest0013 end";
}

/**
 * @tc.name: InitDstStreamTest0014
 * @tc.desc: Test of InitDstStream
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, InitDstStreamTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: InitDstStreamTest0014 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    j_compress_ptr cinfo = nullptr;
    cinfo->dest == nullptr;
    JpegDecoder->InitDstStream();
    GTEST_LOG_(INFO) << "JpegDecoderTest: InitDstStreamTest0014 end";
}

/**
 * @tc.name: EmptyOutputBufferTest0015
 * @tc.desc: Test of EmptyOutputBuffer
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, EmptyOutputBufferTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: EmptyOutputBufferTest0015 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    j_compress_ptr cinfo = nullptr;
    boolean ret = JpegDecoder->EmptyOutputBuffer(cinfo);
    ASSERT_EQ(ret, FALSE);
    GTEST_LOG_(INFO) << "JpegDecoderTest: EmptyOutputBufferTest0015 end";
}

/**
 * @tc.name: TermDstStreamTest0016
 * @tc.desc: Test of TermDstStream
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, TermDstStreamTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: TermDstStreamTest0016 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    j_compress_ptr cinfo = nullptr;
    JpegDecoder->TermDstStream(cinfo);
    GTEST_LOG_(INFO) << "JpegDecoderTest: TermDstStreamTest0016 end";
}

/**
 * @tc.name: DoubleToStringTest0017
 * @tc.desc: Test of DoubleToString
 * @tc.type: FUNC
 */
HWTEST_F(JpegDecoderTest, DoubleToStringTest0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegDecoderTest: DoubleToStringTest0017 start";
    auto jpegDecoder = std::make_shared<JpegDecoder>();
    double num;
    std::string ret = JpegDecoder->DoubleToString(num);
    ASSERT_EQ(ret, result);
    GTEST_LOG_(INFO) << "JpegDecoderTest: DoubleToStringTest0017 end";
}
}
}