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
#include <gtest/gtest.h>
#include "buffer_source_stream.h"
#include "exif_info.h"
#include "image_packer.h"
#include "jpeg_decoder.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
static constexpr size_t STREAM_SIZE_ONE = 1;
static constexpr size_t STREAM_SIZE_TWO = 2;
static constexpr size_t STREAM_SIZE = 1000;
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
}
}