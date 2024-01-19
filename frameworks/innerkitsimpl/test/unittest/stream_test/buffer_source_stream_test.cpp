/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include <fstream>
#include <fcntl.h>
#include "buffer_source_stream.h"
#include "image_type.h"
#include "image_utils.h"
#include "image_source.h"
#include "image_source_util.h"
#include "media_errors.h"
#include "pixel_map.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;
using namespace OHOS::ImagePlugin;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPG_PATH = "/data/local/tmp/image/test.jpg";
static constexpr uint32_t MAXSIZE = 10000;
class BufferSourceStreamTest : public testing::Test {
public:
    BufferSourceStreamTest() {}
    ~BufferSourceStreamTest() {}
};

/**
 * @tc.name: BufferSourceStreamTest001
 * @tc.desc: CreateSourceStream
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *buffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(buffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest001 end";
}

/**
 * @tc.name: BufferSourceStreamTest002
 * @tc.desc: CreateSourceStream buffer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(buffer, size);
    ASSERT_EQ(bufferSourceStream, nullptr);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest002 end";
}

/**
 * @tc.name: BufferSourceStreamTest003
 * @tc.desc: CreateSourceStream size is 0
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest003 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *buffer = pixelMap->GetPixels();
    uint32_t size = 0;
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(buffer, size);
    ASSERT_EQ(bufferSourceStream, nullptr);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest003 end";
}

/**
 * @tc.name: BufferSourceStreamTest004
 * @tc.desc: Peek
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest004 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *buffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(buffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = MAXSIZE;
    bool ret = bufferSourceStream->Peek(desiredSize, outData);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest004 end";
}

/**
 * @tc.name: BufferSourceStreamTest005
 * @tc.desc: Peek desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest005 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *buffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(buffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = 0;
    bool ret = bufferSourceStream->Peek(desiredSize, outData);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest005 end";
}

/**
 * @tc.name: BufferSourceStreamTest006
 * @tc.desc: Read
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest006 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *buffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(buffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = MAXSIZE;
    bool ret = bufferSourceStream->Read(desiredSize, outData);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest006 end";
}

/**
 * @tc.name: BufferSourceStreamTest007
 * @tc.desc: Read desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest007 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *buffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(buffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = 0;
    bool ret = bufferSourceStream->Read(desiredSize, outData);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest007 end";
}

/**
 * @tc.name: BufferSourceStreamTest008
 * @tc.desc: Peek
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest008 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    uint32_t desiredSize = size;
    uint32_t readSize;
    bool ret = bufferSourceStream->Peek(desiredSize, data, size, readSize);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest008 end";
}

/**
 * @tc.name: BufferSourceStreamTest009
 * @tc.desc: Peek desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest009 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    uint32_t desiredSize = 0;
    uint32_t readSize;
    bool ret = bufferSourceStream->Peek(desiredSize, data, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest009 end";
}

/**
 * @tc.name: BufferSourceStreamTest0010
 * @tc.desc: Peek out buffer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0010 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint8_t *data = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    uint32_t desiredSize = size;
    uint32_t readSize;
    bool ret = bufferSourceStream->Peek(desiredSize, data, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0010 end";
}

/**
 * @tc.name: BufferSourceStreamTest0011
 * @tc.desc: Read
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0011 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    uint32_t desiredSize = size;
    uint32_t readSize;
    bool ret = bufferSourceStream->Read(desiredSize, data, size, readSize);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0011 end";
}

/**
 * @tc.name: BufferSourceStreamTest0012
 * @tc.desc: Read out buffer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0012 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint8_t *data = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    uint32_t desiredSize = size;
    uint32_t readSize;
    bool ret = bufferSourceStream->Read(desiredSize, data, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0012 end";
}

/**
 * @tc.name: BufferSourceStreamTest0013
 * @tc.desc: Tell
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0013 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    uint32_t ret = bufferSourceStream->Tell();
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0013 end";
}

/**
 * @tc.name: BufferSourceStreamTest0014
 * @tc.desc: Seek
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0014 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    uint32_t position = size;
    bool ret = bufferSourceStream->Seek(position);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0014 end";
}

/**
 * @tc.name: BufferSourceStreamTest0015
 * @tc.desc: Seek position is -1
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0015 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    uint32_t position = -1;
    bool ret = bufferSourceStream->Seek(position);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0015 end";
}

/**
 * @tc.name: BufferSourceStreamTest0016
 * @tc.desc: GetStreamSize
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0016 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    size_t ret = bufferSourceStream->GetStreamSize();
    ASSERT_NE(ret, 0);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0016 end";
}

/**
 * @tc.name: BufferSourceStreamTest0017
 * @tc.desc: GetDataPtr
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0017 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    uint8_t *ret = bufferSourceStream->GetDataPtr();
    ASSERT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0017 end";
}

/**
 * @tc.name: BufferSourceStreamTest0018
 * @tc.desc: GetStreamType
 * @tc.type: FUNC
 */
HWTEST_F(BufferSourceStreamTest, BufferSourceStreamTest0018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0018 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const uint8_t *outBuffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    std::unique_ptr<BufferSourceStream> bufferSourceStream = BufferSourceStream::CreateSourceStream(outBuffer, size);
    ASSERT_NE(bufferSourceStream, nullptr);
    uint32_t ret = bufferSourceStream->GetStreamType();
    ASSERT_EQ(ret, BUFFER_SOURCE_TYPE);
    GTEST_LOG_(INFO) << "BufferSourceStreamTest: BufferSourceStreamTest0018 end";
}
}
}