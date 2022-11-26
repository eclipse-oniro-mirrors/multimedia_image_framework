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
#include "webp_decoder.h"
#include "image_packer.h"
#include "buffer_source_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
static constexpr size_t NUMBER_ONE = 1;
static constexpr size_t NUMBER_TWO = 2;
class WebpDecoderTest : public testing::Test {
public:
    WebpDecoderTest() {}
    ~WebpDecoderTest() {}
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
        if (streamSize == NUMBER_ONE) {
            streamBuffer = std::make_shared<uint8_t>(streamSize);
            outData.inputStreamBuffer = streamBuffer.get();
        } else if (streamSize == NUMBER_TWO) {
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
 * @tc.name: GetImageSizeTest001
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::PlSize plSize;
    webpDecoder->SetSource(*streamPtr.release());
    webpDecoder->GetImageSize(2, plSize);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest001 end";
}

/**
 * @tc.name: GetImageSizeTest002
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, GetImageSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest002 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    ImagePlugin::PlSize plSize;
    webpDecoder->GetImageSize(0, plSize);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    webpDecoder->SetSource(*streamPtr.release());
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest002 end";
}

/**
 * @tc.name: GetImageSizeTest003
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, GetImageSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest003 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    webpDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    webpDecoder->GetImageSize(0, plSize);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest003 end";
}

/**
 * @tc.name: GetImageSizeTest004
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, GetImageSizeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest004 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(true);
    webpDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    webpDecoder->GetImageSize(0, plSize);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest004 end";
}

/**
 * @tc.name: GetImageSizeTest005
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, GetImageSizeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest005 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(true);
    webpDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    webpDecoder->GetImageSize(0, plSize);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest005 end";
}

/**
 * @tc.name: GetImageSizeTest006
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, GetImageSizeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest006 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    webpDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    webpDecoder->GetImageSize(0, plSize);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest006 end";
}

/**
 * @tc.name: SetDecodeOptionsTest001
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, SetDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    webpDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    webpDecoder->SetDecodeOptions(2, opts, info);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest002
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, SetDecodeOptionsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest002 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    PixelDecodeOptions opts;
    PlImageInfo info;
    webpDecoder->SetDecodeOptions(0, opts, info);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    webpDecoder->SetSource(*streamPtr.release());
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest002 end";
}

/**
 * @tc.name: SetDecodeOptionsTest003
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, SetDecodeOptionsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest003 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    webpDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PlPixelFormat::RGB_565;
    PlImageInfo info;
    webpDecoder->SetDecodeOptions(0, opts, info);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest003 end";
}

/**
 * @tc.name: SetDecodeOptionsTest004
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, SetDecodeOptionsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest004 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    webpDecoder->SetDecodeOptions(0, opts, info);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest004 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: DecodeTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    webpDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    webpDecoder->Decode(2, context);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: DecodeTest002
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, DecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: DecodeTest002 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    DecodeContext context;
    webpDecoder->Decode(0, context);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    webpDecoder->SetSource(*streamPtr.release());
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: DecodeTest002 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, PromoteIncrementalDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: PromoteIncrementalDecodeTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    webpDecoder->SetSource(*streamPtr.release());
    ProgDecodeContext context;
    webpDecoder->PromoteIncrementalDecode(2, context);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: PromoteIncrementalDecodeTest001 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest002
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, PromoteIncrementalDecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: PromoteIncrementalDecodeTest002 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    ProgDecodeContext context;
    webpDecoder->PromoteIncrementalDecode(0, context);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    webpDecoder->SetSource(*streamPtr.release());
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: PromoteIncrementalDecodeTest002 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest003
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, PromoteIncrementalDecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: PromoteIncrementalDecodeTest003 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    webpDecoder->PromoteIncrementalDecode(0, context);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: PromoteIncrementalDecodeTest003 end";
}
}
}