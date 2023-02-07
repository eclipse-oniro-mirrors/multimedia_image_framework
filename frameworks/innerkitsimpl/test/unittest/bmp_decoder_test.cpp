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
#include "bmp_decoder.h"
#include "buffer_source_stream.h"
#include "image_packer.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
static constexpr size_t NUMBER_ONE = 1;
static constexpr size_t NUMBER_TWO = 2;
class BmpDecoderTest : public testing::Test {
public:
    BmpDecoderTest() {}
    ~BmpDecoderTest() {}
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
HWTEST_F(BmpDecoderTest, GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest001 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::PlSize plSize;
    bmpDecoder->SetSource(*streamPtr.release());
    bmpDecoder->GetImageSize(2, plSize);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest001 end";
}

/**
 * @tc.name: GetImageSizeTest002
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, GetImageSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest002 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    ImagePlugin::PlSize plSize;
    bmpDecoder->GetImageSize(0, plSize);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    bmpDecoder->SetSource(*streamPtr.release());
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest002 end";
}

/**
 * @tc.name: GetImageSizeTest003
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, GetImageSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest003 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    bmpDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    bmpDecoder->GetImageSize(0, plSize);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest003 end";
}

/**
 * @tc.name: GetImageSizeTest004
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, GetImageSizeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest004 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(true);
    bmpDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    bmpDecoder->GetImageSize(0, plSize);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest004 end";
}

/**
 * @tc.name: GetImageSizeTest005
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, GetImageSizeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest005 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(true);
    bmpDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    bmpDecoder->GetImageSize(0, plSize);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest005 end";
}

/**
 * @tc.name: GetImageSizeTest006
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, GetImageSizeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest006 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    bmpDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    bmpDecoder->GetImageSize(0, plSize);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest006 end";
}

/**
 * @tc.name: SetDecodeOptionsTest001
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest001 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    bmpDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    bmpDecoder->SetDecodeOptions(2, opts, info);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest002
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetDecodeOptionsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest002 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    PixelDecodeOptions opts;
    PlImageInfo info;
    bmpDecoder->SetDecodeOptions(0, opts, info);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    bmpDecoder->SetSource(*streamPtr.release());
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest002 end";
}

/**
 * @tc.name: SetDecodeOptionsTest003
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetDecodeOptionsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest003 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    bmpDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PlPixelFormat::RGB_565;
    PlImageInfo info;
    bmpDecoder->SetDecodeOptions(0, opts, info);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest003 end";
}

/**
 * @tc.name: SetDecodeOptionsTest004
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetDecodeOptionsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest004 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    bmpDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    bmpDecoder->SetDecodeOptions(0, opts, info);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest004 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeTest001 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    bmpDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    bmpDecoder->Decode(2, context);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: DecodeTest002
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, DecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeTest002 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    DecodeContext context;
    bmpDecoder->Decode(0, context);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    bmpDecoder->SetSource(*streamPtr.release());
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeTest002 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, PromoteIncrementalDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: PromoteIncrementalDecodeTest001 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    bmpDecoder->SetSource(*streamPtr.release());
    ProgDecodeContext context;
    bmpDecoder->PromoteIncrementalDecode(2, context);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: PromoteIncrementalDecodeTest001 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest002
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, PromoteIncrementalDecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: PromoteIncrementalDecodeTest002 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    ProgDecodeContext context;
    bmpDecoder->PromoteIncrementalDecode(0, context);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    bmpDecoder->SetSource(*streamPtr.release());
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: PromoteIncrementalDecodeTest002 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest003
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, PromoteIncrementalDecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: PromoteIncrementalDecodeTest003 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    bmpDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    bmpDecoder->PromoteIncrementalDecode(0, context);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: PromoteIncrementalDecodeTest003 end";
}
}
}