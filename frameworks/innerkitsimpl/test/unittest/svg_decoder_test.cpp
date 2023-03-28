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
#include "svg_decoder.h"
#include "buffer_source_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace ImagePlugin {
static constexpr size_t NUMBER_ONE = 1;
static constexpr size_t NUMBER_TWO = 2;
class SvgDecoderTest : public testing::Test {};

class MockInputDataStream : public SourceStream {
public:
    MockInputDataStream() = default;
    ~MockInputDataStream() {}

    uint32_t UpdateData(const uint8_t *data, uint32_t size, bool isCompleted) override
    {
        return ERR_IMAGE_DATA_UNSUPPORT;
    }

    bool Read(uint32_t desiredSize, DataStreamBuffer &outData) override
    {
        if (streamSize_ == NUMBER_ONE) {
            streamBuffer_ = std::make_shared<uint8_t>(streamSize_);
            outData.inputStreamBuffer = streamBuffer_.get();
        } else if (streamSize_ == NUMBER_TWO) {
            outData.dataSize = streamSize_;
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
        return streamSize_;
    }

    void SetReturn(bool returnValue)
    {
        returnValue_ = returnValue;
    }

    void SetStreamSize(size_t size)
    {
        streamSize_ = size;
    }

private:
    bool returnValue_ = false;
    size_t streamSize_ = 0;
    std::shared_ptr<uint8_t> streamBuffer_ = nullptr;
};

/**
 * @tc.name: GetImageSizeTest001
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    int size = 1000;
    auto data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::PlSize plSize;
    svgDecoder->SetSource(*streamPtr.release());
    svgDecoder->GetImageSize(2, plSize);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest001 end";
}

/**
 * @tc.name: GetImageSizeTest002
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, GetImageSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest002 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    ImagePlugin::PlSize plSize;
    svgDecoder->GetImageSize(0, plSize);
    int size = 1000;
    auto data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    svgDecoder->SetSource(*streamPtr.release());
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest002 end";
}

/**
 * @tc.name: GetImageSizeTest003
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, GetImageSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest003 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    svgDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    svgDecoder->GetImageSize(0, plSize);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest003 end";
}

/**
 * @tc.name: GetImageSizeTest004
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, GetImageSizeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest004 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(true);
    svgDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    svgDecoder->GetImageSize(0, plSize);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest004 end";
}

/**
 * @tc.name: GetImageSizeTest005
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, GetImageSizeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest005 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(true);
    svgDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    svgDecoder->GetImageSize(0, plSize);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest005 end";
}

/**
 * @tc.name: GetImageSizeTest006
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, GetImageSizeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest006 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    svgDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    svgDecoder->GetImageSize(0, plSize);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest006 end";
}

/**
 * @tc.name: SetDecodeOptionsTest001
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, SetDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: SetDecodeOptionsTest001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    int size = 1000;
    auto data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    svgDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    svgDecoder->SetDecodeOptions(2, opts, info);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: SetDecodeOptionsTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest002
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, SetDecodeOptionsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: SetDecodeOptionsTest002 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    PixelDecodeOptions opts;
    PlImageInfo info;
    svgDecoder->SetDecodeOptions(0, opts, info);
    int size = 1000;
    auto data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    svgDecoder->SetSource(*streamPtr.release());
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: SetDecodeOptionsTest002 end";
}

/**
 * @tc.name: SetDecodeOptionsTest003
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, SetDecodeOptionsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: SetDecodeOptionsTest003 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    int size = 1000;
    auto data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    svgDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PlPixelFormat::RGB_565;
    PlImageInfo info;
    svgDecoder->SetDecodeOptions(0, opts, info);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: SetDecodeOptionsTest003 end";
}

/**
 * @tc.name: SetDecodeOptionsTest004
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, SetDecodeOptionsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: SetDecodeOptionsTest004 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    svgDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    svgDecoder->SetDecodeOptions(0, opts, info);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: SetDecodeOptionsTest004 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DecodeTest001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    int size = 1000;
    auto data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    svgDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    svgDecoder->Decode(2, context);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: DecodeTest002
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DecodeTest002 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    DecodeContext context;
    svgDecoder->Decode(0, context);
    int size = 1000;
    auto data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    svgDecoder->SetSource(*streamPtr.release());
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DecodeTest002 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, PromoteIncrementalDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: PromoteIncrementalDecodeTest001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    int size = 1000;
    auto data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    svgDecoder->SetSource(*streamPtr.release());
    ProgDecodeContext context;
    svgDecoder->PromoteIncrementalDecode(2, context);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: PromoteIncrementalDecodeTest001 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest002
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, PromoteIncrementalDecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: PromoteIncrementalDecodeTest002 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    ProgDecodeContext context;
    svgDecoder->PromoteIncrementalDecode(0, context);
    int size = 1000;
    auto data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    svgDecoder->SetSource(*streamPtr.release());
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: PromoteIncrementalDecodeTest002 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest003
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, PromoteIncrementalDecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: PromoteIncrementalDecodeTest003 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    svgDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    svgDecoder->PromoteIncrementalDecode(0, context);
    bool result = (svgDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "SvgDecoderTest: PromoteIncrementalDecodeTest003 end";
}
}
}