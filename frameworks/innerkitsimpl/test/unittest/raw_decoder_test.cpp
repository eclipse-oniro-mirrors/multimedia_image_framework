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
#include "buffer_source_stream.h"
#include "raw_decoder.h"
#include "raw_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Multimedia {
static constexpr size_t NUMBER_ONE = 1;
static constexpr size_t NUMBER_TWO = 2;
class RawDecoderTest : public testing::Test {
public:
    RawDecoderTest() {}
    ~RawDecoderTest() {}
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
HWTEST_F(RawDecoderTest, GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest001 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::PlSize plSize;
    rawDecoder->SetSource(*streamPtr.release());
    rawDecoder->GetImageSize(2, plSize);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest001 end";
}

/**
 * @tc.name: GetImageSizeTest002
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, GetImageSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest002 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    ImagePlugin::PlSize plSize;
    rawDecoder->GetImageSize(0, plSize);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    rawDecoder->SetSource(*streamPtr.release());
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest002 end";
}

/**
 * @tc.name: GetImageSizeTest003
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, GetImageSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest003 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    rawDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    rawDecoder->GetImageSize(0, plSize);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest003 end";
}

/**
 * @tc.name: GetImageSizeTest004
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, GetImageSizeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest004 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(true);
    rawDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    rawDecoder->GetImageSize(0, plSize);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest004 end";
}

/**
 * @tc.name: GetImageSizeTest005
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, GetImageSizeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest005 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(true);
    rawDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    rawDecoder->GetImageSize(0, plSize);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest005 end";
}

/**
 * @tc.name: GetImageSizeTest006
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, GetImageSizeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest006 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    rawDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    rawDecoder->GetImageSize(0, plSize);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: GetImageSizeTest006 end";
}

/**
 * @tc.name: RawDecoderTest001
 * @tc.desc: HasProperty
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest001 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    string key = "1";
    bool res = rawDecoder->HasProperty(key);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest001 end";
}

/**
 * @tc.name: RawDecoderTest002
 * @tc.desc: PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest002 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    ProgDecodeContext progContext;
    uint32_t index = 1;
    uint32_t res = rawDecoder->PromoteIncrementalDecode(index, progContext);
    ASSERT_EQ(res, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest002 end";
}

/**
 * @tc.name: RawDecoderTest003
 * @tc.desc: GetTopLevelImageNum
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest003 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 1;
    uint32_t res = rawDecoder->GetTopLevelImageNum(index);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest003 end";
}

/**
 * @tc.name: RawDecoderTest004
 * @tc.desc: SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest004 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 1;
    const PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t res = rawDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(res, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest004 end";
}

/**
 * @tc.name: RawDecoderTest005
 * @tc.desc: SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest005 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    const PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t res = rawDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(res, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest005 end";
}

/**
 * @tc.name: RawDecoderTest006
 * @tc.desc: GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest006 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    PlSize size;
    size.width = 3;
    size.height = 4;
    uint32_t res = rawDecoder->GetImageSize(index, size);
    ASSERT_EQ(res, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest006 end";
}

/**
 * @tc.name: RawDecoderTest007
 * @tc.desc: Decode
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest007 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    DecodeContext context;
    uint32_t res = rawDecoder->Decode(index, context);
    ASSERT_EQ(res, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest007 end";
}

/**
 * @tc.name: RawDecoderTest008
 * @tc.desc: Decode
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest008 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 1;
    DecodeContext context;
    uint32_t res = rawDecoder->Decode(index, context);
    ASSERT_EQ(res, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest008 end";
}

/**
 * @tc.name: SetDecodeOptionsTest001
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, SetDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest001 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    rawDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    rawDecoder->SetDecodeOptions(2, opts, info);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest002
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, SetDecodeOptionsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest002 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    PixelDecodeOptions opts;
    PlImageInfo info;
    rawDecoder->SetDecodeOptions(0, opts, info);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    rawDecoder->SetSource(*streamPtr.release());
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest002 end";
}

/**
 * @tc.name: SetDecodeOptionsTest003
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, SetDecodeOptionsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest003 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    rawDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PlPixelFormat::RGB_565;
    PlImageInfo info;
    rawDecoder->SetDecodeOptions(0, opts, info);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest003 end";
}

/**
 * @tc.name: SetDecodeOptionsTest004
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, SetDecodeOptionsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest004 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    rawDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    rawDecoder->SetDecodeOptions(0, opts, info);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest004 end";
}

/**
 * @tc.name: SetDecodeOptionsTest005
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, SetDecodeOptionsTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest005 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(true);
    rawDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    rawDecoder->SetDecodeOptions(0, opts, info);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest005 end";
}

/**
 * @tc.name: SetDecodeOptionsTest006
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, SetDecodeOptionsTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest006 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    rawDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    rawDecoder->SetDecodeOptions(0, opts, info);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest006 end";
}

/**
 * @tc.name: SetDecodeOptionsTest007
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, SetDecodeOptionsTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest007 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    PixelDecodeOptions opts;
    PlImageInfo info;
    rawDecoder->SetDecodeOptions(5, opts, info);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    rawDecoder->SetSource(*streamPtr.release());
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest002 end";
}

/**
 * @tc.name: SetDecodeOptionsTest008
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, SetDecodeOptionsTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest008 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(0);
    mock->SetReturn(true);
    rawDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    rawDecoder->SetDecodeOptions(2, opts, info);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptionsTest008 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DecodeTest001 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    rawDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    rawDecoder->Decode(2, context);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: DecodeTest002
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DecodeTest002 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    DecodeContext context;
    rawDecoder->Decode(0, context);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    rawDecoder->SetSource(*streamPtr.release());
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: DecodeTest002 end";
}

/**
 * @tc.name: DoDecodeHeaderByPiex001
 * @tc.desc: Test of DoDecodeHeaderByPiex
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DoDecodeHeaderByPiex001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DoDecodeHeaderByPiex001 start";
    std::unique_ptr<RawStream> rawStream_;
    piex::PreviewImageData imageData;
    piex::Error error = piex::GetPreviewImageData(rawStream_.get(), &imageData);
    error = piex::Error::kFail;
    auto rawDecoder = std::make_shared<RawDecoder>();
    rawDecoder->DoDecodeHeaderByPiex();
    imageData.preview.format = piex::Image::kJpegCompressed;
    imageData.preview.length = 1;
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: DoDecodeHeaderByPiex001 end";
}

/**
 * @tc.name: DoDecodeHeaderByPiex002
 * @tc.desc: Test of DoDecodeHeaderByPiex
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DoDecodeHeaderByPiex002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DoDecodeHeaderByPiex002 start";
    std::unique_ptr<RawStream> rawStream_;
    piex::PreviewImageData imageData;
    piex::Error error = piex::GetPreviewImageData(rawStream_.get(), &imageData);
    error = piex::Error::kOk;
    auto rawDecoder = std::make_shared<RawDecoder>();
    imageData.preview.format = piex::Image::kJpegCompressed;
    imageData.preview.length = 1;
    rawDecoder->DoDecodeHeaderByPiex();
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: DoDecodeHeaderByPiex002 end";
}

/**
 * @tc.name: DoDecodeHeaderByPiex003
 * @tc.desc: Test of DoDecodeHeaderByPiex
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DoDecodeHeaderByPiex003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DoDecodeHeaderByPiex003 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    rawDecoder->DoDecodeHeaderByPiex();
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: DoDecodeHeaderByPiex003 end";
}

/**
 * @tc.name: DoSetDecodeOptions
 * @tc.desc: Test of DoSetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DoSetDecodeOptions, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DoSetDecodeOptions001 start";
    uint32_t index = 1;
    PixelDecodeOptions opts;
    PlImageInfo info;
    auto rawDecoder = std::make_shared<RawDecoder>();
    rawDecoder->DoSetDecodeOptions(index, opts, info);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: DoSetDecodeOptions001 end";
}

/**
 * @tc.name: DoGetImageSize
 * @tc.desc: Test of DoGetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DoGetImageSize, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DoGetImageSize start";
    uint32_t index = 1;
    PlSize size;
    std::unique_ptr<AbsImageDecoder> jpegDecoder_;
    auto rawDecoder = std::make_shared<RawDecoder>();
    rawDecoder->DoGetImageSize(index, size);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: DoGetImageSize end";
}

/**
 * @tc.name: DoDecode
 * @tc.desc: Test of DoDecode
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DoDecode, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DoDecode start";
    uint32_t index = 1;
    DecodeContext context;
    auto rawDecoder = std::make_shared<RawDecoder>();
    rawDecoder->DoDecode(index, context);
    bool result = (rawDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "RawDecoderTest: DoDecode end";
}

/**
 * @tc.name: DecodeTest003
 * @tc.desc: Test of DoDecode
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DecodeTest003 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    DecodeContext context;
    rawDecoder->state_ = ImagePlugin::RawDecoder::RawDecodingState::IMAGE_DECODING;
    uint32_t result = rawDecoder->DoDecode(index, context);
    ASSERT_EQ(result, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "RawDecoderTest: DecodeTest003 end";
}

/**
 * @tc.name: SetDecodeOptions007
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, SetDecodeOptions007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptions007 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    PixelDecodeOptions opts;
    PlImageInfo info;
    rawDecoder->state_ = ImagePlugin::RawDecoder::RawDecodingState::IMAGE_DECODING;
    rawDecoder->jpegDecoder_ = nullptr;
    uint32_t result = rawDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptions007 end";
}

/**
 * @tc.name: GetImageSize007
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, GetImageSize007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptions007 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    PlSize size;
    rawDecoder->state_ = ImagePlugin::RawDecoder::RawDecodingState::BASE_INFO_PARSED;
    rawDecoder->jpegDecoder_ = nullptr;
    uint32_t result = rawDecoder->GetImageSize(index, size);
    ASSERT_EQ(result, 0);
    GTEST_LOG_(INFO) << "RawDecoderTest: SetDecodeOptions007 end";
}

/**
 * @tc.name: DoSetDecodeOptions001
 * @tc.desc: Test of DoSetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DoSetDecodeOptions001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DoSetDecodeOptions001 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    PixelDecodeOptions opts;
    PlImageInfo info;
    rawDecoder->jpegDecoder_ = nullptr;
    uint32_t result = rawDecoder->DoSetDecodeOptions(index, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "RawDecoderTest: DoSetDecodeOptions001 end";
}

/**
 * @tc.name: DoGetImageSize001
 * @tc.desc: Test of DoGetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, DoGetImageSize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: DoGetImageSize001 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    PlSize size;
    rawDecoder->jpegDecoder_ = nullptr;
    uint32_t result = rawDecoder->DoGetImageSize(index, size);
    ASSERT_EQ(result, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "RawDecoderTest: DoGetImageSize001 end";
}
}
}