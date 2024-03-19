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
#include "webp_decoder.h"
#include "image_packer.h"
#include "buffer_source_stream.h"
#include "mock_data_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
class WebpDecoderTest : public testing::Test {
public:
    WebpDecoderTest() {}
    ~WebpDecoderTest() {}
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
 * @tc.name: GetImageSizeTest007
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, GetImageSizeTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest007 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    webpDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    webpDecoder->GetImageSize(0, plSize);
    webpDecoder->GetImageSize(0, plSize);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest007 end";
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
 * @tc.name: DecodeTest003
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, DecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: DecodeTest003 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    webpDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    webpDecoder->Decode(0, context);
    webpDecoder->Decode(0, context);
    bool result = (webpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: DecodeTest003 end";
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

/**
 * @tc.name: GetImageSizeTest008
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, GetImageSizeTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest008 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    webpDecoder->SetSource(*mock.get());
    uint32_t index = 0;
    ImagePlugin::PlSize plSize;
    webpDecoder->state_ = WebpDecodingState::BASE_INFO_PARSED;
    uint32_t result = webpDecoder->GetImageSize(index, plSize);
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetImageSizeTest008 end";
}

/**
 * @tc.name: SetDecodeOptionsTest005
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, SetDecodeOptionsTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest005 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    uint32_t index = 0;
    PixelDecodeOptions opts;
    PlImageInfo info;
    opts.desiredPixelFormat = PlPixelFormat::RGB_565;
    webpDecoder->state_ = WebpDecodingState::BASE_INFO_PARSED;
    uint32_t result = webpDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest005 end";
}

/**
 * @tc.name: DecodeTest004
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, DecodeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: DecodeTest004 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    webpDecoder->SetSource(*streamPtr.release());
    uint32_t index = 0;
    DecodeContext context;
    webpDecoder->state_ = WebpDecodingState::IMAGE_ERROR;
    uint32_t result = webpDecoder->Decode(index, context);
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "WebpDecoderTest: DecodeTest004 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest004
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, PromoteIncrementalDecodeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: PromoteIncrementalDecodeTest004 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    uint32_t index = 0;
    ProgDecodeContext context;
    webpDecoder->state_ = WebpDecodingState::IMAGE_DECODING;
    uint32_t result = webpDecoder->PromoteIncrementalDecode(index, context);
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "WebpDecoderTest: PromoteIncrementalDecodeTest004 end";
}

/**
 * @tc.name: ReadIncrementalHeadTest001
 * @tc.desc: Test of ReadIncrementalHead
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, ReadIncrementalHeadTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: ReadIncrementalHeadTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    uint32_t result = webpDecoder->ReadIncrementalHead();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "WebpDecoderTest: ReadIncrementalHeadTest001 end";
}

/**
 * @tc.name: IsDataEnoughTest001
 * @tc.desc: Test of IsDataEnough
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, IsDataEnoughTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: IsDataEnoughTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    mock->returnValue_ = false;
    bool result = webpDecoder->IsDataEnough();
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "WebpDecoderTest: IsDataEnoughTest001 end";
}

/**
 * @tc.name: GetWebpDecodeModeTest001
 * @tc.desc: Test of GetWebpDecodeMode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, GetWebpDecodeModeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetWebpDecodeModeTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    PlPixelFormat pixelFormat = PlPixelFormat::RGB_565;
    bool premul = false;
    uint32_t result = webpDecoder->GetWebpDecodeMode(pixelFormat, premul);
    ASSERT_EQ(result, MODE_RGB_565);
    pixelFormat = PlPixelFormat::NV21;
    result = webpDecoder->GetWebpDecodeMode(pixelFormat, premul);
    ASSERT_EQ(result, MODE_RGBA);
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetWebpDecodeModeTest001 end";
}

/**
 * @tc.name: DoCommonDecodeTest001
 * @tc.desc: Test of DoCommonDecode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, DoCommonDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetWebpDecodeModeTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    DecodeContext context;
    uint32_t result = webpDecoder->DoCommonDecode(context);
    ASSERT_EQ(result, ERR_IMAGE_MALLOC_ABNORMAL);
    GTEST_LOG_(INFO) << "WebpDecoderTest: DoCommonDecodeTest001 end";
}

/**
 * @tc.name: PreDecodeProcTest001
 * @tc.desc: Test of PreDecodeProc
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, PreDecodeProcTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetWebpDecodeModeTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    DecodeContext context;
    WebPDecoderConfig config;
    bool isIncremental = false;
    bool result = webpDecoder->PreDecodeProc(context, config, isIncremental);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "WebpDecoderTest: PreDecodeProcTest001 end";
}

/**
 * @tc.name: AllocOutputBufferTest001
 * @tc.desc: Test of HeapMemoryCreate
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, AllocOutputBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: AllocOutputBufferTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    DecodeContext context;
    bool isIncremental = false;
    context.pixelsBuffer.buffer = nullptr;
    context.allocatorType = Media::AllocatorType::HEAP_ALLOC;
    bool result = webpDecoder->AllocOutputBuffer(context, isIncremental);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "WebpDecoderTest: AllocOutputBufferTest001 end";
}

/**
 * @tc.name: ReadIncrementalHeadTest002
 * @tc.desc: Test of ReadIncrementalHead
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, ReadIncrementalHeadTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: ReadIncrementalHeadTest002 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    mock->streamSize = 4096;
    mock->returnValue_ = false;
    uint32_t result = webpDecoder->ReadIncrementalHead();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "WebpDecoderTest: ReadIncrementalHeadTest002 end";
}

/**
 * @tc.name: DoIncrementalDecodeTest001
 * @tc.desc: Test of DoIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, DoIncrementalDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: DoIncrementalDecodeTest001 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    uint32_t result = webpDecoder->DoIncrementalDecode(context);
    ASSERT_EQ(result, ERR_IMAGE_MALLOC_ABNORMAL);

    context.decodeContext.pixelsBuffer.buffer = malloc(4);
    context.decodeContext.allocatorType = AllocatorType::DMA_ALLOC;
    mock->returnValue_ = false;
    result = webpDecoder->DoIncrementalDecode(context);
    ASSERT_EQ(result, ERR_IMAGE_DECODE_FAILED);
    free(context.decodeContext.pixelsBuffer.buffer);
    context.decodeContext.pixelsBuffer.buffer = nullptr;
    GTEST_LOG_(INFO) << "WebpDecoderTest: DoIncrementalDecodeTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest006
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, SetDecodeOptionsTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest006 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    uint32_t index = 0;
    PixelDecodeOptions opts;
    PlImageInfo info;
    opts.desiredPixelFormat = PlPixelFormat::RGB_565;
    webpDecoder->state_ = WebpDecodingState::IMAGE_DECODING;
    uint32_t result = webpDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "WebpDecoderTest: SetDecodeOptionsTest006 end";
}

/**
 * @tc.name: IsDataEnoughTest002
 * @tc.desc: Test of IsDataEnough
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, IsDataEnoughTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: IsDataEnoughTest002 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    mock->returnValue_ = true;
    bool result = webpDecoder->IsDataEnough();
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpDecoderTest: IsDataEnoughTest002 end";
}

/**
 * @tc.name: GetWebpDecodeModeTest002
 * @tc.desc: Test of GetWebpDecodeMode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, GetWebpDecodeModeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetWebpDecodeModeTest002 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    PlPixelFormat pixelFormat = PlPixelFormat::BGRA_8888;
    bool premul = false;
    uint32_t result = webpDecoder->GetWebpDecodeMode(pixelFormat, premul);
    ASSERT_EQ(result, MODE_BGRA);
    pixelFormat = PlPixelFormat::RGBA_8888;
    result = webpDecoder->GetWebpDecodeMode(pixelFormat, premul);
    ASSERT_EQ(result, MODE_RGBA);
    GTEST_LOG_(INFO) << "WebpDecoderTest: GetWebpDecodeModeTest002 end";
}

/**
 * @tc.name: DoCommonDecodeTest002
 * @tc.desc: Test of DoCommonDecode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, DoCommonDecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: DoCommonDecodeTest002 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    DecodeContext context;
    context.pixelsBuffer.buffer = malloc(4);
    uint32_t result = webpDecoder->DoCommonDecode(context);
    ASSERT_EQ(result, ERR_IMAGE_DECODE_FAILED);
    free(context.pixelsBuffer.buffer);
    context.pixelsBuffer.buffer = nullptr;
    GTEST_LOG_(INFO) << "WebpDecoderTest: DoCommonDecodeTest002 end";
}

/**
 * @tc.name: DoIncrementalDecodeTest002
 * @tc.desc: Test of DoIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, DoIncrementalDecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: DoIncrementalDecodeTest002 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    mock->returnValue_ = true;
    ProgDecodeContext context;
    context.decodeContext.pixelsBuffer.buffer = malloc(4);
    webpDecoder->dataBuffer_.inputStreamBuffer = nullptr;
    uint32_t result = webpDecoder->DoIncrementalDecode(context);
    ASSERT_EQ(result, ERR_IMAGE_DECODE_FAILED);
    free(context.decodeContext.pixelsBuffer.buffer);
    context.decodeContext.pixelsBuffer.buffer = nullptr;
    GTEST_LOG_(INFO) << "WebpDecoderTest: DoIncrementalDecodeTest002 end";
}

/**
 * @tc.name: AllocOutputBufferTest002
 * @tc.desc: Test of SharedMemoryCreate
 * @tc.type: FUNC
 */
HWTEST_F(WebpDecoderTest, AllocOutputBufferTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpDecoderTest: AllocOutputBufferTest002 start";
    auto webpDecoder = std::make_shared<WebpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    webpDecoder->SetSource(*mock.get());
    DecodeContext context;
    bool isIncremental = false;
    context.pixelsBuffer.buffer = nullptr;
    context.allocatorType = Media::AllocatorType::SHARE_MEM_ALLOC;
    bool result = webpDecoder->AllocOutputBuffer(context, isIncremental);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "WebpDecoderTest: AllocOutputBufferTest002 end";
}
}
}