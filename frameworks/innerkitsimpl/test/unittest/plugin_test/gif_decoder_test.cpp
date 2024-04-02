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
#include "gif_decoder.h"
#include "buffer_source_stream.h"
#include "image_packer.h"
#include "mock_data_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
class GifDecoderTest : public testing::Test {
public:
    GifDecoderTest() {}
    ~GifDecoderTest() {}
};

/**
 * @tc.name: GetImageSizeTest001
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: GetImageSizeTest001 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::PlSize plSize;
    gifDecoder->SetSource(*streamPtr.release());
    gifDecoder->GetImageSize(2, plSize);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: GetImageSizeTest001 end";
}

/**
 * @tc.name: GetImageSizeTest003
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, GetImageSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: GetImageSizeTest003 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    gifDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    gifDecoder->GetImageSize(0, plSize);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: GetImageSizeTest003 end";
}

/**
 * @tc.name: GetImageSizeTest004
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, GetImageSizeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: GetImageSizeTest004 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(true);
    gifDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    gifDecoder->GetImageSize(0, plSize);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: GetImageSizeTest004 end";
}

/**
 * @tc.name: GetImageSizeTest005
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, GetImageSizeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: GetImageSizeTest005 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(true);
    gifDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    gifDecoder->GetImageSize(0, plSize);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: GetImageSizeTest005 end";
}

/**
 * @tc.name: GetImageSizeTest006
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, GetImageSizeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: GetImageSizeTest006 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    gifDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    gifDecoder->GetImageSize(0, plSize);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: GetImageSizeTest006 end";
}

/**
 * @tc.name: SetDecodeOptionsTest001
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, SetDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: SetDecodeOptionsTest001 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    gifDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    gifDecoder->SetDecodeOptions(2, opts, info);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: SetDecodeOptionsTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest003
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, SetDecodeOptionsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: SetDecodeOptionsTest003 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    gifDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PlPixelFormat::RGB_565;
    PlImageInfo info;
    gifDecoder->SetDecodeOptions(0, opts, info);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: SetDecodeOptionsTest003 end";
}

/**
 * @tc.name: SetDecodeOptionsTest004
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, SetDecodeOptionsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: SetDecodeOptionsTest004 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    gifDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    gifDecoder->SetDecodeOptions(0, opts, info);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: SetDecodeOptionsTest004 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: DecodeTest001 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    gifDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    gifDecoder->Decode(2, context);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, PromoteIncrementalDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: PromoteIncrementalDecodeTest001 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    gifDecoder->SetSource(*streamPtr.release());
    ProgDecodeContext context;
    gifDecoder->PromoteIncrementalDecode(2, context);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: PromoteIncrementalDecodeTest001 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest003
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, PromoteIncrementalDecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: PromoteIncrementalDecodeTest003 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    gifDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    gifDecoder->PromoteIncrementalDecode(0, context);
    bool result = (gifDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifDecoderTest: PromoteIncrementalDecodeTest003 end";
}

/**
 * @tc.name: GetTopLevelImageNumTest001
 * @tc.desc: Test of GetTopLevelImageNum
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, GetTopLevelImageNum001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: GetTopLevelImageNum001 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    uint32_t num = 0;
    gifDecoder->SetSource(*streamPtr.release());
    uint32_t res = gifDecoder->GetTopLevelImageNum(num);
    ASSERT_EQ(res, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "GifDecoderTest: GetTopLevelImageNum001 end";
}

/**
 * @tc.name: GetTopLevelImageNumTest002
 * @tc.desc: Test of GetTopLevelImageNum
 * @tc.type: FUNC
 */
HWTEST_F(GifDecoderTest, GetTopLevelImageNum002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifDecoderTest: GetTopLevelImageNum002 start";
    auto gifDecoder = std::make_shared<GifDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    gifDecoder->SetSource(*mock.get());
    uint32_t num = 0;
    uint32_t res = gifDecoder->GetTopLevelImageNum(num);
    ASSERT_EQ(res, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "GifDecoderTest: GetTopLevelImageNum002 end";
}
}
}