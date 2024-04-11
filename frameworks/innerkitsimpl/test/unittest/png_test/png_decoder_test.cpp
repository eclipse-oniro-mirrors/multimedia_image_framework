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
#include <fstream>
#include "buffer_source_stream.h"
#include "media_errors.h"
#include "memory.h"
#include "png_decoder.h"
#include "securec.h"
#include "mock_data_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Multimedia {
class PngDecoderTest : public testing::Test {
public:
    PngDecoderTest() {}
    ~PngDecoderTest() {}
};

/**
 * @tc.name: GetImageSizeTest001
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    ImagePlugin::PlSize plSize;
    pngDecoder->SetSource(*streamPtr.release());
    pngDecoder->GetImageSize(2, plSize);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest001 end";
}

/**
 * @tc.name: GetImageSizeTest002
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetImageSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    ImagePlugin::PlSize plSize;
    pngDecoder->GetImageSize(0, plSize);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest002 end";
}

/**
 * @tc.name: GetImageSizeTest003
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetImageSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    pngDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    pngDecoder->GetImageSize(0, plSize);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest003 end";
}

/**
 * @tc.name: GetImageSizeTest004
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetImageSizeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest004 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(true);
    pngDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    pngDecoder->GetImageSize(0, plSize);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest004 end";
}

/**
 * @tc.name: GetImageSizeTest005
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetImageSizeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest005 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(true);
    pngDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    pngDecoder->GetImageSize(0, plSize);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest005 end";
}

/**
 * @tc.name: GetImageSizeTest006
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetImageSizeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest006 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    pngDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    pngDecoder->GetImageSize(0, plSize);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest006 end";
}

/**
 * @tc.name: GetImageSizeTest007
 * @tc.desc: Test of GetImageSize, cover code branch: if (state_ >= PngDecodingState::BASE_INFO_PARSED) branch: true
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetImageSizeTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest007 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    pngDecoder->SetSource(*mock.get());
    DecodeContext context;
    pngDecoder->Decode(2, context);
    ImagePlugin::PlSize plSize;
    pngDecoder->GetImageSize(0, plSize);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest007 end";
}

/**
 * @tc.name: SetDecodeOptionsTest001
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(2, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest002
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    PixelDecodeOptions opts;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest002 end";
}

/**
 * @tc.name: SetDecodeOptionsTest003
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PlPixelFormat::RGB_565;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest003 end";
}

/**
 * @tc.name: SetDecodeOptionsTest004
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest004 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest004 end";
}

/**
 * @tc.name: SetDecodeOptionsTest005
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest005 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest005 end";
}

/**
 * @tc.name: SetDecodeOptionsTest006
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest006 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PlPixelFormat::RGB_888;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest006 end";
}

/**
 * @tc.name: SetDecodeOptionsTest007
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest007 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PlPixelFormat::RGBA_F16;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest007 end";
}

/**
 * @tc.name: SetDecodeOptionsTest008
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest008 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PlPixelFormat::BGRA_8888;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest008 end";
}

/**
 * @tc.name: SetDecodeOptionsTest009
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest009 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredPixelFormat = PlPixelFormat::ARGB_8888;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest009 end";
}

/**
 * @tc.name: SetDecodeOptionsTest010
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest010 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredSize.width = 0;
    opts.desiredSize.height = 0;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest010 end";
}

/**
 * @tc.name: SetDecodeOptionsTest011
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest011 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredSize.width = 0;
    opts.desiredSize.height = 1;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest011 end";
}

/**
 * @tc.name: SetDecodeOptionsTest012
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest012 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    PixelDecodeOptions opts;
    opts.desiredSize.width = 1;
    PlImageInfo info;
    pngDecoder->SetDecodeOptions(0, opts, info);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest012 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    pngDecoder->Decode(2, context);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: DecodeTest002
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, DecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    DecodeContext context;
    pngDecoder->Decode(0, context);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest002 end";
}

/**
 * @tc.name: DecodeTest003
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, DecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    pngDecoder->Decode(2, context);
    pngDecoder->Decode(2, context);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest003 end";
}

/**
 * @tc.name: DecodeTest004
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, DecodeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest004 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    DecodeContext context;
    pngDecoder->Reset();
    pngDecoder->Decode(2, context);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest004 end";
}

/**
 * @tc.name: HasProperty001
 * @tc.desc: test HasProperty
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, HasProperty001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: HasProperty001 start";
    ImagePlugin::PngDecoder pngdcod;
    std::string key = "";
    bool haspro = pngdcod.HasProperty(key);
    ASSERT_EQ(haspro, false);
    GTEST_LOG_(INFO) << "PngDecoderTest: HasProperty001 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest001
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PromoteIncrementalDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    ProgDecodeContext context;
    pngDecoder->PromoteIncrementalDecode(2, context);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest001 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest002
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PromoteIncrementalDecodeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    ProgDecodeContext context;
    pngDecoder->PromoteIncrementalDecode(0, context);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest002 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest003
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PromoteIncrementalDecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    pngDecoder->PromoteIncrementalDecode(0, context);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest003 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest004
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PromoteIncrementalDecodeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest004 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    context.decodeContext.allocatorType = Media::AllocatorType::SHARE_MEM_ALLOC;
    pngDecoder->PromoteIncrementalDecode(0, context);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest004 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest005
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PromoteIncrementalDecodeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest005 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    context.decodeContext.allocatorType = Media::AllocatorType::SHARE_MEM_ALLOC;
    pngDecoder->Reset();
    pngDecoder->PromoteIncrementalDecode(0, context);
    bool result = (pngDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest005 end";
}

/**
 * @tc.name: ChooseFormat
 * @tc.desc: Test of ChooseFormat
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, ChooseFormat, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: ChooseFormatTest start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    PlPixelFormat outputFormat;
    png_byte destType = PNG_COLOR_TYPE_RGBA;
    pngDecoder->ChooseFormat(PlPixelFormat::BGRA_8888, outputFormat, destType);
    pngDecoder->ChooseFormat(PlPixelFormat::ARGB_8888, outputFormat, destType);
    pngDecoder->ChooseFormat(PlPixelFormat::RGB_888, outputFormat, destType);
    pngDecoder->ChooseFormat(PlPixelFormat::RGBA_F16, outputFormat, destType);
    pngDecoder->ChooseFormat(PlPixelFormat::UNKNOWN, outputFormat, destType);
    ASSERT_EQ(outputFormat, PlPixelFormat::RGBA_8888);
    pngDecoder->ChooseFormat(PlPixelFormat::RGBA_8888, outputFormat, destType);
    ASSERT_EQ(outputFormat, PlPixelFormat::RGBA_8888);
    pngDecoder->ChooseFormat(PlPixelFormat::ASTC_8X8, outputFormat, destType);
    ASSERT_EQ(outputFormat, PlPixelFormat::RGBA_8888);
    GTEST_LOG_(INFO) << "PngDecoderTest: ChooseFormatTest end";
}

/**
 * @tc.name: ConvertOriginalFormat
 * @tc.desc: Test of ConvertOriginalFormat
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, ConvertOriginalFormat, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: ConvertOriginalFormatTest start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    png_byte destination;
    pngDecoder->ConvertOriginalFormat(PNG_COLOR_TYPE_PALETTE, destination);
    ASSERT_EQ(destination, PNG_COLOR_TYPE_RGB);
    pngDecoder->ConvertOriginalFormat(PNG_COLOR_TYPE_GRAY, destination);
    ASSERT_EQ(destination, PNG_COLOR_TYPE_RGB);
    pngDecoder->ConvertOriginalFormat(PNG_COLOR_TYPE_GRAY_ALPHA, destination);
    ASSERT_EQ(destination, PNG_COLOR_TYPE_RGB);
    pngDecoder->ConvertOriginalFormat(PNG_COLOR_TYPE_RGB, destination);
    ASSERT_EQ(destination, PNG_COLOR_TYPE_RGB);
    pngDecoder->ConvertOriginalFormat(PNG_COLOR_TYPE_RGB_ALPHA, destination);
    ASSERT_EQ(destination, PNG_COLOR_TYPE_RGB_ALPHA);
    ASSERT_EQ(pngDecoder->ConvertOriginalFormat(111, destination), false);
    GTEST_LOG_(INFO) << "PngDecoderTest: ConvertOriginalFormatTest end";
}

/**
 * @tc.name: ProcessData001
 * @tc.desc: Test of ProcessData
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, ProcessData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: ProcessData001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    png_structp pngStructPtr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr,
        ImagePlugin::PngDecoder::PngErrorExit, ImagePlugin::PngDecoder::PngWarning);
    png_infop infoStructPtr = png_create_info_struct(pngStructPtr);
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    DataStreamBuffer streamData;
    uint32_t ret = pngDecoder->ProcessData(nullptr, infoStructPtr, mock.get(), streamData, 10, 20);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PngDecoderTest: ProcessData001 end";
}

/**
 * @tc.name: ProcessData002
 * @tc.desc: Test of ProcessData
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, ProcessData002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: ProcessData002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    png_structp pngStructPtr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr,
        ImagePlugin::PngDecoder::PngErrorExit, ImagePlugin::PngDecoder::PngWarning);
    png_infop infoStructPtr = png_create_info_struct(pngStructPtr);
    DataStreamBuffer streamData;
    streamData.dataSize = 4;
    const uint32_t ret = pngDecoder->ProcessData(pngStructPtr, infoStructPtr, mock.get(), streamData, 1, 20);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PngDecoderTest: ProcessData002 end";
}

/**
 * @tc.name: IncrementalRead001
 * @tc.desc: Test of IncrementalRead
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, IncrementalRead001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalRead001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    uint32_t desiredSize = 5;
    DataStreamBuffer outData;
    uint32_t ret = pngDecoder->IncrementalRead(nullptr, desiredSize, outData);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalRead001 end";
}

/**
 * @tc.name: IncrementalRead002
 * @tc.desc: Test of IncrementalRead
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, IncrementalRead002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalRead002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    DataStreamBuffer outData;
    uint32_t ret = pngDecoder->IncrementalRead(mock.get(), 0, outData);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalRead002 end";
}

/**
 * @tc.name: ReadIncrementalHead001
 * @tc.desc: Test of ReadIncrementalHead
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, ReadIncrementalHead001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: ReadIncrementalHead001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    PngImageInfo info;
    uint32_t ret = pngDecoder->ReadIncrementalHead(nullptr, info);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PngDecoderTest: ReadIncrementalHead001 end";
}

/**
 * @tc.name: IncrementalReadRows001
 * @tc.desc: Test of IncrementalReadRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, IncrementalReadRows001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalReadRows001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    uint32_t ret = pngDecoder->IncrementalReadRows(nullptr);
    ASSERT_EQ(ret, ERR_IMAGE_GET_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalReadRows001 end";
}

/**
 * @tc.name: IncrementalReadRows002
 * @tc.desc: Test of IncrementalReadRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, IncrementalReadRows002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalReadRows002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    pngDecoder->idatLength_ = 1;
    pngDecoder->incrementalLength_ = 2;
    uint32_t ret = pngDecoder->IncrementalReadRows(mock.get());
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalReadRows002 end";
}

/**
 * @tc.name: PushCurrentToDecode001
 * @tc.desc: Test of PushCurrentToDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PushCurrentToDecode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PushCurrentToDecode001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    uint32_t ret = pngDecoder->PushCurrentToDecode(nullptr);
    ASSERT_EQ(ret, ERR_IMAGE_GET_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: PushCurrentToDecode001 end";
}

/**
 * @tc.name: PushCurrentToDecode002
 * @tc.desc: Test of PushCurrentToDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PushCurrentToDecode002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PushCurrentToDecode002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    pngDecoder->idatLength_ = 0;
    uint32_t ret = pngDecoder->PushCurrentToDecode(mock.get());
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: PushCurrentToDecode002 end";
}

/**
 * @tc.name: PushCurrentToDecode003
 * @tc.desc: Test of PushCurrentToDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PushCurrentToDecode003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PushCurrentToDecode003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    pngDecoder->incrementalLength_ = 5;
    pngDecoder->idatLength_ = 20;
    pngDecoder->PushCurrentToDecode(mock.get());
    GTEST_LOG_(INFO) << "PngDecoderTest: PushCurrentToDecode003 end";
}

/**
 * @tc.name: GetDecodeFormat001
 * @tc.desc: Test of GetDecodeFormat
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetDecodeFormat001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetDecodeFormat001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    PlPixelFormat format = PlPixelFormat::RGB_888;
    PlPixelFormat outputFormat;
    PlAlphaType alphaType;
    uint32_t ret = pngDecoder->GetDecodeFormat(format, outputFormat, alphaType);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetDecodeFormat001 end";
}

/**
 * @tc.name: GetDecodeFormat002
 * @tc.desc: Test of GetDecodeFormat
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetDecodeFormat002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetDecodeFormat002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    PngImageInfo info;
    PlPixelFormat format = PlPixelFormat::RGBA_F16;
    PlPixelFormat outputFormat;
    PlAlphaType alphaType;
    info.bitDepth = 16;
    uint32_t ret = pngDecoder->GetDecodeFormat(format, outputFormat, alphaType);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetDecodeFormat002 end";
}

/**
 * @tc.name: PngErrorExit001
 * @tc.desc: Test of PngErrorExit
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PngErrorExit001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PngErrorExit001 start";
    PngDecoder png;
    png_structp pngPtr = nullptr;
    png_const_charp message;
    png.PngErrorExit(pngPtr, message);
    GTEST_LOG_(INFO) << "PngDecoderTest: PngErrorExit001 end";
}

/**
 * @tc.name: PngErrorMessage001
 * @tc.desc: Test of PngErrorMessage
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PngErrorMessage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PngErrorMessage001 start";
    PngDecoder png;
    png_structp pngPtr = nullptr;
    png_const_charp message;
    png.PngErrorMessage(pngPtr, message);
    GTEST_LOG_(INFO) << "PngDecoderTest: PngErrorMessage001 end";
}

/**
 * @tc.name: PngWarningMessage001
 * @tc.desc: Test of PngWarningMessage
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PngWarningMessage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PngWarningMessage001 start";
    PngDecoder png;
    png_structp pngPtr = nullptr;
    png_const_charp message;
    png.PngWarningMessage(pngPtr, message);
    GTEST_LOG_(INFO) << "PngDecoderTest: PngWarningMessage001 end";
}

/**
 * @tc.name: IsChunk001
 * @tc.desc: Test of IsChunk
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, IsChunk001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: IsChunk001 start";
    PngDecoder png;
    const png_byte *chunk = nullptr;
    const char *flag = nullptr;
    bool ret = png.IsChunk(chunk, flag);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PngDecoderTest: IsChunk001 end";
}

/**
 * @tc.name: IncrementalRead003
 * @tc.desc: Test of IncrementalRead
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, IncrementalRead003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalRead003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    uint32_t desiredSize = 0;
    DataStreamBuffer outData;
    outData.inputStreamBuffer = nullptr;
    uint32_t ret = pngDecoder->IncrementalRead(mock.get(), desiredSize, outData);
    ASSERT_NE(ret, ERR_IMAGE_GET_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalRead003 end";
}

/**
 * @tc.name: SaveRows001
 * @tc.desc: Test of SaveRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SaveRows001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveRows001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    DataStreamBuffer readData;
    readData.inputStreamBuffer= new uint8_t;
    png_bytep row = const_cast<png_bytep>(readData.inputStreamBuffer);
    png_uint_32 rowNum = 1;
    pngDecoder->SaveRows(row, rowNum);
    delete readData.inputStreamBuffer;
    readData.inputStreamBuffer = nullptr;
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveRows001 end";
}

/**
 * @tc.name: SaveRows002
 * @tc.desc: Test of SaveRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SaveRows002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveRows002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    DataStreamBuffer readData;
    readData.inputStreamBuffer= new uint8_t;
    png_bytep row = const_cast<png_bytep>(readData.inputStreamBuffer);
    png_uint_32 rowNum = 0;
    pngDecoder->SaveRows(row, rowNum);
    delete readData.inputStreamBuffer;
    readData.inputStreamBuffer = nullptr;
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveRows002 end";
}

/**
 * @tc.name: SaveInterlacedRows001
 * @tc.desc: Test of SaveInterlacedRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SaveInterlacedRows001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveInterlacedRows001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    png_bytep row = nullptr;
    png_uint_32 rowNum = 0;
    int pass = 0;
    pngDecoder->SaveInterlacedRows(row, rowNum, pass);
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveInterlacedRows001 end";
}

/**
 * @tc.name: SaveInterlacedRows002
 * @tc.desc: Test of SaveInterlacedRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SaveInterlacedRows002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveInterlacedRows002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    DataStreamBuffer readData;
    readData.inputStreamBuffer= new uint8_t;
    png_bytep row = const_cast<png_bytep>(readData.inputStreamBuffer);
    png_uint_32 rowNum = 1;
    int pass = 0;
    pngDecoder->SaveInterlacedRows(row, rowNum, pass);
    delete readData.inputStreamBuffer;
    readData.inputStreamBuffer = nullptr;
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveInterlacedRows002 end";
}

/**
 * @tc.name: GetAllRows001
 * @tc.desc: Test of GetAllRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetAllRows001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetAllRows001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    png_structp pngPtr = nullptr;
    png_bytep row = nullptr;
    png_uint_32 rowNum = 0;
    int pass = 0;
    pngDecoder->GetAllRows(pngPtr, row, rowNum, pass);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetAllRows001 end";
}

/**
 * @tc.name: GetAllRows002
 * @tc.desc: Test of GetAllRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetAllRows002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetAllRows002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    png_structp pngPtr = png_create_read_struct(PNG_LIBPNG_VER_STRING,
        nullptr, pngDecoder->PngErrorExit, pngDecoder->PngWarning);
    DataStreamBuffer readData;
    readData.inputStreamBuffer= new uint8_t;
    png_bytep row = const_cast<png_bytep>(readData.inputStreamBuffer);
    png_uint_32 rowNum = 0;
    int pass = 0;
    pngDecoder->GetAllRows(pngPtr, row, rowNum, pass);
    delete readData.inputStreamBuffer;
    readData.inputStreamBuffer = nullptr;
    GTEST_LOG_(INFO) << "PngDecoderTest: GetAllRows002 end";
}

/**
 * @tc.name: PushAllToDecode001
 * @tc.desc: Test of PushAllToDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PushAllToDecode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PushAllToDecode001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    InputDataStream *stream = nullptr;
    size_t bufferSize = 0;
    size_t length = 0;
    uint32_t ret = pngDecoder->PushAllToDecode(stream, bufferSize, length);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PngDecoderTest: PushAllToDecode001 end";
}

/**
 * @tc.name: PushAllToDecode002
 * @tc.desc: Test of PushAllToDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PushAllToDecode002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PushAllToDecode002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    size_t bufferSize = 1;
    size_t length = 1;
    uint32_t ret = pngDecoder->PushAllToDecode(mock.get(), bufferSize, length);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: PushAllToDecode002 end";
}

/**
 * @tc.name: IncrementalReadRows003
 * @tc.desc: Test of IncrementalReadRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, IncrementalReadRows003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalReadRows003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    pngDecoder->pngStructPtr_ = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr,
        pngDecoder->PngErrorExit, pngDecoder->PngWarning);
    pngDecoder->idatLength_ = 0;
    uint32_t ret = pngDecoder->IncrementalReadRows(mock.get());
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalReadRows003 end";
}

/**
 * @tc.name: ConfigInfo
 * @tc.desc: Test of ConfigInfo
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, ConfigInfo001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: ConfigInfo001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    NinePatchListener nine;
    PixelDecodeOptions opts;
    opts.desiredPixelFormat =  PlPixelFormat::RGB_565;
    nine.patch_ = new PngNinePatchRes;
    pngDecoder->idatLength_ = 1;
    uint32_t ret = pngDecoder->ConfigInfo(opts);
    ASSERT_EQ(ret, SUCCESS);
    delete nine.patch_;
    nine.patch_ = nullptr;
    GTEST_LOG_(INFO) << "PngDecoderTest: ConfigInfo001 end";
}

/**
 * @tc.name: DoOneTimeDecode001
 * @tc.desc: Test of DoOneTimeDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, DoOneTimeDecode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: DoOneTimeDecode001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    DecodeContext context;
    pngDecoder->idatLength_ = 0;
    uint32_t ret = pngDecoder->DoOneTimeDecode(context);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "PngDecoderTest: DoOneTimeDecode001 end";
}

/**
 * @tc.name: DoOneTimeDecode002
 * @tc.desc: Test of DoOneTimeDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, DoOneTimeDecode002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: DoOneTimeDecode002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    DecodeContext context;
    pngDecoder->idatLength_ = 1;
    uint32_t ret = pngDecoder->DoOneTimeDecode(context);
    ASSERT_NE(ret, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: DoOneTimeDecode002 end";
}

/**
 * @tc.name: FinishOldDecompress001
 * @tc.desc: Test of FinishOldDecompress
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, FinishOldDecompress001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: FinishOldDecompress001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    bool ret = pngDecoder->FinishOldDecompress();
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: FinishOldDecompress001 end";
}

/**
 * @tc.name: FinishOldDecompress002
 * @tc.desc: Test of FinishOldDecompress
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, FinishOldDecompress002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: FinishOldDecompress002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    pngDecoder->state_ = PngDecodingState::IMAGE_ERROR;
    bool ret = pngDecoder->FinishOldDecompress();
    ASSERT_NE(ret, false);
    GTEST_LOG_(INFO) << "PngDecoderTest: FinishOldDecompress002 end";
}

/**
 * @tc.name: InitPnglib001
 * @tc.desc: Test of InitPnglib
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, InitPnglib001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: InitPnglib001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    bool ret = pngDecoder->InitPnglib();
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: InitPnglib001 end";
}

/**
 * @tc.name: DealNinePatch001
 * @tc.desc: Test of DealNinePatch
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, DealNinePatch001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: DealNinePatch001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    const  PixelDecodeOptions opts;
    pngDecoder->ninePatch_.patch_ = new PngNinePatchRes;
    pngDecoder->DealNinePatch(opts);
    delete pngDecoder->ninePatch_.patch_;
    pngDecoder->ninePatch_.patch_ = nullptr;
    GTEST_LOG_(INFO) << "PngDecoderTest: DealNinePatch001 end";
}

/**
 * @tc.name: ReadUserChunk001
 * @tc.desc: Test of ReadUserChunk
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, ReadUserChunk001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: ReadUserChunk001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    png_structp png_ptr = nullptr;
    png_unknown_chunkp chunk = nullptr;
    uint32_t ret = pngDecoder->ReadUserChunk(png_ptr, chunk);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: ReadUserChunk001 end";
}

/**
 * @tc.name: GetInterlacedRows001
 * @tc.desc: Test of GetInterlacedRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetInterlacedRows001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetInterlacedRows001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    DataStreamBuffer readData;
    png_structp pngPtr = nullptr;
    png_bytep row = nullptr;
    png_uint_32 rowNum = 0;
    int pass = 0;
    pngDecoder->GetInterlacedRows(pngPtr, row, rowNum, pass);
    pngPtr = png_create_read_struct(PNG_LIBPNG_VER_STRING,
        nullptr, pngDecoder->PngErrorExit, pngDecoder->PngWarning);
    row = const_cast<png_bytep>(readData.inputStreamBuffer);
    pngDecoder->GetInterlacedRows(pngPtr, row, rowNum, pass);
    ASSERT_NE(pngPtr, nullptr);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetInterlacedRows001 end";
}

/**
 * @tc.name: PngWarning001
 * @tc.desc: Test of PngWarning
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PngWarning001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PngWarning001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    png_const_charp message = nullptr;
    png_structp pngPtr = nullptr;
    pngDecoder->PngWarning(pngPtr, message);
    GTEST_LOG_(INFO) << "PngDecoderTest: PngWarning001 end";
}

/**
 * @tc.name: PushCurrentToDecode004
 * @tc.desc: Test of PushCurrentToDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PushCurrentToDecode004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PushCurrentToDecode004 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    pngDecoder->incrementalLength_ = 20;
    pngDecoder->idatLength_ = 5;
    auto ret = pngDecoder->PushCurrentToDecode(mock.get());
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PngDecoderTest: PushCurrentToDecode004 end";
}

/**
 * @tc.name: AllocOutputBuffer001
 * @tc.desc: Test of AllocOutputBuffer
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, AllocOutputBuffer001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: AllocOutputBuffer001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    ImagePlugin::DecodeContext context;
    auto ret = pngDecoder->AllocOutputBuffer(context);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PngDecoderTest: AllocOutputBuffer001 end";
}

/**
 * @tc.name: AllocOutputBuffer002
 * @tc.desc: Test of AllocOutputBuffer
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, AllocOutputBuffer002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: AllocOutputBuffer002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    ImagePlugin::DecodeContext context;
    context.allocatorType = Media::AllocatorType::DMA_ALLOC;
    auto ret = pngDecoder->AllocOutputBuffer(context);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PngDecoderTest: AllocOutputBuffer002 end";
}

/**
 * @tc.name: FinishOldDecompress003
 * @tc.desc: Test of FinishOldDecompress
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, FinishOldDecompress003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: FinishOldDecompress003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    pngDecoder->state_ = PngDecodingState::SOURCE_INITED;
    bool ret = pngDecoder->FinishOldDecompress();
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PngDecoderTest: FinishOldDecompress003 end";
}

/**
 * @tc.name: FinishOldDecompress004
 * @tc.desc: Test of FinishOldDecompress
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, FinishOldDecompress004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: FinishOldDecompress004 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    pngDecoder->state_ = PngDecodingState::IMAGE_DECODED;
    pngDecoder->pngStructPtr_ = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr,
        pngDecoder->PngErrorExit, pngDecoder->PngWarning);
    bool ret = pngDecoder->FinishOldDecompress();
    ASSERT_NE(ret, false);
    GTEST_LOG_(INFO) << "PngDecoderTest: FinishOldDecompress004 end";
}

/**
 * @tc.name: GetImageIdatSize001
 * @tc.desc: Test of GetImageIdatSize
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetImageIdatSize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageIdatSize001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    uint32_t ret = pngDecoder->GetImageIdatSize(mock.get());
    ASSERT_NE(ret, 0);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageIdatSize001 end";
}

/**
 * @tc.name: SaveInterlacedRows003
 * @tc.desc: Test of SaveInterlacedRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SaveInterlacedRows003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveInterlacedRows003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    DataStreamBuffer readData;
    png_bytep row = const_cast<png_bytep>(readData.inputStreamBuffer);
    png_uint_32 rowNum = 0;
    int pass = 0;
    pngDecoder->SaveInterlacedRows(row, rowNum, pass);
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveInterlacedRows003 end";
}

/**
 * @tc.name: SetDecodeOptionsTest013
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest013 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    pngDecoder->state_ = PngDecodingState::BASE_INFO_PARSED;
    auto result = pngDecoder->SetDecodeOptions(0, opts, info);
    ASSERT_EQ(result, 0);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest013 end";
}

/**
 * @tc.name: DecodeTest005
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, DecodeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest005 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    DecodeContext context;
    pngDecoder->pngStructPtr_ = nullptr;
    uint32_t result = pngDecoder->Decode(0, context);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    ASSERT_EQ(result, ERR_IMAGE_INIT_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest005 end";
}

/**
 * @tc.name: DecodeTest006
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, DecodeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest006 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    DecodeContext context;
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    auto streamPtr = BufferSourceStream::CreateSourceStream(data.get(), size);
    pngDecoder->SetSource(*streamPtr.release());
    pngDecoder->state_ = PngDecodingState::IMAGE_ERROR;
    uint32_t result = pngDecoder->Decode(0, context);
    ASSERT_NE(result, ERR_IMAGE_INIT_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeTest006 end";
}

/**
 * @tc.name: AllocOutputBuffer003
 * @tc.desc: Test of AllocOutputBuffer
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, AllocOutputBuffer003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: AllocOutputBuffer003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    ImagePlugin::DecodeContext context;
    context.allocatorType = Media::AllocatorType::DEFAULT;
    auto ret = pngDecoder->AllocOutputBuffer(context);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PngDecoderTest: AllocOutputBuffer003 end";
}

/**
 * @tc.name: AllocOutputBuffer004
 * @tc.desc: Test of AllocOutputBuffer
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, AllocOutputBuffer004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: AllocOutputBuffer004 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    ImagePlugin::DecodeContext context;
    context.allocatorType = Media::AllocatorType::DMA_ALLOC;
    pngDecoder->pngImageInfo_.rowDataSize = 1;
    pngDecoder->pngImageInfo_.height = 1;
    auto ret = pngDecoder->AllocOutputBuffer(context);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PngDecoderTest: AllocOutputBuffer004 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest006
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PromoteIncrementalDecodeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest006 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    ProgDecodeContext context;
    pngDecoder->pngStructPtr_ = nullptr;
    context.decodeContext.allocatorType = Media::AllocatorType::SHARE_MEM_ALLOC;
    uint32_t result = pngDecoder->PromoteIncrementalDecode(0, context);
    ASSERT_EQ(result, ERR_IMAGE_INIT_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest006 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest007
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PromoteIncrementalDecodeTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest007 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    context.decodeContext.pixelsBuffer.buffer  = malloc(1);
    pngDecoder->state_ = PngDecodingState::IMAGE_DECODING;
    uint32_t result = pngDecoder->PromoteIncrementalDecode(0, context);
    ASSERT_NE(result, ERR_IMAGE_MALLOC_ABNORMAL);
    free(context.decodeContext.pixelsBuffer.buffer);
    context.decodeContext.pixelsBuffer.buffer = nullptr;
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest007 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest008
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PromoteIncrementalDecodeTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest008 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    ProgDecodeContext context;
    pngDecoder->state_ = PngDecodingState::IMAGE_ERROR;
    uint32_t result = pngDecoder->PromoteIncrementalDecode(0, context);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest008 end";
}

/**
 * @tc.name: GetDecodeFormat003
 * @tc.desc: Test of GetDecodeFormat
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetDecodeFormat003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetDecodeFormat003 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    PlPixelFormat format = PlPixelFormat::ALPHA_8;
    PlPixelFormat outputFormat;
    PlAlphaType alphaType;
    pngDecoder->pngImageInfo_.bitDepth = 16;
    uint32_t ret = pngDecoder->GetDecodeFormat(format, outputFormat, alphaType);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetDecodeFormat003 end";
}

/**
 * @tc.name: GetImageSizeTest008
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetImageSizeTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest008 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    pngDecoder->pngStructPtr_ = nullptr;
    pngDecoder->pngInfoPtr_ = nullptr;
    ImagePlugin::PlSize plSize;
    uint32_t result =pngDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, ERR_IMAGE_INIT_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest008 end";
}

/**
 * @tc.name: GetImageSizeTest009
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetImageSizeTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest009 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(true);
    pngDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    pngDecoder->state_ = PngDecodingState::BASE_INFO_PARSED;
    uint32_t result = pngDecoder->GetImageSize(0, plSize);
    ASSERT_EQ(result, 0);
    GTEST_LOG_(INFO) << "PngDecoderTest: GetImageSizeTest009 end";
}

/**
 * @tc.name: IncrementalRead004
 * @tc.desc: Test of IncrementalRead
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, IncrementalRead004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalRead004 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    pngDecoder->SetSource(*mock.get());
    uint32_t desiredSize = 5;
    DataStreamBuffer outData;
    outData.dataSize = 1;
    uint32_t ret = pngDecoder->IncrementalRead(mock.get(), desiredSize, outData);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
    GTEST_LOG_(INFO) << "PngDecoderTest: IncrementalRead004 end";
}

/**
 * @tc.name: SaveInterlacedRows004
 * @tc.desc: Test of SaveInterlacedRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SaveInterlacedRows004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveInterlacedRows004 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    png_bytep row = new uint8_t;
    pngDecoder->firstRow_ = 3;
    pngDecoder->lastRow_ = 1;
    pngDecoder->pngImageInfo_.rowDataSize = 2;
    png_uint_32 rowNum = 2;
    int pass = 0;
    pngDecoder->SaveInterlacedRows(row, rowNum, pass);
    pass = 1;
    pngDecoder->outputRowsNum_ = 1;
    pngDecoder->SaveInterlacedRows(row, rowNum, pass);
    pass = 1;
    pngDecoder->pngImageInfo_.numberPasses = 2;
    pngDecoder->SaveInterlacedRows(row, rowNum, pass);
    ASSERT_NE(row, nullptr);
    delete  row;
    row = nullptr;
    GTEST_LOG_(INFO) << "PngDecoderTest: SaveInterlacedRows004 end";
}

/**
 * @tc.name: GetInterlacedRows002
 * @tc.desc: Test of GetInterlacedRows
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, GetInterlacedRows002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: GetInterlacedRows002 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    png_uint_32 rowNum = 0;
    int pass = 0;
    png_structp pngPtr = png_create_read_struct(PNG_LIBPNG_VER_STRING,
        nullptr, pngDecoder->PngErrorExit, pngDecoder->PngWarning);
    png_bytep row = new uint8_t;
    pngDecoder->GetInterlacedRows(pngPtr, row, rowNum, pass);
    ASSERT_NE(pngPtr, nullptr);
    delete row;
    row = nullptr;
    GTEST_LOG_(INFO) << "PngDecoderTest: GetInterlacedRows002 end";
}

/**
 * @tc.name: PromoteIncrementalDecodeTest009
 * @tc.desc: Test of PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, PromoteIncrementalDecodeTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest009 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    pngDecoder->pngStructPtr_ = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr,
        pngDecoder->PngErrorExit, pngDecoder->PngWarning);
    pngDecoder->pngInfoPtr_ = png_create_info_struct(pngDecoder->pngStructPtr_);
    ProgDecodeContext context;
    pngDecoder->pngImageInfo_.rowDataSize = 0;
    pngDecoder->pngImageInfo_.height = 0;
    pngDecoder->state_ = PngDecodingState::IMAGE_DECODING;
    context.decodeContext.pixelsBuffer.buffer = nullptr;
    context.decodeContext.allocatorType = Media::AllocatorType::SHARE_MEM_ALLOC;
    uint32_t result = pngDecoder->PromoteIncrementalDecode(0, context);
    ASSERT_EQ(result, ERR_IMAGE_MALLOC_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: PromoteIncrementalDecodeTest009 end";
}

/**
 * @tc.name: DecodeHeader001
 * @tc.desc: Test of DecodeHeader
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, DecodeHeader001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeHeader001 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    pngDecoder->inputStreamPtr_ = mock.get();
    mock->returnValue_ = true;
    pngDecoder->decodeHeadFlag_ = true;
    pngDecoder->pngImageInfo_.width = 0;
    pngDecoder->pngImageInfo_.height = 0;
    uint32_t result = pngDecoder->DecodeHeader();
    ASSERT_EQ(result, ERR_IMAGE_GET_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: DecodeHeader001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest014
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, SetDecodeOptionsTest014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest014 start";
    auto pngDecoder = std::make_shared<PngDecoder>();
    uint32_t index = 0;
    PixelDecodeOptions opts;
    PlImageInfo info;
    pngDecoder->pngStructPtr_ = nullptr;
    pngDecoder->pngInfoPtr_ = nullptr;
    uint32_t result = pngDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_INIT_ABNORMAL);
    GTEST_LOG_(INFO) << "PngDecoderTest: SetDecodeOptionsTest014 end";
}
} // namespace Multimedia
} // namespace OHOS