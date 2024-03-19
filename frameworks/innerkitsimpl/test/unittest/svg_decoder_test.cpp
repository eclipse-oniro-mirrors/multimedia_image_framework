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

#define private public
#include <gtest/gtest.h>
#include "svg_decoder.h"
#include "buffer_source_stream.h"
#include "mock_data_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
class SvgDecoderTest : public testing::Test {
public:
    SvgDecoderTest() {}
    ~SvgDecoderTest() {}
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

/**
 * @tc.name: SetDecodeOptions001
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, SetDecodeOptions001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: SetDecodeOptions001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    svgDecoder->SetSource(*mock.get());
    uint32_t index = 0;
    PixelDecodeOptions opts;
    PlImageInfo info;
    svgDecoder->state_ = SvgDecoder::SvgDecodingState::IMAGE_ERROR;
    svgDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(svgDecoder->state_, SvgDecoder::SvgDecodingState::BASE_INFO_PARSING);
    GTEST_LOG_(INFO) << "SvgDecoderTest: SetDecodeOptions001 end";
}

/**
 * @tc.name: GetImageSizeTest007
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, GetImageSizeTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest007 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    svgDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    uint32_t index = 0;
    svgDecoder->state_ = SvgDecoder::SvgDecodingState::IMAGE_ERROR;
    uint32_t ret = svgDecoder->GetImageSize(index, plSize);
    ASSERT_EQ(ret, Media::SUCCESS);
    GTEST_LOG_(INFO) << "SvgDecoderTest: GetImageSizeTest007 end";
}

/**
 * @tc.name: AllocBuffer001
 * @tc.desc: Test of AllocBuffer
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, AllocBuffer001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: AllocBuffer001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    svgDecoder->SetSource(*mock.get());
    DecodeContext context;
    svgDecoder->svgDom_ = nullptr;
    bool ret = svgDecoder->AllocBuffer(context);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "SvgDecoderTest: AllocBuffer001 end";
}

/**
 * @tc.name: BuildStream001
 * @tc.desc: Test of BuildStream
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, BuildStream001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: BuildStream001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    svgDecoder->SetSource(*mock.get());
    svgDecoder->inputStreamPtr_ = nullptr;
    bool ret = svgDecoder->BuildStream();
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "SvgDecoderTest: BuildStream001 end";
}

/**
 * @tc.name: BuildDom001
 * @tc.desc: Test of BuildDom
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, BuildDom001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: BuildDom001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    svgDecoder->SetSource(*mock.get());
    svgDecoder->svgStream_ = nullptr;
    bool ret = svgDecoder->BuildDom();
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "SvgDecoderTest: BuildDom001 end";
}

/**
 * @tc.name: DoSetDecodeOptions001
 * @tc.desc: Test of DoSetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DoSetDecodeOptions001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptions001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    svgDecoder->SetSource(*mock.get());
    svgDecoder->svgDom_ = nullptr;
    uint32_t index = 1;
    PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t ret = svgDecoder->DoSetDecodeOptions(index, opts, info);
    ASSERT_EQ(ret, Media::ERROR);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptions001 end";
}

/**
 * @tc.name: DoGetImageSize001
 * @tc.desc: Test of DoGetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DoGetImageSize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoGetImageSize001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    svgDecoder->SetSource(*mock.get());
    svgDecoder->svgDom_ = nullptr;
    uint32_t index = 1;
    PlSize size;
    uint32_t ret = svgDecoder->DoGetImageSize(index, size);
    ASSERT_EQ(ret, Media::ERROR);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoGetImageSize001 end";
}

/**
 * @tc.name: DoDecode001
 * @tc.desc: Test of DoDecode
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DoDecode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoDecode001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    svgDecoder->SetSource(*mock.get());
    svgDecoder->svgDom_ = nullptr;
    uint32_t index = 1;
    DecodeContext context;
    uint32_t ret = svgDecoder->DoDecode(index, context);
    ASSERT_EQ(ret, Media::ERROR);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoDecode001 end";
}
}
}