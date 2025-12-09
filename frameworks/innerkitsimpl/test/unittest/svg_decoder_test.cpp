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
#define private public
#include "buffer_source_stream.h"
#include "mock_data_stream.h"
#include "plugin_export.h"
#include "svg_decoder.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {

constexpr static int32_t OPTS_DESIREDSIZE = 2;
static const std::string IMAGE_SVG_SRC = "/data/local/tmp/image/test.svg";
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
    ImagePlugin::Size plSize;
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
    ImagePlugin::Size plSize;
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
    ImagePlugin::Size plSize;
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
    ImagePlugin::Size plSize;
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
    ImagePlugin::Size plSize;
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
    ImagePlugin::Size plSize;
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
    opts.desiredPixelFormat = PixelFormat::RGB_565;
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
    ImagePlugin::Size plSize;
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
 * @tc.name: DoSetDecodeOptionsTest002
 * @tc.desc: Verify that DoSetDecodeOptions returns Media::ERROR when the SVG DOM container size is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DoSetDecodeOptionsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptionsTest002 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    ASSERT_NE(svgDecoder, nullptr);

    PixelDecodeOptions opts;
    PlImageInfo info;
    auto streamPtr = SkStream::MakeFromFile(IMAGE_SVG_SRC.c_str());
    ASSERT_NE(streamPtr, nullptr);
    svgDecoder->svgDom_ = SkSVGDOM::MakeFromStream(*streamPtr);
    ASSERT_NE(svgDecoder->svgDom_, nullptr);
    svgDecoder->svgDom_->setContainerSize(SkSize::MakeEmpty());

    uint32_t result = svgDecoder->DoSetDecodeOptions(0, opts, info);
    EXPECT_EQ(result, Media::ERROR);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptionsTest002 end";
}

/**
 * @tc.name: DoSetDecodeOptionsTest003
 * @tc.desc: Verify that DoSetDecodeOptions returns ERR_MEDIA_INVALID_OPERATION when the desired size is invalid
 *           and the crop rectangle is set with SCALE_FIRST strategy.
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DoSetDecodeOptionsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptionsTest003 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    ASSERT_NE(svgDecoder, nullptr);
    PixelDecodeOptions opts;
    PlImageInfo info;
    auto streamPtr = SkStream::MakeFromFile(IMAGE_SVG_SRC.c_str());
    ASSERT_NE(streamPtr, nullptr);
    svgDecoder->svgDom_ = SkSVGDOM::MakeFromStream(*streamPtr);
    ASSERT_NE(svgDecoder->svgDom_, nullptr);
    svgDecoder->svgDom_->setContainerSize(SkSize::Make(1, 1));
    opts.desiredSize.width = -1;
    opts.desiredSize.height = -1;
    opts.CropRect = {1, 1, 1, 1};
    opts.cropAndScaleStrategy = CropAndScaleStrategy::SCALE_FIRST;

    uint32_t result = svgDecoder->DoSetDecodeOptions(0, opts, info);
    EXPECT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptionsTest003 end";
}

/**
 * @tc.name: DoSetDecodeOptionsTest004
 * @tc.desc: Verify that DoSetDecodeOptions returns ERR_MEDIA_INVALID_OPERATION when the crop rectangle is invalid
 *           and the SCALE_FIRST strategy is used.
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DoSetDecodeOptionsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptionsTest004 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    ASSERT_NE(svgDecoder, nullptr);
    PixelDecodeOptions opts;
    PlImageInfo info;
    auto streamPtr = SkStream::MakeFromFile(IMAGE_SVG_SRC.c_str());
    ASSERT_NE(streamPtr, nullptr);
    svgDecoder->svgDom_ = SkSVGDOM::MakeFromStream(*streamPtr);
    ASSERT_NE(svgDecoder->svgDom_, nullptr);
    svgDecoder->svgDom_->setContainerSize(SkSize::Make(1, 1));
    opts.desiredSize.width = 1;
    opts.desiredSize.height = 1;
    opts.CropRect = {-1, -1, 0, 0};
    opts.cropAndScaleStrategy = CropAndScaleStrategy::SCALE_FIRST;

    uint32_t result = svgDecoder->DoSetDecodeOptions(0, opts, info);
    EXPECT_EQ(result, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptionsTest004 end";
}

/**
 * @tc.name: DoSetDecodeOptionsTest005
 * @tc.desc: Verify that DoSetDecodeOptions returns Media::SUCCESS when the desired size and crop rectangle
 *           are valid with the SCALE_FIRST strategy.
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DoSetDecodeOptionsTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptionsTest005 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    ASSERT_NE(svgDecoder, nullptr);
    PixelDecodeOptions opts;
    PlImageInfo info;
    auto streamPtr = SkStream::MakeFromFile(IMAGE_SVG_SRC.c_str());
    ASSERT_NE(streamPtr, nullptr);
    svgDecoder->svgDom_ = SkSVGDOM::MakeFromStream(*streamPtr);
    ASSERT_NE(svgDecoder->svgDom_, nullptr);
    svgDecoder->svgDom_->setContainerSize(SkSize::Make(1, 1));
    opts.desiredSize.width = OPTS_DESIREDSIZE;
    opts.desiredSize.height = OPTS_DESIREDSIZE;
    opts.CropRect = {1, 1, 1, 1};
    opts.cropAndScaleStrategy = CropAndScaleStrategy::SCALE_FIRST;

    uint32_t result = svgDecoder->DoSetDecodeOptions(0, opts, info);
    EXPECT_EQ(result, Media::SUCCESS);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptionsTest005 end";
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
    Size size;
    uint32_t ret = svgDecoder->DoGetImageSize(index, size);
    ASSERT_EQ(ret, Media::ERROR);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoGetImageSize001 end";
}

/**
 * @tc.name: DoGetImageSizeTest002
 * @tc.desc: Verify that DoGetImageSize returns Media::ERROR when the SVG DOM container size is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DoGetImageSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoGetImageSizeTest002 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    ASSERT_NE(svgDecoder, nullptr);
    auto streamPtr = SkStream::MakeFromFile(IMAGE_SVG_SRC.c_str());
    ASSERT_NE(streamPtr, nullptr);
    svgDecoder->svgDom_ = SkSVGDOM::MakeFromStream(*streamPtr);
    ASSERT_NE(svgDecoder->svgDom_, nullptr);
    svgDecoder->svgDom_->setContainerSize(SkSize::MakeEmpty());

    Size size;
    uint32_t ret = svgDecoder->DoGetImageSize(0, size);
    ASSERT_EQ(ret, Media::ERROR);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoGetImageSizeTest002 end";
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

/**
 * @tc.name: PluginExternalCreateTest001
 * @tc.desc: Test of PluginExternalCreate when not find class or creator is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, PluginExternalCreateTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: PluginExternalCreateTest001 start";
    std::string className = "";
    auto result = PluginExternalCreate(className);
    ASSERT_EQ(result, nullptr);
    className = "#ImplClassType";
    result = PluginExternalCreate(className);
    ASSERT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "SvgDecoderTest: PluginExternalCreateTest001 end";
}

/**
 * @tc.name: DecodeFailureTest001
 * @tc.desc: Test Decode failure branch
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DecodeFailureTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DecodeFailureTest001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    ASSERT_NE(svgDecoder, nullptr);
    svgDecoder->state_ = SvgDecoder::SvgDecodingState::IMAGE_DECODING;
    svgDecoder->svgDom_ = nullptr;
    DecodeContext context;
    uint32_t ret = svgDecoder->Decode(0, context);
    ASSERT_NE(ret, Media::SUCCESS);
    ASSERT_EQ(svgDecoder->state_, SvgDecoder::SvgDecodingState::IMAGE_ERROR);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DecodeFailureTest001 end";
}

/**
 * @tc.name: DoSetDecodeOptionsFailureTest001
 * @tc.desc: Test SetDecodeOptions failure in DoSetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DoSetDecodeOptionsFailureTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptionsFailureTest001 start";
    
    auto svgDecoder = std::make_shared<SvgDecoder>();
    ASSERT_NE(svgDecoder, nullptr);
    
    auto mock = std::make_shared<MockInputDataStream>();
    svgDecoder->SetSource(*mock.get());
    
    svgDecoder->state_ = SvgDecoder::SvgDecodingState::SOURCE_INITED;
    
    PixelDecodeOptions opts;
    opts.desiredSize.width = OPTS_DESIREDSIZE;
    opts.desiredSize.height = OPTS_DESIREDSIZE;
    PlImageInfo info;
    
    uint32_t ret = svgDecoder->SetDecodeOptions(0, opts, info);
    
    ASSERT_NE(ret, Media::SUCCESS);
    ASSERT_EQ(svgDecoder->state_, SvgDecoder::SvgDecodingState::BASE_INFO_PARSING);
    
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoSetDecodeOptionsFailureTest001 end";
}

/**
 * @tc.name: DoGetImageSizeFailureTest001
 * @tc.desc: Test GetImageSize failure in DoGetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(SvgDecoderTest, DoGetImageSizeFailureTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoGetImageSizeFailureTest001 start";
    auto svgDecoder = std::make_shared<SvgDecoder>();
    ASSERT_NE(svgDecoder, nullptr);
    
    auto mock = std::make_shared<MockInputDataStream>();
    svgDecoder->SetSource(*mock.get());
    svgDecoder->state_ = SvgDecoder::SvgDecodingState::SOURCE_INITED;
    Size size;
    uint32_t ret = svgDecoder->GetImageSize(0, size);
    
    ASSERT_NE(ret, Media::SUCCESS);
    ASSERT_EQ(svgDecoder->state_, SvgDecoder::SvgDecodingState::BASE_INFO_PARSING);
    ASSERT_EQ(size.width, 0);
    ASSERT_EQ(size.height, 0);
    GTEST_LOG_(INFO) << "SvgDecoderTest: DoGetImageSizeFailureTest001 end";
}
}
}