/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "image_source.h"
#include "image_log.h"
#include "tiff_decoder.h"
#include "color_utils.h"
#include "pixel_map.h"
#include "buffer_source_stream.h"
#include "file_source_stream.h"
#include "image_system_properties.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace ImagePlugin {

namespace {
    const std::string IMAGE_TIFF_NO_ICC_PATH = "/data/local/tmp/image/output.tiff";
    const std::string IMAGE_TIFF_DISPLAY_P3_PATH = "/data/local/tmp/image/output_icc_Display_P3.tiff";
    const std::string IMAGE_TIFF_D50_XYZ_PATH = "/data/local/tmp/image/output_icc_D50_XYZ.tiff";
    const int32_t MOCK_SIZE = 300;
    const int32_t MOCK_INDEX = 3;

    const uint32_t MOCK_TELL = 10;
    const uint32_t MOCK_SIZE_100 = 100;
    const uint32_t MOCK_SIZE_200 = 200;
    const uint32_t MOCK_SEEK_POS = 20;
    const uint32_t MOCK_SEEK_OFFSET = 5;
    const uint32_t MOCK_CUR_POS = 15;
    const int32_t MOCK_NEG_OFFSET = -10;
    const int32_t MOCK_INVALID_WHENCE = 999;
}

class TiffDecoderTest : public testing::Test {
public:
    TiffDecoderTest() {}
    ~TiffDecoderTest() {}
private:
    void CreatePixelMapTest(const std::string &path, bool isSupportICC);
    void FreeContext(DecodeContext &decodeContext);
};

void TiffDecoderTest::CreatePixelMapTest(const std::string &path, bool isSupportICC)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/tiff";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMap(0, decodeOpts, errorCode);
    ASSERT_NE(pixelMap, nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    ASSERT_EQ(imageSource->mainDecoder_->IsSupportICCProfile(), isSupportICC);
#endif
}

void TiffDecoderTest::FreeContext(DecodeContext &context)
{
    if (context.pixelsBuffer.buffer != nullptr) {
        if (context.freeFunc != nullptr) {
            context.freeFunc(context.pixelsBuffer.buffer, context.pixelsBuffer.context,
                context.pixelsBuffer.bufferSize);
        } else {
            PixelMap::ReleaseMemory(context.allocatorType, context.pixelsBuffer.buffer,
                context.pixelsBuffer.context, context.pixelsBuffer.bufferSize);
        }
    }
}

/**
 * @tc.name: ImageSourceDecodeTest001
 * @tc.desc: Test decoding TIFF images and judging support ICC Profile.
 * @tc.type: FUNC
 */
HWTEST_F(TiffDecoderTest, ImageSourceDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffDecoderTest: ImageSourceDecodeTest001 start";
    std::vector<std::pair<std::string, bool>> paths {
        { IMAGE_TIFF_NO_ICC_PATH, true },
        { IMAGE_TIFF_DISPLAY_P3_PATH, true },
        { IMAGE_TIFF_D50_XYZ_PATH, true }};
    for (const auto &pathPair : paths) {
        CreatePixelMapTest(pathPair.first, pathPair.second);
    }
    GTEST_LOG_(INFO) << "TiffDecoderTest: ImageSourceDecodeTest001 end";
}

/**
 * @tc.name: SetSourceTest001
 * @tc.desc: Test of TiffDecoder set source but data is nullptr or data len is zero.
 * @tc.type: FUNC
 */
HWTEST_F(TiffDecoderTest, SetSourceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffDecoderTest: SetSourceTest001 start";
    BufferSourceStream bufferStream(nullptr, 0, 0);
    std::shared_ptr<TiffDecoder> tiffDecoder = std::make_shared<TiffDecoder>();
    ASSERT_NE(tiffDecoder, nullptr);
    tiffDecoder->SetSource(bufferStream);
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_TIFF_NO_ICC_PATH);
    tiffDecoder->SetSource(*fileSourceStream.get());
    ASSERT_NE(tiffDecoder->tifCodec_, nullptr);
    GTEST_LOG_(INFO) << "TiffDecoderTest: SetSourceTest001 end";
}

/**
 * @tc.name: ResetTest001
 * @tc.desc: Test of TiffDecoder reset.
 * @tc.type: FUNC
 */
HWTEST_F(TiffDecoderTest, ResetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffDecoderTest: ResetTest001 start";
    BufferSourceStream bufferStream(nullptr, 0, 0);
    std::shared_ptr<TiffDecoder> tiffDecoder = std::make_shared<TiffDecoder>();
    ASSERT_NE(tiffDecoder, nullptr);
    tiffDecoder->Reset();
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_TIFF_NO_ICC_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    tiffDecoder->SetSource(*fileSourceStream.get());
    ASSERT_NE(tiffDecoder->tifCodec_, nullptr);
    tiffDecoder->Reset();
    ASSERT_EQ(tiffDecoder->tifCodec_, nullptr);
    GTEST_LOG_(INFO) << "TiffDecoderTest: ResetTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest001
 * @tc.desc: Test of TiffDecoder SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(TiffDecoderTest, SetDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffDecoderTest: SetDecodeOptionsTest001 start";
    std::shared_ptr<TiffDecoder> tiffDecoder = std::make_shared<TiffDecoder>();
    ASSERT_NE(tiffDecoder, nullptr);
    PixelDecodeOptions opts;
    PlImageInfo imageInfo;
    // tifCodec_ is nullptr
    uint32_t errorCode = tiffDecoder->SetDecodeOptions(0, opts, imageInfo);
    ASSERT_EQ(errorCode, ERR_MEDIA_INVALID_PARAM);

    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_TIFF_NO_ICC_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    tiffDecoder->SetSource(*fileSourceStream.get());
    ASSERT_NE(tiffDecoder->tifCodec_, nullptr);
    //index is not 0
    errorCode = tiffDecoder->SetDecodeOptions(MOCK_INDEX, opts, imageInfo);
    ASSERT_EQ(errorCode, ERR_MEDIA_INVALID_PARAM);
    
    errorCode = tiffDecoder->SetDecodeOptions(0, opts, imageInfo);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "TiffDecoderTest: SetDecodeOptionsTest001 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: Test of TiffDecoder Decode
 * @tc.type: FUNC
 */
HWTEST_F(TiffDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffDecoderTest: DecodeTest001 start";
    std::shared_ptr<TiffDecoder> tiffDecoder = std::make_shared<TiffDecoder>();
    ASSERT_NE(tiffDecoder, nullptr);
    DecodeContext decodeContext;
    // tifCodec_ is nullptr
    uint32_t errorCode = tiffDecoder->Decode(0, decodeContext);
    ASSERT_EQ(errorCode, ERR_IMAGE_DECODE_HEAD_ABNORMAL);

    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_TIFF_NO_ICC_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    tiffDecoder->SetSource(*fileSourceStream.get());
    ASSERT_NE(tiffDecoder->tifCodec_, nullptr);

    // SetDecodeOptions not called
    errorCode = tiffDecoder->Decode(0, decodeContext);
    ASSERT_EQ(errorCode, SUCCESS);

    // SetDecodeOptions is called
    tiffDecoder->Reset();
    std::unique_ptr<FileSourceStream> fileSourceStream2 = FileSourceStream::CreateSourceStream(IMAGE_TIFF_NO_ICC_PATH);
    ASSERT_NE(fileSourceStream2, nullptr);
    tiffDecoder->SetSource(*fileSourceStream2.get());
    ASSERT_NE(tiffDecoder->tifCodec_, nullptr);
    errorCode = tiffDecoder->SetDecodeOptions(0, PixelDecodeOptions(), decodeContext.info);
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = tiffDecoder->Decode(0, decodeContext);
    ASSERT_EQ(errorCode, SUCCESS);
    FreeContext(decodeContext);
    GTEST_LOG_(INFO) << "TiffDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: GetImageSizeTest001
 * @tc.desc: Test of TiffDecoder GetImageSize when state_ is BASE_INFO_PARSED.
 * @tc.type: FUNC
 */
HWTEST_F(TiffDecoderTest, GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffDecoderTest: GetImageSizeTest001 start";
    std::shared_ptr<TiffDecoder> tiffDecoder = std::make_shared<TiffDecoder>();
    ASSERT_NE(tiffDecoder, nullptr);
    Size size;
    // tifCodec_ is nullptr
    uint32_t errorCode = tiffDecoder->GetImageSize(0, size);
    ASSERT_EQ(errorCode, ERR_IMAGE_DECODE_HEAD_ABNORMAL);

    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_TIFF_NO_ICC_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    tiffDecoder->SetSource(*fileSourceStream.get());
    ASSERT_NE(tiffDecoder->tifCodec_, nullptr);
    errorCode = tiffDecoder->GetImageSize(0, size);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "TiffDecoderTest: GetImageSizeTest001 end";
}

/**
 * @tc.name: GetSrcColorSpaceTest001
 * @tc.desc: Test of TiffDecoder GetSrcColorSpace when profile is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(TiffDecoderTest, GetSrcColorSpaceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffDecoderTest: GetSrcColorSpaceTest001 start";
#ifdef IMAGE_COLORSPACE_FLAG
    auto name = OHOS::Media::ColorUtils::GetSrcColorSpace(nullptr);
    ASSERT_EQ(name, OHOS::ColorManager::ColorSpaceName::NONE);
#endif
    GTEST_LOG_(INFO) << "TiffDecoderTest: GetSrcColorSpaceTest001 end";
}

/**
 * @tc.name: ParseICCProfileTest001
 * @tc.desc: Test of TiffDecoder ParseICCProfile
 * @tc.type: FUNC
 */
HWTEST_F(TiffDecoderTest, ParseICCProfileTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffDecoderTest: ParseICCProfileTest001 start";
    std::shared_ptr<TiffDecoder> tiffDecoder = std::make_shared<TiffDecoder>();
    ASSERT_NE(tiffDecoder, nullptr);
    tiffDecoder->Reset();
    ASSERT_EQ(tiffDecoder->tifCodec_, nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    tiffDecoder->ParseICCProfile();
    ASSERT_EQ(tiffDecoder->isSupportICCProfile_, true);
#endif
    GTEST_LOG_(INFO) << "TiffDecoderTest: ParseICCProfileTest001 end";
}

/**
 * @tc.name: AllocBufferTest001
 * @tc.desc: Test of TiffDecoder AllocBuffer
 * @tc.type: FUNC
 */
HWTEST_F(TiffDecoderTest, AllocBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffDecoderTest: AllocBufferTest001 start";
    std::shared_ptr<TiffDecoder> tiffDecoder = std::make_shared<TiffDecoder>();
    ASSERT_NE(tiffDecoder, nullptr);
    DecodeContext decodeContext;

    decodeContext.allocatorType = AllocatorType::HEAP_ALLOC;
    auto ret = tiffDecoder->AllocBuffer(decodeContext, MOCK_SIZE);
    FreeContext(decodeContext);
    decodeContext.pixelsBuffer.buffer = nullptr;
    EXPECT_TRUE(ret);

    decodeContext.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    ret = tiffDecoder->AllocBuffer(decodeContext, MOCK_SIZE);
    FreeContext(decodeContext);
    decodeContext.pixelsBuffer.buffer = nullptr;
    EXPECT_TRUE(ret);

#if !defined(CROSS_PLATFORM)
    if (ImageSystemProperties::GetDmaEnabled()) {
        decodeContext.allocatorType = AllocatorType::DMA_ALLOC;
        ret = tiffDecoder->AllocBuffer(decodeContext, MOCK_SIZE);
        FreeContext(decodeContext);
        decodeContext.pixelsBuffer.buffer = nullptr;
        EXPECT_TRUE(ret);
    }
#endif

    GTEST_LOG_(INFO) << "TiffDecoderTest: AllocBufferTest001 end";
}

class MockInputDataStream : public InputDataStream {
public:
    MockInputDataStream(uint32_t tell, uint32_t size)
        : tell_(tell), size_(size), seekCalled_(false), seekArg_(0), seekReturn_(true) {}

    bool Read(uint32_t, DataStreamBuffer&) override { return false; }
    bool Read(uint32_t, uint8_t*, uint32_t, uint32_t&) override { return false; }
    bool Peek(uint32_t, DataStreamBuffer&) override { return false; }
    bool Peek(uint32_t, uint8_t*, uint32_t, uint32_t&) override { return false; }

    uint32_t Tell() override { return tell_; }
    bool Seek(uint32_t position) override
    {
        seekCalled_ = true;
        seekArg_ = position;
        if (seekReturn_) tell_ = position;
        return seekReturn_;
    }
    size_t GetStreamSize() override { return size_; }

    void SetSeekReturn(bool ret) { seekReturn_ = ret; }
    void SetTell(uint32_t t) { tell_ = t; }

    uint32_t tell_ = 0;
    uint32_t size_ = 0;
    bool seekCalled_ = false;
    uint32_t seekArg_ = 0;
    bool seekReturn_ = true;
};

HWTEST_F(TiffDecoderTest, SeekProc_SEEK_SET_Test, TestSize.Level3)
{
    MockInputDataStream stream(MOCK_TELL, MOCK_SIZE_100);
    TiffDecoder decoder;
    toff_t ret = decoder.SeekProc(static_cast<thandle_t>(&stream), MOCK_SEEK_POS, SEEK_SET);
    EXPECT_TRUE(stream.seekCalled_);
    EXPECT_EQ(stream.seekArg_, MOCK_SEEK_POS);
    EXPECT_EQ(ret, MOCK_SEEK_POS);
}

HWTEST_F(TiffDecoderTest, SeekProc_SEEK_CUR_Test, TestSize.Level3)
{
    MockInputDataStream stream(MOCK_CUR_POS, MOCK_SIZE_100);
    TiffDecoder decoder;
    toff_t ret = decoder.SeekProc(static_cast<thandle_t>(&stream), MOCK_SEEK_OFFSET, SEEK_CUR);
    EXPECT_TRUE(stream.seekCalled_);
    EXPECT_EQ(stream.seekArg_, MOCK_CUR_POS + MOCK_SEEK_OFFSET);
    EXPECT_EQ(ret, MOCK_CUR_POS + MOCK_SEEK_OFFSET);
}

HWTEST_F(TiffDecoderTest, SeekProc_SEEK_END_Test, TestSize.Level3)
{
    MockInputDataStream stream(0, MOCK_SIZE_200);
    TiffDecoder decoder;
    toff_t ret = decoder.SeekProc(static_cast<thandle_t>(&stream), MOCK_NEG_OFFSET, SEEK_END);
    EXPECT_TRUE(stream.seekCalled_);
    EXPECT_EQ(stream.seekArg_, MOCK_SIZE_200 + MOCK_NEG_OFFSET);
    EXPECT_EQ(ret, MOCK_SIZE_200 + MOCK_NEG_OFFSET);
}

HWTEST_F(TiffDecoderTest, SeekProc_InvalidWhence_Test, TestSize.Level3)
{
    MockInputDataStream stream(0, MOCK_SIZE_100);
    TiffDecoder decoder;
    toff_t ret = decoder.SeekProc(static_cast<thandle_t>(&stream), 0, MOCK_INVALID_WHENCE);
    EXPECT_EQ(ret, static_cast<toff_t>(-1));
}

HWTEST_F(TiffDecoderTest, SeekProc_NullStream_Test, TestSize.Level3)
{
    TiffDecoder decoder;
    toff_t ret = decoder.SeekProc(nullptr, 0, SEEK_SET);
    EXPECT_EQ(ret, static_cast<toff_t>(-1));
}

HWTEST_F(TiffDecoderTest, SeekProc_SeekFail_Test, TestSize.Level3)
{
    MockInputDataStream stream(MOCK_TELL, MOCK_SIZE_100);
    stream.SetSeekReturn(false);
    TiffDecoder decoder;
    toff_t ret = decoder.SeekProc(static_cast<thandle_t>(&stream), MOCK_SEEK_POS, SEEK_SET);
    EXPECT_TRUE(stream.seekCalled_);
    EXPECT_EQ(ret, static_cast<toff_t>(-1));
}
} //ImagePlugin
} //OHOS