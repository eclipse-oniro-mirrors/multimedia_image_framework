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
#include "plugin_export.h"
#include "bmp_decoder.h"
#include "buffer_source_stream.h"
#include "image_packer.h"
#include "mock_data_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
class BmpDecoderTest : public testing::Test {
public:
    BmpDecoderTest() {}
    ~BmpDecoderTest() {}
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
 * @tc.name: GetImageSizeTest007
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, GetImageSizeTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest007 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetReturn(false);
    bmpDecoder->SetSource(*mock.get());
    ImagePlugin::PlSize plSize;
    bmpDecoder->GetImageSize(0, plSize);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest007 end";
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
 * @tc.name: SetDecodeOptionsTest005
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetDecodeOptionsTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest005 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(true);
    bmpDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    bmpDecoder->SetDecodeOptions(0, opts, info);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest005 end";
}

/**
 * @tc.name: SetDecodeOptionsTest006
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetDecodeOptionsTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest006 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    bmpDecoder->SetSource(*mock.get());
    PixelDecodeOptions opts;
    PlImageInfo info;
    bmpDecoder->SetDecodeOptions(0, opts, info);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest006 end";
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
 * @tc.name: DecodeTest003
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, DecodeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeTest003 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    DecodeContext context;
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(1);
    mock->SetReturn(true);
    bmpDecoder->SetSource(*mock.get());
    bmpDecoder->Decode(0, context);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeTest003 end";
}

/**
 * @tc.name: DecodeTest004
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, DecodeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeTest004 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    DecodeContext context;
    auto mock = std::make_shared<MockInputDataStream>();
    mock->SetStreamSize(2);
    mock->SetReturn(true);
    bmpDecoder->SetSource(*mock.get());
    bmpDecoder->Decode(0, context);
    int size = 1000;
    std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(size);
    bool result = (bmpDecoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeTest004 end";
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

/**
 * @tc.name: ConvertToAlphaTypeTest
 * @tc.desc: Test of ConvertToAlphaType
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, ConvertToAlphaTypeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: ConvertToAlphaType start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    ASSERT_EQ(bmpDecoder->ConvertToAlphaType(kOpaque_SkAlphaType), PlAlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
    ASSERT_EQ(bmpDecoder->ConvertToAlphaType(kPremul_SkAlphaType), PlAlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    ASSERT_EQ(bmpDecoder->ConvertToAlphaType(kUnpremul_SkAlphaType), PlAlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    ASSERT_EQ(bmpDecoder->ConvertToAlphaType(kUnknown_SkAlphaType), PlAlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
    GTEST_LOG_(INFO) << "BmpDecoderTest: ConvertToAlphaType end";
}

/**
 * @tc.name: ConvertToColorTypeTest
 * @tc.desc: Test of ConvertToColorType
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, ConvertToColorTypeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: ConvertToColorTypeTest start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    PlPixelFormat outputFormat;
    ASSERT_EQ(bmpDecoder->ConvertToColorType(PlPixelFormat::UNKNOWN, outputFormat), kRGBA_8888_SkColorType);
    ASSERT_EQ(bmpDecoder->ConvertToColorType(PlPixelFormat::RGBA_8888, outputFormat), kRGBA_8888_SkColorType);
    ASSERT_EQ(bmpDecoder->ConvertToColorType(PlPixelFormat::BGRA_8888, outputFormat), kBGRA_8888_SkColorType);
    ASSERT_EQ(bmpDecoder->ConvertToColorType(PlPixelFormat::ALPHA_8, outputFormat), kRGBA_8888_SkColorType);
    ASSERT_EQ(bmpDecoder->ConvertToColorType(PlPixelFormat::RGB_565, outputFormat), kRGB_565_SkColorType);
    ASSERT_EQ(bmpDecoder->ConvertToColorType(PlPixelFormat::RGB_888, outputFormat), kRGBA_8888_SkColorType);
    GTEST_LOG_(INFO) << "BmpDecoderTest: ConvertToColorTypeTest end";
}

/**
 * @tc.name: GetImageSizeTest008
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, GetImageSizeTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest008 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    uint32_t index = 0;
    ImagePlugin::PlSize plSize;
    bmpDecoder->state_ = BmpDecodingState::IMAGE_DECODING;
    uint32_t result = bmpDecoder->GetImageSize(index, plSize);
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "BmpDecoderTest: GetImageSizeTest008 end";
}

/**
 * @tc.name: SetDecodeOptionsTest007
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetDecodeOptionsTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest007 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    uint32_t index = 0;
    const PixelDecodeOptions opts;
    PlImageInfo info;
    bmpDecoder->state_ = BmpDecodingState::IMAGE_DECODING;
    uint32_t result = bmpDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(result, ERR_IMAGE_DECODE_HEAD_ABNORMAL);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest007 end";
}

/**
 * @tc.name: SetShareMemBufferTest001
 * @tc.desc: Test of SetShareMemBuffer
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetShareMemBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetShareMemBufferTest001 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    uint64_t byteCount = 0;
    DecodeContext context;
    uint32_t result = bmpDecoder->SetShareMemBuffer(byteCount, context);
    ASSERT_EQ(result, ERR_SHAMEM_DATA_ABNORMAL);
    byteCount = 4;
    result = bmpDecoder->SetShareMemBuffer(byteCount, context);
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetShareMemBufferTest001 end";
}

/**
 * @tc.name: SetContextPixelsBufferTest001
 * @tc.desc: Test of SetContextPixelsBuffer
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetContextPixelsBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetContextPixelsBufferTest001 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    uint64_t byteCount = 0;
    DecodeContext context;
    SkImageInfo dstInfo;
    uint32_t result = bmpDecoder->SetContextPixelsBuffer(byteCount, context, dstInfo);
    ASSERT_EQ(result, ERR_SHAMEM_DATA_ABNORMAL);
    context.allocatorType = Media::AllocatorType::DMA_ALLOC;
    result = bmpDecoder->SetContextPixelsBuffer(byteCount, context, dstInfo);
    ASSERT_EQ(result, ERR_DMA_NOT_EXIST);
    context.allocatorType = Media::AllocatorType::CUSTOM_ALLOC;
    result = bmpDecoder->SetContextPixelsBuffer(byteCount, context, dstInfo);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_VALUE);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetContextPixelsBufferTest001 end";
}

/**
 * @tc.name: DmaMemAllocTest001
 * @tc.desc: Test of DmaMemAlloc
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, DmaMemAllocTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: DmaMemAllocTest001 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    uint64_t byteCount = 0;
    DecodeContext context;
    SkImageInfo dstInfo;
    context.allocatorType = Media::AllocatorType::DMA_ALLOC;
    uint32_t result = bmpDecoder->SetContextPixelsBuffer(byteCount, context, dstInfo);
    ASSERT_EQ(result, ERR_DMA_NOT_EXIST);
    GTEST_LOG_(INFO) << "BmpDecoderTest: DmaMemAllocTest001 end";
}

/**
 * @tc.name: SetBufferTest001
 * @tc.desc: Test of SetBuffer
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetBufferTest001 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    uint64_t byteCount = 0;
    DecodeContext context;
    SkImageInfo dstInfo;
    context.allocatorType = Media::AllocatorType::CUSTOM_ALLOC;
    uint32_t result = bmpDecoder->SetContextPixelsBuffer(byteCount, context, dstInfo);
    ASSERT_EQ(result, ERR_MEDIA_INVALID_VALUE);
    byteCount = -1;
    result = bmpDecoder->SetContextPixelsBuffer(byteCount, context, dstInfo);
    ASSERT_EQ(result, ERR_IMAGE_MALLOC_ABNORMAL);
    byteCount = 3;
    result = bmpDecoder->SetContextPixelsBuffer(byteCount, context, dstInfo);
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetBufferTest001 end";
}

/**
 * @tc.name: DecodeTest005
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, DecodeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeTest005 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    uint32_t index = 1;
    DecodeContext context;
    uint32_t result = bmpDecoder->Decode(index, context);
    ASSERT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
    index = 0;
    result = bmpDecoder->Decode(index, context);
    ASSERT_EQ(result, ERR_IMAGE_DECODE_FAILED);
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeTest005 end";
}

/**
 * @tc.name: DecodeHeaderTest001
 * @tc.desc: Test of DecodeHeader
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, DecodeHeaderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeHeaderTest001 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    bool result = bmpDecoder->DecodeHeader();
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "BmpDecoderTest: DecodeHeaderTest001 end";
}

/**
 * @tc.name: readTest001
 * @tc.desc: Test of read
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, readTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: readTest001 start";
    auto bmpStream = std::make_shared<BmpStream>();
    void *buffer = nullptr;
    size_t size = 0;
    size_t result = bmpStream->read(buffer, size);
    ASSERT_EQ(result, 0);
    GTEST_LOG_(INFO) << "BmpDecoderTest: readTest001 end";
}

/**
 * @tc.name: peekTest001
 * @tc.desc: Test of peek
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, peekTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: peekTest001 start";
    auto bmpStream = std::make_shared<BmpStream>();
    void *buffer = nullptr;
    size_t size = 0;
    size_t result = bmpStream->peek(buffer, size);
    ASSERT_EQ(result, 0);
    bmpStream->inputStream_ = (ImagePlugin::InputDataStream *)malloc(sizeof(ImagePlugin::InputDataStream));
    result = bmpStream->peek(buffer, size);
    ASSERT_EQ(result, 0);
    free(bmpStream->inputStream_);
    bmpStream->inputStream_ = NULL;
    GTEST_LOG_(INFO) << "BmpDecoderTest: peekTest001 end";
}

/**
 * @tc.name: isAtEndTest001
 * @tc.desc: Test of isAtEnd
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, isAtEndTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: isAtEndTest001 start";
    auto bmpStream = std::make_shared<BmpStream>();
    bool result = bmpStream->isAtEnd();
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "BmpDecoderTest: isAtEndTest001 end";
}

/**
 * @tc.name: PluginExternalCreateTest001
 * @tc.desc: Test of PluginExternalCreate
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, PluginExternalCreateTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: PluginExternalCreateTest001 start";
    std::string className;
    auto result = PluginExternalCreate(className);
    ASSERT_EQ(result, nullptr);
    className = "#ImplClassType";
    result = PluginExternalCreate(className);
    ASSERT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "BmpDecoderTest: PluginExternalCreateTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest008
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(BmpDecoderTest, SetDecodeOptionsTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest008 start";
    auto bmpDecoder = std::make_shared<BmpDecoder>();
    uint32_t index = 0;
    const PixelDecodeOptions opts;
    PlImageInfo info;
    bmpDecoder->state_ = BmpDecodingState::BASE_INFO_PARSED;
    uint32_t result = bmpDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "BmpDecoderTest: SetDecodeOptionsTest008 end";
}
}
}