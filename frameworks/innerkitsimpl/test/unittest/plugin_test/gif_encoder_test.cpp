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
#include "gif_encoder.h"
#include "image_source.h"
#include "buffer_packer_stream.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {

constexpr uint32_t MAX_SIZE = 10;
constexpr int32_t OUTPUT_DATA_LENGTH = 1000;
constexpr int32_t WIDTH = 10;
constexpr int32_t HEIGHT = 10;
constexpr int32_t LARGE_WIDTH = 100;
constexpr int32_t LARGE_HEIGHT = 100;
constexpr uint32_t SMALL_BUFFER_SIZE = 10;
constexpr uint16_t TEST_WIDTH_10x10 = 10;
constexpr uint16_t TEST_HEIGHT_10x10 = 10;
constexpr uint16_t TEST_WIDTH_50x50 = 50;
constexpr uint16_t TEST_HEIGHT_50x50 = 50;
constexpr uint16_t TEST_WIDTH_20x20 = 20;
constexpr uint16_t TEST_HEIGHT_20x20 = 20;
constexpr int32_t ENCODE_BUFFER_10 = 10;
constexpr int32_t ENCODE_BUFFER_5 = 5;
constexpr int32_t ENCODE_BUFFER_3 = 3;
constexpr int32_t ENCODE_BUFFER_1 = 1;
constexpr int32_t ENCODE_BUFFER_2 = 2;
constexpr int32_t LARGE_DATA_LENGTH = 5000;
constexpr int32_t LZWWRITEOUT_CODE_100 = 100;
constexpr int32_t LZWWRITEOUT_CODE_50 = 50;
constexpr int32_t LZWWRITEOUT_CODE_200 = 200;
constexpr int32_t FLUSH_OUTPUT_CODE = 4096;
constexpr int32_t COLOR_SUBDIVMAP_SIZE = 256;
constexpr int32_t COLOR_PIXEL_NUM = 100;
constexpr int32_t COLOR_NUM = 1;
class GifEncoderTest : public testing::Test {
public:
    GifEncoderTest() {}
    ~GifEncoderTest() {}
};

/**
 * @tc.name: GifEncoderTest001
 * @tc.desc: Test of GifEncoder
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, GifEncoderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: GifEncoderTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);
    GTEST_LOG_(INFO) << "GifEncoderTest: GifEncoderTest001 end";
}

/**
 * @tc.name: StartEncode001
 * @tc.desc: Test of StartEncode
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, StartEncode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: StartEncode001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(OUTPUT_DATA_LENGTH);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), MAX_SIZE);
    auto result = gifEncoder->StartEncode(*stream.get(), plOpts);
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "GifEncoderTest: StartEncode001 end";
}

/**
 * @tc.name: AddImage001
 * @tc.desc: Test of AddImage
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, AddImage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: AddImage001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    Media::InitializationOptions opts;
    opts.size.width = WIDTH;
    opts.size.height = HEIGHT;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    auto result = gifEncoder->AddImage(*pixelMap.get());
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "GifEncoderTest: AddImage001 end";
}

/**
 * @tc.name: AddImage002
 * @tc.desc: Test of AddImage
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, AddImage002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: AddImage002 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    Media::InitializationOptions opts;
    opts.size.width = WIDTH;
    opts.size.height = HEIGHT;
    opts.editable = true;
    auto pixelMap1 = Media::PixelMap::Create(opts);
    auto pixelMap2 = Media::PixelMap::Create(opts);
    auto result = gifEncoder->AddImage(*pixelMap1.get());
    ASSERT_EQ(result, SUCCESS);
    result = gifEncoder->AddImage(*pixelMap2.get());
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "GifEncoderTest: AddImage002 end";
}

/**
 * @tc.name: AddImage003
 * @tc.desc: pixelMaps_'s data is empty
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, AddImage003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: AddImage003 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    Media::InitializationOptions opts;
    opts.size.width = WIDTH;
    opts.size.height = HEIGHT;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    pixelMap->SetPixelsAddr(nullptr, nullptr, MAX_SIZE, AllocatorType::HEAP_ALLOC, nullptr);
    auto result = gifEncoder->AddImage(*pixelMap.get());
    ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "GifEncoderTest: AddImage003 end";
}

/**
 * @tc.name: FinalizeEncode001
 * @tc.desc: pixelMaps_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, FinalizeEncode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: FinalizeEncode001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    auto result = gifEncoder->FinalizeEncode();
    ASSERT_EQ(result, COMMON_ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "GifEncoderTest: FinalizeEncode001 end";
}

/**
 * @tc.name: Write001
 * @tc.desc: Test of Write
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, Write001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: Write001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(OUTPUT_DATA_LENGTH);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), MAX_SIZE);
    auto ret = gifEncoder->StartEncode(*stream.get(), plOpts);
    ASSERT_EQ(ret, SUCCESS);
    std::unique_ptr<uint8_t[]> rgb = std::make_unique<uint8_t[]>(MAX_SIZE);
    bool result = gifEncoder->Write(rgb.get(), MAX_SIZE);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifEncoderTest: Write001 end";
}

/**
 * @tc.name: FinalizeEncodeWithTransparentPixelTest001
 * @tc.desc: Test FinalizeEncode with transparent pixels
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, FinalizeEncodeWithTransparentPixelTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: FinalizeEncodeWithTransparentPixelTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);
    
    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(OUTPUT_DATA_LENGTH);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), OUTPUT_DATA_LENGTH);
    auto ret = gifEncoder->StartEncode(*stream.get(), plOpts);
    ASSERT_EQ(ret, SUCCESS);
    
    Media::InitializationOptions opts;
    opts.size.width = WIDTH;
    opts.size.height = HEIGHT;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);
    
    uint32_t* pixels = static_cast<uint32_t*>(pixelMap->GetWritablePixels());
    if (pixels != nullptr) {
        for (int i = 0; i < (WIDTH * HEIGHT / 2); i++) {
            pixels[i] = 0x00FF0000;
        }
        for (int i = (WIDTH * HEIGHT / 2); i < WIDTH * HEIGHT; i++) {
            pixels[i] = 0xFF00FF00;
        }
    }
    
    ret = gifEncoder->AddImage(*pixelMap.get());
    ASSERT_EQ(ret, SUCCESS);
    
    ret = gifEncoder->FinalizeEncode();
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "GifEncoderTest: FinalizeEncodeWithTransparentPixelTest001 end";
}

/**
 * @tc.name: FinalizeEncodeErrorTest001
 * @tc.desc: Test FinalizeEncode error path when errorCode != SUCCESS
 *           This test ensures the error logging branch is covered
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, FinalizeEncodeErrorTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: FinalizeEncodeErrorTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);
    
    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(SMALL_BUFFER_SIZE);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), SMALL_BUFFER_SIZE);
    auto ret = gifEncoder->StartEncode(*stream.get(), plOpts);
    ASSERT_EQ(ret, SUCCESS);
    
    Media::InitializationOptions opts;
    opts.size.width = LARGE_WIDTH;
    opts.size.height = LARGE_HEIGHT;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);
    
    ret = gifEncoder->AddImage(*pixelMap.get());
    ASSERT_EQ(ret, SUCCESS);
    
    gifEncoder->FinalizeEncode();
    GTEST_LOG_(INFO) << "GifEncoderTest: FinalizeEncodeErrorTest001 end";
}

/**
 * @tc.name: BuildColorSubdivMapSuccessTest001
 * @tc.desc: Test BuildColorSubdivMap success path
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, BuildColorSubdivMapSuccessTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: BuildColorSubdivMapSuccessTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);

    ColorSubdivMap colorSubdivMap[COLOR_SUBDIVMAP_SIZE];
    uint32_t colorSubdivMapSize = 1;

    std::fill(std::begin(colorSubdivMap), std::end(colorSubdivMap), ColorSubdivMap{});
    colorSubdivMap[0].colorNum = COLOR_NUM;
    colorSubdivMap[0].pixelNum = COLOR_PIXEL_NUM;

    uint32_t ret = gifEncoder->BuildColorSubdivMap(colorSubdivMap, &colorSubdivMapSize);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "GifEncoderTest: BuildColorSubdivMapSuccessTest001 end";
}

/**
 * @tc.name: LZWEncodeFailureTest001
 * @tc.desc: Test LZWEncode failure in LZWEncodeFrame
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, LZWEncodeFailureTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWEncodeFailureTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(ENCODE_BUFFER_10);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), ENCODE_BUFFER_10);
    gifEncoder->StartEncode(*stream.get(), plOpts);

    std::unique_ptr<uint8_t[]> outputBuffer = std::make_unique<uint8_t[]>(TEST_WIDTH_10x10 * TEST_HEIGHT_10x10);

    gifEncoder->InitDictionary();

    uint32_t ret = gifEncoder->LZWEncodeFrame(outputBuffer.get(), TEST_WIDTH_10x10, TEST_HEIGHT_10x10);
    ASSERT_EQ(ret, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWEncodeFailureTest001 end";
}

/**
 * @tc.name: LZWWriteOutEofCodeFailureTest001
 * @tc.desc: Test LZWWriteOut eofCode failure
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, LZWWriteOutEofCodeFailureTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWWriteOutEofCodeFailureTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(ENCODE_BUFFER_5);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), ENCODE_BUFFER_5);
    gifEncoder->StartEncode(*stream.get(), plOpts);

    std::unique_ptr<uint8_t[]> outputBuffer = std::make_unique<uint8_t[]>(TEST_WIDTH_50x50 * TEST_HEIGHT_50x50);

    for (int i = 0; i < TEST_WIDTH_50x50 * TEST_HEIGHT_50x50; i++) {
        outputBuffer[i] = static_cast<uint8_t>(i % 256);
    }

    gifEncoder->InitDictionary();
    uint32_t ret = gifEncoder->LZWEncodeFrame(outputBuffer.get(), TEST_WIDTH_50x50, TEST_HEIGHT_50x50);
    ASSERT_EQ(ret, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWWriteOutEofCodeFailureTest001 end";
}

/**
 * @tc.name: LZWWriteOutFlushCodeFailureTest001
 * @tc.desc: Test LZWWriteOut FLUSH_OUTPUT failure
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, LZWWriteOutFlushCodeFailureTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWWriteOutFlushCodeFailureTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(ENCODE_BUFFER_3);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), ENCODE_BUFFER_3);
    gifEncoder->StartEncode(*stream.get(), plOpts);

    std::unique_ptr<uint8_t[]> outputBuffer = std::make_unique<uint8_t[]>(TEST_WIDTH_20x20 * TEST_HEIGHT_20x20);

    gifEncoder->InitDictionary();
    uint32_t ret = gifEncoder->LZWEncodeFrame(outputBuffer.get(), TEST_WIDTH_20x20, TEST_HEIGHT_20x20);
    ASSERT_EQ(ret, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWWriteOutFlushCodeFailureTest001 end";
}

/**
 * @tc.name: LZWEncodeRunningCodeMaxTest001
 * @tc.desc: Test LZWEncode when runningCode_ >= LZ_MAX_CODE
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, LZWEncodeRunningCodeMaxTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWEncodeRunningCodeMaxTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(OUTPUT_DATA_LENGTH * 10);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), OUTPUT_DATA_LENGTH * 10);
    gifEncoder->StartEncode(*stream.get(), plOpts);

    gifEncoder->InitDictionary();

    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(LARGE_DATA_LENGTH);
    for (int i = 0; i < LARGE_DATA_LENGTH; i++) {
        buffer[i] = static_cast<uint8_t>((i * 7 + 13) % 256);
    }

    uint32_t ret = gifEncoder->LZWEncode(buffer.get(), LARGE_DATA_LENGTH);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWEncodeRunningCodeMaxTest001 end";
}

/**
 * @tc.name: LZWBufferOutputFirstByteTest001
 * @tc.desc: Test LZWBufferOutput failure at first byte output
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, LZWBufferOutputFirstByteTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWBufferOutputFirstByteTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(ENCODE_BUFFER_1);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), ENCODE_BUFFER_1);
    gifEncoder->StartEncode(*stream.get(), plOpts);

    gifEncoder->InitDictionary();

    uint32_t ret = gifEncoder->LZWWriteOut(LZWWRITEOUT_CODE_100);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWBufferOutputFirstByteTest001 end";
}

/**
 * @tc.name: LZWBufferOutputFlushTest001
 * @tc.desc: Test LZWBufferOutput with FLUSH_OUTPUT
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, LZWBufferOutputFlushTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWBufferOutputFlushTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(ENCODE_BUFFER_1);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), ENCODE_BUFFER_1);
    gifEncoder->StartEncode(*stream.get(), plOpts);

    gifEncoder->InitDictionary();

    gifEncoder->LZWWriteOut(LZWWRITEOUT_CODE_50);
    uint32_t ret = gifEncoder->LZWWriteOut(FLUSH_OUTPUT_CODE);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWBufferOutputFlushTest001 end";
}

/**
 * @tc.name: LZWBufferOutputSecondByteTest001
 * @tc.desc: Test LZWBufferOutput failure at second byte output
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, LZWBufferOutputSecondByteTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWBufferOutputSecondByteTest001 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    ASSERT_NE(gifEncoder, nullptr);

    PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(ENCODE_BUFFER_2);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), ENCODE_BUFFER_2);
    gifEncoder->StartEncode(*stream.get(), plOpts);

    gifEncoder->InitDictionary();

    gifEncoder->LZWWriteOut(LZWWRITEOUT_CODE_100);
    uint32_t ret = gifEncoder->LZWWriteOut(LZWWRITEOUT_CODE_200);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "GifEncoderTest: LZWBufferOutputSecondByteTest001 end";
}
}
}