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
}
}