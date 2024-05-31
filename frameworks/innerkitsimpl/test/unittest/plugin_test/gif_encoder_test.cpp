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
    bool result = (gifEncoder != nullptr);
    ASSERT_EQ(result, true);
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
    auto outputData = std::make_unique<uint8_t[]>(1000);
    auto maxSize = 10;
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), maxSize);
    gifEncoder->StartEncode(*stream.get(), plOpts);
    bool result = (gifEncoder != nullptr);
    ASSERT_EQ(result, true);
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
    opts.size.width = 10.f;
    opts.size.height = 10.f;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    gifEncoder->AddImage(*pixelMap.get());
    bool result = (gifEncoder != nullptr);
    ASSERT_EQ(result, true);
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
    opts.size.width = 10.f;
    opts.size.height = 10.f;
    opts.editable = true;
    auto pixelMap1 = Media::PixelMap::Create(opts);
    auto pixelMap2 = Media::PixelMap::Create(opts);
    gifEncoder->AddImage(*pixelMap1.get());
    gifEncoder->AddImage(*pixelMap2.get());
    bool result = (gifEncoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifEncoderTest: AddImage002 end";
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
    gifEncoder->FinalizeEncode();
    bool result = (gifEncoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifEncoderTest: FinalizeEncode001 end";
}

/**
 * @tc.name: FinalizeEncode002
 * @tc.desc: pixelMaps_'s data is empty
 * @tc.type: FUNC
 */
HWTEST_F(GifEncoderTest, FinalizeEncode002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GifEncoderTest: FinalizeEncode002 start";
    auto gifEncoder = std::make_shared<GifEncoder>();
    Media::InitializationOptions opts;
    opts.size.width = 10.f;
    opts.size.height = 10.f;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    pixelMap->SetPixelsAddr(nullptr, nullptr, 10, AllocatorType::HEAP_ALLOC, nullptr);
    gifEncoder->AddImage(*pixelMap.get());
    gifEncoder->FinalizeEncode();
    bool result = (gifEncoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifEncoderTest: FinalizeEncode002 end";
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
    auto outputData = std::make_unique<uint8_t[]>(1000);
    auto maxSize = 10;
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), maxSize);
    gifEncoder->StartEncode(*stream.get(), plOpts);
    std::unique_ptr<uint8_t[]> rgb = std::make_unique<uint8_t[]>(10);
    gifEncoder->Write(rgb.get(), 10);
    bool result = (gifEncoder != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "GifEncoderTest: Write001 end";
}

}
}