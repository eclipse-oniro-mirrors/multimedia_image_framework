/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <fstream>
#include "image_creator.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_utils.h"
#include "directory_ex.h"
#include "image_creator_manager.h"
#include "consumer_surface.h"
#include "producer_surface.h"
#include "external_window.h"
#include "native_window.h"
#include "image_creator_buffer_processor.h"

using namespace testing::ext;
using namespace OHOS::Media;

static bool g_mockConsumerNull = false;
static bool g_mockProducerNull = false;
static bool g_mockProcessorNull = false;
static bool g_mockDequeueNull = false;
namespace OHOS {
static constexpr uint32_t MOCK_FORMAT_COUNT = 1;
sptr<IConsumerSurface> IConsumerSurface::Create(std::string)
{
    return g_mockConsumerNull ? nullptr : new OHOS::ConsumerSurface("mock");
}
sptr<Surface> Surface::CreateSurfaceAsProducer(sptr<IBufferProducer>&)
{
    sptr<IBufferProducer> dummyProducer = nullptr;
    return g_mockProducerNull ? nullptr : new OHOS::ProducerSurface(dummyProducer);
}
uint32_t ImagePacker::GetSupportedFormats(std::set<std::string> &formats)
{
    return MOCK_FORMAT_COUNT;
}
std::shared_ptr<IBufferProcessor> ImageCreator::GetBufferProcessor()
{
    std::shared_ptr<IBufferProcessor> buffProcessor = std::make_shared<ImageCreatorBufferProcessor>(this);
    return g_mockProcessorNull ? nullptr : buffProcessor;
}
sptr<SurfaceBuffer> ImageCreator::DequeueImage()
{
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    return g_mockDequeueNull ? nullptr : buffer;
}
}

namespace OHOS {
namespace Multimedia {
static constexpr int32_t NUM_1 = 1;
class ImageCreatorTest : public testing::Test {
public:
    ImageCreatorTest() {}
    ~ImageCreatorTest() {}
};
class ImageCreatorReleaseListenerTest : public SurfaceBufferReleaseListener {
public:
    void OnSurfaceBufferRelease() override {}
};
class ImageCreatorAvailableListenerTest : public SurfaceBufferAvaliableListener {
public:
    int32_t cnt_{0};
    void OnSurfaceBufferAvaliable()
    {
        cnt_ = NUM_1;
    }
};

/**
 * @tc.name: CreateImageCreator_001
 * @tc.desc: Verify CreateImageCreator returns early when consumer surface creation fails.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, CreateImageCreator_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator_001 start";
    ImageCreator creat;
    int32_t width = 1;
    int32_t height = 2;
    int32_t format = 3;
    int32_t capicity = 4;
    g_mockConsumerNull = true;
    g_mockProducerNull = false;
    std::shared_ptr<ImageCreator> ret = creat.CreateImageCreator(width, height, format, capicity);
    ASSERT_NE(ret, nullptr);
    ASSERT_EQ(ret->creatorConsumerSurface_, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator_001 end";
}

/**
 * @tc.name: CreateImageCreator_002
 * @tc.desc: Verify CreateImageCreator returns early when producer surface creation fails.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, CreateImageCreator_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator_002 start";
    ImageCreator creat;
    int32_t width = 1;
    int32_t height = 2;
    int32_t format = 3;
    int32_t capicity = 4;
    g_mockConsumerNull = false;
    g_mockProducerNull = true;
    std::shared_ptr<ImageCreator> ret = creat.CreateImageCreator(width, height, format, capicity);
    ASSERT_NE(ret, nullptr);
    ASSERT_NE(ret->creatorConsumerSurface_, nullptr);
    ASSERT_EQ(ret->creatorProducerSurface_, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator_002 end";
}

/**
 * @tc.name: CreateImageCreator_003
 * @tc.desc: Verify CreateImageCreator initializes both consumer and producer surfaces successfully.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, CreateImageCreator_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator_003 start";
    ImageCreator creat;
    int32_t width = 1;
    int32_t height = 2;
    int32_t format = 3;
    int32_t capicity = 4;
    g_mockConsumerNull = false;
    g_mockProducerNull = false;
    std::shared_ptr<ImageCreator> ret = creat.CreateImageCreator(width, height, format, capicity);
    ASSERT_NE(ret, nullptr);
    ASSERT_NE(ret->creatorConsumerSurface_, nullptr);
    ASSERT_NE(ret->creatorProducerSurface_, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator_003 end";
}

/**
 * @tc.name: CreatorPackImage_001
 * @tc.desc: Verify CreatorPackImage handles GetSupportedFormats failure by
 *           triggering the error log and returning 0 path.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, CreatorPackImage_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreatorPackImage_001 start";
    uint32_t color[64] = {};
    uint32_t colorlength = 64;
    InitializationOptions opts;
    opts.pixelFormat = OHOS::Media::PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.height = 8;
    opts.size.width = 8;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(color, colorlength, opts);
    ASSERT_NE(pixelMap.get(), nullptr);
    int64_t bufferSize = 2 * 1024 * 1024;
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(8, 8, 3, 1);
    ASSERT_NE(creator, nullptr);
    int32_t status = creator->SaveSTP(color, buffer, colorlength, opts);
    ASSERT_EQ(status, ERR_MEDIA_INVALID_VALUE);
    free(buffer);
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreatorPackImage_001 end";
}

/**
 * @tc.name: DequeueNativeImage_001
 * @tc.desc: Verify DequeueNativeImage returns nullptr when GetBufferProcessor returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, DequeueNativeImage_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: DequeueNativeImage_001 start";
    g_mockProcessorNull = true;
    g_mockDequeueNull = false;
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    std::shared_ptr<NativeImage> ret = creator->DequeueNativeImage();
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: DequeueNativeImage_001 end";
}

/**
 * @tc.name: DequeueNativeImage_002
 * @tc.desc: Verify DequeueNativeImage returns nullptr when DequeueImage returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, DequeueNativeImage_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: DequeueNativeImage_002 start";
    g_mockProcessorNull = false;
    g_mockDequeueNull = true;
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    std::shared_ptr<NativeImage> ret = creator->DequeueNativeImage();
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: DequeueNativeImage_002 end";
}
} // namespace Multimedia
} // namespace OHOS