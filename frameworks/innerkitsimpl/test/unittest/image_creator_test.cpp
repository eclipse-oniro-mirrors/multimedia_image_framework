/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "image_creator.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_utils.h"
#include "directory_ex.h"
#include "image_creator_manager.h"

using namespace testing::ext;
using namespace OHOS::Media;
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
 * @tc.name: CreateImageCreator001
 * @tc.desc: test CreateImageCreator
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, CreateImageCreator001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator001 start";
    ImageCreator creat;
    int32_t width = 1;
    int32_t height = 2;
    int32_t format = 3;
    int32_t capicity = 4;
    std::shared_ptr<ImageCreator> createimagec = creat.CreateImageCreator(width, height, format, capicity);
    ASSERT_NE(createimagec, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator001 end";
}

/**
 * @tc.name: SaveSTP001
 * @tc.desc: test SaveSTP
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSTP001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSTP001 start";
    ImageCreator creat;
    uint32_t *buffer = nullptr;
    uint8_t *tempBuffer = nullptr;
    uint32_t bufferSize = 1;
    InitializationOptions initializationOpts;
    int32_t savesp = creat.SaveSTP(buffer, tempBuffer, bufferSize, initializationOpts);
    ASSERT_EQ(savesp, -1);
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSTP001 end";
}

/**
 * @tc.name: SaveSTP002
 * @tc.desc: test SaveSTP
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSTP002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSTP002 start";
    ImageCreator creat;
    uint32_t *buffer = nullptr;
    uint8_t *tempBuffer = nullptr;
    uint32_t bufferSize = 0;
    InitializationOptions initializationOpts;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(buffer, bufferSize, initializationOpts);
    ASSERT_EQ(pixelMap, nullptr);
    int32_t savesp = creat.SaveSTP(buffer, tempBuffer, bufferSize, initializationOpts);
    ASSERT_EQ(savesp, ERR_MEDIA_INVALID_VALUE);
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSTP002 end";
}

/**
 * @tc.name: SaveSenderBufferAsImage001
 * @tc.desc: test SaveSenderBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSenderBufferAsImage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage001 start";
    ImageCreator creat;
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    InitializationOptions initializationOpts;
    int32_t savesend = creat.SaveSenderBufferAsImage(buffer, initializationOpts);
    ASSERT_EQ(savesend, 0);
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage001 end";
}

/**
 * @tc.name: SaveSenderBufferAsImage002
 * @tc.desc: test SaveSenderBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSenderBufferAsImage002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage002start";
    ImageCreator creat;
    OHOS::sptr<OHOS::SurfaceBuffer> buffer;
    InitializationOptions initializationOpts;
    int32_t savesend = creat.SaveSenderBufferAsImage(buffer, initializationOpts);
    ASSERT_EQ(savesend, 0);
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage002 end";
}

/**
 * @tc.name: SaveSenderBufferAsImage003
 * @tc.desc: test SaveSenderBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSenderBufferAsImage003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage003 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = SurfaceBuffer::Create();
    InitializationOptions initializationOpts;
    int32_t savesend = creator->SaveSenderBufferAsImage(buffer, initializationOpts);
    ASSERT_EQ(savesend, ERR_MEDIA_INVALID_VALUE);
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage003 end";
}

/**
 * @tc.name: getSurfaceById001
 * @tc.desc: test getSurfaceById
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, getSurfaceById001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: getSurfaceById001 start";
    ImageCreator creat;
    std::string id = "";
    sptr<IConsumerSurface> getsrfid = creat.getSurfaceById(id);
    ASSERT_EQ(getsrfid, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: getSurfaceById001 end";
}

/**
 * @tc.name: ReleaseCreator001
 * @tc.desc: test ReleaseCreator
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, ReleaseCreator001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: ReleaseCreator001 start";
    ImageCreator creat;
    creat.ReleaseCreator();
    ASSERT_NE(&creat, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: ReleaseCreator001 end";
}

/**
 * @tc.name: OnBufferAvailable001
 * @tc.desc: test OnBufferAvailable
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, OnBufferAvailable001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferAvailable001 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    sptr<ImageCreatorSurfaceListener> listener = new ImageCreatorSurfaceListener();
    listener->ic_ = creator;
    listener->OnBufferAvailable();
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferAvailable001 end";
}

/**
 * @tc.name: OnBufferAvailable002
 * @tc.desc: test OnBufferAvailable
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, OnBufferAvailable002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferAvailable002 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    sptr<ImageCreatorSurfaceListener> listener = new ImageCreatorSurfaceListener();
    listener->ic_ = creator;
    listener->ic_->RegisterBufferAvaliableListener(listener->ic_->surfaceBufferAvaliableListener_);
    listener->OnBufferAvailable();
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferAvailable002 end";
}

/**
 * @tc.name: DequeueImage001
 * @tc.desc: test DequeueImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, DequeueImage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: DequeueImage001 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = creator->DequeueImage();
    ASSERT_NE(buffer, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: DequeueImage001 end";
}

/**
 * @tc.name: OnBufferRelease001
 * @tc.desc: test OnBufferRelease
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, OnBufferRelease001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferRelease001 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = creator->DequeueImage();
    ASSERT_NE(buffer, nullptr);
    (void)ImageCreator::OnBufferRelease(buffer);
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferRelease001 end";
}

/**
 * @tc.name: OnBufferRelease002
 * @tc.desc: test OnBufferRelease
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, OnBufferRelease002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferRelease002 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    GSError ret = ImageCreator::OnBufferRelease(buffer);
    ASSERT_EQ(ret, GSERROR_NO_ENTRY);
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferRelease002 end";
}

/**
 * @tc.name: OnBufferRelease003
 * @tc.desc: test OnBufferRelease
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, OnBufferRelease003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferRelease003 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    GSError ret = ImageCreator::OnBufferRelease(buffer);
    ASSERT_EQ(ret, GSERROR_NO_ENTRY);
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferRelease003 end";
}

/**
 * @tc.name: QueueImage001
 * @tc.desc: test QueueImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, QueueImage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: QueueImage001 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> buffer;
    creator->QueueImage(buffer);
    GTEST_LOG_(INFO) << "ImageCreatorTest: QueueImage001 end";
}

/**
 * @tc.name: SaveSTP002
 * @tc.desc: test SaveSTP
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSTP003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSTP003 start";

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

    ImagePacker imagePacker;
    PackOption option;
    option.format = ImageReceiver::OPTION_FORMAT;
    option.numberHint = ImageReceiver::OPTION_NUMBERHINT;
    option.quality = ImageReceiver::OPTION_QUALITY;
    std::set<std::string> formats;

    uint32_t ret = imagePacker.GetSupportedFormats(formats);
    ASSERT_EQ(ret, SUCCESS);

    imagePacker.StartPacking(buffer, bufferSize, option);
    imagePacker.AddImage(*pixelMap);
    int64_t packedSize = 0;
    imagePacker.FinalizePacking(packedSize);
    ASSERT_NE(packedSize, 0);

    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(8, 8, 3, 1);
    ASSERT_NE(creator, nullptr);

    int32_t status = creator->SaveSTP(color, buffer, colorlength, opts);
    ASSERT_EQ(status, ERR_MEDIA_INVALID_VALUE);

    free(buffer);
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSTP003 end";
}

/**
 * @tc.name: GetBufferProcessor001
 * @tc.desc: test GetBufferProcessor
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, GetBufferProcessor001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: GetBufferProcessor001 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    creator->bufferProcessor_ = nullptr;
    creator->GetBufferProcessor();
    ASSERT_NE(creator->bufferProcessor_, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: GetBufferProcessor001 end";
}

/**
 * @tc.name: QueueNativeImage001
 * @tc.desc: test QueueNativeImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, QueueNativeImage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: QueueNativeImage001 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    std::shared_ptr<NativeImage> image = nullptr;
    creator->QueueNativeImage(image);
    ASSERT_EQ(image, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: QueueNativeImage001 end";
}

/**
 * @tc.name: CreateImageCreator002
 * @tc.desc: test CreateImageCreator
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, CreateImageCreator002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator002 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator->creatorConsumerSurface_, nullptr);
    ASSERT_NE(creator->creatorProducerSurface_, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator002 end";
}

/**
 * @tc.name: GetCreatorSurface001
 * @tc.desc: test GetCreatorSurface
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, GetCreatorSurface001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: GetCreatorSurface001 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    sptr<IConsumerSurface> buffer = creator->GetCreatorSurface();
    ASSERT_NE(buffer, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: GetCreatorSurface001 end";
}

/**
 * @tc.name: DequeueNativeImage001
 * @tc.desc: test DequeueNativeImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, DequeueNativeImage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: DequeueNativeImage001 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    std::shared_ptr<NativeImage> buffer = creator->DequeueNativeImage();
    ASSERT_NE(buffer, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: DequeueNativeImage001 end";
}

/**
 * @tc.name: OnBufferRelease004
 * @tc.desc: Verify ImageCreator using other buffer release listener to call onBufferRelease.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, OnBufferRelease004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferRelease004 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    std::shared_ptr<ImageCreatorReleaseListenerTest> release =
        std::make_shared<ImageCreatorReleaseListenerTest>();
    ASSERT_NE(release, nullptr);
    creator->RegisterBufferReleaseListener(release);
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = creator->DequeueImage();
    ASSERT_NE(buffer, nullptr);
    GSError error = ImageCreator::OnBufferRelease(buffer);
    ASSERT_EQ(error, GSERROR_NO_ENTRY);
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferRelease004 end";
}

/**
 * @tc.name: QueueNativeImage002
 * @tc.desc: Verify ImageCreator using native image as parameter to call QueueNativeImage.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, QueueNativeImage002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: QueueNativeImage002 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    std::shared_ptr<NativeImage> image = creator->DequeueNativeImage();
    ASSERT_NE(image, nullptr);
    creator->QueueNativeImage(image);
    image = creator->DequeueNativeImage();
    ASSERT_NE(image, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: QueueNativeImage002 end";
}

/**
 * @tc.name: OnBufferAvailable004
 * @tc.desc: Verify ImageCreator using other buffer avaliable listener to call OnBufferAvailable.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, OnBufferAvailable004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferAvailable004 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);

    std::shared_ptr<ImageCreatorAvailableListenerTest> available =
        std::make_shared<ImageCreatorAvailableListenerTest>();
    creator->RegisterBufferAvaliableListener(available);

    std::shared_ptr<ImageCreatorSurfaceListener> surfaceListener =
        std::make_shared<ImageCreatorSurfaceListener>();
    surfaceListener->ic_ = creator;

    surfaceListener->OnBufferAvailable();
    ASSERT_EQ(available->cnt_, NUM_1);
    GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferAvailable004 end";
}

/**
 * @tc.name: SaveSenderBufferAsImage004
 * @tc.desc: Verify that ImageCreator call SaveSenderBufferAsImage when buffer is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSenderBufferAsImage004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage004 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(NUM_1, NUM_1, NUM_1, NUM_1);
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = NUM_1,
        .height = NUM_1,
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError ret = buffer->Alloc(requestConfig);
    ASSERT_EQ(ret, GSERROR_OK);
    InitializationOptions initializationOpts;
    initializationOpts.size.width = NUM_1;
    initializationOpts.size.height = NUM_1;
    initializationOpts.pixelFormat = OHOS::Media::PixelFormat::RGBA_8888;
    int32_t savesend = creator->SaveSenderBufferAsImage(buffer, initializationOpts);
    ASSERT_EQ(savesend, SUCCESS);
#endif
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage004 end";
}

} // namespace Multimedia
} // namespace OHOS
