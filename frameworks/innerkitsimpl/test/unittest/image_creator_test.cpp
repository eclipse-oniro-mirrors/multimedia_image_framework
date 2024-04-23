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
class ImageCreatorTest : public testing::Test {
public:
    ImageCreatorTest() {}
    ~ImageCreatorTest() {}
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
} // namespace Multimedia
} // namespace OHOS
