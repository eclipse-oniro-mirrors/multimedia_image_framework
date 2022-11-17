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
 
#include <gtest/gtest.h>
#include <fstream>
#include "image_receiver.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "hilog/log.h"
#include "image_receiver_manager.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
static constexpr int32_t RECEIVER_TEST_WIDTH = 8192;
static constexpr int32_t RECEIVER_TEST_HEIGHT = 8;
static constexpr int32_t RECEIVER_TEST_CAPACITY = 8;
static constexpr int32_t RECEIVER_TEST_FORMAT = 4;

class ImageReceiverTest : public testing::Test {
public:
    ImageReceiverTest() {}
    ~ImageReceiverTest() {}
};

/**
 * @tc.name: ImageReceiver001
 * @tc.desc: test SaveBufferAsImage buffer is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver001 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver->ReadLastImage();
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    imageReceiver->SaveBufferAsImage(fd, surfaceBuffer1, opts);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver001 end";
}

/**
 * @tc.name: ImageReceiver002
 * @tc.desc: test SaveBufferAsImage buffer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver002 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::shared_ptr<ImageReceiver> imageReceiver1 = imageReceiverManager.getImageReceiverByKeyId("1");
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = nullptr;
    ASSERT_EQ(surfaceBuffer1, nullptr);
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    imageReceiver1->SaveBufferAsImage(fd, surfaceBuffer1, opts);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver002 end";
}

/**
 * @tc.name: ImageReceiver003
 * @tc.desc: test SaveBufferAsImage fd is -1
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver003 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::shared_ptr<ImageReceiver> imageReceiver1 = imageReceiverManager.getImageReceiverByKeyId("1");
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = nullptr;
    ASSERT_EQ(surfaceBuffer1, nullptr);
    int fd = -1;
    imageReceiver1->SaveBufferAsImage(fd, surfaceBuffer1, opts);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver003 end";
}

/**
 * @tc.name: ImageReceiver004
 * @tc.desc: test SaveBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver004 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::shared_ptr<ImageReceiver> imageReceiver1 = imageReceiverManager.getImageReceiverByKeyId("1");
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    imageReceiver1->SaveBufferAsImage(fd, opts);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver004 end";
}

/**
 * @tc.name: ImageReceiver005
 * @tc.desc: test SaveBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver005 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::shared_ptr<ImageReceiver> imageReceiver1 = imageReceiverManager.getImageReceiverByKeyId("1");
    int fd = -1;
    imageReceiver1->SaveBufferAsImage(fd, opts);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver005 end";
}


/**
 * @tc.name: ImageReceiver006
 * @tc.desc: test ReleaseBuffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver006 start";
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::shared_ptr<ImageReceiver> imageReceiver1 = imageReceiverManager.getImageReceiverByKeyId("1");
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver1->ReadLastImage();
    imageReceiver1->ReleaseBuffer(surfaceBuffer1);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver006 end";
}

/**
 * @tc.name: ImageReceiver007
 * @tc.desc: test ReleaseBuffer surfaceBuffer1 is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver007 start";
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::shared_ptr<ImageReceiver> imageReceiver1 = imageReceiverManager.getImageReceiverByKeyId("1");
    ASSERT_NE(imageReceiver1, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = nullptr;
    imageReceiver1->ReleaseBuffer(surfaceBuffer1);
    ASSERT_EQ(surfaceBuffer1, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver007 end";
}

/**
 * @tc.name: ImageReceiver008
 * @tc.desc: test ReleaseBuffer listenerConsumerSurface is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver008 start";
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::shared_ptr<ImageReceiver> imageReceiver1 = imageReceiverManager.getImageReceiverByKeyId("1");
    ASSERT_NE(imageReceiver1->iraContext_, nullptr);
    auto listenerConsumerSurface = imageReceiver1->iraContext_->GetReceiverBufferConsumer();
    listenerConsumerSurface = nullptr;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver1->ReadLastImage();
    imageReceiver1->ReleaseBuffer(surfaceBuffer1);
    ASSERT_EQ(surfaceBuffer1, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver008 end";
}

/**
 * @tc.name: ImageReceiver009
 * @tc.desc: test OnBufferAvailable
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver009, TestSize.Level3) {
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver009 start";
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::shared_ptr<ImageReceiver> imageReceiver1 = imageReceiverManager.getImageReceiverByKeyId("1");
    sptr<ImageReceiverSurfaceListener> listener = new ImageReceiverSurfaceListener();
    listener->ir_ = imageReceiver1;
    listener->OnBufferAvailable();
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver009 end";
}

/**
 * @tc.name: ImageReceiver0010
 * @tc.desc: test CreateImageReceiverContext
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver0010, TestSize.Level3) {
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0010 start";
    std::shared_ptr<ImageReceiver> iva = std::make_shared<ImageReceiver>();
    iva->iraContext_ = ImageReceiverContext::CreateImageReceiverContext();
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0010 end";
}

/**
 * @tc.name: ImageReceiver0011
 * @tc.desc: test CreateImageReceiver
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0011 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0011 end";
}

/**
 * @tc.name: ImageReceiver0012
 * @tc.desc: test ReadNextImage iraContext_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0012 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    OHOS::sptr<OHOS::SurfaceBuffer> surfacebuffer = imageReceiver->ReadNextImage();
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0012 end";
}

/**
 * @tc.name: ImageReceiver0013
 * @tc.desc: test ReadLastImage iraContext_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0013 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    OHOS::sptr<OHOS::SurfaceBuffer> surfacebuffer = imageReceiver->ReadLastImage();
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0013 end";
}
}
}