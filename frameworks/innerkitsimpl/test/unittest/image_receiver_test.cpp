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
#define private public
#include <fstream>
#include "image_receiver.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
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
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver->ReadLastImage();
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    int32_t res = imageReceiver->SaveBufferAsImage(fd, surfaceBuffer1, opts);
    ASSERT_EQ(res, SUCCESS);
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
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = nullptr;
    ASSERT_EQ(surfaceBuffer1, nullptr);
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    int32_t res = imageReceiver->SaveBufferAsImage(fd, surfaceBuffer1, opts);
    ASSERT_EQ(res, SUCCESS);
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
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = nullptr;
    ASSERT_EQ(surfaceBuffer1, nullptr);
    int fd = -1;
    int32_t res = imageReceiver->SaveBufferAsImage(fd, surfaceBuffer1, opts);
    ASSERT_EQ(res, SUCCESS);
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
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    int32_t res = imageReceiver->SaveBufferAsImage(fd, opts);
    ASSERT_EQ(res, SUCCESS);
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
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    int fd = -1;
    int32_t res = imageReceiver->SaveBufferAsImage(fd, opts);
    ASSERT_EQ(res, SUCCESS);
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
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver->ReadLastImage();
    imageReceiver->ReleaseBuffer(surfaceBuffer1);
    ASSERT_EQ(surfaceBuffer1, nullptr);
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
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = nullptr;
    imageReceiver->ReleaseBuffer(surfaceBuffer1);
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
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    ASSERT_NE(imageReceiver->iraContext_, nullptr);
    auto listenerConsumerSurface = imageReceiver->iraContext_->GetReceiverBufferConsumer();
    listenerConsumerSurface = nullptr;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver->ReadLastImage();
    imageReceiver->ReleaseBuffer(surfaceBuffer1);
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
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    sptr<ImageReceiverSurfaceListener> listener = new ImageReceiverSurfaceListener();
    listener->ir_ = imageReceiver;
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
    ASSERT_EQ(surfacebuffer, nullptr);
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
    ASSERT_EQ(surfacebuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0013 end";
}

/**
 * @tc.name: ImageReceiver0014
 * @tc.desc: test ReleaseBuffer listenerConsumerSurface is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0014 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    ASSERT_NE(imageReceiver->iraContext_, nullptr);
    auto listenerConsumerSurface = imageReceiver->iraContext_->GetReceiverBufferConsumer();
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver->ReadLastImage();
    imageReceiver->ReleaseBuffer(surfaceBuffer1);
    ASSERT_EQ(surfaceBuffer1, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0014 end";
}

/**
 * @tc.name: ImageReceiver0015
 * @tc.desc: test ReleaseBuffer iraContext_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0015 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver->ReadLastImage();
    imageReceiver->iraContext_ = nullptr;
    imageReceiver->ReleaseBuffer(surfaceBuffer1);
    ASSERT_EQ(surfaceBuffer1, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0015 end";
}

/**
 * @tc.name: SaveBufferAsImage
 * @tc.desc: test SaveBufferAsImage return
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, SaveBufferAsImage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImage001 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(
        RECEIVER_TEST_WIDTH, RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = imageReceiver->ReadLastImage();
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    int32_t res = imageReceiver->SaveBufferAsImage(fd, buffer, opts);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImage001 end";
}

/**
 * @tc.name: GetBufferProcessorTest001
 * @tc.desc: test GetBufferProcessor
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, GetBufferProcessorTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: GetBufferProcessorTest001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::shared_ptr<IBufferProcessor> surfacebuffer = imageReceiver->GetBufferProcessor();
    ASSERT_EQ(surfacebuffer, imageReceiver->bufferProcessor_);
    ASSERT_NE(nullptr, imageReceiver->bufferProcessor_);
    imageReceiver->bufferProcessor_ = nullptr;
    surfacebuffer = imageReceiver->GetBufferProcessor();
    GTEST_LOG_(INFO) << "ImageReceiverTest: GetBufferProcessorTest001 end";
}

/**
 * @tc.name: NextNativeImageTest001
 * @tc.desc: test NextNativeImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, NextNativeImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: NextNativeImageTest001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::shared_ptr<NativeImage> surfacebuffer = imageReceiver->NextNativeImage();
    ASSERT_EQ(surfacebuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: NextNativeImageTest001 end";
}

/**
 * @tc.name: LastNativeImageTest001
 * @tc.desc: test LastNativeImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, LastNativeImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: LastNativeImageTest001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::shared_ptr<NativeImage> surfacebuffer = imageReceiver->LastNativeImage();
    ASSERT_EQ(surfacebuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: LastNativeImageTest001 end";
}

/**
 * @tc.name: SaveSTPTest001
 * @tc.desc: test SaveSTP
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, SaveSTPTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveSTPTest001 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(
        RECEIVER_TEST_WIDTH, RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    ASSERT_EQ(surfaceBuffer, nullptr);
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    int32_t res = imageReceiver->SaveBufferAsImage(fd, surfaceBuffer, opts);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveSTPTest001 end";
}

/**
 * @tc.name: getSurfaceByIdTest001
 * @tc.desc: test getSurfaceById
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, getSurfaceByIdTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: getSurfaceByIdTest001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::string id;
    auto surfacebuffer = imageReceiver->getSurfaceById(id);
    ASSERT_EQ(surfacebuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: getSurfaceByIdTest001 end";
}

/**
 * @tc.name: ReleaseReceiverTest001
 * @tc.desc: test ReleaseReceiver
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ReleaseReceiverTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ReleaseReceiverTest001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    imageReceiver->ReleaseReceiver();
    GTEST_LOG_(INFO) << "ImageReceiverTest: ReleaseReceiverTest001 end";
}
}
}