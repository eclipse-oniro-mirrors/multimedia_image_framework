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
#include <fcntl.h>
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
static const std::string IMAGE_INPUT_JPG_PATH = "/data/local/tmp/image/800-500.jpg";
static constexpr int32_t RECEIVER_TEST_TRUE_WIDTH = 800;
static constexpr int32_t RECEIVER_TEST_TRUE_HEIGHT = 500;

class ImageReceiverTest : public testing::Test {
public:
    ImageReceiverTest() {}
    ~ImageReceiverTest() {}
    void AllocSurfaceBuffer(OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer);
};

class SurfaceBufferAvaliableListenerTest : public SurfaceBufferAvaliableListener {
public:
    void OnSurfaceBufferAvaliable()
    {
        testBool_ = true;
    }
    bool testBool_{false};
};

void ImageReceiverTest::AllocSurfaceBuffer(OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer)
{
    BufferRequestConfig requestConfig = {
        .width = RECEIVER_TEST_TRUE_WIDTH,
        .height = RECEIVER_TEST_TRUE_HEIGHT,
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError ret = surfaceBuffer->Alloc(requestConfig);
    ASSERT_EQ(ret, GSERROR_OK);
}
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
    ASSERT_NE(iva->iraContext_, nullptr);
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
 * @tc.name: ImageReceiver0016
 * @tc.desc: test ReleaseBuffer iraContext_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0015 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    int64_t timestamp = 0;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver->ReadLastImage(timestamp);
    imageReceiver->iraContext_ = nullptr;
    imageReceiver->ReleaseBuffer(surfaceBuffer1);
    ASSERT_EQ(surfaceBuffer1, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0016 end";
}

/**
 * @tc.name: ImageReceiver0017
 * @tc.desc: test ReadNextImage iraContext_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ImageReceiver0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0017 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    int64_t timestamp = 0;
    OHOS::sptr<OHOS::SurfaceBuffer> surfacebuffer = imageReceiver->ReadNextImage(timestamp);
    ASSERT_EQ(surfacebuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiver0017 end";
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
 * @tc.name: GetBufferProcessorTest002
 * @tc.desc: test GetBufferProcessor when bufferProcessor_ already exists
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, GetBufferProcessorTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: GetBufferProcessorTest002 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::shared_ptr<IBufferProcessor> surfacebuffer1 = imageReceiver->GetBufferProcessor();
    ASSERT_EQ(surfacebuffer1, imageReceiver->bufferProcessor_);
    ASSERT_NE(nullptr, imageReceiver->bufferProcessor_);
    IBufferProcessor* rawPtr1 = surfacebuffer1.get();
    std::shared_ptr<IBufferProcessor> surfacebuffer2 = imageReceiver->GetBufferProcessor();
    ASSERT_EQ(surfacebuffer1.get(), surfacebuffer2.get());
    ASSERT_EQ(rawPtr1, surfacebuffer2.get());
    ASSERT_EQ(surfacebuffer2, imageReceiver->bufferProcessor_);
    GTEST_LOG_(INFO) << "ImageReceiverTest: GetBufferProcessorTest002 end";
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
 * @tc.name: NextNativeImageTest002
 * @tc.desc: test NextNativeImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, NextNativeImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: NextNativeImageTest002 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    imageReceiver->bufferProcessor_ = nullptr;
    std::shared_ptr<NativeImage> surfacebuffer = imageReceiver->NextNativeImage();
    ASSERT_EQ(surfacebuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: NextNativeImageTest002 end";
}

/**
 * @tc.name: NextNativeImageTest003
 * @tc.desc: test NextNativeImageTest with ReadNextImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, NextNativeImageTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: NextNativeImageTest003 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    int64_t timestamp = 0;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver->ReadNextImage(timestamp);
    imageReceiver->iraContext_->SetCurrentBuffer(surfaceBuffer1);
    std::shared_ptr<NativeImage> surfacebuffer = imageReceiver->NextNativeImage();
    ASSERT_EQ(surfacebuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: NextNativeImageTest003 end";
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
 * @tc.name: LastNativeImageTest002
 * @tc.desc: test LastNativeImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, LastNativeImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: LastNativeImageTest002 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    imageReceiver->bufferProcessor_ = nullptr;
    std::shared_ptr<NativeImage> surfacebuffer = imageReceiver->LastNativeImage();
    ASSERT_EQ(surfacebuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: LastNativeImageTest002 end";
}

/**
 * @tc.name: LastNativeImageTest003
 * @tc.desc: test LastNativeImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, LastNativeImageTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: LastNativeImageTest003 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1 = imageReceiver->ReadLastImage();
    imageReceiver->iraContext_->SetCurrentBuffer(surfaceBuffer1);
    std::shared_ptr<NativeImage> surfacebuffer = imageReceiver->LastNativeImage();
    ASSERT_EQ(surfacebuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: LastNativeImageTest003 end";
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
 * @tc.name: SaveSTPTest002
 * @tc.desc: test SaveBufferAsImage when PackImage fails (to cover SaveSTP's else branch)
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, SaveSTPTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveSTPTest002 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(
        RECEIVER_TEST_WIDTH, RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    int fd = -1;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t res = imageReceiver->SaveBufferAsImage(fd, surfaceBuffer, opts);
    GTEST_LOG_(INFO) << "SaveBufferAsImage returned: " << res;
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveSTPTest002 end";
}

/**
 * @tc.name: SaveSTPTest003
 * @tc.desc: test SaveBufferAsImage with valid buffer but invalid fd
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, SaveSTPTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveSTPTest003 start";

    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(
        RECEIVER_TEST_WIDTH, RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    int fd = -1;
    int32_t res = imageReceiver->SaveBufferAsImage(fd, surfaceBuffer, opts);
    GTEST_LOG_(INFO) << "SaveBufferAsImage returned: " << res;
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveSTPTest003 end";
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
    ASSERT_EQ(imageReceiver->iraContext_, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ReleaseReceiverTest001 end";
}

/**
 * @tc.name: SaveBufferAsImageTest001
 * @tc.desc: test SaveBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, SaveBufferAsImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest001 start";
    InitializationOptions opts;
    opts.size.width = 0;
    opts.size.height = 0;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(0,
        0, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer;
    ASSERT_EQ(surfaceBuffer, nullptr);
    int fd = -1;
    int32_t res = imageReceiver->SaveBufferAsImage(fd, surfaceBuffer, opts);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest001 end";
}

/**
 * @tc.name: SaveBufferAsImageTest002
 * @tc.desc: test SaveBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, SaveBufferAsImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest002 start";
    InitializationOptions opts;
    opts.size.width = 0;
    opts.size.height = 0;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(0,
        0, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer;
    ASSERT_EQ(surfaceBuffer, nullptr);
    int fd = -1;
    int32_t res = imageReceiver->SaveBufferAsImage(fd, opts);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest002 end";
}

/**
 * @tc.name: SaveBufferAsImageTest003
 * @tc.desc: test SaveBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, SaveBufferAsImageTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest003 start";
    InitializationOptions opts;
    opts.size.width = 0;
    opts.size.height = 0;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(0,
        0, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    int32_t res = imageReceiver->SaveBufferAsImage(fd, opts);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest003 end";
}

/**
 * @tc.name: SaveBufferAsImageTest004
 * @tc.desc: test SaveBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, SaveBufferAsImageTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest004 start";
    InitializationOptions opts;
    opts.size.width = 0;
    opts.size.height = 0;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(0,
        0, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    int32_t res = imageReceiver->SaveBufferAsImage(fd, surfaceBuffer, opts);
    ASSERT_EQ(res, ERR_MEDIA_INVALID_VALUE);
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest004 end";
}

/**
 * @tc.name: SaveBufferAsImageTest005
 * @tc.desc: test SaveBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, SaveBufferAsImageTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest005 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(0,
        0, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    int fd = -1;
    int32_t res = imageReceiver->SaveBufferAsImage(fd, surfaceBuffer, opts);
    ASSERT_EQ(res, ERR_MEDIA_INVALID_VALUE);
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest005 end";
}

/**
 * @tc.name: SaveBufferAsImageTest006
 * @tc.desc: test SaveBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, SaveBufferAsImageTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest006 start";
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(0,
        0, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    int fd = open("/data/receiver/Receiver_buffer7.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    imageReceiver->iraContext_->receiverConsumerSurface_ = nullptr;
    int32_t res = imageReceiver->SaveBufferAsImage(fd, surfaceBuffer, opts);
    ASSERT_EQ(res, ERR_MEDIA_INVALID_VALUE);
    GTEST_LOG_(INFO) << "ImageReceiverTest: SaveBufferAsImageTest006 end";
}

/**
 * @tc.name: GetReceiverSurfaceTest001
 * @tc.desc: test GetReceiverSurface
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, GetReceiverSurfaceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: GetReceiverSurfaceTest001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    sptr<Surface> surfacebuffer = imageReceiver->GetReceiverSurface();
    ASSERT_NE(surfacebuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: GetReceiverSurfaceTest001 end";
}

/**
 * @tc.name: getSurfacePixelMapTest001
 * @tc.desc: test getSurfacePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, getSurfacePixelMapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: getSurfacePixelMapTest001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    ASSERT_NE(imageReceiver->iraContext_, nullptr);
    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_WIDTH;
    opts.size.height = RECEIVER_TEST_HEIGHT;
    opts.editable = true;
    imageReceiver->iraContext_->currentBuffer_ = SurfaceBuffer::Create();
    std::unique_ptr<PixelMap> pixelmp_ptr = imageReceiver->getSurfacePixelMap(opts);
    ASSERT_EQ(pixelmp_ptr, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: getSurfacePixelMapTest001 end";
}

/**
 * @tc.name: ImageReceiverTest_PackImageTest001
 * @tc.desc: Verify that save and pack image from buffer.
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, PackImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiverTest_PackImageTest001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_TRUE_WIDTH,
        RECEIVER_TEST_TRUE_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    ASSERT_NE(imageReceiver->iraContext_, nullptr);

    InitializationOptions opts;
    opts.size.width = RECEIVER_TEST_TRUE_WIDTH;
    opts.size.height = RECEIVER_TEST_TRUE_HEIGHT;
    opts.pixelFormat = Media::PixelFormat::RGBA_8888;
    opts.editable = true;

    imageReceiver->iraContext_->currentBuffer_ = SurfaceBuffer::Create();
    AllocSurfaceBuffer(imageReceiver->iraContext_->currentBuffer_);
    int fd = open(IMAGE_INPUT_JPG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, 0);
    int32_t errorCode = imageReceiver->SaveBufferAsImage(fd, opts);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiverTest_PackImageTest001 end";
}

/**
 * @tc.name: ImageReceiverTest_ReleaseBufferTest001
 * @tc.desc: Verify that call releaseBuffer when buffer and iraContext_ is effective.
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ReleaseBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiverTest_ReleaseBufferTest001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_TRUE_WIDTH,
        RECEIVER_TEST_TRUE_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    ASSERT_NE(imageReceiver->iraContext_, nullptr);

    imageReceiver->iraContext_->currentBuffer_ = SurfaceBuffer::Create();
    AllocSurfaceBuffer(imageReceiver->iraContext_->currentBuffer_);
    imageReceiver->ReleaseBuffer(imageReceiver->iraContext_->currentBuffer_);
    ASSERT_EQ(imageReceiver->iraContext_->currentBuffer_, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiverTest_ReleaseBufferTest001 end";
}

/**
 * @tc.name: ImageReceiverTest_ReleaseBufferTest002
 * @tc.desc: Verify that call releaseBuffer when buffer and iraContext_ is effective,
 *           but receiverConsumerSurface_ is disable.
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ReleaseBufferTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiverTest_ReleaseBufferTest002 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_TRUE_WIDTH,
        RECEIVER_TEST_TRUE_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    ASSERT_NE(imageReceiver->iraContext_, nullptr);

    OHOS::sptr<OHOS::SurfaceBuffer> mockSurfaceBuffer = SurfaceBuffer::Create();
    AllocSurfaceBuffer(mockSurfaceBuffer);
    imageReceiver->iraContext_->receiverConsumerSurface_ = nullptr;
    imageReceiver->ReleaseBuffer(mockSurfaceBuffer);
    ASSERT_EQ(mockSurfaceBuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiverTest_ReleaseBufferTest002 end";
}

/**
 * @tc.name: ImageReceiverTest_ReleaseBufferTest003
 * @tc.desc: Verify that call releaseBuffer when buffer is effective,
 *           but iraContext_ is disable.
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, ReleaseBufferTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiverTest_ReleaseBufferTest003 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_TRUE_WIDTH,
        RECEIVER_TEST_TRUE_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    ASSERT_NE(imageReceiver->iraContext_, nullptr);

    OHOS::sptr<OHOS::SurfaceBuffer> mockSurfaceBuffer = SurfaceBuffer::Create();
    AllocSurfaceBuffer(mockSurfaceBuffer);
    imageReceiver->iraContext_.reset();
    imageReceiver->ReleaseBuffer(mockSurfaceBuffer);
    ASSERT_EQ(mockSurfaceBuffer, nullptr);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiverTest_ReleaseBufferTest003 end";
}

/**
 * @tc.name: ImageReceiverTest_OnBufferAvailableTest001
 * @tc.desc: Verify that ImageSurfaceReceiverListener call OnBufferAvailable when ir_ is effective.
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, OnBufferAvailableTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiverTest_OnBufferAvailableTest001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_TRUE_WIDTH,
        RECEIVER_TEST_TRUE_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ASSERT_NE(imageReceiver, nullptr);
    ASSERT_NE(imageReceiver->iraContext_, nullptr);
    auto avaiableListener = std::make_shared<SurfaceBufferAvaliableListenerTest>();
    ASSERT_NE(avaiableListener, nullptr);
    imageReceiver->RegisterBufferAvaliableListener(avaiableListener);

    auto receiverListener = std::make_shared<ImageReceiverSurfaceListener>();
    ASSERT_NE(receiverListener, nullptr);
    receiverListener->ir_ = imageReceiver;
    receiverListener->OnBufferAvailable();
    ASSERT_EQ(avaiableListener->testBool_, true);
    GTEST_LOG_(INFO) << "ImageReceiverTest: ImageReceiverTest_OnBufferAvailableTest001 end";
}

/**
 * @tc.name: OnBufferAvailableTest002
 * @tc.desc: test OnBufferAvailable with null ir (not set)
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, OnBufferAvailableTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: OnBufferAvailableTest003 start";
    auto receiverListener = std::make_shared<ImageReceiverSurfaceListener>();
    ASSERT_NE(receiverListener, nullptr);
    receiverListener->OnBufferAvailable();
    EXPECT_NO_FATAL_FAILURE(receiverListener->OnBufferAvailable());
    GTEST_LOG_(INFO) << "ImageReceiverTest: OnBufferAvailableTest002 end";
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
 * @tc.name: CreateImageReceiver001
 * @tc.desc: test CreateImageReceiver by options
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverTest, CreateImageReceiver001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverTest: CreateImageReceiver001 start";
    std::shared_ptr<ImageReceiver> imageReceiver;
    ImageReceiverOptions options;
    options.width = RECEIVER_TEST_WIDTH;
    options.height = RECEIVER_TEST_HEIGHT;
    options.capacity = RECEIVER_TEST_CAPACITY;
    imageReceiver = ImageReceiver::CreateImageReceiver(options);
    ASSERT_NE(imageReceiver, nullptr);
    EXPECT_EQ(imageReceiver->iraContext_->GetWidth(), RECEIVER_TEST_WIDTH);
    EXPECT_EQ(imageReceiver->iraContext_->GetHeight(), RECEIVER_TEST_HEIGHT);
    EXPECT_EQ(imageReceiver->iraContext_->GetCapicity(), RECEIVER_TEST_CAPACITY);
    GTEST_LOG_(INFO) << "ImageReceiverTest: CreateImageReceiver001 end";
}
}
}