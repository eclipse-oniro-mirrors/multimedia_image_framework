/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "media_errors.h"
#include "native_image.h"
#include "image_creator.h"

using namespace testing::ext;
namespace OHOS {
namespace Media {
const std::string DATA_SIZE_TAG = "dataSize";
static constexpr int32_t NUMI_0 = 0;
static constexpr uint32_t NUM_0 = 0;
static constexpr int32_t RECEIVER_TEST_WIDTH = 8192;
static constexpr int32_t RECEIVER_TEST_HEIGHT = 8;
static constexpr int32_t RECEIVER_TEST_CAPACITY = 8;
static constexpr int32_t RECEIVER_TEST_FORMAT = 4;
class NativeImageTest : public testing::Test {
public:
    NativeImageTest() {}
    ~NativeImageTest() {}
};

/**
 * @tc.name: NativeImageTest001
 * @tc.desc: GetSize
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    int32_t width = 0;
    int32_t height = 0;
    int32_t res = image.GetSize(width, height);
    ASSERT_EQ(res, ERR_MEDIA_DEAD_OBJECT);

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest001 end";
}

/**
 * @tc.name: NativeImageTest002
 * @tc.desc: GetDataSize
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest002 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    uint64_t size = 96;
    int32_t res = image.GetDataSize(size);
    ASSERT_EQ(res, ERR_MEDIA_DEAD_OBJECT);

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest002 end";
}

/**
 * @tc.name: NativeImageTest003
 * @tc.desc: GetFormat
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest003 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    int32_t format = 4;
    int32_t res = image.GetFormat(format);
    ASSERT_EQ(res, ERR_MEDIA_DEAD_OBJECT);

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest003 end";
}

/**
 * @tc.name: NativeImageTest004
 * @tc.desc: GetFormat
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest004 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    int32_t type = 4;
    NativeComponent* res = image.GetComponent(type);
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest004 end";
}

/**
 * @tc.name: NativeImageTest005
 * @tc.desc: CombineYUVComponents
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest005 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    uint32_t res = image.CombineYUVComponents();
    ASSERT_NE(res, SUCCESS);

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest005 end";
}

/**
 * @tc.name: NativeImageTest006
 * @tc.desc: CombineYUVComponents
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest006 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    image.release();

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest006 end";
}
/**
 * @tc.name: NativeImageTest006
 * @tc.desc: SplitSurfaceToComponent***
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, SplitSurfaceToComponent, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: SplitSurfaceToComponent start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    image.buffer_ = nullptr;
    int32_t ret = image.SplitSurfaceToComponent();
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "NativeImageTest: SplitSurfaceToComponent end";
}

/**
 * @tc.name: CreateComponent001
 * @tc.desc: CreateComponent
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, CreateComponent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: CreateComponent001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    int32_t type = 1;
    size_t size = 0;
    int32_t row = 1;
    int32_t pixel = 1;
    uint8_t *vir = nullptr;
    std::shared_ptr<IBufferProcessor> release = nullptr;
    NativeImage image(buffer, release);
    NativeComponent *native = new(NativeComponent);
    image.components_.insert(std::make_pair(1, native));
    NativeComponent* ret = image.CreateComponent(type, size, row, pixel, vir);
    ASSERT_NE(ret, nullptr);
    ret = image.CreateComponent(2, size, row, pixel, vir);
    ASSERT_EQ(ret, nullptr);
    size = 1;
    vir = new(uint8_t);
    ret = image.CreateComponent(type, size, row, pixel, vir);
    ASSERT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: CreateComponent001 end";
}

/**
 * @tc.name: GetCachedComponent001
 * @tc.desc: GetCachedComponent
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetCachedComponent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetCachedComponent001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> release = nullptr;
    NativeImage image(buffer, release);
    NativeComponent* ret = image.GetCachedComponent(1);
    ASSERT_EQ(ret, nullptr);
    NativeComponent *native = new(NativeComponent);
    image.components_.insert(std::make_pair(1, native));
    ret = image.GetCachedComponent(1);
    ASSERT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: GetCachedComponent001 end";
}

/**
 * @tc.name: SplitYUV422SPComponent001
 * @tc.desc: SplitYUV422SPComponent
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, SplitYUV422SPComponent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> release = nullptr;
    NativeImage image(buffer, release);
    image.buffer_ = nullptr;
    int32_t ret = image.SplitYUV422SPComponent();
    ASSERT_EQ(ret, ERR_MEDIA_NULL_POINTER);
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent001 end";
}

/**
 * @tc.name: BuildComponent001
 * @tc.desc: BuildComponent
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, BuildComponent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: BuildComponent001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    size_t size = 10;
    int32_t row = 10;
    int32_t pixel = 10;
    uint8_t *vir = new uint8_t;
    int32_t type = 1;
    image.components_.clear();
    image.CreateComponent(type, size, row, pixel, vir);
    ASSERT_EQ(1, image.components_.size());
    image.components_.clear();
    image.CreateComponent(type, size, row, pixel, vir);
    ASSERT_EQ(1, image.components_.size());
    GTEST_LOG_(INFO) << "NativeImageTest: BuildComponent001 end";
}

/**
 * @tc.name: NativeImageTest007
 * @tc.desc: NativeImage
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest007 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    sptr<SurfaceBuffer> buffer = creator->DequeueImage();
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);

    int32_t ret1 = image.SplitYUV422SPComponent();
    ASSERT_EQ(ret1, SUCCESS);

    uint64_t size = 0;
    auto extraData = image.buffer_->GetExtraData();
    int32_t extraDataSize = NUMI_0;
    auto res = extraData->ExtraGet(DATA_SIZE_TAG, extraDataSize);
    ASSERT_NE(res, NUM_0);
    int32_t ret2 = image.GetDataSize(size);
    ASSERT_EQ(ret2, SUCCESS);

    int32_t width = 0;
    int32_t height = 0;
    int32_t ret3 = image.GetSize(width, height);
    ASSERT_EQ(ret3, SUCCESS);

    int32_t format = 0;
    int32_t ret4 = image.GetFormat(format);
    ASSERT_EQ(format, image.buffer_->GetFormat());
    ASSERT_EQ(ret4, SUCCESS);

    int32_t ret5 = image.SplitSurfaceToComponent();
    ASSERT_EQ(ret5, ERR_MEDIA_DATA_UNSUPPORT);

    uint32_t ret6 = image.CombineYUVComponents();
    ASSERT_EQ(ret6, SUCCESS);

    int32_t type = 0;
    auto ret7 = image.CreateCombineComponent(type);
    ASSERT_NE(ret7, nullptr);

    type = 1;
    NativeComponent* ret8 = image.GetComponent(type);
    ASSERT_NE(ret8, nullptr);
    type = image.buffer_->GetFormat();
    ret8 = image.GetComponent(type);
    ASSERT_NE(ret8, nullptr);
    NativeComponent nativeComponent;
    NativeComponent *native = &nativeComponent;
    image.components_.insert(std::make_pair(type, native));
    ret8 = image.GetComponent(type);
    ASSERT_NE(ret8, nullptr);

    uint8_t *ret9 = image.GetSurfaceBufferAddr();
    ASSERT_NE(ret9, nullptr);
    image.buffer_ = nullptr;
    ret9 = image.GetSurfaceBufferAddr();
    ASSERT_EQ(ret9, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest007 end";
}

/**
 * @tc.name: BuildComponentTest002
 * @tc.desc: BuildComponent
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, BuildComponentTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: BuildComponentTest002 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    size_t size = 10;
    int32_t row = 10;
    int32_t pixel = 10;
    uint8_t *vir = nullptr;
    int32_t type = 10;
    image.components_.clear();
    auto ret = image.CreateComponent(type, size, row, pixel, vir);
    auto iter = image.components_.find(type);
    ASSERT_EQ(iter->first, 10);
    ASSERT_NE(iter->second.get(), nullptr);
    ASSERT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: BuildComponentTest002 end";
}

/**
 * @tc.name: GetTimestampTest001
 * @tc.desc: GetTimestamp
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetTimestampTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetTimestampTest001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    int64_t timestamp = 0;
    int32_t ret = image.GetTimestamp(timestamp);
    ASSERT_EQ(ret, ERR_MEDIA_DEAD_OBJECT);

    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    buffer = creator->DequeueImage();
    ASSERT_NE(buffer, nullptr);
    NativeImage nativeImage(buffer, releaser);
    ret = nativeImage.GetTimestamp(timestamp);
    ASSERT_EQ(timestamp, nativeImage.timestamp_);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "NativeImageTest: GetTimestampTest001 end";
}

/**
 * @tc.name: releaseTest002
 * @tc.desc: release
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, releaseTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: releaseTest002 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    sptr<SurfaceBuffer> buffer = creator->DequeueImage();
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::shared_ptr<IBufferProcessor> releaser = imageReceiver->GetBufferProcessor();
    ASSERT_NE(releaser, nullptr);
    NativeImage image(buffer, releaser);

    int32_t type = image.buffer_->GetFormat();
    image.GetComponent(type);
    NativeComponent nativeComponent;
    NativeComponent *native = &nativeComponent;
    image.components_.insert(std::make_pair(type, native));
    image.GetComponent(type);
    ASSERT_TRUE(image.components_.size() > 0);
    image.release();
    ASSERT_EQ(image.releaser_, nullptr);
    ASSERT_EQ(image.buffer_, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: releaseTest002 end";
}
}
}