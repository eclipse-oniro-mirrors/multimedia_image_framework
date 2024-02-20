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


using namespace testing::ext;
namespace OHOS {
namespace Media {
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
    delete(vir);
    vir = nullptr;
    delete(native);
    native = nullptr;
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
    delete(native);
    native = nullptr;
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
    delete vir;
    vir = nullptr;
    image.components_.clear();
    image.CreateComponent(type, size, row, pixel, vir);
    ASSERT_EQ(1, image.components_.size());
    GTEST_LOG_(INFO) << "NativeImageTest: BuildComponent001 end";
}
}
}