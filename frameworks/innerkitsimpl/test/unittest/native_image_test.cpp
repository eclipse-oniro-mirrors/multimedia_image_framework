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
    int32_t res = image.CombineYUVComponents();
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
}
}