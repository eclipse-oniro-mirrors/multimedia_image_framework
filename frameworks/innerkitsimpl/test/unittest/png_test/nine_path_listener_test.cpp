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
#include <fstream>
#include <cmath>
#include "securec.h"
#include "memory.h"
#include "nine_patch_listener.h"
#include "png_ninepatch_res.h"

using namespace testing::ext;
namespace OHOS {
namespace Multimedia {

static constexpr int32_t NUM_SINGLE_DIV = 1;
static constexpr int32_t NUM_DOUBLE_DIV = 2;
static constexpr int32_t DIV_POINT_X_THREE = 3;
static constexpr int32_t DIV_POINT_Y_FOUR = 4;
static constexpr int32_t SCALED_DIMENSION_100 = 100;

class NinePathListenerTest : public testing::Test {
public:
    NinePathListenerTest() {}
    ~NinePathListenerTest() {}
};

/**
 * @tc.name: ReadChunk001
 * @tc.desc: test ReadChunk
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, ReadChunk001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk001 start";
    ImagePlugin::NinePatchListener ninepath;
    const std::string tag = "npTc";
    void *data = nullptr;
    ASSERT_EQ(data, nullptr);
    size_t length = 88;
    bool readck = ninepath.ReadChunk(tag, data, length);
    ASSERT_EQ(readck, false);
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk001 end";
}

/**
 * @tc.name: ReadChunk003
 * @tc.desc: Test ReadChunk when patch_ already exists
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, ReadChunk003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk003 start";
    ImagePlugin::NinePatchListener listener;
    listener.patch_ = static_cast<ImagePlugin::PngNinePatchRes *>(
        malloc(sizeof(ImagePlugin::PngNinePatchRes) + NUM_DOUBLE_DIV * sizeof(int32_t)
        + NUM_DOUBLE_DIV * sizeof(int32_t))
    );
    listener.patch_->xDivsOffset = sizeof(ImagePlugin::PngNinePatchRes);
    listener.patch_->yDivsOffset = sizeof(ImagePlugin::PngNinePatchRes) + NUM_DOUBLE_DIV * sizeof(int32_t);
    listener.patch_->numXDivs = NUM_DOUBLE_DIV;
    listener.patch_->numYDivs = NUM_DOUBLE_DIV;
    ImagePlugin::PngNinePatchRes patch;
    patch.numXDivs = 1;
    patch.numYDivs = 1;
    patch.numColors = 1;
    patch.xDivsOffset = sizeof(ImagePlugin::PngNinePatchRes);
    patch.yDivsOffset = sizeof(ImagePlugin::PngNinePatchRes) + sizeof(int32_t);
    size_t length = patch.SerializedSize();
    bool ret = listener.ReadChunk("npTc", &patch, length);
    EXPECT_EQ(ret, true);
    ASSERT_NE(listener.patch_, nullptr);
    free(listener.patch_);
    listener.patch_ = nullptr;
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk003 end";
}

/**
 * @tc.name: ReadChunk004
 * @tc.desc: Test ReadChunk when length != patch.SerializedSize()
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, ReadChunk004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk004 start";
    ImagePlugin::NinePatchListener listener;
    ImagePlugin::PngNinePatchRes patch;
    patch.numXDivs = 1;
    patch.numYDivs = 1;
    patch.numColors = 1;
    patch.xDivsOffset = sizeof(ImagePlugin::PngNinePatchRes);
    patch.yDivsOffset = sizeof(ImagePlugin::PngNinePatchRes) + sizeof(int32_t);
    size_t wrongLength = patch.SerializedSize() + DIV_POINT_Y_FOUR;
    bool ret = listener.ReadChunk("npTc", &patch, wrongLength);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk004 end";
}


/**
 * @tc.name: ReadChunk005
 * @tc.desc: Test ReadChunk with wrong tag or too small length
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, ReadChunk005, TestSize.Level3)
{
    ImagePlugin::NinePatchListener listener;
    ImagePlugin::PngNinePatchRes patch1;
    patch1.numXDivs = 1;
    patch1.numYDivs = 1;
    patch1.numColors = 1;
    patch1.xDivsOffset = sizeof(ImagePlugin::PngNinePatchRes);
    patch1.yDivsOffset = sizeof(ImagePlugin::PngNinePatchRes) + sizeof(int32_t);
    bool ret1 = listener.ReadChunk("abcd", &patch1, patch1.SerializedSize());
    EXPECT_EQ(ret1, true);
    ImagePlugin::PngNinePatchRes patch2;
    patch2.numXDivs = 1;
    patch2.numYDivs = 1;
    patch2.numColors = 1;
    patch2.xDivsOffset = sizeof(ImagePlugin::PngNinePatchRes);
    patch2.yDivsOffset = sizeof(ImagePlugin::PngNinePatchRes) + sizeof(int32_t);
    bool ret2 = listener.ReadChunk("npTc", &patch2, sizeof(ImagePlugin::PngNinePatchRes) - 1);
    EXPECT_EQ(ret2, true);
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk005 end";
}

/**
 * @tc.name: Scale001
 * @tc.desc: test Scale
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, Scale001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NinePathListenerTest: Scale001 start";
    ImagePlugin::NinePatchListener ninepath;
    float scaleX = 1.0;
    float scaleY = 2.0;
    int32_t scaledWidth = 3;
    int32_t scaledHeight = 4;
    ninepath.Scale(scaleX, scaleY, scaledWidth, scaledHeight);
    ASSERT_NE(&ninepath, nullptr);
    GTEST_LOG_(INFO) << "NinePathListenerTest: Scale001 end";
}

/**
 * @tc.name: Scale002
 * @tc.desc: Verify early exit if scaleX/scaleY approx NO_SCALE
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, Scale002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NinePathListenerTest: Scale002 start";
    ImagePlugin::NinePatchListener listener;
    constexpr int32_t numX = 1, numY = 1;
    size_t memSize = sizeof(ImagePlugin::PngNinePatchRes) + numX * sizeof(int32_t) + numY * sizeof(int32_t);
    std::unique_ptr<uint8_t[]> memBuffer = std::make_unique<uint8_t[]>(memSize);
    EXPECT_NE(memBuffer, nullptr);
    listener.patch_ = reinterpret_cast<ImagePlugin::PngNinePatchRes *>(memBuffer.get());
    EXPECT_NE(listener.patch_, nullptr);
    listener.patch_->xDivsOffset = sizeof(ImagePlugin::PngNinePatchRes);
    listener.patch_->yDivsOffset = sizeof(ImagePlugin::PngNinePatchRes) + numX * sizeof(int32_t);
    listener.patch_->numXDivs = numX;
    listener.patch_->numYDivs = numY;
    int32_t *xDivs = listener.patch_->GetXDivs();
    int32_t *yDivs = listener.patch_->GetYDivs();
    EXPECT_NE(xDivs, nullptr);
    EXPECT_NE(yDivs, nullptr);
    xDivs[0] = 1;
    yDivs[0] = 1;
    listener.Scale(1.0f, 1.0f, SCALED_DIMENSION_100, SCALED_DIMENSION_100);
    EXPECT_EQ(xDivs[0], 1);
    EXPECT_EQ(yDivs[0], 1);
    listener.patch_ = nullptr;
    GTEST_LOG_(INFO) << "NinePathListenerTest: Scale002 end";
}

/**
 * @tc.name: Scale003
 * @tc.desc: Verify small difference in scale still triggers ScaleDivRange
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, Scale003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NinePathListenerTest: Scale003 start";
    ImagePlugin::NinePatchListener listener;
    constexpr int32_t numX = NUM_DOUBLE_DIV, numY = NUM_DOUBLE_DIV;
    size_t memSize = sizeof(ImagePlugin::PngNinePatchRes) + numX * sizeof(int32_t) + numY * sizeof(int32_t);
    std::unique_ptr<uint8_t[]> memBuffer = std::make_unique<uint8_t[]>(memSize);
    EXPECT_NE(memBuffer, nullptr);
    listener.patch_ = reinterpret_cast<ImagePlugin::PngNinePatchRes *>(memBuffer.get());
    EXPECT_NE(listener.patch_, nullptr);
    listener.patch_->xDivsOffset = sizeof(ImagePlugin::PngNinePatchRes);
    listener.patch_->yDivsOffset = sizeof(ImagePlugin::PngNinePatchRes) + numX * sizeof(int32_t);
    listener.patch_->numXDivs = numX;
    listener.patch_->numYDivs = numY;
    int32_t *xDivs = listener.patch_->GetXDivs();
    int32_t *yDivs = listener.patch_->GetYDivs();
    EXPECT_NE(xDivs, nullptr);
    EXPECT_NE(yDivs, nullptr);
    
    xDivs[0] = NUM_SINGLE_DIV;
    xDivs[1] = DIV_POINT_X_THREE;
    yDivs[0] = NUM_DOUBLE_DIV;
    yDivs[1] = DIV_POINT_Y_FOUR;
    listener.Scale(1.5f, 2.0f, 200, 200);
    EXPECT_GT(xDivs[1], xDivs[0]);
    EXPECT_GT(yDivs[1], yDivs[0]);
    listener.patch_ = nullptr;
    GTEST_LOG_(INFO) << "NinePathListenerTest: Scale003 end";
}

/**
 * @tc.name: Scale004
 * @tc.desc: test Scale and cover ScaleDivRange
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, Scale004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NinePathListenerTest: Scale004 start";
    ImagePlugin::NinePatchListener listener;
    constexpr int32_t numX = NUM_DOUBLE_DIV, numY = NUM_DOUBLE_DIV;
    size_t memSize = sizeof(ImagePlugin::PngNinePatchRes) + numX * sizeof(int32_t) + numY * sizeof(int32_t);
    std::unique_ptr<uint8_t[]> memBuffer = std::make_unique<uint8_t[]>(memSize);
    EXPECT_NE(memBuffer, nullptr);
    listener.patch_ = reinterpret_cast<ImagePlugin::PngNinePatchRes *>(memBuffer.get());
    EXPECT_NE(listener.patch_, nullptr);
    listener.patch_->xDivsOffset = sizeof(ImagePlugin::PngNinePatchRes);
    listener.patch_->yDivsOffset = sizeof(ImagePlugin::PngNinePatchRes) + numX * sizeof(int32_t);
    listener.patch_->numXDivs = numX;
    listener.patch_->numYDivs = numY;
    int32_t *xDivs = listener.patch_->GetXDivs();
    int32_t *yDivs = listener.patch_->GetYDivs();
    EXPECT_NE(xDivs, nullptr);
    EXPECT_NE(yDivs, nullptr);
    xDivs[0] = NUM_SINGLE_DIV;
    xDivs[1] = DIV_POINT_X_THREE;
    yDivs[0] = NUM_DOUBLE_DIV;
    yDivs[1] = DIV_POINT_Y_FOUR;
    listener.Scale(1.5f, 2.0f, 10, 10);
    EXPECT_GT(xDivs[1], xDivs[0]);
    EXPECT_GT(yDivs[1], yDivs[0]);
    listener.patch_ = nullptr;
    GTEST_LOG_(INFO) << "NinePathListenerTest: Scale004 end";
}

/**
 * @tc.name: ReadChunk002
 * @tc.desc: test ReadChunk
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, ReadChunk002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk002 start";
    ImagePlugin::NinePatchListener ninepath;
    const std::string tag = "npTc";
    int *p = new int;
    int32_t length = 33;
    bool ret = ninepath.ReadChunk(tag, static_cast<void *>(p), length);
    ASSERT_EQ(ret, false);
    delete p;
    p = nullptr;
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk002 end";
}
} // namespace Multimedia
} // namespace OHOS