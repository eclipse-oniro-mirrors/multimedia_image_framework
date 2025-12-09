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
#include <arpa/inet.h>
#include <fstream>
#include <memory>
#include "png_ninepatch_res.h"

using namespace testing::ext;
namespace OHOS {
namespace Multimedia {

static constexpr size_t NUMX_DIVS = 2;
static constexpr size_t NUMY_DIVS = 3;

class PngNinepatchResTest : public testing::Test {
public:
    PngNinepatchResTest() {}
    ~PngNinepatchResTest() {}
};

/**
 * @tc.name: DeviceToFile001
 * @tc.desc: test DeviceToFile
 * @tc.type: FUNC
 */
HWTEST_F(PngNinepatchResTest, DeviceToFile001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngNinepatchResTest: DeviceToFile001 start";
    ImagePlugin::PngNinePatchRes pngnp;
    pngnp.DeviceToFile();
    ASSERT_NE(&pngnp, nullptr);
    GTEST_LOG_(INFO) << "PngNinepatchResTest: DeviceToFile001 end";
}

/**
 * @tc.name: FileToDevice001
 * @tc.desc: test FileToDevice
 * @tc.type: FUNC
 */
HWTEST_F(PngNinepatchResTest, FileToDevice001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngNinepatchResTest: FileToDevice001 start";
    ImagePlugin::PngNinePatchRes pngnp;
    pngnp.FileToDevice();
    ASSERT_NE(&pngnp, nullptr);
    GTEST_LOG_(INFO) << "PngNinepatchResTest: FileToDevice001 end";
}

/**
 * @tc.name: SerializedSize001
 * @tc.desc: test SerializedSize
 * @tc.type: FUNC
 */
HWTEST_F(PngNinepatchResTest, SerializedSize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngNinepatchResTest: SerializedSize001 start";
    ImagePlugin::PngNinePatchRes pngnp;
    const size_t sersize = pngnp.SerializedSize();
    ASSERT_EQ(sersize, 32);
    GTEST_LOG_(INFO) << "PngNinepatchResTest: SerializedSize001 end";
}

/**
 * @tc.name: Deserialize001
 * @tc.desc: Test Deserialize with valid inData (covers Fill9patchOffsets: patch != nullptr)
 * @tc.type: FUNC
 */
HWTEST_F(PngNinepatchResTest, Deserialize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngNinepatchResTest: Deserialize001 start";
    ImagePlugin::PngNinePatchRes patch;
    patch.numXDivs = NUMX_DIVS;
    patch.numYDivs = NUMY_DIVS;
    patch.wasDeserialized = false;
    void* inData = &patch;
    ImagePlugin::PngNinePatchRes* result = ImagePlugin::PngNinePatchRes::Deserialize(inData);
    EXPECT_EQ(result, &patch);
    EXPECT_TRUE(patch.wasDeserialized);
    const size_t structSize = sizeof(ImagePlugin::PngNinePatchRes);
    const size_t xDivsSize = patch.numXDivs * sizeof(int32_t);
    const size_t yDivsSize = patch.numYDivs * sizeof(int32_t);
    const uint32_t expectedXDivsOffset = structSize;
    const uint32_t expectedYDivsOffset = expectedXDivsOffset + xDivsSize;
    const uint32_t expectedColorsOffset = expectedYDivsOffset + yDivsSize;
    EXPECT_EQ(patch.xDivsOffset, expectedXDivsOffset);
    EXPECT_EQ(patch.yDivsOffset, expectedYDivsOffset);
    EXPECT_EQ(patch.colorsOffset, expectedColorsOffset);
    GTEST_LOG_(INFO) << "PngNinepatchResTest: Deserialize001 end";
}
} // namespace Multimedia
} // namespace OHOS