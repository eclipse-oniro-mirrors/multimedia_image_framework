/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <memory>
#include "ext_pixel_convert.h"
#include "media_errors.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

static constexpr size_t BYTE_COUNT_NUM_2 = 2;
static constexpr size_t BYTE_COUNT_NUM_4 = 4;
static constexpr size_t BYTE_COUNT_NUM_5 = 5;
static constexpr size_t BYTE_COUNT_NUM_6 = 6;
static constexpr size_t BYTE_COUNT_NUM_7 = 7;
static constexpr size_t BYTE_COUNT_NUM_8 = 8;
static constexpr uint8_t DATA_SIZE = 8;
static constexpr uint8_t DATA_R = 0x10;
static constexpr uint8_t DATA_G = 0x20;
static constexpr uint8_t DATA_B = 0x30;

class ExtPixelConvertTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: RGBxToRGB001
 * @tc.desc: Test RGBxToRGB when src.byteCount is not a multiple of 4 (invalid parameter)
 * @tc.type: FUNC
 */
HWTEST_F(ExtPixelConvertTest, RGBxToRGB001, testing::ext::TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBxToRGB001 start";
    ExtPixels src;
    src.byteCount = BYTE_COUNT_NUM_5;
    ExtPixels dst;
    std::shared_ptr<ExtPixelConvert> extPixelConvert = std::make_shared<ExtPixelConvert>();
    auto ret = extPixelConvert->RGBxToRGB(src, dst);
    EXPECT_EQ(ret, Media::ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBxToRGB001 end";
}

/**
 * @tc.name: RGBxToRGB002
 * @tc.desc: Test RGBxToRGB when dst.byteCount is insufficient (too large)
 * @tc.type: FUNC
 */
HWTEST_F(ExtPixelConvertTest, RGBxToRGB002, testing::ext::TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBxToRGB002 start";
    ExtPixels src;
    src.byteCount = BYTE_COUNT_NUM_4;
    ExtPixels dst;
    dst.byteCount = BYTE_COUNT_NUM_2;
    std::shared_ptr<ExtPixelConvert> extPixelConvert = std::make_shared<ExtPixelConvert>();
    auto ret = extPixelConvert->RGBxToRGB(src, dst);
    EXPECT_EQ(ret, Media::ERR_IMAGE_TOO_LARGE);
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBxToRGB002 end";
}

/**
 * @tc.name: RGBxToRGB003
 * @tc.desc: Test RGBxToRGB with valid parameters (expect success)
 * @tc.type: FUNC
 */
HWTEST_F(ExtPixelConvertTest, RGBxToRGB003, testing::ext::TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBxToRGB003 start";
    ExtPixels src;
    uint8_t srcData[BYTE_COUNT_NUM_4] = {DATA_SIZE, DATA_SIZE + 1, DATA_SIZE + 2, DATA_SIZE + 3};
    src.data = srcData;
    src.byteCount = BYTE_COUNT_NUM_4;
    ExtPixels dst;
    uint8_t dstData[BYTE_COUNT_NUM_6] = {0};
    dst.data = dstData;
    dst.byteCount = BYTE_COUNT_NUM_6;
    std::shared_ptr<ExtPixelConvert> extPixelConvert = std::make_shared<ExtPixelConvert>();
    auto ret = extPixelConvert->RGBxToRGB(src, dst);
    EXPECT_EQ(ret, Media::SUCCESS);
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBxToRGB003 end";
}

/**
 * @tc.name: RGBToRGBx001
 * @tc.desc: Test RGBToRGBx when src.byteCount is not a multiple of 3 (invalid parameter)
 * @tc.type: FUNC
 */
HWTEST_F(ExtPixelConvertTest, RGBToRGBx001, testing::ext::TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBToRGBx001 start";
    ExtPixels src;
    src.byteCount = BYTE_COUNT_NUM_5;
    ExtPixels dst;
    std::shared_ptr<ExtPixelConvert> extPixelConvert = std::make_shared<ExtPixelConvert>();
    auto ret = extPixelConvert->RGBToRGBx(src, dst);
    EXPECT_EQ(ret, Media::ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBToRGBx001 end";
}

/**
 * @tc.name: RGBToRGBx002
 * @tc.desc: Test RGBToRGBx when dst.byteCount is insufficient (too large)
 * @tc.type: FUNC
 */
HWTEST_F(ExtPixelConvertTest, RGBToRGBx002, testing::ext::TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBToRGBx002 start";
    ExtPixels src;
    src.byteCount = BYTE_COUNT_NUM_6;
    uint8_t srcData[BYTE_COUNT_NUM_6] = {0};
    src.data = srcData;
    ExtPixels dst;
    dst.byteCount = BYTE_COUNT_NUM_7;
    uint8_t dstData[BYTE_COUNT_NUM_7] = {0};
    dst.data = dstData;
    std::shared_ptr<ExtPixelConvert> extPixelConvert = std::make_shared<ExtPixelConvert>();
    auto ret = extPixelConvert->RGBToRGBx(src, dst);
    EXPECT_EQ(ret, Media::ERR_IMAGE_TOO_LARGE);
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBToRGBx002 end";
}

/**
 * @tc.name: RGBToRGBx003
 * @tc.desc: Test RGBToRGBx with valid parameters (expect success)
 * @tc.type: FUNC
 */
HWTEST_F(ExtPixelConvertTest, RGBToRGBx003, testing::ext::TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBToRGBx003 start";
    ExtPixels src;
    uint8_t srcData[BYTE_COUNT_NUM_6] = {
        DATA_R, DATA_G, DATA_B,
        DATA_R + 1, DATA_G + 1, DATA_B + 1
    };
    src.data = srcData;
    src.byteCount = BYTE_COUNT_NUM_6;
    ExtPixels dst;
    uint8_t dstData[BYTE_COUNT_NUM_8] = {0};
    dst.data = dstData;
    dst.byteCount = BYTE_COUNT_NUM_8;
    std::shared_ptr<ExtPixelConvert> extPixelConvert = std::make_shared<ExtPixelConvert>();
    auto ret = extPixelConvert->RGBToRGBx(src, dst);
    EXPECT_EQ(ret, Media::SUCCESS);
    GTEST_LOG_(INFO) << "ExtPixelConvertTest: RGBToRGBx003 end";
}
} // namespace ImagePlugin
} // namespace OHOS