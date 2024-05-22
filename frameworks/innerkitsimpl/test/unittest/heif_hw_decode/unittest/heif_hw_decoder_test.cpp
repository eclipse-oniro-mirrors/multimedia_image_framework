/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "hardware/heif_hw_decoder.h"
#include "image_system_properties.h"
#include "mock_heif_hw_decode_flow.h"
#include "media_errors.h" // foundation/multimedia/image_framework/interfaces/innerkits/include/

namespace OHOS::Media {
using namespace testing::ext;
using namespace OHOS::ImagePlugin;

class HeifHwDecoderTest : public testing::Test {
public:
    static constexpr char TEST_HEIF_IMG_NO_GRID[] = "/data/local/tmp/image/heif_test/1024x1024_nogrid";
    static constexpr char TEST_HEIF_IMG_WITH_GRID[] = "/data/local/tmp/image/heif_test/1024x1024_grid_512x512_2x2";
};

HWTEST_F(HeifHwDecoderTest, AllocOutputBufferWithInvalidSize, TestSize.Level1)
{
    HeifHardwareDecoder testObj;
    sptr<SurfaceBuffer> output = testObj.AllocateOutputBuffer(
        0, 512, static_cast<int32_t>(GRAPHIC_PIXEL_FMT_YCBCR_420_SP));
    ASSERT_TRUE(output == nullptr);
}

HWTEST_F(HeifHwDecoderTest, AllocOutputBufferWithInvalidPixelFmt, TestSize.Level1)
{
    HeifHardwareDecoder testObj;
    sptr<SurfaceBuffer> output = testObj.AllocateOutputBuffer(
        512, 512, static_cast<int32_t>(GRAPHIC_PIXEL_FMT_RGBA_8888));
    ASSERT_TRUE(output == nullptr);
}

HWTEST_F(HeifHwDecoderTest, AllocOutputBufferOk, TestSize.Level1)
{
    HeifHardwareDecoder testObj;
    sptr<SurfaceBuffer> output = testObj.AllocateOutputBuffer(
        1024, 512, static_cast<int32_t>(GRAPHIC_PIXEL_FMT_YCBCR_420_SP));
    ASSERT_TRUE(output != nullptr);
}

HWTEST_F(HeifHwDecoderTest, DoDecodeWithInvalidInputs, TestSize.Level1)
{
    HeifHardwareDecoder testObj;
    GridInfo gridInfo = {
        .displayWidth = 1024,
        .displayHeight = 512,
        .enableGrid = false,
        .cols = 0,
        .rows = 0,
        .tileWidth = 0,
        .tileHeight = 0
    };
    std::vector<std::vector<uint8_t>> inputs;
    sptr<SurfaceBuffer> output = testObj.AllocateOutputBuffer(gridInfo.displayWidth, gridInfo.displayHeight,
                                                              static_cast<int32_t>(GRAPHIC_PIXEL_FMT_YCBCR_420_SP));
    uint32_t ret = testObj.DoDecode(gridInfo, inputs, output);
    ASSERT_TRUE(ret != Media::SUCCESS);
}

HWTEST_F(HeifHwDecoderTest, DoDecodeWithInvalidOutputBuffer, TestSize.Level1)
{
    HeifHardwareDecoder testObj;
    GridInfo gridInfo = {
        .displayWidth = 1024,
        .displayHeight = 512,
        .enableGrid = false,
        .cols = 0,
        .rows = 0,
        .tileWidth = 0,
        .tileHeight = 0
    };
    std::vector<std::vector<uint8_t>> inputs;
    inputs.emplace_back(std::vector<uint8_t>(1));
    inputs.emplace_back(std::vector<uint8_t>(1));
    sptr<SurfaceBuffer> output = nullptr;
    uint32_t ret = testObj.DoDecode(gridInfo, inputs, output);
    ASSERT_TRUE(ret != Media::SUCCESS);
}

HWTEST_F(HeifHwDecoderTest, DoDecodeWithInvalidGridInfo1, TestSize.Level1)
{
    HeifHardwareDecoder testObj;
    GridInfo gridInfo = {
        .displayWidth = 512,
        .displayHeight = 512,
        .enableGrid = true,
        .cols = 0,
        .rows = 0,
        .tileWidth = 0,
        .tileHeight = 0
    };
    std::vector<std::vector<uint8_t>> inputs;
    inputs.emplace_back(std::vector<uint8_t>(1));
    inputs.emplace_back(std::vector<uint8_t>(1));
    sptr<SurfaceBuffer> output = testObj.AllocateOutputBuffer(gridInfo.displayWidth, gridInfo.displayHeight,
                                                              static_cast<int32_t>(GRAPHIC_PIXEL_FMT_YCBCR_420_SP));
    uint32_t ret = testObj.DoDecode(gridInfo, inputs, output);
    ASSERT_TRUE(ret != Media::SUCCESS);
}

HWTEST_F(HeifHwDecoderTest, DoDecodeWithInvalidGridInfo2, TestSize.Level1)
{
    HeifHardwareDecoder testObj;
    GridInfo gridInfo = {
        .displayWidth = 1024,
        .displayHeight = 1024,
        .enableGrid = true,
        .cols = 1,
        .rows = 2,
        .tileWidth = 512,
        .tileHeight = 512
    };
    std::vector<std::vector<uint8_t>> inputs;
    inputs.emplace_back(std::vector<uint8_t>(1));
    inputs.emplace_back(std::vector<uint8_t>(1));
    sptr<SurfaceBuffer> output = testObj.AllocateOutputBuffer(gridInfo.displayWidth, gridInfo.displayHeight,
                                                              static_cast<int32_t>(GRAPHIC_PIXEL_FMT_YCBCR_420_SP));
    uint32_t ret = testObj.DoDecode(gridInfo, inputs, output);
    ASSERT_TRUE(ret != Media::SUCCESS);
}

HWTEST_F(HeifHwDecoderTest, DoDecodeWithInvalidGridInfo3, TestSize.Level1)
{
    HeifHardwareDecoder testObj;
    GridInfo gridInfo = {
        .displayWidth = 512,
        .displayHeight = 512,
        .enableGrid = true,
        .cols = 1,
        .rows = 1,
        .tileWidth = 512,
        .tileHeight = 0
    };
    std::vector<std::vector<uint8_t>> inputs;
    inputs.emplace_back(std::vector<uint8_t>(1));
    inputs.emplace_back(std::vector<uint8_t>(1));
    sptr<SurfaceBuffer> output = testObj.AllocateOutputBuffer(gridInfo.displayWidth, gridInfo.displayHeight,
                                                              static_cast<int32_t>(GRAPHIC_PIXEL_FMT_YCBCR_420_SP));
    uint32_t ret = testObj.DoDecode(gridInfo, inputs, output);
    ASSERT_TRUE(ret != Media::SUCCESS);
}

HWTEST_F(HeifHwDecoderTest, DoDecodeWithInvalidGridInfo4, TestSize.Level1)
{
    HeifHardwareDecoder testObj;
    GridInfo gridInfo = {
        .displayWidth = 513,
        .displayHeight = 512,
        .enableGrid = true,
        .cols = 1,
        .rows = 1,
        .tileWidth = 512,
        .tileHeight = 512
    };
    std::vector<std::vector<uint8_t>> inputs;
    inputs.emplace_back(std::vector<uint8_t>(1));
    inputs.emplace_back(std::vector<uint8_t>(1));
    sptr<SurfaceBuffer> output = testObj.AllocateOutputBuffer(gridInfo.displayWidth, gridInfo.displayHeight,
                                                              static_cast<int32_t>(GRAPHIC_PIXEL_FMT_YCBCR_420_SP));
    uint32_t ret = testObj.DoDecode(gridInfo, inputs, output);
    ASSERT_TRUE(ret != Media::SUCCESS);
}

HWTEST_F(HeifHwDecoderTest, DoDecodeOkNoGrid, TestSize.Level1)
{
    bool ret = true;
    if (ImageSystemProperties::GetHardWareDecodeEnabled()) {
        CommandOpt opt = {
            .pixelFormat = UserPixelFormat::NV21,
            .inputPath = TEST_HEIF_IMG_NO_GRID
        };
        HeifHwDecoderFlow testObj;
        ret = testObj.Run(opt);
    }
    ASSERT_TRUE(ret);
}

HWTEST_F(HeifHwDecoderTest, DoDecodeOkWithGrid, TestSize.Level1)
{
    bool ret = true;
    if (ImageSystemProperties::GetHardWareDecodeEnabled()) {
        CommandOpt opt = {
            .pixelFormat = UserPixelFormat::NV21,
            .inputPath = TEST_HEIF_IMG_WITH_GRID
        };
        HeifHwDecoderFlow testObj;
        ret = testObj.Run(opt);
    }
    ASSERT_TRUE(ret);
}
} // namespace OHOS::Media