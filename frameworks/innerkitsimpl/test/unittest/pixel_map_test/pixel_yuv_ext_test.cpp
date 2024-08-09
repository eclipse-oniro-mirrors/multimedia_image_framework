/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <string>

#include "media_errors.h"
#include "pixel_yuv_ext.h"
#include "pixel_yuv_ext_utils.h"

using namespace OHOS::Media;
using namespace testing::ext;
namespace OHOS {
namespace Media {
class PixelYuvExtTest : public testing::Test {
public:
    PixelYuvExtTest() {}
    ~PixelYuvExtTest() {}
};

#ifdef EXT_PIXEL
static constexpr int32_t LENGTH = 8;

/**
 * @tc.name: ScaleAbnormal_001
 * @tc.desc: ScaleAbnormal_001 pixelYuvExt None
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtTest, ScaleAbnormal_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtTest: ScaleAbnormal_001 start";
    float xAxis = 0.5f;
    float yAxis = 1.0f;
    PixelYuvExt pixelYuvExt;
    auto width = pixelYuvExt.imageInfo_.size.width;
    pixelYuvExt.scale(xAxis, yAxis);
    ASSERT_EQ(width, pixelYuvExt.imageInfo_.size.width);
    GTEST_LOG_(INFO) << "PixelYuvExtTest: ScaleAbnormal_001 end";
}

/**
 * @tc.name: ScaleAbnormal_002
 * @tc.desc: ScaleAbnormal_002 invalid size
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtTest, ScaleAbnormal_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtTest: ScaleAbnormal_002 start";
    float xAxis = 1.0f;
    float yAxis = 1.0f;
    PixelYuvExt pixelYuvExt;
    pixelYuvExt.imageInfo_.pixelFormat = PixelFormat::NV21;
    pixelYuvExt.imageInfo_.size.width = PIXEL_MAP_MAX_RAM_SIZE + 1;
    pixelYuvExt.imageInfo_.size.height = PIXEL_MAP_MAX_RAM_SIZE;
    pixelYuvExt.allocatorType_ = AllocatorType::HEAP_ALLOC;
    pixelYuvExt.scale(xAxis, yAxis);
    ASSERT_EQ(PIXEL_MAP_MAX_RAM_SIZE + 1, pixelYuvExt.imageInfo_.size.width);
    GTEST_LOG_(INFO) << "PixelYuvExtTest: ScaleAbnormal_002 end";
}

/**
 * @tc.name: RotateAbnormal_001
 * @tc.desc: RotateAbnormal_001
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtTest, RotateAbnormal_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtTest: RotateAbnormal_001 start";
    PixelYuvExt pixelYuvExt;
    auto width = pixelYuvExt.imageInfo_.size.width;
    pixelYuvExt.rotate(0);
    ASSERT_EQ(width, pixelYuvExt.imageInfo_.size.width);
    pixelYuvExt.imageInfo_.pixelFormat = PixelFormat::NV21;
    pixelYuvExt.rotate(1.0f);
    ASSERT_EQ(width, pixelYuvExt.imageInfo_.size.width);
    pixelYuvExt.rotate(-1.0f);
    ASSERT_EQ(width, pixelYuvExt.imageInfo_.size.width);
    GTEST_LOG_(INFO) << "PixelYuvExtTest: RotateAbnormal_001 end";
}

/**
 * @tc.name: RotateAbnormal_002
 * @tc.desc: RotateAbnormal_002 invalid size
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtTest, RotateAbnormal_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtTest: RotateAbnormal_002 start";
    PixelYuvExt pixelYuvExt;
    auto width = pixelYuvExt.imageInfo_.size.width;
    pixelYuvExt.imageInfo_.pixelFormat = PixelFormat::NV21;
    pixelYuvExt.rotate(90.0f);
    ASSERT_EQ(width, pixelYuvExt.imageInfo_.size.width);
    pixelYuvExt.imageInfo_.size.width = 1;
    pixelYuvExt.imageInfo_.size.height = 1;
    pixelYuvExt.allocatorType_ = AllocatorType::HEAP_ALLOC;
    pixelYuvExt.rotate(180.0f);
    ASSERT_EQ(1, pixelYuvExt.imageInfo_.size.width);
    GTEST_LOG_(INFO) << "PixelYuvExtTest: RotateAbnormal_002 end";
}

/**
 * @tc.name: FlipAbnormal_001
 * @tc.desc: FlipAbnormal_001 invalid size
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtTest, FlipAbnormal_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtTest: FlipAbnormal_001 start";
    PixelYuvExt pixelYuvExt;
    pixelYuvExt.imageInfo_.pixelFormat = PixelFormat::NV21;
    pixelYuvExt.imageInfo_.size.width = PIXEL_MAP_MAX_RAM_SIZE + 1;
    pixelYuvExt.imageInfo_.size.height = PIXEL_MAP_MAX_RAM_SIZE;
    pixelYuvExt.allocatorType_ = AllocatorType::HEAP_ALLOC;
    pixelYuvExt.flip(true, true);
    ASSERT_EQ(PIXEL_MAP_MAX_RAM_SIZE + 1, pixelYuvExt.imageInfo_.size.width);
    GTEST_LOG_(INFO) << "PixelYuvExtTest: FlipAbnormal_001 end";
}

#ifdef IMAGE_COLORSPACE_FLAG
/**
 * @tc.name: ColorSpaceBGRAToYuvAbnormal_001
 * @tc.desc: ColorSpaceBGRAToYuvAbnormal_001
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtTest, ColorSpaceBGRAToYuvAbnormal_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtTest: ColorSpaceBGRAToYuvAbnormal_001 start";
    PixelYuvExt pixelYuvExt;
    ImageInfo imageInfo;
    uint8_t src[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    SkTransYuvInfo dst;
    Size size;
    size.width = 1;
    size.height = 1;
    PixelFormat pixelFormat = PixelFormat::NV21;
    auto grColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    uint32_t ret = pixelYuvExt.ColorSpaceBGRAToYuv(src, dst, imageInfo, pixelFormat, grColorSpace);
    ASSERT_EQ(ret, ERR_IMAGE_COLOR_CONVERT);
    GTEST_LOG_(INFO) << "PixelYuvExtTest: ColorSpaceBGRAToYuvAbnormal_001 end";
}

/**
 * @tc.name: ApplyColorSpaceAbnormal_001
 * @tc.desc: ApplyColorSpaceAbnormal_001
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtTest, ApplyColorSpaceAbnormal_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtTest: ApplyColorSpaceAbnormal_001 start";
    PixelYuvExt pixelYuvExt;
    auto grColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    uint32_t ret = pixelYuvExt.ApplyColorSpace(grColorSpace);
    ASSERT_EQ(ret, ERR_IMAGE_COLOR_CONVERT);
    GTEST_LOG_(INFO) << "PixelYuvExtTest: ApplyColorSpaceAbnormal_001 end";
}

/**
 * @tc.name: ApplyColorSpaceAbnormal_002
 * @tc.desc: ApplyColorSpaceAbnormal_002
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtTest, ApplyColorSpaceAbnormal_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtTest: ApplyColorSpaceAbnormal_002 start";
    auto grColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    PixelYuvExt pixelYuvExt;
    pixelYuvExt.imageInfo_.pixelFormat = PixelFormat::NV21;
    uint32_t ret = pixelYuvExt.ApplyColorSpace(grColorSpace);
    ASSERT_EQ(ret, ERR_MEDIA_INVALID_VALUE);
    GTEST_LOG_(INFO) << "PixelYuvExtTest: ApplyColorSpaceAbnormal_002 end";
}
#endif
#endif
} // namespace Multimedia
} // namespace OHOS