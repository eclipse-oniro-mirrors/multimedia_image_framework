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
#include "pixel_yuv_ext_utils.h"

using namespace OHOS::Media;
using namespace testing::ext;
namespace OHOS {
namespace Media {
static const std::string ERROR_MESSAGE = "PixelYuvExtUtilsTest SetDecodeErrorMsg";
class PixelYuvExtUtilsTest : public testing::Test {
    public:
        PixelYuvExtUtilsTest() {}
        ~PixelYuvExtUtilsTest() {}
};

#ifdef EXT_PIXEL
static constexpr int32_t LENGTH = 8;
static constexpr int32_t NUM_2 = 2;

/**
 * @tc.name: Yuv420ToARGB001
 * @tc.desc: Yuv420ToARGB NV21
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtUtilsTest, Yuv420ToARGB001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: Yuv420ToARGB001 start";
    uint8_t src[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t dst[LENGTH] = {0};
    Size size;
    size.width = 1;
    size.height = 1;
    PixelFormat pixelFormat = PixelFormat::NV21;
    YUVDataInfo info;
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: Yuv420ToARGB001 before para 1";
    bool res = PixelYuvExtUtils::Yuv420ToARGB(src, dst, size, pixelFormat, info);
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: Yuv420ToARGB001 after para 1";
    ASSERT_EQ(res, true);
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: Yuv420ToARGB001 end";
}

/**
 * @tc.name: Yuv420ToARGB002
 * @tc.desc: Yuv420ToARGB null pointer
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtUtilsTest, Yuv420ToARGB002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: Yuv420ToARGB002 start";
    uint8_t src[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    Size size;
    size.width = 1;
    size.height = 1;
    PixelFormat pixelFormat = PixelFormat::NV21;
    YUVDataInfo info;
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: Yuv420ToARGB002 before para 1";
    bool res = PixelYuvExtUtils::Yuv420ToARGB(src, nullptr, size, pixelFormat, info);
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: Yuv420ToARGB002 after para 1";
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: Yuv420ToARGB002 end";
}

/**
 * @tc.name: NV12Rotate001
 * @tc.desc: Test NV12Rotate failed
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtUtilsTest, NV12Rotate001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: NV12Rotate001 start";
    uint8_t src[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t dst[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    PixelSize size;
    size.srcW = 1;
    size.srcH = 1;
    size.dstW = 1;
    size.dstH = 0;
    YUVDataInfo info;
    YUVStrideInfo dstStrides;
    auto rotateNum = OpenSourceLibyuv::RotationMode::kRotate90;

    bool res = PixelYuvExtUtils::NV12Rotate(src, size, info, rotateNum, dst, dstStrides);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: NV12Rotate001 end";
}

/**
 * @tc.name: YuvRotate001
 * @tc.desc: Test YuvRotate failed
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtUtilsTest, YuvRotate001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: YuvRotate001 start";
    uint8_t srcPixels[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t dstPixels[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    PixelFormat pixelFormat = PixelFormat::ARGB_8888;
    Size dstSize;
    YUVStrideInfo dstStrides;
    YUVDataInfo info;
    info.yWidth = 0;
    info.yHeight = 0;
    info.imageSize.width = 0;
    info.imageSize.height = 0;
    auto rotateNum = OpenSourceLibyuv::RotationMode::kRotate90;

    bool res = PixelYuvExtUtils::YuvRotate(srcPixels, pixelFormat, info, dstSize, dstPixels, dstStrides, rotateNum);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: YuvRotate001 end";
}

/**
 * @tc.name: ConvertYuvMode001
 * @tc.desc: Test ConvertYuvMode
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtUtilsTest, ConvertYuvMode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: ConvertYuvMode001 start";
    auto filterMode = OpenSourceLibyuv::FilterMode::kFilterBox;
    auto option = AntiAliasingOption::NONE;

    PixelYuvExtUtils::ConvertYuvMode(filterMode, option);
    ASSERT_EQ(filterMode, OpenSourceLibyuv::FilterMode::kFilterNone);
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: ConvertYuvMode001 end";
}

/**
 * @tc.name: ConvertYuvMode002
 * @tc.desc: Test ConvertYuvMode
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtUtilsTest, ConvertYuvMode002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: ConvertYuvMode002 start";
    auto filterMode = OpenSourceLibyuv::FilterMode::kFilterBox;

    auto option = AntiAliasingOption::GAUSS;
    PixelYuvExtUtils::ConvertYuvMode(filterMode, option);
    ASSERT_EQ(filterMode, OpenSourceLibyuv::FilterMode::kFilterBox);
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: ConvertYuvMode002 end";
}

/**
 * @tc.name: Mirror001
 * @tc.desc: Test Mirror failed
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtUtilsTest, Mirror001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: Mirror001 start";
    uint8_t src[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t dst[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    Size size;
    size.width = 0;
    size.height = 0;
    auto format = PixelFormat::NV21;
    YUVDataInfo info;
    YUVStrideInfo dstStrides;
    bool isReversed = false;

    bool res = PixelYuvExtUtils::Mirror(src, dst, size, format, info, dstStrides, isReversed);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "PixelYuvExtUtilsTest: Mirror001 end";
}

/**
 * @tc.name: YuvRotate002
 * @tc.desc: Test YuvRotate with invalid size.
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtUtilsTest, YuvRotate002, TestSize.Level3)
{
    uint8_t srcPixels[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t dstPixels[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    PixelFormat pixelFormat = PixelFormat::YCBCR_P010;
    Size dstSize;
    YUVStrideInfo dstStrides;
    YUVDataInfo info;
    info.yWidth = 0;
    info.yHeight = 0;
    info.imageSize.width = 0;
    info.imageSize.height = 0;
    auto rotateNum = OpenSourceLibyuv::RotationMode::kRotate90;

    bool res = PixelYuvExtUtils::YuvRotate(srcPixels, pixelFormat, info, dstSize, dstPixels, dstStrides, rotateNum);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: YuvRotate003
 * @tc.desc: Test YuvRotate with invalid dstSize and dstStrides.
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtUtilsTest, YuvRotate003, TestSize.Level3)
{
    uint8_t srcPixels[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t dstPixels[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    PixelFormat pixelFormat = PixelFormat::YCBCR_P010;
    Size dstSize;
    YUVStrideInfo dstStrides;
    YUVDataInfo info;
    info.yWidth = NUM_2;
    info.yHeight = NUM_2;
    info.imageSize.width = NUM_2;
    info.imageSize.height = NUM_2;
    info.yStride = info.yWidth;
    info.uvStride = (info.yWidth + 1) / NUM_2 * NUM_2;
    info.yOffset = 0;
    info.uvOffset = info.yWidth * info.yHeight;
    auto rotateNum = OpenSourceLibyuv::RotationMode::kRotate90;

    bool res = PixelYuvExtUtils::YuvRotate(srcPixels, pixelFormat, info, dstSize, dstPixels, dstStrides, rotateNum);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: YuvRotate004
 * @tc.desc: Verify successful rotation by 90 degrees.
 * @tc.type: FUNC
 */
HWTEST_F(PixelYuvExtUtilsTest, YuvRotate004, TestSize.Level3)
{
    uint8_t srcPixels[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t dstPixels[LENGTH] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    PixelFormat pixelFormat = PixelFormat::YCBCR_P010;
    Size dstSize;
    dstSize.width = NUM_2;
    dstSize.height = NUM_2;
    YUVDataInfo info;
    info.yWidth = NUM_2;
    info.yHeight = NUM_2;
    info.imageSize.width = NUM_2;
    info.imageSize.height = NUM_2;
    info.yStride = info.yWidth;
    info.uvStride = (info.yWidth + 1) / NUM_2 * NUM_2;
    info.yOffset = 0;
    info.uvOffset = info.yWidth * info.yHeight;
    YUVStrideInfo dstStrides;
    dstStrides.yStride = info.yWidth;
    dstStrides.uvStride = (info.yWidth + 1) / NUM_2 * NUM_2;
    dstStrides.yOffset = 0;
    dstStrides.uvOffset = info.yWidth * info.yHeight;
    auto rotateNum = OpenSourceLibyuv::RotationMode::kRotate90;

    bool res = PixelYuvExtUtils::YuvRotate(srcPixels, pixelFormat, info, dstSize, dstPixels, dstStrides, rotateNum);
    ASSERT_EQ(res, true);
}
#endif
} // namespace Multimedia
} // namespace OHOS
