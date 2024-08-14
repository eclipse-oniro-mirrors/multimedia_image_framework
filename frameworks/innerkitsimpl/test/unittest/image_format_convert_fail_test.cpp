/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define private public
#define protected public
#include <gtest/gtest.h>

#include "buffer_packer_stream.h"
#include "image_format_convert.h"
#include "image_format_convert_ext_utils.h"
#include "image_log.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"

using namespace testing::ext;
namespace OHOS {
namespace Media {
static constexpr int32_t LENGTH = 8;

struct ImageSize {
    int32_t width = 0;
    int32_t height = 0;
    float dstWidth = 0;
    float dstHeight = 0;
    const uint32_t color = 0;
    uint32_t dst = 0;
};

class ImageFormatConvertFailTest : public testing::Test {
public:
    ImageFormatConvertFailTest() {}
    ~ImageFormatConvertFailTest() {}
    static ConvertFunction TestGetConvertFuncByFormat(PixelFormat srcFormat, PixelFormat destFormat);
};

ConvertFunction ImageFormatConvertFailTest::TestGetConvertFuncByFormat(PixelFormat srcFormat, PixelFormat destFormat)
{
    return ImageFormatConvert::GetConvertFuncByFormat(srcFormat, destFormat);
}

/**
 * @tc.name: GetConvertFuncByFormat_Test_DMA_ALLOC
 * @tc.desc: test RGB_565 to YUV-Nv21 with DMA_ALLOC
 * @tc.type: FUNC
 */
HWTEST_F(ImageFormatConvertFailTest, GetConvertFuncByFormat_Test_DMA_ALLOC, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: GetConvertFuncByFormat_Test_DMA_ALLOC start";
    uint8_t src[LENGTH] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    uint8_t dst[LENGTH] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV21;
    ConvertFunction cvtFunc = ImageFormatConvertFailTest::TestGetConvertFuncByFormat(srcFormat, destFormat);

    const_uint8_buffer_type srcBuffer = src;
    RGBDataInfo rgbInfo = { 1, 1 };
    rgbInfo.stride = 1;
    ColorSpace colorspace = ColorSpace::UNKNOWN;
    DestConvertInfo destInfo = { 1, 1 };
    destInfo.allocType = AllocatorType::DMA_ALLOC;
    destInfo.format = PixelFormat::NV21;
    destInfo.buffer = dst;
    destInfo.bufferSize = 1;
    destInfo.yStride = 1;
    destInfo.uvStride = 2;
    destInfo.yOffset = 1;
    destInfo.uvOffset = 1;

    EXPECT_EQ(cvtFunc(srcBuffer, rgbInfo, destInfo, colorspace), true);
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: GetConvertFuncByFormat_Test_DMA_ALLOC end";
}

/**
 * @tc.name: YUVGetConvertFuncByFormat_DMA_ALLOC
 * @tc.desc: test YUV-Nv21 to RGBA_8888 with DMA_ALLOC
 * @tc.type: FUNC
 */
HWTEST_F(ImageFormatConvertFailTest, YUVGetConvertFuncByFormat_DMA_ALLOC, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: YUVGetConvertFuncByFormat_DMA_ALLOC start";
    uint8_t src[LENGTH] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    uint8_t dst[LENGTH] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    YUVDataInfo yDInfo;

    yDInfo.imageSize = {1, 1};
    yDInfo.yWidth = 1;
    yDInfo.yHeight = 1;
    yDInfo.uvWidth = 2;
    yDInfo.uvHeight = 1;
    yDInfo.yStride = 1;
    yDInfo.uStride = 2;
    yDInfo.vStride = 2;
    yDInfo.uvStride = 2;
    yDInfo.yOffset = 0;
    yDInfo.uOffset = 1;
    yDInfo.vOffset = 1;
    yDInfo.uvOffset = 1;

    ColorSpace colorspace = ColorSpace::UNKNOWN;
    DestConvertInfo destInfo = { 1, 1 };
    destInfo.allocType = AllocatorType::DMA_ALLOC;
    destInfo.format = PixelFormat::RGBA_8888;
    destInfo.buffer = dst;
    destInfo.bufferSize = LENGTH;
    destInfo.yStride = 1;
    destInfo.uvStride = 2;
    destInfo.yOffset = 0;
    destInfo.uvOffset = 1;

    YUVConvertFunction yuvCvtFunc = ImageFormatConvert::YUVGetConvertFuncByFormat(srcFormat, destFormat);
    EXPECT_EQ(yuvCvtFunc(src, yDInfo, destInfo, colorspace), true);
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: YUVGetConvertFuncByFormat_DMA_ALLOC end";
}

/**
 * @tc.name: GetConvertFuncByFormat_Test_Null
 * @tc.desc: test BGRA_8888 to YUV-Nv21 null ptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageFormatConvertFailTest, GetConvertFuncByFormat_Test_Null, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: GetConvertFuncByFormat_Test_Null start";
    PixelFormat srcFormat = PixelFormat::BGRA_8888;
    PixelFormat destFormat = PixelFormat::NV21;
    const_uint8_buffer_type srcBuffer = nullptr;
    RGBDataInfo rgbInfo = { 1, 1 };
    ColorSpace colorspace = ColorSpace::UNKNOWN;
    DestConvertInfo destInfo = { 1, 1 };

    ConvertFunction cvtFunc = ImageFormatConvertFailTest::TestGetConvertFuncByFormat(srcFormat, destFormat);
    EXPECT_EQ(cvtFunc(srcBuffer, rgbInfo, destInfo, colorspace), false);
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: GetConvertFuncByFormat_Test_Null end";
}

/**
 * @tc.name: YUVGetConvertFuncByFormat_Test_Null_8888
 * @tc.desc: test YUV-Nv21 to RGBA_8888 null ptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageFormatConvertFailTest, YUVGetConvertFuncByFormat_Test_Null_8888, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: YUVGetConvertFuncByFormat_Test_Null_8888 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGBA_8888;
    const_uint8_buffer_type srcBuffer = nullptr;
    YUVDataInfo yDInfo;
    ColorSpace colorspace = ColorSpace::UNKNOWN;
    DestConvertInfo destInfo = { 1, 1 };

    YUVConvertFunction yuvCvtFunc = ImageFormatConvert::YUVGetConvertFuncByFormat(srcFormat, destFormat);
    EXPECT_EQ(yuvCvtFunc(srcBuffer, yDInfo, destInfo, colorspace), false);
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: YUVGetConvertFuncByFormat_Test_Null_8888 end";
}

/**
 * @tc.name: YUVGetConvertFuncByFormat_Test_Null_888
 * @tc.desc: test YUV-Nv21 to RGB_888 null ptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageFormatConvertFailTest, YUVGetConvertFuncByFormat_Test_Null_888, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: YUVGetConvertFuncByFormat_Test_Null_888 start";
    PixelFormat srcFormat = PixelFormat::NV21;
    PixelFormat destFormat = PixelFormat::RGB_888;
    const_uint8_buffer_type srcBuffer = nullptr;
    YUVDataInfo yDInfo;
    ColorSpace colorspace = ColorSpace::UNKNOWN;
    DestConvertInfo destInfo = { 1, 1 };

    YUVConvertFunction yuvCvtFunc = ImageFormatConvert::YUVGetConvertFuncByFormat(srcFormat, destFormat);
    EXPECT_EQ(yuvCvtFunc(srcBuffer, yDInfo, destInfo, colorspace), false);
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: YUVGetConvertFuncByFormat_Test_Null_888 end";
}

/**
 * @tc.name: GetConvertFuncByFormat_Test_InvalidSize
 * @tc.desc: test RGB_565 to YUV-Nv21 with invalid width
 * @tc.type: FUNC
 */
HWTEST_F(ImageFormatConvertFailTest, GetConvertFuncByFormat_Test_InvalidSize, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: GetConvertFuncByFormat_Test_DMA_ALLOC start";
    uint8_t src[LENGTH] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    uint8_t dst[LENGTH] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    PixelFormat srcFormat = PixelFormat::RGB_565;
    PixelFormat destFormat = PixelFormat::NV21;
    ConvertFunction cvtFunc = ImageFormatConvertFailTest::TestGetConvertFuncByFormat(srcFormat, destFormat);

    const_uint8_buffer_type srcBuffer = src;
    RGBDataInfo rgbInfo = { PIXEL_MAP_MAX_RAM_SIZE + 1, 1 };
    rgbInfo.stride = PIXEL_MAP_MAX_RAM_SIZE + 1;
    ColorSpace colorspace = ColorSpace::UNKNOWN;
    DestConvertInfo destInfo = { PIXEL_MAP_MAX_RAM_SIZE + 1, 1 };
    destInfo.allocType = AllocatorType::DMA_ALLOC;
    destInfo.format = PixelFormat::NV21;
    destInfo.buffer = dst;
    destInfo.bufferSize = 1;
    destInfo.yStride = PIXEL_MAP_MAX_RAM_SIZE + 1;
    destInfo.uvStride = 2;
    destInfo.yOffset = 1;
    destInfo.uvOffset = 1;

    EXPECT_EQ(cvtFunc(srcBuffer, rgbInfo, destInfo, colorspace), false);
    GTEST_LOG_(INFO) << "ImageFormatConvertFailTest: GetConvertFuncByFormat_Test_DMA_ALLOC end";
}
} // namespace Media
} // namespace OHOS