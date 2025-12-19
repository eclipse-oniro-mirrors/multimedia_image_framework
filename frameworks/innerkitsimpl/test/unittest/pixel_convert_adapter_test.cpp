/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include "image_source.h"
#include "image_source_util.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_convert_adapter.h"
#include "pixel_map.h"
#include "pixel_yuv_utils.h"

using namespace testing::ext;
using namespace OHOS::Media;

#define VALID_RGBX_BUFFER_SIZE 12
#define VALID_RGB_BUFFER_SIZE 9
#define INVALID_BYTE_COUNT 11
#define VALID_BYTE_COUNT 12
#define SRC_WIDTH_10 10
#define SRC_HEIGHT_10 10
#define DST_WIDTH_5 5
#define DST_HEIGHT_5 5
#define BYTES_PER_PIXEL_4 4
#define YUV_WIDTH_4 4
#define YUV_HEIGHT_4 4
#define YUV_Y_SIZE 16
#define YUV_UV_SIZE 8
#define RGB_BUFFER_SIZE 48

namespace OHOS {
namespace Multimedia {
class PixelConvertAdapterTest : public testing::Test {
public:
    PixelConvertAdapterTest() {}
    ~PixelConvertAdapterTest() {}
};

/**
 * @tc.name: PixelConvertAdapterTest001
 * @tc.desc: WritePixelsConvert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, PixelConvertAdapterTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest001 start";
    PixelMap pixelMap;
    uint32_t srcRowBytes = 2;
    uint32_t rowDataSize = 3 * srcRowBytes;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::RGB_565;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * 3;
    void *srcPixels = malloc(bufferSize);
    EXPECT_NE(srcPixels, nullptr);

    PixelMap pixelMap1;
    uint32_t dstRowBytes = 2;
    uint32_t rowDataSize1 = 3 * dstRowBytes;
    ImageInfo dstInfo;
    dstInfo.size.width = 4;
    dstInfo.size.height = 4;
    dstInfo.pixelFormat = PixelFormat::RGB_565;
    dstInfo.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(dstInfo);
    uint32_t bufferSize1 = rowDataSize1 * 3;
    void *dstPixels = malloc(bufferSize1);
    EXPECT_NE(dstPixels, nullptr);

    Position dstPos;
    dstPos.x = 0;
    dstPos.y = 0;
    bool ret = PixelConvertAdapter::WritePixelsConvert(srcPixels,
        srcRowBytes, info, dstPixels, dstPos, dstRowBytes, dstInfo);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest001 end";
}

/**
 * @tc.name: PixelConvertAdapterTest002
 * @tc.desc: WritePixelsConvert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, PixelConvertAdapterTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest002 start";
    void *srcPixels = nullptr;
    uint32_t srcRowBytes = 1;
    ImageInfo srcInfo;
    void *dstPixels = nullptr;
    Position dstPos;
    dstPos.x = 0;
    dstPos.y = 0;
    uint32_t dstRowBytes = 1;
    ImageInfo dstInfo;
    bool ret = PixelConvertAdapter::WritePixelsConvert(srcPixels,
        srcRowBytes, srcInfo, dstPixels, dstPos, dstRowBytes, dstInfo);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest002 end";
}

/**
 * @tc.name: PixelConvertAdapterTest003
 * @tc.desc: ReadPixelsConvert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, PixelConvertAdapterTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest003 start";
    PixelMap pixelMap;
    uint32_t srcRowBytes = 2;
    uint32_t rowDataSize = 3 * srcRowBytes;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::RGB_565;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * 3;
    void *srcPixels = malloc(bufferSize);
    EXPECT_NE(srcPixels, nullptr);

    PixelMap pixelMap1;
    uint32_t dstRowBytes = 2;
    uint32_t rowDataSize1 = 3 * dstRowBytes;
    ImageInfo dstInfo;
    dstInfo.size.width = 4;
    dstInfo.size.height = 4;
    dstInfo.pixelFormat = PixelFormat::RGB_565;
    dstInfo.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(dstInfo);
    uint32_t bufferSize1 = rowDataSize1 * 3;
    void *dstPixels = malloc(bufferSize1);
    EXPECT_NE(dstPixels, nullptr);

    Position dstPos;
    dstPos.x = 0;
    dstPos.y = 0;
    bool ret = PixelConvertAdapter::ReadPixelsConvert(srcPixels,
        dstPos, srcRowBytes, info, dstPixels, dstRowBytes, dstInfo);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest003 end";
}

/**
 * @tc.name: PixelConvertAdapterTest004
 * @tc.desc: ReadPixelsConvert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, PixelConvertAdapterTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest004 start";
    void *srcPixels = nullptr;
    uint32_t srcRowBytes = 1;
    ImageInfo srcInfo;
    srcInfo.size.width = 3;
    srcInfo.size.height = 3;
    srcInfo.pixelFormat = PixelFormat::RGB_565;
    srcInfo.colorSpace = ColorSpace::SRGB;
    void *dstPixels = nullptr;
    Position dstPos;
    dstPos.x = 0;
    dstPos.y = 0;
    uint32_t dstRowBytes = 1;
    ImageInfo dstInfo;
    bool ret = PixelConvertAdapter::ReadPixelsConvert(srcPixels,
        dstPos, srcRowBytes, srcInfo, dstPixels, dstRowBytes, dstInfo);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest004 end";
}

/**
 * @tc.name: PixelConvertAdapterTest005
 * @tc.desc: EraseBitmap
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, PixelConvertAdapterTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest005 start";
    PixelMap pixelMap;
    uint32_t srcRowBytes = 2;
    uint32_t rowDataSize = 3 * srcRowBytes;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::RGB_565;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * 3;
    void *srcPixels = malloc(bufferSize);
    EXPECT_NE(srcPixels, nullptr);
    uint32_t color = 0;
    bool ret = PixelConvertAdapter::EraseBitmap(srcPixels, srcRowBytes, info, color);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest005 end";
}

/**
 * @tc.name: PixelConvertAdapterTest006
 * @tc.desc: EraseBitmap
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, PixelConvertAdapterTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest006 start";
    PixelMap pixelMap;
    uint32_t srcRowBytes = 2;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::RGB_565;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    void *srcPixels = nullptr;
    uint32_t color = 0;
    bool ret = PixelConvertAdapter::EraseBitmap(srcPixels, srcRowBytes, info, color);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest006 end";
}

/**
 * @tc.name: PixelConvertAdapterTest007
 * @tc.desc: WritePixelsConvert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, PixelConvertAdapterTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest007 start";
    PixelMap pixelMap;
    uint32_t srcRowBytes = 2;
    uint32_t rowDataSize = 3 * srcRowBytes;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 4;
    info.pixelFormat = PixelFormat::ARGB_8888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * 3;
    void *srcPixels = malloc(bufferSize);
    EXPECT_NE(srcPixels, nullptr);

    PixelMap pixelMap1;
    uint32_t dstRowBytes = 2;
    uint32_t rowDataSize1 = 3 * dstRowBytes;
    ImageInfo dstInfo;
    dstInfo.size.width = 4;
    dstInfo.size.height = 4;
    dstInfo.pixelFormat = PixelFormat::ARGB_8888;
    dstInfo.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(dstInfo);
    uint32_t bufferSize1 = rowDataSize1 * 3;
    void *dstPixels = malloc(bufferSize1);
    EXPECT_NE(dstPixels, nullptr);

    Position dstPos;
    dstPos.x = 0;
    dstPos.y = 0;
    bool ret = PixelConvertAdapter::WritePixelsConvert(srcPixels,
        srcRowBytes, info, dstPixels, dstPos, dstRowBytes, dstInfo);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest007 end";
}

/**
 * @tc.name: PixelConvertAdapterTest008
 * @tc.desc: WritePixelsConvert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, PixelConvertAdapterTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest008 start";
    PixelMap pixelMap;
    uint32_t srcRowBytes = 2;
    uint32_t rowDataSize = 3 * srcRowBytes;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::ARGB_8888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * 3;
    void *srcPixels = malloc(bufferSize);
    EXPECT_NE(srcPixels, nullptr);

    PixelMap pixelMap1;
    uint32_t dstRowBytes = 2;
    uint32_t rowDataSize1 = 3 * dstRowBytes;
    ImageInfo dstInfo;
    dstInfo.size.width = 4;
    dstInfo.size.height = 3;
    dstInfo.pixelFormat = PixelFormat::ARGB_8888;
    dstInfo.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(dstInfo);
    uint32_t bufferSize1 = rowDataSize1 * 3;
    void *dstPixels = malloc(bufferSize1);
    EXPECT_NE(dstPixels, nullptr);

    Position dstPos;
    dstPos.x = 0;
    dstPos.y = 0;
    bool ret = PixelConvertAdapter::WritePixelsConvert(srcPixels,
        srcRowBytes, info, dstPixels, dstPos, dstRowBytes, dstInfo);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest008 end";
}

/**
 * @tc.name: PixelConvertAdapterTest009
 * @tc.desc: WritePixelsConvert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, PixelConvertAdapterTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest009 start";
    PixelMap pixelMap;
    uint32_t srcRowBytes = 2;
    uint32_t rowDataSize = 3 * srcRowBytes;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * 3;
    void *srcPixels = malloc(bufferSize);
    EXPECT_NE(srcPixels, nullptr);

    PixelMap pixelMap1;
    uint32_t dstRowBytes = 2;
    uint32_t rowDataSize1 = 3 * dstRowBytes;
    ImageInfo dstInfo;
    dstInfo.size.width = 4;
    dstInfo.size.height = 3;
    dstInfo.pixelFormat = PixelFormat::RGB_888;
    dstInfo.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(dstInfo);
    uint32_t bufferSize1 = rowDataSize1 * 3;
    void *dstPixels = malloc(bufferSize1);
    EXPECT_NE(dstPixels, nullptr);

    Position dstPos;
    dstPos.x = 0;
    dstPos.y = 0;
    bool ret = PixelConvertAdapter::WritePixelsConvert(srcPixels,
        srcRowBytes, info, dstPixels, dstPos, dstRowBytes, dstInfo);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest009 end";
}

/**
 * @tc.name: PixelConvertAdapterTest0010
 * @tc.desc: WritePixelsConvert
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, PixelConvertAdapterTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest0010 start";
    PixelMap pixelMap;
    uint32_t srcRowBytes = 2;
    uint32_t rowDataSize = 3 * srcRowBytes;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 4;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * 3;
    void *srcPixels = malloc(bufferSize);
    EXPECT_NE(srcPixels, nullptr);

    PixelMap pixelMap1;
    uint32_t dstRowBytes = 2;
    uint32_t rowDataSize1 = 3 * dstRowBytes;
    ImageInfo dstInfo;
    dstInfo.size.width = 4;
    dstInfo.size.height = 4;
    dstInfo.pixelFormat = PixelFormat::RGB_888;
    dstInfo.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(dstInfo);
    uint32_t bufferSize1 = rowDataSize1 * 3;
    void *dstPixels = malloc(bufferSize1);
    EXPECT_NE(dstPixels, nullptr);

    Position dstPos;
    dstPos.x = 0;
    dstPos.y = 0;
    bool ret = PixelConvertAdapter::WritePixelsConvert(srcPixels,
        srcRowBytes, info, dstPixels, dstPos, dstRowBytes, dstInfo);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: PixelConvertAdapterTest0010 end";
}

/**
 * @tc.name: YUV420ToRGB888Test001
 * @tc.desc: Verify YUV420ToRGB888 conversion fails with invalid input parameters
 *           Tests empty/invalid source/destination buffers return false
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, YUV420ToRGB888Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: YUV420ToRGB888Test001 start";
    uint8_t src[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t dst[] = {0};
    YuvImageInfo srcInfo;
    YuvImageInfo dstInfo;
    bool result = PixelConvertAdapter::YUV420ToRGB888(src, srcInfo, dst, dstInfo);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: YUV420ToRGB888Test001 end";
}

/**
 * @tc.name: RGBxToRGBInvalidByteCountTest001
 * @tc.desc: Test RGBxToRGB with byteCount not multiple of 4
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, RGBxToRGBInvalidByteCountTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: RGBxToRGBInvalidByteCountTest001 start";
    uint8_t srcPixels[VALID_RGBX_BUFFER_SIZE] = {0xFF, 0x00, 0x00, 0x00,
                                                  0x00, 0xFF, 0x00, 0x00,
                                                  0x00, 0x00, 0xFF, 0x00};
    uint8_t dstPixels[VALID_RGB_BUFFER_SIZE];
    
    bool result = PixelConvertAdapter::RGBxToRGB(srcPixels, dstPixels, INVALID_BYTE_COUNT);
    ASSERT_FALSE(result);
    
    result = PixelConvertAdapter::RGBxToRGB(srcPixels, dstPixels, VALID_BYTE_COUNT);
    ASSERT_TRUE(result);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: RGBxToRGBInvalidByteCountTest001 end";
}

/**
 * @tc.name: ReadPixelsConvertOutOfBoundsTest001
 * @tc.desc: Test ReadPixelsConvert fails when reading pixels with out-of-bounds position
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, ReadPixelsConvertOutOfBoundsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: ReadPixelsConvertOutOfBoundsTest001 start";

    ImageInfo srcInfo;
    srcInfo.size.width = SRC_WIDTH_10;
    srcInfo.size.height = SRC_HEIGHT_10;
    srcInfo.pixelFormat = PixelFormat::RGBA_8888;
    srcInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    srcInfo.colorSpace = ColorSpace::SRGB;

    ImageInfo dstInfo;
    dstInfo.size.width = DST_WIDTH_5;
    dstInfo.size.height = DST_HEIGHT_5;
    dstInfo.pixelFormat = PixelFormat::RGBA_8888;
    dstInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    dstInfo.colorSpace = ColorSpace::SRGB;

    uint32_t srcBufferSize = SRC_WIDTH_10 * SRC_HEIGHT_10 * BYTES_PER_PIXEL_4;
    uint32_t dstBufferSize = DST_WIDTH_5 * DST_HEIGHT_5 * BYTES_PER_PIXEL_4;

    std::vector<uint8_t> srcBuffer(srcBufferSize, 0xFF);
    std::vector<uint8_t> dstBuffer(dstBufferSize);

    Position srcPos;
    srcPos.x = SRC_WIDTH_10;
    srcPos.y = SRC_HEIGHT_10;

    uint32_t srcRowBytes = SRC_WIDTH_10 * BYTES_PER_PIXEL_4;
    uint32_t dstRowBytes = DST_WIDTH_5 * BYTES_PER_PIXEL_4;

    bool result = PixelConvertAdapter::ReadPixelsConvert(
        srcBuffer.data(), srcPos, srcRowBytes, srcInfo, dstBuffer.data(), dstRowBytes, dstInfo);

    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: ReadPixelsConvertOutOfBoundsTest001 end";
}

/**
 * @tc.name: YUV420ToRGB888SuccessTest001
 * @tc.desc: Test YUV420ToRGB888 successful conversion with valid parameters
 *           Verifies successful YUV to RGB color space conversion
 * @tc.type: FUNC
 */
HWTEST_F(PixelConvertAdapterTest, YUV420ToRGB888SuccessTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: YUV420ToRGB888SuccessTest001 start";

    uint8_t *yuvData = static_cast<uint8_t*>(malloc(YUV_Y_SIZE + YUV_UV_SIZE));
    ASSERT_NE(yuvData, nullptr);
    std::fill_n(yuvData, YUV_Y_SIZE + YUV_UV_SIZE, 128);

    YuvImageInfo srcInfo;
    srcInfo.width = YUV_WIDTH_4;
    srcInfo.height = YUV_HEIGHT_4;
    srcInfo.format = AVPixelFormat::AV_PIX_FMT_NV12;
    srcInfo.yuvFormat = PixelFormat::NV12;
    srcInfo.yuvDataInfo.yWidth = YUV_WIDTH_4;
    srcInfo.yuvDataInfo.yHeight = YUV_HEIGHT_4;
    srcInfo.yuvDataInfo.uvWidth = YUV_WIDTH_4 / 2;
    srcInfo.yuvDataInfo.uvHeight = YUV_HEIGHT_4 / 2;
    srcInfo.yuvDataInfo.yStride = YUV_WIDTH_4;
    srcInfo.yuvDataInfo.uvStride = YUV_WIDTH_4;
    srcInfo.yuvDataInfo.yOffset = 0;
    srcInfo.yuvDataInfo.uvOffset = YUV_Y_SIZE;

    uint8_t *rgbData = static_cast<uint8_t*>(malloc(RGB_BUFFER_SIZE));
    ASSERT_NE(rgbData, nullptr);

    YuvImageInfo dstInfo;
    dstInfo.width = YUV_WIDTH_4;
    dstInfo.height = YUV_HEIGHT_4;
    dstInfo.format = AVPixelFormat::AV_PIX_FMT_RGB24;
    dstInfo.yuvFormat = PixelFormat::RGB_888;

    bool result = PixelConvertAdapter::YUV420ToRGB888(yuvData, srcInfo, rgbData, dstInfo);

    ASSERT_TRUE(result);

    free(yuvData);
    free(rgbData);
    GTEST_LOG_(INFO) << "PixelConvertAdapterTest: YUV420ToRGB888SuccessTest001 end";
}
}
}

