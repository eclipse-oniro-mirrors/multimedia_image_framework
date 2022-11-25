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

using namespace testing::ext;
using namespace OHOS::Media;
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
}
}

