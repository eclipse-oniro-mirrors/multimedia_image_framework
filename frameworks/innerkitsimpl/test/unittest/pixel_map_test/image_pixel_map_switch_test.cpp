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
#include <string>
#include "media_errors.h"
#include "pixel_map.h"
#include "color_space.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
constexpr int32_t MAX_DIMENSION = INT32_MAX >> 2;
static constexpr int32_t PIXEL_MAP_TEST_WIDTH = 3;
static constexpr int32_t PIXEL_MAP_TEST_HEIGHT = 3;
class ImagePixelMapSwitchTest : public testing::Test {
public:
    ImagePixelMapSwitchTest() {}
    ~ImagePixelMapSwitchTest() {}
};

/**
 * @tc.name: ImagePixelMapSwitchTest001
 * @tc.desc: create pixelmap with color,colorlength,offset,width and initialization options
 * @tc.desc: !CheckParams(colors, colorLength, offset, stride, opts)
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest001 start";
    /**
     * @tc.steps: step1. set color,colorlength,offset,width and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    const uint32_t color[8] = {};
    uint32_t colorlength = 8;
    const int32_t offset = 1;
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = opts.size.width;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(color, colorlength, offset, width, opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest001 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest002
 * @tc.desc: create pixelmap with color,colorlength,offset,width and initialization options
 * @tc.desc: dstPixelMap->SetImageInfo(dstImageInfo) != SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest002 start";
    /**
     * @tc.steps: step1. set color,colorlength,offset,width and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    uint32_t colorlength = sizeof(color) / sizeof(color[0]);
    const int32_t offset = 1;
    InitializationOptions opts;
    opts.size.width = 0;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = opts.size.width;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(color, colorlength, offset, width, opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest002 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest002
 * @tc.desc: create pixelmap with color,colorlength,offset,width and initialization options
 * @tc.desc: bufferSize == 0
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest002_1, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest002 start";
    /**
     * @tc.steps: step1. set color,colorlength,offset,width and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    const uint32_t color[8] = {};
    uint32_t colorlength = 8;
    const int32_t offset = 1;
    InitializationOptions opts;
    opts.size.width = 0;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = opts.size.width;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(color, colorlength, offset, width, opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest002 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest003
 * @tc.desc: create pixelmap with initialization options
 * @tc.desc: dstPixelMap->SetImageInfo(dstImageInfo) != SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest003 start";
    /**
     * @tc.steps: step1. set initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    InitializationOptions opts;
    opts.size.width = 0;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest003 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest004
 * @tc.desc: create pixelmap with initialization options
 * @tc.desc: bufferSize > PIXEL_MAP_MAX_RAM_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest003 start";
    /**
     * @tc.steps: step1. set initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    InitializationOptions opts;
    opts.size.width = 700 * 1024 * 1024;
    opts.size.height = 700 * 1024 * 1024;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest004 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest005
 * @tc.desc: create pixelmap with pixelmap, rect and InitializationOptions options
 * @tc.desc: cropType == CropValue::INVALID
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest005 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    ImageInfo info;
    info.size.width = 0;
    info.size.height = 0;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    PixelMap srcPixelMap;
    srcPixelMap.SetImageInfo(info);
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    
    Rect rect;
    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(srcPixelMap, rect, opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest005 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest006
 * @tc.desc: create pixelmap ,and then SetImageInfo
 * @tc.desc: info.size.width <= 0
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest006 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 0;
    info.size.height = 0;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    uint32_t ret = pixelMap.SetImageInfo(info, isReused);
    EXPECT_EQ(ret, ERR_IMAGE_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest006 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest007
 * @tc.desc: create pixelmap ,and then SetImageInfo
 * @tc.desc: PixelFormat = UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest007 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::UNKNOWN;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    uint32_t ret = pixelMap.SetImageInfo(info, isReused);
    EXPECT_EQ(ret, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest007 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest008
 * @tc.desc: GetPixel8
 * @tc.desc: !CheckValidParam(x, y)
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest008 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    pixelMap.SetImageInfo(info, isReused);
    const uint8_t* ret = pixelMap.GetPixel8(300, 400);
    EXPECT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest008 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest009
 * @tc.desc: GetPixel16
 * @tc.desc: !CheckValidParam(x, y)
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest009 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    pixelMap.SetImageInfo(info, isReused);
    const uint16_t* ret = pixelMap.GetPixel16(300, 400);
    EXPECT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest009 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest010
 * @tc.desc: GetPixel32
 * @tc.desc: !CheckValidParam(x, y)
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest010 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    pixelMap.SetImageInfo(info, isReused);
    const uint32_t* ret = pixelMap.GetPixel32(300, 400);
    EXPECT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest010 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest011
 * @tc.desc: GetPixel
 * @tc.desc: !CheckValidParam(x, y)
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest011 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    pixelMap.SetImageInfo(info, isReused);
    const uint8_t* ret = pixelMap.GetPixel(300, 400);
    EXPECT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest011 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest012
 * @tc.desc: GetARGB32Color
 * @tc.desc: colorProc_ == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest012 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    uint32_t color = 0;
    bool ret = pixelMap.GetARGB32Color(200, 300, color);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest012 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest013
 * @tc.desc: GetARGB32Color
 * @tc.desc: src == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest013 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    pixelMap.SetImageInfo(info, isReused);
    uint32_t color = 0;
    bool ret = pixelMap.GetARGB32Color(300, 400, color);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest013 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest014
 * @tc.desc: SetAlpha
 * @tc.desc: AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN == alphaType
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest014 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::UNKNOWN;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    pixelMap.SetImageInfo(info, isReused);
    float percent = 0.8;
    bool ret = pixelMap.SetAlpha(percent);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest014 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest015
 * @tc.desc: SetAlpha
 * @tc.desc: percent <= 0 || percent > 1
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest015 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    pixelMap.SetImageInfo(info, isReused);
    float percent = 1.5;
    bool ret = pixelMap.SetAlpha(percent);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest015 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest016
 * @tc.desc: WritePixel
 * @tc.desc: pos.x < 0 || pos.y < 0 || pos.x >= GetWidth() || pos.y >= GetHeight()
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest016 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    Position position;
    position.x = -1;
    position.y = -1;
    uint32_t color = 9;
    uint32_t ret = pixelMap.WritePixel(position, color);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest016 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest017
 * @tc.desc: WritePixel
 * @tc.desc: pos.x < 0 || pos.y < 0 || pos.x >= GetWidth() || pos.y >= GetHeight()
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest017 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    Position position;
    position.x = 300;
    position.y = 400;
    uint32_t color = 9;
    uint32_t ret = pixelMap.WritePixel(position, color);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest017 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest018
 * @tc.desc: WritePixel
 * @tc.desc: !IsEditable()
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest018 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::ARGB_8888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    Position position;
    position.x = 100;
    position.y = 200;
    uint32_t color = 9;
    uint32_t ret = pixelMap.WritePixel(position, color);
    EXPECT_EQ(ret, ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest018 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest019
 * @tc.desc: WritePixel
 * @tc.desc: !IsEditable()
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest019 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::UNKNOWN;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    Position position;
    position.x = 100;
    position.y = 200;
    uint32_t color = 9;
    uint32_t ret = pixelMap.WritePixel(position, color);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest019 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest020
 * @tc.desc: WritePixel
 * @tc.desc: IsValidImageInfo(imageInfo_)
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest020 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    ImageInfo info;
    pixelMap.SetImageInfo(info);
    Position position;
    position.x = 0;
    position.y = 0;
    uint32_t color = 9;
    uint32_t ret = pixelMap.WritePixel(position, color);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest020 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest021
 * @tc.desc: WritePixel
 * @tc.desc: data_ == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest021, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest021 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    PixelMap pixelMap;
    Position position;
    // 0 means position
    position.x = 0;
    position.y = 0;
    // 9 for test
    uint32_t color = 9;
    uint32_t res = pixelMap.WritePixel(position, color);
    ASSERT_EQ(res, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest021 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest022
 * @tc.desc: FreePixelMap
 * @tc.desc: case AllocatorType::SHARE_MEM_ALLOC:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest022, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest022 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    // 3 means pixelmap perPixel bytes
    int8_t bytesPerPixel = 3;
    int8_t rowDataSize = PIXEL_MAP_TEST_WIDTH * bytesPerPixel;
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::RGB_565;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * PIXEL_MAP_TEST_HEIGHT;
    void *buffer = malloc(bufferSize);
    EXPECT_NE(buffer, nullptr);
    pixelMap.SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::SHARE_MEM_ALLOC, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest022 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest023
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest023 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    const uint32_t *colors = nullptr;
    // 8 means colorlength
    uint32_t colorlength = 8;
    // 1 means offset
    const int32_t offset = 1;
    InitializationOptions opts;
    // 200 means opts width
    opts.size.width = 200;
    // 300 means opts height
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = opts.size.width;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(colors, colorlength, offset, width, opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest023 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest024
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest024 start";
    /**
     * @tc.steps: step1. set pixelmap, rect and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    // 8 means real color length
    // { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 } used for test
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    // 0 means test color length
    uint32_t colorlength = 0;
    // 1 means offset
    const int32_t offset = 1;
    InitializationOptions opts;
    // 200 means opts width
    opts.size.width = 200;
    // 300 means opts height
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = opts.size.width;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(color, colorlength, offset, width, opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest024 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest025
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest025 start";

    InitializationOptions opts;
    // 700 * 1024 * 1024 means opts width
    opts.size.width = 700 * 1024 * 1024;
    // 700 * 1024 * 1024 means opts height
    opts.size.height = 700 * 1024 * 1024;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest025 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest026
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest026 start";

    InitializationOptions opts;
    // 700 * 1024 * 1024 means opts width
    opts.size.width = 700 * 1024 * 1024;
    // 700 * 1024 * 1024 means opts height
    opts.size.height = 700 * 1024 * 1024;
    opts.pixelFormat = PixelFormat::BGRA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest026 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest027
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest027 start";
    ImageInfo info;
    // 200 means info width
    info.size.width = 200;
    // 300 means info height
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    PixelMap srcPixelMap;
    srcPixelMap.SetImageInfo(info);
    InitializationOptions opts;
    // 200 means opts width
    opts.size.width = 200;
    // 300 means opts height
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    Rect rect;
    // 0, 0, 300, 400 means rect for test
    rect.left = 0;
    rect.top = 0;
    rect.width = 300;
    rect.height = 400;
    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(srcPixelMap, rect, opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest027 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest027_1
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest027_1, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest027 start";
    PixelMap pixelMap;
    ImageInfo info;
    // 200 means info width
    info.size.width = 200;
    // 300 means info height
    info.size.height = 300;
    info.pixelFormat = PixelFormat::NV21;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    uint32_t res = pixelMap.SetImageInfo(info, isReused);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest027 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest028
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest028, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest028 start";
    PixelMap pixelMap;
    ImageInfo info;
    // 200 means info width
    info.size.width = 200;
    // 300 means info height
    info.size.height = 300;
    info.pixelFormat = PixelFormat::CMYK;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    uint32_t res = pixelMap.SetImageInfo(info, isReused);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest028 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest029
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest029, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest029 start";
    PixelMap pixelMap;
    ImageInfo info;
    // 200 means info width
    info.size.width = 200;
    // 300 means info height
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    uint32_t res = pixelMap.SetImageInfo(info, isReused);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest029 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest030
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest030, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest030 start";
    PixelMap pixelMap;
    ImageInfo info;
    // 200 means info width
    info.size.width = 200;
    // 300 means info height
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    bool isReused = false;
    uint32_t res = pixelMap.SetImageInfo(info, isReused);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest030 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest031
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest031, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest031 start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    // 0 means bufferSize
    uint64_t bufferSize = 0;
    // 0 means offset
    uint32_t offset = 0;
    // 8 means stride
    uint32_t stride = 8;
    Rect rect;
    // 0, 0, 1, 2 means rect for test
    rect.left = 0;
    rect.top = 0;
    rect.height = 1;
    rect.width = 2;
    uint8_t *dst = nullptr;
    uint32_t res1 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res1, ERR_IMAGE_INVALID_PARAMETER);

    // 96 means bufferSize
    bufferSize = 96;
    // -1 means rect left
    rect.left = -1;
    uint32_t res2 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res2, ERR_IMAGE_INVALID_PARAMETER);

    // 0 means rect left
    rect.left = 0;
    // -1 means rect top
    rect.top = -1;
    uint32_t res3 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res3, ERR_IMAGE_INVALID_PARAMETER);

    // 0 means rect top
    rect.top = 0;
    stride = std::numeric_limits<int32_t>::max();
    uint32_t res4 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res4, ERR_IMAGE_INVALID_PARAMETER);

    // 8 means stride
    stride = 8;
    // 128 means offset
    offset = 128;
    uint32_t res5 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res5, ERR_IMAGE_INVALID_PARAMETER);

    // 0 means offset and rect.width
    offset = 0;
    rect.width = 0;
    uint32_t res6 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res6, ERR_IMAGE_INVALID_PARAMETER);

    // 1 used to test when width beyond max
    rect.width = MAX_DIMENSION + 1;
    uint32_t res7 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res7, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest031 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest031_1
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest031_1, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest031 start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    // 96 means bufferSize
    uint64_t bufferSize = 96;
    // 0 means offset
    uint32_t offset = 0;
    // 8 means stride
    uint32_t stride = 8;
    Rect rect;
    // 0, 0, 1, 2 means rect for test
    rect.left = 0;
    rect.top = 0;
    rect.height = 1;
    rect.width = 2;
    uint8_t *dst = nullptr;
    uint32_t res1 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res1, ERR_IMAGE_INVALID_PARAMETER);

    // 0 means rect height
    rect.height = 0;
    uint32_t res2 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res2, ERR_IMAGE_INVALID_PARAMETER);

    // 1 used to test when height beyond max
    rect.height = MAX_DIMENSION + 1;
    uint32_t res3 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res3, ERR_IMAGE_INVALID_PARAMETER);

    // 1 means rect height
    rect.height = 1;
    // 3 means rect left
    rect.left = 3;
    uint32_t res4 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res4, ERR_IMAGE_INVALID_PARAMETER);

    // 0 means rect left
    rect.left = 0;
    // 3 means rect top
    rect.top = 3;
    uint32_t res5 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res5, ERR_IMAGE_INVALID_PARAMETER);

    // 6 means stride
    stride = 6;
    uint32_t res6 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res6, ERR_IMAGE_INVALID_PARAMETER);

    // 8 means stride
    stride = 8;
    // 6 means bufferSize
    bufferSize = 6;
    uint32_t res7 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res7, ERR_IMAGE_INVALID_PARAMETER);

    // 96 means bufferSize and offset
    bufferSize = 96;
    offset = 96;
    uint32_t res8 = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    ASSERT_EQ(res8, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest031 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest032
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest032, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest032 start";
    PixelMap pixelMap;
    ImageInfo info;
    // 200 means info width
    info.size.width = 200;
    // 300 means info height
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    // 96 means bufferSize
    uint64_t bufferSize = 96;
    // 0 means offset
    uint32_t offset = 0;
    // 8 means stride
    uint32_t stride = 8;
    Rect rect;
    // 0, 0, 1, 2 means rect for test
    rect.left = 0;
    rect.top = 0;
    rect.height = 1;
    rect.width = 2;
    uint8_t *source = nullptr;
    uint32_t res = pixelMap.WritePixels(source, bufferSize, offset, stride, rect);
    ASSERT_EQ(res, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest032 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest033
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest033, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest033 start";
    PixelMap pixelMap;
    ImageInfo info;
    // 0 means info width
    info.size.width = 0;
    // 300 means info height
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    // 1 means color
    uint32_t color = 1;
    uint32_t res = pixelMap.WritePixels(color);
    ASSERT_EQ(res, SUCCESS);

    // 200 means info width
    info.size.width = 200;
    pixelMap.SetImageInfo(info);
    uint32_t res1 = pixelMap.WritePixels(color);
    ASSERT_EQ(res1, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest033 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest034
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest034, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest034 start";
    PixelMap pixelMap;
    ImageInfo info;
    // 200 means info width
    info.size.width = 200;
    // 300 means info height
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    uint32_t ret1 = pixelMap.SetImageInfo(info);
    ASSERT_EQ(ret1, SUCCESS);
    // 0.0 means alpha percent
    float percent = 0.0;
    uint32_t res1 = pixelMap.SetAlpha(percent);
    ASSERT_EQ(res1, ERR_IMAGE_DATA_UNSUPPORT);

    // 2.0 means alpha percent
    percent = 2.0;
    uint32_t res2 = pixelMap.SetAlpha(percent);
    ASSERT_EQ(res2, ERR_IMAGE_DATA_UNSUPPORT);

    // 0.5 means alpha percent
    percent = 0.5;
    info.pixelFormat = PixelFormat::ARGB_8888;
    uint32_t ret3 = pixelMap.SetImageInfo(info);
    ASSERT_EQ(ret3, SUCCESS);
    uint32_t res3 = pixelMap.SetAlpha(percent);
    ASSERT_EQ(res3, ERR_IMAGE_DATA_UNSUPPORT);

    info.pixelFormat = PixelFormat::ALPHA_8;
    uint32_t ret4 = pixelMap.SetImageInfo(info);
    ASSERT_EQ(ret4, SUCCESS);
    uint32_t res4 = pixelMap.SetAlpha(percent);
    ASSERT_EQ(res4, ERR_IMAGE_DATA_UNSUPPORT);

    info.pixelFormat = PixelFormat::RGBA_8888;
    uint32_t ret5 = pixelMap.SetImageInfo(info);
    ASSERT_EQ(ret5, SUCCESS);
    uint32_t res5 = pixelMap.SetAlpha(percent);
    ASSERT_EQ(res5, ERR_IMAGE_DATA_UNSUPPORT);

    info.pixelFormat = PixelFormat::BGRA_8888;
    uint32_t ret6 = pixelMap.SetImageInfo(info);
    ASSERT_EQ(ret6, SUCCESS);
    uint32_t res6 = pixelMap.SetAlpha(percent);
    ASSERT_EQ(res6, ERR_IMAGE_DATA_UNSUPPORT);

    info.pixelFormat = PixelFormat::RGBA_F16;
    uint32_t ret7 = pixelMap.SetImageInfo(info);
    ASSERT_EQ(ret7, SUCCESS);
    uint32_t res7 = pixelMap.SetAlpha(percent);
    ASSERT_EQ(res7, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest034 end";
}

/**
 * @tc.name: ImagePixelMapSwitchTest035
 * @tc.desc:
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapSwitchTest, ImagePixelMapSwitchTest035, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest035 start";

    InitializationOptions opts;
    // 100 means opts width
    opts.size.width = 100;
    // 300 means opts height
    opts.size.height = 400;
    opts.pixelFormat = PixelFormat::BGRA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(opts);
    int num = newPixelMap->GetCapacity();
    GTEST_LOG_(INFO) << "buffersize :"<< num;
    // 160000 means pixelmap capacity
    EXPECT_EQ(num, 160000);
    EXPECT_NE(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapSwitchTest: ImagePixelMapSwitchTest035 end";
}
} // namespace Multimedia
} // namespace OHOS