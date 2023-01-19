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
#include "media_errors.h"
#include "pixel_map.h"
#include "color_space.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
static constexpr int32_t PIXEL_MAP_TEST_WIDTH = 3;
static constexpr int32_t PIXEL_MAP_TEST_HEIGHT = 3;
static constexpr int32_t PIXEL_MAP_RGB565_BYTE = 2;
static constexpr int32_t PIXEL_MAP_RGB888_BYTE = 3;
static constexpr int32_t PIXEL_MAP_ARGB8888_BYTE = 4;
constexpr int32_t PIXEL_MAP_BIG_TEST_WIDTH = 4 * 1024;
constexpr int32_t PIXEL_MAP_BIG_TEST_HEIGHT = 3 * 100;

class ImagePixelMapTest : public testing::Test {
public:
    ImagePixelMapTest() {}
    ~ImagePixelMapTest() {}
};

    std::unique_ptr<PixelMap> ConstructPixmap()
    {
        int32_t pixelMapWidth = 4;
        int32_t pixelMapHeight = 3;
        std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
        ImageInfo info;
        info.size.width = pixelMapWidth;
        info.size.height = pixelMapHeight;
        info.pixelFormat = PixelFormat::RGB_888;
        info.colorSpace = ColorSpace::SRGB;
        pixelMap->SetImageInfo(info);

        int32_t rowDataSize = pixelMapWidth;
        uint32_t bufferSize = rowDataSize * pixelMapHeight;
        if (bufferSize <= 0) {
            return nullptr;
        }
        void *buffer = malloc(bufferSize);
        if (buffer == nullptr) {
            return nullptr;
        }
        char *ch = reinterpret_cast<char *>(buffer);
        for (unsigned int i = 0; i < bufferSize; i++) {
            *(ch++) = (char)i;
        }

        pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);

        return pixelMap;
    }

    std::unique_ptr<PixelMap> ConstructBigPixmap()
    {
        int32_t pixelMapWidth = PIXEL_MAP_BIG_TEST_WIDTH;
        int32_t pixelMapHeight = PIXEL_MAP_BIG_TEST_HEIGHT;
        std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
        ImageInfo info;
        info.size.width = pixelMapWidth;
        info.size.height = pixelMapHeight;
        info.pixelFormat = PixelFormat::RGB_888;
        info.colorSpace = ColorSpace::SRGB;
        pixelMap->SetImageInfo(info);

        int32_t bufferSize = pixelMap->GetByteCount();
        if (bufferSize <= 0) {
            return nullptr;
        }
        void *buffer = malloc(bufferSize);
        if (buffer == nullptr) {
            return nullptr;
        }
        char *ch = reinterpret_cast<char *>(buffer);
        for (int32_t i = 0; i < bufferSize; i++) {
            *(ch++) = 'a';
        }

        pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);

        return pixelMap;
    }
/**
 * @tc.name: ImagePixelMap001
 * @tc.desc: ALPHA_8 pixel format pixel map operation
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ImagePixelMap001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap001 start";
    /**
     * @tc.steps: step1. Set image info and alloc pixel map memory.
     * @tc.expected: step1. The pixel map info is correct.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    int32_t rowDataSize = (PIXEL_MAP_TEST_WIDTH + 3) / 4 * 4;
    uint32_t bufferSize = rowDataSize * PIXEL_MAP_TEST_HEIGHT;
    void *buffer = malloc(bufferSize);
    EXPECT_NE(buffer, nullptr);
    pixelMap.SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    uint8_t *data = const_cast<uint8_t *>(pixelMap.GetPixels());
    EXPECT_NE(data, nullptr);
    EXPECT_EQ(pixelMap.GetHeight(), PIXEL_MAP_TEST_HEIGHT);
    EXPECT_EQ(pixelMap.GetWidth(), PIXEL_MAP_TEST_WIDTH);
    EXPECT_EQ(pixelMap.GetPixelFormat(), PixelFormat::ALPHA_8);
    EXPECT_EQ(pixelMap.GetColorSpace(), ColorSpace::SRGB);
    EXPECT_EQ(pixelMap.GetPixelBytes(), 1);
    EXPECT_EQ(pixelMap.GetRowBytes(), rowDataSize);
    EXPECT_EQ(pixelMap.GetByteCount(), PIXEL_MAP_TEST_HEIGHT * rowDataSize);
    /**
     * @tc.steps: step2. Get image info.
     * @tc.expected: step2. The pixel map info is correct
     */
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    EXPECT_EQ(outInfo.size.width, info.size.width);
    EXPECT_EQ(outInfo.size.height, info.size.height);
    EXPECT_EQ(outInfo.pixelFormat, info.pixelFormat);
    EXPECT_EQ(outInfo.colorSpace, info.colorSpace);
    /**
     * @tc.steps: step3. Set image color data and get image color value.
     * @tc.expected: step3. The image color value is correct
     */
    for (int32_t i = 0; i < rowDataSize * PIXEL_MAP_TEST_HEIGHT; i++) {
        data[i] = i;
    }
    uint32_t color = 0;
    EXPECT_NE(pixelMap.GetPixel8(1, 1), nullptr);
    EXPECT_EQ(*pixelMap.GetPixel8(1, 1), 0x05);
    EXPECT_EQ(pixelMap.GetARGB32Color(1, 1, color), true);
    EXPECT_EQ(pixelMap.GetARGB32ColorA(color), 5);
    EXPECT_EQ(pixelMap.GetARGB32ColorR(color), 0);
    EXPECT_EQ(pixelMap.GetARGB32ColorG(color), 0);
    EXPECT_EQ(pixelMap.GetARGB32ColorB(color), 0);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap001 end";
}

/**
 * @tc.name: ImagePixelMap002
 * @tc.desc: RGB_565 pixel format pixel map operation
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ImagePixelMap002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap002 start";
    /**
     * @tc.steps: step1. Set image info and alloc pixel map memory.
     * @tc.expected: step1. The pixel map info is correct.
     */
    PixelMap pixelMap;
    int8_t bytesPerPixel = 2;
    int8_t rowDataSize = PIXEL_MAP_TEST_WIDTH * bytesPerPixel;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::RGB_565;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * PIXEL_MAP_TEST_HEIGHT;
    void *buffer = malloc(bufferSize);
    EXPECT_NE(buffer, nullptr);
    pixelMap.SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    uint8_t *data = const_cast<uint8_t *>(pixelMap.GetPixels());
    EXPECT_NE(data, nullptr);
    EXPECT_EQ(pixelMap.GetHeight(), PIXEL_MAP_TEST_HEIGHT);
    EXPECT_EQ(pixelMap.GetWidth(), PIXEL_MAP_TEST_WIDTH);
    EXPECT_EQ(pixelMap.GetPixelFormat(), PixelFormat::RGB_565);
    EXPECT_EQ(pixelMap.GetColorSpace(), ColorSpace::SRGB);
    EXPECT_EQ(pixelMap.GetPixelBytes(), bytesPerPixel);
    EXPECT_EQ(pixelMap.GetRowBytes(), rowDataSize);
    EXPECT_EQ(pixelMap.GetByteCount(), PIXEL_MAP_TEST_HEIGHT * rowDataSize);
    /**
     * @tc.steps: step2. Set image color data and get image color value.
     * @tc.expected: step2. The image color value is correct
     */
    for (int32_t i = 0; i < PIXEL_MAP_TEST_WIDTH * PIXEL_MAP_RGB565_BYTE * PIXEL_MAP_TEST_HEIGHT; i++) {
        data[i] = i;
    }
    EXPECT_NE(pixelMap.GetPixel16(1, 1), nullptr);
    EXPECT_EQ(*pixelMap.GetPixel16(1, 1), 0x0908);
    uint32_t color = 0;
    uint32_t expect = 0xFF422008;
    EXPECT_EQ(pixelMap.GetARGB32Color(1, 1, color), true);
    EXPECT_EQ(color, expect);
    // RGB565: binary: 0000100100001000
    // split to :         00001       001000          01000
    //                      |           |                |
    //                      B           G                R
    // transfer to RGB888:
    //                      1           8                8
    // multi 256(8bit length)
    //                 256*1/2^5    256*8/2^6       256*8/2^5
    // another method:
    //                 (x<<3 | x>>2)  (x<<2 | x>>4)
    EXPECT_EQ(pixelMap.GetARGB32ColorA(color), 255);
    EXPECT_EQ(pixelMap.GetARGB32ColorR(color), 66);  // (8<<3 | 8 >> 2)
    EXPECT_EQ(pixelMap.GetARGB32ColorG(color), 32);  // (8<<2 | 8 >> 4)
    EXPECT_EQ(pixelMap.GetARGB32ColorB(color), 8);   // (1<<3 | 1 >> 2)
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap002 end";
}

/**
 * @tc.name: ImagePixelMap003
 * @tc.desc: ARGB_8888 pixel format pixel map operation
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ImagePixelMap003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap003 start";
    /**
     * @tc.steps: step1. Set image info and alloc pixel map memory.
     * @tc.expected: step1. The pixel map info is correct.
     */
    int8_t bytesPerPixel = 4;
    int8_t rowDataSize = PIXEL_MAP_TEST_WIDTH * bytesPerPixel;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ARGB_8888;
    info.colorSpace = ColorSpace::SRGB;
    PixelMap pixelMap;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * PIXEL_MAP_TEST_HEIGHT;
    void *buffer = malloc(bufferSize);
    EXPECT_NE(buffer, nullptr);
    pixelMap.SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    uint8_t *data = const_cast<uint8_t *>(pixelMap.GetPixels());
    EXPECT_NE(data, nullptr);
    EXPECT_EQ(pixelMap.GetHeight(), PIXEL_MAP_TEST_HEIGHT);
    EXPECT_EQ(pixelMap.GetWidth(), PIXEL_MAP_TEST_WIDTH);
    EXPECT_EQ(pixelMap.GetPixelFormat(), PixelFormat::ARGB_8888);
    EXPECT_EQ(pixelMap.GetColorSpace(), ColorSpace::SRGB);
    EXPECT_EQ(pixelMap.GetPixelBytes(), bytesPerPixel);
    EXPECT_EQ(pixelMap.GetRowBytes(), rowDataSize);
    EXPECT_EQ(pixelMap.GetByteCount(), PIXEL_MAP_TEST_HEIGHT * rowDataSize);
    /**
     * @tc.steps: step2. Set image color data and get image color value.
     * @tc.expected: step2. The image color value is correct
     */
    for (int32_t i = 0; i < PIXEL_MAP_TEST_WIDTH * PIXEL_MAP_ARGB8888_BYTE * PIXEL_MAP_TEST_HEIGHT; i++) {
        data[i] = i;
    }
    EXPECT_NE(pixelMap.GetPixel(1, 1), nullptr);
    EXPECT_EQ(*pixelMap.GetPixel32(1, 1), static_cast<uint32_t>(0x13121110));
    uint32_t color = 0;
    EXPECT_EQ(pixelMap.GetARGB32Color(1, 1, color), true);
    EXPECT_EQ(pixelMap.GetARGB32ColorA(color), 0x10);
    EXPECT_EQ(pixelMap.GetARGB32ColorR(color), 0x11);
    EXPECT_EQ(pixelMap.GetARGB32ColorG(color), 0x12);
    EXPECT_EQ(pixelMap.GetARGB32ColorB(color), 0x13);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap003 end";
}

/**
 * @tc.name: ImagePixelMap004
 * @tc.desc: Get pixel position out of image range
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ImagePixelMap004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap004 start";
    /**
     * @tc.steps: step1. Set image info and alloc pixel map memory.
     * @tc.expected: step1. The pixel map info is correct.
     */
    PixelMap pixelMap;
    int8_t bytesPerPixel = 4;
    int8_t rowDataSize = PIXEL_MAP_TEST_WIDTH * bytesPerPixel;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ARGB_8888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * PIXEL_MAP_TEST_HEIGHT;
    void *buffer = malloc(bufferSize);
    EXPECT_NE(buffer, nullptr);
    pixelMap.SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    uint8_t *data = const_cast<uint8_t *>(pixelMap.GetPixels());
    EXPECT_NE(data, nullptr);
    EXPECT_EQ(pixelMap.GetHeight(), PIXEL_MAP_TEST_HEIGHT);
    EXPECT_EQ(pixelMap.GetWidth(), PIXEL_MAP_TEST_WIDTH);
    EXPECT_EQ(pixelMap.GetPixelFormat(), PixelFormat::ARGB_8888);
    EXPECT_EQ(pixelMap.GetColorSpace(), ColorSpace::SRGB);
    EXPECT_EQ(pixelMap.GetByteCount(), PIXEL_MAP_TEST_HEIGHT * rowDataSize);
    /**
     * @tc.steps: step2. Set image color data and get image color value.
     * @tc.expected: step2. Get image color value failed, because of position out of image range.
     */
    for (int32_t i = 0; i < PIXEL_MAP_TEST_WIDTH * PIXEL_MAP_ARGB8888_BYTE * PIXEL_MAP_TEST_HEIGHT; i++) {
        data[i] = i;
    }
    EXPECT_EQ(pixelMap.GetPixel32(4, 4), nullptr);
    EXPECT_EQ(pixelMap.GetPixel(-1, -1), nullptr);
    uint32_t color = 0;
    EXPECT_EQ(pixelMap.GetARGB32Color(4, 4, color), false);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap004 end";
}

/**
 * @tc.name: ImagePixelMap005
 * @tc.desc: Set error image size
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ImagePixelMap005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap005 start";
    /**
     * @tc.steps: step1. Set image error info include image height and width.
     * @tc.expected: step1. The pixel map info is default value.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = -10;
    info.size.height = 10;
    EXPECT_EQ(pixelMap.SetImageInfo(info), ERR_IMAGE_DATA_ABNORMAL);
    EXPECT_EQ(pixelMap.GetHeight(), 0);
    EXPECT_EQ(pixelMap.GetWidth(), 0);
    EXPECT_EQ(pixelMap.GetPixelFormat(), PixelFormat::UNKNOWN);
    EXPECT_EQ(pixelMap.GetColorSpace(), ColorSpace::SRGB);
    EXPECT_EQ(pixelMap.GetByteCount(), 0);
    uint8_t *data = const_cast<uint8_t *>(pixelMap.GetPixels());
    EXPECT_EQ(data, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap005 end";
}

/**
 * @tc.name: ImagePixelMap006
 * @tc.desc: Set unknown pixel format and color space
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ImagePixelMap006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap006 start";
    /**
     * @tc.steps: step1. Set image unknown pixel format and color space info.
     * @tc.expected: step1. The pixel map info is default value.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 10;
    info.size.height = 10;
    EXPECT_EQ(pixelMap.SetImageInfo(info), ERR_IMAGE_DATA_UNSUPPORT);
    EXPECT_EQ(pixelMap.GetHeight(), 0);
    EXPECT_EQ(pixelMap.GetWidth(), 0);
    EXPECT_EQ(pixelMap.GetPixelFormat(), PixelFormat::UNKNOWN);
    EXPECT_EQ(pixelMap.GetColorSpace(), ColorSpace::SRGB);
    EXPECT_EQ(pixelMap.GetByteCount(), 0);
    uint8_t *data = const_cast<uint8_t *>(pixelMap.GetPixels());
    EXPECT_EQ(data, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap006 end";
}

/**
 * @tc.name: ImagePixelMap007
 * @tc.desc: Set pixel map size out of max value
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ImagePixelMap007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap007 start";
    /**
     * @tc.steps: step1. Set image size out of max value (500MB).
     * @tc.expected: step1. The pixel map info is default value.
     */
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 500 * 1024;
    info.size.height = 500 * 1024;
    info.pixelFormat = PixelFormat::ARGB_8888;
    info.colorSpace = ColorSpace::SRGB;
    EXPECT_EQ(pixelMap.SetImageInfo(info), ERR_IMAGE_TOO_LARGE);
    EXPECT_EQ(pixelMap.GetHeight(), 0);
    EXPECT_EQ(pixelMap.GetWidth(), 0);
    EXPECT_EQ(pixelMap.GetByteCount(), 0);
    uint8_t *data = const_cast<uint8_t *>(pixelMap.GetPixels());
    EXPECT_EQ(data, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap007 end";
}

/**
 * @tc.name: ImagePixelMap008
 * @tc.desc: RGB_888 pixel format pixel map operation
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ImagePixelMap008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap008 start";
    /**
     * @tc.steps: step1. Set image info and alloc pixel map memory.
     * @tc.expected: step1. The pixel map info is correct.
     */
    int8_t bytesPerPixel = 3;
    int8_t rowDataSize = PIXEL_MAP_TEST_WIDTH * bytesPerPixel;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    PixelMap pixelMap;
    pixelMap.SetImageInfo(info);
    uint32_t bufferSize = rowDataSize * PIXEL_MAP_TEST_HEIGHT;
    void *buffer = malloc(bufferSize);
    EXPECT_NE(buffer, nullptr);
    pixelMap.SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    uint8_t *data = const_cast<uint8_t *>(pixelMap.GetPixels());
    EXPECT_NE(data, nullptr);
    EXPECT_EQ(pixelMap.GetHeight(), PIXEL_MAP_TEST_HEIGHT);
    EXPECT_EQ(pixelMap.GetWidth(), PIXEL_MAP_TEST_WIDTH);
    EXPECT_EQ(pixelMap.GetPixelFormat(), PixelFormat::RGB_888);
    EXPECT_EQ(pixelMap.GetColorSpace(), ColorSpace::SRGB);
    EXPECT_EQ(pixelMap.GetPixelBytes(), bytesPerPixel);
    EXPECT_EQ(pixelMap.GetRowBytes(), rowDataSize);
    EXPECT_EQ(pixelMap.GetByteCount(), PIXEL_MAP_TEST_HEIGHT * rowDataSize);
    /**
     * @tc.steps: step2. Set image color data and get image color value.
     * @tc.expected: step2. The image color value is correct
     */
    for (int32_t i = 0; i < PIXEL_MAP_TEST_WIDTH * PIXEL_MAP_RGB888_BYTE * PIXEL_MAP_TEST_HEIGHT; i++) {
        data[i] = i;
    }
    EXPECT_NE(pixelMap.GetPixel(1, 1), nullptr);
    uint32_t color = 0;
    EXPECT_EQ(pixelMap.GetARGB32Color(1, 1, color), true);
    EXPECT_EQ(pixelMap.GetARGB32ColorA(color), 255);
    EXPECT_EQ(pixelMap.GetARGB32ColorR(color), 12);
    EXPECT_EQ(pixelMap.GetARGB32ColorG(color), 13);
    EXPECT_EQ(pixelMap.GetARGB32ColorB(color), 14);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap008 end";
}

/**
 * @tc.name: ImagePixelMap009
 * @tc.desc: create pixelmap with wrong source and correct initialization options
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ImagePixelMap009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap009 start";
    /**
     * @tc.steps: step1. set source pixelmap wrong and correct initialization options
     * @tc.expected: step1. The new pixelmap is null.
     */
    PixelMap srcPixelMap;
    ImageInfo imageInfo;
    srcPixelMap.SetImageInfo(imageInfo);
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(srcPixelMap, opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap009 end";
}
/**
* @tc.name: ImagePixelMap010
* @tc.desc: test WriteToParcel
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap010 start";
    Parcel data;
    std::unique_ptr<PixelMap> pixelmap = ConstructPixmap();
    bool ret = pixelmap.get()->Marshalling(data);
    EXPECT_EQ(true, ret);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap010 end";
}

/**
* @tc.name: ImagePixelMap011
* @tc.desc: test CreateFromParcel
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap011 start";

    Parcel data;
    std::unique_ptr<PixelMap> pixelmap1 = ConstructPixmap();
    bool ret = pixelmap1.get()->Marshalling(data);
    EXPECT_EQ(true, ret);

    PixelMap *pixelmap2 = PixelMap::Unmarshalling(data);
    EXPECT_EQ(pixelmap1->GetHeight(), pixelmap2->GetHeight());
    EXPECT_EQ(pixelmap1->GetWidth(), pixelmap2->GetWidth());
    EXPECT_EQ(pixelmap1->GetPixelFormat(), pixelmap2->GetPixelFormat());
    EXPECT_EQ(pixelmap1->GetColorSpace(), pixelmap2->GetColorSpace());
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap011 end";
}
/**
 * @tc.name: ImagePixelMap012
 * @tc.desc: create pixelmap with color,colorlength,offset,width and initialization options
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ImagePixelMap012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap012 start";
    /**
     * @tc.steps: step1. set color,colorlength,offset,width and initialization options
     * @tc.expected: step1. The new pixelmap is not null.
     */
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    uint32_t colorlength = sizeof(color) / sizeof(color[0]);
    const int32_t offset = 1;
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = opts.size.width;

    std::unique_ptr<PixelMap> newPixelMap = PixelMap::Create(color, colorlength, offset, width, opts);
    EXPECT_EQ(newPixelMap, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap012 end";
}


/**
* @tc.name: ImagePixelMap013
* @tc.desc: test CreateFromParcel
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap013 start";

    Parcel data;
    std::unique_ptr<PixelMap> pixelmap1 = ConstructBigPixmap();
    EXPECT_NE(pixelmap1, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMap013 ConstructPixmap success";
    bool ret = pixelmap1.get()->Marshalling(data);
    GTEST_LOG_(INFO) << "ImagePixelMap013 Marshalling success";
    EXPECT_EQ(true, ret);

    PixelMap *pixelmap2 = PixelMap::Unmarshalling(data);
    GTEST_LOG_(INFO) << "ImagePixelMap013 Unmarshalling success";
    GTEST_LOG_(INFO) << "ImagePixelMap013 pixelmap1 GetHeight :" << pixelmap1->GetHeight();
    GTEST_LOG_(INFO) << "ImagePixelMap013 pixelmap2 GetHeight :" << pixelmap2->GetHeight();
    EXPECT_EQ(pixelmap1->GetHeight(), pixelmap2->GetHeight());
    GTEST_LOG_(INFO) << "ImagePixelMap013 GetHeight success";
    EXPECT_EQ(pixelmap1->GetWidth(), pixelmap2->GetWidth());
    GTEST_LOG_(INFO) << "ImagePixelMap013 GetWidth success";
    EXPECT_EQ(pixelmap1->GetPixelFormat(), pixelmap2->GetPixelFormat());
    GTEST_LOG_(INFO) << "ImagePixelMap013 GetPixelFormat success";
    EXPECT_EQ(pixelmap1->GetColorSpace(), pixelmap2->GetColorSpace());
    GTEST_LOG_(INFO) << "ImagePixelMap013 GetColorSpace success";
    EXPECT_EQ(true, pixelmap1->IsSameImage(*pixelmap2));
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap013 end";
}


/**
* @tc.name: ImagePixelMap014
* @tc.desc: test GetPixel8
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap014 GetPixel8 start";
    PixelMap pixelMap;
    int32_t x = 1;
    int32_t y = 1;
    uint8_t *ret = 0;
    EXPECT_EQ(ret, pixelMap.GetPixel8(x, y));
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap014 GetPixel8 end";
}

/**
* @tc.name: ImagePixelMap015
* @tc.desc: test GetPixel16
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap015 GetPixel16 start";
    PixelMap pixelMap;
    int32_t x = 1;
    int32_t y = 1;
    uint16_t *ret = 0;
    EXPECT_EQ(ret, pixelMap.GetPixel16(x, y));
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap015 GetPixel16 end";
}

/**
* @tc.name: ImagePixelMap016
* @tc.desc: test GetPixelBytes
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap016 GetPixelBytes start";
    PixelMap pixelMap;
    int32_t ret = 0;
    EXPECT_EQ(ret, pixelMap.GetPixelBytes());
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap016 GetPixelBytes end";
}

/**
* @tc.name: ImagePixelMap017
* @tc.desc: test GetPixelBytes
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap017 scale start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    float xAxis = 2.0;
    float yAxis = 1.0;
    pixelMap.scale(xAxis, yAxis);
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    int32_t width = PIXEL_MAP_TEST_WIDTH;
    int32_t height = PIXEL_MAP_TEST_HEIGHT;
    EXPECT_EQ(width, outInfo.size.width);
    EXPECT_EQ(height, outInfo.size.height);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap017 scale end";
}

/**
* @tc.name: ImagePixelMap018
* @tc.desc: test translate
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap018 translate start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    float xAxis = 2.0;
    float yAxis = 1.0;
    pixelMap.translate(xAxis, yAxis);
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap018 translate end";
}

/**
* @tc.name: ImagePixelMap019
* @tc.desc: test rotate
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap019 rotate start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    float degrees = 90.0;
    pixelMap.rotate(degrees);
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    int32_t width = PIXEL_MAP_TEST_HEIGHT;
    int32_t height = PIXEL_MAP_TEST_WIDTH;
    EXPECT_EQ(width, outInfo.size.width);
    EXPECT_EQ(height, outInfo.size.height);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap019 rotate end";
}

/**
* @tc.name: ImagePixelMap020
* @tc.desc: test flip
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap020 flip start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    pixelMap.flip(false, true);
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    int32_t width = PIXEL_MAP_TEST_WIDTH;
    int32_t height = PIXEL_MAP_TEST_HEIGHT;
    EXPECT_EQ(width, outInfo.size.width);
    EXPECT_EQ(height, outInfo.size.height);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap020 flip end";
}

/**
* @tc.name: ImagePixelMap021
* @tc.desc: test crop
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap021, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap021 crop start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    Rect rect;
    rect.left = 0;
    rect.top = 0;
    rect.height = 1;
    rect.width = 1;
    pixelMap.crop(rect);
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    int32_t width = 3;
    int32_t height = 3;
    EXPECT_EQ(width, outInfo.size.width);
    EXPECT_EQ(height, outInfo.size.height);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap021 crop end";
}

/**
* @tc.name: ImagePixelMap022
* @tc.desc: test SetAlpha
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap022, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap022 SetAlpha start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::RGB_888;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    float percent = 0.5;
    pixelMap.SetAlpha(percent);
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    bool getAlpha = false;
    if (outInfo.pixelFormat != info.pixelFormat) {
        getAlpha = true;
    }
    EXPECT_EQ(false, getAlpha);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap022 SetAlpha end";
}

/**
* @tc.name: ImagePixelMap023
* @tc.desc: test GetARGB32ColorA
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap023 GetARGB32ColorA start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t color = 1;
    pixelMap.GetARGB32ColorA(color);
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    int32_t width = PIXEL_MAP_TEST_WIDTH;
    int32_t height = PIXEL_MAP_TEST_HEIGHT;
    EXPECT_EQ(width, outInfo.size.width);
    EXPECT_EQ(height, outInfo.size.height);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap023 GetARGB32ColorA end";
}

/**
* @tc.name: ImagePixelMap024
* @tc.desc: test GetARGB32ColorR
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap024 GetARGB32ColorR start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t color = 1;
    pixelMap.GetARGB32ColorR(color);
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    int32_t width = PIXEL_MAP_TEST_WIDTH;
    int32_t height = PIXEL_MAP_TEST_HEIGHT;
    EXPECT_EQ(width, outInfo.size.width);
    EXPECT_EQ(height, outInfo.size.height);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap024 GetARGB32ColorR end";
}

/**
* @tc.name: ImagePixelMap025
* @tc.desc: test GetARGB32ColorG
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap025 GetARGB32ColorG start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t color = 1;
    pixelMap.GetARGB32ColorG(color);
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    int32_t width = PIXEL_MAP_TEST_WIDTH;
    int32_t height = PIXEL_MAP_TEST_HEIGHT;
    EXPECT_EQ(width, outInfo.size.width);
    EXPECT_EQ(height, outInfo.size.height);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap025 GetARGB32ColorG end";
}

/**
* @tc.name: ImagePixelMap026
* @tc.desc: test GetARGB32ColorB
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap026 GetARGB32ColorB start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t color = 1;
    pixelMap.GetARGB32ColorB(color);
    ImageInfo outInfo;
    pixelMap.GetImageInfo(outInfo);
    int32_t width = PIXEL_MAP_TEST_WIDTH;
    int32_t height = PIXEL_MAP_TEST_HEIGHT;
    EXPECT_EQ(width, outInfo.size.width);
    EXPECT_EQ(height, outInfo.size.height);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap026 GetARGB32ColorB end";
}

/**
* @tc.name: ImagePixelMap027
* @tc.desc: test IsSameImage
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap027 IsSameImage start";
    PixelMap pixelMap, pixelMap1;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    pixelMap1.SetImageInfo(info);
    bool ret = pixelMap.IsSameImage(pixelMap1);
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap027 IsSameImage end";
}

/**
* @tc.name: ImagePixelMap028
* @tc.desc: test ReadPixels
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap028, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap028 ReadPixels start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint64_t bufferSize = 96;
    uint32_t offset = 0;
    uint32_t stride = 8;
    Rect rect;
    rect.left = 0;
    rect.top = 0;
    rect.height = 1;
    rect.width = 2;
    uint8_t *dst = 0;
    uint32_t ret = pixelMap.ReadPixels(bufferSize, offset, stride, rect, dst);
    bool getReadPixels = true;
    if (ret != SUCCESS) {
        getReadPixels = false;
    }
    EXPECT_EQ(false, getReadPixels);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap028 ReadPixels end";
}

/**
* @tc.name: ImagePixelMap029
* @tc.desc: test ReadPixels
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap029, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap029 ReadPixels start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint64_t bufferSize = 96;
    uint8_t *dst = 0;
    uint32_t ret = pixelMap.ReadPixels(bufferSize, dst);
    bool getReadPixels = true;
    if (ret != SUCCESS) {
        getReadPixels = false;
    }
    EXPECT_EQ(false, getReadPixels);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap029 ReadPixels end";
}

/**
* @tc.name: ImagePixelMap030
* @tc.desc: test ReadPixel
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap030, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap030 ReadPixel start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    int32_t x = 0;
    int32_t y = 0;
    Position position;
    position.x = x;
    position.y = y;
    uint32_t dst = 0;
    uint32_t ret = pixelMap.ReadPixel(position, dst);
    bool getReadPixel = true;
    if (ret != SUCCESS) {
        getReadPixel = false;
    }
    EXPECT_EQ(false, getReadPixel);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap030 ReadPixel end";
}

/**
* @tc.name: ImagePixelMap031
* @tc.desc: test ResetConfig
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap031, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap031 ResetConfig start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    Size size;
    size.width = 2 * PIXEL_MAP_TEST_WIDTH;
    size.height = 2 * PIXEL_MAP_TEST_HEIGHT;
    PixelFormat pixelFormat = PixelFormat::RGBA_8888;
    uint32_t ret = pixelMap.ResetConfig(size, pixelFormat);
    bool getResetConfig = true;
    if (ret != SUCCESS) {
        getResetConfig = false;
    }
    EXPECT_EQ(false, getResetConfig);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap031 ResetConfig end";
}

/**
* @tc.name: ImagePixelMap032
* @tc.desc: test SetAlphaType
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap032, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap032 SetAlphaType start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    AlphaType alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    bool ret = pixelMap.SetAlphaType(alphaType);
    EXPECT_EQ(true, ret);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap032 SetAlphaType end";
}

/**
* @tc.name: ImagePixelMap033
* @tc.desc: test SetAlphaType
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap033, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap033 SetAlphaType start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    AlphaType alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    bool ret = pixelMap.SetAlphaType(alphaType);
    EXPECT_EQ(true, ret);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap033 SetAlphaType end";
}

/**
* @tc.name: ImagePixelMap034
* @tc.desc: test WritePixel
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap034, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap034 WritePixel start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    int32_t x = 0;
    int32_t y = 0;
    Position position;
    position.x = x;
    position.y = y;
    uint32_t color = 9;
    uint32_t ret = pixelMap.WritePixel(position, color);
    bool getWritePixel = true;
    if (ret != SUCCESS) {
        getWritePixel = false;
    }
    EXPECT_EQ(false, getWritePixel);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap034 WritePixel end";
}

/**
* @tc.name: ImagePixelMap035
* @tc.desc: test GetFd
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap035, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap035 GetFd start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);

    void *ret = pixelMap.GetFd();
    bool isFd = false;
    if (ret != nullptr) {
        isFd = true;
    }
    EXPECT_EQ(false, isFd);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap035 GetFd end";
}

/**
* @tc.name: ImagePixelMap036
* @tc.desc: test GetCapacity
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap036, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap036 GetCapacity start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    uint32_t ret = pixelMap.GetCapacity();
    bool getCapacity = false;
    if (ret != 0) {
        getCapacity = true;
    }
    EXPECT_EQ(false, getCapacity);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap036 GetCapacity end";
}

/**
* @tc.name: ImagePixelMap037
* @tc.desc: test IsSourceAsResponse
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap037, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap037 IsSourceAsResponse start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    bool ret = pixelMap.IsSourceAsResponse();
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap037 IsSourceAsResponse end";
}

/**
* @tc.name: ImagePixelMap038
* @tc.desc: test GetWritablePixels
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap038, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap038 GetWritablePixels start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    void *ret = pixelMap.GetWritablePixels();
    bool getPixels = true;
    if (ret == nullptr) {
        getPixels = false;
    }
    EXPECT_EQ(false, getPixels);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap038 GetWritablePixels end";
}
#ifdef IMAGE_COLORSPACE_FLAG
/**
* @tc.name: ImagePixelMap039
* @tc.desc: test InnerSetColorSpace
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap039, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap039 InnerSetColorSpace start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    OHOS::ColorManager::ColorSpace grColorSpace =
        OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    pixelMap.InnerSetColorSpace(grColorSpace);
    OHOS::ColorManager::ColorSpace outColorSpace = pixelMap.InnerGetGrColorSpace();
    EXPECT_EQ(outColorSpace, grColorSpace);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap039 InnerSetColorSpace end";
}
#endif
} // namespace Multimedia
} // namespace OHOS
