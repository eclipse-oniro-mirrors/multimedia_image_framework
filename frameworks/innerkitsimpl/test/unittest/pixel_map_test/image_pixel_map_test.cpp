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
#include "image_source.h"
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
        int32_t bytesPerPixel = 3;
        std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
        ImageInfo info;
        info.size.width = pixelMapWidth;
        info.size.height = pixelMapHeight;
        info.pixelFormat = PixelFormat::RGB_888;
        info.colorSpace = ColorSpace::SRGB;
        pixelMap->SetImageInfo(info);

        int32_t rowDataSize = pixelMapWidth * bytesPerPixel;
        uint32_t bufferSize = rowDataSize * pixelMapHeight;
        if (bufferSize <= 0) {
            return nullptr;
        }
        void *buffer = malloc(bufferSize);
        if (buffer == nullptr) {
            return nullptr;
        }
        char *ch = static_cast<char *>(buffer);
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
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap002 start" << bufferSize;
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
    EXPECT_EQ(pixelMap.SetImageInfo(info), SUCCESS);
    EXPECT_EQ(pixelMap.GetHeight(), info.size.height);
    EXPECT_EQ(pixelMap.GetWidth(), info.size.width);
    EXPECT_NE(pixelMap.GetByteCount(), 0);
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

    Parcel data2;
    pixelmap2->Marshalling(data2);
    PIXEL_MAP_ERR err;
    PixelMap *pixelmap3 = PixelMap::Unmarshalling(data2, err);
    EXPECT_EQ(pixelmap2->GetHeight(), pixelmap3->GetHeight());
    EXPECT_EQ(pixelmap2->GetWidth(), pixelmap3->GetWidth());
    EXPECT_EQ(pixelmap2->GetPixelFormat(), pixelmap3->GetPixelFormat());
    EXPECT_EQ(pixelmap2->GetColorSpace(), pixelmap3->GetColorSpace());

    uint32_t code = 10; // test num.
    pixelmap3->SetPixelMapError(code, "error");
    EXPECT_EQ(code, pixelmap3->errorCode);
    EXPECT_EQ("error", pixelmap3->errorInfo);

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
    int32_t width = PIXEL_MAP_TEST_WIDTH * 2;
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
    EXPECT_TRUE(SkColorSpace::Equals(
        outColorSpace.ToSkColorSpace().get(), grColorSpace.ToSkColorSpace().get()));
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap039 InnerSetColorSpace end";
}

static constexpr uint32_t PIXEL_MAP_TEST_PIXEL = 0xFF994422;
static constexpr uint32_t PIXEL_MAP_TEST_DISPLAY_P3_PIXEL = 0xFF2B498E;
static constexpr uint32_t PIXEL_MAP_TEST_ADOBE_RGB_PIXEL = 0xFF294686;
static constexpr uint32_t PIXEL_MAP_TEST_DCI_P3_PIXEL = 0xFF3D5A9D;
static constexpr uint32_t PIXEL_MAP_TEST_BT2020_PIXEL = 0xFF1C3E74;
static constexpr int32_t POINT_ZERO = 0;

/**
* @tc.name: ImagePixelMap040
* @tc.desc: test ApplyColorSpace DISPLAY_P3
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap040, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap040 ApplyColorSpace start";
    const uint32_t dataLength = PIXEL_MAP_TEST_WIDTH * PIXEL_MAP_TEST_HEIGHT;
    vector<uint32_t> data(dataLength, PIXEL_MAP_TEST_PIXEL);
    InitializationOptions opts;
    opts.pixelFormat = OHOS::Media::PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = PIXEL_MAP_TEST_WIDTH;
    opts.size.height = PIXEL_MAP_TEST_HEIGHT;

    auto pixelmap = PixelMap::Create(data.data(), dataLength, opts);
    auto grColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    pixelmap->InnerSetColorSpace(grColorSpace);
    auto applyGrColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::DISPLAY_P3);
    pixelmap->ApplyColorSpace(applyGrColorSpace);

    auto pixelZero = pixelmap->GetPixel32(POINT_ZERO, POINT_ZERO);
    EXPECT_EQ(*pixelZero, PIXEL_MAP_TEST_DISPLAY_P3_PIXEL);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap040 ApplyColorSpace end";
}

/**
* @tc.name: ImagePixelMap041
* @tc.desc: test ApplyColorSpace ADOBE_RGB
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap041, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap040 ApplyColorSpace start";
    const uint32_t dataLength = PIXEL_MAP_TEST_WIDTH * PIXEL_MAP_TEST_HEIGHT;
    vector<uint32_t> data(dataLength, PIXEL_MAP_TEST_PIXEL);
    InitializationOptions opts;
    opts.pixelFormat = OHOS::Media::PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = PIXEL_MAP_TEST_WIDTH;
    opts.size.height = PIXEL_MAP_TEST_HEIGHT;

    auto pixelmap = PixelMap::Create(data.data(), dataLength, opts);
    auto grColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    pixelmap->InnerSetColorSpace(grColorSpace);
    auto applyGrColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::ADOBE_RGB);
    pixelmap->ApplyColorSpace(applyGrColorSpace);

    auto pixelZero = pixelmap->GetPixel32(POINT_ZERO, POINT_ZERO);
    EXPECT_EQ(*pixelZero, PIXEL_MAP_TEST_ADOBE_RGB_PIXEL);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap041 ApplyColorSpace end";
}

/**
* @tc.name: ImagePixelMap042
* @tc.desc: test ApplyColorSpace DCI_P3
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap042, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap042 ApplyColorSpace start";
    const uint32_t dataLength = PIXEL_MAP_TEST_WIDTH * PIXEL_MAP_TEST_HEIGHT;
    vector<uint32_t> data(dataLength, PIXEL_MAP_TEST_PIXEL);
    InitializationOptions opts;
    opts.pixelFormat = OHOS::Media::PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = PIXEL_MAP_TEST_WIDTH;
    opts.size.height = PIXEL_MAP_TEST_HEIGHT;

    auto pixelmap = PixelMap::Create(data.data(), dataLength, opts);
    auto grColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    pixelmap->InnerSetColorSpace(grColorSpace);
    auto applyGrColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::DCI_P3);
    pixelmap->ApplyColorSpace(applyGrColorSpace);

    auto pixelZero = pixelmap->GetPixel32(POINT_ZERO, POINT_ZERO);
    EXPECT_EQ(*pixelZero, PIXEL_MAP_TEST_DCI_P3_PIXEL);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap042 ApplyColorSpace end";
}

/**
* @tc.name: ImagePixelMap043
* @tc.desc: test ApplyColorSpace Rec.2020
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap043, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap043 ApplyColorSpace start";
    const uint32_t dataLength = PIXEL_MAP_TEST_WIDTH * PIXEL_MAP_TEST_HEIGHT;
    vector<uint32_t> data(dataLength, PIXEL_MAP_TEST_PIXEL);
    InitializationOptions opts;
    opts.pixelFormat = OHOS::Media::PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = PIXEL_MAP_TEST_WIDTH;
    opts.size.height = PIXEL_MAP_TEST_HEIGHT;

    auto pixelmap = PixelMap::Create(data.data(), dataLength, opts);
    auto grColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    pixelmap->InnerSetColorSpace(grColorSpace);
    auto applyGrColorSpace = OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::BT2020);
    pixelmap->ApplyColorSpace(applyGrColorSpace);

    auto pixelZero = pixelmap->GetPixel32(POINT_ZERO, POINT_ZERO);
    EXPECT_EQ(*pixelZero, PIXEL_MAP_TEST_BT2020_PIXEL);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap043 ApplyColorSpace end";
}
#endif

/**
* @tc.name: ImagePixelMap044
* @tc.desc: test getEncodedFormat
* @tc.type: FUNC
* @tc.require: AR000FTAMO
*/
HWTEST_F(ImagePixelMapTest, ImagePixelMap044, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap044 getEncodedFormat start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = PIXEL_MAP_TEST_WIDTH;
    info.size.height = PIXEL_MAP_TEST_HEIGHT;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    ImageInfo info1;
    pixelMap.GetImageInfo(info1);
    EXPECT_EQ(info1.encodedFormat.empty(), true);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap044 getEncodedFormat end";
}

std::unique_ptr<PixelMap> CreatePixelMapCommon(int32_t width, int32_t height)
{
    const uint32_t dataLength = width * height;
    uint32_t *data = new uint32_t[dataLength];
    for (uint32_t i = 0; i < dataLength; i++) {
        data[i] = 0xFFFF0000;
    }
    InitializationOptions opts;
    opts.pixelFormat = OHOS::Media::PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = width;
    opts.size.height = height;
    std::unique_ptr<PixelMap> pixelmap = PixelMap::Create(data, dataLength, opts);
    delete[] data;
    return pixelmap;
}

/**
* @tc.name: CheckPixelsInput001
* @tc.desc: test CheckPixelsInput
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, CheckPixelsInput001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput001 start";
    std::unique_ptr<PixelMap> pixelMap = CreatePixelMapCommon(8, 8);;
    ASSERT_NE(pixelMap.get(), nullptr);

    uint8_t *source = nullptr;
    int32_t bufferSize = 0;
    uint32_t stride = 0;
    uint32_t offset = 0;
    struct Rect region = {0};
    uint32_t status = 0;

    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);

    // test source is nullptr
    ASSERT_EQ(source, nullptr);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    // test bufferSize is 0
    source = static_cast<uint8_t *>(malloc(1));
    ASSERT_NE(source, nullptr);

    ASSERT_EQ(bufferSize, 0);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    bufferSize = pixelMap->GetByteCount();
    ASSERT_NE(bufferSize, 0);

    // test region.left < 0
    region = {.left = -1, .top = 0, .width = imageInfo.size.width, .height = imageInfo.size.height};
    ASSERT_EQ(region.left < 0 ? 0 : 1, 0);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    // test region.top < 0
    region = {.left = 0, .top = -1, .width = imageInfo.size.width, .height = imageInfo.size.height};
    ASSERT_NE(region.left < 0 ? 0 : 1, 0);
    ASSERT_EQ(region.top < 0 ? 0 : 1, 0);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    free(source);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput001 end";
}

/**
* @tc.name: CheckPixelsInput002
* @tc.desc: test CheckPixelsInput
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, CheckPixelsInput002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput002 start";
    std::unique_ptr<PixelMap> pixelMap = CreatePixelMapCommon(8, 8);;
    ASSERT_NE(pixelMap.get(), nullptr);

    uint8_t *source = static_cast<uint8_t *>(malloc(1));
    uint64_t bufferSize = static_cast<uint64_t>(pixelMap->GetByteCount());
    uint32_t stride = 0;
    uint32_t offset = 0;
    struct Rect region = {0};
    uint32_t status = 0;

    ASSERT_NE(source, nullptr);

    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);

    region = {.left = 0, .top = 0, .width = imageInfo.size.width, .height = imageInfo.size.height};
    ASSERT_NE(region.left < 0 ? 0 : 1, 0);
    ASSERT_NE(region.top < 0 ? 0 : 1, 0);

    // test stride > numeric_limits<int32_t>::max()
    stride = std::numeric_limits<uint32_t>::max();
    ASSERT_EQ(stride > std::numeric_limits<int32_t>::max() ? 0 : 1, 0);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    stride = 0;
    ASSERT_NE(stride > std::numeric_limits<int32_t>::max() ? 0 : 1, 0);

    // test static_cast<uint64_t>(offset) > bufferSize
    offset = static_cast<uint32_t>(bufferSize + 1);
    ASSERT_EQ(static_cast<uint64_t>(offset) > bufferSize ? 0 : 1, 0);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    offset = 0;
    ASSERT_NE(static_cast<uint64_t>(offset) > bufferSize ? 0 : 1, 0);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    free(source);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput002 end";
}

/**
* @tc.name: CheckPixelsInput003
* @tc.desc: test CheckPixelsInput
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, CheckPixelsInput003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput003 start";
    // 8 means pixelmap width and height
    std::unique_ptr<PixelMap> pixelMap = CreatePixelMapCommon(8, 8);;
    ASSERT_NE(pixelMap.get(), nullptr);
    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);

    // 1 means bytecount
    uint8_t *source = static_cast<uint8_t *>(malloc(1));
    uint64_t bufferSize = static_cast<uint64_t>(pixelMap->GetByteCount());
    uint32_t stride = 0; // 0 means stride for test
    uint32_t offset = 0; // 0 means offset for test
    struct Rect region = {.left = 0, .top = 0, .width = imageInfo.size.width, .height = imageInfo.size.height};
    uint32_t status = 0;

    ASSERT_NE(source, nullptr);
    ASSERT_NE(bufferSize, 0);
    ASSERT_NE(region.left < 0 ? 0 : 1, 0);
    ASSERT_NE(region.top < 0 ? 0 : 1, 0);
    ASSERT_NE(stride > std::numeric_limits<int32_t>::max() ? 0 : 1, 0);
    ASSERT_NE(static_cast<uint64_t>(offset) > bufferSize ? 0 : 1, 0);
    // -1 means region width for test
    region.width = -1;
    ASSERT_EQ(region.width < 0 ? 0 : 1, 0);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);
    region.width = imageInfo.size.width;
    ASSERT_NE(region.width < 0 ? 0 : 1, 0);
    // -1 means region height for test
    region.height = -1;
    ASSERT_EQ(region.height < 0 ? 0 : 1, 0);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);
    region.height = imageInfo.size.height;
    ASSERT_NE(region.height < 0 ? 0 : 1, 0);
    // INT32_MAX >> 2 means region max width/height
    int maxDimension = INT32_MAX >> 2;
    // 1 used to check overflow
    region.width = maxDimension + 1;
    ASSERT_EQ(region.width > maxDimension ? 0 : 1, 0);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);
    region.width = imageInfo.size.width;
    ASSERT_NE(region.width > maxDimension ? 0 : 1, 0);
    // 1 used to check overflow
    region.height = maxDimension + 1;
    ASSERT_EQ(region.height > maxDimension ? 0 : 1, 0);
    status = pixelMap->WritePixels(source, bufferSize, offset, stride, region);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);
    region.height = imageInfo.size.height;
    ASSERT_NE(region.height > maxDimension ? 0 : 1, 0);

    free(source);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput003 end";
}

/**
* @tc.name: CheckPixelsInput004
* @tc.desc: test CheckPixelsInput
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, CheckPixelsInput004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput004 start";
    // 8 means pixelmap width and height
    std::unique_ptr<PixelMap> pixelMap = CreatePixelMapCommon(8, 8);;
    ASSERT_NE(pixelMap.get(), nullptr);

    ImageInfo info;
    pixelMap->GetImageInfo(info);

    uint8_t *source4 = static_cast<uint8_t *>(malloc(1));
    uint64_t size4 = static_cast<uint64_t>(pixelMap->GetByteCount());
    uint32_t stride4 = 0; // 0 means stride for test
    uint32_t offset4 = 0; // 0 means offset for test
    struct Rect region4 = {.left = 0, .top = 0, .width = info.size.width, .height = info.size.height};
    uint32_t status = 0;

    ASSERT_NE(source4, nullptr);
    ASSERT_NE(size4, 0);
    ASSERT_NE(region4.left < 0 ? 0 : 1, 0);
    ASSERT_NE(region4.top < 0 ? 0 : 1, 0);
    ASSERT_NE(stride4 > std::numeric_limits<int32_t>::max() ? 0 : 1, 0);
    ASSERT_NE(static_cast<uint64_t>(offset4) > size4 ? 0 : 1, 0);

    // INT32_MAX >> 2 means region max width/height
    int maxDimension = INT32_MAX >> 2;
    ASSERT_NE(region4.width < 0 ? 0 : 1, 0);
    ASSERT_NE(region4.height < 0 ? 0 : 1, 0);
    ASSERT_NE(region4.width > maxDimension ? 0 : 1, 0);
    ASSERT_NE(region4.height > maxDimension ? 0 : 1, 0);

    int32_t left = pixelMap->GetWidth() - region4.width;
    // 1 for test
    region4.left = left + 1;
    ASSERT_EQ(region4.left > left ? 0 : 1, 0);
    status = pixelMap->WritePixels(source4, size4, offset4, stride4, region4);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    // 0 for test
    region4.left = 0;
    ASSERT_NE(region4.left > left ? 0 : 1, 0);

    int32_t top = pixelMap->GetHeight() - region4.height;
    // 1 for test
    region4.top = top + 1;
    ASSERT_EQ(region4.top > top ? 0 : 1, 0);
    status = pixelMap->WritePixels(source4, size4, offset4, stride4, region4);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    // 0 for test
    region4.top = 0;
    ASSERT_NE(region4.top > top ? 0 : 1, 0);

    free(source4);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput004 end";
}

/**
* @tc.name: CheckPixelsInput005
* @tc.desc: test CheckPixelsInput
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, CheckPixelsInput005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput005 start";
    // 8 means pixelmap width and height
    std::unique_ptr<PixelMap> pixelMap = CreatePixelMapCommon(8, 8);;
    ASSERT_NE(pixelMap.get(), nullptr);

    ImageInfo info;
    pixelMap->GetImageInfo(info);

    uint8_t *source5 = static_cast<uint8_t *>(malloc(1));
    uint64_t size5 = static_cast<uint64_t>(pixelMap->GetByteCount());
    uint32_t stride5 = 0; // 0 means stride for test
    uint32_t offset5 = 0; // 0 means offset for test
    struct Rect region5 = {.left = 0, .top = 0, .width = info.size.width, .height = info.size.height};
    uint32_t status = 0;

    ASSERT_NE(source5, nullptr);
    ASSERT_NE(size5, 0);
    ASSERT_NE(region5.left < 0 ? 0 : 1, 0);
    ASSERT_NE(region5.top < 0 ? 0 : 1, 0);
    ASSERT_NE(stride5 > std::numeric_limits<int32_t>::max() ? 0 : 1, 0);
    ASSERT_NE(static_cast<uint64_t>(offset5) > size5 ? 0 : 1, 0);

    // INT32_MAX >> 2 means region max width/height
    int maxDimension = INT32_MAX >> 2;
    ASSERT_NE(region5.width < 0 ? 0 : 1, 0);
    ASSERT_NE(region5.height < 0 ? 0 : 1, 0);
    ASSERT_NE(region5.width > maxDimension ? 0 : 1, 0);
    ASSERT_NE(region5.height > maxDimension ? 0 : 1, 0);

    ASSERT_NE(region5.left > pixelMap->GetWidth() - region5.width ? 0 : 1, 0);
    ASSERT_NE(region5.top > pixelMap->GetHeight() - region5.height ? 0 : 1, 0);

    // 4 means pixel bytes
    uint32_t regionStride = static_cast<uint32_t>(region5.width) * 4;
    // 1 for test
    stride5 = regionStride - 1;
    ASSERT_EQ(stride5 < regionStride ? 0 : 1, 0);
    status = pixelMap->WritePixels(source5, size5, offset5, stride5, region5);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    stride5 = regionStride;
    ASSERT_NE(stride5 < regionStride ? 0 : 1, 0);

    // 1 for test
    size5 = regionStride - 1;
    ASSERT_EQ(size5 < regionStride ? 0 : 1, 0);
    status = pixelMap->WritePixels(source5, size5, offset5, stride5, region5);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);

    free(source5);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput005 end";
}

/**
* @tc.name: CheckPixelsInput006
* @tc.desc: test CheckPixelsInput
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, CheckPixelsInput006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput006 start";
    // 8 means pixelmap width and height
    std::unique_ptr<PixelMap> pixelMap = CreatePixelMapCommon(8, 8);;
    ASSERT_NE(pixelMap.get(), nullptr);
    ImageInfo info;
    pixelMap->GetImageInfo(info);

    // 1 means bytecount
    uint8_t *source6 = static_cast<uint8_t *>(malloc(1));
    uint64_t size6 = static_cast<uint64_t>(pixelMap->GetByteCount());
    uint32_t stride6 = 0; // 0 means stride for test
    uint32_t offset6 = 0; // 0 means offset for test
    struct Rect region6 = {.left = 0, .top = 0, .width = info.size.width, .height = info.size.height};
    uint32_t status = 0;
    ASSERT_NE(source6, nullptr);
    ASSERT_NE(size6, 0);
    ASSERT_NE(region6.left < 0 ? 0 : 1, 0);
    ASSERT_NE(region6.top < 0 ? 0 : 1, 0);
    ASSERT_NE(stride6 > std::numeric_limits<int32_t>::max() ? 0 : 1, 0);
    ASSERT_NE(static_cast<uint64_t>(offset6) > size6 ? 0 : 1, 0);

    // INT32_MAX >> 2 means region max width/height
    int maxDimension = INT32_MAX >> 2;
    ASSERT_NE(region6.width < 0 ? 0 : 1, 0);
    ASSERT_NE(region6.height < 0 ? 0 : 1, 0);
    ASSERT_NE(region6.width > maxDimension ? 0 : 1, 0);
    ASSERT_NE(region6.height > maxDimension ? 0 : 1, 0);
    ASSERT_NE(region6.left > pixelMap->GetWidth() - region6.width ? 0 : 1, 0);
    ASSERT_NE(region6.top > pixelMap->GetHeight() - region6.height ? 0 : 1, 0);
    uint32_t regionStride = static_cast<uint32_t>(region6.width) * 4;
    stride6 = regionStride;
    ASSERT_NE(stride6 < regionStride ? 0 : 1, 0);
    ASSERT_NE(size6 < regionStride ? 0 : 1, 0);
    // 1 for test
    offset6 = static_cast<uint32_t>(size6 - regionStride) + 1;
    ASSERT_EQ(static_cast<uint64_t>(offset6) > (size6 - regionStride) ? 0 : 1, 0);
    status = pixelMap->WritePixels(source6, size6, offset6, stride6, region6);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);
    // 0 for test
    offset6 = 0;
    ASSERT_NE(static_cast<uint64_t>(offset6) > (size6 - regionStride) ? 0 : 1, 0);
    uint64_t lastLinePos = offset6 + static_cast<uint64_t>(region6.height - 1) * stride6;
    // 1 for test
    size6 = lastLinePos + regionStride - 1;
    ASSERT_EQ(lastLinePos > (size6  - regionStride) ? 0 : 1, 0);
    status = pixelMap->WritePixels(source6, size6, offset6, stride6, region6);
    ASSERT_EQ(status, ERR_IMAGE_INVALID_PARAMETER);
    size6 = static_cast<uint64_t>(pixelMap->GetByteCount());
    ASSERT_NE(lastLinePos > (size6  - regionStride) ? 0 : 1, 0);
    status = pixelMap->WritePixels(source6, size6, offset6, stride6, region6);
    ASSERT_NE(status, ERR_IMAGE_INVALID_PARAMETER);
    free(source6);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: CheckPixelsInput006 end";
}

/**
* @tc.name: SetAlpha001
* @tc.desc: test SetAlpha
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, SetAlpha001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetAlpha001 start";
    // 64 means data length
    const uint32_t dataLength = 64;
    uint32_t data[64] = {0};
    InitializationOptions opts;
    opts.pixelFormat = OHOS::Media::PixelFormat::RGBA_F16;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = 8; // 8 means pielmap width
    opts.size.height = 8; // 8 means pielmap height
    std::unique_ptr<PixelMap> pixelmap = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelmap.get(), nullptr);

    AlphaType alphaType = pixelmap->GetAlphaType();
    ASSERT_NE(alphaType, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
    ASSERT_NE(alphaType, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);

    float percent = 0.5f; // 0.5f means alpha value
    ASSERT_NE(percent <= 0 ? 0 : 1, 0);
    ASSERT_NE(percent > 1 ? 0 : 1, 0);

    ASSERT_EQ(pixelmap->GetPixelFormat(), PixelFormat::RGBA_F16);

    int8_t alphaIndex = 3; // 3 means alphaIndex
    ASSERT_NE(alphaIndex, -1);

    int32_t pixelByte = pixelmap->GetPixelBytes();
    ASSERT_EQ(pixelByte, 8); // 8 means pixelByte
    ASSERT_NE(pixelmap->GetPixelFormat(), PixelFormat::ALPHA_8);

    uint32_t pixelsSize = pixelmap->GetByteCount();
    ASSERT_EQ(pixelsSize > 0 ? 0 : 1, 0);

    uint32_t status = pixelmap->SetAlpha(percent);
    ASSERT_EQ(status, SUCCESS);

    ASSERT_EQ(alphaType, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetAlpha001 end";
}

/**
* @tc.name: SetAlpha002
* @tc.desc: test SetAlpha
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, SetAlpha002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetAlpha002 start";
    // 64 means data length
    const uint32_t dataLength = 64;
    uint32_t data[64] = {0};
    InitializationOptions opts;
    opts.pixelFormat = OHOS::Media::PixelFormat::ALPHA_8;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    opts.size.width = 8; // 8 means pielmap width
    opts.size.height = 8; // 8 means pielmap height
    std::unique_ptr<PixelMap> pixelmap2 = PixelMap::Create(data, dataLength, opts);
    ASSERT_NE(pixelmap2.get(), nullptr);

    AlphaType alphaType = pixelmap2->GetAlphaType();
    ASSERT_NE(alphaType, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
    ASSERT_NE(alphaType, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);

    float percent = 0.8f; // 0.8f means alpha value
    ASSERT_NE(percent <= 0 ? 0 : 1, 0);
    ASSERT_NE(percent > 1 ? 0 : 1, 0);

    ASSERT_EQ(pixelmap2->GetPixelFormat(), PixelFormat::ALPHA_8);

    int8_t alphaIndex = 0; // 0 means alphaIndex
    ASSERT_NE(alphaIndex, -1);

    int32_t pixelByte = pixelmap2->GetPixelBytes();
    ASSERT_EQ(pixelByte, 1); // 1 means pixelByte
    ASSERT_NE(pixelmap2->GetPixelFormat(), PixelFormat::RGBA_F16);

    uint32_t pixelsSize = pixelmap2->GetByteCount();
    ASSERT_EQ(pixelsSize > 0 ? 0 : 1, 0);

    uint32_t status = pixelmap2->SetAlpha(percent);
    ASSERT_EQ(status, 0);
    ASSERT_EQ(alphaType, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetAlpha002 end";
}

/**
* @tc.name: TlvEncode001
* @tc.desc: test TlvEncode
* @tc.type: FUNC
*/
HWTEST_F(ImagePixelMapTest, TlvEncode001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: TlvEncode001 start";
    // 8 means pixelmap width and height
    std::unique_ptr<PixelMap> pixelMap = CreatePixelMapCommon(8, 8);;
    ASSERT_NE(pixelMap.get(), nullptr);

    std::vector<uint8_t> buff;
    bool success = pixelMap->EncodeTlv(buff);
    ASSERT_EQ(success, true);

    PixelMap *pixelMap2 = PixelMap::DecodeTlv(buff);
    ASSERT_NE(pixelMap2, nullptr);

    GTEST_LOG_(INFO) << "ImagePixelMapTest: TlvEncode001 end";
}

/**
 * @tc.name: TransformData001
 * @tc.desc: ASTC transform test
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, TransformData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: TransformData001 start";
    // 3 means bytesPerPixel
    int8_t bytesPerPixel = 3;
    int8_t rowDataSize = PIXEL_MAP_TEST_WIDTH * bytesPerPixel;
    ImageInfo imgInfo;
    imgInfo.size.width = PIXEL_MAP_TEST_WIDTH;
    imgInfo.size.height = PIXEL_MAP_TEST_HEIGHT;
    imgInfo.pixelFormat = PixelFormat::RGB_888;
    imgInfo.colorSpace = ColorSpace::SRGB;
    PixelMap pixelMap;
    pixelMap.SetImageInfo(imgInfo);
    uint32_t pixelsSize = rowDataSize * PIXEL_MAP_TEST_HEIGHT;
    void *buffer = malloc(pixelsSize);
    EXPECT_NE(buffer, nullptr);
    pixelMap.SetPixelsAddr(buffer, nullptr, pixelsSize, AllocatorType::HEAP_ALLOC, nullptr);
    // {1.5, 1.5, 0, -1, -1, -1, -1, 0, 0, false, false} means astc transform data
    TransformData transformData = {1.5, 1.5, 0, -1, -1, -1, -1, 0, 0, false, false};
    pixelMap.SetTransformData(transformData);
    TransformData transformData2;
    pixelMap.GetTransformData(transformData2);
    EXPECT_EQ(transformData2.scaleX, transformData.scaleX);
    EXPECT_EQ(transformData2.scaleY, transformData.scaleY);
    EXPECT_EQ(transformData2.flipX, transformData.flipX);
    EXPECT_EQ(transformData2.flipY, transformData.flipY);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: TransformData001 end";
}

/**
 * @tc.name: ModifyImageProperty001
 * @tc.desc: ModifyImageProperty test
 * @tc.type: FUNC
 */
HWTEST_F(ImagePixelMapTest, ModifyImageProperty001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ModifyImageProperty001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string path = "/data/local/tmp/image/test_exif.jpg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    DecodeOptions decopts;
    uint32_t ret = SUCCESS;
    auto pixelMap = imageSource->CreatePixelMap(decopts, ret);
    ASSERT_EQ(ret, SUCCESS);

    std::string key = "Model";
    std::string imagesource_org_value = "TNY-AL00";
    pixelMap->ModifyImageProperty(key, "Test");
    std::string getValue;
    pixelMap->GetImagePropertyString(key, getValue);
    EXPECT_EQ(getValue, "Test");
    imageSource->GetImagePropertyString(0, key, getValue);
    EXPECT_EQ(getValue, imagesource_org_value);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ModifyImageProperty001 end";
}
} // namespace Multimedia
} // namespace OHOS
