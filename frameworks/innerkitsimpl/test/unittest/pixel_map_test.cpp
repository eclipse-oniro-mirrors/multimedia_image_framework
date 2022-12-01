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

#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "pixel_convert_adapter.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class PixelMapTest : public testing::Test {
public:
    PixelMapTest() {}
    ~PixelMapTest() {}
};

std::unique_ptr<PixelMap> ConstructPixmap(AllocatorType type)
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
    char *ch = static_cast<char *>(buffer);
    for (unsigned int i = 0; i < bufferSize; i++) {
        *(ch++) = (char)i;
    }

    pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, type, nullptr);

    return pixelMap;
}

std::unique_ptr<PixelMap> ConstructPixmap(int32_t width, int32_t height, PixelFormat format,
    AlphaType alphaType, AllocatorType type)
{
    std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = format;
    info.colorSpace = ColorSpace::SRGB;
    info.alphaType = alphaType;
    pixelMap->SetImageInfo(info);

    int32_t rowDataSize = width;
    uint32_t bufferSize = rowDataSize * height;
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

    pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, type, nullptr);

    return pixelMap;
}

std::unique_ptr<PixelMap> ConstructPixmap(PixelFormat format, AlphaType alphaType)
{
    int32_t width = 200;
    int32_t height = 300;
    InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = format;
    opts.alphaType = alphaType;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);

    return pixelMap;
}

/**
 * @tc.name: PixelMapTestT001
 * @tc.desc: delete PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest001 start";

    auto pixelMap1 = ConstructPixmap(AllocatorType::SHARE_MEM_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    pixelMap1 = nullptr;

    auto pixelMap2 = ConstructPixmap((AllocatorType)10);
    EXPECT_TRUE(pixelMap2 != nullptr);
    pixelMap2 = nullptr;

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest001 end";
}

/**
 * @tc.name: PixelMapTestT002
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest002 start";

    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    uint32_t colorlength = sizeof(color) / sizeof(color[0]);
    EXPECT_TRUE(colorlength == 8);
    const int32_t offset = 0;
    InitializationOptions opts;
    opts.size.width = 3;
    opts.size.height = 2;
    opts.pixelFormat = PixelFormat::UNKNOWN;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = opts.size.width;
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, 0, opts);
    EXPECT_EQ(pixelMap1, nullptr);

    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(color, colorlength, offset, INT32_MAX, opts);
    EXPECT_EQ(pixelMap2, nullptr);

    std::unique_ptr<PixelMap> pixelMap3 = PixelMap::Create(color, colorlength, -1, width, opts);
    EXPECT_EQ(pixelMap3, nullptr);

    std::unique_ptr<PixelMap> pixelMap4= PixelMap::Create(color, colorlength, 100, width, opts);
    EXPECT_EQ(pixelMap4, nullptr);

    std::unique_ptr<PixelMap> pixelMap5= PixelMap::Create(color, colorlength, offset, width, opts);
    EXPECT_TRUE(pixelMap5 != nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest002 end";
}

/**
 * @tc.name: PixelMapTestT003
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTestT003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTestT003 start";

    InitializationOptions opts1;
    opts1.size.width = 200;
    opts1.size.height = 300;
    opts1.pixelFormat = PixelFormat::RGBA_8888;
    opts1.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(opts1);
    EXPECT_TRUE(pixelMap1 != nullptr);

    InitializationOptions opts2;
    opts2.size.width = 200;
    opts2.size.height = 300;
    opts2.pixelFormat = PixelFormat::BGRA_8888;
    opts2.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(opts2);
    EXPECT_TRUE(pixelMap2 != nullptr);

    InitializationOptions opts3;
    opts3.size.width = 200;
    opts3.size.height = 300;
    opts3.pixelFormat = PixelFormat::ARGB_8888;
    opts3.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> pixelMap3 = PixelMap::Create(opts3);
    EXPECT_TRUE(pixelMap3 != nullptr);

    InitializationOptions opts4;
    opts4.size.width = 200;
    opts4.size.height = 300;
    opts4.pixelFormat = PixelFormat::RGB_565;
    opts4.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> pixelMap4 = PixelMap::Create(opts4);
    EXPECT_TRUE(pixelMap4 != nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTestT003 end";
}

/**
 * @tc.name: PixelMapTest004
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest004 start";

    PixelMap srcPixelMap;
    ImageInfo imageInfo;
    imageInfo.size.width = 200;
    imageInfo.size.height = 300;
    imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    imageInfo.colorSpace = ColorSpace::SRGB;
    srcPixelMap.SetImageInfo(imageInfo);
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    Rect srcRect1;
    srcRect1.width = 200;
    srcRect1.height = 300;
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(srcPixelMap, srcRect1, opts);
    EXPECT_EQ(pixelMap1, nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest004 end";
}

/**
 * @tc.name: PixelMapTest005
 * @tc.desc: SetImageInfo
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest005 start";
    std::unique_ptr<PixelMap> pixelMap1 = std::make_unique<PixelMap>();
    ImageInfo info1;
    info1.size.width = 200;
    info1.size.height = 0;
    info1.pixelFormat = PixelFormat::RGB_888;
    info1.colorSpace = ColorSpace::SRGB;
    auto ret = pixelMap1->SetImageInfo(info1);
    EXPECT_EQ(ret, ERR_IMAGE_DATA_ABNORMAL);

    std::unique_ptr<PixelMap> pixelMap2 = std::make_unique<PixelMap>();
    ImageInfo info2;
    info2.size.width = 200;
    info2.size.height = 300;
    info2.pixelFormat = PixelFormat::NV12;
    info2.colorSpace = ColorSpace::SRGB;
    ret = pixelMap2->SetImageInfo(info2);
    EXPECT_EQ(ret, SUCCESS);

    std::unique_ptr<PixelMap> pixelMap3 = std::make_unique<PixelMap>();
    ImageInfo info3;
    info3.size.width = 200;
    info3.size.height = 300;
    info3.pixelFormat = PixelFormat::NV21;
    info3.colorSpace = ColorSpace::SRGB;
    ret = pixelMap3->SetImageInfo(info3);
    EXPECT_EQ(ret, SUCCESS);

    std::unique_ptr<PixelMap> pixelMap4 = std::make_unique<PixelMap>();
    ImageInfo info4;
    info4.size.width = 200;
    info4.size.height = 300;
    info4.pixelFormat = PixelFormat::CMYK;
    info4.colorSpace = ColorSpace::SRGB;
    ret = pixelMap4->SetImageInfo(info4);
    EXPECT_EQ(ret, SUCCESS);

    std::unique_ptr<PixelMap> pixelMap5 = std::make_unique<PixelMap>();
    ImageInfo info5;
    info5.size.width = 200;
    info5.size.height = 300;
    info5.pixelFormat = PixelFormat::RGBA_F16;
    info5.colorSpace = ColorSpace::SRGB;
    ret = pixelMap5->SetImageInfo(info5);
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest005 end";
}

/**
 * @tc.name: PixelMapTest006
 * @tc.desc: SetImageInfo
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest006 start";
    std::unique_ptr<PixelMap> pixelMap1 = std::make_unique<PixelMap>();
    ImageInfo info1;
    info1.size.width = INT32_MAX;
    info1.size.height = 300;
    info1.pixelFormat = PixelFormat::RGB_888;
    info1.colorSpace = ColorSpace::SRGB;
    auto ret = pixelMap1->SetImageInfo(info1);
    EXPECT_EQ(ret, ERR_IMAGE_TOO_LARGE);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest006 end";
}

/**
 * @tc.name: PixelMapTest007
 * @tc.desc: GetPixel
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest007 start";

    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    auto ret1 = pixelMap1->GetPixel8(100, 200);
    EXPECT_TRUE(ret1 == nullptr);

    auto pixelMap2 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap2 != nullptr);
    auto ret2 = pixelMap2->GetPixel16(100, 200);
    EXPECT_TRUE(ret2 == nullptr);

    auto pixelMap3 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap3 != nullptr);
    auto ret3 = pixelMap3->GetPixel32(100, 200);
    EXPECT_TRUE(ret3 == nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest007 end";
}

/**
 * @tc.name: PixelMapTest008
 * @tc.desc: IsSameImage
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest008 start";

    std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);

    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    auto ret = pixelMap1->IsSameImage(*pixelMap);
    EXPECT_FALSE(ret);

    auto pixelMap2 = ConstructPixmap(300, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap2 != nullptr);
    ret = pixelMap1->IsSameImage(*pixelMap2);
    EXPECT_FALSE(ret);

    auto pixelMap3 = ConstructPixmap(200, 200, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap3 != nullptr);
    ret = pixelMap1->IsSameImage(*pixelMap3);
    EXPECT_FALSE(ret);

    auto pixelMap4 = ConstructPixmap(200, 300, PixelFormat::RGB_888, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap4 != nullptr);
    ret = pixelMap1->IsSameImage(*pixelMap4);
    EXPECT_FALSE(ret);

    auto pixelMap5 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_PREMUL,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap5 != nullptr);
    ret = pixelMap1->IsSameImage(*pixelMap5);
    EXPECT_FALSE(ret);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest008 end";
}

/**
 * @tc.name: PixelMapTest009
 * @tc.desc: ReadPixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest009 start";

    std::unique_ptr<PixelMap> pixelMap1 = std::make_unique<PixelMap>();
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap1->SetImageInfo(info);
    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    EXPECT_TRUE(dst1 != nullptr);
    auto ret = pixelMap1->ReadPixels(bufferSize1, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    auto pixelMap2 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap2 != nullptr);
    uint64_t bufferSize2 = 96;
    uint8_t *dst2 = new uint8_t(0);
    EXPECT_TRUE(dst2 != nullptr);
    ret = pixelMap2->ReadPixels(bufferSize2, dst2);
    EXPECT_TRUE(ret != SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest009 end";
}

/**
 * @tc.name: PixelMapTest010
 * @tc.desc: ReadPixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest010 start";
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    uint32_t offset1 = 0;
    uint32_t stride1 = 8;
    Rect rect1;
    rect1.left = 0;
    rect1.top = 0;
    rect1.height = 1;
    rect1.width = 2;
    EXPECT_TRUE(dst1 != nullptr);
    auto ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect1, dst1);
    EXPECT_TRUE(ret == SUCCESS);

    uint64_t bufferSize2 = 0;
    uint8_t *dst2 = new uint8_t(0);
    EXPECT_TRUE(dst2 != nullptr);
    ret = pixelMap1->ReadPixels(bufferSize2, offset1, stride1, rect1, dst2);
    EXPECT_TRUE(ret != SUCCESS);

    uint64_t bufferSize3 = 96;
    uint8_t *dst3 = new uint8_t(0);
    uint32_t offset3 = 0;
    uint32_t stride3 = 8;
    Rect rect3;
    rect3.left = -1;
    rect3.top = 0;
    rect3.height = 1;
    rect3.width = 2;
    ret = pixelMap1->ReadPixels(bufferSize3, offset3, stride3, rect3, dst3);
    EXPECT_TRUE(ret != SUCCESS);

    uint64_t bufferSize4 = 96;
    uint8_t *dst4 = new uint8_t(0);
    Rect rect4;
    rect4.left = 0;
    rect4.top = -1;
    rect4.height = 1;
    rect4.width = 2;
    ret = pixelMap1->ReadPixels(bufferSize4, offset3, stride3, rect4, dst4);
    EXPECT_TRUE(ret != SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest010 end";
}

/**
 * @tc.name: PixelMapTest011
 * @tc.desc: ReadPixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest011 start";
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);

    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    uint32_t offset1 = 0;
    uint32_t stride1 = 8;
    Rect rect1;
    rect1.left = 0;
    rect1.top = 0;
    rect1.height = -1;
    rect1.width = 2;
    auto ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect1, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    Rect rect2;
    rect2.left = 0;
    rect2.top = 0;
    rect2.height = 1;
    rect2.width = -1;
    ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect2, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    Rect rect3;
    rect3.left = 0;
    rect3.top = 0;
    rect3.height = (INT32_MAX >> 2) + 1;
    rect3.width = 2;
    ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect3, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    Rect rect4;
    rect4.left = 0;
    rect4.top = 0;
    rect4.height = 1;
    rect4.width = (INT32_MAX >> 2) + 1;
    ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect4, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest011 end";
}

/**
 * @tc.name: PixelMapTest012
 * @tc.desc: ReadPixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest012 start";
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);

    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    uint32_t offset1 = 0;
    uint32_t stride1 = 8;
    Rect rect1;
    rect1.left = 500;
    rect1.top = 0;
    rect1.height = 1;
    rect1.width = 2;
    auto ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect1, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    Rect rect2;
    rect2.left = 0;
    rect2.top = 500;
    rect2.height = 1;
    rect2.width = 2;
    ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect2, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    uint32_t stride2 = 1;
    Rect rect3;
    rect3.left = 0;
    rect3.top = 0;
    rect3.height = 1;
    rect3.width = 2;
    ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride2, rect3, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    uint64_t bufferSize2 = 6;
    ret = pixelMap1->ReadPixels(bufferSize2, offset1, stride1, rect3, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest012 end";
}

/**
 * @tc.name: PixelMapTest013
 * @tc.desc: ReadPixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest013 start";
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);

    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    uint32_t offset1 = 500;
    uint32_t stride1 = 8;
    Rect rect1;
    rect1.left = 0;
    rect1.top = 0;
    rect1.height = 1;
    rect1.width = 2;
    auto ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect1, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    std::unique_ptr<PixelMap> pixelMap2 = std::make_unique<PixelMap>();
    ImageInfo info;
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap2->SetImageInfo(info);
    EXPECT_TRUE(pixelMap2 != nullptr);

    uint64_t bufferSize2 = 96;
    uint8_t *dst2 = new uint8_t(0);
    uint32_t offset2 = 0;
    uint32_t stride2 = 8;
    Rect rect2;
    rect2.left = 0;
    rect2.top = 0;
    rect2.height = 1;
    rect2.width = 2;
    ret = pixelMap2->ReadPixels(bufferSize2, offset2, stride2, rect2, dst2);
    EXPECT_TRUE(ret != SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest013 end";
}

/**
 * @tc.name: PixelMapTest014
 * @tc.desc: ReadPixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest014 start";
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);

    Position position;
    position.x = 1;
    position.y = 1;
    uint32_t dst = 0;
    auto ret = pixelMap1->ReadPixel(position, dst);
    EXPECT_TRUE(ret == SUCCESS);

    Position position1;
    position1.x = -1;
    position1.y = 1;
    ret = pixelMap1->ReadPixel(position1, dst);
    EXPECT_TRUE(ret != SUCCESS);

    Position position2;
    position2.x = 1;
    position2.y = -1;
    ret = pixelMap1->ReadPixel(position2, dst);
    EXPECT_TRUE(ret != SUCCESS);

    Position position3;
    position3.x = 300;
    position3.y = 1;
    ret = pixelMap1->ReadPixel(position3, dst);
    EXPECT_TRUE(ret != SUCCESS);

    Position position4;
    position4.x = 1;
    position4.y = 400;
    ret = pixelMap1->ReadPixel(position4, dst);
    EXPECT_TRUE(ret != SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest014 end";
}

/**
 * @tc.name: PixelMapTest015
 * @tc.desc: ResetConfig
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest015 start";
    auto pixelMap1 = ConstructPixmap(3, 3, PixelFormat::ALPHA_8, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    Size size1;
    size1.width = 6;
    size1.height = 6;
    PixelFormat pixelFormat = PixelFormat::UNKNOWN;
    auto ret = pixelMap1->ResetConfig(size1, pixelFormat);
    EXPECT_TRUE(ret != SUCCESS);

    Size size2;
    size2.width = 1;
    size2.height = 1;
    PixelFormat pixelFormat2 = PixelFormat::RGB_888;
    ret = pixelMap1->ResetConfig(size2, pixelFormat2);
    EXPECT_TRUE(ret == SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest015 end";
}

/**
 * @tc.name: PixelMapTest016
 * @tc.desc: ResetConfig
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest016 start";
    auto pixelMap1 = ConstructPixmap(3, 3, PixelFormat::ALPHA_8, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    Size size1;
    size1.width = 6;
    size1.height = 6;
    PixelFormat pixelFormat = PixelFormat::UNKNOWN;
    auto ret = pixelMap1->ResetConfig(size1, pixelFormat);
    EXPECT_TRUE(ret != SUCCESS);

    Size size2;
    size2.width = 1;
    size2.height = 1;
    PixelFormat pixelFormat2 = PixelFormat::RGB_888;
    ret = pixelMap1->ResetConfig(size2, pixelFormat2);
    EXPECT_TRUE(ret == SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest016 end";
}

/**
 * @tc.name: PixelMapTest017
 * @tc.desc: SetAlphaType
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest017 start";
    auto pixelMap1 = ConstructPixmap(3, 3, PixelFormat::ALPHA_8, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    auto ret = pixelMap1->SetAlphaType(AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest017 end";
}

/**
 * @tc.name: PixelMapTest018
 * @tc.desc: WritePixel
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest018 start";
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    EXPECT_TRUE(pixelMap != nullptr);

    Position position;
    position.x = 0;
    position.y = 0;
    uint32_t color = 9;
    auto ret = pixelMap->WritePixel(position, color);
    EXPECT_FALSE(ret);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest018 end";
}

/**
 * @tc.name: PixelMapTest019
 * @tc.desc: WritePixel
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest019 start";
    PixelMap srcPixelMap;
    ImageInfo imageInfo;
    imageInfo.size.width = 200;
    imageInfo.size.height = 300;
    imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    imageInfo.colorSpace = ColorSpace::SRGB;
    srcPixelMap.SetImageInfo(imageInfo);
    int32_t rowDataSize = 200;
    uint32_t bufferSize = rowDataSize * 300;
    void *buffer = malloc(bufferSize);
    char *ch = static_cast<char *>(buffer);
    for (unsigned int i = 0; i < bufferSize; i++) {
        *(ch++) = (char)i;
    }
    srcPixelMap.SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    Rect srcRect1;
    srcRect1.width = 200;
    srcRect1.height = 300;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(srcPixelMap, srcRect1, opts);

    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    uint32_t offset1 = 500;
    uint32_t stride1 = 8;
    Rect rect1;
    rect1.left = 0;
    rect1.top = 0;
    rect1.height = 1;
    rect1.width = 2;
    auto ret = pixelMap->WritePixels(dst1, bufferSize1, offset1, stride1, rect1);
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest019 end";
}

/**
 * @tc.name: PixelMapTest020
 * @tc.desc: WritePixel
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest020 start";
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    EXPECT_TRUE(pixelMap != nullptr);

    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    auto ret = pixelMap->WritePixels(dst1, bufferSize1);
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest020 end";
}

/**
 * @tc.name: PixelMapTest021
 * @tc.desc: WritePixel
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest021, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest021 start";
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    EXPECT_TRUE(pixelMap != nullptr);

    uint32_t color = 1;
    auto ret = pixelMap->WritePixels(color);
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest021 end";
}

/**
 * @tc.name: PixelMapTest022
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest022, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest022 start";
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(opts);
    EXPECT_TRUE(pixelMap1 != nullptr);
    Parcel data;
    auto ret = pixelMap1->Marshalling(data);
    EXPECT_TRUE(ret);
    PixelMap *pixelMap2 = PixelMap::Unmarshalling(data);
    EXPECT_EQ(pixelMap1->GetHeight(), pixelMap2->GetHeight());

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest022 end";
}

/**
 * @tc.name: PixelMapTest023
 * @tc.desc: SetAlpha
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest023 start";
    auto pixelMap1 = ConstructPixmap(PixelFormat::ALPHA_8, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    EXPECT_TRUE(pixelMap1 != nullptr);
    auto ret = pixelMap1->SetAlpha(0.f);
    EXPECT_TRUE(ret != SUCCESS);
    ret = pixelMap1->SetAlpha(2.f);
    EXPECT_TRUE(ret != SUCCESS);
    ret = pixelMap1->SetAlpha(0.1f);
    EXPECT_TRUE(ret == SUCCESS);

    auto pixelMap2 = ConstructPixmap(PixelFormat::ARGB_8888, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    ret = pixelMap2->SetAlpha(0.1f);
    EXPECT_TRUE(ret == SUCCESS);

    auto pixelMap3 = ConstructPixmap(PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    ret = pixelMap3->SetAlpha(0.1f);
    EXPECT_TRUE(ret == SUCCESS);

    auto pixelMap4 = ConstructPixmap(PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    ret = pixelMap4->SetAlpha(0.1f);
    EXPECT_TRUE(ret == SUCCESS);

    auto pixelMap5 = ConstructPixmap(PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    ret = pixelMap5->SetAlpha(0.1f);
    EXPECT_TRUE(ret == SUCCESS);

    auto pixelMap6 = ConstructPixmap(PixelFormat::CMYK, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    ret = pixelMap6->SetAlpha(0.1f);
    EXPECT_TRUE(ret != SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest023 end";
}
}
}