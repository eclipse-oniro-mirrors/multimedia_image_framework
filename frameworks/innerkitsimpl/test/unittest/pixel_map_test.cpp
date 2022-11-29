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
    AllocatorType type)
{
    std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = format;
    info.colorSpace = ColorSpace::SRGB;
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

    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    auto ret1 = pixelMap1->GetPixel8(100, 200);
    EXPECT_TRUE(ret1 == nullptr);

    auto pixelMap2 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap2 != nullptr);
    auto ret2 = pixelMap2->GetPixel16(100, 200);
    EXPECT_TRUE(ret2 == nullptr);

    auto pixelMap3 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap3 != nullptr);
    auto ret3 = pixelMap3->GetPixel32(100, 200);
    EXPECT_TRUE(ret3 == nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest007 end";
}
}
}