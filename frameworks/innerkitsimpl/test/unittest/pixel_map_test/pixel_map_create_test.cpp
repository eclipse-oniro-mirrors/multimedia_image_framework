/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define protected public
#define private public
#include <gtest/gtest.h>

#include <climits>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "image_type.h"
#include "media_errors.h"
#include "pixel_map.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class PixelMapTest : public testing::Test {
public:
    PixelMapTest() {}
    ~PixelMapTest() {}
};

static std::map<PixelFormat, std::string> gPixelFormat = {
    { PixelFormat::ARGB_8888, "PixelFormat::ARGB_8888" },
    { PixelFormat::RGB_565,   "PixelFormat::RGB_565" },
    { PixelFormat::RGBA_8888, "PixelFormat::RGBA_8888" },
    { PixelFormat::BGRA_8888, "PixelFormat::BGRA_8888" },
    { PixelFormat::RGB_888,   "PixelFormat::RGB_888" },
    { PixelFormat::ALPHA_8,   "PixelFormat::ALPHA_8" },
    { PixelFormat::RGBA_F16,  "PixelFormat::RGBA_F16" },
    { PixelFormat::NV21,      "PixelFormat::NV21" },
    { PixelFormat::NV12,      "PixelFormat::NV12" }
};

/**
 * @tc.name: PixelMapCreateTest001
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest001 start";

    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;

    std::map<PixelFormat, std::string>::iterator iter;

    // ARGB_8888 to others
    options.srcPixelFormat = PixelFormat::ARGB_8888;
    for (iter = gPixelFormat.begin(); iter != gPixelFormat.end(); ++iter) {
        uint32_t colorlength = 24;    // w:2 * h:3 * pixelByte:4
        uint8_t buffer[24] = { 0 };    // w:2 * h:3 * pixelByte:4
        for (int i = 0; i < colorlength; i += 4) {
            buffer[i] = 0x78;
            buffer[i + 1] = 0x83;
            buffer[i + 2] = 0xDF;
            buffer[i + 3] = 0x52;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        EXPECT_NE(pixelMap1, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest001 end";
}

/**
 * @tc.name: PixelMapCreateTest002
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest002 start";

    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;

    std::map<PixelFormat, std::string>::iterator iter;

    // RGB_565 to others
    options.srcPixelFormat = PixelFormat::RGB_565;
    for (iter = gPixelFormat.begin(); iter != gPixelFormat.end(); ++iter) {
        uint32_t colorlength = 12;    // w:2 * h:3 * pixelByte:2
        uint8_t buffer[12] = { 0 };    // w:2 * h:3 * pixelByte:2
        for (int i = 0; i < colorlength; i += 6) {
            buffer[i] = 0xEA;
            buffer[i + 1] = 0x8E;
            buffer[i + 2] = 0x0A;
            buffer[i + 3] = 0x87;
            buffer[i + 4] = 0x0B;
            buffer[i + 5] = 0x87;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        EXPECT_NE(pixelMap1, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest002 end";
}

/**
 * @tc.name: PixelMapCreateTest003
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest003 start";

    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;

    std::map<PixelFormat, std::string>::iterator iter;

    // RGBA_8888 to others
    options.srcPixelFormat = PixelFormat::RGBA_8888;
    for (iter = gPixelFormat.begin(); iter != gPixelFormat.end(); ++iter) {
        uint32_t colorlength = 24;    // w:2 * h:3 * pixelByte:4
        uint8_t buffer[24] = { 0 };    // w:2 * h:3 * pixelByte:4
        for (int i = 0; i < colorlength; i += 4) {
            buffer[i] = 0x83;
            buffer[i + 1] = 0xDF;
            buffer[i + 2] = 0x52;
            buffer[i + 3] = 0x78;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        EXPECT_NE(pixelMap1, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest003 end";
}

/**
 * @tc.name: PixelMapCreateTest004
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest004 start";

    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;

    std::map<PixelFormat, std::string>::iterator iter;

    // BGRA_8888 to others
    options.srcPixelFormat = PixelFormat::BGRA_8888;
    for (iter = gPixelFormat.begin(); iter != gPixelFormat.end(); ++iter) {
        uint32_t colorlength = 24;    // w:2 * h:3 * pixelByte:4
        uint8_t buffer[24] = { 0 };    // w:2 * h:3 * pixelByte:4
        for (int i = 0; i < colorlength; i += 4) {
            buffer[i] = 0x52;
            buffer[i + 1] = 0xDF;
            buffer[i + 2] = 0x83;
            buffer[i + 3] = 0x78;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        EXPECT_NE(pixelMap1, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest004 end";
}

/**
 * @tc.name: PixelMapCreateTest005
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest005 start";

    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;

    std::map<PixelFormat, std::string>::iterator iter;

    // RGB_888 to others
    options.srcPixelFormat = PixelFormat::RGB_888;
    for (iter = gPixelFormat.begin(); iter != gPixelFormat.end(); ++iter) {
        uint32_t colorlength = 18;    // w:2 * h:3 * pixelByte:3
        uint8_t buffer[20] = { 0 };    // w:2 * h:3 * pixelByte:3 and add 2 for uint32_t
        for (int i = 0; i < colorlength; i += 3) {
            buffer[i] = 0x83;
            buffer[i + 1] = 0xDF;
            buffer[i + 2] = 0x52;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        EXPECT_NE(pixelMap1, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest005 end";
}

/**
 * @tc.name: PixelMapCreateTest006
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest006 start";

    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;

    std::map<PixelFormat, std::string>::iterator iter;

    // ALPHA_8 to others
    options.srcPixelFormat = PixelFormat::ALPHA_8;
    for (iter = gPixelFormat.begin(); iter != gPixelFormat.end(); ++iter) {
        if (iter->first == PixelFormat::ARGB_8888) {
            continue; // PixelMap doesn't support ARGB
        }

        uint32_t colorlength = 6;    // w:2 * h:3 * pixelByte:1
        uint8_t buffer[8] = { 0 };    // w:2 * h:3 * pixelByte:1 and add 2 for uint32_t
        for (int i = 0; i < colorlength; i++) {
            buffer[i] = 0x78;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        EXPECT_NE(pixelMap1, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest006 end";
}

/**
 * @tc.name: PixelMapCreateTest007
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest007 start";

    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;

    std::map<PixelFormat, std::string>::iterator iter;

    // RGBA_F16 to others
    options.srcPixelFormat = PixelFormat::RGBA_F16;
    for (iter = gPixelFormat.begin(); iter != gPixelFormat.end(); ++iter) {
        uint32_t colorlength = 48;    // w:2 * h:3 * pixelByte:8
        uint8_t buffer[48] = { 0 };    // w:2 * h:3 * pixelByte:8
        for (int i = 0; i < colorlength; i += 8) {
            buffer[i] = 0xEF;
            buffer[i + 1] = 0x82;
            buffer[i + 2] = 0x05;
            buffer[i + 3] = 0xDF;
            buffer[i + 4] = 0x05;
            buffer[i + 5] = 0x52;
            buffer[i + 6] = 0x78;
            buffer[i + 7] = 0x78;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        EXPECT_NE(pixelMap1, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest007 end";
}

/**
 * @tc.name: PixelMapCreateTest008
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest008 start";

    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;

    std::map<PixelFormat, std::string>::iterator iter;

    // NV21 to others
    options.srcPixelFormat = PixelFormat::NV21;
    for (iter = gPixelFormat.begin(); iter != gPixelFormat.end(); ++iter) {
        uint8_t buffer[12] = { 0 };    // w:2 * h:3 * pixelByte:2
        int yLen = options.size.width * options.size.height;  // yLen is 6
        int w = (options.size.width % 2 == 0) ? (options.size.width) : (options.size.width + 1);
        int h = (options.size.height % 2 == 0) ? (options.size.height) : (options.size.height + 1);
        int uvLen = w * h / 2;    // uvLen is 4
        for (int i = 0; i < yLen; i++) {
            buffer[i] = 0xAA;
        }
        for (int i = yLen; i < yLen + uvLen; i += 2) {
            buffer[i] = 0x62;
            buffer[i + 1] = 0x50;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        uint32_t colorlength = yLen + uvLen;
        options.pixelFormat = iter->first;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        EXPECT_NE(pixelMap1, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest008 end";
}

/**
 * @tc.name: PixelMapCreateTest009
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest009 start";

    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;

    std::map<PixelFormat, std::string>::iterator iter;

    // NV12 to others
    options.srcPixelFormat = PixelFormat::NV12;
    for (iter = gPixelFormat.begin(); iter != gPixelFormat.end(); ++iter) {
        uint8_t buffer[12] = { 0 };    // w:2 * h:3 * pixelByte:2
        int yLen = options.size.width * options.size.height;  // yLen is 6
        int w = (options.size.width % 2 == 0) ? (options.size.width) : (options.size.width + 1);
        int h = (options.size.height % 2 == 0) ? (options.size.height) : (options.size.height + 1);
        int uvLen = w * h / 2;    // uvLen is 4
        for (int i = 0; i < yLen; i++) {
            buffer[i] = 0xAA;
        }
        for (int i = yLen; i < yLen + uvLen; i += 2) {
            buffer[i] = 0x50;
            buffer[i + 1] = 0x62;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        uint32_t colorlength = yLen + uvLen;
        options.pixelFormat = iter->first;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        EXPECT_NE(pixelMap1, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest009 end";
}

/**
 * @tc.name: PixelMapCreateTest010
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest010 start";

    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;

    std::map<PixelFormat, std::string>::iterator iter;

    // CMYK to others
    options.srcPixelFormat = PixelFormat::CMYK;
    for (iter = gPixelFormat.begin(); iter != gPixelFormat.end(); ++iter) {
        uint32_t colorlength = 18;    // w:2 * h:3 * pixelByte:3
        uint8_t buffer[20] = { 0 };    // w:2 * h:3 * pixelByte:3 and add 2 for uint32_t
        for (int i = 0; i < 6; i++) {
            buffer[i] = 0xDF;
            buffer[i + 6] = 0x52;
            buffer[i + 12] = 0x83;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        EXPECT_EQ(pixelMap1, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest010 end";
}

/**
 * @tc.name: PixelMapTestT002
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest002 start";

    // 8 means color length, { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 } used for test
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    uint32_t colorlength = sizeof(color) / sizeof(color[0]);
    EXPECT_TRUE(colorlength == 8);
    // 0 means offset
    const int32_t offset = 0;
    InitializationOptions opts;
    // 3 means width
    opts.size.width = 3;
    // 2 means height
    opts.size.height = 2;
    opts.pixelFormat = PixelFormat::UNKNOWN;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = opts.size.width;

    // 0 means width
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, 0, opts);
    EXPECT_NE(pixelMap1, nullptr);

    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(color, colorlength, offset, INT32_MAX, opts);
    EXPECT_NE(pixelMap2, nullptr);
    // -1 means offset
    std::unique_ptr<PixelMap> pixelMap3 = PixelMap::Create(color, colorlength, -1, width, opts);
    EXPECT_NE(pixelMap3, nullptr);
    // 100 means offset
    std::unique_ptr<PixelMap> pixelMap4= PixelMap::Create(color, colorlength, 100, width, opts);
    EXPECT_NE(pixelMap4, nullptr);

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
    // 200 means width
    opts1.size.width = 200;
    // 300 means height
    opts1.size.height = 300;
    opts1.pixelFormat = PixelFormat::RGBA_8888;
    opts1.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(opts1);
    EXPECT_TRUE(pixelMap1 != nullptr);

    InitializationOptions opts2;
    // 200 means width
    opts2.size.width = 200;
    // 300 means height
    opts2.size.height = 300;
    opts2.pixelFormat = PixelFormat::BGRA_8888;
    opts2.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(opts2);
    EXPECT_TRUE(pixelMap2 != nullptr);

    InitializationOptions opts3;
    // 200 means width
    opts3.size.width = 200;
    // 300 means height
    opts3.size.height = 300;
    opts3.pixelFormat = PixelFormat::ARGB_8888;
    opts3.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> pixelMap3 = PixelMap::Create(opts3);
    EXPECT_TRUE(pixelMap3 != nullptr);

    InitializationOptions opts4;
    // 200 means width
    opts4.size.width = 200;
    // 300 means height
    opts4.size.height = 300;
    opts4.pixelFormat = PixelFormat::RGB_565;
    opts4.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> pixelMap4 = PixelMap::Create(opts4);
    EXPECT_TRUE(pixelMap4 != nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTestT003 end";
}

/**
 * @tc.name: CreateFromPixelsTest001
 * @tc.desc: Verify CreateFromPixels succeeds with default BGRA source format. [AUTO-GENERATED]
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreateFromPixelsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest001 start";

    uint8_t pixels[] = {
        0x00, 0x11, 0x22, 0xFF, 0x33, 0x44, 0x55, 0xFF,
        0x66, 0x77, 0x88, 0xFF, 0x99, 0xAA, 0xBB, 0xFF
    };
    InitializationOptions opts;
    opts.size.width = 2;
    opts.size.height = 2;
    opts.pixelFormat = PixelFormat::BGRA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    auto [pixelMap, errCode] = PixelMap::CreateFromPixels(pixels, sizeof(pixels), opts);

    ASSERT_EQ(errCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    EXPECT_EQ(pixelMap->GetWidth(), 2);
    EXPECT_EQ(pixelMap->GetHeight(), 2);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::BGRA_8888);

    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest001 end";
}

/**
 * @tc.name: CreateFromPixelsTest002
 * @tc.desc: Verify CreateFromPixels succeeds with a custom RGB row stride. [AUTO-GENERATED]
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreateFromPixelsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest002 start";

    uint8_t pixels[] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0xEE, 0xEE,
        0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0
    };
    InitializationOptions opts;
    opts.size.width = 2;
    opts.size.height = 2;
    opts.srcPixelFormat = PixelFormat::RGB_888;
    opts.pixelFormat = PixelFormat::RGB_888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.srcRowStride = 8;

    auto [pixelMap, errCode] = PixelMap::CreateFromPixels(pixels, sizeof(pixels), opts);

    ASSERT_EQ(errCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    EXPECT_EQ(pixelMap->GetWidth(), 2);
    EXPECT_EQ(pixelMap->GetHeight(), 2);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::RGB_888);

    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest002 end";
}

/**
 * @tc.name: CreateFromPixelsTest003
 * @tc.desc: Verify CreateFromPixels rejects a null buffer. [AUTO-GENERATED]
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreateFromPixelsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest003 start";

    InitializationOptions opts;
    opts.size.width = 2;
    opts.size.height = 2;
    opts.pixelFormat = PixelFormat::BGRA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    auto [pixelMap, errCode] = PixelMap::CreateFromPixels(nullptr, 16, opts);

    EXPECT_EQ(pixelMap, nullptr);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);

    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest003 end";
}

/**
 * @tc.name: CreateFromPixelsTest004
 * @tc.desc: Verify CreateFromPixels rejects an undersized source row stride. [AUTO-GENERATED]
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreateFromPixelsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest004 start";

    uint8_t pixels[] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
        0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0
    };
    InitializationOptions opts;
    opts.size.width = 2;
    opts.size.height = 2;
    opts.srcPixelFormat = PixelFormat::RGB_888;
    opts.pixelFormat = PixelFormat::RGB_888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.srcRowStride = 5;

    auto [pixelMap, errCode] = PixelMap::CreateFromPixels(pixels, sizeof(pixels), opts);

    EXPECT_EQ(pixelMap, nullptr);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);

    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest004 end";
}

/**
 * @tc.name: CreateFromPixelsTest005
 * @tc.desc: Verify CreateFromPixels rejects invalid size options. [AUTO-GENERATED]
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreateFromPixelsTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest005 start";

    uint8_t pixels[] = { 0x00, 0x11, 0x22, 0xFF };
    InitializationOptions opts;
    opts.size.width = 0;
    opts.size.height = 1;
    opts.pixelFormat = PixelFormat::BGRA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    auto [pixelMap, errCode] = PixelMap::CreateFromPixels(pixels, sizeof(pixels), opts);

    EXPECT_EQ(pixelMap, nullptr);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);

    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest005 end";
}

/**
 * @tc.name: CreateFromPixelsTest006
 * @tc.desc: Verify CreateFromPixels rejects unsupported destination formats. [AUTO-GENERATED]
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreateFromPixelsTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest006 start";

    uint8_t pixels[] = {
        0x00, 0x11, 0x22, 0xFF, 0x33, 0x44, 0x55, 0xFF,
        0x66, 0x77, 0x88, 0xFF, 0x99, 0xAA, 0xBB, 0xFF
    };
    InitializationOptions opts;
    opts.size.width = 2;
    opts.size.height = 2;
    opts.srcPixelFormat = PixelFormat::BGRA_8888;
    opts.pixelFormat = PixelFormat::ASTC_4x4;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    auto [pixelMap, errCode] = PixelMap::CreateFromPixels(pixels, sizeof(pixels), opts);

    EXPECT_EQ(pixelMap, nullptr);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);

    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest006 end";
}

/**
 * @tc.name: CreateFromPixelsTest007
 * @tc.desc: Verify CreateFromPixels applies default destination format and alpha type. [AUTO-GENERATED]
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreateFromPixelsTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest007 start";

    uint8_t pixels[] = {
        0x00, 0x11, 0x22, 0x80, 0x33, 0x44, 0x55, 0x80,
        0x66, 0x77, 0x88, 0x80, 0x99, 0xAA, 0xBB, 0x80
    };
    InitializationOptions opts;
    opts.size.width = 2;
    opts.size.height = 2;
    opts.pixelFormat = PixelFormat::UNKNOWN;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;

    auto [pixelMap, errCode] = PixelMap::CreateFromPixels(pixels, sizeof(pixels), opts);

    ASSERT_EQ(errCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::RGBA_8888);
    EXPECT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);

    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest007 end";
}

/**
 * @tc.name: CreateFromPixelsTest008
 * @tc.desc: Verify CreateFromPixels rejects an undersized pixel buffer. [AUTO-GENERATED]
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreateFromPixelsTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest008 start";

    uint8_t pixels[] = {
        0x00, 0x11, 0x22, 0xFF, 0x33, 0x44, 0x55, 0xFF,
        0x66, 0x77, 0x88, 0xFF, 0x99, 0xAA, 0xBB, 0xFF
    };
    InitializationOptions opts;
    opts.size.width = 2;
    opts.size.height = 2;
    opts.pixelFormat = PixelFormat::BGRA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    auto [pixelMap, errCode] = PixelMap::CreateFromPixels(pixels, sizeof(pixels) - 1, opts);

    EXPECT_EQ(pixelMap, nullptr);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);

    GTEST_LOG_(INFO) << "PixelMapTest: CreateFromPixelsTest008 end";
}

} // namespace Multimedia
} // namespace OHOS
