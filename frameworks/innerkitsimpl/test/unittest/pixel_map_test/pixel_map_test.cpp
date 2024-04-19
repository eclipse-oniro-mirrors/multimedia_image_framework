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

#define private public
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
const uint8_t red = 0xFF;
const uint8_t green = 0x8F;
const uint8_t blue = 0x7F;
const uint8_t alpha = 0x7F;
class PixelMapTest : public testing::Test {
public:
    PixelMapTest() {}
    ~PixelMapTest() {}
};

std::unique_ptr<PixelMap> ConstructPixmap(AllocatorType type)
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

    int32_t bytesPerPixel = 3;
    int32_t rowDataSize = width * bytesPerPixel;
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

std::map<PixelFormat, std::string> gPixelFormat = {
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

void CreateBuffer(const uint32_t width, const uint32_t height, const uint32_t pixelByte,
    uint8_t buffer[])
{
    uint32_t colorLength = width * height * pixelByte;
    for (int i = 0; i < colorLength; i += pixelByte) {
        buffer[i] = blue;       // i blue index
        buffer[i + 1] = green;  // i + 1: green index
        buffer[i + 2] = red;    // i + 2: red index
        buffer[i + 3] = alpha;  // i + 3: alpha index
    }
}

void InitOption(struct InitializationOptions& opts, const uint32_t width, const uint32_t height,
    PixelFormat format, AlphaType alphaType)
{
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = format;
    opts.alphaType = alphaType;
}

/**
 * @tc.name: PixelMapCreateTest001
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest001, TestSize.Level3)
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
HWTEST_F(PixelMapTest, PixelMapCreateTest002, TestSize.Level3)
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
HWTEST_F(PixelMapTest, PixelMapCreateTest003, TestSize.Level3)
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
HWTEST_F(PixelMapTest, PixelMapCreateTest004, TestSize.Level3)
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
 * @tc.name: PixelMapTest004
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest004 start";

    PixelMap srcPixelMap;
    ImageInfo imageInfo;
    // 200 means width
    imageInfo.size.width = 200;
    // 300 means height
    imageInfo.size.height = 300;
    imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    imageInfo.colorSpace = ColorSpace::SRGB;
    srcPixelMap.SetImageInfo(imageInfo);
    InitializationOptions opts;
    // 200 means width
    opts.size.width = 200;
    // 300 means height
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    Rect srcRect1;
    // 200 means Rect width
    srcRect1.width = 200;
    // 300 means Rect height
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
    // 200 means width
    info2.size.width = 200;
    // 300 means height
    info2.size.height = 300;
    info2.pixelFormat = PixelFormat::NV12;
    info2.colorSpace = ColorSpace::SRGB;
    ret = pixelMap2->SetImageInfo(info2);
    EXPECT_EQ(ret, SUCCESS);

    std::unique_ptr<PixelMap> pixelMap3 = std::make_unique<PixelMap>();
    ImageInfo info3;
    // 200 means width
    info3.size.width = 200;
    // 300 means height
    info3.size.height = 300;
    info3.pixelFormat = PixelFormat::NV21;
    info3.colorSpace = ColorSpace::SRGB;
    ret = pixelMap3->SetImageInfo(info3);
    EXPECT_EQ(ret, SUCCESS);

    std::unique_ptr<PixelMap> pixelMap4 = std::make_unique<PixelMap>();
    ImageInfo info4;
    // 200 means width
    info4.size.width = 200;
    // 300 means height
    info4.size.height = 300;
    info4.pixelFormat = PixelFormat::CMYK;
    info4.colorSpace = ColorSpace::SRGB;
    ret = pixelMap4->SetImageInfo(info4);
    EXPECT_EQ(ret, SUCCESS);

    std::unique_ptr<PixelMap> pixelMap5 = std::make_unique<PixelMap>();
    ImageInfo info5;
    // 200 means width
    info5.size.width = 200;
    // 300 means height
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
    void *dstPixels = nullptr;
    void *fdBuffer = nullptr;
    uint32_t bufferSize = pixelMap1->GetByteCount();
    pixelMap1->SetPixelsAddr(dstPixels, fdBuffer, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    ImageInfo info1;
    info1.size.width = INT32_MAX;
    // 300 means height
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

    // 200 means width, 300 means height
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    // 100 means pixel x, 200 means pixel y
    auto ret1 = pixelMap1->GetPixel8(100, 200);
    EXPECT_TRUE(ret1 == nullptr);

    // 200 means width, 300 means height
    auto pixelMap2 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap2 != nullptr);
    // 100 means pixel x, 200 means pixel y
    auto ret2 = pixelMap2->GetPixel16(100, 200);
    EXPECT_TRUE(ret2 == nullptr);

    // 200 means width, 300 means height
    auto pixelMap3 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap3 != nullptr);
    // 100 means pixel x, 200 means pixel y
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
    // 200 means width
    info.size.width = 200;
    // 300 means height
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);

    // 200 means width, 300 means height
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    auto ret = pixelMap1->IsSameImage(*pixelMap);
    EXPECT_FALSE(ret);

    // 200 means width, 300 means height
    auto pixelMap2 = ConstructPixmap(300, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap2 != nullptr);
    ret = pixelMap1->IsSameImage(*pixelMap2);
    EXPECT_FALSE(ret);

    // 200 means width, 200 means height
    auto pixelMap3 = ConstructPixmap(200, 200, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap3 != nullptr);
    ret = pixelMap1->IsSameImage(*pixelMap3);
    EXPECT_FALSE(ret);

    // 200 means width, 300 means height
    auto pixelMap4 = ConstructPixmap(200, 300, PixelFormat::RGB_888, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap4 != nullptr);
    ret = pixelMap1->IsSameImage(*pixelMap4);
    EXPECT_FALSE(ret);

    // 200 means width, 300 means height
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
    // 200 means width
    info.size.width = 200;
    // 300 means height
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap1->SetImageInfo(info);
    // 96 means buffferSize
    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    EXPECT_TRUE(dst1 != nullptr);
    auto ret = pixelMap1->ReadPixels(bufferSize1, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    // 200 means width, 300 means height
    auto pixelMap2 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap2 != nullptr);
    // 96 means buffferSize
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
    // 200 means width, 300 means height
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    // 96 means buffferSize
    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    // 0 means offset
    uint32_t offset1 = 0;
    // 8 means stride
    uint32_t stride1 = 8;
    Rect rect1;
    // 0, 0, 1, 2 means rect
    rect1.left = 0;
    rect1.top = 0;
    rect1.height = 1;
    rect1.width = 2;
    EXPECT_TRUE(dst1 != nullptr);
    auto ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect1, dst1);
    EXPECT_TRUE(ret == SUCCESS);

    // 0 means buffferSize
    uint64_t bufferSize2 = 0;
    uint8_t *dst2 = new uint8_t(0);
    EXPECT_TRUE(dst2 != nullptr);
    ret = pixelMap1->ReadPixels(bufferSize2, offset1, stride1, rect1, dst2);
    EXPECT_TRUE(ret != SUCCESS);

    // 96 means buffferSize
    uint64_t bufferSize3 = 96;
    uint8_t *dst3 = new uint8_t(0);
    // 0 means offset
    uint32_t offset3 = 0;
    // 8 means stride
    uint32_t stride3 = 8;
    Rect rect3;
    // -1, 0, 1, 2 means rect
    rect3.left = -1;
    rect3.top = 0;
    rect3.height = 1;
    rect3.width = 2;
    ret = pixelMap1->ReadPixels(bufferSize3, offset3, stride3, rect3, dst3);
    EXPECT_TRUE(ret != SUCCESS);

    // 96 means buffferSize
    uint64_t bufferSize4 = 96;
    uint8_t *dst4 = new uint8_t(0);
    Rect rect4;
    // 0, -1, 1, 2 means rect
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
    // 200 means width, 300 means height
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    
    // 96 means buffferSize
    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    // 0 means offset
    uint32_t offset1 = 0;
    // 8 means stride
    uint32_t stride1 = 8;
    Rect rect1;
    // 0, 0, -1, 2 means rect
    rect1.left = 0;
    rect1.top = 0;
    rect1.height = -1;
    rect1.width = 2;
    auto ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect1, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    Rect rect2;
    // 0, 0, 1, -1 means rect
    rect2.left = 0;
    rect2.top = 0;
    rect2.height = 1;
    rect2.width = -1;
    ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect2, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    Rect rect3;
    // 0, 0, 1, 2 means rect
    rect3.left = 0;
    rect3.top = 0;
    rect3.height = (INT32_MAX >> 2) + 1;
    rect3.width = 2;
    ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect3, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    Rect rect4;
    // 0, 0, 1, 1 means rect
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
    // 200 means width, 300 means height
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);

    // 96 means buffferSize
    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    // 0 means offset
    uint32_t offset1 = 0;
    // 8 means stride
    uint32_t stride1 = 8;
    Rect rect1;
    // 500, 0, 1, 2 means rect
    rect1.left = 500;
    rect1.top = 0;
    rect1.height = 1;
    rect1.width = 2;
    auto ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect1, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    Rect rect2;
    // 0, 500, 1, 2 means rect
    rect2.left = 0;
    rect2.top = 500;
    rect2.height = 1;
    rect2.width = 2;
    ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect2, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    uint32_t stride2 = 1;
    Rect rect3;
    // 0, 0, 1, 2 means rect
    rect3.left = 0;
    rect3.top = 0;
    rect3.height = 1;
    rect3.width = 2;
    ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride2, rect3, dst1);
    EXPECT_TRUE(ret != SUCCESS);

    // 6 means buffferSize
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

/**
 * @tc.name: PixelMapTest024
 * @tc.desc: Test of ReleaseSharedMemory
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest024 start";
    std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
    ImageInfo imageInfo;
    imageInfo.size.width = 200;
    imageInfo.size.height = 300;
    imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    imageInfo.colorSpace = ColorSpace::SRGB;
    pixelMap->SetImageInfo(imageInfo);
    int32_t rowDataSize = 200;
    uint32_t bufferSize = rowDataSize * 300;
    void *buffer = malloc(bufferSize);
    char *ch = static_cast<char *>(buffer);
    for (unsigned int i = 0; i < bufferSize; i++) {
        *(ch++) = (char)i;
    }
    uint32_t contextSize = 10;
    void *context = malloc(contextSize);
    EXPECT_TRUE(context != nullptr);
    char *contextChar = static_cast<char *>(context);
    for (int32_t i = 0; i < contextSize; i++) {
        *(contextChar++) = (char)i;
    }
    pixelMap->SetPixelsAddr(buffer, context, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);
    EXPECT_TRUE(pixelMap != nullptr);
    pixelMap = nullptr;

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest024 end";
}

/**
 * @tc.name: PixelMapTest025
 * @tc.desc: Test of Create
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest025 start";
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    uint32_t colorlength = sizeof(color) / sizeof(color[0]);
    EXPECT_TRUE(colorlength == 8);
    const int32_t offset = -1;
    InitializationOptions opts;
    opts.size.width = 3;
    opts.size.height = 2;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = opts.size.width;
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, 1, opts);
    EXPECT_NE(pixelMap1, nullptr);

    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(color, colorlength, offset, INT32_MAX, opts);
    EXPECT_NE(pixelMap2, nullptr);

    std::unique_ptr<PixelMap> pixelMap3= PixelMap::Create(color, colorlength, offset, width, opts);
    EXPECT_NE(pixelMap3, nullptr);

    std::unique_ptr<PixelMap> pixelMap4= PixelMap::Create(color, colorlength, 0, width, opts);
    EXPECT_TRUE(pixelMap4 != nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest025 end";
}

/**
 * @tc.name: PixelMapTest026
 * @tc.desc: Test of Create rect is abnormal
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest026 start";
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

    Rect rect;
    rect.left = -100;
    rect.top = 0;
    rect.height = 1;
    rect.width = 1;
    InitializationOptions opts;
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    opts.scaleMode = ScaleMode::CENTER_CROP;
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(srcPixelMap, rect, opts);
    EXPECT_TRUE(pixelMap1 == nullptr);

    Rect rect2;
    rect2.left = 0;
    rect2.top = 0;
    rect2.height = 100;
    rect2.width = 100;
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(srcPixelMap, rect2, opts);
    EXPECT_TRUE(pixelMap2 == nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest026 end";
}

/**
 * @tc.name: PixelMapTest027
 * @tc.desc: Test of Create useSourceIfMatch is true
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest027 start";
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

    Rect rect;
    rect.left = 0;
    rect.top = 0;
    rect.height = 100;
    rect.width = 100;
    InitializationOptions opts;
    opts.size.width = 0;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::UNKNOWN;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    opts.scaleMode = ScaleMode::CENTER_CROP;
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(srcPixelMap, rect, opts);
    EXPECT_TRUE(pixelMap1 == nullptr);

    InitializationOptions opts2;
    opts2.size.width = 0;
    opts2.size.height = 0;
    opts2.pixelFormat = PixelFormat::UNKNOWN;
    opts2.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts2.useSourceIfMatch = true;
    opts2.editable = true;
    opts2.scaleMode = ScaleMode::CENTER_CROP;
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(srcPixelMap, rect, opts2);
    EXPECT_TRUE(pixelMap2 == nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest027 end";
}

/**
 * @tc.name: PixelMapTest028
 * @tc.desc: Test of GetPixel8, GetPixel16, GetPixel32
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest028, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest028 start";
    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::ALPHA_8, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    auto ret1 = pixelMap1->GetPixel8(100, 200);
    EXPECT_TRUE(ret1 != nullptr);

    auto pixelMap2 = ConstructPixmap(200, 300, PixelFormat::RGB_565, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap2 != nullptr);
    auto ret2 = pixelMap2->GetPixel16(100, 200);
    EXPECT_TRUE(ret2 != nullptr);

    auto pixelMap3 = ConstructPixmap(200, 300, PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap3 != nullptr);
    auto ret3 = pixelMap3->GetPixel32(100, 200);
    EXPECT_TRUE(ret3 == nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest028 end";
}

/**
 * @tc.name: PixelMapTest029
 * @tc.desc: Test of IsSameImage
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapTest029, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest029 start";
    std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();

    auto pixelMap1 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    auto ret = pixelMap1->IsSameImage(*pixelMap);
    EXPECT_FALSE(ret);

    auto pixelMap2 = ConstructPixmap(500, 600, PixelFormat::RGB_888, AlphaType::IMAGE_ALPHA_TYPE_PREMUL,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap2 != nullptr);
    ret = pixelMap1->IsSameImage(*pixelMap2);
    EXPECT_FALSE(ret);

    auto pixelMap3 = ConstructPixmap(200, 300, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap3 != nullptr);
    ret = pixelMap1->IsSameImage(*pixelMap3);
    EXPECT_FALSE(ret);

    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapTest029 end";
}

/**
 * @tc.name: SetRowStride and GetRowStride
 * @tc.desc: test SetRowStride and GetRowStride
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, SetAndGetRowStride, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetAndGetRowStride start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);

    uint32_t stride = 1;
    pixelMap.SetRowStride(stride);
    int32_t res = pixelMap.GetRowStride();
    ASSERT_EQ(res, stride);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetAndGetRowStride end";
}

#ifdef IMAGE_COLORSPACE_FLAG
/**
 * @tc.name: ImagePixelMap030
 * @tc.desc: test InnerSetColorSpace
 * @tc.type: FUNC
 * @tc.require: AR000FTAMO
 */
HWTEST_F(PixelMapTest, PixelMapTest030, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap039 InnerSetColorSpace start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    OHOS::ColorManager::ColorSpace grColorSpace =
        OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    pixelMap.InnerSetColorSpace(grColorSpace);
    OHOS::ColorManager::ColorSpace outColorSpace = pixelMap.InnerGetGrColorSpace();
    pixelMap.InnerSetColorSpace(outColorSpace);
    ASSERT_NE(&outColorSpace, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ImagePixelMap039 InnerSetColorSpace end";
}

/**
 * @tc.name: InnerGetGrColorSpacePtrTest
 * @tc.desc: test InnerGetGrColorSpacePtr
 * @tc.type: FUNC
 * @tc.require: AR000FTAMO
 */
HWTEST_F(PixelMapTest, InnerGetGrColorSpacePtrTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: InnerGetGrColorSpacePtrTest InnerSetColorSpace start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    OHOS::ColorManager::ColorSpace grColorSpace =
        OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    pixelMap.InnerSetColorSpace(grColorSpace);
    std::shared_ptr<OHOS::ColorManager::ColorSpace> outColorSpace = pixelMap.InnerGetGrColorSpacePtr();
    ASSERT_NE(outColorSpace, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: InnerGetGrColorSpacePtrTest InnerSetColorSpace end";
}
#endif

#ifdef IMAGE_PURGEABLE_PIXELMAP
/**
 * @tc.name: IsPurgeable
 * @tc.desc: test IsPurgeable
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, IsPurgeableTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: IsPurgeableTest IsPurgeable start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    bool res = pixelMap.IsPurgeable();
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: IsPurgeableTest IsPurgeable end";
}

/**
 * @tc.name: GetPurgeableMemPtr
 * @tc.desc: test GetPurgeableMemPtr
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, GetPurgeableMemPtrTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: GetPurgeableMemPtrTest GetPurgeableMemPtr start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    std::shared_ptr<PurgeableMem::PurgeableMemBase> res = pixelMap.GetPurgeableMemPtr();
    ASSERT_EQ(res, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: GetPurgeableMemPtrTest GetPurgeableMemPtr end";
}

/**
 * @tc.name: SetPurgeableMemPtr
 * @tc.desc: test SetPurgeableMemPtr
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, SetPurgeableMemPtrTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetPurgeableMemPtrTest SetPurgeableMemPtr start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    std::shared_ptr<PurgeableMem::PurgeableMemBase> res = pixelMap.GetPurgeableMemPtr();
    ASSERT_EQ(res, nullptr);
    pixelMap.SetPurgeableMemPtr(res);
    std::shared_ptr<PurgeableMem::PurgeableMemBase> ptr = pixelMap.GetPurgeableMemPtr();
    ASSERT_EQ(ptr, nullptr);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetPurgeableMemPtrTest SetPurgeableMemPtr end";
}
#endif

/**
 * @tc.name: IsStrideAlignment
 * @tc.desc: test IsStrideAlignment
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, IsStrideAlignmentTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: IsStrideAlignmentTest IsStrideAlignment start";
    PixelMap pixelMap;
    ImageInfo info;
    info.size.width = 3;
    info.size.height = 3;
    info.pixelFormat = PixelFormat::ALPHA_8;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap.SetImageInfo(info);
    bool res = pixelMap.IsStrideAlignment();
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: IsStrideAlignmentTest IsStrideAlignment end";
}

/**
 * @tc.name: GetPurgeableMemPtr
 * @tc.desc: GetPixelFormatDetail***
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, GetPixelFormatDetail, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: GetPixelFormatDetail  start";
    PixelMap pixelmap;
    PixelFormat format = PixelFormat::RGBA_8888;
    auto ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format = PixelFormat::BGRA_8888;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format = PixelFormat::ARGB_8888 ;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format = PixelFormat::ALPHA_8;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format = PixelFormat::ARGB_8888;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format = PixelFormat::RGB_565;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format =PixelFormat::RGB_888;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format =PixelFormat::NV12;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format = PixelFormat::CMYK;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format = PixelFormat::RGBA_F16;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format = PixelFormat::ASTC_4x4;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, true);
    format = PixelFormat::UNKNOWN;
    ret = pixelmap.GetPixelFormatDetail(format);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: GetPixelFormatDetail GetPurgeableMemPtr end";
}
/**
 * @tc.name: GetPurgeableMemPtr
 * @tc.desc: SetAlpha  GetNamedAlphaType
 * @tc.type: FUNC***
 */
HWTEST_F(PixelMapTest, GetNamedAlphaType, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: GetNamedAlphaType  start";
    PixelMap pixelmap;
    ImageInfo info;
    const float percent = 1;
    auto ret = pixelmap.SetAlpha(percent);
    ASSERT_EQ(ret, ERR_IMAGE_DATA_UNSUPPORT);
    info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    ret = pixelmap.SetAlpha(percent);
    ASSERT_EQ(ret, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: GetNamedAlphaTyp  end";
}
/**
 * @tc.name: GetPurgeableMemPtr
 * @tc.desc: SetAlpha  GetNamedPixelFormat
 * @tc.type: FUNC***
 */
HWTEST_F(PixelMapTest, GetNamedPixelFormat001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: GetNamedPixelFormat001  start";
    PixelMap pixelmap;
    ImageInfo info;
    const float percent = 1;
    info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    info.pixelFormat = PixelFormat::ALPHA_8;
    auto ret = pixelmap.SetAlpha(percent);
    ASSERT_EQ(ret, ERR_IMAGE_DATA_UNSUPPORT);
    info.pixelFormat = PixelFormat::RGBA_F16;
    ret = pixelmap.SetAlpha(percent);
    ASSERT_EQ(ret, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: GetNamedPixelFormat001  end";
}
/**
 * @tc.name: GetPurgeableMemPtr
 * @tc.desc: SetAlpha  GetAlphaIndex
 * @tc.type: FUNC***
 */
HWTEST_F(PixelMapTest, GetNamedPixelFormat002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: GetNamedPixelFormat002  start";
    PixelMap pixelmap;
    ImageInfo info;
    const float percent = 1;
    info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    info.pixelFormat = PixelFormat::ARGB_8888;
    uint32_t ret = pixelmap.SetAlpha(percent);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: GetNamedPixelFormat002  end";
}

/**
 * @tc.name: GetPurgeableMemPtr
 * @tc.desc: ReadImageInfo
 * @tc.type: FUNC***
 */
HWTEST_F(PixelMapTest, ReadImageInfo, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ReadImageInfo  start";
    PixelMap pixeimap;
    Parcel parcel;
    ImageInfo imgInfo;
    bool ret = pixeimap.ReadImageInfo(parcel, imgInfo);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ReadImageInfo  end";
}

/**
 * @tc.name: ConvertAlphaFormatTest001
 * @tc.desc: Covernt alpha format to premul or unpremul, format is RGB_565.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ConvertAlphaFormatTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest001 start";
    const int32_t offset = 0;
    /* for test */
    const int32_t width = 2;
    /* for test */
    const int32_t height = 2;
    /* for test */
    const uint32_t pixelByte = 4;
    constexpr uint32_t colorLength = width * height * pixelByte;
    uint8_t buffer[colorLength] = {0};
    CreateBuffer(width, height, pixelByte, buffer);
    uint32_t *color = (uint32_t *)buffer;
    InitializationOptions opts1;
    InitOption(opts1, width, height, PixelFormat::RGB_565, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorLength, offset, width, opts1);

    EXPECT_TRUE(pixelMap1 != nullptr);
    InitializationOptions opts2;
    InitOption(opts2, width, height, PixelFormat::RGB_565, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(opts2);
    EXPECT_TRUE(pixelMap2 != nullptr);

    uint32_t ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), true);
    ASSERT_NE(ret, SUCCESS);

    ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), false);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest001 end";
}

/**
 * @tc.name: ConvertAlphaFormatTest002
 * @tc.desc: Covernt alpha format to premul or unpremul, format is RGBA_8888.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ConvertAlphaFormatTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest002 start";
    const int32_t offset = 0;
    /* for test */
    const int32_t width = 2;
    /* for test */
    const int32_t height = 2;
    /* for test */
    const uint32_t pixelByte = 4;
    constexpr uint32_t colorLength = width * height * pixelByte;
    uint8_t buffer[colorLength] = {0};
    CreateBuffer(width, height, pixelByte, buffer);
    uint32_t *color = (uint32_t *)buffer;
    InitializationOptions opts1;
    InitOption(opts1, width, height, PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorLength, offset, width, opts1);

    EXPECT_TRUE(pixelMap1 != nullptr);
    InitializationOptions opts2;
    InitOption(opts2, width, height, PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);

    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(opts2);
    EXPECT_TRUE(pixelMap2 != nullptr);

    void *pixelMapData = pixelMap2->GetWritablePixels();
    uint8_t *wpixel = static_cast<uint8_t *>(pixelMapData);
    uint32_t ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), true);
    ASSERT_EQ(ret, SUCCESS);
    float percent = static_cast<float>(alpha) / UINT8_MAX;
    for (int i = 0; i < colorLength; i += 4)
    {
        EXPECT_TRUE(std::abs(wpixel[i] - percent * red) <= 1);       // 1: Floating point to integer error
        EXPECT_TRUE(std::abs(wpixel[i + 1] - percent * green) <= 1); // 1: Floating point to integer error
        EXPECT_TRUE(std::abs(wpixel[i + 2] - percent * blue) <= 1);  // 1: Floating point to integer error
        EXPECT_TRUE(wpixel[i + 3] == alpha);
    }
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest002 end";
}

/**
 * @tc.name: ConvertAlphaFormatTest003
 * @tc.desc: covernt alpha format to premul or unpremul,format is BGRA_8888
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ConvertAlphaFormatTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest003 start";
    const int32_t offset = 0;       //for test
    const int32_t width = 2;        //for test
    const int32_t height = 2;       //for test
    const uint32_t pixelByte = 4;   //for test
    constexpr uint32_t colorLength = width * height * pixelByte;
    uint8_t buffer[colorLength] = {0};
    CreateBuffer(width, height, pixelByte, buffer);
    uint32_t *color = (uint32_t *)buffer;
    InitializationOptions opts1;
    InitOption(opts1, width, height, PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorLength, offset, width, opts1);
    EXPECT_TRUE(pixelMap1 != nullptr);
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(opts1);
    EXPECT_TRUE(pixelMap2 != nullptr);
    void *pixelMapData = pixelMap2->GetWritablePixels();
    uint8_t *wpixel = static_cast<uint8_t *>(pixelMapData);
    uint32_t ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), true);
    ASSERT_EQ(ret, SUCCESS);
    float percent = static_cast<float>(alpha) / UINT8_MAX;
    for (int i = 0; i < colorLength; i += 4)
    {
        EXPECT_TRUE(std::abs(wpixel[i] - percent * red) <= 1);      // 1: Floating point to integer error
        EXPECT_TRUE(std::abs(wpixel[i + 1] - percent * green) <= 1); // 1: Floating point to integer error
        EXPECT_TRUE(std::abs(wpixel[i + 2] - percent * blue) <= 1);   // 1: Floating point to integer error
        EXPECT_TRUE(wpixel[i + 3] == alpha);
    }
    std::unique_ptr<PixelMap> pixelMap3 = PixelMap::Create(opts1);
    EXPECT_TRUE(pixelMap3 != nullptr);
    void *pixelMapData3 = pixelMap3->GetWritablePixels();
    uint8_t *wpixel3 = static_cast<uint8_t *>(pixelMapData3);
    ret = pixelMap2->ConvertAlphaFormat(*pixelMap3.get(), false);
    ASSERT_EQ(ret, SUCCESS);
    for (int i = 0; i < colorLength; i += 4)
    {
        EXPECT_TRUE(std::abs(wpixel3[i] - red) <= 1);      // 1: Floating point to integer error
        EXPECT_TRUE(std::abs(wpixel3[i + 1] - green) <= 1); // 1: Floating point to integer error
        EXPECT_TRUE(std::abs(wpixel3[i + 2] - blue) <= 1);   // 1: Floating point to integer error
        EXPECT_TRUE(wpixel3[i + 3] == alpha);
    }
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest003 end";
}

/**
 * @tc.name: ConvertAlphaFormatTest004
 * @tc.desc: Covernt alpha format to premul or unpremul, format is RGB_888.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ConvertAlphaFormatTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest004 start";
    const int32_t offset = 0; //for test
    const int32_t width = 2; //for test
    const int32_t height = 2; //for test
    const uint32_t pixelByte = 4; //for test
    constexpr uint32_t colorLength = width * height * pixelByte;
    uint8_t buffer[colorLength] = {0};
    CreateBuffer(width, height, pixelByte, buffer);
    uint32_t *color = (uint32_t *)buffer;
    InitializationOptions opts1;
    InitOption(opts1, width, height, PixelFormat::RGB_888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorLength, offset, width, opts1);

    EXPECT_TRUE(pixelMap1 != nullptr);
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(opts1);
    EXPECT_TRUE(pixelMap2 != nullptr);

    uint32_t ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), true);
    ASSERT_NE(ret, SUCCESS);
    ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), false);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest004 end";
}

/**
 * @tc.name: ConvertAlphaFormatTest005
 * @tc.desc: covernt alpha format to premul or unpremul, format is ALPHA_8.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ConvertAlphaFormatTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest005 start";
    const int32_t offset = 0; //for test
    const int32_t width = 2; //for test
    const int32_t height = 2; //for test
    const uint32_t pixelByte = 4; //for test
    constexpr uint32_t colorLength = width * height * pixelByte;
    uint8_t buffer[colorLength] = {0};
    CreateBuffer(width, height, pixelByte, buffer);
    uint32_t *color = (uint32_t *)buffer;
    InitializationOptions opts1;
    InitOption(opts1, width, height, PixelFormat::ALPHA_8, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorLength, offset, width, opts1);
    EXPECT_TRUE(pixelMap1 != nullptr);
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(opts1);
    EXPECT_TRUE(pixelMap2 != nullptr);
    uint8_t *spixel = static_cast<uint8_t *>(pixelMap1->GetWritablePixels());
    uint32_t ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), true);
    ASSERT_NE(ret, SUCCESS);
    std::unique_ptr<PixelMap> pixelMap3 = PixelMap::Create(opts1);
    EXPECT_TRUE(pixelMap3 != nullptr);
    void *pixelMapData3 = pixelMap3->GetWritablePixels();
    uint8_t *wpixel3 = static_cast<uint8_t *>(pixelMapData3);
    ret = pixelMap1->ConvertAlphaFormat(*pixelMap3.get(), false);
    ASSERT_EQ(ret, SUCCESS);
    for (int i = 0; i < colorLength; i += 4)
    {
        EXPECT_TRUE(std::abs(wpixel3[i] - spixel[i]) <= 1);         // 1: Floating point to integer error
        EXPECT_TRUE(std::abs(wpixel3[i + 1] - spixel[i + 1]) <= 1); // 1: Floating point to integer error
        EXPECT_TRUE(std::abs(wpixel3[i + 2] - spixel[i + 2]) <= 1); // 1: Floating point to integer error
        EXPECT_TRUE(wpixel3[i + 3] == spixel[i + 3]);
    }
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest005 end";
}

/**
 * @tc.name: ConvertAlphaFormatTest006
 * @tc.desc: Covernt alpha format to premul or unpremul. Format is ALPHA_8, source format is BGRA_8888.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ConvertAlphaFormatTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest006 start";
    const int32_t offset = 0;
    /* for test */
    const int32_t width = 2;
    /* for test */
    const int32_t height = 2;
    /* for test */
    const uint32_t pixelByte = 4;
    constexpr uint32_t colorLength = width * height * pixelByte;
    uint8_t buffer[colorLength] = {0};
    CreateBuffer(width, height, pixelByte, buffer);
    uint32_t *color = (uint32_t *)buffer;
    InitializationOptions opts1;
    InitOption(opts1, width, height, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorLength, offset, width, opts1);

    EXPECT_TRUE(pixelMap1 != nullptr);
    InitializationOptions opts2;
    InitOption(opts2, width, height, PixelFormat::ALPHA_8, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(opts2);
    EXPECT_TRUE(pixelMap2 != nullptr);

    uint32_t ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), true);
    ASSERT_NE(ret, SUCCESS);
    ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), false);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest006 end";
}

/**
 * @tc.name: ConvertAlphaFormatTest007
 * @tc.desc: RGB_888 pixel format pixel map operation, foramt is RGBA_F16.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ConvertAlphaFormatTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest007 start";
        const int32_t offset = 0;
    /* for test */
    const int32_t width = 2;
    /* for test */
    const int32_t height = 2;
    /* for test */
    const uint32_t pixelByte = 4;
    constexpr uint32_t colorLength = width * height * pixelByte;
    uint8_t buffer[colorLength] = {0};
    CreateBuffer(width, height, pixelByte, buffer);
    uint32_t *color = (uint32_t *)buffer;
    InitializationOptions opts1;
    InitOption(opts1, width, height, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorLength, offset, width, opts1);

    EXPECT_TRUE(pixelMap1 != nullptr);
    InitializationOptions opts2;
    InitOption(opts2, width, height, PixelFormat::RGBA_F16, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(opts2);
    EXPECT_TRUE(pixelMap2 != nullptr);

    uint32_t ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), true);
    ASSERT_NE(ret, SUCCESS);
    ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), false);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest007 end";
}

/**
 * @tc.name: ConvertAlphaFormatTest008
 * @tc.desc: RGB_888 pixel format pixel map operation, image info is default.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ConvertAlphaFormatTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest008 start";
    const int32_t offset = 0;
    /* for test */
    const int32_t width = 2;
    /* for test */
    const int32_t height = 2;
    /* for test */
    const uint32_t pixelByte = 4;
    constexpr uint32_t colorLength = width * height * pixelByte;
    uint8_t buffer[colorLength] = {0};
    CreateBuffer(width, height, pixelByte, buffer);
    uint32_t *color = (uint32_t *)buffer;
    InitializationOptions opts1;
    InitOption(opts1, width, height, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorLength, offset, width, opts1);

    EXPECT_TRUE(pixelMap1 != nullptr);
    InitializationOptions opts2;
    InitOption(opts2, width, height, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(opts2);
    EXPECT_TRUE(pixelMap2 != nullptr);

    uint32_t ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), true);
    ASSERT_EQ(ret, SUCCESS);
    ret = pixelMap1->ConvertAlphaFormat(*pixelMap2.get(), false);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: ConvertAlphaFormatTest008 end";
}
}
}