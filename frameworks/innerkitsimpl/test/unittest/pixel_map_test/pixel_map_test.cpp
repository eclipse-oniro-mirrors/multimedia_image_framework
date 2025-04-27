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

#define protected public
#define private public
#include <gtest/gtest.h>
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "pixel_convert_adapter.h"
#include "securec.h"

#define IMAGE_YUV_PATH  "/data/local/tmp/image/P010.yuv"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {

constexpr int8_t ARGB_8888_BYTES = 4;
const uint8_t red = 0xFF;
const uint8_t green = 0x8F;
const uint8_t blue = 0x7F;
const uint8_t alpha = 0x7F;
constexpr uint32_t ASTC_WIDTH = 256;
constexpr uint32_t ASTC_HEIGHT = 256;
// 16 means header bytes
constexpr uint32_t HEADER_BYTES = 16;
// 4 means ASTC compression format is 4x4
constexpr uint32_t COMPRESSION_FORMAT = 4;
// 16 means ASTC per block bytes and header bytes
constexpr uint32_t PER_BLOCK_BYTES = 16;
constexpr uint32_t BLOCK_SIZE = 4;
constexpr uint8_t ASTC_PER_BLOCK_BYTES = 16;
constexpr uint8_t ASTC_MAGIC_0 = 0x13; // ASTC MAGIC ID 0x13
constexpr uint8_t ASTC_MAGIC_1 = 0xAB; // ASTC MAGIC ID 0xAB
constexpr uint8_t ASTC_MAGIC_2 = 0xA1; // ASTC MAGIC ID 0xA1
constexpr uint8_t ASTC_MAGIC_3 = 0x5C; // ASTC MAGIC ID 0x5C
constexpr uint8_t MASKBITS_FOR_8BIT = 0xFF;
constexpr uint8_t ASTC_1TH_BYTES = 8;
constexpr uint8_t ASTC_2TH_BYTES = 16;
constexpr uint8_t ASTC_BLOCK4X4_FIT_SUT_ASTC_EXAMPLE0[ASTC_PER_BLOCK_BYTES] = {
    0x43, 0x80, 0xE9, 0xE8, 0xFA, 0xFC, 0x14, 0x17, 0xFF, 0xFF, 0x81, 0x42, 0x12, 0x5A, 0xD4, 0xE9
};
constexpr uint32_t RECT_X = 1;
constexpr uint32_t RECT_Y = 1;
constexpr uint32_t SIZE_WIDTH = 2;
constexpr uint32_t SIZE_HEIGHT = 2;
constexpr uint32_t SIZE_MAX_WIDTH = 61440;
constexpr uint32_t SIZE_MAX_HEIGHT = 61440;
const static std::string EXIF_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";

struct ImageSize {
    int32_t width = 0;
    int32_t height = 0;
    float dstWidth = 0;
    float dstHeight = 0;
    const uint32_t color = 0;
    uint32_t dst = 0;
};

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

std::unique_ptr<PixelMap> ConstructPixelMap(int32_t width, int32_t height, PixelFormat format, AlphaType alphaType,
    AllocatorType type)
{
    std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = format;
    info.colorSpace = ColorSpace::SRGB;
    info.alphaType = alphaType;
    pixelMap->SetImageInfo(info);

    int32_t rowDataSize = ImageUtils::GetRowDataSizeByPixelFormat(width, format);
    if (rowDataSize <= 0) {
        return nullptr;
    }
    size_t bufferSize = rowDataSize * height;
    void* buffer = malloc(bufferSize); // Buffer's lifecycle will be held by pixelMap
    if (buffer == nullptr) {
        return nullptr;
    }
    char* ch = static_cast<char*>(buffer);
    for (unsigned int i = 0; i < bufferSize; i++) {
        *(ch++) = (char)i;
    }

    pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, type, type != AllocatorType::CUSTOM_ALLOC ? nullptr :
        [](void* addr, void* context, uint32_t size) {
            free(addr);
        });

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

std::map<PixelFormat, std::string> rgbPixelFormat = {
    { PixelFormat::ARGB_8888, "PixelFormat::ARGB_8888" },
    { PixelFormat::RGB_565,   "PixelFormat::RGB_565" },
    { PixelFormat::RGBA_8888, "PixelFormat::RGBA_8888" },
    { PixelFormat::BGRA_8888, "PixelFormat::BGRA_8888" },
    { PixelFormat::RGB_888,   "PixelFormat::RGB_888" },
    { PixelFormat::ALPHA_8,   "PixelFormat::ALPHA_8" },
    { PixelFormat::RGBA_F16,  "PixelFormat::RGBA_F16" },
    { PixelFormat::RGBA_1010102, "PixelFormat::RGBA_1010102"}
};

static bool CompareTwoPixelMap(PixelMap &pixelmap1, PixelMap &pixelmap2)
{
    ImageInfo imageInfo1, imageInfo2;
    pixelmap1.GetImageInfo(imageInfo1);
    pixelmap2.GetImageInfo(imageInfo2);
    bool flag = true;
    if (imageInfo1.size.width != imageInfo2.size.width || imageInfo1.size.height != imageInfo2.size.height) {
        GTEST_LOG_(INFO) << "PixelMap size not compared";
        flag = false;
    }
    if (imageInfo1.pixelFormat != imageInfo2.pixelFormat) {
        GTEST_LOG_(INFO) << "PixelMap pixelFormat not compared";
        flag = false;
    }
    if (imageInfo1.colorSpace != imageInfo2.colorSpace) {
        GTEST_LOG_(INFO) << "PixelMap colorSpace not compared";
        flag = false;
    }
    if (imageInfo1.alphaType != imageInfo2.alphaType) {
        GTEST_LOG_(INFO) << "PixelMap alphaType not compared";
        flag = false;
    }
    if (imageInfo1.baseDensity != imageInfo2.baseDensity) {
        GTEST_LOG_(INFO) << "PixelMap baseDensity not compared";
        flag = false;
    }
    if (imageInfo1.encodedFormat != imageInfo2.encodedFormat) {
        GTEST_LOG_(INFO) << "PixelMap encodedFormat not compared";
        flag = false;
    }
    if (pixelmap1.GetAllocatorType() != pixelmap2.GetAllocatorType()) {
        GTEST_LOG_(INFO) << "PixelMap GetAllocatorType not compared";
        flag = false;
    }
    if (pixelmap1.GetByteCount() != pixelmap2.GetByteCount()) {
        GTEST_LOG_(INFO) << "PixelMap GetByteCount not compared";
        flag = false;
    }
    if (pixelmap1.GetRowBytes() != pixelmap2.GetRowBytes()) {
        GTEST_LOG_(INFO) << "PixelMap GetRowBytes not compared";
        flag = false;
    }
    if (pixelmap1.GetRowStride() != pixelmap2.GetRowStride()) {
        GTEST_LOG_(INFO) << "PixelMap GetRowStride not compared";
        flag = false;
    }
    return flag;
}

static bool ConstructAstcBody(uint8_t* astcBody, size_t& blockNums, const uint8_t* astcBlockPart)
{
    if (astcBody == nullptr || astcBlockPart == nullptr) {
        return false;
    }
 
    uint8_t* astcBuf = astcBody;
    for (size_t blockIdx = 0; blockIdx < blockNums; blockIdx++) {
        if (memcpy_s(astcBuf, ASTC_PER_BLOCK_BYTES, astcBlockPart, ASTC_PER_BLOCK_BYTES) != 0) {
            return false;
        }
        astcBuf += ASTC_PER_BLOCK_BYTES;
    }
    return true;
}
 
static bool GenAstcHeader(uint8_t* header, size_t blockSize, size_t width, size_t height)
{
    if (header == nullptr) {
        return false;
    }
    uint8_t* tmp = header;
    *tmp++ = ASTC_MAGIC_0;
    *tmp++ = ASTC_MAGIC_1;
    *tmp++ = ASTC_MAGIC_2;
    *tmp++ = ASTC_MAGIC_3;
    *tmp++ = static_cast<uint8_t>(blockSize);
    *tmp++ = static_cast<uint8_t>(blockSize);
    // 1 means 3D block size
    *tmp++ = 1;
    *tmp++ = width & MASKBITS_FOR_8BIT;
    *tmp++ = (width >> ASTC_1TH_BYTES) & MASKBITS_FOR_8BIT;
    *tmp++ = (width >> ASTC_2TH_BYTES) & MASKBITS_FOR_8BIT;
    *tmp++ = height & MASKBITS_FOR_8BIT;
    *tmp++ = (height >> ASTC_1TH_BYTES) & MASKBITS_FOR_8BIT;
    *tmp++ = (height >> ASTC_2TH_BYTES) & MASKBITS_FOR_8BIT;
    // astc support 3D, for 2D,the 3D size is 1
    *tmp++ = 1;
    *tmp++ = 0;
    *tmp++ = 0;
    return true;
}
 
static bool ConstructPixelAstc(int32_t width, int32_t height, std::unique_ptr<Media::PixelMap>& pixelMap)
{
    SourceOptions opts;
    size_t blockNum = ((ASTC_WIDTH + COMPRESSION_FORMAT - 1) / COMPRESSION_FORMAT) *
        ((height + COMPRESSION_FORMAT - 1) / COMPRESSION_FORMAT);
    size_t size = blockNum * PER_BLOCK_BYTES + HEADER_BYTES;
    // malloc data here
    uint8_t* data = (uint8_t*)malloc(size);

    if (!GenAstcHeader(data, BLOCK_SIZE, width, height)) {
        GTEST_LOG_(ERROR) << "ConstructPixelAstc GenAstcHeader failed\n";

        return false;
    }
    if (!ConstructAstcBody(data + HEADER_BYTES, blockNum, ASTC_BLOCK4X4_FIT_SUT_ASTC_EXAMPLE0)) {
        GTEST_LOG_(ERROR) << "ConstructAstcBody ConstructAstcBody failed\n";
        return false;
    }
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (errorCode != SUCCESS || !imageSource) {
        return false;
    }
    DecodeOptions decodeOpts;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != SUCCESS) {
        return false;
    }
    return true;
}

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

static bool ReadFile(void *chOrg, std::string path, int32_t totalSize, int32_t srcNum)
{
    FILE* const fileOrg = fopen(path.c_str(), "rb");
    if (fileOrg == nullptr) {
        GTEST_LOG_(INFO) << "Can not open" << path.c_str();
        return false;
    }
    if (srcNum == 0) {
        size_t bytesOrg = fread(chOrg, sizeof(uint8_t), static_cast<size_t>(totalSize), fileOrg);
        if (bytesOrg < static_cast<size_t>(totalSize)) {
            GTEST_LOG_(INFO) << "Read fail";
            return false;
        }
    } else {
        size_t bytesOrg = fread(chOrg, sizeof(uint16_t), static_cast<size_t>(totalSize), fileOrg);
        if (bytesOrg < static_cast<size_t>(totalSize)) {
            GTEST_LOG_(INFO) << "Read fail" << bytesOrg << "totalsize" << totalSize;
            return false;
        }
    }
    return true;
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
    delete dst1;

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
    delete dst2;

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
    delete dst1;

    // 0 means buffferSize
    uint64_t bufferSize2 = 0;
    uint8_t *dst2 = new uint8_t(0);
    EXPECT_TRUE(dst2 != nullptr);
    ret = pixelMap1->ReadPixels(bufferSize2, offset1, stride1, rect1, dst2);
    EXPECT_TRUE(ret != SUCCESS);
    delete dst2;

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
    delete dst3;

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
    delete dst4;

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
    delete dst1;

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
    delete dst1;

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

    // 96 means buffferSize
    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    // 500 means offset
    uint32_t offset1 = 500;
    // 8 means stride
    uint32_t stride1 = 8;
    Rect rect1;
    // 0, 0, 1, 2 means rect
    rect1.left = 0;
    rect1.top = 0;
    rect1.height = 1;
    rect1.width = 2;
    auto ret = pixelMap1->ReadPixels(bufferSize1, offset1, stride1, rect1, dst1);
    EXPECT_TRUE(ret != SUCCESS);
    delete dst1;

    std::unique_ptr<PixelMap> pixelMap2 = std::make_unique<PixelMap>();
    ImageInfo info;
    // 200, 300 means size
    info.size.width = 200;
    info.size.height = 300;
    info.pixelFormat = PixelFormat::RGBA_F16;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap2->SetImageInfo(info);
    EXPECT_TRUE(pixelMap2 != nullptr);

    // 96 means buffferSize
    uint64_t bufferSize2 = 96;
    uint8_t *dst2 = new uint8_t(0);
    uint32_t offset2 = 0;
    // 8 means stride
    uint32_t stride2 = 8;
    Rect rect2;
    // 0, 0, 1, 2 means rect
    rect2.left = 0;
    rect2.top = 0;
    rect2.height = 1;
    rect2.width = 2;
    ret = pixelMap2->ReadPixels(bufferSize2, offset2, stride2, rect2, dst2);
    EXPECT_TRUE(ret != SUCCESS);
    delete dst2;

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
    // 1, 1 means position
    position.x = 1;
    position.y = 1;
    uint32_t dst = 0;
    auto ret = pixelMap1->ReadPixel(position, dst);
    EXPECT_TRUE(ret == SUCCESS);

    Position position1;
    // -1, 1 means position
    position1.x = -1;
    position1.y = 1;
    ret = pixelMap1->ReadPixel(position1, dst);
    EXPECT_TRUE(ret != SUCCESS);

    Position position2;
    // 1, -1 means position
    position2.x = 1;
    position2.y = -1;
    ret = pixelMap1->ReadPixel(position2, dst);
    EXPECT_TRUE(ret != SUCCESS);

    Position position3;
    // 300, 1 means position
    position3.x = 300;
    position3.y = 1;
    ret = pixelMap1->ReadPixel(position3, dst);
    EXPECT_TRUE(ret != SUCCESS);

    Position position4;
    // 1, 400 means position
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
    // 6, 6 means size
    size1.width = 6;
    size1.height = 6;
    PixelFormat pixelFormat = PixelFormat::UNKNOWN;
    auto ret = pixelMap1->ResetConfig(size1, pixelFormat);
    EXPECT_TRUE(ret != SUCCESS);

    Size size2;
    // 1, 1 means size
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
    // 3, 3 means size
    auto pixelMap1 = ConstructPixmap(3, 3, PixelFormat::ALPHA_8, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap1 != nullptr);
    Size size1;
    // 6, 6 means size
    size1.width = 6;
    size1.height = 6;
    PixelFormat pixelFormat = PixelFormat::UNKNOWN;
    auto ret = pixelMap1->ResetConfig(size1, pixelFormat);
    EXPECT_TRUE(ret != SUCCESS);

    Size size2;
    // 1, 1 means size
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
    // 3, 3 means size
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
    // 200, 300 means size
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    EXPECT_TRUE(pixelMap != nullptr);

    Position position;
    // 0, 0 means position
    position.x = 0;
    position.y = 0;
    // 9 means color buffer
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
    // 200, 300 means size
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    EXPECT_TRUE(pixelMap != nullptr);

    // 96 means bufferSize
    uint64_t bufferSize1 = 96;
    uint8_t *dst1 = new uint8_t(0);
    auto ret = pixelMap->WritePixels(dst1, bufferSize1);
    EXPECT_TRUE(ret);
    delete dst1;

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
    // 200, 300 means size
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    EXPECT_TRUE(pixelMap != nullptr);

    // 1 means color buffer
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
    // 200, 300 means size
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
    // 0.f, 2.f, 0.1f means alpha
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
    // 200, 300 means size
    imageInfo.size.width = 200;
    imageInfo.size.height = 300;
    imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    imageInfo.colorSpace = ColorSpace::SRGB;
    pixelMap->SetImageInfo(imageInfo);
    // 200 means rowDataSize
    int32_t rowDataSize = 200;
    // 300 means height
    uint32_t bufferSize = rowDataSize * 300;
    void *buffer = malloc(bufferSize);
    char *ch = static_cast<char *>(buffer);
    for (unsigned int i = 0; i < bufferSize; i++) {
        *(ch++) = (char)i;
    }
    // 10 means contextSize
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
    // 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 means buffer
    // 8 means color length
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    uint32_t colorlength = sizeof(color) / sizeof(color[0]);
    EXPECT_TRUE(colorlength == 8);
    // -1 means offset
    const int32_t offset = -1;
    InitializationOptions opts;
    // 2, 3 means size
    opts.size.width = 3;
    opts.size.height = 2;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = opts.size.width;
    // 1 means width
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
    PixelMap pixelMap;
    ImageInfo inInfo;
    inInfo.size.width = 1;
    inInfo.size.height = 2;
    inInfo.pixelFormat = PixelFormat::RGBA_8888;
    inInfo.colorSpace = ColorSpace::SRGB;
    inInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    pixelMap.SetImageInfo(inInfo);
    Parcel parcel;
    pixelMap.WriteImageInfo(parcel);
    ImageInfo outInfo;
    bool ret = pixelMap.ReadImageInfo(parcel, outInfo);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(outInfo.size.width, 1);
    ASSERT_EQ(outInfo.size.height, 2);
    ASSERT_EQ(outInfo.pixelFormat, PixelFormat::RGBA_8888);
    ASSERT_EQ(outInfo.colorSpace, ColorSpace::SRGB);
    ASSERT_EQ(outInfo.alphaType, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
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

/**
 * @tc.name: VersionIdTest001
 * @tc.desc: test pixelmap verisonId get&set interface
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, VersionIdTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: VersionIdTest001 start";
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
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(color, colorLength, offset, width, opts1);

    EXPECT_TRUE(pixelMap != nullptr);
    uint32_t versionId = pixelMap->GetVersionId();
    // 1 means the pixelmap's initialized versionId
    ASSERT_EQ(versionId, 1);
    pixelMap->AddVersionId();
    versionId = pixelMap->GetVersionId();
    // 2 used to test add func
    ASSERT_EQ(versionId, 2);
    // 10 used to test set func
    pixelMap->SetVersionId(10);
    versionId = pixelMap->GetVersionId();
    ASSERT_EQ(versionId, 10);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: VersionIdTest001 end";
}

/**
 * @tc.name: SetMemoryNameTest001
 * @tc.desc: test pixelmap setname
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, SetMemoryNameTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetMemoryNameTest001 start";
    const int32_t offset = 0;
    /* for test */
    const int32_t width = 512;
    /* for test */
    const int32_t height = 512;
    /* for test */
    const uint32_t pixelByte = 4;
    constexpr uint32_t colorLength = width * height * pixelByte;
    uint8_t buffer[colorLength] = {0};
    CreateBuffer(width, height, pixelByte, buffer);
    uint32_t *color = (uint32_t *)buffer;
    InitializationOptions opts1;
    InitOption(opts1, width, height, PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL);
    opts1.useDMA = true;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(color, colorLength, offset, width, opts1);
    EXPECT_TRUE(pixelMap != nullptr);

    uint32_t ret = pixelMap->SetMemoryName("testname");
    EXPECT_TRUE(ret != ERR_MEMORY_NOT_SUPPORT);
    EXPECT_TRUE(ret == SUCCESS);

    std::string longName(50, '1');
    ret = pixelMap->SetMemoryName(longName);
    EXPECT_TRUE(ret != ERR_MEMORY_NOT_SUPPORT);
    EXPECT_TRUE(ret == COMMON_ERR_INVALID_PARAMETER);

    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetMemoryNameTest001 end";
}

/**
 * @tc.name: SetMemoryNameTest002
 * @tc.desc: Verify SetMemoryName returns error when memory type is not supported or context is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, SetMemoryNameTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetMemoryNameTest002 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::BGRA_8888,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::HEAP_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    uint32_t ret = pixelMap->SetMemoryName("testname");
    EXPECT_EQ(ret, ERR_MEMORY_NOT_SUPPORT);
    pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    pixelMap->context_ = nullptr;
    ret = pixelMap->SetMemoryName("testname");
    EXPECT_EQ(ret, ERR_MEMORY_NOT_SUPPORT);
    GTEST_LOG_(INFO) << "ImagePixelMapTest: SetMemoryNameTest002 end";
}

/**
 * @tc.name: ReadARGBPixelsTest001
 * @tc.desc: Test ReadARGBPixels with valid inputs
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ReadARGBPixelsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ReadARGBPixelsTest001 start";

    auto pixelMap = ConstructPixelMap(1, 1, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap != nullptr);
    size_t dataSize = ARGB_8888_BYTES;
    uint8_t data[ARGB_8888_BYTES];
    uint32_t ret = pixelMap->ReadARGBPixels(dataSize, data);
    EXPECT_EQ(ret, SUCCESS);
    ASSERT_EQ(data[0], 3);
    ASSERT_EQ(data[1], 2);
    ASSERT_EQ(data[2], 1);
    ASSERT_EQ(data[3], 0);

    GTEST_LOG_(INFO) << "PixelMapTest: ReadARGBPixelsTest001 end";
}

/**
 * @tc.name: ReadARGBPixelsTest002
 * @tc.desc: Test ReadARGBPixels with invalid inputs
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ReadARGBPixelsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ReadARGBPixelsTest002 start";

    auto pixelMap = ConstructPixelMap(1, 1, PixelFormat::ALPHA_8, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap != nullptr);
    size_t dataSize = ARGB_8888_BYTES;
    uint8_t data[ARGB_8888_BYTES];
    uint32_t ret = pixelMap->ReadARGBPixels(dataSize, data);
    EXPECT_EQ(ret, ERR_IMAGE_COLOR_CONVERT);

    GTEST_LOG_(INFO) << "PixelMapTest: ReadARGBPixelsTest002 end";
}

/**
 * @tc.name: ReadARGBPixelsTest003
 * @tc.desc: Test ReadARGBPixels with invalid inputs
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ReadARGBPixelsTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ReadARGBPixelsTest003 start";

    auto pixelMap = ConstructPixelMap(1, 1, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap != nullptr);
    size_t dataSize = 1;
    uint8_t data[1];
    uint32_t ret = pixelMap->ReadARGBPixels(dataSize, data);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);

    GTEST_LOG_(INFO) << "PixelMapTest: ReadARGBPixelsTest003 end";
}

/**
 * @tc.name: PixelMapCreateTest011
 * @tc.desc: Create PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCreateTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest011 start";
    ImageSize imageSize = {1920, 1080, 0, 0, 0, 0}; // 1920: width 1080: height
    int32_t ySize = imageSize.width * imageSize.height;
    int32_t uvSize = ((imageSize.width + 1) / 2) * ((imageSize.height + 1) / 2); // 2: Addapting to size
    const size_t totalSize = (ySize + 2 * uvSize);
    uint16_t*  const chOrg = new uint16_t[totalSize];
    bool result = ReadFile(chOrg, IMAGE_YUV_PATH, totalSize, 1);
    ASSERT_EQ(result, true);
    const uint32_t dataLength = totalSize * 2; // 2: Addapting to size
    uint32_t *data = reinterpret_cast<uint32_t *>(chOrg);
    InitializationOptions opts;
    opts.srcPixelFormat = PixelFormat::YCBCR_P010;
    opts.pixelFormat = PixelFormat::YCBCR_P010;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.size.width = imageSize.width;
    opts.size.height = imageSize.height;
    opts.useDMA = true;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    EXPECT_TRUE(pixelMap != nullptr);
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCreateTest011 end";
}

/**
 * @tc.name: MarshallingUnmarshallingCustomAllocPixelMapTest
 * @tc.desc: Test marshalling and unmarshalling PixelMap with CUSTOM_ALLOC allocator type
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, MarshallingUnmarshallingCustomAllocPixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: MarshallingUnmarshallingCustomAllocPixelMapTest start";

    auto pixelMap = ConstructPixelMap(1, 1, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::CUSTOM_ALLOC);
    EXPECT_TRUE(pixelMap != nullptr);
    Parcel parcel;
    auto ret = pixelMap->Marshalling(parcel);
    EXPECT_TRUE(ret);
    PixelMap* newPixelMap = PixelMap::Unmarshalling(parcel);
    EXPECT_EQ(newPixelMap->GetAllocatorType(), AllocatorType::HEAP_ALLOC);

    GTEST_LOG_(INFO) << "PixelMapTest: MarshallingUnmarshallingCustomAllocPixelMapTest end";
}

/**
 * @tc.name: MarshallingUnmarshallingDefaultAllocPixelMapTest
 * @tc.desc: Test marshalling and unmarshalling PixelMap with DEFAULT allocator type
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, MarshallingUnmarshallingDefaultAllocPixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: MarshallingUnmarshallingDefaultAllocPixelMapTest start";

    auto pixelMap = ConstructPixelMap(1, 1, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::DEFAULT);
    EXPECT_TRUE(pixelMap != nullptr);
    Parcel parcel;
    auto ret = pixelMap->Marshalling(parcel);
    EXPECT_TRUE(ret);
    PixelMap* newPixelMap = PixelMap::Unmarshalling(parcel);
    EXPECT_EQ(newPixelMap->GetAllocatorType(), AllocatorType::HEAP_ALLOC);

    GTEST_LOG_(INFO) << "PixelMapTest: MarshallingUnmarshallingDefaultAllocPixelMapTest end";
}

/**
 * @tc.name: GetByteCountTest
 * @tc.desc: Test get byte count and get allocation byte count
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, GetByteCountTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: GetByteCountTest start";

    auto pixelMap = ConstructPixelMap(1, 1, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(pixelMap != nullptr);
    int32_t byteCount = pixelMap->GetByteCount();
    uint32_t allocByteCount = pixelMap->GetAllocationByteCount();
    EXPECT_TRUE(byteCount == ImageUtils::GetPixelBytes(PixelFormat::BGRA_8888) &&
        allocByteCount >= static_cast<uint32_t>(byteCount));

    GTEST_LOG_(INFO) << "PixelMapTest: GetByteCountTest end";
}

/**
 * @tc.name: PixelMapCloneTest001
 * @tc.desc: Clone PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapCloneTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCloneTest001 start";

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
    for (iter = rgbPixelFormat.begin(); iter != rgbPixelFormat.end() ; ++iter) {
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
        int32_t errorCode = 0;
        std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, width, options);
        if (pixelMap1 != nullptr) {
            std::unique_ptr<PixelMap> pixelMap_clone = pixelMap1->Clone(errorCode);
            EXPECT_NE(pixelMap_clone, nullptr);
            EXPECT_EQ(errorCode, 0);
            EXPECT_EQ(true, CompareTwoPixelMap(*(pixelMap1.get()), *(pixelMap_clone.get())));
        }
    }
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapCloneTest001 end";
}

/**
 * @tc.name: UnmodifiablePixelMapTest
 * @tc.desc: Test unmodifiable PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, UnmodifiablePixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: UnmodifiablePixelMapTest start";

    auto pixelMap = ConstructPixelMap(2, 2, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::HEAP_ALLOC);
    uint32_t* data = static_cast<uint32_t*>(pixelMap->GetWritablePixels());
    data[0] = 0xFFFFFFFF;
    data[1] = 0xAAAAAAAA;
    data[2] = 0x66666666;
    data[3] = 0x00000000;

    pixelMap->SetModifiable(false);
    EXPECT_FALSE(pixelMap->IsModifiable());

    pixelMap->scale(10, 10);
    EXPECT_EQ(data, pixelMap->GetWritablePixels());
    EXPECT_EQ(pixelMap->GetWidth(), 2);
    EXPECT_EQ(pixelMap->GetHeight(), 2);

    Rect rect = {0, 0, 1, 1};
    pixelMap->crop(rect);
    EXPECT_EQ(data, pixelMap->GetWritablePixels());
    EXPECT_EQ(pixelMap->GetWidth(), 2);
    EXPECT_EQ(pixelMap->GetHeight(), 2);

    pixelMap->translate(2, 2);
    EXPECT_EQ(data, pixelMap->GetWritablePixels());
    EXPECT_EQ(pixelMap->GetWidth(), 2);
    EXPECT_EQ(pixelMap->GetHeight(), 2);

    pixelMap->rotate(90);
    EXPECT_EQ(data, pixelMap->GetWritablePixels());
    EXPECT_EQ(data[0], 0xFFFFFFFF);
    EXPECT_EQ(data[1], 0xAAAAAAAA);
    EXPECT_EQ(data[2], 0x66666666);
    EXPECT_EQ(data[3], 0x00000000);

    pixelMap->flip(true, false);
    EXPECT_EQ(data, pixelMap->GetWritablePixels());
    EXPECT_EQ(data[0], 0xFFFFFFFF);
    EXPECT_EQ(data[1], 0xAAAAAAAA);
    EXPECT_EQ(data[2], 0x66666666);
    EXPECT_EQ(data[3], 0x00000000);

    pixelMap->SetAlpha(0.5);
    EXPECT_EQ(data, pixelMap->GetWritablePixels());
    EXPECT_EQ(data[0], 0xFFFFFFFF);
    EXPECT_EQ(data[1], 0xAAAAAAAA);
    EXPECT_EQ(data[2], 0x66666666);
    EXPECT_EQ(data[3], 0x00000000);

    Position pos = {0, 0};
    uint32_t ret = pixelMap->WritePixel(pos, 0xCCCCCCCC);
    EXPECT_NE(ret, SUCCESS);
    EXPECT_EQ(data[0], 0xFFFFFFFF);

    GTEST_LOG_(INFO) << "PixelMapTest: UnmodifiablePixelMapTest end";
}

/**
 * @tc.name: CreatePixelMapTest001
 * @tc.desc: Verify NV21 format PixelMap can be created successfully with DMA enabled.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreatePixelMapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreatePixelMapTest001 start";
    InitializationOptions opts;
    opts.size.width = SIZE_WIDTH;
    opts.size.height = SIZE_HEIGHT;
    opts.pixelFormat = PixelFormat::NV21;
    opts.useDMA = true;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    EXPECT_NE(pixelMap, nullptr);
    GTEST_LOG_(INFO) << "PixelMapTest: CreatePixelMapTest001 end";
}

/**
 * @tc.name: CreatePixelMapTest
 * @tc.desc: Verify PixelMap creation fails with invalid source rect and empty initialization options.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreatePixelMapTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreatePixelMapTest002 start";
    auto srcPixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::NV21,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::DMA_ALLOC);
    ASSERT_NE(srcPixelMap, nullptr);
    const InitializationOptions opts;
    const Rect srcRect{RECT_X, RECT_Y, SIZE_WIDTH, SIZE_HEIGHT};
    int32_t errorCode;
    auto pixelMap = PixelMap::Create(*(srcPixelMap.get()), srcRect, opts, errorCode);
    EXPECT_EQ(pixelMap, nullptr);
    GTEST_LOG_(INFO) << "PixelMapTest: CreatePixelMapTest002 end";
}

/**
 * @tc.name: CopyPixelMapTest001
 * @tc.desc: Verify PixelMap copy function with different formats and test null data handling.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CopyPixelMapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CopyPixelMapTest001 start";
    auto srcPixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::NV21,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::DMA_ALLOC);
    ASSERT_NE(srcPixelMap, nullptr);
    auto dstPixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::RGBA_8888,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::DMA_ALLOC);
    ASSERT_NE(dstPixelMap, nullptr);
    bool ret = PixelMap::CopyPixelMap(*(srcPixelMap.get()), *(dstPixelMap.get()));
    EXPECT_TRUE(ret);
    srcPixelMap->data_ = nullptr;
    ret = PixelMap::CopyPixelMap(*(srcPixelMap.get()), *(dstPixelMap.get()));
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "PixelMapTest: CopyPixelMapTest001 end";
}

/**
 * @tc.name: CloneTest001
 * @tc.desc: Verify PixelMap clone functionality with different formats and test null data handling.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CloneTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CloneTest001 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::NV21, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    int32_t errorCode = 0;
    auto ret = pixelMap->Clone(errorCode);
    EXPECT_EQ(ret, nullptr);
    auto srcPixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::RGBA_8888,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::DMA_ALLOC);
    srcPixelMap->data_ = nullptr;
    ret = srcPixelMap->Clone(errorCode);
    EXPECT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PixelMapTest: CloneTest001 end";
}

/**
 * @tc.name: IsSameSizeTest001
 * @tc.desc: Verify PixelMap size comparison function with identical dimensions.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, IsSameSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: IsSameSizeTest001 start";
    Size srcSize{SIZE_WIDTH, SIZE_HEIGHT};
    Size dstSize{SIZE_WIDTH, SIZE_HEIGHT};
    EXPECT_TRUE(PixelMap::IsSameSize(srcSize, dstSize));
    GTEST_LOG_(INFO) << "PixelMapTest: IsSameSizeTest001 end";
}

/**
 * @tc.name: SetImageInfoTest001
 * @tc.desc: Verify PixelMap SetImageInfo function with abnormal pixel bytes case.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, SetImageInfoTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: SetImageInfoTest001 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::NV21, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    pixelMap->pixelBytes_ = 0;
    ImageInfo info;
    int32_t ret = pixelMap->SetImageInfo(info, false);
    EXPECT_EQ(ret, ERR_IMAGE_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "PixelMapTest: SetImageInfoTest001 end";
}

/**
 * @tc.name: SetImageInfoTest002
 * @tc.desc: Verify PixelMap SetImageInfo function with oversized image dimensions case.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, SetImageInfoTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: SetImageInfoTest002 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::NV21, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::HEAP_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    ImageInfo info;
    pixelMap->rowDataSize_ = SIZE_MAX_WIDTH;
    info.size.width = SIZE_WIDTH;
    info.size.height = SIZE_MAX_HEIGHT;
    int32_t ret = pixelMap->SetImageInfo(info, false);
    EXPECT_EQ(ret, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "PixelMapTest: SetImageInfoTest002 end";
}

/**
 * @tc.name: GetPixelTest001
 * @tc.desc: Verify GetPixel function with ASTC format and invalid coordinates.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, GetPixelTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: GetPixelTest001 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::RGBA_8888,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    pixelMap->isAstc_ = true;
    auto ret = pixelMap->GetPixel(RECT_X, RECT_Y);
    EXPECT_EQ(ret, nullptr);
    ret = pixelMap->GetPixel(-1, -1);
    EXPECT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PixelMapTest: GetPixelTest001 end";
}

/**
 * @tc.name: GetARGB32ColorTest001
 * @tc.desc: Verify GetARGB32Color function with null color processor and invalid coordinates.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, GetARGB32ColorTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: GetARGB32ColorTest001 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::RGBA_8888,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    pixelMap->colorProc_ = nullptr;
    uint32_t color = 1;
    bool ret = pixelMap->GetARGB32Color(RECT_X, RECT_Y, color);
    EXPECT_FALSE(ret);
    ret = pixelMap->GetARGB32Color(-1, -1, color);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "PixelMapTest: GetARGB32ColorTest001 end";
}

/**
 * @tc.name: ModifyImagePropertyTest001
 * @tc.desc: Verify ModifyImageProperty with empty key/value and null exif metadata.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ModifyImagePropertyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ModifyImagePropertyTest001 start";
    SourceOptions opts;
    uint32_t errorCode = 0;
    auto imageSource = ImageSource::CreateImageSource(EXIF_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions dopts;
    auto pixelMap = imageSource->CreatePixelMapEx(0, dopts, errorCode);
    ASSERT_NE(pixelMap, nullptr);
    uint32_t ret = pixelMap->ModifyImageProperty("", "");
    EXPECT_EQ(ret, ERR_MEDIA_VALUE_INVALID);
    pixelMap->exifMetadata_ = nullptr;
    ret = pixelMap->ModifyImageProperty("", "");
    EXPECT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "PixelMapTest: ModifyImagePropertyTest001 end";
}

/**
 * @tc.name: GetImagePropertyIntTest001
 * @tc.desc: Verify GetImagePropertyInt with valid and empty EXIF keys.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, GetImagePropertyIntTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: GetImagePropertyIntTest001 start";
    SourceOptions opts;
    uint32_t errorCode = 0;
    auto imageSource = ImageSource::CreateImageSource(EXIF_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions dopts;
    auto pixelMap = imageSource->CreatePixelMapEx(0, dopts, errorCode);
    ASSERT_NE(pixelMap, nullptr);
    std::string key = "GPSLatitude";
    int32_t val = 0;
    uint32_t ret = pixelMap->GetImagePropertyInt(key, val);
    EXPECT_EQ(ret, SUCCESS);
    key = "";
    ret = pixelMap->GetImagePropertyInt(key, val);
    EXPECT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "PixelMapTest: GetImagePropertyIntTest001 end";
}

/**
 * @tc.name: ALPHA8ToARGBTestTest001
 * @tc.desc: Verify ALPHA8ToARGB conversion with null/invalid input/output and correct conversion behavior.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ALPHA8ToARGBTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ALPHA8ToARGBTest001 start";
    uint8_t inArray[] = {0x43, 0x80, 0xE9, 0xE8, 0xFA};
    uint8_t *in = nullptr;
    uint32_t outArray[] = {0x43, 0x80, 0xE9, 0xE8};
    uint32_t *out = outArray;
    EXPECT_FALSE(PixelMap::ALPHA8ToARGB(in, 0, out, sizeof(outArray) / sizeof(outArray[0])));
    in = inArray;
    out = nullptr;
    EXPECT_FALSE(PixelMap::ALPHA8ToARGB(in, sizeof(inArray) / sizeof(inArray[0]), out, 0));
    in = inArray;
    out = outArray;
    EXPECT_FALSE(PixelMap::ALPHA8ToARGB(in, sizeof(inArray) / sizeof(inArray[0]), out,
        sizeof(outArray) / sizeof(outArray[0])));
    GTEST_LOG_(INFO) << "PixelMapTest: ALPHA8ToARGBTest001 end";
}

/**
 * @tc.name: ALPHA8ToARGBTestTest001
 * @tc.desc: Verify RGB565 to ARGB conversion with null/invalid inputs and correct buffer size handling.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, RGB565ToARGBTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: RGB565ToARGBTest001 start";
    uint8_t inArray[] = {0x43, 0x80, 0xE9, 0xE8, 0xFA};
    uint8_t *in = nullptr;
    uint32_t outArray[] = {0x43, 0x80, 0xE9, 0xE8};
    uint32_t *out = outArray;
    EXPECT_FALSE(PixelMap::RGB565ToARGB(in, 0, out, sizeof(outArray) / sizeof(outArray[0])));
    in = inArray;
    out = nullptr;
    EXPECT_FALSE(PixelMap::RGB565ToARGB(in, sizeof(inArray) / sizeof(inArray[0]), out, 0));
    in = nullptr;
    out = nullptr;
    EXPECT_FALSE(PixelMap::RGB565ToARGB(in, 0, out, 0));
    in = inArray;
    out = outArray;
    EXPECT_FALSE(PixelMap::RGB565ToARGB(in, sizeof(inArray) / sizeof(inArray[0]), out,
        sizeof(outArray) / sizeof(outArray[0])));
    GTEST_LOG_(INFO) << "PixelMapTest: RGB565ToARGBTest001 end";
}

/**
 * @tc.name: ALPHA8ToARGBTestTest001
 * @tc.desc: Verify ARGB8888 to ARGB conversion with invalid parameters and buffer handling.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ARGB8888ToARGBTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ARGB8888ToARGBTest001 start";
    uint8_t inArray[] = {0x43, 0x80, 0xE9, 0xE8, 0xFA};
    uint8_t *in = nullptr;
    uint32_t outArray[] = {0x43, 0x80, 0xE9, 0xE8};
    uint32_t *out = outArray;
    EXPECT_FALSE(PixelMap::ARGB8888ToARGB(in, 0, out, sizeof(outArray) / sizeof(outArray[0])));
    in = inArray;
    out = nullptr;
    EXPECT_FALSE(PixelMap::ARGB8888ToARGB(in, sizeof(inArray) / sizeof(inArray[0]), out, 0));
    in = nullptr;
    out = nullptr;
    EXPECT_FALSE(PixelMap::ARGB8888ToARGB(in, 0, out, 0));
    in = inArray;
    out = outArray;
    EXPECT_FALSE(PixelMap::ARGB8888ToARGB(in, sizeof(inArray) / sizeof(inArray[0]), out,
        sizeof(outArray) / sizeof(outArray[0])));
    GTEST_LOG_(INFO) << "PixelMapTest: ARGB8888ToARGBTest001 end";
}

/**
 * @tc.name: RGBA8888ToARGBTest001
 * @tc.desc: Verify RGBA8888 to ARGB format conversion with invalid inputs and buffer size checks.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, RGBA8888ToARGBTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: RGBA8888ToARGBTest001 start";
    uint8_t inArray[] = {0x43, 0x80, 0xE9, 0xE8, 0xFA};
    uint8_t *in = nullptr;
    uint32_t outArray[] = {0x43, 0x80, 0xE9, 0xE8};
    uint32_t *out = outArray;
    EXPECT_FALSE(PixelMap::RGBA8888ToARGB(in, 0, out, sizeof(outArray) / sizeof(outArray[0])));
    in = inArray;
    out = nullptr;
    EXPECT_FALSE(PixelMap::RGBA8888ToARGB(in, sizeof(inArray) / sizeof(inArray[0]), out, 0));
    in = nullptr;
    out = nullptr;
    EXPECT_FALSE(PixelMap::RGBA8888ToARGB(in, 0, out, 0));
    in = inArray;
    out = outArray;
    EXPECT_FALSE(PixelMap::RGBA8888ToARGB(in, sizeof(inArray) / sizeof(inArray[0]), out,
        sizeof(outArray) / sizeof(outArray[0])));
    GTEST_LOG_(INFO) << "PixelMapTest: RGBA8888ToARGBTest001 end";
}

/**
 * @tc.name: RGB888ToARGBTest001
 * @tc.desc: Test RGB888 to ARGB conversion with null/invalid inputs and validate buffer size checks.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, RGB888ToARGBTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: RGB888ToARGBTest001 start";
    uint8_t inArray[] = {0x43, 0x80, 0xE9, 0xE8, 0xFA};
    uint8_t *in = nullptr;
    uint32_t outArray[] = {0x43, 0x80, 0xE9, 0xE8};
    uint32_t *out = outArray;
    EXPECT_FALSE(PixelMap::RGB888ToARGB(in, 0, out, sizeof(outArray) / sizeof(outArray[0])));
    in = inArray;
    out = nullptr;
    EXPECT_FALSE(PixelMap::RGB888ToARGB(in, sizeof(inArray) / sizeof(inArray[0]), out, 0));
    in = nullptr;
    out = nullptr;
    EXPECT_FALSE(PixelMap::RGB888ToARGB(in, 0, out, 0));
    in = inArray;
    out = outArray;
    EXPECT_FALSE(PixelMap::RGB888ToARGB(in, sizeof(inArray) / sizeof(inArray[0]), out,
        sizeof(outArray) / sizeof(outArray[0])));
    GTEST_LOG_(INFO) << "PixelMapTest: RGB888ToARGBTest001 end";
}

/**
 * @tc.name: GetByteCountTest001
 * @tc.desc: Verify GetByteCount returns 0 when pixel map is ASTC compressed format.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, GetByteCountTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: GetByteCountTest001 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::RGBA_8888,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::SHARE_MEM_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    pixelMap->isAstc_ = true;
    EXPECT_EQ(pixelMap->GetByteCount(), 0);
    GTEST_LOG_(INFO) << "PixelMapTest: GetByteCountTest001 end";
}

/**
 * @tc.name: GetAllocationByteCountTest001
 * @tc.desc: Verify GetAllocationByteCount returns 0 when context is null or DMA allocated.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, GetAllocationByteCountTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: GetAllocationByteCountTest001 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::RGBA_8888,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    uint32_t ret = pixelMap->GetAllocationByteCount();
    EXPECT_EQ(ret, 0);
    pixelMap->context_ = nullptr;
    ret = pixelMap->GetAllocationByteCount();
    EXPECT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "PixelMapTest: GetAllocationByteCountTest001 end";
}

/**
 * @tc.name: ReadPixelsTest001
 * @tc.desc: Verify ReadPixels returns error when called with invalid parameters
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ReadPixelsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ReadPixelsTest001 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::NV21,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    const uint64_t bufferSize = static_cast<uint64_t>(pixelMap->GetByteCount());
    auto srcBuffer = std::make_unique<uint8_t[]>(bufferSize);
    uint32_t ret = pixelMap->ReadPixels(bufferSize, srcBuffer.get());
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapTest: ReadPixelsTest001 end";
}

/**
 * @tc.name: ReadARGBPixelsTest004
 * @tc.desc: Verify ReadARGBPixels returns error when called with ASTC format, null buffer or unmapped data.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ReadARGBPixelsTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ReadARGBPixelsTest004 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::RGBA_8888,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::SHARE_MEM_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    const uint64_t bufferSize = static_cast<uint64_t>(pixelMap->GetByteCount());
    auto srcBuffer = std::make_unique<uint8_t[]>(bufferSize);
    uint8_t* srcPtr = srcBuffer.get();
    pixelMap->isAstc_ = true;
    uint32_t ret = pixelMap->ReadARGBPixels(bufferSize, srcPtr);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    pixelMap->isAstc_ = false;
    ret = pixelMap->ReadARGBPixels(bufferSize, nullptr);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    pixelMap->isUnMap_ = true;
    ret = pixelMap->ReadARGBPixels(bufferSize, srcPtr);
    EXPECT_EQ(ret, ERR_IMAGE_READ_PIXELMAP_FAILED);
    pixelMap->isUnMap_ = false;
    pixelMap->data_ = nullptr;
    ret = pixelMap->ReadARGBPixels(bufferSize, srcPtr);
    EXPECT_EQ(ret, ERR_IMAGE_READ_PIXELMAP_FAILED);
    pixelMap->isUnMap_ = true;
    pixelMap->data_ = nullptr;
    ret = pixelMap->ReadARGBPixels(bufferSize, srcPtr);
    EXPECT_EQ(ret, ERR_IMAGE_READ_PIXELMAP_FAILED);
    GTEST_LOG_(INFO) << "PixelMapTest: ReadARGBPixelsTest004 end";
}

/**
 * @tc.name: ResetConfigTest004
 * @tc.desc: Verify ResetConfig returns error when input invalid size or unsupported pixel format.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ResetConfigTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ResetConfigTest004 start";
    auto pixelMap = ConstructPixelMap(SIZE_WIDTH, SIZE_HEIGHT, PixelFormat::RGBA_8888,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::SHARE_MEM_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    Size size = {-1, 1};
    uint32_t ret = pixelMap->ResetConfig(size, pixelMap->GetPixelFormat());
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    size = {1, -1};
    ret = pixelMap->ResetConfig(size, pixelMap->GetPixelFormat());
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    size = {-1, -1};
    ret = pixelMap->ResetConfig(size, pixelMap->GetPixelFormat());
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    size = {1, 1};
    pixelMap->imageInfo_.pixelFormat = PixelFormat::CMYK;
    ret = pixelMap->ResetConfig(size, pixelMap->GetPixelFormat());
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapTest: ResetConfigTest004 end";
}

/**
 * @tc.name: UnMapPixelMapTest
 * @tc.desc: Test UnMap PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, UnMapPixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: UnMapPixelMapTest start";
    auto pixelMap_sharedMem = ConstructPixmap(PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
    EXPECT_NE(pixelMap_sharedMem, nullptr);
    EXPECT_EQ(pixelMap_sharedMem->GetAllocatorType(), AllocatorType::SHARE_MEM_ALLOC);
    EXPECT_NE(true, pixelMap_sharedMem->UnMap());
    EXPECT_NE(true, pixelMap_sharedMem->IsUnMap());
    pixelMap_sharedMem->IncreaseUseCount();
    EXPECT_NE(false, pixelMap_sharedMem->UnMap());
    EXPECT_NE(false, pixelMap_sharedMem->IsUnMap());
    auto pixelMap = ConstructPixmap(AllocatorType::DMA_ALLOC);
    EXPECT_NE(pixelMap, nullptr);
    EXPECT_NE(true, pixelMap->UnMap());
    GTEST_LOG_(INFO) << "PixelMapTest: UnMapPixelMapTest end";
}
 
/**
 * @tc.name: GetImagePropertyIntPixelMapTest
 * @tc.desc: Test GetImagePropertyInt PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, GetImagePropertyIntPixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: GetImagePropertyIntPixelMapTest start";
    auto pixelMap = ConstructPixmap(AllocatorType::SHARE_MEM_ALLOC);
    string key = "GPSLatitude";

    int32_t val = 0;
    EXPECT_NE(true, pixelMap->GetImagePropertyInt(key, val));
    GTEST_LOG_(INFO) << "PixelMapTest: GetImagePropertyIntPixelMapTest end";
}
 
/**
 * @tc.name: UseCountPixelMapTest
 * @tc.desc: Test UseCount PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, UseCountPixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: UseCountPixelMapTest start";
    auto pixelMap = ConstructPixmap(AllocatorType::SHARE_MEM_ALLOC);
   
    pixelMap->IncreaseUseCount();
    pixelMap->IncreaseUseCount();
    EXPECT_EQ(2, pixelMap->GetUseCount());
    pixelMap->DecreaseUseCount();
    EXPECT_EQ(1, pixelMap->GetUseCount());
    GTEST_LOG_(INFO) << "PixelMapTest: UseCountPixelMapTest end";
}
 
/**
 * @tc.name: MemoryDirtyPixelMapTest
 * @tc.desc: Test MemoryDirty PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, MemoryDirtyPixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: MemoryDirtyPixelMapTest start";
    auto pixelMap = ConstructPixmap(AllocatorType::SHARE_MEM_ALLOC);
    pixelMap->MarkDirty();
    EXPECT_EQ(true, pixelMap->IsMemoryDirty());
    GTEST_LOG_(INFO) << "PixelMapTest: MemoryDirtyPixelMapTest end";
}

/**
 * @tc.name: ConvertFromAstcPixelMapTest
 * @tc.desc: Test ConvertFromAstc PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ConvertFromAstcPixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ConvertFromAstcPixelMapTest start";
    std::unique_ptr<PixelMap> pixelMap = nullptr;
    OHOS::Multimedia::ConstructPixelAstc(ASTC_WIDTH, ASTC_HEIGHT, pixelMap);
    ASSERT_NE(pixelMap, nullptr);
    uint32_t errorCode = 0;
    auto result = PixelMap::ConvertFromAstc(pixelMap.get(), errorCode, PixelFormat::RGBA_8888);
    ASSERT_EQ(errorCode, 0);
    for (int i = 0; i < static_cast<int>(PixelFormat::EXTERNAL_MAX); i++) {
        if (i == 3) {
            continue;
        }
        result = PixelMap::ConvertFromAstc(pixelMap.get(), errorCode, static_cast<PixelFormat>(i));
        EXPECT_NE(errorCode, 0);
    }
    GTEST_LOG_(INFO) << "PixelMapTest: ConvertFromAstcPixelMapTest end";
}

/**
 * @tc.name: ColorTableCoefficientstest
 * @tc.desc: Test of Create
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, ColorTableCoefficientstest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: ColorTableCoefficientstest start";
    // 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 means buffer
    // 8 means color length
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    uint32_t colorlength = sizeof(color) / sizeof(color[0]);
    EXPECT_TRUE(colorlength == 8);
    // -1 means offset
    const int32_t offset = -1;
    InitializationOptions opts;
    // 2, 3 means size
    opts.size.width = 3;
    opts.size.height = 2;
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.convertColorSpace = {0, 0, YuvConversion::BT601,
        YuvConversion::BT601};
    int32_t width = opts.size.width;
    // 1 means width
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(color, colorlength, offset, 1, opts);
    EXPECT_NE(pixelMap1, nullptr);

    opts.convertColorSpace = {0, 0, YuvConversion::BT709,
        YuvConversion::BT709};
    std::unique_ptr<PixelMap> pixelMap2 = PixelMap::Create(color, colorlength, offset, INT32_MAX, opts);
    EXPECT_NE(pixelMap2, nullptr);

    opts.convertColorSpace = {0, 0, YuvConversion::BT2020, YuvConversion::BT2020};
    std::unique_ptr<PixelMap> pixelMap3= PixelMap::Create(color, colorlength, offset, width, opts);
    EXPECT_NE(pixelMap3, nullptr);

    opts.convertColorSpace = {0, 0, YuvConversion(8), YuvConversion::BT709};
    std::unique_ptr<PixelMap> pixelMap4= PixelMap::Create(color, colorlength, 0, width, opts);
    EXPECT_EQ(pixelMap4, nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: ColorTableCoefficientstest end";
}
 
// For test closeFd func
class TestPixelMap : public PixelMap {
public:
    TestPixelMap() {}
    virtual ~TestPixelMap() {}
    bool CloseFd()
    {
        return PixelMap::CloseFd();
    }
};

/**
 * @tc.name: pixelmapfd001
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, pixelmapfd001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: pixelmapfd001 start";
    close(0); // close 0
    InitializationOptions opts;
    // 200, 300 means size
    opts.size.width = 200;
    opts.size.height = 300;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.useSourceIfMatch = true;
    opts.editable = true;
    opts.useDMA = false;
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(opts);
    EXPECT_TRUE(pixelMap1 != nullptr);
    Parcel data;
    auto ret = pixelMap1->Marshalling(data);
    EXPECT_TRUE(ret);
    PixelMap *pixelMap2 = PixelMap::Unmarshalling(data);
    EXPECT_EQ(pixelMap1->GetHeight(), pixelMap2->GetHeight());

    std::unique_ptr<PixelMap> pixelMapBase =
        ConstructPixmap(PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
    EXPECT_NE(nullptr, pixelMapBase);
    TestPixelMap* testPixelMap = (TestPixelMap*)pixelMapBase.release();
    EXPECT_EQ(true, testPixelMap->CloseFd());
    delete testPixelMap;

    std::unique_ptr<PixelMap> pixelMap3 = PixelMap::Create(opts);
    std::unique_ptr<PixelMap> pixelMap4 = PixelMap::Create(*(pixelMap3.get()), opts);
    EXPECT_TRUE(pixelMap4 != nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: pixelmapfd001 end";
}

/**
 * @tc.name: CloseFdPixelMapTest
 * @tc.desc: Test CloseFd PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CloseFdPixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CloseFdPixelMapTest start";
    std::unique_ptr<PixelMap> pixelMapBase =
        ConstructPixmap(PixelFormat::RGBA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
    EXPECT_NE(nullptr, pixelMapBase);
    TestPixelMap* testPixelMap = (TestPixelMap*)pixelMapBase.release();
    EXPECT_EQ(true, testPixelMap->CloseFd());
 
    std::unique_ptr<PixelMap> testHeapPixelMap = ConstructPixmap(AllocatorType::HEAP_ALLOC);
    EXPECT_NE(nullptr, testHeapPixelMap);
    TestPixelMap* heapPixelMap = (TestPixelMap*)testHeapPixelMap.release();
    EXPECT_EQ(false, heapPixelMap->CloseFd());
 
    delete testPixelMap;
    delete heapPixelMap;
    GTEST_LOG_(INFO) << "PixelMapTest: CloseFdPixelMapTest end";
}
}
}
