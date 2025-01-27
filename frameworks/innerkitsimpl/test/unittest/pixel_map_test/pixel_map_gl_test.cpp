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
#include <cstddef>
#include <cstdint>
#include <securec.h>
#include <chrono>
#include <thread>
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "pixel_convert_adapter.h"
#include "post_proc.h"
#include "pixel_map_program_manager.h"
 
using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
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
 
const uint32_t ANGLE90 = 90;
const uint32_t ANGLE0 = 0;
const uint32_t ANGLE180 = 180;
const uint32_t ANGLE183 = 183;
const uint32_t ANGLE277 = 277;
 
const int32_t NUM_2 = 2;
const int32_t NUM_3 = 3;
const int32_t NUM_4 = 4;
const int32_t NUM_10 = 10;
const int32_t NUM_24 = 24;
const int32_t NUM_512 = 512;
const int32_t NUM_647 = 647;
 
struct Size {
    int32_t x = 0;
    int32_t y = 0;
};
 
bool ConstructAstcBody(uint8_t* astcBody, size_t& blockNums, const uint8_t* astcBlockPart)
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
 
bool GenAstcHeader(uint8_t* header, size_t blockSize, size_t width, size_t height)
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
 
bool ConstructPixelAstc(int32_t width, int32_t height, std::unique_ptr<Media::PixelMap>& pixelMap)
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
 
class PixelMapTest : public testing::Test {
public:
    PixelMapTest() {}
    ~PixelMapTest() {}
};
 
std::map<PixelFormat, std::string> SupportDmaMemPixelFormat = {
    { PixelFormat::RGBA_8888, "PixelFormat::RGBA_8888" },
    { PixelFormat::RGBA_1010102, "PixelFormat::RGBA_1010102"},
    { PixelFormat::YCBCR_P010,      "PixelFormat::YCBCR_P010" },
    { PixelFormat::YCRCB_P010,      "PixelFormat::YCRCB_P010" }
};
 
std::map<PixelFormat, std::string> SupportAshMemPixelFormat = {
    { PixelFormat::ARGB_8888, "PixelFormat::ARGB_8888" },
    { PixelFormat::RGB_565,   "PixelFormat::RGB_565" },
    { PixelFormat::RGBA_8888, "PixelFormat::RGBA_8888" },
    { PixelFormat::BGRA_8888, "PixelFormat::BGRA_8888" },
    { PixelFormat::RGB_888,   "PixelFormat::RGB_888" },
    { PixelFormat::ALPHA_8,   "PixelFormat::ALPHA_8" },
    { PixelFormat::RGBA_F16,  "PixelFormat::RGBA_F16" },
    { PixelFormat::RGBA_1010102, "PixelFormat::RGBA_1010102"},
    { PixelFormat::NV21,      "PixelFormat::NV21" },
    { PixelFormat::NV12,      "PixelFormat::NV12" },
    { PixelFormat::YCBCR_P010,      "PixelFormat::YCBCR_P010" },
    { PixelFormat::YCRCB_P010,      "PixelFormat::YCRCB_P010" },
    { PixelFormat::ASTC_4x4,      "PixelFormat::ASTC_4x4" }
};
 
static bool PixelMapScaleWithGpu(std::unique_ptr<Media::PixelMap> &pixelMap, Size desiredSize)
{
    if (!pixelMap) {
        return false;
    }
    for (int i = 0; i <= NUM_10; i++) {
        bool flag =
            PostProc::ScalePixelMapWithGPU(*(pixelMap.get()),
            {desiredSize.x, desiredSize.y}, static_cast<Media::AntiAliasingOption>(i), true) &&
            PostProc::ScalePixelMapWithGPU(*(pixelMap.get()),
            {desiredSize.x, desiredSize.y}, static_cast<Media::AntiAliasingOption>(i));
        if (!flag) {
            return false;
        }
    }
    return true;
}
 
static bool PixelMapRotate(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    if (!pixelMap) {
        return false;
    }
    return PostProc::RotateInRectangularSteps(*(pixelMap.get()), ANGLE90, true) &&
        PostProc::RotateInRectangularSteps(*(pixelMap.get()), ANGLE0, true) &&
        PostProc::RotateInRectangularSteps(*(pixelMap.get()), ANGLE180, true) &&
        PostProc::RotateInRectangularSteps(*(pixelMap.get()), ANGLE183, true) &&
        PostProc::RotateInRectangularSteps(*(pixelMap.get()), ANGLE277, true);
}
 
/**
 * @tc.name: PixelMapAshMemTestRotate001
 * @tc.desc: Rotate and Scale Ashmem PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapAshMemTestRotate001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapAshMemTestRotate001 start";
 
    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = NUM_2;
    options.size.height = NUM_3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;
 
    std::map<PixelFormat, std::string>::iterator iter;
 
    // ARGB_8888 to others
    options.srcPixelFormat = PixelFormat::ARGB_8888;
    for (iter =  SupportAshMemPixelFormat.begin(); iter !=  SupportAshMemPixelFormat.end() ; ++iter) {
        uint32_t colorlength = NUM_24;    // w:2 * h:3 * pixelByte:4
        uint8_t buffer[NUM_24] = { 0 };    // w:2 * h:3 * pixelByte:4
        for (int i = 0; i < colorlength; i += 4) {
            buffer[i] = 0x78;
            buffer[i + 1] = 0x83;
            buffer[i + 2] = 0xDF;
            buffer[i + 3] = 0x52;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        
        std::unique_ptr<PixelMap> pixelMap = nullptr;
        if (options.pixelFormat != PixelFormat::ASTC_4x4) {
            pixelMap = PixelMap::Create(color, colorlength, offset, width, options);
        } else {
            ConstructPixelAstc(ASTC_WIDTH, ASTC_HEIGHT, pixelMap);
        }
        if (pixelMap != nullptr) {
            EXPECT_EQ(true, PixelMapRotate(pixelMap));
        } else {
            GTEST_LOG_(INFO) << "convert failed is " << iter->second;
        }
    }
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapAshMemTestRotate001 end";
}
 
/**
 * @tc.name: PixelMapAshMemTestRotate002
 * @tc.desc: Rotate and Scale Ashmem PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapAshMemTestRotate002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapAshMemTestRotate002 start";
 
    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = NUM_512;
    options.size.height = NUM_647;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;
 
    std::map<PixelFormat, std::string>::iterator iter;
 
    // ARGB_8888 to others
    options.srcPixelFormat = PixelFormat::ARGB_8888;
    for (iter =  SupportAshMemPixelFormat.begin(); iter !=  SupportAshMemPixelFormat.end() ; ++iter) {
        uint32_t colorlength = NUM_512 * NUM_647 * NUM_4;    // w:2 * h:3 * pixelByte:4
        uint8_t buffer[NUM_512 * NUM_647 * NUM_4] = { 0 };    // w:2 * h:3 * pixelByte:4
        for (int i = 0; i < colorlength; i += NUM_4) {
            buffer[i] = 0x78;
            buffer[i + 1] = 0x83;
            buffer[i + 2] = 0xDF;
            buffer[i + 3] = 0x52;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        
        std::unique_ptr<PixelMap> pixelMap = nullptr;
        if (options.pixelFormat != PixelFormat::ASTC_4x4) {
            pixelMap = PixelMap::Create(color, colorlength, offset, width, options);
        } else {
            ConstructPixelAstc(ASTC_WIDTH, ASTC_HEIGHT, pixelMap);
        }
        if (pixelMap != nullptr) {
            EXPECT_EQ(true, PixelMapRotate(pixelMap));
        }
    }
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapAshMemTestRotate002 end";
}
 
/**
 * @tc.name: PixelMapAshMemTestRotateAndScale003
 * @tc.desc: Rotate and Scale Ashmem PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapDmaTestRotate001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapDmaTestRotate001 start";
    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = NUM_512;
    options.size.height = NUM_512;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    options.useDMA = true;
    int32_t width = options.size.width;
    std::map<PixelFormat, std::string>::iterator iter;
    // ARGB_8888 to others
    options.srcPixelFormat = PixelFormat::ARGB_8888;
    for (iter =  SupportDmaMemPixelFormat.begin(); iter !=  SupportDmaMemPixelFormat.end() ; ++iter) {
        uint32_t colorLength = NUM_512 * NUM_647 * NUM_4;    // w:2 * h:3 * pixelByte:4
        uint8_t buffer[NUM_512 * NUM_647 * NUM_4] = { 0 };    // w:2 * h:3 * pixelByte:4
        for (int i = 0; i < colorLength; i += NUM_4) {
            buffer[i] = 0x78;
            buffer[i + 1] = 0x83;
            buffer[i + 2] = 0xDF;
            buffer[i + 3] = 0x52;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        
        std::unique_ptr<PixelMap> pixelMap = nullptr;
        pixelMap = PixelMap::Create(color, colorLength, offset, width, options);
        EXPECT_NE(nullptr, pixelMap);
        EXPECT_EQ(true, PixelMapRotate(pixelMap));
    }
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapDmaTestRotate001 end";
}
 
/**
 * @tc.name: PixelMapAshMemTestScale001
 * @tc.desc: Scale Ashmem PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapAshMemTestScale001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapAshMemTestScale001 start";
 
    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = NUM_2;
    options.size.height = NUM_3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;
 
    std::map<PixelFormat, std::string>::iterator iter;
 
    // ARGB_8888 to others
    options.srcPixelFormat = PixelFormat::ARGB_8888;
    for (iter =  SupportAshMemPixelFormat.begin(); iter !=  SupportAshMemPixelFormat.end() ; ++iter) {
        uint32_t colorlength = NUM_24;    // w:2 * h:3 * pixelByte:4
        uint8_t buffer[NUM_24] = { 0 };    // w:2 * h:3 * pixelByte:4
        for (int i = 0; i < colorlength; i += 4) {
            buffer[i] = 0x78;
            buffer[i + 1] = 0x83;
            buffer[i + 2] = 0xDF;
            buffer[i + 3] = 0x52;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        
        std::unique_ptr<PixelMap> pixelMap = nullptr;
        if (options.pixelFormat != PixelFormat::ASTC_4x4) {
            pixelMap = PixelMap::Create(color, colorlength, offset, width, options);
        } else {
            ConstructPixelAstc(ASTC_WIDTH, ASTC_HEIGHT, pixelMap);
        }
        EXPECT_NE(nullptr, pixelMap);
        int format = static_cast<int32_t>(pixelMap->GetPixelFormat());
        if (format == 1 || format == 2 || format == 3 || format == 4 || format == 5 || format == 7) {
            EXPECT_EQ(true, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() / 2, pixelMap->GetHeight() / 2}));
            EXPECT_EQ(true, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() * 2, pixelMap->GetHeight() * 2}));
        }else {
            EXPECT_EQ(false, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() / 2, pixelMap->GetHeight() / 2}));
            EXPECT_EQ(false, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() * 2, pixelMap->GetHeight() * 2}));
        }
    }
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapAshMemTestScale001 end";
}
 
/**
 * @tc.name: PixelMapAshMemTestScale002
 * @tc.desc: Scale Ashmem PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapAshMemTestScale002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapAshMemTestScale002 start";
 
    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = NUM_512;
    options.size.height = NUM_647;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;
 
    std::map<PixelFormat, std::string>::iterator iter;
 
    // ARGB_8888 to others
    options.srcPixelFormat = PixelFormat::ARGB_8888;
    for (iter =  SupportAshMemPixelFormat.begin(); iter !=  SupportAshMemPixelFormat.end() ; ++iter) {
        uint32_t colorLength = NUM_512 * NUM_647 * NUM_4;    // w:2 * h:3 * pixelByte:4
        uint8_t buffer[NUM_512 * NUM_647 * NUM_4] = { 0 };    // w:2 * h:3 * pixelByte:4
        for (int i = 0; i < colorLength; i += NUM_4) {
            buffer[i] = 0x78;
            buffer[i + 1] = 0x83;
            buffer[i + 2] = 0xDF;
            buffer[i + 3] = 0x52;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        
        std::unique_ptr<PixelMap> pixelMap = nullptr;
        if (options.pixelFormat != PixelFormat::ASTC_4x4) {
            pixelMap = PixelMap::Create(color, colorLength, offset, width, options);
        } else {
            ConstructPixelAstc(ASTC_WIDTH, ASTC_HEIGHT, pixelMap);
        }
        EXPECT_NE(nullptr, pixelMap);
        int format = static_cast<int32_t>(pixelMap->GetPixelFormat());
        if (format == 1 || format == 2 || format == 3 || format == 4 || format == 5 || format == 6 ||format == 7) {
            EXPECT_EQ(true, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() / 2, pixelMap->GetHeight() / 2}));
            EXPECT_EQ(true, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() * 2, pixelMap->GetHeight() * 2}));
        }else {
            EXPECT_EQ(false, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() / 2, pixelMap->GetHeight() / 2}));
            EXPECT_EQ(false, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() * 2, pixelMap->GetHeight() * 2}));
        }
    }
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapAshMemTestScale002 end";
}
 
/**
 * @tc.name: PixelMapDmaTestScale001
 * @tc.desc: Scale Dma PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, PixelMapDmaTestScale001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapDmaTestScale001 start";
    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = NUM_512;
    options.size.height = NUM_512;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    options.useDMA = true;
    int32_t width = options.size.width;
    std::map<PixelFormat, std::string>::iterator iter;
    // ARGB_8888 to others
    options.srcPixelFormat = PixelFormat::ARGB_8888;
    for (iter =  SupportDmaMemPixelFormat.begin(); iter !=  SupportDmaMemPixelFormat.end() ; ++iter) {
        uint32_t colorLength = NUM_512 * NUM_512 * NUM_4;    // w:2 * h:3 * pixelByte:4
        uint8_t buffer[NUM_512 * NUM_512 * NUM_4] = { 0 };    // w:2 * h:3 * pixelByte:4
        for (int i = 0; i < colorLength; i += NUM_4) {
            buffer[i] = 0x78;
            buffer[i + 1] = 0x83;
            buffer[i + 2] = 0xDF;
            buffer[i + 3] = 0x52;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = iter->first;
        
        std::unique_ptr<PixelMap> pixelMap = nullptr;
        pixelMap = PixelMap::Create(color, colorLength, offset, width, options);
        EXPECT_NE(nullptr, pixelMap);
        int format = static_cast<int32_t>(pixelMap->GetPixelFormat());
        if (format == 1 || format == 2 || format == 3 || format == 4 || format == 5 || format == 7) {
            EXPECT_EQ(true, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() / 2, pixelMap->GetHeight() / 2}));
            EXPECT_EQ(true, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() * 2, pixelMap->GetHeight() * 2}));
        }else {
            EXPECT_EQ(false, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() / 2, pixelMap->GetHeight() / 2}));
            EXPECT_EQ(false, PixelMapScaleWithGpu(pixelMap, {pixelMap->GetWidth() * 2, pixelMap->GetHeight() * 2}));
        }
    }
    GTEST_LOG_(INFO) << "PixelMapTest: PixelMapDmaTestScale001 end";
}
}
}
