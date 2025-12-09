/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "basic_transformer.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
constexpr int32_t PIXEL_MAP_MAX_RAM_SIZE = 600 * 1024 * 1024;
static constexpr uint32_t DST_WIDTH_640 = 640;
static constexpr uint32_t DST_HEIGHT_480 = 480;
static constexpr uint32_t DST_WIDTH_320 = 320;
static constexpr uint32_t DST_HEIGHT_240 = 240;
static constexpr uint32_t SRC_WIDTH_100 = 100;
static constexpr uint32_t SRC_HEIGHT_100 = 100;
static constexpr uint32_t SRC_WIDTH_2 = 2;
static constexpr uint32_t SRC_HEIGHT_2 = 2;
static constexpr uint32_t LARGE_WIDTH_1000000 = 1000000;
static constexpr uint32_t LARGE_HEIGHT_1000000 = 1000000;
static constexpr uint32_t LARGE_WIDTH_20000 = 20000;
static constexpr uint32_t LARGE_HEIGHT_20000 = 20000;
static constexpr uint32_t DST_WIDTH_200 = 200;
static constexpr uint32_t DST_HEIGHT_200 = 200;
static constexpr uint64_t BUFFER_SIZE_1MB = 1024 * 1024;
static constexpr uint64_t BUFFER_SIZE_512KB = 512 * 1024;
static constexpr uint32_t UINT8_BYTE_SIZE = 1;
static constexpr uint32_t UINT16_BYTE_SIZE = 2;
static constexpr uint32_t UINT32_BYTE_SIZE = 4;
static constexpr int FD_10 = 10;
static constexpr int FD_20 = 20;
static constexpr float MATRIX_SCALE_X = 1e-7f;
static constexpr float MATRIX_SCALE_Y = 1.0f;
static constexpr float TRANS_X = 100.0f;
static constexpr float TRANS_Y = 0.0f;
static constexpr float ROTATE_DEGREE = 90.0f;
static constexpr float SCALE_FACTOR = 2.0f;
static constexpr float SCALE_1X = 1.0f;
static constexpr float SCALE_0X = 0.0f;
static constexpr uint16_t RGB565_RED = 0xF800;
static constexpr uint16_t RGB565_GREEN = 0x07E0;
static constexpr uint16_t RGB565_BLUE = 0x001F;
static constexpr uint16_t RGB565_YELLOW = 0xFFE0;
static constexpr uint32_t PIXEL_INDEX_0 = 0;
static constexpr uint32_t PIXEL_INDEX_1 = 1;
static constexpr uint32_t PIXEL_INDEX_2 = 2;
static constexpr uint32_t PIXEL_INDEX_3 = 3;

class BasicTransformerTest : public testing::Test {
public:
    BasicTransformerTest() {}
    ~BasicTransformerTest() {}
};

/**
 * @tc.name: CheckAllocateBufferTest001
 * @tc.desc: CheckAllocateBuffer
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, CheckAllocateBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: CheckAllocateBufferTest001 start";
    BasicTransformer basicTransformer;
    PixmapInfo outPixmap;
    BasicTransformer::AllocateMem allocate = nullptr;
    int fd = 0;
    uint64_t bufferSize = 0;
    Size dstSize;
    bool ret = basicTransformer.CheckAllocateBuffer(outPixmap, allocate, fd, bufferSize, dstSize);
    ASSERT_EQ(ret, false);
    bufferSize = 128;
    ret = basicTransformer.CheckAllocateBuffer(outPixmap, allocate, fd, bufferSize, dstSize);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "BasicTransformerTest: CheckAllocateBufferTest001 end";
}


/**
 * @tc.name: ReleaseBufferTest001
 * @tc.desc: ReleaseBuffer
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, ReleaseBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: ReleaseBufferTest001 start";
    BasicTransformer basicTransformer;
    AllocatorType allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    int fd = 0;
    int dataSize = 2;
    uint8_t *buffer = new uint8_t;
    basicTransformer.ReleaseBuffer(allocatorType, fd, dataSize, buffer);
    ASSERT_NE(buffer, nullptr);
    buffer = new uint8_t;
    allocatorType = AllocatorType::HEAP_ALLOC;
    basicTransformer.ReleaseBuffer(allocatorType, fd, dataSize, buffer);
    ASSERT_NE(buffer, nullptr);
    GTEST_LOG_(INFO) << "BasicTransformerTest: ReleaseBufferTest001 end";
}

/**
 * @tc.name: TransformPixmapTest001
 * @tc.desc: TransformPixmap
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, TransformPixmapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapTest001 start";
    BasicTransformer basicTransformer;
    PixmapInfo inPixmap;
    PixmapInfo outPixmap;
    BasicTransformer::AllocateMem allocate = nullptr;
    uint32_t ret = basicTransformer.TransformPixmap(inPixmap, outPixmap, allocate);
    ASSERT_EQ(ret, ERR_IMAGE_GENERAL_ERROR);
    inPixmap.data = new uint8_t;
    ret = basicTransformer.TransformPixmap(inPixmap, outPixmap, allocate);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PIXEL);
    inPixmap.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    basicTransformer.matrix_.operType_ = 0x02;
    basicTransformer.matrix_.fMat_[IMAGE_SCALEX] = 1;
    inPixmap.imageInfo.size.width = -FHALF;
    basicTransformer.matrix_.fMat_[IMAGE_SCALEY] = 1;
    inPixmap.imageInfo.size.height = -FHALF;
    ret = basicTransformer.TransformPixmap(inPixmap, outPixmap, allocate);
    ASSERT_EQ(ret, ERR_IMAGE_ALLOC_MEMORY_FAILED);
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapTest001 end";
}

/**
 * @tc.name: TransformPixmapTest002
 * @tc.desc: TransformPixmap
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, TransformPixmapTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapTest002 start";
    BasicTransformer basicTransformer;
    PixmapInfo inPixmap;
    PixmapInfo outPixmap;
    BasicTransformer::AllocateMem allocate = nullptr;
    inPixmap.data = new uint8_t;
    inPixmap.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    basicTransformer.matrix_.operType_ = 0x02;
    basicTransformer.matrix_.fMat_[IMAGE_SCALEX] = 1;
    inPixmap.imageInfo.size.width = PIXEL_MAP_MAX_RAM_SIZE;
    basicTransformer.matrix_.fMat_[IMAGE_SCALEY] = 1;
    inPixmap.imageInfo.size.height = 1;
    uint32_t ret = basicTransformer.TransformPixmap(inPixmap, outPixmap, allocate);
    ASSERT_EQ(ret, ERR_IMAGE_ALLOC_MEMORY_FAILED);
    inPixmap.imageInfo.size.width = -FHALF;
    inPixmap.imageInfo.size.height = -FHALF;
    ret = basicTransformer.TransformPixmap(inPixmap, outPixmap, allocate);
    ASSERT_EQ(ret, ERR_IMAGE_ALLOC_MEMORY_FAILED);
    inPixmap.imageInfo.size.width = 1;
    inPixmap.imageInfo.size.height = 1;
    ret = basicTransformer.TransformPixmap(inPixmap, outPixmap, allocate);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapTest002 end";
}

/**
 * @tc.name: GetAroundPixelRGB565Test001
 * @tc.desc: GetAroundPixelRGB565
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, GetAroundPixelRGB565Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: GetAroundPixelRGB565Test001 start";
    BasicTransformer basicTransformer;
    Media::BasicTransformer::AroundPos aroundPos;
    uint32_t *color = new uint32_t(0);
    uint8_t *data = reinterpret_cast<uint8_t*>(color);
    uint32_t rb = 2;
    Media::BasicTransformer::AroundPixels aroundPixels;
    basicTransformer.GetAroundPixelRGB565(aroundPos, data, rb, aroundPixels);
    ASSERT_EQ(aroundPixels.color11, 0);
    delete color;
    GTEST_LOG_(INFO) << "BasicTransformerTest: GetAroundPixelRGB565Test001 end";
}

/**
 * @tc.name: BasicTransformerCheckAllocateBufferElseBranchTest001
 * @tc.desc: Test CheckAllocateBuffer else branch (allocate != nullptr) with non-null return.
 * Expect success and correct buffer/context setup.
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, BasicTransformerCheckAllocateBufferElseBranchTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: CheckAllocateBufferElseBranchTest001 start";
    static Size sDstSize = {DST_WIDTH_640, DST_HEIGHT_480};
    static int sFd = FD_10;
    static uint64_t sBufferSize = BUFFER_SIZE_1MB;
    static uint8_t* mockAllocatedData = new uint8_t[sBufferSize];
    BasicTransformer::AllocateMem customAllocate = [](const Size& size, uint64_t bufSize,
        int& outFd, uint32_t uniqueId) -> uint8_t* {
        EXPECT_EQ(size.width, sDstSize.width);
        EXPECT_EQ(size.height, sDstSize.height);
        EXPECT_EQ(bufSize, sBufferSize);
        EXPECT_EQ(outFd, sFd);
        return mockAllocatedData;
    };
    BasicTransformer transformer;
    PixmapInfo outPixmap(false);
    bool result = transformer.CheckAllocateBuffer(outPixmap, customAllocate, sFd, sBufferSize, sDstSize);
    EXPECT_TRUE(result) << "Success path returns false unexpectedly";
    EXPECT_EQ(outPixmap.data, mockAllocatedData) << "outPixmap.data not match mock allocated memory";
    EXPECT_NE(outPixmap.context, nullptr) << "outPixmap.context is null in success path";
    EXPECT_EQ(*outPixmap.context, sFd) << "outPixmap.context stores wrong fd";
    delete[] mockAllocatedData;
    delete outPixmap.context;
    outPixmap.data = nullptr;
    outPixmap.context = nullptr;
    mockAllocatedData = nullptr;
    sDstSize = {0, 0};
    sFd = 0;
    sBufferSize = 0;

    GTEST_LOG_(INFO) << "BasicTransformerTest: CheckAllocateBufferElseBranchTest001 end";
}

/**
 * @tc.name: BasicTransformerCheckAllocateBufferElseBranchTest002
 * @tc.desc: Test CheckAllocateBuffer else branch (allocate != nullptr) with null return.
 * Expect failure and correct state.
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, BasicTransformerCheckAllocateBufferElseBranchTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: CheckAllocateBufferElseBranchTest002 start";
    BasicTransformer transformer;
    PixmapInfo outPixmap(false);
    Size dstSize = {DST_WIDTH_320, DST_HEIGHT_240};
    int fd = FD_20;
    uint64_t bufferSize = BUFFER_SIZE_512KB;
    BasicTransformer::AllocateMem allocateNull = [](const Size&, uint64_t, int&, uint32_t) -> uint8_t* {
        return nullptr;
    };
    bool result = transformer.CheckAllocateBuffer(outPixmap, allocateNull, fd, bufferSize, dstSize);
    EXPECT_FALSE(result) << "Failure path returns true unexpectedly";
    EXPECT_EQ(outPixmap.data, nullptr) << "outPixmap.data should be null when allocate failed";
    EXPECT_NE(outPixmap.context, nullptr) << "outPixmap.context should be allocated in else branch";
    EXPECT_EQ(*outPixmap.context, fd) << "outPixmap.context stores wrong fd value";
    GTEST_LOG_(INFO) << "BasicTransformerTest: CheckAllocateBufferElseBranchTest002 end";
}

/**
 * @tc.name: TransformPixmapAllocFailTest001
 * @tc.desc: Trigger ERR_IMAGE_ALLOC_MEMORY_FAILED when dstSize.width <= 0. Expect error code returned.
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, TransformPixmapAllocFailTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapAllocFailTest001 start";
    PixmapInfo inPixmap(false);
    inPixmap.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    inPixmap.imageInfo.size = {DST_WIDTH_640, DST_HEIGHT_480};
    inPixmap.data = new uint8_t[DST_WIDTH_640 * DST_HEIGHT_480 * UINT32_BYTE_SIZE];
    BasicTransformer transformer;
    transformer.SetScaleParam(SCALE_0X, SCALE_1X);
    PixmapInfo outPixmap(false);
    uint32_t ret = transformer.TransformPixmap(inPixmap, outPixmap, nullptr);
    EXPECT_EQ(ret, ERR_IMAGE_ALLOC_MEMORY_FAILED) << "Not return ERR_IMAGE_ALLOC_MEMORY_FAILED when dstSize.width=0";
    delete[] inPixmap.data;
    inPixmap.data = nullptr;
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapAllocFailTest001 end";
}

/**
 * @tc.name: TransformPixmapAllocFailTest002
 * @tc.desc: Trigger ERR_IMAGE_ALLOC_MEMORY_FAILED via ImageUtils::CheckMulOverflow. Expect error code returned.
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, TransformPixmapAllocFailTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapAllocFailTest002 start";
    PixmapInfo inPixmap(false);
    inPixmap.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    inPixmap.imageInfo.size = {LARGE_WIDTH_1000000, LARGE_HEIGHT_1000000};
    inPixmap.data = new uint8_t[UINT8_BYTE_SIZE];
    BasicTransformer transformer;
    PixmapInfo outPixmap(false);
    uint32_t ret = transformer.TransformPixmap(inPixmap, outPixmap, nullptr);
    EXPECT_EQ(ret, ERR_IMAGE_ALLOC_MEMORY_FAILED) << "Not return ERR_IMAGE_ALLOC_MEMORY_FAILED when mul overflow";
    delete[] inPixmap.data;
    inPixmap.data = nullptr;
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapAllocFailTest002 end";
}

/**
 * @tc.name: TransformPixmapAllocFailTest003
 * @tc.desc: Trigger ERR_IMAGE_ALLOC_MEMORY_FAILED when bufferSize > PIXEL_MAP_MAX_RAM_SIZE. Expect error code returned.
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, TransformPixmapAllocFailTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapAllocFailTest003 start";
    PixmapInfo inPixmap(false);
    inPixmap.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    inPixmap.imageInfo.size = {LARGE_WIDTH_20000, LARGE_HEIGHT_20000};
    inPixmap.data = new uint8_t[UINT8_BYTE_SIZE];
    BasicTransformer transformer;
    PixmapInfo outPixmap(false);
    uint32_t ret = transformer.TransformPixmap(inPixmap, outPixmap, nullptr);
    EXPECT_EQ(ret, ERR_IMAGE_ALLOC_MEMORY_FAILED);
    delete[] inPixmap.data;
    inPixmap.data = nullptr;
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapAllocFailTest003 end";
}

/**
 * @tc.name: TransformPixmapAllocFailTest004
 * @tc.desc: Trigger ERR_IMAGE_ALLOC_MEMORY_FAILED when CheckAllocateBuffer returns false. Expect error code returned.
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, TransformPixmapAllocFailTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapAllocFailTest004 start";

    PixmapInfo inPixmap(false);
    inPixmap.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    inPixmap.imageInfo.size = {DST_WIDTH_640, DST_HEIGHT_480};
    inPixmap.data = new uint8_t[DST_WIDTH_640 * DST_HEIGHT_480 * UINT32_BYTE_SIZE];
    BasicTransformer::AllocateMem allocateNull = [](const Size&, uint64_t, int&, uint32_t) -> uint8_t* {
        return nullptr;
    };
    BasicTransformer transformer;
    PixmapInfo outPixmap(false);
    uint32_t ret = transformer.TransformPixmap(inPixmap, outPixmap, allocateNull);
    EXPECT_EQ(ret, ERR_IMAGE_ALLOC_MEMORY_FAILED)
        << "Not return ERR_IMAGE_ALLOC_MEMORY_FAILED when CheckAllocateBuffer fail";
    delete[] inPixmap.data;
    inPixmap.data = nullptr;
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapAllocFailTest004 end";
}

/**
 * @tc.name: TransformPixmapMatrixNotInvertTest001
 * @tc.desc: Trigger ERR_IMAGE_MATRIX_NOT_INVERT when matrix inversion fails. Expect error code returned.
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, TransformPixmapMatrixNotInvertTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapMatrixNotInvertTest001 start";
    PixmapInfo inPixmap(false);
    inPixmap.data = nullptr;
    inPixmap.bufferSize = 0;
    inPixmap.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    inPixmap.imageInfo.size.width = DST_WIDTH_640;
    inPixmap.imageInfo.size.height = DST_HEIGHT_480;
    const uint64_t inBufferSize = DST_WIDTH_640 * DST_HEIGHT_480 * UINT32_BYTE_SIZE;
    inPixmap.data = new (std::nothrow) uint8_t[inBufferSize];
    ASSERT_NE(inPixmap.data, nullptr) << "Allocate inPixmap.data failed";
    std::fill_n(inPixmap.data, inBufferSize, 0x00);
    PixmapInfo outPixmap(false);
    outPixmap.data = nullptr;
    outPixmap.bufferSize = 0;
    outPixmap.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    outPixmap.imageInfo.size.width = 0;
    outPixmap.imageInfo.size.height = 0;
    BasicTransformer transformer;
    auto& matrix = transformer.matrix_;
    matrix.Reset();
    matrix.fMat_[IMAGE_SCALEX] = MATRIX_SCALE_X;
    matrix.fMat_[IMAGE_SCALEY] = MATRIX_SCALE_Y;
    matrix.fMat_[IMAGE_TRANSX] = TRANS_X;
    matrix.fMat_[IMAGE_TRANSY] = TRANS_Y;
    matrix.operType_ = SCALE_TYPE | TRANSLATE_TYPE;
    uint32_t ret = transformer.TransformPixmap(inPixmap, outPixmap, nullptr);
    EXPECT_EQ(ret, ERR_IMAGE_MATRIX_NOT_INVERT) << "Not return ERR_IMAGE_MATRIX_NOT_INVERT when matrix invert fail";
    delete[] inPixmap.data;
    inPixmap.data = nullptr;
    outPixmap.data = nullptr;
    GTEST_LOG_(INFO) << "BasicTransformerTest: TransformPixmapMatrixNotInvertTest001 end";
}

/**
 * @tc.name: DrawPixelmapPointLoopTest001
 * @tc.desc: Test pointLoop logic (pt.x < 0 → size.width + pt.x; pt.y < 0 → size.height + pt.y).
 * Expect TransformPixmap success.
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, DrawPixelmapPointLoopTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: DrawPixelmapPointLoopTest001 start";
    PixmapInfo inPixmap(false);
    inPixmap.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    inPixmap.imageInfo.size = {SRC_WIDTH_100, SRC_HEIGHT_100};
    inPixmap.data = new uint8_t[SRC_WIDTH_100 * SRC_HEIGHT_100 * UINT32_BYTE_SIZE];
    std::fill_n(inPixmap.data, SRC_WIDTH_100 * SRC_HEIGHT_100 * UINT32_BYTE_SIZE, 0xFF);
    BasicTransformer transformer;
    transformer.SetRotateParam(ROTATE_DEGREE);
    transformer.SetScaleParam(SCALE_FACTOR, SCALE_FACTOR);
    PixmapInfo outPixmap(false);
    uint32_t ret = transformer.TransformPixmap(inPixmap, outPixmap, nullptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS) << "TransformPixmap failed unexpectedly";
    EXPECT_NE(outPixmap.data, nullptr) << "outPixmap.data is null after success";
    EXPECT_EQ(outPixmap.bufferSize, static_cast<uint64_t>(DST_WIDTH_200 * DST_HEIGHT_200 * UINT32_BYTE_SIZE));
    
    delete[] inPixmap.data;
    delete[] outPixmap.data;
    inPixmap.data = nullptr;
    outPixmap.data = nullptr;

    GTEST_LOG_(INFO) << "BasicTransformerTest: DrawPixelmapPointLoopTest001 end";
}

/**
 * @tc.name: BilinearPixelProcRGB565Test001
 * @tc.desc: Test BilinearPixelProc with PixelFormat::RGB_565. Expect TransformPixmap success and correct pixel output.
 * @tc.type: FUNC
 */
HWTEST_F(BasicTransformerTest, BilinearPixelProcRGB565Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BasicTransformerTest: BilinearPixelProcRGB565Test001 start";
    const int32_t srcWidth = SRC_WIDTH_2;
    const int32_t srcHeight = SRC_HEIGHT_2;
    const int32_t pixelBytes = UINT16_BYTE_SIZE;
    PixmapInfo inPixmap(false);
    inPixmap.imageInfo.pixelFormat = PixelFormat::RGB_565;
    inPixmap.imageInfo.size = {srcWidth, srcHeight};
    inPixmap.data = new uint8_t[srcWidth * srcHeight * pixelBytes];
    uint16_t* srcPixels = reinterpret_cast<uint16_t*>(inPixmap.data);
    srcPixels[PIXEL_INDEX_0] = RGB565_RED;
    srcPixels[PIXEL_INDEX_1] = RGB565_GREEN;
    srcPixels[PIXEL_INDEX_2] = RGB565_BLUE;
    srcPixels[PIXEL_INDEX_3] = RGB565_YELLOW;
    BasicTransformer transformer;
    transformer.SetScaleParam(SCALE_1X, SCALE_1X);
    transformer.SetTranslateParam(TRANS_Y, TRANS_Y);
    PixmapInfo outPixmap(false);
    uint32_t ret = transformer.TransformPixmap(inPixmap, outPixmap, nullptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS) << "TransformPixmap failed for RGB_565 format";
    EXPECT_NE(outPixmap.data, nullptr) << "outPixmap.data is null for RGB_565 format";
    EXPECT_EQ(outPixmap.imageInfo.size.width, srcWidth) << "out width mismatch for RGB_565";
    EXPECT_EQ(outPixmap.imageInfo.size.height, srcHeight) << "out height mismatch for RGB_565";
    uint16_t* dstPixels = reinterpret_cast<uint16_t*>(outPixmap.data);
    EXPECT_NE(dstPixels[PIXEL_INDEX_0], 0x0000) << "RGB_565 red pixel not written";
    EXPECT_NE(dstPixels[PIXEL_INDEX_1], 0x0000) << "RGB_565 green pixel not written";
    EXPECT_NE(dstPixels[PIXEL_INDEX_2], 0x0000) << "RGB_565 blue pixel not written";
    EXPECT_NE(dstPixels[PIXEL_INDEX_3], 0x0000) << "RGB_565 yellow pixel not written";

    delete[] inPixmap.data;
    delete[] outPixmap.data;
    inPixmap.data = nullptr;
    outPixmap.data = nullptr;

    GTEST_LOG_(INFO) << "BasicTransformerTest: BilinearPixelProcRGB565Test001 end";
}
}
}