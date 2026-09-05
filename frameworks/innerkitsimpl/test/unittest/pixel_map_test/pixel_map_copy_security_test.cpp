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

#include <cstdlib>
#include <cstring>
#include <vector>
#include <gtest/gtest.h>

#include "image_utils.h"
#include "media_errors.h"
#include "memory_manager.h"
#include "pixel_astc.h"
#include "pixel_map.h"
#include "securec.h"

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "message_parcel.h"
#endif

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
namespace {
constexpr uint8_t PIXEL_VALUE = 0x5A;
constexpr uint8_t PADDING_VALUE = 0xA5;
constexpr int32_t COPY_WIDTH = 8;
constexpr int32_t COPY_HEIGHT = 8;
constexpr int32_t SOURCE_STRIDE = 4096;
constexpr int32_t DESTINATION_STRIDE = 64;
constexpr int32_t RGBA_BYTES = 4;

// Model a readable DMA source layout without requiring a device allocator.
// The backing allocation is still heap-owned so its lifetime is independent of the override.
class DmaLayoutPixelMap : public PixelMap {
public:
    AllocatorType GetAllocatorType() override
    {
        return AllocatorType::DMA_ALLOC;
    }
};

std::unique_ptr<PixelMap> MakeAstcPixelMap(PixelFormat format, int32_t capacityAdjustment = 0)
{
    ImageInfo info;
    info.size = {511, 511};
    info.pixelFormat = format;
    auto pixelMap = std::make_unique<PixelAstc>();
    if (pixelMap->SetImageInfo(info) != SUCCESS) {
        return nullptr;
    }
    const int32_t adjustedCapacity = static_cast<int32_t>(ImageUtils::GetAstcBytesCount(info)) + capacityAdjustment;
    if (adjustedCapacity <= 0) {
        return nullptr;
    }
    const uint32_t capacity = static_cast<uint32_t>(adjustedCapacity);
    void *pixels = malloc(capacity);
    if (pixels == nullptr) {
        return nullptr;
    }
    memset_s(pixels, capacity, PIXEL_VALUE, capacity);
    pixelMap->SetAstcRealSize(info.size);
    pixelMap->SetAstc(true);
    pixelMap->SetPixelsAddr(pixels, nullptr, capacity, AllocatorType::HEAP_ALLOC, nullptr);
    return pixelMap;
}

std::unique_ptr<PixelMap> MakeDmaLayoutPixelMap()
{
    auto pixelMap = std::make_unique<DmaLayoutPixelMap>();
    ImageInfo info;
    info.size = {COPY_WIDTH, COPY_HEIGHT};
    info.pixelFormat = PixelFormat::RGBA_8888;
    if (pixelMap->SetImageInfo(info) != SUCCESS) {
        return nullptr;
    }
    constexpr uint32_t capacity = SOURCE_STRIDE * COPY_HEIGHT;
    void *pixels = malloc(capacity);
    if (pixels == nullptr) {
        return nullptr;
    }
    memset_s(pixels, capacity, PIXEL_VALUE, capacity);
    pixelMap->SetPixelsAddr(pixels, nullptr, capacity, AllocatorType::HEAP_ALLOC, nullptr);
    pixelMap->SetRowStride(SOURCE_STRIDE);
    return pixelMap;
}

std::unique_ptr<PixelMap> MakeWritableRgbaPixelMap(const Size &size, uint32_t capacity)
{
    auto pixelMap = std::make_unique<PixelMap>();
    ImageInfo info;
    info.size = size;
    info.pixelFormat = PixelFormat::RGBA_8888;
    info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    if (pixelMap->SetImageInfo(info) != SUCCESS) {
        return nullptr;
    }
    void *pixels = malloc(capacity);
    if (pixels == nullptr) {
        return nullptr;
    }
    memset_s(pixels, capacity, PADDING_VALUE, capacity);
    pixelMap->SetPixelsAddr(pixels, nullptr, capacity, AllocatorType::HEAP_ALLOC, nullptr);
    pixelMap->SetEditable(true);
    return pixelMap;
}
} // namespace

class PixelMapCopySecurityTest : public testing::Test {};

/**
 * @tc.name: AstcByteCountUsesOriginalBlockDimensions
 * @tc.desc: Count compressed blocks, including partial blocks, after display dimensions change.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, AstcByteCountUsesOriginalBlockDimensions, TestSize.Level3)
{
    const PixelFormat formats[] = {PixelFormat::ASTC_4x4, PixelFormat::ASTC_6x6, PixelFormat::ASTC_8x8};
    const int32_t expectedSizes[] = {262160, 118352, 65552};
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        auto source = MakeAstcPixelMap(formats[i]);
        ASSERT_NE(source, nullptr);
        EXPECT_EQ(source->GetByteCount(), expectedSizes[i]);
        source->scale(0.5f, 0.5f);
        EXPECT_EQ(source->GetByteCount(), expectedSizes[i]);
        source->SetAstcRealSize({0, 511});
        EXPECT_EQ(source->GetByteCount(), 0);
    }
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
/**
 * @tc.name: CreateAstcWithDefaultOptionsPreservesCompressedData
 * @tc.desc: Default and matching-format creation use the ASTC clone with the exact source payload.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, CreateAstcWithDefaultOptionsPreservesCompressedData, TestSize.Level3)
{
    auto source = MakeAstcPixelMap(PixelFormat::ASTC_8x8);
    ASSERT_NE(source, nullptr);
    source->scale(0.5f, 0.5f);
    for (PixelFormat target : {PixelFormat::UNKNOWN, PixelFormat::ASTC_8x8}) {
        InitializationOptions opts;
        opts.pixelFormat = target;
        auto clone = PixelMap::Create(*source, opts);
        ASSERT_NE(clone, nullptr);
        EXPECT_TRUE(clone->IsAstc());
        EXPECT_EQ(clone->GetPixelFormat(), PixelFormat::ASTC_8x8);
        EXPECT_EQ(clone->GetByteCount(), 65552);
        EXPECT_EQ(clone->GetCapacity(), source->GetCapacity());
        EXPECT_NE(clone->GetPixels(), source->GetPixels());
        EXPECT_EQ(memcmp(clone->GetPixels(), source->GetPixels(), source->GetCapacity()), 0);
        EXPECT_EQ(clone->GetWidth(), source->GetWidth());
        Size realSize;
        clone->GetAstcRealSize(realSize);
        EXPECT_EQ(realSize.width, 511);
        TransformData sourceTransform;
        TransformData cloneTransform;
        source->GetTransformData(sourceTransform);
        clone->GetTransformData(cloneTransform);
        EXPECT_FLOAT_EQ(cloneTransform.scaleX, sourceTransform.scaleX);
        EXPECT_FLOAT_EQ(cloneTransform.scaleY, sourceTransform.scaleY);
    }
}

/**
 * @tc.name: CreateAstcRejectsTruncatedPayload
 * @tc.desc: A source one byte short of its compressed block size must not be cloned.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, CreateAstcRejectsTruncatedPayload, TestSize.Level3)
{
    auto source = MakeAstcPixelMap(PixelFormat::ASTC_8x8, -1);
    ASSERT_NE(source, nullptr);
    InitializationOptions opts;
    int32_t error = SUCCESS;
    auto clone = PixelMap::Create(*source, Rect{}, opts, error);
    EXPECT_EQ(clone, nullptr);
    EXPECT_NE(error, SUCCESS);
}

/**
 * @tc.name: UnmarshallingRejectsDmaDimensionMismatch
 * @tc.desc: Reject both the original transposed geometry and the shorter-height variant.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, UnmarshallingRejectsDmaDimensionMismatch, TestSize.Level3)
{
    for (const Size declaredSize : {Size{8, 1024}, Size{8, 8}, Size{1024, 8}}) {
        MemoryData data = {nullptr, 32768, "DmaGeometryTest", {1024, 8}, PixelFormat::RGBA_8888};
        auto memory = MemoryManager::CreateMemory(AllocatorType::DMA_ALLOC, data);
        ASSERT_NE(memory, nullptr);
        PixelMap source;
        ImageInfo info;
        info.size = declaredSize;
        info.pixelFormat = PixelFormat::RGBA_8888;
        ASSERT_EQ(source.SetImageInfo(info), SUCCESS);
        const uint32_t declaredBytes = declaredSize.width * declaredSize.height * RGBA_BYTES;
        source.SetPixelsAddr(memory->data.data, memory->extend.data, declaredBytes, AllocatorType::DMA_ALLOC, nullptr);
        MessageParcel parcel;
        ASSERT_TRUE(source.Marshalling(parcel));
        std::unique_ptr<PixelMap> received(PixelMap::Unmarshalling(parcel));
        EXPECT_EQ(received != nullptr, declaredSize.width == 1024);
    }
}
#endif

/**
 * @tc.name: CopyDmaRowsUsesDestinationStride
 * @tc.desc: Copy between different readable/writable layouts without overwriting destination padding.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, CopyDmaRowsUsesDestinationStride, TestSize.Level3)
{
    auto source = MakeDmaLayoutPixelMap();
    ASSERT_NE(source, nullptr);
    std::vector<uint8_t> destination(DESTINATION_STRIDE * COPY_HEIGHT, PADDING_VALUE);
    MemoryData data = {destination.data(), destination.size(), "CopyStrideTest",
        {DESTINATION_STRIDE / RGBA_BYTES, COPY_HEIGHT}, PixelFormat::RGBA_8888};
    auto memory = MemoryManager::CreateMemory(AllocatorType::HEAP_ALLOC, data);
    ASSERT_NE(memory, nullptr);
    ASSERT_TRUE(PixelMap::CopyPixMapToDst(*source, *memory, COPY_WIDTH * COPY_HEIGHT * RGBA_BYTES));
    for (int32_t row = 0; row < COPY_HEIGHT; ++row) {
        for (int32_t col = 0; col < DESTINATION_STRIDE; ++col) {
            EXPECT_EQ(destination[row * DESTINATION_STRIDE + col],
                col < COPY_WIDTH * RGBA_BYTES ? PIXEL_VALUE : PADDING_VALUE);
        }
    }
}

/**
 * @tc.name: CopyDmaRowsChecksBothLastRowBounds
 * @tc.desc: Accept an exact final-row boundary and reject source or destination one byte short before copying.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, CopyDmaRowsChecksBothLastRowBounds, TestSize.Level3)
{
    auto source = MakeDmaLayoutPixelMap();
    ASSERT_NE(source, nullptr);
    constexpr uint32_t destinationEnd = (COPY_HEIGHT - 1) * DESTINATION_STRIDE + COPY_WIDTH * RGBA_BYTES;
    std::vector<uint8_t> destination(destinationEnd, PADDING_VALUE);
    MemoryData data = {destination.data(), destination.size() - 1, "CopyCapacityTest",
        {DESTINATION_STRIDE / RGBA_BYTES, COPY_HEIGHT}, PixelFormat::RGBA_8888};
    auto memory = MemoryManager::CreateMemory(AllocatorType::HEAP_ALLOC, data);
    ASSERT_NE(memory, nullptr);
    EXPECT_FALSE(PixelMap::CopyPixMapToDst(*source, *memory, COPY_WIDTH * COPY_HEIGHT * RGBA_BYTES));
    EXPECT_EQ(destination.front(), PADDING_VALUE);
    memory->data.size = destination.size();
    source->pixelsSize_ = (COPY_HEIGHT - 1) * SOURCE_STRIDE + COPY_WIDTH * RGBA_BYTES - 1;
    EXPECT_FALSE(PixelMap::CopyPixMapToDst(*source, *memory, COPY_WIDTH * COPY_HEIGHT * RGBA_BYTES));
    EXPECT_EQ(destination.front(), PADDING_VALUE);
    ++source->pixelsSize_;
    EXPECT_TRUE(PixelMap::CopyPixMapToDst(*source, *memory, COPY_WIDTH * COPY_HEIGHT * RGBA_BYTES));
}

/**
 * @tc.name: CopyRejectsAstcOverread
 * @tc.desc: The copy sink rejects the old inflated size even if its destination is large enough.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, CopyRejectsAstcOverread, TestSize.Level3)
{
    auto source = MakeAstcPixelMap(PixelFormat::ASTC_8x8);
    ASSERT_NE(source, nullptr);
    constexpr uint32_t oldByteCount = 261632;
    std::vector<uint8_t> destination(oldByteCount, PADDING_VALUE);
    MemoryData data = {destination.data(), destination.size(), "AstcCopyTest", {511, 511}, PixelFormat::ASTC_8x8};
    auto memory = MemoryManager::CreateMemory(AllocatorType::HEAP_ALLOC, data);
    ASSERT_NE(memory, nullptr);
    EXPECT_FALSE(PixelMap::CopyPixMapToDst(*source, *memory, oldByteCount));
    EXPECT_EQ(destination.front(), PADDING_VALUE);
    EXPECT_TRUE(PixelMap::CopyPixMapToDst(*source, *memory, source->GetByteCount()));
    EXPECT_EQ(destination[source->GetByteCount() - 1], PIXEL_VALUE);
    EXPECT_EQ(destination[source->GetByteCount()], PADDING_VALUE);
}

/**
 * @tc.name: BaseWritePixelsRejectsYuvButVirtualWriteStillWorks
 * @tc.desc: Reject base YUV writes while preserving derived plane-aware writes for long inputs.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, BaseWritePixelsRejectsYuvButVirtualWriteStillWorks, TestSize.Level3)
{
    for (PixelFormat format : {PixelFormat::NV12, PixelFormat::NV21,
        PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010}) {
        InitializationOptions opts;
        opts.size = {64, 64};
        opts.pixelFormat = format;
        opts.allocatorType = AllocatorType::HEAP_ALLOC;
        opts.editable = true;
        auto pixelMap = PixelMap::Create(opts);
        ASSERT_NE(pixelMap, nullptr);
        const uint32_t capacity = pixelMap->GetCapacity();
        std::vector<uint8_t> input(capacity * 2, PIXEL_VALUE);
        EXPECT_EQ(pixelMap->PixelMap::WritePixels(input.data(), input.size()), ERR_IMAGE_INVALID_PARAMETER);
        EXPECT_EQ(pixelMap->WritePixels(input.data(), input.size()), SUCCESS);
        EXPECT_EQ(memcmp(pixelMap->GetPixels(), input.data(), capacity), 0);
    }
}

/**
 * @tc.name: WritePixelsRejectsInvalidDestinationStride
 * @tc.desc: Public stride changes must not cause partial writes, out-of-bounds writes or signed offset overflow.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, WritePixelsRejectsInvalidDestinationStride, TestSize.Level3)
{
    constexpr int32_t width = 2;
    constexpr uint32_t rowBytes = width * RGBA_BYTES;
    for (int32_t height : {2, 3}) {
        const uint32_t capacity = rowBytes * height;
        auto pixelMap = MakeWritableRgbaPixelMap({width, height}, capacity);
        ASSERT_NE(pixelMap, nullptr);
        std::vector<uint8_t> input(capacity, PIXEL_VALUE);
        std::vector<uint8_t> unchanged(capacity, PADDING_VALUE);
        for (uint32_t stride : {0U, rowBytes - 1, rowBytes * 2, 1U << 30, UINT32_MAX}) {
            pixelMap->SetRowStride(stride);
            EXPECT_EQ(pixelMap->WritePixels(input.data(), input.size()), ERR_IMAGE_WRITE_PIXELMAP_FAILED);
            EXPECT_EQ(memcmp(pixelMap->GetPixels(), unchanged.data(), capacity), 0);
        }
    }
}

/**
 * @tc.name: WritePixelsRejectsShortSourceDespiteSmallDeclaredCapacity
 * @tc.desc: The input must cover every source row even if the PixelMap advertises a smaller capacity.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, WritePixelsRejectsShortSourceDespiteSmallDeclaredCapacity, TestSize.Level3)
{
    constexpr uint32_t rowBytes = 2 * RGBA_BYTES;
    auto pixelMap = MakeWritableRgbaPixelMap({2, 2}, rowBytes);
    ASSERT_NE(pixelMap, nullptr);
    std::vector<uint8_t> unchanged(rowBytes, PADDING_VALUE);
    for (uint32_t inputSize : {rowBytes, rowBytes * 2 - 1}) {
        std::vector<uint8_t> input(inputSize, PIXEL_VALUE);
        EXPECT_EQ(pixelMap->WritePixels(input.data(), input.size()), ERR_IMAGE_INVALID_PARAMETER);
        EXPECT_EQ(memcmp(pixelMap->GetPixels(), unchanged.data(), unchanged.size()), 0);
    }
}

/**
 * @tc.name: WritePixelsRejectsDestinationOneByteShort
 * @tc.desc: Reject a padded destination that is one byte short of its final row before modifying any pixel.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, WritePixelsRejectsDestinationOneByteShort, TestSize.Level3)
{
    constexpr uint32_t rowBytes = 2 * RGBA_BYTES;
    constexpr uint32_t stride = rowBytes * 2;
    constexpr uint32_t capacity = stride + rowBytes - 1;
    auto pixelMap = MakeWritableRgbaPixelMap({2, 2}, capacity);
    ASSERT_NE(pixelMap, nullptr);
    pixelMap->SetRowStride(stride);
    std::vector<uint8_t> input(capacity, PIXEL_VALUE);
    std::vector<uint8_t> unchanged(capacity, PADDING_VALUE);
    EXPECT_EQ(pixelMap->WritePixels(input.data(), input.size()), ERR_IMAGE_WRITE_PIXELMAP_FAILED);
    EXPECT_EQ(memcmp(pixelMap->GetPixels(), unchanged.data(), capacity), 0);
}

/**
 * @tc.name: WritePixelsPreservesPaddingAndAcceptsExactBounds
 * @tc.desc: Accept contiguous and padded layouts with exact or larger input, preserving all destination padding.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapCopySecurityTest, WritePixelsPreservesPaddingAndAcceptsExactBounds, TestSize.Level3)
{
    constexpr uint32_t rowBytes = 2 * RGBA_BYTES;
    for (uint32_t stride : {rowBytes, rowBytes * 2}) {
        for (uint32_t capacity : {stride + rowBytes, stride * 2}) {
            for (uint32_t inputSize : {capacity, capacity * 2}) {
                auto pixelMap = MakeWritableRgbaPixelMap({2, 2}, capacity);
                ASSERT_NE(pixelMap, nullptr);
                pixelMap->SetRowStride(stride);
                std::vector<uint8_t> input(inputSize);
                for (uint32_t i = 0; i < inputSize; ++i) {
                    input[i] = static_cast<uint8_t>(i + 1);
                }
                std::vector<uint8_t> expected(capacity, PADDING_VALUE);
                for (uint32_t row = 0; row < 2; ++row) {
                    for (uint32_t col = 0; col < rowBytes; ++col) {
                        expected[row * stride + col] = input[row * rowBytes + col];
                    }
                }
                EXPECT_EQ(pixelMap->WritePixels(input.data(), input.size()), SUCCESS);
                EXPECT_EQ(memcmp(pixelMap->GetPixels(), expected.data(), capacity), 0);
            }
        }
    }
}
} // namespace Multimedia
} // namespace OHOS
