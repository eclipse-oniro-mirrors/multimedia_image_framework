/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <sys/mman.h>
#include <cstdint>
#include <limits>
#include <numeric>
#include <vector>

#include "pixel_map_gl_scope.h"
#include "native_window.h"
#include "pixel_map_gl_resource.h"
#include "pixel_map_gl_utils.h"
#include "pixel_map_program_manager_utils.h"
#include "pixel_map_from_surface.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
static constexpr int DEFAULT_WIDTH = 1280;
static constexpr int DEFAULT_HEIGHT = 800;

class EglImageTest : public testing::Test {
public:
    EglImageTest() {}
    ~EglImageTest() {}
};

/**
 * @tc.name: PixelMapFromSurfaceTest001
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest001, TestSize.Level3)
{
    Rect srcRect = {0, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    // pass an invalid surfaceId to expect to get an invalid result.
    auto pixelMap = CreatePixelMapFromSurfaceId(0, srcRect);
    EXPECT_EQ(pixelMap, nullptr);
}

/**
 * @tc.name: PixelMapGlUtilsRectValidationTest001
 * @tc.desc: Test overflow-safe rect validation helper.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapGlUtilsRectValidationTest001, TestSize.Level3)
{
    EXPECT_TRUE(PixelMapGlUtils::IsRectInBounds(Rect{0, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT},
        DEFAULT_WIDTH, DEFAULT_HEIGHT));
    EXPECT_FALSE(PixelMapGlUtils::IsRectInBounds(Rect{DEFAULT_WIDTH / 2, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT},
        DEFAULT_WIDTH, DEFAULT_HEIGHT));
    EXPECT_FALSE(PixelMapGlUtils::IsRectInBounds(
        Rect{std::numeric_limits<int32_t>::max() - 2, 0, 4, 1}, DEFAULT_WIDTH, DEFAULT_HEIGHT));
}

/**
 * @tc.name: PixelMapGlUtilsImageLayoutTest001
 * @tc.desc: Test row bytes and packed buffer validation helper.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapGlUtilsImageLayoutTest001, TestSize.Level3)
{
    size_t rowBytes = 0;
    size_t contiguousSize = 0;
    EXPECT_TRUE(PixelMapGlUtils::ValidateImageLayout(Size{4, 3}, 16, 4, rowBytes, contiguousSize));
    EXPECT_EQ(rowBytes, 16);
    EXPECT_EQ(contiguousSize, 48);
    EXPECT_FALSE(PixelMapGlUtils::ComputeRowBytes(std::numeric_limits<int32_t>::max(), 2, rowBytes));
    EXPECT_FALSE(PixelMapGlUtils::ValidateImageLayout(Size{4, 3}, 15, 4, rowBytes, contiguousSize));
    EXPECT_FALSE(PixelMapGlUtils::ComputePackedBufferSize(
        Size{std::numeric_limits<int32_t>::max(), std::numeric_limits<int32_t>::max()}, 8, contiguousSize));
}

/**
 * @tc.name: PixelMapGlUtilsBuildSlrWeightsTest001
 * @tc.desc: Test SLR weight generation is bounded and normalized.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapGlUtilsBuildSlrWeightsTest001, TestSize.Level3)
{
    auto weights = PixelMapGlUtils::BuildSlrWeights(0.0f, 3);
    ASSERT_EQ(weights.size(), static_cast<size_t>(3 * PixelMapGlUtils::MAX_SLR_WIN_SIZE));
    for (int row = 0; row < 3; ++row) {
        const auto begin = weights.begin() + row * PixelMapGlUtils::MAX_SLR_WIN_SIZE;
        const auto end = begin + PixelMapGlUtils::MAX_SLR_WIN_SIZE;
        float sum = std::accumulate(begin, end, 0.0f);
        EXPECT_NEAR(sum, 1.0f, 1e-4f);
    }
    EXPECT_TRUE(PixelMapGlUtils::BuildSlrWeights(1.0f, 0).empty());
}

/**
 * @tc.name: PixelMapGlUtilsContextExpireDelayTest001
 * @tc.desc: Test manager destroy delay helper.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapGlUtilsContextExpireDelayTest001, TestSize.Level3)
{
    EXPECT_EQ(PixelMapGlUtils::GetContextExpireDelaySec(1, 8), PixelMapGlUtils::MAX_CONTEXT_EXPIRED_TIME_SEC);
    EXPECT_EQ(PixelMapGlUtils::GetContextExpireDelaySec(8, 8), PixelMapGlUtils::MIN_CONTEXT_EXPIRED_TIME_SEC);
    EXPECT_EQ(PixelMapGlUtils::GetContextExpireDelaySec(5, 8), PixelMapGlUtils::MIN_CONTEXT_EXPIRED_TIME_SEC * 4);
}

/**
 * @tc.name: PixelMapGlResourceCopyHelpersTest001
 * @tc.desc: Test strided/linear copy helpers.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapGlResourceCopyHelpersTest001, TestSize.Level3)
{
    constexpr int32_t width = 2;
    constexpr int32_t height = 2;
    constexpr int32_t pixelBytes = 4;
    constexpr int32_t stride = 12;
    constexpr size_t rowBytes = static_cast<size_t>(width) * static_cast<size_t>(pixelBytes);
    const std::vector<uint8_t> src = {
        1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0,
        9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0
    };
    std::vector<char> linear(16, 0);
    EXPECT_TRUE(PixelMapGlResource::CopyStridedToLinear(
        src.data(), stride, height, rowBytes, linear.data(), linear.size()));
    EXPECT_EQ(static_cast<uint8_t>(linear[0]), 1);
    EXPECT_EQ(static_cast<uint8_t>(linear[7]), 8);
    EXPECT_EQ(static_cast<uint8_t>(linear[8]), 9);
    EXPECT_EQ(static_cast<uint8_t>(linear[15]), 16);

    std::vector<uint8_t> dst(static_cast<size_t>(stride) * height, 0);
    EXPECT_TRUE(PixelMapGlResource::CopyLinearToStrided(
        linear.data(), linear.size(), rowBytes, height, dst.data(), stride));
    EXPECT_EQ(dst[0], 1);
    EXPECT_EQ(dst[7], 8);
    EXPECT_EQ(dst[12], 9);
    EXPECT_EQ(dst[19], 16);
}

/**
 * @tc.name: PixelMapGlResourceScopedHandleTest001
 * @tc.desc: Test GL scoped handle wrappers keep ownership transitions predictable.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapGlResourceScopedHandleTest001, TestSize.Level3)
{
    PixelMapGlResource::ScopedTexture texture;
    EXPECT_EQ(texture.Get(), 0U);
    texture.Reset(0U);
    EXPECT_EQ(texture.Release(), 0U);

    PixelMapGlResource::ScopedBuffer buffer;
    EXPECT_EQ(buffer.Get(), 0U);
    PixelMapGlResource::ScopedBuffer movedBuffer(std::move(buffer));
    EXPECT_EQ(movedBuffer.Get(), 0U);
    EXPECT_EQ(buffer.Get(), 0U);

    PixelMapGlResource::ScopedFramebuffer framebuffer;
    EXPECT_EQ(framebuffer.Get(), 0U);
    framebuffer.Reset(0U);
    EXPECT_EQ(framebuffer.Get(), 0U);
}

/**
 * @tc.name: PixelMapGlScopeExitTest001
 * @tc.desc: Test scope exit helper executes once unless released.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapGlScopeExitTest001, TestSize.Level3)
{
    int callCount = 0;
    {
        auto guard = PixelMapGlScope::MakeScopeExit([&callCount] { ++callCount; });
        EXPECT_EQ(callCount, 0);
        guard.Release();
    }
    EXPECT_EQ(callCount, 0);
    {
        auto guard = PixelMapGlScope::MakeScopeExit([&callCount] { ++callCount; });
        (void)guard;
    }
    EXPECT_EQ(callCount, 1);
}

/**
 * @tc.name: PixelMapProgramManagerUtilsTest001
 * @tc.desc: Test program manager pool helpers.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapProgramManagerUtilsTest001, TestSize.Level3)
{
    using namespace PixelMapProgramManagerUtils;
    EXPECT_TRUE(IsPoolStateValid(4, 2));
    EXPECT_FALSE(IsPoolStateValid(1, 2));
    EXPECT_TRUE(CanCreateProgram(3, MAX_GL_INSTANCE_NUM));
    EXPECT_FALSE(CanCreateProgram(MAX_GL_INSTANCE_NUM, MAX_GL_INSTANCE_NUM));
    EXPECT_TRUE(ShouldWaitForAvailableProgram(MAX_GL_INSTANCE_NUM, MAX_GL_INSTANCE_NUM, 0));
    EXPECT_FALSE(ShouldWaitForAvailableProgram(MAX_GL_INSTANCE_NUM - 1, MAX_GL_INSTANCE_NUM, 0));
    EXPECT_TRUE(ShouldStopDestroyThread(0, 1));
    EXPECT_TRUE(ShouldStopDestroyThread(2, 0));
    EXPECT_FALSE(ShouldStopDestroyThread(2, 1));
    EXPECT_EQ(ComputeDestroySleepSeconds(100, 100, 2, MAX_GL_INSTANCE_NUM),
        PixelMapGlUtils::GetContextExpireDelaySec(2, MAX_GL_INSTANCE_NUM));
    EXPECT_EQ(ComputeDestroySleepSeconds(115, 100, MAX_GL_INSTANCE_NUM, MAX_GL_INSTANCE_NUM), 0);
}

/**
 * @tc.name: PixelMapGlUtilsComputeLapSharpenAlphaTest001
 * @tc.desc: Test Lap sharpen parameter helper thresholds.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapGlUtilsComputeLapSharpenAlphaTest001, TestSize.Level3)
{
    EXPECT_FLOAT_EQ(PixelMapGlUtils::ComputeLapSharpenAlpha(0.81f), 0.0f);
    EXPECT_FLOAT_EQ(PixelMapGlUtils::ComputeLapSharpenAlpha(0.7f), 0.06f);
    EXPECT_FLOAT_EQ(PixelMapGlUtils::ComputeLapSharpenAlpha(0.55f), 0.1f);
    EXPECT_FLOAT_EQ(PixelMapGlUtils::ComputeLapSharpenAlpha(0.4f), 0.15f);
}

/**
 * @tc.name: PixelMapGlUtilsResolveDmaTransferModeTest001
 * @tc.desc: Test DMA input/output routing for GPU post-processing.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapGlUtilsResolveDmaTransferModeTest001, TestSize.Level3)
{
    auto heapMode = PixelMapGlUtils::ResolveDmaTransferMode(AllocatorType::HEAP_ALLOC, 0);
    EXPECT_EQ(heapMode.outputAllocType, AllocatorType::HEAP_ALLOC);
    EXPECT_FALSE(heapMode.isSourceDma);
    EXPECT_FALSE(heapMode.isTargetDma);
    EXPECT_FALSE(heapMode.isDma);

    auto dmaMode = PixelMapGlUtils::ResolveDmaTransferMode(AllocatorType::DMA_ALLOC, 0);
    EXPECT_EQ(dmaMode.outputAllocType, AllocatorType::DMA_ALLOC);
    EXPECT_TRUE(dmaMode.isSourceDma);
    EXPECT_TRUE(dmaMode.isTargetDma);
    EXPECT_TRUE(dmaMode.isDma);

    auto noPaddingDmaMode = PixelMapGlUtils::ResolveDmaTransferMode(
        AllocatorType::DMA_ALLOC, static_cast<uint64_t>(1));
    EXPECT_EQ(noPaddingDmaMode.outputAllocType, AllocatorType::HEAP_ALLOC);
    EXPECT_TRUE(noPaddingDmaMode.isSourceDma);
    EXPECT_FALSE(noPaddingDmaMode.isTargetDma);
    EXPECT_TRUE(noPaddingDmaMode.isDma);
}
}
}
