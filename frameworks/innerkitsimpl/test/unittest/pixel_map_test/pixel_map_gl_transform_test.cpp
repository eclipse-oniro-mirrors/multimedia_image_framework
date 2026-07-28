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

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "image_type.h"
#include "image_utils.h"
#include "pixel_map.h"

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "pixel_map_gl_common.h"
#include "pixel_map_gl_utils.h"
#include "pixel_map_program_manager.h"
#endif

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {

namespace {
constexpr int32_t TEST_WIDTH = 128;
constexpr int32_t TEST_HEIGHT = 128;
constexpr int32_t RGBA_BYTES = 4;
constexpr uint8_t COLOR_R = 0x78;
constexpr uint8_t COLOR_G = 0x83;
constexpr uint8_t COLOR_B = 0xDF;
constexpr uint8_t COLOR_A = 0x52;

std::unique_ptr<PixelMap> CreateTestPixelMap(int32_t width, int32_t height, PixelFormat format)
{
    InitializationOptions options;
    options.size.width = width;
    options.size.height = height;
    options.srcPixelFormat = PixelFormat::RGBA_8888;
    options.pixelFormat = format;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    options.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    options.editable = true;

    int32_t colorLength = width * height * RGBA_BYTES;
    std::vector<uint8_t> buffer(colorLength, 0);
    for (int32_t i = 0; i < colorLength; i += RGBA_BYTES) {
        buffer[i] = COLOR_R;
        buffer[i + 1] = COLOR_G;
        buffer[i + 2] = COLOR_B;
        buffer[i + 3] = COLOR_A;
    }
    uint32_t *colors = reinterpret_cast<uint32_t *>(buffer.data());
    return PixelMap::Create(colors, colorLength, 0, width, options);
}
} // namespace

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)

class PixelMapGlTransformTest : public testing::Test {};

/**
 * @tc.name: ProgramManagerScaleSuccess001
 * @tc.desc: Drive PixelMapProgramManager scale pipeline end-to-end with real pixel data.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapGlTransformTest, ProgramManagerScaleSuccess001, TestSize.Level3)
{
    auto pixelMap = CreateTestPixelMap(TEST_WIDTH, TEST_HEIGHT, PixelFormat::RGBA_8888);
    ASSERT_NE(nullptr, pixelMap);

    auto *program = PixelMapProgramManager::GetInstance().GetProgram();
    if (program == nullptr) {
        GTEST_SKIP() << "EGL/GL program is unavailable on this target";
    }

    Size targetSize = { TEST_WIDTH * 2, TEST_HEIGHT * 2 };
    int32_t pixelBytes = ImageUtils::GetPixelBytes(PixelFormat::RGBA_8888);
    size_t targetBufSize = static_cast<size_t>(targetSize.width) * targetSize.height * pixelBytes;
    std::vector<uint8_t> targetBuf(targetBufSize, 0);

    GPUTransformData trans {};
    trans.transformationType = TransformationType::SCALE;
    trans.glFormat = GL_RGBA;
    trans.sourceInfo_.size = { pixelMap->GetWidth(), pixelMap->GetHeight() };
    trans.sourceInfo_.stride = pixelMap->GetRowStride();
    trans.sourceInfo_.pixelBytes = pixelBytes;
    trans.sourceInfo_.addr = pixelMap->GetPixels();
    trans.sourceInfo_.context = pixelMap->GetFd();
    trans.targetInfo_.size = targetSize;
    trans.targetInfo_.stride = targetSize.width * pixelBytes;
    trans.targetInfo_.pixelBytes = pixelBytes;
    trans.targetInfo_.outdata = targetBuf.data();
    auto dmaMode = PixelMapGlUtils::ResolveDmaTransferMode(pixelMap->GetAllocatorType(), 0);
    trans.isSourceDma = dmaMode.isSourceDma;
    trans.isTargetDma = dmaMode.isTargetDma;
    trans.isDma = dmaMode.isDma;

    program->SetGPUTransformData(trans);
    ASSERT_TRUE(PixelMapProgramManager::GetInstance().ExecutProgram(program));
    EXPECT_TRUE(std::any_of(targetBuf.begin(), targetBuf.end(),
        [](uint8_t value) { return value != 0; }));
}

/**
 * @tc.name: ProgramManagerRotateSuccess001
 * @tc.desc: Drive PixelMapProgramManager rotate pipeline end-to-end with real pixel data.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapGlTransformTest, ProgramManagerRotateSuccess001, TestSize.Level3)
{
    auto pixelMap = CreateTestPixelMap(TEST_WIDTH, TEST_HEIGHT, PixelFormat::RGBA_8888);
    ASSERT_NE(nullptr, pixelMap);

    auto *program = PixelMapProgramManager::GetInstance().GetProgram();
    if (program == nullptr) {
        GTEST_SKIP() << "EGL/GL program is unavailable on this target";
    }

    float degrees = 90.0f;
    float angle = degrees * static_cast<float>(M_PI) / 180.0f;
    int32_t srcW = pixelMap->GetWidth();
    int32_t srcH = pixelMap->GetHeight();
    Size targetSize = {
        static_cast<int32_t>(std::abs(srcW * std::cos(angle)) + std::abs(srcH * std::sin(angle))),
        static_cast<int32_t>(std::abs(srcH * std::cos(angle)) + std::abs(srcW * std::sin(angle)))
    };
    int32_t pixelBytes = ImageUtils::GetPixelBytes(PixelFormat::RGBA_8888);
    size_t targetBufSize = static_cast<size_t>(targetSize.width) * targetSize.height * pixelBytes;
    std::vector<uint8_t> targetBuf(targetBufSize, 0);

    GlCommon::Mat4 identity;
    std::array<float, 3> axis = { 0.0f, 0.0f, 1.0f };
    float rotDegrees = std::fmod(degrees, 360.0f);
    rotDegrees = std::fmod(360.0f - rotDegrees, 360.0f);

    GPUTransformData trans {};
    trans.transformationType = TransformationType::ROTATE;
    trans.glFormat = GL_RGBA;
    trans.rotateDegreeZ = rotDegrees;
    trans.rotateTrans = GlCommon::Mat4(identity, rotDegrees, axis);
    trans.sourceInfo_.size = { srcW, srcH };
    trans.sourceInfo_.stride = pixelMap->GetRowStride();
    trans.sourceInfo_.pixelBytes = pixelBytes;
    trans.sourceInfo_.addr = pixelMap->GetPixels();
    trans.sourceInfo_.context = pixelMap->GetFd();
    trans.targetInfo_.size = targetSize;
    trans.targetInfo_.stride = targetSize.width * pixelBytes;
    trans.targetInfo_.pixelBytes = pixelBytes;
    trans.targetInfo_.outdata = targetBuf.data();
    auto dmaMode = PixelMapGlUtils::ResolveDmaTransferMode(pixelMap->GetAllocatorType(), 0);
    trans.isSourceDma = dmaMode.isSourceDma;
    trans.isTargetDma = dmaMode.isTargetDma;
    trans.isDma = dmaMode.isDma;

    program->SetGPUTransformData(trans);
    ASSERT_TRUE(PixelMapProgramManager::GetInstance().ExecutProgram(program));
    EXPECT_TRUE(std::any_of(targetBuf.begin(), targetBuf.end(),
        [](uint8_t value) { return value != 0; }));
}

/**
 * @tc.name: ResolveDmaTransferModeDma001
 * @tc.desc: ResolveDmaTransferMode for DMA_ALLOC with zero noPaddingUsage (real DMA writeback).
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapGlTransformTest, ResolveDmaTransferModeDma001, TestSize.Level3)
{
    auto mode = PixelMapGlUtils::ResolveDmaTransferMode(AllocatorType::DMA_ALLOC, 0);
    EXPECT_TRUE(mode.isSourceDma);
    EXPECT_TRUE(mode.isTargetDma);
    EXPECT_TRUE(mode.isDma);
    EXPECT_EQ(mode.outputAllocType, AllocatorType::DMA_ALLOC);
}

/**
 * @tc.name: ResolveDmaTransferModeHeap001
 * @tc.desc: ResolveDmaTransferMode for HEAP_ALLOC.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapGlTransformTest, ResolveDmaTransferModeHeap001, TestSize.Level3)
{
    auto mode = PixelMapGlUtils::ResolveDmaTransferMode(AllocatorType::HEAP_ALLOC, 0);
    EXPECT_FALSE(mode.isSourceDma);
    EXPECT_FALSE(mode.isTargetDma);
    EXPECT_FALSE(mode.isDma);
    EXPECT_EQ(mode.outputAllocType, AllocatorType::HEAP_ALLOC);
}

/**
 * @tc.name: ResolveDmaTransferModeShareMem001
 * @tc.desc: ResolveDmaTransferMode for SHARE_MEM_ALLOC.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapGlTransformTest, ResolveDmaTransferModeShareMem001, TestSize.Level3)
{
    auto mode = PixelMapGlUtils::ResolveDmaTransferMode(AllocatorType::SHARE_MEM_ALLOC, 0);
    EXPECT_FALSE(mode.isSourceDma);
    EXPECT_FALSE(mode.isTargetDma);
    EXPECT_FALSE(mode.isDma);
    EXPECT_EQ(mode.outputAllocType, AllocatorType::SHARE_MEM_ALLOC);
}

#endif // !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)

} // namespace Multimedia
} // namespace OHOS