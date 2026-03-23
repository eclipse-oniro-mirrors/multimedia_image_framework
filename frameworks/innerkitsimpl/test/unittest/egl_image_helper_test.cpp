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

#include <limits>

#include "pixel_map_egl_utils.h"
#include "pixel_map_gl_common.h"
#include "pixel_map_gl_resource.h"
#include "pixel_map_gl_scope.h"
#include "pixel_map_gl_utils.h"
#include "pixel_map_program_manager_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
class EglImageHelperTest : public testing::Test {
public:
    EglImageHelperTest() = default;
    ~EglImageHelperTest() override = default;
};

/**
 * @tc.name: PixelMapEglUtilsInvalidHandleTest001
 * @tc.desc: Test EGL helper guards on invalid handles.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapEglUtilsInvalidHandleTest001, TestSize.Level3)
{
    EGLConfig config = nullptr;
    EGLContext context = EGL_NO_CONTEXT;
    EGLSurface surface = EGL_NO_SURFACE;

    EXPECT_FALSE(PixelMapEglUtils::ChooseDefaultConfig(EGL_NO_DISPLAY, config));
    EXPECT_FALSE(PixelMapEglUtils::CreateContext(EGL_NO_DISPLAY, config, context));
    EXPECT_FALSE(PixelMapEglUtils::CreatePbufferSurface(EGL_NO_DISPLAY, config, surface));

    PixelMapEglUtils::ResetCurrentContext(EGL_NO_DISPLAY, EGL_NO_CONTEXT);
    SUCCEED();
}

/**
 * @tc.name: PixelMapGlCommonTransformDefaultsTest001
 * @tc.desc: Test GPU transform data defaults for new DMA routing flags.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGlCommonTransformDefaultsTest001, TestSize.Level3)
{
    GPUTransformData transformData;
    EXPECT_EQ(transformData.glFormat, GL_RGBA);
    EXPECT_FALSE(transformData.isDma);
    EXPECT_FALSE(transformData.isSourceDma);
    EXPECT_FALSE(transformData.isTargetDma);
    EXPECT_EQ(transformData.sourceInfo_.addr, nullptr);
    EXPECT_EQ(transformData.sourceInfo_.context, nullptr);
    EXPECT_EQ(transformData.targetInfo_.outdata, nullptr);
    EXPECT_EQ(transformData.targetInfo_.context, nullptr);

    GlCommon::Mat4 identity;
    EXPECT_FLOAT_EQ(identity.at(0, 0), 1.0f);
    EXPECT_FLOAT_EQ(identity.at(1, 1), 1.0f);
    EXPECT_FLOAT_EQ(identity.at(2, 2), 1.0f);
    EXPECT_FLOAT_EQ(identity.at(3, 3), 1.0f);
}

/**
 * @tc.name: PixelMapGlResourceValidationTest001
 * @tc.desc: Test GL resource helper validation and default RAII states.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGlResourceValidationTest001, TestSize.Level3)
{
    size_t rowBytes = 0;
    size_t contiguousSize = 0;
    EXPECT_TRUE(PixelMapGlResource::IsValidGlTransferSize(0));
    EXPECT_TRUE(PixelMapGlResource::IsValidGlTransferSize(PixelMapGlResource::MAX_GL_TRANSFER_SIZE));
    EXPECT_FALSE(PixelMapGlResource::IsValidGlTransferSize(PixelMapGlResource::MAX_GL_TRANSFER_SIZE + 1));
    EXPECT_FALSE(PixelMapGlResource::ValidateTransferLayout(Size { 4, 3 }, 15, 4, rowBytes, contiguousSize));
    EXPECT_TRUE(PixelMapGlResource::ValidateTransferLayout(Size { 4, 3 }, 16, 4, rowBytes, contiguousSize));
    EXPECT_EQ(rowBytes, 16U);
    EXPECT_EQ(contiguousSize, 48U);

    PixelMapGlResource::ScopedNativeWindowBuffer nativeBuffer;
    EXPECT_EQ(nativeBuffer.Get(), nullptr);
    EXPECT_EQ(nativeBuffer.Release(), nullptr);

    PixelMapGlResource::ScopedEglImage eglImage;
    EXPECT_EQ(eglImage.Get(), EGL_NO_IMAGE_KHR);
    EXPECT_EQ(eglImage.Release(), EGL_NO_IMAGE_KHR);
}

/**
 * @tc.name: PixelMapGlScopeMoveTest001
 * @tc.desc: Test scope exit move semantics only trigger once.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGlScopeMoveTest001, TestSize.Level3)
{
    int callCount = 0;
    {
        auto guard = PixelMapGlScope::MakeScopeExit([&callCount] { ++callCount; });
        auto movedGuard = std::move(guard);
        (void)movedGuard;
    }
    EXPECT_EQ(callCount, 1);
}

/**
 * @tc.name: PixelMapProgramManagerUtilsStateTest001
 * @tc.desc: Test manager helper state calculation edge cases.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapProgramManagerUtilsStateTest001, TestSize.Level3)
{
    using namespace PixelMapProgramManagerUtils;
    EXPECT_FALSE(IsPoolStateValid(-1, 0));
    EXPECT_FALSE(CanCreateProgram(-1, MAX_GL_INSTANCE_NUM));
    EXPECT_TRUE(ShouldWaitForAvailableProgram(MAX_GL_INSTANCE_NUM, MAX_GL_INSTANCE_NUM, 0));
    EXPECT_TRUE(ShouldStopDestroyThread(0, 1));
    EXPECT_EQ(ComputeDestroySleepSeconds(100, 120, 4, MAX_GL_INSTANCE_NUM),
        PixelMapGlUtils::GetContextExpireDelaySec(4, MAX_GL_INSTANCE_NUM));
}

/**
 * @tc.name: PixelMapGlUtilsResolveDmaTransferModeTest002
 * @tc.desc: Test helper routes no-padding DMA to heap writeback.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGlUtilsResolveDmaTransferModeTest002, TestSize.Level3)
{
    auto mode = PixelMapGlUtils::ResolveDmaTransferMode(
        AllocatorType::DMA_ALLOC, std::numeric_limits<uint64_t>::max());
    EXPECT_TRUE(mode.isSourceDma);
    EXPECT_FALSE(mode.isTargetDma);
    EXPECT_TRUE(mode.isDma);
    EXPECT_EQ(mode.outputAllocType, AllocatorType::HEAP_ALLOC);
}
} // namespace Media
} // namespace OHOS
