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

#include <cmath>
#include <limits>

#include "pixel_map_egl_utils.h"
#include "pixel_map_from_surface.h"
#include "pixel_map_gl_common.h"
#include "pixel_map_gl_context.h"
#include "pixel_map_gl_post_proc_program.h"
#include "pixel_map_gl_resource.h"
#include "pixel_map_gl_scope.h"
#include "pixel_map_gl_shader.h"
#include "pixel_map_gl_utils.h"
#include "pixel_map_program_manager.h"
#include "pixel_map_program_manager_utils.h"
#include "render_context.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
class EglImageHelperTest : public testing::Test {
public:
    EglImageHelperTest() = default;
    ~EglImageHelperTest() override = default;
};

class TestShader : public PixelMapGlShader::Shader {
public:
    bool Clear() override
    {
        return Shader::Clear();
    }

    void SetTargetSize(const Size &targetSize)
    {
        targetSize_ = targetSize;
    }
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
 * @tc.name: PixelMapGlCommonMat4OperationsTest001
 * @tc.desc: Test Mat4 constructors, multiply path and zero-axis rotation stay finite.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGlCommonMat4OperationsTest001, TestSize.Level3)
{
    GlCommon::Mat4 filled(2.0f);
    EXPECT_FLOAT_EQ(filled.at(0, 0), 2.0f);
    EXPECT_FLOAT_EQ(filled.at(3, 3), 2.0f);

    std::array<std::array<float, GlCommon::NUM_4>, GlCommon::NUM_4> values = {{
        {{1.0f, 2.0f, 3.0f, 4.0f}},
        {{5.0f, 6.0f, 7.0f, 8.0f}},
        {{9.0f, 10.0f, 11.0f, 12.0f}},
        {{13.0f, 14.0f, 15.0f, 16.0f}},
    }};
    GlCommon::Mat4 fromArray(values);
    EXPECT_FLOAT_EQ(fromArray.at(2, 1), 10.0f);

    GlCommon::Mat4 rotated(fromArray, GlCommon::DEGREES_90, {0.0f, 0.0f, 0.0f});
    for (int row = 0; row < GlCommon::NUM_4; ++row) {
        for (int col = 0; col < GlCommon::NUM_4; ++col) {
            EXPECT_TRUE(std::isfinite(rotated.at(row, col)));
        }
    }

    GlCommon::Mat4 result = filled * fromArray;
    EXPECT_FLOAT_EQ(result.at(0, 0), 56.0f);
    EXPECT_FLOAT_EQ(result.at(3, 3), 80.0f);
    EXPECT_NE(result.GetDataPtr(), nullptr);
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
    EXPECT_FALSE(PixelMapGlResource::IsValidGlTransferSize(Size { 0, 1 }));
    EXPECT_TRUE(PixelMapGlResource::IsValidGlTransferSize(
        Size { PixelMapGlResource::MAX_GL_TRANSFER_DIMENSION, PixelMapGlResource::MAX_GL_TRANSFER_DIMENSION }));
    EXPECT_FALSE(PixelMapGlResource::IsValidGlTransferSize(
        Size { PixelMapGlResource::MAX_GL_TRANSFER_DIMENSION + 1, PixelMapGlResource::MAX_GL_TRANSFER_DIMENSION }));
    EXPECT_FALSE(PixelMapGlResource::ValidateTransferLayout(Size { 4, 3 }, 15, 4, rowBytes, contiguousSize));
    EXPECT_TRUE(PixelMapGlResource::ValidateTransferLayout(Size { 4, 3 }, 16, 4, rowBytes, contiguousSize));
    EXPECT_EQ(rowBytes, 16U);
    EXPECT_EQ(contiguousSize, 48U);
    EXPECT_FALSE(PixelMapGlResource::ValidateTransferLayout(
        Size { PixelMapGlResource::MAX_GL_TRANSFER_DIMENSION + 1, 1 },
        (PixelMapGlResource::MAX_GL_TRANSFER_DIMENSION + 1) * 4, 4, rowBytes, contiguousSize));

    PixelMapGlResource::ScopedNativeWindowBuffer nativeBuffer;
    EXPECT_EQ(nativeBuffer.Get(), nullptr);
    EXPECT_EQ(nativeBuffer.Release(), nullptr);

    PixelMapGlResource::ScopedEglImage eglImage;
    EXPECT_EQ(eglImage.Get(), EGL_NO_IMAGE_KHR);
    EXPECT_EQ(eglImage.Release(), EGL_NO_IMAGE_KHR);
}

/**
 * @tc.name: PixelMapGlResourceCopyFailureTest001
 * @tc.desc: Test GL resource copy helpers reject invalid layouts and truncated buffers.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGlResourceCopyFailureTest001, TestSize.Level3)
{
    constexpr size_t rowBytes = 8;
    const uint8_t src[12] = {0};
    char dst[16] = {0};
    EXPECT_FALSE(PixelMapGlResource::CopyStridedToLinear(nullptr, 8, 2, rowBytes, dst, sizeof(dst)));
    EXPECT_FALSE(PixelMapGlResource::CopyStridedToLinear(src, 8, 3, rowBytes, dst, sizeof(dst)));

    const char linear[16] = {0};
    uint8_t strided[12] = {0};
    EXPECT_FALSE(PixelMapGlResource::CopyLinearToStrided(nullptr, sizeof(linear), rowBytes, 2, strided, 8));
    EXPECT_FALSE(PixelMapGlResource::CopyLinearToStrided(linear, 4, rowBytes, 2, strided, 8));
    EXPECT_FALSE(PixelMapGlResource::CopyLinearToStrided(linear, sizeof(linear), rowBytes, 2, strided, 4));

    PixelMapGlResource::ScopedFramebuffer framebuffer(0U);
    PixelMapGlResource::ScopedFramebuffer movedFramebuffer(std::move(framebuffer));
    EXPECT_EQ(framebuffer.Get(), 0U);
    EXPECT_EQ(movedFramebuffer.Release(), 0U);
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
 * @tc.name: PixelMapProgramManagerUtilsStateTest002
 * @tc.desc: Test manager helper calculation for elapsed timeout and negative states.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapProgramManagerUtilsStateTest002, TestSize.Level3)
{
    using namespace PixelMapProgramManagerUtils;
    EXPECT_FALSE(ShouldWaitForAvailableProgram(MAX_GL_INSTANCE_NUM - 1, MAX_GL_INSTANCE_NUM, 0));
    EXPECT_FALSE(ShouldStopDestroyThread(2, 1));
    EXPECT_EQ(ComputeDestroySleepSeconds(115, 100, MAX_GL_INSTANCE_NUM, MAX_GL_INSTANCE_NUM), 0);
    EXPECT_EQ(ComputeDestroySleepSeconds(100, 0, 3, MAX_GL_INSTANCE_NUM),
        PixelMapGlUtils::GetContextExpireDelaySec(3, MAX_GL_INSTANCE_NUM));
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

/**
 * @tc.name: PixelMapGlUtilsMathEdgeTest001
 * @tc.desc: Test GL util overflow guards, SLR kernel edge branches and sharpen alpha thresholds.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGlUtilsMathEdgeTest001, TestSize.Level3)
{
    EXPECT_TRUE(PixelMapGlUtils::IsInt32MulOverflow(0, 2));
    EXPECT_FALSE(PixelMapGlUtils::IsInt32MulOverflow(2, 3));

    size_t rowBytes = 0;
    size_t contiguousSize = 0;
    EXPECT_FALSE(PixelMapGlUtils::ComputeRowBytes(0, 4, rowBytes));
    EXPECT_FALSE(PixelMapGlUtils::ComputePackedBufferSize(Size { 0, 1 }, 4, contiguousSize));
    EXPECT_FLOAT_EQ(PixelMapGlUtils::GeSLRFactor(2.0f, 2), 0.0f);
    EXPECT_FLOAT_EQ(PixelMapGlUtils::GeSLRFactor(0.0f, 2), 0.0f);
    EXPECT_TRUE(std::isfinite(PixelMapGlUtils::GeSLRFactor(0.5f, 2)));

    auto weights = PixelMapGlUtils::BuildSlrWeights(std::numeric_limits<float>::infinity(), 2);
    EXPECT_EQ(weights.size(), static_cast<size_t>(2 * PixelMapGlUtils::MAX_SLR_WIN_SIZE));
    EXPECT_FLOAT_EQ(PixelMapGlUtils::ComputeLapSharpenAlpha(0.5f), 0.15f);
}

/**
 * @tc.name: PixelMapContextInvalidStateTest001
 * @tc.desc: Test RenderContext and PixelMapGlContext guard branches without initialized EGL state.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapContextInvalidStateTest001, TestSize.Level3)
{
    PixelMapGlContext glContext(false);
    EXPECT_FALSE(glContext.CreatePbufferSurface());
    EXPECT_FALSE(glContext.MakeCurrentSimple(true));
    EXPECT_FALSE(glContext.MakeCurrentSimple(false));
    glContext.MakeCurrent(EGL_NO_SURFACE);
    glContext.Clear();

    RenderContext renderContext;
    EXPECT_FALSE(renderContext.CreatePbufferSurface());
    renderContext.MakeCurrent(EGL_NO_SURFACE);
    renderContext.Clear();
    SUCCEED();
}

/**
 * @tc.name: PixelMapGlShaderFactoryAndParamsTest001
 * @tc.desc: Test shader factory, parameter validation and write-texture guard branch.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGlShaderFactoryAndParamsTest001, TestSize.Level3)
{
    auto invalidShader = PixelMapGlShader::ShaderFactory::GetInstance().Get(PixelMapGlShader::SHADER_INVALID);
    EXPECT_EQ(invalidShader, nullptr);

    auto vertexShader = PixelMapGlShader::ShaderFactory::GetInstance().Get(PixelMapGlShader::SHADER_VERTEX);
    auto rotateShader = PixelMapGlShader::ShaderFactory::GetInstance().Get(PixelMapGlShader::SHADER_ROTATE);
    auto slrShader = PixelMapGlShader::ShaderFactory::GetInstance().Get(PixelMapGlShader::SHADER_SLR);
    auto lapShader = PixelMapGlShader::ShaderFactory::GetInstance().Get(PixelMapGlShader::SHADER_LAP);
    ASSERT_NE(vertexShader, nullptr);
    ASSERT_NE(rotateShader, nullptr);
    ASSERT_NE(slrShader, nullptr);
    ASSERT_NE(lapShader, nullptr);
    EXPECT_EQ(vertexShader->GetShaderType(), PixelMapGlShader::SHADER_VERTEX);
    EXPECT_EQ(rotateShader->GetShaderType(), PixelMapGlShader::SHADER_ROTATE);
    EXPECT_EQ(slrShader->GetShaderType(), PixelMapGlShader::SHADER_SLR);
    EXPECT_EQ(lapShader->GetShaderType(), PixelMapGlShader::SHADER_LAP);

    GPUTransformData transformData {};
    transformData.rotateDegreeZ = GlCommon::DEGREES_180;
    transformData.rotateTrans = GlCommon::Mat4(1.0f);
    transformData.sourceInfo_.size = { 0, 4 };
    transformData.targetInfo_.size = { 8, 8 };
    EXPECT_TRUE(rotateShader->SetParams(transformData));
    EXPECT_FALSE(lapShader->SetParams(transformData));

    TestShader testShader;
    testShader.SetReadTexId(5U);
    testShader.SetWriteTexId(7U);
    EXPECT_EQ(testShader.GetReadTexId(), 5U);
    EXPECT_EQ(testShader.GetWriteTexId(), 7U);
    testShader.SetTargetSize(Size { 0, 8 });
    EXPECT_FALSE(testShader.BuildWriteTexture());
}

/**
 * @tc.name: PixelMapProgramExecutionGuardTest001
 * @tc.desc: Test post processing program and manager guard branches without GL context.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapProgramExecutionGuardTest001, TestSize.Level3)
{
    PixelMapGLPostProcProgram program;
    EXPECT_FALSE(program.Execute());

    GPUTransformData transformData {};
    transformData.transformationType = static_cast<TransformationType>(0);
    program.SetGPUTransformData(transformData);
    char output = 0;
    EXPECT_TRUE(program.GenProcEndData(&output));
    EXPECT_TRUE(program.GenProcDmaEndData(reinterpret_cast<void *>(0x1)));

    EXPECT_FALSE(PixelMapProgramManager::ExecutProgram(nullptr));
}

/**
 * @tc.name: PixelMapFromSurfaceInterfaceGuardTest001
 * @tc.desc: Test PixelMapFromSurface public create interface rejects invalid parameters consistently.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapFromSurfaceInterfaceGuardTest001, TestSize.Level3)
{
    PixelMapFromSurface helper;
    EXPECT_EQ(helper.Create(0, Rect { 0, 0, 1, 1 }), nullptr);
    EXPECT_EQ(helper.Create(1, Rect { -1, 0, 1, 1 }), nullptr);
    EXPECT_EQ(helper.Create(1, Rect { 0, 0, 0, 1 }), nullptr);
}

/**
 * @tc.name: PixelMapGlContextInterfaceLifecycleTest001
 * @tc.desc: Test PixelMapGlContext public lifecycle methods across init, make-current and clear.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGlContextInterfaceLifecycleTest001, TestSize.Level3)
{
    PixelMapGlContext context;
    const bool inited = context.Init();
    if (!inited) {
        SUCCEED();
        return;
    }

    EXPECT_NE(context.GetEGLContext(), EGL_NO_CONTEXT);
    EXPECT_NE(context.GetEGLDisplay(), EGL_NO_DISPLAY);
    EXPECT_NE(context.pbufferSurface_, EGL_NO_SURFACE);
    EXPECT_TRUE(context.CreatePbufferSurface());
    EXPECT_TRUE(context.MakeCurrentSimple(true));
    EXPECT_TRUE(context.MakeCurrentSimple(true));
    EXPECT_TRUE(context.MakeCurrentSimple(false));
    context.MakeCurrent(EGL_NO_SURFACE);
    context.Clear();
    EXPECT_EQ(context.GetEGLContext(), EGL_NO_CONTEXT);
    EXPECT_EQ(context.pbufferSurface_, EGL_NO_SURFACE);
}

/**
 * @tc.name: RenderContextInterfaceLifecycleTest001
 * @tc.desc: Test RenderContext public lifecycle methods across EGL init, make-current and clear.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, RenderContextInterfaceLifecycleTest001, TestSize.Level3)
{
    RenderContext context;
    const bool initEglRet = context.InitEGLContext();
    if (!initEglRet) {
        SUCCEED();
        return;
    }

    EXPECT_NE(context.GetEGLContext(), EGL_NO_CONTEXT);
    EXPECT_NE(context.GetEGLDisplay(), EGL_NO_DISPLAY);
    EXPECT_NE(context.pbufferSurface_, EGL_NO_SURFACE);
    EXPECT_TRUE(context.CreatePbufferSurface());
    context.MakeCurrent(EGL_NO_SURFACE);
    context.Clear();
    EXPECT_EQ(context.GetEGLContext(), EGL_NO_CONTEXT);
    EXPECT_EQ(context.GetEGLDisplay(), EGL_NO_DISPLAY);
    EXPECT_EQ(context.pbufferSurface_, EGL_NO_SURFACE);
}

/**
 * @tc.name: PixelMapGlShaderInterfaceGuardTest002
 * @tc.desc: Test shader public use-path guards for invalid image sizes.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGlShaderInterfaceGuardTest002, TestSize.Level3)
{
    PixelMapGlShader::RotateShader rotateShader;
    PixelMapGlShader::SLRShader slrShader;
    PixelMapGlShader::LapShader lapShader;

    EXPECT_FALSE(rotateShader.Use());
    EXPECT_FALSE(slrShader.Use());
    EXPECT_FALSE(lapShader.Use());
}

/**
 * @tc.name: PixelMapProgramManagerInterfaceTest001
 * @tc.desc: Test shader build caching and program acquisition interfaces.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapProgramManagerInterfaceTest001, TestSize.Level3)
{
    const bool firstBuildRet = PixelMapGLPostProcProgram::BuildShader();
    const bool secondBuildRet = PixelMapProgramManager::BuildShader();
    EXPECT_EQ(firstBuildRet, secondBuildRet);

    PixelMapGLPostProcProgram *program = PixelMapProgramManager::GetInstance().GetProgram();
    if (program == nullptr) {
        SUCCEED();
        return;
    }
    EXPECT_FALSE(PixelMapProgramManager::ExecutProgram(program));
}

/**
 * @tc.name: PixelMapGLPostProcProgramInterfaceTest001
 * @tc.desc: Test post processing program public init path and default execute branch.
 * @tc.type: FUNC
 */
HWTEST_F(EglImageHelperTest, PixelMapGLPostProcProgramInterfaceTest001, TestSize.Level3)
{
    PixelMapGLPostProcProgram program;
    const bool initRet = program.Init();
    if (!initRet) {
        SUCCEED();
        return;
    }

    GPUTransformData transformData {};
    transformData.transformationType = static_cast<TransformationType>(0);
    program.SetGPUTransformData(transformData);
    EXPECT_TRUE(program.Init());
    EXPECT_TRUE(program.Execute());
}
} // namespace Media
} // namespace OHOS
