/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "native_window.h"
#include "pixel_map_from_surface.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
static constexpr int DEFAULT_WIDTH = 1280;
static constexpr int DEFAULT_HEIGHT = 800;

class EglImageTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    static inline sptr<OHOS::Surface> cSurface;
    class ConsumerSurfaceListener : public IBufferConsumerListener {
    public:
        explicit ConsumerSurfaceListener(const sptr<OHOS::Surface> &cSurface) : surface(cSurface) {}
        void OnBufferAvailable()
        {
            if (surface == nullptr) {
                return;
            }
            // acquire buffer
            sptr<SurfaceBuffer> buffer = nullptr;
            int fence = -1;
            int64_t timestamp;
            OHOS::Rect damage;
            auto ret = surface->AcquireBuffer(buffer, fence, timestamp, damage);
            if (ret != SURFACE_ERROR_OK) {
                close(fence);
                return;
            }
            close(fence);
            surface->ReleaseBuffer(lastBuffer, -1);
            lastBuffer = buffer;
        };
    private:
        sptr<OHOS::Surface> surface;
        sptr<SurfaceBuffer> lastBuffer;
    };
    static inline sptr<OHOS::IBufferConsumerListener> consumerListener;
    static inline sptr<OHOS::Surface> pSurface;
    static inline NativeWindow* nativeWindow = nullptr;

    static void Draw();
};

void EglImageTest::Draw()
{
    Region::Rect srcRect = {0, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    Region region;
    region.rects = &srcRect;
    region.rectNumber = 1;
    if (nativeWindow == nullptr) {
        return;
    }

    int fence = -1;
    NativeWindowBuffer *buffer;
    int ret = NativeWindowRequestBuffer(nativeWindow, &buffer, &fence);
    if (ret != 0 || buffer == nullptr) {
        close(fence);
        return;
    }

    close(fence);
    NativeObjectReference(buffer);

    // draw pixels.
    auto bufferHandle = GetBufferHandleFromNative(buffer);
    if (bufferHandle != nullptr) {
        uint8_t *data = reinterpret_cast<uint8_t *>(
            mmap(bufferHandle->virAddr, bufferHandle->size, PROT_READ | PROT_WRITE, MAP_SHARED, bufferHandle->fd, 0));
        if (data != MAP_FAILED) {
            uint8_t val = 128;
            for (int i = 0; i < bufferHandle->size; ++i) {
                data[i] = val;
            }
            munmap(data, bufferHandle->size);
        }
    }

    NativeWindowFlushBuffer(nativeWindow, buffer, -1, region);
    NativeObjectUnreference(buffer);
}

void EglImageTest::SetUpTestCase()
{
    cSurface = Surface::CreateSurfaceAsConsumer("imageFrameWorkEglImageTestSurface");
    consumerListener = sptr<OHOS::IBufferConsumerListener>(new ConsumerSurfaceListener(cSurface));
    
    if (cSurface != nullptr) {
        auto producer = cSurface->GetProducer();
        pSurface = Surface::CreateSurfaceAsProducer(producer);
        cSurface->RegisterConsumerListener(consumerListener);
    }
    if (pSurface != nullptr) {
        nativeWindow = CreateNativeWindowFromSurface(&pSurface);
        NativeWindowHandleOpt(nativeWindow, SET_BUFFER_GEOMETRY, DEFAULT_WIDTH, DEFAULT_HEIGHT);
        SurfaceUtils::GetInstance()->Add(pSurface->GetUniqueId(), pSurface);
    }
}

void EglImageTest::TearDownTestCase()
{
    if (nativeWindow != nullptr) {
        DestoryNativeWindow(nativeWindow);
        nativeWindow = nullptr;
    }
    if (pSurface != nullptr) {
        SurfaceUtils::GetInstance()->Remove(pSurface->GetUniqueId());
    }
}

/**
 * @tc.name: RenderContextTest001
 * @tc.desc: Test of RenderContext
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, RenderContextTest001, TestSize.Level1)
{
    auto renderContext = std::make_unique<RenderContext>();
    auto ret = renderContext->Init();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: RenderContextTest002
 * @tc.desc: Test of RenderContext
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, RenderContextTest002, TestSize.Level1)
{
    auto renderContext = std::make_unique<RenderContext>();
    EXPECT_EQ(renderContext->GetGrContext(), nullptr);
    EXPECT_EQ(renderContext->GetEGLContext(), EGL_NO_CONTEXT);
    EXPECT_EQ(renderContext->GetEGLDisplay(), EGL_NO_DISPLAY);
    auto ret = renderContext->Init();
    EXPECT_EQ(ret, true);
    EXPECT_NE(renderContext->GetGrContext(), nullptr);
    EXPECT_NE(renderContext->GetEGLContext(), EGL_NO_CONTEXT);
    EXPECT_NE(renderContext->GetEGLDisplay(), EGL_NO_DISPLAY);
}

/**
 * @tc.name: RenderContextTest003
 * @tc.desc: Test of RenderContext
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, RenderContextTest003, TestSize.Level1)
{
    auto renderContext = std::make_unique<RenderContext>();
    auto ret = renderContext->Init();
    EXPECT_EQ(ret, true);
    renderContext->MakeCurrent(EGL_NO_SURFACE);
    auto currSurface = eglGetCurrentSurface(EGL_DRAW);
    // even though MakeCurrent(EGL_NO_SURFACE), current surface is still not EGL_NO_SURFACE
    // in our renderContext, it will be a pbufferSurface.
    EXPECT_NE(currSurface, EGL_NO_SURFACE);
}

/**
 * @tc.name: RenderContextTest004
 * @tc.desc: Test of RenderContext
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, RenderContextTest004, TestSize.Level1)
{
    auto renderContext = std::make_unique<RenderContext>();
    auto ret = renderContext->Init();
    EXPECT_EQ(ret, true);
    renderContext->MakeCurrent(EGL_NO_SURFACE);
    auto currSurface = eglGetCurrentSurface(EGL_DRAW);
    // even though MakeCurrent(EGL_NO_SURFACE), current surface is still not EGL_NO_SURFACE
    // in our renderContext, it will be a pbufferSurface.
    EXPECT_NE(currSurface, EGL_NO_SURFACE);
}

/**
 * @tc.name: RenderContextTest005
 * @tc.desc: Test of RenderContext
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, RenderContextTest005, TestSize.Level1)
{
    auto renderContext = std::make_unique<RenderContext>();
    auto ret = renderContext->Init();
    EXPECT_EQ(ret, true);
    renderContext->MakeCurrent(EGL_NO_SURFACE);
    auto currSurface = eglGetCurrentSurface(EGL_DRAW);
    // even though MakeCurrent(EGL_NO_SURFACE), current surface is still not EGL_NO_SURFACE
    // in our renderContext, it will be a pbufferSurface.
    EXPECT_NE(currSurface, EGL_NO_SURFACE);
    EGLSurface surface = eglCreateWindowSurface(
        renderContext->GetEGLDisplay(), renderContext->GetEGLConfig(),
        static_cast<EGLNativeWindowType>(nativeWindow), nullptr);
    EXPECT_NE(surface, EGL_NO_SURFACE);
    renderContext->MakeCurrent(surface);
    EXPECT_EQ(surface, eglGetCurrentSurface(EGL_DRAW));
}

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
 * @tc.name: PixelMapFromSurfaceTest002
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest002, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass a valid srcRect to expect to get a valid result.
    Rect srcRect = {0, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_NE(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest003
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest003, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {-1, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest004
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest004, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {0, -1, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest005
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest005, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {-1, -1, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest006
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest006, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {DEFAULT_WIDTH, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest007
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest007, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {0, DEFAULT_HEIGHT + 1, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest008
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest008, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {DEFAULT_WIDTH + 1, DEFAULT_HEIGHT, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest009
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest009, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {0, 0, 0, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest010
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest010, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {0, 0, 0, 0};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest011
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest011, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {0, 0, DEFAULT_WIDTH, 0};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest012
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest012, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {0, 0, DEFAULT_WIDTH + 1, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest013
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest013, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    Rect srcRect = {0, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT + 1};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest014
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest014, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    // DEFAULT_WIDTH / 2 + DEFAULT_WIDTH > DEFAULT_WIDTH
    Rect srcRect = {DEFAULT_WIDTH / 2, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest015
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest015, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass an invalid srcRect to expect to get an invalid result.
    // DEFAULT_HEIGHT / 2 + DEFAULT_HEIGHT > DEFAULT_HEIGHT
    Rect srcRect = {0, DEFAULT_HEIGHT / 2, DEFAULT_WIDTH, DEFAULT_HEIGHT};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_EQ(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest016
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest016, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass a valid srcRect to expect to get a valid result.
    // DEFAULT_WIDTH / 2, DEFAULT_HEIGHT / 3 are valid rect sizes.
    Rect srcRect = {0, 0, DEFAULT_WIDTH / 2, DEFAULT_HEIGHT / 3};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_NE(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest017
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest017, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass a valid srcRect to expect to get a valid result.
    // DEFAULT_WIDTH / 2 + DEFAULT_WIDTH / 2 <= DEFAULT_WIDTH, DEFAULT_HEIGHT / 3 + DEFAULT_HEIGHT / 3 < DEFAULT_HEIGHT.
    Rect srcRect = {DEFAULT_WIDTH / 2, DEFAULT_HEIGHT / 3, DEFAULT_WIDTH / 2, DEFAULT_HEIGHT / 3};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_NE(pixelMap, nullptr);
    }
}

/**
 * @tc.name: PixelMapFromSurfaceTest018
 * @tc.desc: Test of PixelMapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, PixelMapFromSurfaceTest018, TestSize.Level3)
{
    EglImageTest::Draw();
    // pass a valid srcRect to expect to get a valid result.
    // DEFAULT_WIDTH / 2 + DEFAULT_WIDTH / 3 < DEFAULT_WIDTH, 0 + DEFAULT_HEIGHT / 3 < DEFAULT_HEIGHT.
    Rect srcRect = {DEFAULT_WIDTH / 2, 0, DEFAULT_WIDTH / 3, DEFAULT_HEIGHT / 3};
    if (pSurface != nullptr) {
        auto pixelMap = CreatePixelMapFromSurfaceId(pSurface->GetUniqueId(), srcRect);
        EXPECT_NE(pixelMap, nullptr);
    }
}

/**
 * @tc.name: Clear001
 * @tc.desc: Test of Clear
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, Clear001, TestSize.Level3)
{
    auto renderContext = std::make_unique<RenderContext>();
    renderContext->eglDisplay_ = EGL_NO_DISPLAY;
    renderContext->Clear();
    EXPECT_EQ(renderContext->eglDisplay_, EGL_NO_DISPLAY);
}

/**
 * @tc.name: CreatePbufferSurface001
 * @tc.desc: Test of CreatePbufferSurface
 * @tc.type: FUNC
 */
HWTEST_F(EglImageTest, CreatePbufferSurface001, TestSize.Level3)
{
    auto renderContext = std::make_unique<RenderContext>();
    renderContext->pbufferSurface_ = EGL_NO_SURFACE;
    bool ret = renderContext->CreatePbufferSurface();
    EXPECT_EQ(ret, false);
}
}
}
