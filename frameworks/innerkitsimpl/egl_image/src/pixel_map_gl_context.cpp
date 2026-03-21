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

#include "pixel_map_gl_context.h"

#include <mutex>

#include "pixel_map_egl_utils.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE
#undef LOG_TAG
#define LOG_TAG "PixelMapGlContext"

namespace OHOS {
namespace Media {

static bool displayInitFlag = false;
static std::mutex g_displayMutex;
static uint32_t g_contextRefCount = 0;
EGLDisplay PixelMapGlContext::eglDisplay_ = EGL_NO_DISPLAY;
EGLConfig PixelMapGlContext::config_ = nullptr;

PixelMapGlContext::PixelMapGlContext()
{
}

PixelMapGlContext::PixelMapGlContext(bool init)
{
    if (init) {
        InitEGLContext();
    }
}

PixelMapGlContext::~PixelMapGlContext() noexcept
{
    Clear();
}

bool PixelMapGlContext::Init()
{
    if (!InitEGLContext()) {
        return false;
    }

    if (!InitGrContext()) {
        return false;
    }

    return true;
}

bool PixelMapGlContext::InitEGLContext()
{
    ImageTrace imageTrace("PixelMapGlContext::InitEGLContext");
    std::lock_guard<std::mutex> lock(g_displayMutex);
    if (eglContext_ != EGL_NO_CONTEXT) {
        return true;
    }
    if (!displayInitFlag) {
        if (!PixelMapEglUtils::InitDisplay(eglDisplay_)) {
            return false;
        }
        if (!PixelMapEglUtils::ChooseDefaultConfig(eglDisplay_, config_)) {
            (void)eglTerminate(eglDisplay_);
            eglDisplay_ = EGL_NO_DISPLAY;
            return false;
        }
        IMAGE_LOGE("PixelMapGlContext::Init");
        displayInitFlag = true;
    }

    if (eglDisplay_ == EGL_NO_DISPLAY) {
        return false;
    }

    if (!PixelMapEglUtils::CreateContext(eglDisplay_, config_, eglContext_)) {
        return false;
    }

    if (!PixelMapEglUtils::CreatePbufferSurface(eglDisplay_, config_, pbufferSurface_)) {
        (void)eglDestroyContext(eglDisplay_, eglContext_);
        eglContext_ = EGL_NO_CONTEXT;
        return false;
    }
    ++g_contextRefCount;
    MakeCurrent(pbufferSurface_);

    return true;
}

bool PixelMapGlContext::CreatePbufferSurface()
{
    return PixelMapEglUtils::CreatePbufferSurface(eglDisplay_, config_, pbufferSurface_);
}

bool PixelMapGlContext::MakeCurrentSimple(bool needCurrent)
{
    if (eglDisplay_ == EGL_NO_DISPLAY) {
        IMAGE_LOGE("PixelMapGlContext::MakeCurrentSimple invalid egl display");
        return false;
    }
    EGLSurface currSurfaceDraw = pbufferSurface_;
    EGLSurface currSurfaceRead = pbufferSurface_;
    EGLContext currContext = eglContext_;
    if (!needCurrent) {
        currSurfaceDraw = oldEglSurfaceDraw_;
        currSurfaceRead = oldEglSurfaceRead_;
        currContext = oldEglContext_;
    } else {
        EGLSurface oldSurface = eglGetCurrentSurface(EGL_DRAW);
        EGLContext oldContext = eglGetCurrentContext();
        if (oldSurface == currSurfaceDraw && oldContext == currContext) {
            IMAGE_LOGI("PixelGPU::MakeCurrentSimple with same context");
            return true;
        }
        oldEglSurfaceDraw_ = oldSurface;
        oldEglSurfaceRead_ = eglGetCurrentSurface(EGL_READ);
        oldEglContext_ = oldContext;
    }
 
    if (eglMakeCurrent(eglDisplay_, currSurfaceDraw, currSurfaceRead, currContext) != EGL_TRUE) {
        EGLint surfaceId = -1;
        eglQuerySurface(eglDisplay_, currSurfaceDraw, EGL_CONFIG_ID, &surfaceId);
        IMAGE_LOGE(
            "PixelMapGlContext::MakeCurrent failed %{public}d, error is %{public}x needCurrent %{public}d",
            surfaceId,
            eglGetError(), needCurrent);
        return false;
    }
    return true;
}

void PixelMapGlContext::MakeCurrent(EGLSurface surface) const
{
    if (eglDisplay_ == EGL_NO_DISPLAY || eglContext_ == EGL_NO_CONTEXT) {
        IMAGE_LOGE("PixelMapGlContext::MakeCurrent invalid egl context");
        return;
    }
    EGLSurface currSurface = surface;
    if (currSurface == EGL_NO_SURFACE) {
        currSurface = pbufferSurface_;
    }

    if (eglMakeCurrent(eglDisplay_, currSurface, currSurface, eglContext_) != EGL_TRUE) {
        EGLint surfaceId = -1;
        eglQuerySurface(eglDisplay_, surface, EGL_CONFIG_ID, &surfaceId);
        IMAGE_LOGE(
            "PixelMapGlContext::MakeCurrent failed for eglSurface %{public}d, error is %{public}x",
            surfaceId,
            eglGetError());
    }
}

bool PixelMapGlContext::InitGrContext()
{
#ifdef USE_M133_SKIA
    sk_sp<const GrGLInterface> glInterface(GrGLMakeNativeInterface());
#else
    sk_sp<const GrGLInterface> glInterface(GrGLCreateNativeInterface());
#endif
    if (glInterface == nullptr) {
        IMAGE_LOGE("SetUpGrContext failed to make native interface");
        return false;
    }

    GrContextOptions options;
    options.fGpuPathRenderers &= ~GpuPathRenderers::kCoverageCounting;
    options.fPreferExternalImagesOverES3 = true;
    options.fDisableDistanceFieldPaths = true;
#ifdef USE_M133_SKIA
    grContext_ = GrDirectContexts::MakeGL(std::move(glInterface), options);
#else
    grContext_ = GrDirectContext::MakeGL(std::move(glInterface), options);
#endif
    return grContext_ != nullptr;
}

void PixelMapGlContext::Clear() noexcept
{
    std::lock_guard<std::mutex> lock(g_displayMutex);
    if (eglDisplay_ == EGL_NO_DISPLAY) {
        return;
    }

    grContext_ = nullptr;
    PixelMapEglUtils::ResetCurrentContext(eglDisplay_, eglContext_);

    if (pbufferSurface_ != EGL_NO_SURFACE) {
        EGLBoolean ret = eglDestroySurface(eglDisplay_, pbufferSurface_);
        if (ret != EGL_TRUE) {
            IMAGE_LOGE("PixelMapGlContext::Clear() failed error is %{public}x.", eglGetError());
        }
        pbufferSurface_ = EGL_NO_SURFACE;
    }
    if (eglContext_ != EGL_NO_CONTEXT) {
        (void)eglDestroyContext(eglDisplay_, eglContext_);
        eglContext_ = EGL_NO_CONTEXT;
        if (g_contextRefCount > 0) {
            --g_contextRefCount;
        }
    }
    if (g_contextRefCount == 0 && displayInitFlag) {
        (void)eglTerminate(eglDisplay_);
        eglDisplay_ = EGL_NO_DISPLAY;
        config_ = nullptr;
        displayInitFlag = false;
    }
}
} // namespace Media
} // namespace OHOS
