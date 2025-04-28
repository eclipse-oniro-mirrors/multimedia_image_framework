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

#include "pixel_map_gl_context.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE
#undef LOG_TAG
#define LOG_TAG "PixelMapGlContext"

namespace OHOS {
namespace Media {

static bool displayInitFlag = false;
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
    if (!displayInitFlag) {
        eglDisplay_ = eglGetPlatformDisplay(EGL_PLATFORM_OHOS_KHR, EGL_DEFAULT_DISPLAY, nullptr);
        if (eglDisplay_ == EGL_NO_DISPLAY) {
            IMAGE_LOGE("PixelMapGlContext::Init: eglGetDisplay error: ");
            return false;
        }
        EGLint major = 0;
        EGLint minor = 0;
        if (eglInitialize(eglDisplay_, &major, &minor) == EGL_FALSE) {
            IMAGE_LOGE("Failed to initialize EGLDisplay");
            return false;
        }
        if (eglBindAPI(EGL_OPENGL_ES_API) == EGL_FALSE) {
            IMAGE_LOGE("Failed to bind OpenGL ES API");
            return false;
        }
        unsigned int ret;
        EGLint count;
        EGLint configAttribs[] = { EGL_SURFACE_TYPE, EGL_WINDOW_BIT, EGL_RED_SIZE, 8,
            EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8, EGL_ALPHA_SIZE, 8, EGL_RENDERABLE_TYPE,
            EGL_OPENGL_ES3_BIT, EGL_NONE };
        ret = eglChooseConfig(eglDisplay_, configAttribs, &config_, 1, &count);
        if (!(ret && static_cast<unsigned int>(count) >= 1)) {
            IMAGE_LOGE("Failed to eglChooseConfig");
            return false;
        }
        IMAGE_LOGE("PixelMapGlContext::Init");
        displayInitFlag = true;
    }

    if (eglDisplay_ == EGL_NO_DISPLAY) {
        return false;
    }

    static const EGLint contextAttribs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    eglContext_ = eglCreateContext(eglDisplay_, config_, EGL_NO_CONTEXT, contextAttribs);
    if (eglContext_ == EGL_NO_CONTEXT) {
        IMAGE_LOGE("Failed to create egl context %{public}x", eglGetError());
        return false;
    }

    if (!CreatePbufferSurface()) {
        return false;
    }
    MakeCurrent(pbufferSurface_);

    return true;
}

bool PixelMapGlContext::CreatePbufferSurface()
{
    if (pbufferSurface_ == EGL_NO_SURFACE) {
        EGLint attribs[] = {EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE};
        pbufferSurface_ = eglCreatePbufferSurface(eglDisplay_, config_, attribs);
        if (pbufferSurface_ == EGL_NO_SURFACE) {
            IMAGE_LOGE(
                "PixelMapGlContext::CreatePbufferSurface failed, error is %{public}x",
                eglGetError());
            return false;
        }
    }
    return true;
}

bool PixelMapGlContext::MakeCurrentSimple(bool needCurrent)
{
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
    sk_sp<const GrGLInterface> glInterface(GrGLCreateNativeInterface());
    if (glInterface == nullptr) {
        IMAGE_LOGE("SetUpGrContext failed to make native interface");
        return false;
    }

    GrContextOptions options;
    options.fGpuPathRenderers &= ~GpuPathRenderers::kCoverageCounting;
    options.fPreferExternalImagesOverES3 = true;
    options.fDisableDistanceFieldPaths = true;
    grContext_ = GrDirectContext::MakeGL(std::move(glInterface), options);
    return grContext_ != nullptr;
}

void PixelMapGlContext::Clear() noexcept
{
    if (eglDisplay_ == EGL_NO_DISPLAY) {
        return;
    }

    grContext_ = nullptr;

    if (pbufferSurface_ != EGL_NO_SURFACE) {
        EGLBoolean ret = eglDestroySurface(eglDisplay_, pbufferSurface_);
        if (ret != EGL_TRUE) {
            IMAGE_LOGE("PixelMapGlContext::Clear() failed error is %{public}x.", eglGetError());
        }
        pbufferSurface_ = EGL_NO_SURFACE;
    }

    (void)eglDestroyContext(eglDisplay_, eglContext_);
    eglContext_ = EGL_NO_CONTEXT;
}
} // namespace Media
} // namespace OHOS
