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

#include "render_context.h"

#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelMap"

namespace OHOS {
namespace Media {

RenderContext::RenderContext()
{}

RenderContext::~RenderContext() noexcept
{
    Clear();
}
    
bool RenderContext::Init()
{
    if (!InitEGLContext()) {
        return false;
    }

    if (!InitGrContext()) {
        return false;
    }

    return true;
}

bool RenderContext::InitEGLContext()
{
    eglDisplay_ = eglGetPlatformDisplay(EGL_PLATFORM_OHOS_KHR, EGL_DEFAULT_DISPLAY, nullptr);
    if (eglDisplay_ == EGL_NO_DISPLAY) {
        IMAGE_LOGE("RenderContext::Init: eglGetDisplay error: ");
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
    EGLint configAttribs[] = { EGL_SURFACE_TYPE, EGL_WINDOW_BIT, EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8, EGL_BLUE_SIZE, 8,
        EGL_ALPHA_SIZE, 8, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT, EGL_NONE };

    ret = eglChooseConfig(eglDisplay_, configAttribs, &config_, 1, &count);
    if (!(ret && static_cast<unsigned int>(count) >= 1)) {
        IMAGE_LOGE("Failed to eglChooseConfig");
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

bool RenderContext::CreatePbufferSurface()
{
    if (pbufferSurface_ == EGL_NO_SURFACE) {
        EGLint attribs[] = {EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE};
        pbufferSurface_ = eglCreatePbufferSurface(eglDisplay_, config_, attribs);
        if (pbufferSurface_ == EGL_NO_SURFACE) {
            IMAGE_LOGE(
                "RenderContext::CreatePbufferSurface failed, error is %{public}x",
                eglGetError());
            return false;
        }
    }
    return true;
}

void RenderContext::MakeCurrent(EGLSurface surface) const
{
    EGLSurface currSurface = surface;
    if (currSurface == EGL_NO_SURFACE) {
        currSurface = pbufferSurface_;
    }

    if (eglMakeCurrent(eglDisplay_, currSurface, currSurface, eglContext_) != EGL_TRUE) {
        EGLint surfaceId = -1;
        eglQuerySurface(eglDisplay_, surface, EGL_CONFIG_ID, &surfaceId);
        IMAGE_LOGE(
            "RenderContext::MakeCurrent failed for eglSurface %{public}d, error is %{public}x",
            surfaceId,
            eglGetError());
    }
}

bool RenderContext::InitGrContext()
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

void RenderContext::Clear() noexcept
{
    if (eglDisplay_ == EGL_NO_DISPLAY) {
        return;
    }

    grContext_ = nullptr;

    if (pbufferSurface_ != EGL_NO_SURFACE) {
        EGLBoolean ret = eglDestroySurface(eglDisplay_, pbufferSurface_);
        if (ret != EGL_TRUE) {
            IMAGE_LOGE("RenderContext::Clear() failed to destroy pbuffer surface, error is %{public}x.", eglGetError());
        }
        pbufferSurface_ = EGL_NO_SURFACE;
    }

    (void)eglDestroyContext(eglDisplay_, eglContext_);
    (void)eglTerminate(eglDisplay_);
    eglContext_ = EGL_NO_CONTEXT;
    eglDisplay_ = EGL_NO_DISPLAY;
}
} // namespace Media
} // namespace OHOS
