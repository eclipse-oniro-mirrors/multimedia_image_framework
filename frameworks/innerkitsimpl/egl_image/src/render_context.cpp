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
#include "pixel_map_egl_utils.h"

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
    if (!PixelMapEglUtils::InitDisplay(eglDisplay_)) {
        return false;
    }
    if (!PixelMapEglUtils::ChooseDefaultConfig(eglDisplay_, config_)) {
        (void)eglTerminate(eglDisplay_);
        eglDisplay_ = EGL_NO_DISPLAY;
        return false;
    }
    if (!PixelMapEglUtils::CreateContext(eglDisplay_, config_, eglContext_)) {
        (void)eglTerminate(eglDisplay_);
        eglDisplay_ = EGL_NO_DISPLAY;
        return false;
    }
    if (!PixelMapEglUtils::CreatePbufferSurface(eglDisplay_, config_, pbufferSurface_)) {
        (void)eglDestroyContext(eglDisplay_, eglContext_);
        (void)eglTerminate(eglDisplay_);
        eglContext_ = EGL_NO_CONTEXT;
        eglDisplay_ = EGL_NO_DISPLAY;
        return false;
    }
    MakeCurrent(pbufferSurface_);

    return true;
}

bool RenderContext::CreatePbufferSurface()
{
    return PixelMapEglUtils::CreatePbufferSurface(eglDisplay_, config_, pbufferSurface_);
}

void RenderContext::MakeCurrent(EGLSurface surface) const
{
    if (eglDisplay_ == EGL_NO_DISPLAY || eglContext_ == EGL_NO_CONTEXT) {
        IMAGE_LOGE("RenderContext::MakeCurrent invalid egl context");
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
            "RenderContext::MakeCurrent failed for eglSurface %{public}d, error is %{public}x",
            surfaceId,
            eglGetError());
    }
}

bool RenderContext::InitGrContext()
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

void RenderContext::Clear() noexcept
{
    if (eglDisplay_ == EGL_NO_DISPLAY) {
        return;
    }

    grContext_ = nullptr;
    PixelMapEglUtils::ResetCurrentContext(eglDisplay_, eglContext_);

    if (pbufferSurface_ != EGL_NO_SURFACE) {
        EGLBoolean ret = eglDestroySurface(eglDisplay_, pbufferSurface_);
        if (ret != EGL_TRUE) {
            IMAGE_LOGE("RenderContext::Clear() failed to destroy pbuffer surface, error is %{public}x.", eglGetError());
        }
        pbufferSurface_ = EGL_NO_SURFACE;
    }
    if (eglContext_ != EGL_NO_CONTEXT) {
        (void)eglDestroyContext(eglDisplay_, eglContext_);
    }
    (void)eglTerminate(eglDisplay_);
    eglContext_ = EGL_NO_CONTEXT;
    eglDisplay_ = EGL_NO_DISPLAY;
}
} // namespace Media
} // namespace OHOS
