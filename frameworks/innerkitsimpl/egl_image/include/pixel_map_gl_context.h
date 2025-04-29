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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_CONTEXT_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_CONTEXT_H

#ifndef EGL_EGLEXT_PROTOTYPES
#define EGL_EGLEXT_PROTOTYPES
#endif // EGL_EGLEXT_PROTOTYPES

#include "pixel_map_gl_common.h"
#include "EGL/egl.h"
#include "EGL/eglext.h"
#include "GLES/glext.h"
#include "GLES3/gl32.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkColorSpace.h"
#include "include/core/SkImageInfo.h"
#include "include/core/SkSurface.h"
#ifdef USE_M133_SKIA
#include "include/gpu/ganesh/GrBackendSurface.h"
#include "include/gpu/ganesh/GrContextOptions.h"
#include "include/gpu/ganesh/GrDirectContext.h"
#include "include/gpu/ganesh/gl/GrGLDirectContext.h"
#include "include/gpu/ganesh/gl/GrGLInterface.h"
#else
#include "include/gpu/GrBackendSurface.h"
#include "include/gpu/GrDirectContext.h"
#include "include/gpu/gl/GrGLInterface.h"
#endif

namespace OHOS {
namespace Media {

class PixelMapGlContext {
public:
    PixelMapGlContext();
    PixelMapGlContext(bool init);
    ~PixelMapGlContext() noexcept;

    // disallow copy and move
    PixelMapGlContext(const PixelMapGlContext &) = delete;
    void operator=(const PixelMapGlContext &) = delete;
    PixelMapGlContext(const PixelMapGlContext &&) = delete;
    void operator=(const PixelMapGlContext &&) = delete;

    bool Init();

    void MakeCurrent(EGLSurface surface) const;

    bool MakeCurrentSimple(bool needCurrent);

    sk_sp<GrDirectContext> GetGrContext() const
    {
        return grContext_;
    }

    EGLConfig GetEGLConfig() const
    {
        return config_;
    }

    EGLContext GetEGLContext() const
    {
        return eglContext_;
    }

    EGLDisplay GetEGLDisplay() const
    {
        return eglDisplay_;
    }

public:
    void Clear() noexcept;
    bool CreatePbufferSurface();
    bool InitEGLContext();
    bool InitGrContext();

    static EGLDisplay eglDisplay_;
    static EGLConfig config_;
    EGLContext eglContext_ = EGL_NO_CONTEXT;
    EGLSurface pbufferSurface_ = EGL_NO_SURFACE;
    EGLContext oldEglContext_ = EGL_NO_CONTEXT;
    EGLSurface oldEglSurfaceRead_ = EGL_NO_SURFACE;
    EGLSurface oldEglSurfaceDraw_ = EGL_NO_SURFACE;
    sk_sp<GrDirectContext> grContext_;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_CONTEXT_H
