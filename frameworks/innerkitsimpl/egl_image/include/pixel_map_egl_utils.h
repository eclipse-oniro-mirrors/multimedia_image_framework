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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_EGL_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_EGL_UTILS_H

#ifndef EGL_EGLEXT_PROTOTYPES
#define EGL_EGLEXT_PROTOTYPES
#endif

#include "EGL/egl.h"
#include "EGL/eglext.h"

#include "image_log.h"

namespace OHOS {
namespace Media {
namespace PixelMapEglUtils {
inline bool InitDisplay(EGLDisplay &display)
{
    display = eglGetPlatformDisplay(EGL_PLATFORM_OHOS_KHR, EGL_DEFAULT_DISPLAY, nullptr);
    if (display == EGL_NO_DISPLAY) {
        IMAGE_LOGE("PixelMap EGL init failed: eglGetPlatformDisplay");
        return false;
    }

    EGLint major = 0;
    EGLint minor = 0;
    if (eglInitialize(display, &major, &minor) == EGL_FALSE) {
        IMAGE_LOGE("PixelMap EGL init failed: eglInitialize");
        display = EGL_NO_DISPLAY;
        return false;
    }

    if (eglBindAPI(EGL_OPENGL_ES_API) == EGL_FALSE) {
        IMAGE_LOGE("PixelMap EGL init failed: eglBindAPI");
        (void)eglTerminate(display);
        display = EGL_NO_DISPLAY;
        return false;
    }
    return true;
}

inline bool ChooseDefaultConfig(EGLDisplay display, EGLConfig &config)
{
    if (display == EGL_NO_DISPLAY) {
        return false;
    }

    EGLint count = 0;
    EGLint configAttribs[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RED_SIZE, 8,
        EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8,
        EGL_ALPHA_SIZE, 8,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT,
        EGL_NONE
    };
    const EGLBoolean ret = eglChooseConfig(display, configAttribs, &config, 1, &count);
    if (ret != EGL_TRUE || count < 1) {
        IMAGE_LOGE("PixelMap EGL init failed: eglChooseConfig");
        return false;
    }
    return true;
}

inline bool CreateContext(EGLDisplay display, EGLConfig config, EGLContext &context)
{
    if (display == EGL_NO_DISPLAY || config == nullptr) {
        return false;
    }
    static const EGLint contextAttribs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
    context = eglCreateContext(display, config, EGL_NO_CONTEXT, contextAttribs);
    if (context == EGL_NO_CONTEXT) {
        IMAGE_LOGE("PixelMap EGL init failed: eglCreateContext %{public}x", eglGetError());
        return false;
    }
    return true;
}

inline bool CreatePbufferSurface(EGLDisplay display, EGLConfig config, EGLSurface &surface)
{
    if (display == EGL_NO_DISPLAY || config == nullptr) {
        return false;
    }
    if (surface != EGL_NO_SURFACE) {
        return true;
    }
    EGLint attribs[] = { EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE };
    surface = eglCreatePbufferSurface(display, config, attribs);
    if (surface == EGL_NO_SURFACE) {
        IMAGE_LOGE("PixelMap EGL init failed: eglCreatePbufferSurface %{public}x", eglGetError());
        return false;
    }
    return true;
}

inline void ResetCurrentContext(EGLDisplay display, EGLContext context)
{
    if (display == EGL_NO_DISPLAY || context == EGL_NO_CONTEXT) {
        return;
    }
    if (eglGetCurrentContext() == context) {
        (void)eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    }
}
} // namespace PixelMapEglUtils
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_EGL_UTILS_H
