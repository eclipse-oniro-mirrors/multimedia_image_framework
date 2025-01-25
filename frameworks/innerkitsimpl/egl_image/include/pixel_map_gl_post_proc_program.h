/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXELMAP_GL_POST_PROC_PROGRAM_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXELMAP_GL_POST_PROC_PROGRAM_H

#include <iostream>
#include <mutex>
#include <array>
#include <atomic>
#include <condition_variable>
#include <numeric>
#include "pixel_map_gl_shader.h"
#include "surface_buffer.h"
#include "surface_utils.h"
#include "window.h"

#define EXPORT __attribute__ ((visibility ("default")))

namespace OHOS {
namespace Media {
using namespace std;

class PixelMapGLPostProcProgram {
public:
    PixelMapGLPostProcProgram();
    ~PixelMapGLPostProcProgram() noexcept;
    PixelMapGLPostProcProgram(const PixelMapGLPostProcProgram &) = delete;
    void operator=(const PixelMapGLPostProcProgram &) = delete;
    PixelMapGLPostProcProgram(const PixelMapGLPostProcProgram &&) = delete;
    void operator=(const PixelMapGLPostProcProgram &&) = delete;

    bool Init();
    bool GenProcEndData(char *lcdData);
    bool GenProcDmaEndData(void *surfaceBuffer);
    bool Execute();
    void SetGPUTransformData(GPUTransformData &transformData);

    static bool BuildShader();

private:
    static void DestoryInstanceThreadFunc();
    bool GLMakecurrent(bool needCurrent);
    bool InitGLResource();
    bool BuildVertex();
    bool CreateEGLImage(OHNativeWindowBuffer *nativeBuffer, EGLImageKHR &eglImage, GLuint &imageTexId);
    bool UseEGLImageCreateNormalImage(GLuint &imageTexId);
    bool CreateNormalImage(const uint8_t *data, GLuint &imageTexId);
    bool BuildProcTexture(bool needThumb, bool needUpload, GLuint &readTexId);
    bool BuildTargetTexture();
    void DestroyProcTexture();
    bool ResizeRotateWithGL();
    bool ResizeScaleWithGL();
    bool ReadEndData(char *targetData, GLuint &writeTexId);
    bool ReadEndDMAData(void *surfaceBuffer, GLuint &writeTexId);
    void Clear() noexcept;

private:
    unique_ptr<PixelMapGlContext> renderContext_;
    std::shared_ptr<PixelMapGlShader::Shader> rotateShader_ = nullptr;
    std::shared_ptr<PixelMapGlShader::Shader> slrShader_ = nullptr;
    std::shared_ptr<PixelMapGlShader::Shader> lapShader_ = nullptr;
    std::shared_ptr<PixelMapGlShader::Shader> vertexShader_ = nullptr;

    EGLImageKHR eglImage_ = EGL_NO_IMAGE_KHR;
    GPUTransformData transformData_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXELMAP_GL_POST_PROC_PROGRAM_H
