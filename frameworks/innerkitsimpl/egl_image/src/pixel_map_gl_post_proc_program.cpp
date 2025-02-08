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
#include "pixel_map_gl_post_proc_program.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <iostream>

#include "native_buffer.h"
#include "pixel_map_gl_shader.h"
#include "securec.h"
#include "sync_fence.h"
#include "image_utils.h"
#include <fstream>
#include <sstream>
#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelMapGLPostProcProgram"
#define PI 3.1415926

namespace OHOS {
namespace Media {
using namespace GlCommon;
std::once_flag shaderInitFlag[PixelMapGlShader::SHADER_MAX];
std::mutex g_shaderMtx;
std::condition_variable g_shaderCv;
std::atomic<int> g_shaderCount = 0;
std::atomic<int> g_shaderFailCount = 0;

PixelMapGLPostProcProgram::PixelMapGLPostProcProgram()
{
}

PixelMapGLPostProcProgram::~PixelMapGLPostProcProgram() noexcept
{
    Clear();
    IMAGE_LOGE("slr_gpu ~PixelMapGLPostProcProgram()");
}

void PixelMapGLPostProcProgram::SetGPUTransformData(GPUTransformData &transformData)
{
    this->transformData_ = transformData;
}

void PixelMapGLPostProcProgram::Clear() noexcept
{
    if (renderContext_ != nullptr && renderContext_->eglContext_ != EGL_NO_CONTEXT) {
        renderContext_->MakeCurrentSimple(true);
        if (rotateShader_) {
            rotateShader_->Clear();
            rotateShader_.reset();
        }
        if (slrShader_) {
            slrShader_->Clear();
            slrShader_.reset();
        }
        if (lapShader_) {
            lapShader_->Clear();
            lapShader_.reset();
        }
        if (vertexShader_) {
            vertexShader_->Clear();
            vertexShader_.reset();
        }
        renderContext_->MakeCurrentSimple(false);
    }
}

bool PixelMapGLPostProcProgram::BuildShader()
{
    ImageTrace imageTrace("PixelMapGLPostProcProgram::BuildShader");
    static PixelMapGlContext renderContextAll(true);
    for (int i = PixelMapGlShader::SHADER_ROTATE; i < PixelMapGlShader::SHADER_MAX; i++) {
        std::call_once(shaderInitFlag[i], [&]() {
            auto shader = PixelMapGlShader::ShaderFactory::GetInstance().Get(PixelMapGlShader::ShaderType(i));
            g_shaderCount++;
            if (!shader || !shader->LoadProgram()) {
                g_shaderFailCount++;
            }
            std::unique_lock<std::mutex> lock(g_shaderMtx);
            g_shaderCv.notify_all();
        });
    }
    {
        std::unique_lock<std::mutex> lock(g_shaderMtx);
        g_shaderCv.wait(lock, [] {
            return g_shaderCount == PixelMapGlShader::SHADER_MAX - PixelMapGlShader::SHADER_ROTATE;
        });
    }
    return g_shaderFailCount == 0;
}

bool PixelMapGLPostProcProgram::Init()
{
    if (renderContext_ == nullptr) {
        ImageTrace imageTrace("OpenGL context create");
        renderContext_ = make_unique<PixelMapGlContext>();
        if (!renderContext_->InitEGLContext()) {
            IMAGE_LOGE("slr_gpu CreatePixelMapFromSurface: init renderContext failed.");
            return false;
        }
        return InitGLResource();
    }
    return true;
}

bool PixelMapGLPostProcProgram::CreateNormalImage(const uint8_t *data, GLuint &imageTexId)
{
    const Size &sourceSize = transformData_.sourceInfo_.size;
    int perPixelSize = transformData_.sourceInfo_.pixelBytes;
    if (data == nullptr) {
        return false;
    }
    if (imageTexId != 0) {
        glDeleteTextures(1, &imageTexId);
    }
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glGenTextures(1, &imageTexId);
    glBindTexture(GL_TEXTURE_2D, imageTexId);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, sourceSize.width, sourceSize.height, 0,
        transformData_.glFormat, GL_UNSIGNED_BYTE, NULL);
    if (perPixelSize * sourceSize.width == transformData_.sourceInfo_.stride) {
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, sourceSize.width, sourceSize.height,
            transformData_.glFormat, GL_UNSIGNED_BYTE, data);
    } else {
        GLuint pbo = 0;
        glGenBuffers(1, &pbo);
        glBindBuffer(GL_PIXEL_UNPACK_BUFFER, pbo);
        glBufferData(GL_PIXEL_UNPACK_BUFFER,
            sourceSize.width * sourceSize.height * perPixelSize, NULL, GL_STREAM_DRAW);
        char *mapPointer = (char *)glMapBufferRange(GL_PIXEL_UNPACK_BUFFER, 0,
            sourceSize.width * sourceSize.height * perPixelSize, GL_MAP_WRITE_BIT);
        if (mapPointer == NULL) {
            return false;
        }
        for (int i = 0; i < sourceSize.height; i++) {
            if (memcpy_s(mapPointer + sourceSize.width * perPixelSize * i,
                sourceSize.width * perPixelSize * (sourceSize.height - i),
                data + perPixelSize * i, sourceSize.width * perPixelSize) != 0) {
                IMAGE_LOGE("slr_gpu %{public}s memcpy_s failed", __func__);
                return false;
            }
        }
        glUnmapBuffer(GL_PIXEL_UNPACK_BUFFER);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, sourceSize.width, sourceSize.height, 0,
            transformData_.glFormat, GL_UNSIGNED_BYTE, NULL);
        glBindBuffer(GL_PIXEL_UNPACK_BUFFER, 0);
        glDeleteBuffers(1, &pbo);
    }
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool PixelMapGLPostProcProgram::CreateEGLImage(OHNativeWindowBuffer *nativeBuffer,
    EGLImageKHR &eglImage, GLuint &imageTexId)
{
    if (nativeBuffer == nullptr) {
        return false;
    }
    static EGLint attrs[] = {
        EGL_IMAGE_PRESERVED,
        EGL_TRUE,
        EGL_NONE,
    };
    eglImage = eglCreateImageKHR(
        renderContext_->GetEGLDisplay(), EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_OHOS,
        nativeBuffer, attrs);
    if (eglImage == EGL_NO_IMAGE_KHR) {
        IMAGE_LOGE("slr_gpu %{public}s create egl image fail %{public}d", __func__, eglGetError());
        return false;
    }
    if (imageTexId != 0) {
        glDeleteTextures(1, &imageTexId);
    }
    glGenTextures(1, &imageTexId);
    glBindTexture(GL_TEXTURE_EXTERNAL_OES, imageTexId);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    static auto glEGLImageTargetTexture2DOESFunc = reinterpret_cast<PFNGLEGLIMAGETARGETTEXTURE2DOESPROC>(
        eglGetProcAddress("glEGLImageTargetTexture2DOES"));
    if (glEGLImageTargetTexture2DOESFunc == nullptr) {
        IMAGE_LOGE("slr_gpu %{public}s glEGLImageTargetTexture2DOES func not found: %{public}d",
            __func__, eglGetError());
        return false;
    }
    glEGLImageTargetTexture2DOESFunc(GL_TEXTURE_EXTERNAL_OES, static_cast<GLeglImageOES>(eglImage));
    return true;
}

bool PixelMapGLPostProcProgram::UseEGLImageCreateNormalImage(GLuint &imageTexId)
{
    GLuint eglImageTexId = imageTexId;
    Size &sourceSize = transformData_.sourceInfo_.size;
    GLuint tempFbo[NUM_2];
    glGenFramebuffers(NUM_2, tempFbo);
    glBindFramebuffer(GL_READ_FRAMEBUFFER, tempFbo[0]);
    glFramebufferTexture2D(GL_READ_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_EXTERNAL_OES, eglImageTexId, 0);
    IMAGE_LOGD("readfbo status %{public}x", glCheckFramebufferStatus(GL_READ_FRAMEBUFFER));

    glGenTextures(1, &imageTexId);
    glBindTexture(GL_TEXTURE_2D, imageTexId);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, sourceSize.width, sourceSize.height, 0,
        transformData_.glFormat, GL_UNSIGNED_BYTE, NULL);

    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, tempFbo[1]);
    glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, imageTexId, 0);
    IMAGE_LOGD("drawfbo status %{public}x", glCheckFramebufferStatus(GL_DRAW_FRAMEBUFFER));

    glBlitFramebuffer(0, 0, sourceSize.width, sourceSize.height, 0, 0, sourceSize.width,
        sourceSize.height, GL_COLOR_BUFFER_BIT, GL_NEAREST);
    eglDestroyImageKHR(renderContext_->GetEGLDisplay(), eglImage_);
    glDeleteTextures(1, &eglImageTexId);
    glDeleteFramebuffers(NUM_2, tempFbo);
    eglImage_ = EGL_NO_IMAGE_KHR;
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool PixelMapGLPostProcProgram::GLMakecurrent(bool needCurrent)
{
    if (!renderContext_) {
        IMAGE_LOGE("slr_gpu GLMakecurrent renderContext_ == nullptr");
        return false;
    }
    return renderContext_->MakeCurrentSimple(needCurrent);
}

bool PixelMapGLPostProcProgram::InitGLResource()
{
    vertexShader_ = std::make_shared<PixelMapGlShader::VertexShader>();
    if (!vertexShader_->LoadProgram()) {
        return false;
    }
    rotateShader_ = std::make_shared<PixelMapGlShader::RotateShader>();
    if (!rotateShader_->LoadProgram()) {
        return false;
    }
    slrShader_ = std::make_shared<PixelMapGlShader::SLRShader>();
    if (!slrShader_->LoadProgram()) {
        return false;
    }
    lapShader_ = std::make_shared<PixelMapGlShader::LapShader>();
    if (!lapShader_->LoadProgram()) {
        return false;
    }
    return true;
}

bool PixelMapGLPostProcProgram::BuildProcTexture(bool needThumb, bool needUpload, GLuint &readTexId)
{
    OHNativeWindowBuffer *nativeBuffer = nullptr;
    const uint8_t *normalBuffer = nullptr;
    if (!transformData_.isDma) {
        normalBuffer = transformData_.sourceInfo_.addr;
        if (!CreateNormalImage(normalBuffer, readTexId)) {
            return false;
        }
    } else {
        void *surfaceBuffer = transformData_.sourceInfo_.context;
        nativeBuffer = CreateNativeWindowBufferFromSurfaceBuffer(&surfaceBuffer);
        if (!CreateEGLImage(nativeBuffer, eglImage_, readTexId)) {
            DestroyNativeWindowBuffer(nativeBuffer);
            return false;
        }
        DestroyNativeWindowBuffer(nativeBuffer);
        if (!UseEGLImageCreateNormalImage(readTexId)) {
            return false;
        }
    }
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu %{public}s failed gl error: %{public}d %{public}x", __func__, __LINE__, err);
        return false;
    }
    return true;
}

void PixelMapGLPostProcProgram::DestroyProcTexture()
{
    glBindTexture(GL_TEXTURE_2D, 0);
    glBindTexture(GL_TEXTURE_EXTERNAL_OES, 0);
    if (eglImage_ != EGL_NO_IMAGE_KHR) {
        eglDestroyImageKHR(renderContext_->GetEGLDisplay(), eglImage_);
    }
    eglImage_ = EGL_NO_IMAGE_KHR;
    return;
}

bool PixelMapGLPostProcProgram::GenProcEndData(char *lcdData)
{
    ImageTrace imageTrace("GenProcEndData");
    switch (transformData_.transformationType) {
        case TransformationType::SCALE :
            if (!(BuildProcTexture(false, true, slrShader_->GetReadTexId()) &&
                ResizeScaleWithGL() && ReadEndData(lcdData, lapShader_->GetWriteTexId()))) {
                return false;
            }
            break;
        case TransformationType::ROTATE :
            if (!(BuildProcTexture(false, true, rotateShader_->GetReadTexId()) &&
                ResizeRotateWithGL() && ReadEndData(lcdData, rotateShader_->GetWriteTexId()))) {
                return false;
            }
            break;
        default:
            break;
    }

    DestroyProcTexture();
    return true;
}

bool PixelMapGLPostProcProgram::GenProcDmaEndData(void *surfaceBuffer)
{
    ImageTrace imageTrace("GenProcEndData-surface");
    switch (transformData_.transformationType) {
        case TransformationType::SCALE :
            if (!(BuildProcTexture(false, true, slrShader_->GetReadTexId()) &&
                ResizeScaleWithGL() && ReadEndDMAData(surfaceBuffer, lapShader_->GetWriteFbo()))) {
                return false;
            }
            break;
        case TransformationType::ROTATE :
            if (!(BuildProcTexture(false, true, rotateShader_->GetReadTexId()) &&
                ResizeRotateWithGL() && ReadEndDMAData(surfaceBuffer, rotateShader_->GetWriteFbo()))) {
                return false;
            }
            break;
        default:
            break;
    }
    DestroyProcTexture();
    return true;
}

bool PixelMapGLPostProcProgram::ResizeScaleWithGL()
{
    ImageTrace imageTrace("ResizeScaleWithGL");
    ((PixelMapGlShader::SLRShader*)(slrShader_.get()))->SetEglImage(eglImage_);
    ((PixelMapGlShader::SLRShader*)(slrShader_.get()))->SetParams(transformData_);
    if (!slrShader_->Use()) {
        return false;
    }
    ((PixelMapGlShader::LapShader*)(lapShader_.get()))->SetParams(transformData_);
    lapShader_->GetReadTexId() = slrShader_->GetWriteTexId();
    if (!lapShader_->Use()) {
        return false;
    }
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu 3 %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool PixelMapGLPostProcProgram::ResizeRotateWithGL()
{
    ImageTrace imageTrace("ResizeRotateWithGL");
    rotateShader_->SetParams(transformData_);
    if (!rotateShader_->Use()) {
        return false;
    }
    return true;
}

bool PixelMapGLPostProcProgram::ReadEndData(char *targetData, GLuint &writeTexId)
{
    ImageTrace imageTrace("ReadEndData");
    if (targetData == nullptr) {
        return false;
    }
    Size &targetSize = transformData_.targetInfo_.size;
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, writeTexId, 0);
    if (targetSize.width * NUM_4 >= transformData_.targetInfo_.stride) {
        glReadPixels(0, 0, targetSize.width, targetSize.height, GL_RGBA, GL_UNSIGNED_BYTE, targetData);
    } else {
        GLuint pbo = 0;
        glGenBuffers(1, &pbo);
        glBindBuffer(GL_PIXEL_PACK_BUFFER, pbo);
        glBufferData(GL_PIXEL_PACK_BUFFER, targetSize.width * targetSize.height * NUM_4, NULL, GL_STREAM_READ);
        glReadPixels(0, 0, targetSize.width, targetSize.height, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
        char *mapPointer = (char *)glMapBufferRange(GL_PIXEL_PACK_BUFFER, 0,
            targetSize.width * targetSize.height * NUM_4, GL_MAP_READ_BIT);
        if (mapPointer == NULL) {
            return false;
        }
        for (int i = 0; i < targetSize.height; i++) {
            if (memcpy_s(targetData + transformData_.targetInfo_.stride * i,
                targetSize.width * NUM_4 * (targetSize.height - i),
                mapPointer + targetSize.width * NUM_4 * i, targetSize.width * NUM_4) != 0) {
                IMAGE_LOGE("slr_gpu %{public}s memcpy_s fail", __func__);
                return false;
            }
        }
        glUnmapBuffer(GL_PIXEL_PACK_BUFFER);
        glBindBuffer(GL_PIXEL_PACK_BUFFER, 0);
        glDeleteBuffers(1, &pbo);
    }

    glFinish();
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu %{public}s fail %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool PixelMapGLPostProcProgram::ReadEndDMAData(void *surfaceBuffer, GLuint &writeFbo)
{
    ImageTrace imageTrace("ReadEndDMAData ");
    OHNativeWindowBuffer *nativeBuffer = CreateNativeWindowBufferFromSurfaceBuffer(&surfaceBuffer);
    EGLImage endEglImage;
    GLuint endReadTexId;
    if (!CreateEGLImage(nativeBuffer, endEglImage, endReadTexId)) {
        IMAGE_LOGE("slr_gpu ReadEndDMAData CreateEGLImage fail %{public}d", eglGetError());
        return false;
    }
    GLuint endFbo;
    glGenFramebuffers(1, &endFbo);
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, endFbo);
    glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_EXTERNAL_OES, endReadTexId, 0);
    glBindFramebuffer(GL_READ_FRAMEBUFFER, writeFbo);
    Size &targetSize = transformData_.targetInfo_.size;
    glBlitFramebuffer(0, 0, targetSize.width, targetSize.height, 0, 0,
        targetSize.width, targetSize.height, GL_COLOR_BUFFER_BIT, GL_NEAREST);
    eglDestroyImageKHR(renderContext_->GetEGLDisplay(), endEglImage);
    glDeleteTextures(1, &endReadTexId);
    glDeleteFramebuffers(1, &endFbo);
    DestroyNativeWindowBuffer(nativeBuffer);
    glFinish();
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    return true;
}

bool PixelMapGLPostProcProgram::Execute()
{
    if (!GLMakecurrent(true)) {
        IMAGE_LOGE("slr_gpu GenProcEndData cannot makecurent with opengl");
        return false;
    }
    bool ret = true;
    if (transformData_.isDma) {
        ret = GenProcDmaEndData(transformData_.targetInfo_.context);
    } else {
        ret = GenProcEndData((char*)transformData_.targetInfo_.outdata);
    }
    if (!GLMakecurrent(false)) {
        IMAGE_LOGE("slr_gpu GenProcEndData Unbinding failed");
        return false;
    }
    return ret;
}
} // namespace Media
} //