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
#include "pixel_map_gl_post_proc_program.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <atomic>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>

#include "image_utils.h"
#include "native_buffer.h"
#include "pixel_map_gl_scope.h"
#include "pixel_map_gl_resource.h"
#include "pixel_map_gl_shader.h"
#include "pixel_map_gl_utils.h"
#include "securec.h"
#include "sync_fence.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelMapGLPostProcProgram"
#define PI 3.1415926

namespace OHOS {
namespace Media {
using namespace GlCommon;
using PixelMapGlScope::MakeScopeExit;
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
        DestroyProcTexture();
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
    size_t rowBytes = 0;
    size_t contiguousSize = 0;
    if (data == nullptr) {
        return false;
    }
    if (!PixelMapGlResource::ValidateTransferLayout(sourceSize, transformData_.sourceInfo_.stride, perPixelSize,
        rowBytes, contiguousSize)) {
        IMAGE_LOGE("slr_gpu %{public}s invalid source image layout", __func__);
        return false;
    }
    GLuint newImageTexId = 0U;
    glGenTextures(1, &newImageTexId);
    PixelMapGlResource::ScopedTexture scopedImageTexture(newImageTexId);
    glBindTexture(GL_TEXTURE_2D, scopedImageTexture.Get());
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, sourceSize.width, sourceSize.height, 0,
        transformData_.glFormat, GL_UNSIGNED_BYTE, NULL);
    if (static_cast<size_t>(transformData_.sourceInfo_.stride) == rowBytes) {
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, sourceSize.width, sourceSize.height,
            transformData_.glFormat, GL_UNSIGNED_BYTE, data);
    } else {
        GLuint pbo = 0U;
        glGenBuffers(1, &pbo);
        PixelMapGlResource::ScopedBuffer scopedPbo(pbo);
        glBindBuffer(GL_PIXEL_UNPACK_BUFFER, scopedPbo.Get());
        auto resetUnpackBuffer = MakeScopeExit([] { glBindBuffer(GL_PIXEL_UNPACK_BUFFER, 0); });
        glBufferData(GL_PIXEL_UNPACK_BUFFER, contiguousSize, NULL, GL_STREAM_DRAW);
        char *mapPointer = static_cast<char *>(
            glMapBufferRange(GL_PIXEL_UNPACK_BUFFER, 0, contiguousSize, GL_MAP_WRITE_BIT));
        if (mapPointer == NULL) {
            return false;
        }
        if (!PixelMapGlResource::CopyStridedToLinear(data, transformData_.sourceInfo_.stride,
            sourceSize.height, rowBytes, mapPointer, contiguousSize)) {
            IMAGE_LOGE("slr_gpu %{public}s CopyStridedToLinear failed", __func__);
            glUnmapBuffer(GL_PIXEL_UNPACK_BUFFER);
            return false;
        }
        glUnmapBuffer(GL_PIXEL_UNPACK_BUFFER);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, sourceSize.width, sourceSize.height, 0,
            transformData_.glFormat, GL_UNSIGNED_BYTE, NULL);
    }
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    PixelMapGlResource::DeleteTexture(imageTexId);
    imageTexId = scopedImageTexture.Release();
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
    EGLImageKHR newEglImage = eglCreateImageKHR(
        renderContext_->GetEGLDisplay(), EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_OHOS,
        nativeBuffer, attrs);
    if (newEglImage == EGL_NO_IMAGE_KHR) {
        IMAGE_LOGE("slr_gpu %{public}s create egl image fail %{public}d", __func__, eglGetError());
        return false;
    }
    PixelMapGlResource::ScopedEglImage scopedImage;
    scopedImage.Set(renderContext_->GetEGLDisplay(), newEglImage);
    GLuint newImageTexId = 0U;
    glGenTextures(1, &newImageTexId);
    PixelMapGlResource::ScopedTexture scopedTexture(newImageTexId);
    glBindTexture(GL_TEXTURE_EXTERNAL_OES, scopedTexture.Get());
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    static auto glEGLImageTargetTexture2DOESFunc = reinterpret_cast<PFNGLEGLIMAGETARGETTEXTURE2DOESPROC>(
        eglGetProcAddress("glEGLImageTargetTexture2DOES"));
    if (glEGLImageTargetTexture2DOESFunc == nullptr) {
        IMAGE_LOGE("slr_gpu %{public}s glEGLImageTargetTexture2DOES func not found: %{public}d",
            __func__, eglGetError());
        return false;
    }
    glEGLImageTargetTexture2DOESFunc(GL_TEXTURE_EXTERNAL_OES, static_cast<GLeglImageOES>(newEglImage));
    if (glGetError() != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu %{public}s glEGLImageTargetTexture2DOES failed", __func__);
        return false;
    }
    PixelMapGlResource::DeleteTexture(imageTexId);
    imageTexId = scopedTexture.Release();
    eglImage = scopedImage.Release();
    return true;
}

bool PixelMapGLPostProcProgram::UseEGLImageCreateNormalImage(GLuint &imageTexId)
{
    const GLuint eglImageTexId = imageTexId;
    Size &sourceSize = transformData_.sourceInfo_.size;
    GLuint tempFbo[NUM_2] = {0U, 0U};
    glGenFramebuffers(NUM_2, tempFbo);
    PixelMapGlResource::ScopedFramebuffer readFramebuffer(tempFbo[0]);
    PixelMapGlResource::ScopedFramebuffer drawFramebuffer(tempFbo[1]);
    glBindFramebuffer(GL_READ_FRAMEBUFFER, readFramebuffer.Get());
    glFramebufferTexture2D(GL_READ_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_EXTERNAL_OES, eglImageTexId, 0);
    IMAGE_LOGD("readfbo status %{public}x", glCheckFramebufferStatus(GL_READ_FRAMEBUFFER));

    GLuint newImageTexId = 0U;
    glGenTextures(1, &newImageTexId);
    PixelMapGlResource::ScopedTexture scopedImageTexture(newImageTexId);
    glBindTexture(GL_TEXTURE_2D, scopedImageTexture.Get());
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, sourceSize.width, sourceSize.height, 0,
        transformData_.glFormat, GL_UNSIGNED_BYTE, NULL);

    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, drawFramebuffer.Get());
    glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, scopedImageTexture.Get(), 0);
    IMAGE_LOGD("drawfbo status %{public}x", glCheckFramebufferStatus(GL_DRAW_FRAMEBUFFER));

    glBlitFramebuffer(0, 0, sourceSize.width, sourceSize.height, 0, 0, sourceSize.width,
        sourceSize.height, GL_COLOR_BUFFER_BIT, GL_NEAREST);
    GLenum err = glGetError();
    if (err != GL_NO_ERROR) {
        IMAGE_LOGE("slr_gpu %{public}s failed gl error: %{public}x", __func__, err);
        return false;
    }
    DestroyProcTexture();
    imageTexId = scopedImageTexture.Release();
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

bool PixelMapGLPostProcProgram::BuildProcTexture(GLuint &readTexId)
{
    if (!transformData_.isSourceDma) {
        if (!CreateNormalImage(transformData_.sourceInfo_.addr, readTexId)) {
            return false;
        }
    } else {
        void *surfaceBuffer = transformData_.sourceInfo_.context;
        PixelMapGlResource::ScopedNativeWindowBuffer scopedBuffer
            (CreateNativeWindowBufferFromSurfaceBuffer(&surfaceBuffer));
        if (!CreateEGLImage(scopedBuffer.Get(), eglImage_, readTexId)) {
            return false;
        }
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
    if (eglImage_ != EGL_NO_IMAGE_KHR && renderContext_ != nullptr) {
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
            if (!(BuildProcTexture(slrShader_->GetReadTexId()) &&
                ResizeScaleWithGL() && ReadEndData(lcdData, lapShader_->GetWriteTexId()))) {
                return false;
            }
            break;
        case TransformationType::ROTATE :
            if (!(BuildProcTexture(rotateShader_->GetReadTexId()) &&
                ResizeRotateWithGL() && ReadEndData(lcdData, rotateShader_->GetWriteTexId()))) {
                return false;
            }
            break;
        default:
            break;
    }
    return true;
}

bool PixelMapGLPostProcProgram::GenProcDmaEndData(void *surfaceBuffer)
{
    ImageTrace imageTrace("GenProcEndData-surface");
    switch (transformData_.transformationType) {
        case TransformationType::SCALE :
            if (!(BuildProcTexture(slrShader_->GetReadTexId()) &&
                ResizeScaleWithGL() && ReadEndDMAData(surfaceBuffer, lapShader_->GetWriteFbo()))) {
                return false;
            }
            break;
        case TransformationType::ROTATE :
            if (!(BuildProcTexture(rotateShader_->GetReadTexId()) &&
                ResizeRotateWithGL() && ReadEndDMAData(surfaceBuffer, rotateShader_->GetWriteFbo()))) {
                return false;
            }
            break;
        default:
            break;
    }
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
    size_t rowBytes = 0;
    size_t contiguousSize = 0;
    if (!PixelMapGlResource::ValidateTransferLayout(targetSize, transformData_.targetInfo_.stride, NUM_4,
        rowBytes, contiguousSize)) {
        IMAGE_LOGE("slr_gpu %{public}s invalid target image layout", __func__);
        return false;
    }
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, writeTexId, 0);
    if (static_cast<size_t>(transformData_.targetInfo_.stride) == rowBytes) {
        glReadPixels(0, 0, targetSize.width, targetSize.height, GL_RGBA, GL_UNSIGNED_BYTE, targetData);
    } else {
        GLuint pbo = 0U;
        glGenBuffers(1, &pbo);
        PixelMapGlResource::ScopedBuffer scopedPbo(pbo);
        glBindBuffer(GL_PIXEL_PACK_BUFFER, scopedPbo.Get());
        auto resetPackBuffer = MakeScopeExit([] { glBindBuffer(GL_PIXEL_PACK_BUFFER, 0); });
        glBufferData(GL_PIXEL_PACK_BUFFER, contiguousSize, NULL, GL_STREAM_READ);
        glReadPixels(0, 0, targetSize.width, targetSize.height, GL_RGBA, GL_UNSIGNED_BYTE, NULL);
        char *mapPointer = static_cast<char *>(
            glMapBufferRange(GL_PIXEL_PACK_BUFFER, 0, contiguousSize, GL_MAP_READ_BIT));
        if (mapPointer == NULL) {
            return false;
        }
        if (!PixelMapGlResource::CopyLinearToStrided(mapPointer, contiguousSize, rowBytes, targetSize.height,
            reinterpret_cast<uint8_t *>(targetData), transformData_.targetInfo_.stride)) {
            IMAGE_LOGE("slr_gpu %{public}s CopyLinearToStrided fail", __func__);
            glUnmapBuffer(GL_PIXEL_PACK_BUFFER);
            return false;
        }
        glUnmapBuffer(GL_PIXEL_PACK_BUFFER);
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
    PixelMapGlResource::ScopedNativeWindowBuffer nativeBuffer
        (CreateNativeWindowBufferFromSurfaceBuffer(&surfaceBuffer));
    if (nativeBuffer.Get() == nullptr) {
        IMAGE_LOGE("slr_gpu %{public}s CreateNativeWindowBufferFromSurfaceBuffer failed", __func__);
        return false;
    }
    PixelMapGlResource::ScopedEglImage endEglImage;
    GLuint endReadTexId = 0U;
    EGLImageKHR endEglImageHandle = EGL_NO_IMAGE_KHR;
    if (!CreateEGLImage(nativeBuffer.Get(), endEglImageHandle, endReadTexId)) {
        IMAGE_LOGE("slr_gpu ReadEndDMAData CreateEGLImage fail %{public}d", eglGetError());
        return false;
    }
    endEglImage.Set(renderContext_->GetEGLDisplay(), endEglImageHandle);
    GLuint endFbo = 0U;
    glGenFramebuffers(1, &endFbo);
    PixelMapGlResource::ScopedFramebuffer scopedEndFbo(endFbo);
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, scopedEndFbo.Get());
    glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_EXTERNAL_OES, endReadTexId, 0);
    glBindFramebuffer(GL_READ_FRAMEBUFFER, writeFbo);
    Size &targetSize = transformData_.targetInfo_.size;
    glBlitFramebuffer(0, 0, targetSize.width, targetSize.height, 0, 0,
        targetSize.width, targetSize.height, GL_COLOR_BUFFER_BIT, GL_NEAREST);
    endEglImage.Reset();
    PixelMapGlResource::DeleteTexture(endReadTexId);
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
    bool unbindSucceeded = true;
    bool ret = true;
    {
        auto cleanup = MakeScopeExit([this, &unbindSucceeded] {
            DestroyProcTexture();
            if (!GLMakecurrent(false)) {
                IMAGE_LOGE("slr_gpu GenProcEndData Unbinding failed");
                unbindSucceeded = false;
            }
        });
        if (transformData_.isTargetDma) {
            ret = GenProcDmaEndData(transformData_.targetInfo_.context);
        } else {
            ret = GenProcEndData((char*)transformData_.targetInfo_.outdata);
        }
    }
    return ret && unbindSucceeded;
}
} // namespace Media
} //
