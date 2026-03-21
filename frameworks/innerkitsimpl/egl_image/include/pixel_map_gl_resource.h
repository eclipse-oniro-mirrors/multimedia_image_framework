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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_RESOURCE_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_RESOURCE_H

#ifndef EGL_EGLEXT_PROTOTYPES
#define EGL_EGLEXT_PROTOTYPES
#endif

#include <cstddef>
#include <cstdint>
#include <limits>

#include "EGL/egl.h"
#include "EGL/eglext.h"
#include "GLES3/gl32.h"

#include "pixel_map_gl_utils.h"
#include "securec.h"
#include "window.h"

namespace OHOS {
namespace Media {
namespace PixelMapGlResource {
constexpr size_t MAX_GL_TRANSFER_SIZE = 8192;

inline void DeleteTexture(GLuint &textureId)
{
    if (textureId != 0U) {
        glDeleteTextures(1, &textureId);
        textureId = 0U;
    }
}

inline void DeleteBuffer(GLuint &bufferId)
{
    if (bufferId != 0U) {
        glDeleteBuffers(1, &bufferId);
        bufferId = 0U;
    }
}

inline void DeleteFramebuffer(GLuint &framebufferId)
{
    if (framebufferId != 0U) {
        glDeleteFramebuffers(1, &framebufferId);
        framebufferId = 0U;
    }
}

class ScopedNativeWindowBuffer {
public:
    explicit ScopedNativeWindowBuffer(OHNativeWindowBuffer *buffer = nullptr) : buffer_(buffer) {}
    ~ScopedNativeWindowBuffer()
    {
        Reset();
    }

    ScopedNativeWindowBuffer(const ScopedNativeWindowBuffer &) = delete;
    ScopedNativeWindowBuffer &operator=(const ScopedNativeWindowBuffer &) = delete;

    ScopedNativeWindowBuffer(ScopedNativeWindowBuffer &&other) noexcept : buffer_(other.Release()) {}
    ScopedNativeWindowBuffer &operator=(ScopedNativeWindowBuffer &&other) noexcept
    {
        if (this != &other) {
            Reset(other.Release());
        }
        return *this;
    }

    void Reset(OHNativeWindowBuffer *buffer = nullptr)
    {
        if (buffer_ != nullptr) {
            DestroyNativeWindowBuffer(buffer_);
        }
        buffer_ = buffer;
    }

    OHNativeWindowBuffer *Get() const
    {
        return buffer_;
    }

    OHNativeWindowBuffer *Release()
    {
        OHNativeWindowBuffer *buffer = buffer_;
        buffer_ = nullptr;
        return buffer;
    }

private:
    OHNativeWindowBuffer *buffer_ = nullptr;
};

class ScopedTexture {
public:
    explicit ScopedTexture(GLuint textureId = 0U) : textureId_(textureId) {}
    ~ScopedTexture()
    {
        Reset();
    }

    ScopedTexture(const ScopedTexture &) = delete;
    ScopedTexture &operator=(const ScopedTexture &) = delete;

    ScopedTexture(ScopedTexture &&other) noexcept : textureId_(other.Release()) {}
    ScopedTexture &operator=(ScopedTexture &&other) noexcept
    {
        if (this != &other) {
            Reset(other.Release());
        }
        return *this;
    }

    GLuint Get() const
    {
        return textureId_;
    }

    GLuint Release()
    {
        GLuint textureId = textureId_;
        textureId_ = 0U;
        return textureId;
    }

    void Reset(GLuint textureId = 0U)
    {
        DeleteTexture(textureId_);
        textureId_ = textureId;
    }

private:
    GLuint textureId_ = 0U;
};

class ScopedBuffer {
public:
    explicit ScopedBuffer(GLuint bufferId = 0U) : bufferId_(bufferId) {}
    ~ScopedBuffer()
    {
        Reset();
    }

    ScopedBuffer(const ScopedBuffer &) = delete;
    ScopedBuffer &operator=(const ScopedBuffer &) = delete;

    ScopedBuffer(ScopedBuffer &&other) noexcept : bufferId_(other.Release()) {}
    ScopedBuffer &operator=(ScopedBuffer &&other) noexcept
    {
        if (this != &other) {
            Reset(other.Release());
        }
        return *this;
    }

    GLuint Get() const
    {
        return bufferId_;
    }

    GLuint Release()
    {
        GLuint bufferId = bufferId_;
        bufferId_ = 0U;
        return bufferId;
    }

    void Reset(GLuint bufferId = 0U)
    {
        DeleteBuffer(bufferId_);
        bufferId_ = bufferId;
    }

private:
    GLuint bufferId_ = 0U;
};

class ScopedFramebuffer {
public:
    explicit ScopedFramebuffer(GLuint framebufferId = 0U) : framebufferId_(framebufferId) {}
    ~ScopedFramebuffer()
    {
        Reset();
    }

    ScopedFramebuffer(const ScopedFramebuffer &) = delete;
    ScopedFramebuffer &operator=(const ScopedFramebuffer &) = delete;

    ScopedFramebuffer(ScopedFramebuffer &&other) noexcept : framebufferId_(other.Release()) {}
    ScopedFramebuffer &operator=(ScopedFramebuffer &&other) noexcept
    {
        if (this != &other) {
            Reset(other.Release());
        }
        return *this;
    }

    GLuint Get() const
    {
        return framebufferId_;
    }

    GLuint Release()
    {
        GLuint framebufferId = framebufferId_;
        framebufferId_ = 0U;
        return framebufferId;
    }

    void Reset(GLuint framebufferId = 0U)
    {
        DeleteFramebuffer(framebufferId_);
        framebufferId_ = framebufferId;
    }

private:
    GLuint framebufferId_ = 0U;
};

class ScopedEglImage {
public:
    ScopedEglImage() = default;
    ~ScopedEglImage()
    {
        Reset();
    }

    ScopedEglImage(const ScopedEglImage &) = delete;
    ScopedEglImage &operator=(const ScopedEglImage &) = delete;

    void Set(EGLDisplay display, EGLImageKHR image)
    {
        Reset();
        display_ = display;
        image_ = image;
    }

    EGLImageKHR Get() const
    {
        return image_;
    }

    EGLImageKHR Release()
    {
        EGLImageKHR image = image_;
        display_ = EGL_NO_DISPLAY;
        image_ = EGL_NO_IMAGE_KHR;
        return image;
    }

    void Reset()
    {
        if (display_ != EGL_NO_DISPLAY && image_ != EGL_NO_IMAGE_KHR) {
            (void)eglDestroyImageKHR(display_, image_);
        }
        display_ = EGL_NO_DISPLAY;
        image_ = EGL_NO_IMAGE_KHR;
    }

private:
    EGLDisplay display_ = EGL_NO_DISPLAY;
    EGLImageKHR image_ = EGL_NO_IMAGE_KHR;
};

inline bool IsValidGlTransferSize(size_t size)
{
    return size <= MAX_GL_TRANSFER_SIZE;
}

inline bool CopyStridedToLinear(const uint8_t *src, int32_t srcStride, int32_t height, size_t rowBytes,
    char *dst, size_t dstSize)
{
    if (src == nullptr || dst == nullptr || srcStride <= 0 || height <= 0 || rowBytes == 0) {
        return false;
    }
    for (int32_t i = 0; i < height; ++i) {
        const size_t rowOffset = rowBytes * static_cast<size_t>(i);
        if (rowOffset > dstSize || dstSize - rowOffset < rowBytes) {
            return false;
        }
        if (memcpy_s(dst + rowOffset, dstSize - rowOffset,
            src + static_cast<size_t>(srcStride) * static_cast<size_t>(i), rowBytes) != EOK) {
            return false;
        }
    }
    return true;
}

inline bool CopyLinearToStrided(const char *src, size_t srcSize, size_t rowBytes, int32_t height,
    uint8_t *dst, int32_t dstStride)
{
    if (src == nullptr || dst == nullptr || dstStride <= 0 || height <= 0 || rowBytes == 0) {
        return false;
    }
    for (int32_t i = 0; i < height; ++i) {
        const size_t srcOffset = rowBytes * static_cast<size_t>(i);
        const size_t dstOffset = static_cast<size_t>(dstStride) * static_cast<size_t>(i);
        const size_t dstRemain = static_cast<size_t>(dstStride) * static_cast<size_t>(height - i);
        if (srcOffset > srcSize || srcSize - srcOffset < rowBytes || dstRemain < rowBytes) {
            return false;
        }
        if (memcpy_s(dst + dstOffset, dstRemain, src + srcOffset, rowBytes) != EOK) {
            return false;
        }
    }
    return true;
}

inline bool ValidateTransferLayout(const Size &size, int32_t stride, int32_t pixelBytes,
    size_t &rowBytes, size_t &contiguousSize)
{
    if (!PixelMapGlUtils::ValidateImageLayout(size, stride, pixelBytes, rowBytes, contiguousSize)) {
        return false;
    }
    return IsValidGlTransferSize(contiguousSize);
}
} // namespace PixelMapGlResource
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_RESOURCE_H
