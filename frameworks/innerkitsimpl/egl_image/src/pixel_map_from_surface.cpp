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

#include "pixel_map_from_surface.h"

#include "image_log.h"
#include "sync_fence.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PixelMap"

namespace OHOS {
namespace Media {

PixelMapFromSurface::PixelMapFromSurface()
{}

PixelMapFromSurface::~PixelMapFromSurface() noexcept
{
    Clear();
}

void PixelMapFromSurface::Clear() noexcept
{
    if (eglImage_ != EGL_NO_IMAGE_KHR) {
        if (renderContext_ != nullptr) {
            eglDestroyImageKHR(renderContext_->GetEGLDisplay(), eglImage_);
        } else {
            auto disp = eglGetDisplay(EGL_DEFAULT_DISPLAY);
            eglDestroyImageKHR(disp, eglImage_);
        }
        eglImage_ = EGL_NO_IMAGE_KHR;
    }

    if (texId_ != 0U) {
        glDeleteTextures(1, &texId_);
        texId_ = 0U;
    }

    surfaceBuffer_ = nullptr;
    if (nativeWindowBuffer_ != nullptr) {
        DestroyNativeWindowBuffer(nativeWindowBuffer_);
        nativeWindowBuffer_ = nullptr;
    }
}

bool PixelMapFromSurface::GetNativeWindowBufferFromSurface(const sptr<Surface> &surface, const Rect &srcRect)
{
    // private func, surface is not nullptr.
    sptr<SyncFence> fence;
    // a 4 * 4 idetity matrix
    float matrix[16] = {
        1, 0, 0, 0,
        0, 1, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 1
    };
    int ret = surface->GetLastFlushedBuffer(surfaceBuffer_, fence, matrix);
    if (ret != OHOS::GSERROR_OK || surfaceBuffer_ == nullptr) {
        Clear();
        IMAGE_LOGE(
            "CreatePixelMapFromSurface: GetLastFlushedBuffer from nativeWindow failed, err: %{public}d",
            ret);
        return false;
    }

    int bufferWidth = surfaceBuffer_->GetWidth();
    int bufferHeight = surfaceBuffer_->GetHeight();
    if (srcRect.width > bufferWidth || srcRect.height > bufferHeight ||
        srcRect.left >= bufferWidth || srcRect.top >= bufferHeight ||
        srcRect.left + srcRect.width > bufferWidth || srcRect.top + srcRect.height > bufferHeight) {
        IMAGE_LOGE(
            "CreatePixelMapFromSurface: invalid argument: srcRect[%{public}d, %{public}d, %{public}d, %{public}d],"
            "bufferSize:[%{public}d, %{public}d]",
            srcRect.left, srcRect.top, srcRect.width, srcRect.height,
            surfaceBuffer_->GetWidth(), surfaceBuffer_->GetHeight());
        return false;
    }

    if (fence != nullptr) {
        fence->Wait(3000); // wait at most 3000ms
    }
    nativeWindowBuffer_ = CreateNativeWindowBufferFromSurfaceBuffer(&surfaceBuffer_);
    return nativeWindowBuffer_ != nullptr;
}

bool PixelMapFromSurface::CreateEGLImage()
{
    EGLint attrs[] = {
        EGL_IMAGE_PRESERVED,
        EGL_TRUE,
        EGL_NONE,
    };
    eglImage_ = eglCreateImageKHR(
        renderContext_->GetEGLDisplay(), EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_OHOS,
        nativeWindowBuffer_, attrs);
    if (eglImage_ == EGL_NO_IMAGE_KHR) {
        Clear();
        IMAGE_LOGE("%{public}s create egl image fail %{public}d", __func__, eglGetError());
        return false;
    }
    glGenTextures(1, &texId_);
    glBindTexture(GL_TEXTURE_EXTERNAL_OES, texId_);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_EXTERNAL_OES, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    static auto glEGLImageTargetTexture2DOESFunc = reinterpret_cast<PFNGLEGLIMAGETARGETTEXTURE2DOESPROC>(
        eglGetProcAddress("glEGLImageTargetTexture2DOES"));
    if (glEGLImageTargetTexture2DOESFunc == nullptr) {
        Clear();
        IMAGE_LOGE("%{public}s glEGLImageTargetTexture2DOES func not found: %{public}d",
            __func__, eglGetError());
        return false;
    }
    glEGLImageTargetTexture2DOESFunc(GL_TEXTURE_EXTERNAL_OES, static_cast<GLeglImageOES>(eglImage_));
    return true;
}

bool PixelMapFromSurface::DrawImage(const Rect &srcRect)
{
    GraphicPixelFormat pixelFormat = static_cast<GraphicPixelFormat>(surfaceBuffer_->GetFormat());
    SkColorType colorType = kRGBA_8888_SkColorType;
    GLuint glType = GL_RGBA8;
    int bufferWidth = surfaceBuffer_->GetWidth();
    int bufferHeight = surfaceBuffer_->GetHeight();
    if (pixelFormat == GRAPHIC_PIXEL_FMT_BGRA_8888) {
        colorType = kBGRA_8888_SkColorType;
    } else if (pixelFormat == GRAPHIC_PIXEL_FMT_YCBCR_P010 || pixelFormat == GRAPHIC_PIXEL_FMT_YCRCB_P010) {
        colorType = kRGBA_1010102_SkColorType;
        glType = GL_RGB10_A2;
    }
    GrGLTextureInfo grExternalTextureInfo = { GL_TEXTURE_EXTERNAL_OES, texId_, static_cast<GrGLenum>(glType) };
    auto backendTexturePtr =
        std::make_shared<GrBackendTexture>(bufferWidth, bufferHeight, GrMipMapped::kNo, grExternalTextureInfo);
    auto image = SkImage::MakeFromTexture(renderContext_->GetGrContext().get(), *backendTexturePtr,
        kTopLeft_GrSurfaceOrigin, colorType, kPremul_SkAlphaType, nullptr);
    if (image == nullptr) {
        Clear();
        IMAGE_LOGE("%{public}s create SkImage failed.", __func__);
        return false;
    }

    auto imageInfo = SkImageInfo::Make(srcRect.width, srcRect.height, kRGBA_8888_SkColorType, kPremul_SkAlphaType);
    targetSurface_ = SkSurface::MakeRenderTarget(renderContext_->GetGrContext().get(), SkBudgeted::kYes,
        imageInfo, 0, kTopLeft_GrSurfaceOrigin, nullptr);
    if (targetSurface_ == nullptr) {
        Clear();
        IMAGE_LOGE("%{public}s SkSurface::MakeRenderTarget failed.", __func__);
        return false;
    }

    SkCanvas* canvas = targetSurface_->getCanvas();
    SkPaint paint;
    paint.setStyle(SkPaint::kFill_Style);
    SkSamplingOptions sampling(SkFilterMode::kNearest);
    canvas->drawImageRect(image,
        SkRect::MakeXYWH(srcRect.left, srcRect.top, srcRect.width, srcRect.height),
        SkRect::MakeWH(srcRect.width, srcRect.height),
        sampling, &paint, SkCanvas::kStrict_SrcRectConstraint);
    canvas->flush();
    return true;
}

std::unique_ptr<PixelMap> PixelMapFromSurface::Create(uint64_t surfaceId, const Rect &srcRect)
{
    if (srcRect.left < 0 || srcRect.top < 0 || srcRect.width <= 0 || srcRect.height <= 0) {
        IMAGE_LOGE(
            "CreatePixelMapFromSurface: invalid argument: srcRect[%{public}d, %{public}d, %{public}d, %{public}d]",
            srcRect.left, srcRect.top, srcRect.width, srcRect.height);
        return nullptr;
    }

    Clear();
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(surfaceId);
    if (surface == nullptr) {
        IMAGE_LOGE(
            "CreatePixelMapFromSurface: can't find surface for surfaceId: %{public}" PRIu64 ".", surfaceId);
        return nullptr;
    }

    if (!GetNativeWindowBufferFromSurface(surface, srcRect)) {
        return nullptr;
    }

    // init renderContext to do some format convertion if necessary.
    renderContext_ = std::make_unique<RenderContext>();
    if (!renderContext_->Init()) {
        Clear();
        IMAGE_LOGE("CreatePixelMapFromSurface: init renderContext failed.");
        return nullptr;
    }

    if (!CreateEGLImage()) {
        return nullptr;
    }

    if (!DrawImage(srcRect)) {
        return nullptr;
    }

    InitializationOptions options;
    options.size.width = srcRect.width;
    options.size.height = srcRect.height;
    options.srcPixelFormat = PixelFormat::RGBA_8888;
    options.pixelFormat = PixelFormat::RGBA_8888;
    auto pixelMap = PixelMap::Create(options);
    auto imageInfo = SkImageInfo::Make(srcRect.width, srcRect.height, kRGBA_8888_SkColorType, kPremul_SkAlphaType);
    SkPixmap skPixmap(imageInfo, pixelMap->GetPixel(0, 0), pixelMap->GetRowBytes());
    targetSurface_->readPixels(skPixmap, 0, 0);
    return pixelMap;
}

std::unique_ptr<PixelMap> CreatePixelMapFromSurfaceId(uint64_t surfaceId, const Rect &srcRect)
{
    auto helper = std::make_unique<PixelMapFromSurface>();
    return helper->Create(surfaceId, srcRect);
}
} // namespace Media
} // namespace OHOS
