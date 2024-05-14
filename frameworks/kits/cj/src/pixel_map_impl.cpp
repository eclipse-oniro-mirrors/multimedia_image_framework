/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "pixel_map_impl.h"
#include "image_log.h"
#include "media_errors.h"
 
namespace OHOS {
namespace Media {
std::shared_ptr<PixelMap> PixelMapImpl::GetRealPixelMap()
{
    return real_;
}

std::unique_ptr<PixelMap> PixelMapImpl::CreatePixelMap(const InitializationOptions &opts)
{
    std::unique_ptr<PixelMap> ptr_ = PixelMap::Create(opts);
    if (ptr_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] instance init failed!");
    }
    return ptr_;
}

std::unique_ptr<PixelMap> PixelMapImpl::CreatePixelMap(uint32_t *colors, uint32_t colorLength,
    InitializationOptions &opts)
{
    std::unique_ptr<PixelMap> ptr_ = PixelMap::Create(colors, colorLength, opts);
    if (ptr_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] instance init failed!");
    }
    return ptr_;
}

std::unique_ptr<PixelMap> PixelMapImpl::CreateAlphaPixelMap(PixelMap &source, InitializationOptions &opts)
{
    std::unique_ptr<PixelMap> ptr_ = PixelMap::Create(source, opts);
    if (ptr_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] instance init failed!");
    }
    return ptr_;
}

PixelMapImpl::PixelMapImpl(std::shared_ptr<PixelMap> ptr_)
{
    real_ = ptr_;
}

uint32_t PixelMapImpl::ReadPixelsToBuffer(uint64_t &bufferSize, uint8_t *dst)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->ReadPixels(bufferSize, dst);
}

uint32_t PixelMapImpl::ReadPixels(uint64_t &bufferSize, uint32_t &offset, uint32_t &stride, Rect &region, uint8_t *dst)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->ReadPixels(bufferSize, offset, stride, region, dst);
}

uint32_t PixelMapImpl::WriteBufferToPixels(uint8_t *source, uint64_t &bufferSize)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->WritePixels(source, bufferSize);
}

uint32_t PixelMapImpl::WritePixels(uint8_t *source, uint64_t &bufferSize, uint32_t &offset, uint32_t &stride,
    Rect &region)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->WritePixels(source, bufferSize, offset, stride, region);
}

void PixelMapImpl::GetImageInfo(ImageInfo &imageInfo)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return;
    }
    real_->GetImageInfo(imageInfo);
}

int32_t PixelMapImpl::GetDensity()
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return 0;
    }
    return real_->GetBaseDensity();
}

uint32_t PixelMapImpl::Opacity(float percent)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->SetAlpha(percent);
}

void PixelMapImpl::Scale(float xAxis, float yAxis)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return;
    }
    real_->scale(xAxis, yAxis);
}

uint32_t PixelMapImpl::Crop(Rect &rect)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->crop(rect);
}

void PixelMapImpl::Flip(bool xAxis, bool yAxis)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return;
    }
    real_->flip(xAxis, yAxis);
}

void PixelMapImpl::Rotate(float degrees)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return;
    }
    real_->rotate(degrees);
}

void PixelMapImpl::Translate(float xAxis, float yAxis)
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return;
    }
    real_->translate(xAxis, yAxis);
}

uint32_t PixelMapImpl::GetPixelBytesNumber()
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return 0;
    }
    return real_->GetByteCount();
}

uint32_t PixelMapImpl::GetBytesNumberPerRow()
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return 0;
    }
    return real_->GetRowBytes();
}

bool PixelMapImpl::GetIsEditable()
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return false;
    }
    return real_->IsEditable();
}

bool PixelMapImpl::GetIsStrideAlignment()
{
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return false;
    }
    bool isDMA = real_->IsStrideAlignment();
    return isDMA;
}

uint32_t PixelMapImpl::SetColorSpace(std::shared_ptr<OHOS::ColorManager::ColorSpace> colorSpace)
{
#ifdef IMAGE_COLORSPACE_FLAG
    if (real_ == nullptr) {
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }
    real_->InnerSetColorSpace(*colorSpace);
    return 0;
#else
    return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
#endif
}

std::shared_ptr<OHOS::ColorManager::ColorSpace> PixelMapImpl::GetColorSpace()
{
#ifdef IMAGE_COLORSPACE_FLAG
    if (real_ == nullptr) {
        IMAGE_LOGE("[PixelMapImpl] get instance!");
        return nullptr;
    }
    auto colorSpace = real_->InnerGetGrColorSpacePtr();
    return colorSpace;
#else
    return nullptr;
#endif
}

uint32_t PixelMapImpl::ApplyColorSpace(std::shared_ptr<OHOS::ColorManager::ColorSpace> colorSpace)
{
    if (real_ == nullptr) {
        return ERR_IMAGE_READ_PIXELMAP_FAILED;
    }
    return real_->ApplyColorSpace(*colorSpace);
}
}
}