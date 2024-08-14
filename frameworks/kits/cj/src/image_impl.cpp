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
#include "image_impl.h"
#include "image_log.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {

const int32_t DEFAULT_FORMAT = 12;
const int32_t DEFAULT_HEIGHT = 8;
const int32_t DEFAULT_WIDTH = 8192;

ImageHolderManager<NativeImage> ImageImpl::sNativeImageHolder_;

ImageImpl::ImageImpl(std::shared_ptr<NativeImage> nativeImage)
{
    ImageImpl::Create(this, nativeImage);
}

std::shared_ptr<NativeImage> ImageImpl::GetNativeImage()
{
    return native_;
}

int64_t ImageImpl::Create(ImageImpl *image, std::shared_ptr<NativeImage> nativeImage)
{
    auto id = sNativeImageHolder_.save(nativeImage);
    image->native_ = sNativeImageHolder_.get(id);
    image->isTestImage_ = false;
    if (image->native_ == nullptr) {
        IMAGE_LOGE("[ImageImpl] Create : Failed to get native image");
        return INIT_FAILED;
    }
    return SUCCESS;
}

uint32_t ImageImpl::GetClipRect(CRegion *ret)
{
    if (isTestImage_ == true) {
        ret->size.width = DEFAULT_WIDTH;
        ret->size.height = DEFAULT_HEIGHT;
        ret->x = 0;
        ret->y = 0;
        return SUCCESS;
    }
    if (native_ == nullptr) {
        IMAGE_LOGE("Image buffer cannot be nullptr");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t retCode = native_->GetSize(ret->size.width, ret->size.height);
    ret->x = 0;
    ret->y = 0;
    if (retCode != SUCCESS) {
        IMAGE_LOGE("[ImageImpl] GetSize : Image native get size failed.");
    }
    return retCode;
}

uint32_t ImageImpl::GetSize(CSize *ret)
{
    if (isTestImage_ == true) {
        ret->width = DEFAULT_WIDTH;
        ret->height = DEFAULT_HEIGHT;
        return SUCCESS;
    }
    if (native_ == nullptr) {
        IMAGE_LOGE("Image buffer cannot be nullptr");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t retCode = native_->GetSize(ret->width, ret->height);
    if (retCode != SUCCESS) {
        IMAGE_LOGE("[ImageImpl] GetSize : Image native get size failed.");
    }
    return retCode;
}

uint32_t ImageImpl::GetFormat(int32_t *ret)
{
    if (isTestImage_ == true) {
        *ret = DEFAULT_FORMAT;
        return SUCCESS;
    }
    if (native_ == nullptr) {
        IMAGE_LOGE("Image buffer cannot be nullptr");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t retCode = native_->GetFormat(*ret);
    if (retCode != SUCCESS) {
        IMAGE_LOGE("[ImageImpl] GetFormat : Image native get format failed.");
    }
    return retCode;
}

uint32_t ImageImpl::GetComponent(int32_t componentType, CRetComponent *ret)
{
    if (native_ == nullptr) {
        IMAGE_LOGE("Image buffer cannot be nullptr");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    auto nativePtr = native_->GetComponent(componentType);
    if (nativePtr == nullptr) {
        IMAGE_LOGE("Image component is nullptr");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    ret->componentType = componentType;
    ret->rowStride = nativePtr->rowStride;
    ret->pixelStride = nativePtr->pixelStride;
    int64_t len = static_cast<int64_t>(nativePtr->raw.size());
    ret->byteBuffer = static_cast<uint8_t*>(malloc(len + 1));
    if (ret->byteBuffer == nullptr) {
        IMAGE_LOGE("[ImageImpl] GetComponent failed to malloc.");
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    for (int i = 0; i < len; i++) {
        ret->byteBuffer[i] = nativePtr->raw[i];
    }
    ret->byteBuffer[len] = '\0';
    ret->bufSize = len + 1;
    return SUCCESS;
}

void ImageImpl::Release() {}
}  // namespace Media
}  // namespace OHOS