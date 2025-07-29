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

#include "image_log.h"
#include "image_taihe.h"
#include "image_taihe_utils.h"
#include "media_errors.h"

using namespace ANI::Image;

namespace {
    constexpr int NUM0 = 0;
    const std::string MY_NAME = "ImageTaihe";
    constexpr int32_t TEST_WIDTH = 8192;
    constexpr int32_t TEST_HEIGHT = 8;
    constexpr int32_t TEST_FORMAT = 12;
}

namespace ANI::Image {
OHOS::Media::ImageHolderManager<OHOS::Media::NativeImage> ImageImpl::sNativeImageHolder_;

ImageImpl::ImageImpl() : nativeImage_(nullptr), isTestImage_(false), isRelease(false) {}

ImageImpl::ImageImpl(std::shared_ptr<OHOS::Media::NativeImage> nativeImage)
{
    if (nativeImage == nullptr) {
        IMAGE_LOGE("nativeImage is nullptr");
        ImageTaiheUtils::ThrowExceptionError("nativeImage is nullptr");
        return;
    }

    auto id = sNativeImageHolder_.save(nativeImage);
    nativeImage->SetId(id);
    nativeImage_ = sNativeImageHolder_.get(id);
    isTestImage_ = false;
    if (nativeImage_ == nullptr) {
        if (MY_NAME.compare(id.c_str()) == 0) {
            isTestImage_ = true;
        } else {
            IMAGE_LOGE("Failed to get native image");
            ImageTaiheUtils::ThrowExceptionError("Failed to get native image");
            return;
        }
    }
}

ImageImpl::~ImageImpl()
{
    ReleaseSync();
}

struct Image ImageImpl::Create(std::shared_ptr<OHOS::Media::NativeImage> nativeImage)
{
    return make_holder<ImageImpl, struct Image>(nativeImage);
}

void ImageImpl::ReleaseSync()
{
    if (!isRelease) {
        if (nativeImage_ != nullptr) {
            nativeImage_ = nullptr;
        }
        isRelease = true;
    }
}

Size ImageImpl::GetSize()
{
    Size result {NUM0, NUM0};
    if (isTestImage_) {
        result.width = TEST_WIDTH;
        result.height = TEST_HEIGHT;
        return result;
    }
    if (nativeImage_ == nullptr) {
        IMAGE_LOGE("Image surface buffer is nullptr");
        return result;
    }

    if (nativeImage_->GetSize(result.width, result.height) != OHOS::Media::SUCCESS) {
        IMAGE_LOGE("Image native get size failed");
    }
    return result;
}

int32_t ImageImpl::GetFormat()
{
    int32_t format = NUM0;
    if (isTestImage_) {
        return TEST_FORMAT;
    }
    if (nativeImage_ == nullptr) {
        IMAGE_LOGE("Image surface buffer is nullptr");
        return format;
    }

    if (nativeImage_->GetFormat(format) != OHOS::Media::SUCCESS) {
        IMAGE_LOGE("Image native get format failed");
    }
    return format;
}
} // namespace ANI::Image