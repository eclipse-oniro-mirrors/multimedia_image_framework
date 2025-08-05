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

#include <cstdint>

#include "image_format.h"
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

ImageImpl::ImageImpl() : nativeImage_(nullptr) {}

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
    NativeRelease();
}

static inline bool IsEqual(const int32_t& check, OHOS::Media::ImageFormat format)
{
    return (check == int32_t(format));
}
static inline bool IsEqual(const int32_t& check, OHOS::Media::ComponentType type)
{
    return (check == int32_t(type));
}
static inline bool IsYUVComponent(const int32_t& type)
{
    return (IsEqual(type, OHOS::Media::ComponentType::YUV_Y) ||
        IsEqual(type, OHOS::Media::ComponentType::YUV_U) ||
        IsEqual(type, OHOS::Media::ComponentType::YUV_V));
}
static inline bool IsYUV422SPImage(int32_t format)
{
    return (IsEqual(format, OHOS::Media::ImageFormat::YCBCR_422_SP) ||
        (format == int32_t(OHOS::GRAPHIC_PIXEL_FMT_YCBCR_422_SP)));
}
static inline bool CheckComponentType(const int32_t& type, int32_t format)
{
    return ((IsYUV422SPImage(format) && IsYUVComponent(type)) ||
        (!IsYUV422SPImage(format) && IsEqual(type, OHOS::Media::ComponentType::JPEG)));
}

static Component MakeEmptyComponent()
{
    return {ComponentType(ComponentType::key_t::YUV_Y), 0, 0, array<uint8_t>(0)};
}

static Component MakeComponent(int32_t type, OHOS::Media::NativeComponent *nativeComponent)
{
    ComponentType::key_t componentTypeKey;
    ImageTaiheUtils::GetEnumKeyByValue<ComponentType>(static_cast<int32_t>(type), componentTypeKey);
    if (nativeComponent == nullptr) {
        IMAGE_LOGE("nativeComponent is nullptr");
        return {ComponentType(componentTypeKey), 0, 0, array<uint8_t>(0)};
    }
    uint8_t *buffer = nullptr;
    if (nativeComponent->virAddr != nullptr) {
        buffer = nativeComponent->virAddr;
    } else {
        buffer = nativeComponent->raw.data();
    }
    if (buffer == nullptr || nativeComponent->size == 0) {
        IMAGE_LOGE("Invalid buffer");
        return MakeEmptyComponent();
    }

    Component result {
        .componentType = ComponentType(componentTypeKey),
        .rowStride = nativeComponent->rowStride,
        .pixelStride = nativeComponent->pixelStride,
        .byteBuffer = ImageTaiheUtils::CreateTaiheArrayBuffer(buffer, nativeComponent->size),
    };
    return result;
}

int64_t ImageImpl::GetImplPtr()
{
    return static_cast<int64_t>(reinterpret_cast<uintptr_t>(this));
}

struct Image ImageImpl::Create(std::shared_ptr<OHOS::Media::NativeImage> nativeImage)
{
    return make_holder<ImageImpl, struct Image>(nativeImage);
}

void ImageImpl::ReleaseSync()
{
    NativeRelease();
}

void ImageImpl::NativeRelease()
{
    if (nativeImage_ != nullptr) {
        sNativeImageHolder_.release(nativeImage_->GetId());
        nativeImage_->release();
        nativeImage_ = nullptr;
    }
}

static ohos::multimedia::image::image::Region BuildRegion(int32_t width, int32_t height, int32_t x, int32_t y)
{
    Size size {width, height};
    ohos::multimedia::image::image::Region result = {size, x, y};
    return result;
}

ohos::multimedia::image::image::Region ImageImpl::GetClipRect()
{
    ohos::multimedia::image::image::Region errResult = BuildRegion(NUM0, NUM0, NUM0, NUM0);
    if (isTestImage_) {
        return BuildRegion(TEST_WIDTH, TEST_HEIGHT, NUM0, NUM0);
    }
    if (nativeImage_ == nullptr) {
        IMAGE_LOGE("Image surface buffer is nullptr");
        return errResult;
    }

    int32_t width = NUM0;
    int32_t height = NUM0;
    if (nativeImage_->GetSize(width, height) != OHOS::Media::SUCCESS) {
        IMAGE_LOGE("Image native get size failed");
        return errResult;
    }
    return BuildRegion(width, height, NUM0, NUM0);
}

Size ImageImpl::GetSize()
{
    int width = NUM0;
    int height = NUM0;
    if (isTestImage_) {
        return {TEST_WIDTH, TEST_HEIGHT};
    }
    if (nativeImage_ == nullptr) {
        IMAGE_LOGE("Image surface buffer is nullptr");
        return {width, height};
    }

    if (nativeImage_->GetSize(width, height) != OHOS::Media::SUCCESS) {
        IMAGE_LOGE("Image native get size failed");
    }
    return {width, height};
}

Component ImageImpl::GetComponentSync(ComponentType componentType)
{
    int32_t argc = componentType.get_value();
    if (nativeImage_ == nullptr && !isTestImage_) {
        IMAGE_LOGE("native is nullptr");
        return MakeEmptyComponent();
    }

    int32_t format = NUM0;
    if (isTestImage_) {
        const int32_t TEST_FORMAT = 12;
        format = TEST_FORMAT;
    } else {
        nativeImage_->GetFormat(format);
    }

    if (!CheckComponentType(argc, format)) {
        IMAGE_LOGE("Unsupport component type 0 value: %{public}d", argc);
        return MakeEmptyComponent();
    }

    if (isTestImage_) {
        return MakeComponent(argc, nullptr);
    }

    OHOS::Media::NativeComponent *nativeComponent = nativeImage_->GetComponent(argc);
    if (nativeComponent == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERROR, "nativeComponent is nullptr");
        return MakeEmptyComponent();
    }

    return MakeComponent(argc, nativeComponent);
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

int64_t ImageImpl::GetTimestamp()
{
    int64_t result = 0;
    if (nativeImage_ == nullptr) {
        IMAGE_LOGE("Image native is nullptr");
        return result;
    }

    if (nativeImage_->GetTimestamp(result) != OHOS::Media::SUCCESS) {
        IMAGE_LOGE("Image native get timestamp failed");
    }
    return result;
}
} // namespace ANI::Image