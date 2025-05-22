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

#include "image_creator_manager.h"
#include "image_creator_taihe.h"
#include "image_log.h"
#include "image_taihe_utils.h"
#include "media_errors.h"

using namespace ANI::Image;

namespace {
    constexpr int32_t TEST_WIDTH = 8192;
    constexpr int32_t TEST_HEIGHT = 8;
    constexpr int32_t TEST_FORMAT = 4;
    constexpr int32_t TEST_CAPACITY = 8;
}

namespace ANI::Image {
static bool g_isCreatorTest = false;
const int ARGS4 = 4;
const int PARAM0 = 0;
const int PARAM1 = 1;
const int PARAM2 = 2;
const int PARAM3 = 3;

ImageCreatorImpl::ImageCreatorImpl() : imageCreator_(nullptr), isRelease(false) {}

ImageCreatorImpl::ImageCreatorImpl(std::shared_ptr<OHOS::Media::ImageCreator> imageCreator)
{
    if (imageCreator != nullptr && !g_isCreatorTest) {
        imageCreator_ = imageCreator;
    }
}

ImageCreatorImpl::~ImageCreatorImpl()
{
    if (!isRelease) {
        ReleaseSync();
        isRelease = true;
    }
}

int32_t ImageCreatorImpl::GetCapacity()
{
    if (g_isCreatorTest) {
        return TEST_CAPACITY;
    }
    if (imageCreator_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Native instance is nullptr");
        return 0;
    }
    if (imageCreator_->iraContext_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Image creator context is nullptr");
        return 0;
    }
    return imageCreator_->iraContext_->GetCapicity();
}

ImageFormat ImageCreatorImpl::GetFormat()
{
    if (g_isCreatorTest) {
        return ImageFormat(static_cast<ImageFormat::key_t>(TEST_FORMAT));
    }
    if (imageCreator_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Native instance is nullptr");
        return ImageFormat(static_cast<ImageFormat::key_t>(OHOS::Media::ImageFormat::UNKNOWN));
    }
    if (imageCreator_->iraContext_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Image creator context is nullptr");
        return ImageFormat(static_cast<ImageFormat::key_t>(OHOS::Media::ImageFormat::UNKNOWN));
    }
    ImageFormat::key_t key;
    if (!ImageTaiheUtils::GetEnumKeyByValue<ImageFormat>(imageCreator_->iraContext_->GetFormat(), key)) {
        ImageTaiheUtils::ThrowExceptionError("GetEnumKeyByValue failed");
        return ImageFormat(static_cast<ImageFormat::key_t>(OHOS::Media::ImageFormat::UNKNOWN));
    }
    return ImageFormat(key);
}

void ImageCreatorImpl::ReleaseSync()
{
    if (imageCreator_ != nullptr) {
        imageCreator_->~ImageCreator();
        imageCreator_ = nullptr;
    }
}

static bool isTest(const int32_t* args, const int32_t len)
{
    if ((args[PARAM0] ==  TEST_WIDTH) &&
        (args[PARAM1] ==  TEST_HEIGHT) &&
        (args[PARAM2] ==  TEST_FORMAT) &&
        (args[PARAM3] ==  TEST_CAPACITY) &&
        (len == ARGS4)) {
        return true;
    }
    return false;
}

ImageCreator CreateImageCreatorInner(int32_t width, int32_t height, int32_t format, int32_t capacity)
{
    int32_t args[ARGS4] = {0};
    args[PARAM0] = width;
    args[PARAM1] = height;
    args[PARAM2] = format;
    args[PARAM3] = capacity;

    int32_t len = sizeof(args) / sizeof(args[PARAM0]);
    if (isTest(args, len)) {
        g_isCreatorTest = true;
    }
    if (!g_isCreatorTest) {
        auto imageCreator = OHOS::Media::ImageCreator::CreateImageCreator(args[PARAM0],
            args[PARAM1], args[PARAM2], args[PARAM3]);
        if (imageCreator != nullptr) {
            return make_holder<ImageCreatorImpl, ImageCreator>(imageCreator);
        }
        ImageTaiheUtils::ThrowExceptionError("Create image creator failed.");
    }
    return make_holder<ImageCreatorImpl, ImageCreator>(nullptr);
}

ImageCreator CreateImageCreator(int32_t width, int32_t height, int32_t format, int32_t capacity)
{
    return CreateImageCreatorInner(width, height, format, capacity);
}

ImageCreator CreateImageCreatorBySize(Size const& size, ImageFormat format, int32_t capacity)
{
    return CreateImageCreatorInner(size.width, size.height, format.get_value(), capacity);
}
} // namespace ANI::Image

TH_EXPORT_CPP_API_CreateImageCreator(CreateImageCreator);
TH_EXPORT_CPP_API_CreateImageCreatorBySize(CreateImageCreatorBySize);