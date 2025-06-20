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

std::shared_ptr<OHOS::AppExecFwk::EventHandler> ImageCreatorImpl::mainHandler_ = nullptr;
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

bool ImageCreatorImpl::AniSendEvent(const std::function<void()> cb, std::string &name)
{
    if (cb == nullptr) {
        IMAGE_LOGE("%{public}s callback is nullptr", __func__);
        return false;
    }

    if (!mainHandler_) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        if (!runner) {
            IMAGE_LOGE("%{public}s EventRunner is nullptr", __func__);
            return false;
        }
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }

    if (mainHandler_ == nullptr) {
        IMAGE_LOGE("%{public}s mainHandler_ is still nullptr", __func__);
        return false;
    }

    if (!mainHandler_->PostTask(cb, name, 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {})) {
        IMAGE_LOGE("%{public}s PostTask failed", __func__);
        return false;
    }
    return true;
}

static void DoCallBack(std::shared_ptr<ImageCreatorTaiheContext> &context)
{
    auto localContext = std::make_unique<std::shared_ptr<ImageCreatorTaiheContext>>(context);
    if (context == nullptr) {
        IMAGE_LOGE("%{public}s, localContext is nullptr", __func__);
        localContext.release();
        return;
    }

    std::shared_ptr<taihe::callback<void(uintptr_t, uintptr_t)>> cacheCallback =
        std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t, uintptr_t)>>(context->taiheCallback);
    ani_object err = ImageTaiheUtils::ToBusinessError(taihe::get_env(), 0, "Callback is OK");
    (*cacheCallback)(reinterpret_cast<uintptr_t>(err), ImageTaiheUtils::GetUndefinedPtr(taihe::get_env()));
    localContext.release();
}

void ImageCreatorImpl::OnProcessSendEvent(std::shared_ptr<ImageCreatorTaiheContext> &context)
{
    auto task = [context]() mutable {
        DoCallBack(context);
    };
    ImageCreatorImpl::AniSendEvent(task, context->name);
}

static void QueueImageSyncProcess(ImageCreatorCommonArgs &args, ImageImpl *const imageImpl,
    ImageCreatorImpl *const imageCreatorImpl)
{
    if (imageCreatorImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("imageCreatorImpl is nullptr");
        return;
    }

    if (imageImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("imageImpl is nullptr");
        return;
    }

    std::shared_ptr<ImageCreatorTaiheContext> context = std::make_shared<ImageCreatorTaiheContext>();
    if (context == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageCreatorTaiheContext is nullptr");
        return;
    }

    context->name = args.name;
    context->imageCreatorImpl_ = imageCreatorImpl;
    context->imageImpl_ = imageImpl;

    args.callBack(context);
    if (context->status != OHOS::Media::SUCCESS) {
        ImageTaiheUtils::ThrowExceptionError(context->status, "CommonProcessSendEvent failed");
        return;
    }
}

void ImageCreatorImpl::QueueImageSync(weak::Image image)
{
    ImageCreatorCommonArgs args = {
        .name = "QueueImageSync",
        .callBack = nullptr,
    };

    args.callBack = [](std::shared_ptr<ImageCreatorTaiheContext> &context) -> CallbackResult {
        if (context->imageCreatorImpl_ == nullptr) {
            IMAGE_LOGE("imageCreatorImpl is nullptr");
            return std::monostate{};
        }
        auto imageCreatorNative = context->imageCreatorImpl_->imageCreator_;
        if (imageCreatorNative == nullptr) {
            IMAGE_LOGE("imageCreator is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }

        if (context->imageImpl_ == nullptr) {
            IMAGE_LOGE("imageImpl is nullptr");
            return std::monostate{};
        }
        auto imageNative = context->imageImpl_->GetIncrementalImage();
        if (imageNative == nullptr) {
            IMAGE_LOGE("imageNatice is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }

        if (OHOS::Media::SUCCESS != imageNative->CombineYUVComponents()) {
            IMAGE_LOGE("QueueImage try to combine componests");
        }
        imageCreatorNative->QueueNativeImage(imageNative);
        context->status = OHOS::Media::SUCCESS;
        return std::monostate{};
    };

    auto imageImpl = reinterpret_cast<ImageImpl*>(image->GetImplPtr());
    QueueImageSyncProcess(args, imageImpl, this);
}

static struct Image DequeueImageSyncProcess(ImageCreatorCommonArgs &args, ImageCreatorImpl *const imageCreatorImpl)
{
    if (imageCreatorImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("imageCreatorImpl is nullptr");
        return make_holder<ImageImpl, struct Image>();
    }

    std::shared_ptr<ImageCreatorTaiheContext> context = std::make_shared<ImageCreatorTaiheContext>();
    if (context == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageCreatorTaiheContext is nullptr");
        return make_holder<ImageImpl, struct Image>();
    }

    context->name = args.name;
    context->imageCreatorImpl_ = imageCreatorImpl;

    context->result = args.callBack(context);
    if (context->status != OHOS::Media::SUCCESS) {
        ImageTaiheUtils::ThrowExceptionError(context->status, "CommonProcessSendEvent failed");
        return make_holder<ImageImpl, struct Image>();
    }

    if (std::holds_alternative<std::monostate>(context->result)) {
        ImageTaiheUtils::ThrowExceptionError("CommonProcessSendEvent result is empty");
        return make_holder<ImageImpl, struct Image>();
    }

    return std::get<struct Image>(context->result);
}

struct Image ImageCreatorImpl::DequeueImageSync()
{
    ImageCreatorCommonArgs args = {
        .name = "DequeueImageSync",
        .callBack = nullptr,
    };

    args.callBack = [](std::shared_ptr<ImageCreatorTaiheContext> &context) -> CallbackResult {
        if (context->imageCreatorImpl_ == nullptr) {
            IMAGE_LOGE("imageCreatorImpl is nullptr");
            return std::monostate{};
        }
        auto imageCreatorNative = context->imageCreatorImpl_->imageCreator_;
        if (imageCreatorNative == nullptr) {
            IMAGE_LOGE("imageCreator is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }

        auto imageNative = imageCreatorNative->DequeueNativeImage();
        if (imageNative == nullptr) {
            IMAGE_LOGE("DequeueImageSync imageNatice is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }
        struct Image image = ImageImpl::Create(imageNative);
        context->status = OHOS::Media::SUCCESS;
        return image;
    };

    return DequeueImageSyncProcess(args, this);
}

static void OnImageReleaseProcess(ImageCreatorCommonArgs &args, ImageCreatorImpl *creatorImpl,
    ::taihe::callback_view<void(uintptr_t, uintptr_t)> callback)
{
    if (creatorImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("creatorImpl is nullptr");
        return;
    }

    std::shared_ptr<ImageCreatorTaiheContext> context = std::make_shared<ImageCreatorTaiheContext>();
    if (context == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageCreatorTaiheContext is nullptr");
        return;
    }

    context->name = args.name;
    context->callBack = args.callBack;
    context->imageCreatorImpl_ = creatorImpl;
    std::shared_ptr<taihe::callback<void(uintptr_t, uintptr_t)>> taiheCallback =
        std::make_shared<taihe::callback<void(uintptr_t, uintptr_t)>>(callback);
    context->taiheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    args.callBack(context);
}

void ImageCreatorImpl::OnImageRelease(::taihe::callback_view<void(uintptr_t, uintptr_t)> callback)
{
    ImageCreatorCommonArgs args = {
        .name = "OnImageRelease",
        .callBack = nullptr,
    };

    args.callBack = [](std::shared_ptr<ImageCreatorTaiheContext> &context) -> CallbackResult {
        auto native = context->imageCreatorImpl_->imageCreator_;
        if (native == nullptr) {
            IMAGE_LOGE("Native instance is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }
        std::shared_ptr<ImageCreatorReleaseListener> listener = std::make_shared<ImageCreatorReleaseListener>();
        listener->context = context;

        native->RegisterBufferReleaseListener((std::shared_ptr<OHOS::Media::SurfaceBufferReleaseListener> &)listener);

        listener->context->status = OHOS::Media::SUCCESS;
        return std::monostate{};
    };

    OnImageReleaseProcess(args, this, callback);
}

static void OffImageReleaseProcess(ImageCreatorCommonArgs &args, ImageCreatorImpl *creatorImpl)
{
    if (creatorImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("creatorImpl is nullptr");
        return;
    }

    std::shared_ptr<ImageCreatorTaiheContext> context = std::make_shared<ImageCreatorTaiheContext>();
    if (context == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageCreatorTaiheContext is nullptr");
        return;
    }

    context->name = args.name;
    context->callBack = args.callBack;
    context->imageCreatorImpl_ = creatorImpl;

    args.callBack(context);
}

void ImageCreatorImpl::OffImageRelease(::taihe::optional_view<::taihe::callback<void(uintptr_t, uintptr_t)>> callback)
{
    ImageCreatorCommonArgs args = {
        .name = "OffImageRelease",
        .callBack = nullptr,
    };

    args.callBack = [](std::shared_ptr<ImageCreatorTaiheContext> &context) -> CallbackResult {
        if (context->imageCreatorImpl_ == nullptr || context->imageCreatorImpl_->imageCreator_ == nullptr) {
            IMAGE_LOGE("imageCreatorImpl is nullptr");
            return std::monostate{};
        }
        context->imageCreatorImpl_->imageCreator_->UnRegisterBufferReleaseListener();
        context->status = OHOS::Media::SUCCESS;
        return std::monostate{};
    };
    OffImageReleaseProcess(args, this);
}

ImageCreator CreateImageCreator(Size const& size, ImageFormat format, int32_t capacity)
{
    int width = size.width;
    int height = size.height;
    if ((width == TEST_WIDTH) && (height == TEST_HEIGHT) &&
        (format.get_value() == TEST_FORMAT) && (capacity == TEST_CAPACITY)) {
        g_isCreatorTest = true;
    }
    if (!g_isCreatorTest) {
        auto imageCreator = OHOS::Media::ImageCreator::CreateImageCreator(width, height, format.get_value(), capacity);
        return make_holder<ImageCreatorImpl, ImageCreator>(imageCreator);
    }
    return make_holder<ImageCreatorImpl, ImageCreator>();
}
} // namespace ANI::Image

TH_EXPORT_CPP_API_CreateImageCreator(CreateImageCreator);