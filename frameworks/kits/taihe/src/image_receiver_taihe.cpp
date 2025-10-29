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
#include "image_receiver_taihe.h"
#include "image_taihe.h"
#include "image_taihe_utils.h"

using namespace ANI::Image;

namespace ANI::Image {
static constexpr int32_t NUM_0 = 0;
static const char* EMPTY_STRING = "";

struct ImageEnum {
    std::string name;
    int32_t numVal;
    std::string strVal;
};

static std::vector<struct ImageEnum> sImageFormatMap = {
    {"CAMERA_APP_INNER", 4, ""},
    {"JPEG", 2000, ""},
};

std::shared_ptr<OHOS::AppExecFwk::EventHandler> ImageReceiverImpl::mainHandler_ = nullptr;

ImageReceiverImpl::ImageReceiverImpl() : imageReceiver_(nullptr) {}

ImageReceiverImpl::ImageReceiverImpl(std::shared_ptr<OHOS::Media::ImageReceiver> imageReceiver)
{
    imageReceiver_ = imageReceiver;
}

ImageReceiverImpl::~ImageReceiverImpl()
{
    if (!isRelease) {
        NativeRelease();
        isRelease = true;
    }
}

int64_t ImageReceiverImpl::GetImplPtr()
{
    return static_cast<int64_t>(reinterpret_cast<uintptr_t>(this));
}

std::shared_ptr<OHOS::Media::ImageReceiver> ImageReceiverImpl::GetNativeImageReceiver()
{
    return imageReceiver_;
}

void ImageReceiverImpl::UnRegisterReceiverListener()
{
    if (imageReceiver_ != nullptr) {
        imageReceiver_->UnRegisterBufferAvaliableListener();
    }
}

void ImageReceiverImpl::NativeRelease()
{
    imageReceiver_ = nullptr;
}

bool ImageReceiverImpl::AniSendEvent(const std::function<void()> cb, std::string &name)
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

Size ImageReceiverImpl::GetSize()
{
    if (imageReceiver_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverImpl is nullptr");
        return Size{0, 0};
    }
    if (imageReceiver_->iraContext_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverContext is nullptr");
        return Size{0, 0};
    }
    return Size{imageReceiver_->iraContext_->GetWidth(), imageReceiver_->iraContext_->GetHeight()};
}

int32_t ImageReceiverImpl::GetCapacity()
{
    if (imageReceiver_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverImpl is nullptr");
        return 0;
    }
    if (imageReceiver_->iraContext_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverContext is nullptr");
        return 0;
    }
    return imageReceiver_->iraContext_->GetCapicity();
}

ImageFormat ImageReceiverImpl::GetFormat()
{
    if (imageReceiver_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverImpl is nullptr");
        return ImageFormat(static_cast<ImageFormat::key_t>(OHOS::Media::ImageFormat::UNKNOWN));
    }
    if (imageReceiver_->iraContext_ == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverContext is nullptr");
        return ImageFormat(static_cast<ImageFormat::key_t>(OHOS::Media::ImageFormat::UNKNOWN));
    }
    ImageFormat::key_t key;
    if (!ImageTaiheUtils::GetEnumKeyByValue<ImageFormat>(imageReceiver_->iraContext_->GetFormat(), key)) {
        ImageTaiheUtils::ThrowExceptionError("GetEnumKeyByValue failed");
        return ImageFormat(static_cast<ImageFormat::key_t>(OHOS::Media::ImageFormat::UNKNOWN));
    }
    return ImageFormat(key);
}

static bool CheckFormat(int32_t format)
{
    for (auto imgEnum : sImageFormatMap) {
        if (imgEnum.numVal == format) {
            return true;
        }
    }
    return false;
}

static void CommonProcessSendEvent(std::shared_ptr<ImageReceiverTaiheContext> &context)
{
    context->result = context->callBack(context);
}

static string GetReceivingSurfaceIdSyncProcess(ImageReceiverCommonArgs &args, ImageReceiverImpl *const receiverImpl)
{
    if (receiverImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("receiverImpl is nullptr");
        return EMPTY_STRING;
    }

    std::shared_ptr<ImageReceiverTaiheContext> context = std::make_shared<ImageReceiverTaiheContext>();
    if (context == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverTaiheContext is nullptr");
        return EMPTY_STRING;
    }

    context->name = args.name;
    context->callBack = args.callBack;
    context->receiverImpl_ = receiverImpl;

    CommonProcessSendEvent(context);
    if (context->status != OHOS::Media::SUCCESS) {
        ImageTaiheUtils::ThrowExceptionError("CommonProcessSendEvent failed");
        return EMPTY_STRING;
    }

    if (std::holds_alternative<std::monostate>(context->result)) {
        ImageTaiheUtils::ThrowExceptionError("CommonProcessSendEvent result is empty");
        return EMPTY_STRING;
    }

    return std::get<string>(context->result);
}

string ImageReceiverImpl::GetReceivingSurfaceIdSync()
{
    ImageReceiverCommonArgs args = {
        .name = "GetReceivingSurfaceIdSync",
        .callBack = nullptr,
    };

    args.callBack = [](std::shared_ptr<ImageReceiverTaiheContext> &context) -> CallbackResult {
        auto native = context->receiverImpl_->imageReceiver_;
        if (native == nullptr || native->iraContext_ == nullptr) {
            IMAGE_LOGE("Native instance or imageReceiverContext is nullptr");
            context->status = OHOS::Media::COMMON_ERR_INVALID_PARAMETER;
            return std::monostate{};
        }
        context->status = OHOS::Media::SUCCESS;
        return ::taihe::string(native->iraContext_->GetReceiverKey());
    };

    return GetReceivingSurfaceIdSyncProcess(args, this);
}

#ifdef IMAGE_SAVE_BUFFER_TO_PIC
static void DoCallBackTest(OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer1)
{
    if (surfaceBuffer1 == nullptr) {
        IMAGE_LOGE("surfaceBuffer1 is null");
        return;
    }

    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    shared_ptr<ImageReceiver> imageReceiver1 = imageReceiverManager.getImageReceiverByKeyId("1");
    if (imageReceiver1 == nullptr || imageReceiver1->iraContext_ == nullptr) {
        return;
    }
    IMAGE_LOGE("DoCallBackTest format %{public}d", imageReceiver1->iraContext_->GetFormat());

    InitializationOptions opts;
    opts.size.width = surfaceBuffer1->GetWidth();
    opts.size.height = surfaceBuffer1->GetHeight();
    opts.pixelFormat = OHOS::Media::PixelFormat::BGRA_8888;
    opts.alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.scaleMode = OHOS::Media::ScaleMode::CENTER_CROP;
    opts.editable = true;
    IMAGE_LOGE("DoCallBackTest Width %{public}d", opts.size.width);
    IMAGE_LOGE("DoCallBackTest Height %{public}d", opts.size.height);
    int fd = open("/data/receiver/test.jpg", O_RDWR | O_CREAT);
    imageReceiver1->SaveBufferAsImage(fd, surfaceBuffer1, opts);
}
#endif

static struct Image ReadImageSyncProcess(ImageReceiverCommonArgs &args, ImageReceiverImpl *const receiverImpl)
{
    if (receiverImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("receiverImpl is nullptr");
        return make_holder<ImageImpl, struct Image>();
    }

    std::shared_ptr<ImageReceiverTaiheContext> context = std::make_shared<ImageReceiverTaiheContext>();
    if (context == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverTaiheContext is nullptr");
        return make_holder<ImageImpl, struct Image>();
    }

    context->name = args.name;
    context->callBack = args.callBack;
    context->receiverImpl_ = receiverImpl;

    CommonProcessSendEvent(context);
    if (context->status != OHOS::Media::SUCCESS) {
        ImageTaiheUtils::ThrowExceptionError("CommonProcessSendEvent failed");
        return make_holder<ImageImpl, struct Image>();
    }

    if (std::holds_alternative<std::monostate>(context->result)) {
        ImageTaiheUtils::ThrowExceptionError("CommonProcessSendEvent result is empty");
        return make_holder<ImageImpl, struct Image>();
    }

    return std::get<struct Image>(context->result);
}

struct Image ImageReceiverImpl::ReadLatestImageSync()
{
    ImageReceiverCommonArgs args = {
        .name = "ReadLatestImageSync",
        .callBack = nullptr,
    };

    args.callBack = [](std::shared_ptr<ImageReceiverTaiheContext> &context) -> CallbackResult {
        auto native = context->receiverImpl_->imageReceiver_;
        if (native == nullptr) {
            IMAGE_LOGE("Native instance is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }

        std::shared_ptr<OHOS::Media::NativeImage> nativeImage = native->LastNativeImage();
        if (nativeImage == nullptr) {
            IMAGE_LOGE("LastNativeImage is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }
#ifdef IMAGE_DEBUG_FLAG
        if (context->receiverImpl_->isCallBackTest) {
            context->receiverImpl_->isCallBackTest = false;
#ifdef IMAGE_SAVE_BUFFER_TO_PIC
            DoCallBackTest(nativeImage->GetBuffer());
#endif
        }
#endif
        struct Image image = ImageImpl::Create(nativeImage);
        context->status = OHOS::Media::SUCCESS;
        return image;
    };

    return ReadImageSyncProcess(args, this);
}

struct Image ImageReceiverImpl::ReadNextImageSync()
{
    ImageReceiverCommonArgs args = {
        .name = "ReadNextImageSync",
        .callBack = nullptr,
    };

    args.callBack = [](std::shared_ptr<ImageReceiverTaiheContext> &context) -> CallbackResult {
        auto native = context->receiverImpl_->imageReceiver_;
        if (native == nullptr) {
            IMAGE_LOGE("Native instance is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }
        std::shared_ptr<OHOS::Media::NativeImage> nativeImage = native->NextNativeImage();
        if (nativeImage == nullptr) {
            IMAGE_LOGE("NextNativeImage is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }
#ifdef IMAGE_DEBUG_FLAG
        if (context->receiverImpl_->isCallBackTest) {
            context->receiverImpl_->isCallBackTest = false;
#ifdef IMAGE_SAVE_BUFFER_TO_PIC
            DoCallBackTest(nativeImage->GetBuffer());
#endif
        }
#endif
        struct Image image = ImageImpl::Create(nativeImage);
        if (::taihe::has_error()) {
            IMAGE_LOGE("%{public}s ImageImpl::Create failed!", context->name.c_str());
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }
        context->status = OHOS::Media::SUCCESS;
        return image;
    };

    return ReadImageSyncProcess(args, this);
}

static void DoCallBack(std::shared_ptr<ImageReceiverTaiheContext> &context)
{
    auto localContext = std::make_unique<std::shared_ptr<ImageReceiverTaiheContext>>(context);
    if (context == nullptr) {
        IMAGE_LOGE("%{public}s, localContext is nullptr", __func__);
        localContext.release();
        return;
    }

    std::shared_ptr<taihe::callback<void(uintptr_t, uintptr_t)>> cacheCallback =
        std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t, uintptr_t)>>(context->taiheCallback);
    ani_object err = ImageTaiheUtils::ToBusinessError(taihe::get_env(), NUM_0, "Callback is OK");
    (*cacheCallback)(reinterpret_cast<uintptr_t>(err), ImageTaiheUtils::GetUndefinedPtr(taihe::get_env()));
    localContext.release();
}

void ImageReceiverImpl::OnProcessSendEvent(std::shared_ptr<ImageReceiverTaiheContext> &context)
{
    auto task = [context]() mutable {
        DoCallBack(context);
    };
    ImageReceiverImpl::AniSendEvent(task, context->name);
}

static void OnImageArrivalProcess(ImageReceiverCommonArgs &args, ImageReceiverImpl *const receiverImpl,
    callback_view<void(uintptr_t, uintptr_t)> callback)
{
    if (receiverImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("receiverImpl is nullptr");
        return;
    }

    std::shared_ptr<ImageReceiverTaiheContext> context = std::make_shared<ImageReceiverTaiheContext>();
    if (context == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverTaiheContext is nullptr");
        return;
    }

    context->name = args.name;
    context->callBack = args.callBack;
    context->receiverImpl_ = receiverImpl;
    std::shared_ptr<taihe::callback<void(uintptr_t, uintptr_t)>> taiheCallback =
        std::make_shared<taihe::callback<void(uintptr_t, uintptr_t)>>(callback);
    context->taiheCallback = std::reinterpret_pointer_cast<uintptr_t>(taiheCallback);

    args.callBack(context);
}

void ImageReceiverImpl::OnImageArrival(callback_view<void(uintptr_t, uintptr_t)> callback)
{
    ImageReceiverCommonArgs args = {
        .name = "OnImageArrival",
        .callBack = nullptr,
    };

    args.callBack = [](std::shared_ptr<ImageReceiverTaiheContext> &context) -> CallbackResult {
        auto native = context->receiverImpl_->imageReceiver_;
        if (native == nullptr) {
            IMAGE_LOGE("Native instance is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }
        std::shared_ptr<ImageReceiverAvaliableListener> listener = std::make_shared<ImageReceiverAvaliableListener>();
        listener->context = context;

        native->RegisterBufferAvaliableListener(
            (std::shared_ptr<OHOS::Media::SurfaceBufferAvaliableListener> &)listener);

        listener->context->status = OHOS::Media::SUCCESS;
        return std::monostate{};
    };

    OnImageArrivalProcess(args, this, callback);
}

static void OffImageArrivalProcess(ImageReceiverCommonArgs &args, ImageReceiverImpl *const receiverImpl)
{
    if (receiverImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("receiverImpl is nullptr");
        return;
    }

    std::shared_ptr<ImageReceiverTaiheContext> context = std::make_shared<ImageReceiverTaiheContext>();
    if (context == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverTaiheContext is nullptr");
        return;
    }

    context->name = args.name;
    context->callBack = args.callBack;
    context->receiverImpl_ = receiverImpl;

    args.callBack(context);
}

void ImageReceiverImpl::OffImageArrival(optional_view<callback<void(uintptr_t, uintptr_t)>> callback)
{
    ImageReceiverCommonArgs args = {
        .name = "OffImageArrival",
        .callBack = nullptr,
    };

    args.callBack = [](std::shared_ptr<ImageReceiverTaiheContext> &context) -> CallbackResult {
        if (context == nullptr) {
            IMAGE_LOGE("context is nullptr");
            return std::monostate{};
        }
        if (context->receiverImpl_ == nullptr) {
            IMAGE_LOGE("receiverImpl is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }
        context->receiverImpl_->imageReceiver_->UnRegisterBufferAvaliableListener();
        context->status = OHOS::Media::SUCCESS;
        return std::monostate{};
    };

    OffImageArrivalProcess(args, this);
}

static void ReleaseSyncProcess(ImageReceiverCommonArgs &args, ImageReceiverImpl *const receiverImpl)
{
    if (receiverImpl == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("receiverImpl is nullptr");
        return;
    }

    std::shared_ptr<ImageReceiverTaiheContext> context = std::make_shared<ImageReceiverTaiheContext>();
    if (context == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("ImageReceiverTaiheContext is nullptr");
        return;
    }

    context->name = args.name;
    context->callBack = args.callBack;
    context->receiverImpl_ = receiverImpl;

    CommonProcessSendEvent(context);
    if (context->status != OHOS::Media::SUCCESS) {
        ImageTaiheUtils::ThrowExceptionError("CommonProcessSendEvent failed");
        return;
    }
}

void ImageReceiverImpl::ReleaseSync()
{
    ImageReceiverCommonArgs args = {
        .name = "ReleaseSync",
        .callBack = nullptr,
    };

    args.callBack = [](std::shared_ptr<ImageReceiverTaiheContext> &context) -> CallbackResult {
        if (context == nullptr) {
            IMAGE_LOGE("context is nullptr");
            return std::monostate{};
        }
        if (context->receiverImpl_ == nullptr) {
            IMAGE_LOGE("receiverImpl is nullptr");
            context->status = OHOS::Media::ERR_IMAGE_INIT_ABNORMAL;
            return std::monostate{};
        }

        context->receiverImpl_->UnRegisterReceiverListener();
        context->receiverImpl_->NativeRelease();
        context->status = OHOS::Media::SUCCESS;
        return std::monostate{};
    };

    ReleaseSyncProcess(args, this);
}

ImageReceiver CreateImageReceiver(Size const& size, ImageFormat format, int32_t capacity)
{
    if (!CheckFormat(format.get_value())) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "Invalid format");
        return make_holder<ImageReceiverImpl, ImageReceiver>();
    }

    std::shared_ptr<OHOS::Media::ImageReceiver> imageReceiver = OHOS::Media::ImageReceiver::CreateImageReceiver(
        size.width, size.height, format.get_value(), capacity);
    if (imageReceiver == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("Create native image receiver failed");
        return make_holder<ImageReceiverImpl, ImageReceiver>();
    }
    return make_holder<ImageReceiverImpl, ImageReceiver>(imageReceiver);
}
} // namespace ANI::Image

TH_EXPORT_CPP_API_CreateImageReceiver(CreateImageReceiver);
