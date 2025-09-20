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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_RECEIVER_TAIHE_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_RECEIVER_TAIHE_H

#include "event_handler.h"
#include "image_receiver.h"
#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "taihe/runtime.hpp"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;

struct ImageReceiverTaiheContext;
using CallbackResult = std::variant<std::monostate, string, struct Image>;
using CompleteCallback = CallbackResult (*)(std::shared_ptr<ImageReceiverTaiheContext> &);

class ImageReceiverImpl {
public:
    ImageReceiverImpl();
    explicit ImageReceiverImpl(std::shared_ptr<OHOS::Media::ImageReceiver> imageReceiver);
    ~ImageReceiverImpl();
    int64_t GetImplPtr();
    std::shared_ptr<OHOS::Media::ImageReceiver> GetNativeImageReceiver();

    static bool AniSendEvent(const std::function<void()> cb, std::string &name);
    static void OnProcessSendEvent(std::shared_ptr<ImageReceiverTaiheContext> &context);

    Size GetSize();
    int32_t GetCapacity();
    ImageFormat GetFormat();

    string GetReceivingSurfaceIdSync();
    struct Image ReadLatestImageSync();
    struct Image ReadNextImageSync();
    void OnImageArrival(callback_view<void(uintptr_t, uintptr_t)> callback);
    void OffImageArrival(optional_view<callback<void(uintptr_t, uintptr_t)>> callback);
    void ReleaseSync();

#ifdef IMAGE_DEBUG_FLAG
    bool isCallBackTest = false;
#endif

private:
    void UnRegisterReceiverListener();
    void NativeRelease();

    std::shared_ptr<OHOS::Media::ImageReceiver> imageReceiver_;
    bool isRelease = false;
    static std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_;
};

struct ImageReceiverTaiheContext {
    CompleteCallback callBack = nullptr;
    CallbackResult result;
    std::shared_ptr<uintptr_t> taiheCallback = nullptr;
    std::string name;
    ImageReceiverImpl *receiverImpl_ = nullptr;
    uint32_t status = OHOS::Media::ERROR;
};

struct ImageReceiverCommonArgs {
    const std::string name;
    CompleteCallback callBack;
};

class ImageReceiverAvaliableListener : public OHOS::Media::SurfaceBufferAvaliableListener {
public:
    ~ImageReceiverAvaliableListener() override
    {
        context = nullptr;
    }

    void OnSurfaceBufferAvaliable() override
    {
        ImageReceiverImpl::OnProcessSendEvent(context);
    }

    std::shared_ptr<ImageReceiverTaiheContext> context = nullptr;
};
} // namespace ANI::Image

#endif // FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_RECEIVER_TAIHE_H