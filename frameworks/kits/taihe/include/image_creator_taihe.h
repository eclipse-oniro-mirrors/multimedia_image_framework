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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_CREATOR_TAIHE_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_CREATOR_TAIHE_H

#include "event_handler.h"
#include "image_creator.h"
#include "image_taihe.h"
#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "taihe/runtime.hpp"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;

struct ImageCreatorTaiheContext;
using CallbackResult = std::variant<std::monostate, struct Image>;
using CompleteCallback = CallbackResult (*)(std::shared_ptr<ImageCreatorTaiheContext> &);

class ImageCreatorImpl {
public:
    ImageCreatorImpl();
    explicit ImageCreatorImpl(std::shared_ptr<OHOS::Media::ImageCreator> imageCreator);
    ~ImageCreatorImpl();

    static bool AniSendEvent(const std::function<void()> cb, std::string &name);
    static void OnProcessSendEvent(std::shared_ptr<ImageCreatorTaiheContext> &context);

    int32_t GetCapacity();
    ImageFormat GetFormat();

    void QueueImageSync(weak::Image image);

    struct Image DequeueImageSync();

    void OnImageRelease(::taihe::callback_view<void(uintptr_t, uintptr_t)> callback);

    void OffImageRelease(::taihe::optional_view<::taihe::callback<void(uintptr_t, uintptr_t)>> callback);

    void ReleaseSync();

private:
    std::shared_ptr<OHOS::Media::ImageCreator> imageCreator_;
    bool isRelease = false;
    static std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_;
};

struct ImageCreatorTaiheContext {
    CompleteCallback callBack = nullptr;
    CallbackResult result;
    std::shared_ptr<uintptr_t> taiheCallback = nullptr;
    std::string name;
    ImageCreatorImpl *imageCreatorImpl_ = nullptr;
    ImageImpl *imageImpl_ = nullptr;
    uint32_t status = OHOS::Media::ERROR;
};

struct ImageCreatorCommonArgs {
    const std::string name;
    CompleteCallback callBack;
};

class ImageCreatorReleaseListener : public OHOS::Media::SurfaceBufferReleaseListener {
public:
    ~ImageCreatorReleaseListener() override
    {
        context = nullptr;
    }
    void OnSurfaceBufferRelease() override
    {
        ImageCreatorImpl::OnProcessSendEvent(context);
    }
    std::shared_ptr<ImageCreatorTaiheContext> context = nullptr;
};
} // namespace ANI::Image

#endif // FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_CREATOR_TAIHE_H