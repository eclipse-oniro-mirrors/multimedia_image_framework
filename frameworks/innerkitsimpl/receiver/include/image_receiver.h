/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_RECEIVER_INCLUDE_IMAGE_RECEIVER_H
#define FRAMEWORKS_INNERKITSIMPL_RECEIVER_INCLUDE_IMAGE_RECEIVER_H

#include <cstdint>
#include <mutex>
#include <securec.h>
#include <string>
#include <surface.h>

#include "image_format.h"
#include "image_type.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "image_receiver_context.h"
#include "image/image_receiver_native.h"
#include "native_image.h"
#include "surface_utils.h"

namespace OHOS {
namespace Media {
class IBufferProcessor;
class NativeImage;
class SurfaceBufferAvaliableListener {
public:
    SurfaceBufferAvaliableListener()= default;
    virtual ~SurfaceBufferAvaliableListener()= default;
    virtual void OnSurfaceBufferAvaliable() = 0;
};

class ImageReceiverArriveListener : public SurfaceBufferAvaliableListener {
public:
    explicit ImageReceiverArriveListener(OH_ImageReceiverNative* receiver) : receiver_(receiver) {}

    ~ImageReceiverArriveListener() override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_.clear();
    }

    bool HasCallback(OH_ImageReceiver_ImageArriveCallback callback)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::any_of(callbacks_.begin(), callbacks_.end(),
                           [callback](const CallbackData &cbData) { return cbData.callback == callback; });
    }

    bool RegisterCallback(OH_ImageReceiver_ImageArriveCallback callback, void* userdata)
    {
        if (callback == nullptr) {
            return false;
        }
        if (HasCallback(callback)) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_.emplace_back(callback, userdata);
        return true;
    }

    bool UnregisterCallback(OH_ImageReceiver_ImageArriveCallback callback)
    {
        if (callback == nullptr) {
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::remove_if(callbacks_.begin(), callbacks_.end(),
            [callback](const CallbackData &cbData) { return cbData.callback == callback; });
        if (it != callbacks_.end()) {
            callbacks_.erase(it, callbacks_.end());
            return true;
        }
        return false;
    }

    void OnSurfaceBufferAvaliable() __attribute__((no_sanitize("cfi"))) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& cbData : callbacks_) {
            if (cbData.callback != nullptr) {
                cbData.callback(receiver_, cbData.data);
            }
        }
    }

private:
    struct CallbackData {
        OH_ImageReceiver_ImageArriveCallback callback;
        void* data;

        CallbackData(OH_ImageReceiver_ImageArriveCallback cb, void* d) : callback(cb), data(d) {}
    };

    OH_ImageReceiverNative* receiver_ = nullptr;
    std::vector<CallbackData> callbacks_;
    mutable std::mutex mutex_;
};

struct ImageReceiverOptions {
    int32_t width = 0;
    int32_t height = 0;
    int32_t format = 0;
    int32_t capacity = 0;
};

class ImageReceiver {
public:
    std::shared_ptr<ImageReceiverContext> iraContext_ = nullptr;
    sptr<IConsumerSurface> receiverConsumerSurface_ = nullptr;
    sptr<Surface> receiverProducerSurface_ = nullptr;
    std::mutex imageReceiverMutex_;
    std::shared_ptr<SurfaceBufferAvaliableListener> surfaceBufferAvaliableListener_ = nullptr;
    std::shared_ptr<ImageReceiverArriveListener> surfaceBufferAvaliableArriveListener_ = nullptr;
    ImageReceiver() {}
    ~ImageReceiver();
    static inline int32_t pipeFd[2] = {};
    static inline std::string OPTION_FORMAT = "image/jpeg";
    static inline std::int32_t OPTION_QUALITY = 100;
    static inline std::int32_t OPTION_NUMBERHINT = 1;
    static std::shared_ptr<ImageReceiver> CreateImageReceiver(int32_t width,
                                                              int32_t height,
                                                              int32_t format,
                                                              int32_t capacity);
    static std::shared_ptr<ImageReceiver> CreateImageReceiver(ImageReceiverOptions &options);
    sptr<Surface> GetReceiverSurface();
    OHOS::sptr<OHOS::SurfaceBuffer> ReadNextImage();
    OHOS::sptr<OHOS::SurfaceBuffer> ReadLastImage();
    OHOS::sptr<OHOS::SurfaceBuffer> ReadNextImage(int64_t &timestamp);
    OHOS::sptr<OHOS::SurfaceBuffer> ReadLastImage(int64_t &timestamp);
    int32_t SaveBufferAsImage(int &fd,
                              OHOS::sptr<OHOS::SurfaceBuffer> buffer,
                              InitializationOptions initializationOpts);
    int32_t SaveBufferAsImage(int &fd, InitializationOptions initializationOpts);
    void ReleaseBuffer(OHOS::sptr<OHOS::SurfaceBuffer> &buffer);
    std::unique_ptr<PixelMap> getSurfacePixelMap(InitializationOptions initializationOpts);
    void RegisterBufferAvaliableListener(
        std::shared_ptr<SurfaceBufferAvaliableListener> surfaceBufferAvaliableListener)
    {
        surfaceBufferAvaliableListener_ = surfaceBufferAvaliableListener;
    }
    void UnRegisterBufferAvaliableListener()
    {
        surfaceBufferAvaliableListener_.reset();
    }
    static sptr<Surface> getSurfaceById(std::string id);
    void ReleaseReceiver();

    std::shared_ptr<IBufferProcessor> GetBufferProcessor();
    std::shared_ptr<NativeImage> NextNativeImage();
    std::shared_ptr<NativeImage> LastNativeImage();
private:
    std::shared_ptr<IBufferProcessor> bufferProcessor_;
};
class ImageReceiverSurfaceListener : public IBufferConsumerListener {
public:
    std::weak_ptr<ImageReceiver> ir_;
    void OnBufferAvailable() override;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_RECEIVER_INCLUDE_IMAGE_RECEIVER_H
