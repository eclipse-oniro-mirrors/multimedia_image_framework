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

#ifndef FRAMEWORKS_INNERKITSIMPL_RECEIVER_INCLUDE_IMAGE_RECEIVER_CONTEXT_H
#define FRAMEWORKS_INNERKITSIMPL_RECEIVER_INCLUDE_IMAGE_RECEIVER_CONTEXT_H

#include <surface.h>
#include <list>
#include "iconsumer_surface.h"

namespace OHOS {
namespace Media {
class ImageReceiverContext {
public:
    ImageReceiverContext() {
    }
    ~ImageReceiverContext()
    {
        currentBuffer_ = nullptr;
    };
    OHOS::sptr<OHOS::SurfaceBuffer> currentBuffer_;
    static std::shared_ptr<ImageReceiverContext> CreateImageReceiverContext();
    void SetReceiverBufferConsumer(sptr<IConsumerSurface> &consumer)
    {
        receiverConsumerSurface_ = consumer;
    }
    sptr<IConsumerSurface> GetReceiverBufferConsumer()
    {
        return receiverConsumerSurface_;
    }
    void SetReceiverBufferProducer(sptr<Surface> &producer)
    {
        receiverProducerSurface_ = producer;
    }
    sptr<Surface> GetReceiverBufferProducer()
    {
        return receiverProducerSurface_;
    }
    void SetWidth(int32_t width)
    {
        width_ = width;
    }
    int32_t GetWidth() const
    {
        return width_;
    }
    void SetHeight(int32_t height)
    {
        height_ = height;
    }
    int32_t GetHeight() const
    {
        return height_;
    }
    void SetFormat(int32_t format)
    {
        format_ = format;
    }
    int32_t GetFormat() const
    {
        return format_;
    }
    void SetCapicity(int32_t capicity)
    {
        capicity_ = capicity;
    }
    int32_t GetCapicity() const
    {
        return capicity_;
    }
    void SetReceiverKey(std::string receiverKey)
    {
        receiverKey_ = receiverKey;
    }
    std::string GetReceiverKey() const
    {
        return receiverKey_;
    }
    OHOS::sptr<OHOS::SurfaceBuffer> GetCurrentBuffer() const
    {
        return currentBuffer_;
    }
    void SetCurrentBuffer(OHOS::sptr<OHOS::SurfaceBuffer> currentBuffer)
    {
        currentBuffer_ = currentBuffer;
    }

private:
    OHOS::sptr<IConsumerSurface> receiverConsumerSurface_;
    OHOS::sptr<Surface> receiverProducerSurface_;
    int32_t width_ = 0;
    int32_t height_ = 0;
    int32_t format_ = 0;
    int32_t capicity_ = 0;
    std::string receiverKey_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_RECEIVER_INCLUDE_IMAGE_RECEIVER_CONTEXT_H
