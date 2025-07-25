/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <memory>
#include <string>
#include <charconv>

#include "common_utils.h"
#include "image_log.h"
#include "image_receiver_native.h"
#include "image_kits.h"
#include "image_receiver.h"

#ifdef __cplusplus
extern "C" {
#endif

struct OH_ImageReceiverNative {
    std::shared_ptr<OHOS::Media::ImageReceiver> ptrImgRcv;
};

struct OH_ImageReceiverOptions {
    /* Default width of the image received by the consumer, in pixels. */
    int32_t width = 0;
    /* Default height of the image received by the consumer, in pixels. */
    int32_t height = 0;
    /* Image format {@link OHOS_IMAGE_FORMAT_JPEG} created by using the receiver. */
    int32_t format = 0;
    /* Maximum number of images that can be cached. */
    int32_t capacity = 0;
};

namespace OHOS {
namespace Media {
    class ImageReceiverListener : public SurfaceBufferAvaliableListener {
    public:
        explicit ImageReceiverListener(OH_ImageReceiverNative* receiver) : receiver_(receiver), callback_(nullptr) {}

        ~ImageReceiverListener() override
        {
            callback_ = nullptr;
        }

        void OnSurfaceBufferAvaliable() __attribute__((no_sanitize("cfi"))) override
        {
            if (nullptr != callback_) {
                callback_(receiver_);
            }
        }

        OH_ImageReceiverNative* receiver_;
        OH_ImageReceiver_OnCallback callback_;
    };
} // namespace Media
} // namespace OHOS

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverOptions_Create(OH_ImageReceiverOptions** options)
{
    if (nullptr == options) {
        IMAGE_LOGE("Invalid parameter: options=null.");
        return IMAGE_BAD_PARAMETER;
    }
    auto rst = new OH_ImageReceiverOptions;
    if (nullptr == rst) {
        IMAGE_LOGE("OH_ImageReceiverOptions create failed.");
        return IMAGE_ALLOC_FAILED;
    }
    *options = rst;
    IMAGE_LOGI("OH_ImageReceiverOptions Create.");
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverOptions_GetSize(OH_ImageReceiverOptions* options, Image_Size* size)
{
    if (nullptr == options) {
        IMAGE_LOGE("Invalid parameter: options=null.");
        return IMAGE_BAD_PARAMETER;
    }
    size->width = static_cast<uint32_t>(options->width);
    size->height = static_cast<uint32_t>(options->height);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverOptions_SetSize(OH_ImageReceiverOptions* options, Image_Size size)
{
    if (nullptr == options) {
        IMAGE_LOGE("Invalid parameter: options=null.");
        return IMAGE_BAD_PARAMETER;
    }
    options->width = static_cast<int32_t>(size.width);
    options->height = static_cast<int32_t>(size.height);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverOptions_GetCapacity(OH_ImageReceiverOptions* options, int32_t* capacity)
{
    if (nullptr == options) {
        IMAGE_LOGE("Invalid parameter: options=null.");
        return IMAGE_BAD_PARAMETER;
    }
    *capacity = options->capacity;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverOptions_SetCapacity(OH_ImageReceiverOptions* options, int32_t capacity)
{
    if (nullptr == options) {
        IMAGE_LOGE("Invalid parameter: options=null.");
        return IMAGE_BAD_PARAMETER;
    }
    options->capacity = capacity;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverOptions_Release(OH_ImageReceiverOptions* options)
{
    if (nullptr != options) {
        IMAGE_LOGI("OH_ImageReceiverOptions Release.");
        delete options;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverNative_Create(OH_ImageReceiverOptions* options, OH_ImageReceiverNative** receiver)
{
    if (nullptr == options || nullptr == receiver) {
        IMAGE_LOGE("OH_ImageReceiverNative_Create: Invalid parameter");
        return IMAGE_BAD_PARAMETER;
    }

    auto rst = new OH_ImageReceiverNative;
    if (nullptr == rst) {
        IMAGE_LOGE("OH_ImageReceiverNative create failed.");
        return IMAGE_ALLOC_FAILED;
    }

    rst->ptrImgRcv = OHOS::Media::ImageReceiver::CreateImageReceiver(
        options->width, options->height, options->format, options->capacity);
    if (!(rst->ptrImgRcv)) {
        delete rst;
        IMAGE_LOGE("OH_ImageReceiverNative data create failed.");
        return IMAGE_UNKNOWN_ERROR;
    }

    *receiver = rst;
    IMAGE_LOGI("OH_ImageReceiverNative Create.");
    return IMAGE_SUCCESS;
}

static bool ConvertToUint64(const std::string& str, uint64_t& value)
{
    auto [ptr, errCode] = std::from_chars(str.data(), str.data() + str.size(), value);
    bool ret = errCode == std::errc{} && (ptr == str.data() + str.size());
    return ret;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverNative_GetReceivingSurfaceId(OH_ImageReceiverNative* receiver, uint64_t* surfaceId)
{
    if (nullptr == receiver) {
        IMAGE_LOGE("Invalid parameter: receiver=null.");
        return IMAGE_BAD_PARAMETER;
    }
    if (nullptr == receiver->ptrImgRcv || nullptr == receiver->ptrImgRcv->iraContext_) {
        IMAGE_LOGE("Bad parameter: receiver data empty.");
        return IMAGE_BAD_PARAMETER;
    }

    std::string strKey = receiver->ptrImgRcv->iraContext_->GetReceiverKey();
    if (strKey.empty()) {
        IMAGE_LOGE("Bad data: key string empty.");
        return IMAGE_UNKNOWN_ERROR;
    }
    IMAGE_LOGD("OH_ImageReceiverNative_GetReceivingSurfaceId Receiver key = %{public}s", strKey.c_str());

    if (!ConvertToUint64(strKey, *surfaceId)) {
        IMAGE_LOGI("strKey = %{public}s convert string to uint64_t failed", strKey.c_str());
        return IMAGE_UNKNOWN_ERROR;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverNative_ReadLatestImage(OH_ImageReceiverNative* receiver, OH_ImageNative** image)
{
    if (nullptr == receiver) {
        IMAGE_LOGE("Invalid parameter: receiver=null.");
        return IMAGE_BAD_PARAMETER;
    }
    if (nullptr == receiver->ptrImgRcv) {
        IMAGE_LOGE("Bad parameter: receiver data empty.");
        return IMAGE_BAD_PARAMETER;
    }

    auto bufferProcessor = receiver->ptrImgRcv->GetBufferProcessor();
    if (nullptr == bufferProcessor) {
        IMAGE_LOGE("Bad data: buffer processor empty.");
        return IMAGE_UNKNOWN_ERROR;
    }

    int64_t timestamp = 0;
    auto surfaceBuffer = receiver->ptrImgRcv->ReadLastImage(timestamp);
    if (nullptr == surfaceBuffer) {
        IMAGE_LOGE("Bad data: surfacebuffer empty.");
        return IMAGE_UNKNOWN_ERROR;
    }

    auto rst = new OH_ImageNative;
    if (nullptr == rst) {
        IMAGE_LOGE("OH_ImageNative create failed.");
        return IMAGE_ALLOC_FAILED;
    }

    rst->imgNative = new OHOS::Media::NativeImage(surfaceBuffer, bufferProcessor, timestamp);
    if (!(rst->imgNative)) {
        delete rst;
        IMAGE_LOGE("OH_ImageNative data create failed.");
        return IMAGE_UNKNOWN_ERROR;
    }

    *image = rst;
    IMAGE_LOGD("OH_ImageNative ReadLatestImage.");
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverNative_ReadNextImage(OH_ImageReceiverNative* receiver, OH_ImageNative** image)
{
    if (nullptr == receiver) {
        IMAGE_LOGE("Invalid parameter: receiver=null.");
        return IMAGE_BAD_PARAMETER;
    }
    if (nullptr == receiver->ptrImgRcv) {
        IMAGE_LOGE("Bad parameter: receiver data empty.");
        return IMAGE_BAD_PARAMETER;
    }

    auto bufferProcessor = receiver->ptrImgRcv->GetBufferProcessor();
    if (nullptr == bufferProcessor) {
        IMAGE_LOGE("Bad data: buffer processor empty.");
        return IMAGE_UNKNOWN_ERROR;
    }

    int64_t timestamp = 0;
    auto surfaceBuffer = receiver->ptrImgRcv->ReadNextImage(timestamp);
    if (nullptr == surfaceBuffer) {
        IMAGE_LOGE("Bad data: surfacebuffer empty.");
        return IMAGE_UNKNOWN_ERROR;
    }

    auto rst = new OH_ImageNative;
    if (nullptr == rst) {
        IMAGE_LOGE("OH_ImageNative create failed.");
        return IMAGE_ALLOC_FAILED;
    }

    rst->imgNative = new OHOS::Media::NativeImage(surfaceBuffer, bufferProcessor, timestamp);
    if (!(rst->imgNative)) {
        delete rst;
        IMAGE_LOGE("OH_ImageNative data create failed.");
        return IMAGE_UNKNOWN_ERROR;
    }

    *image = rst;
    IMAGE_LOGI("OH_ImageNative ReadNextImage.");
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverNative_On(OH_ImageReceiverNative* receiver, OH_ImageReceiver_OnCallback callback)
{
    if (nullptr == receiver || nullptr == callback) {
        IMAGE_LOGE("OH_ImageReceiverNative_On: Invalid parameter");
        return IMAGE_BAD_PARAMETER;
    }
    if (nullptr == receiver->ptrImgRcv) {
        IMAGE_LOGE("Bad parameter: receiver data empty.");
        return IMAGE_BAD_PARAMETER;
    }

    auto listener = std::make_shared<OHOS::Media::ImageReceiverListener>(receiver);
    listener->callback_ = callback;
    receiver->ptrImgRcv->RegisterBufferAvaliableListener(listener);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverNative_Off(OH_ImageReceiverNative* receiver)
{
    if (nullptr == receiver) {
        IMAGE_LOGE("Invalid parameter: receiver=null.");
        return IMAGE_BAD_PARAMETER;
    }
    if (nullptr == receiver->ptrImgRcv) {
        IMAGE_LOGE("Bad parameter: receiver data empty.");
        return IMAGE_BAD_PARAMETER;
    }

    receiver->ptrImgRcv->UnRegisterBufferAvaliableListener();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverNative_GetSize(OH_ImageReceiverNative* receiver, Image_Size* size)
{
    if (nullptr == receiver || nullptr == size) {
        IMAGE_LOGE("OH_ImageReceiverNative_GetSize: Invalid parameter");
        return IMAGE_BAD_PARAMETER;
    }
    if (nullptr == receiver->ptrImgRcv || nullptr == receiver->ptrImgRcv->iraContext_) {
        IMAGE_LOGE("Bad parameter: receiver data empty.");
        return IMAGE_BAD_PARAMETER;
    }

    size->width = static_cast<uint32_t>(receiver->ptrImgRcv->iraContext_->GetWidth());
    size->height = static_cast<uint32_t>(receiver->ptrImgRcv->iraContext_->GetHeight());
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverNative_GetCapacity(OH_ImageReceiverNative* receiver, int32_t* capacity)
{
    if (nullptr == receiver || nullptr == capacity) {
        IMAGE_LOGE("OH_ImageReceiverNative_GetCapacity: Invalid parameter");
        return IMAGE_BAD_PARAMETER;
    }
    if (nullptr == receiver->ptrImgRcv || nullptr == receiver->ptrImgRcv->iraContext_) {
        IMAGE_LOGE("Bad parameter: receiver data empty.");
        return IMAGE_BAD_PARAMETER;
    }

    *capacity = receiver->ptrImgRcv->iraContext_->GetCapicity();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverNative_Release(OH_ImageReceiverNative* receiver)
{
    if (nullptr == receiver) {
        IMAGE_LOGE("Invalid parameter: receiver=null.");
        return IMAGE_BAD_PARAMETER;
    }
    receiver->ptrImgRcv.reset();
    IMAGE_LOGI("OH_ImageReceiverNative Release.");
    delete receiver;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageReceiverNative_OnImageArrive(OH_ImageReceiverNative* receiver,
    OH_ImageReceiver_ImageArriveCallback callback, void* userdata)
{
    if (nullptr == receiver || nullptr == callback) {
        IMAGE_LOGE("OH_ImageReceiverNative_OnImageArrive: Invalid parameter");
        return IMAGE_RECEIVER_INVALID_PARAMETER;
    }
    if (nullptr == receiver->ptrImgRcv) {
        IMAGE_LOGE("Bad parameter: receiver data empty.");
        return IMAGE_RECEIVER_INVALID_PARAMETER;
    }
    if (receiver->ptrImgRcv->surfaceBufferAvaliableArriveListener_ == nullptr) {
        receiver->ptrImgRcv->surfaceBufferAvaliableArriveListener_ =
            std::make_shared<OHOS::Media::ImageReceiverArriveListener>(receiver);
    }
    bool ret = receiver->ptrImgRcv->surfaceBufferAvaliableArriveListener_->RegisterCallback(callback, userdata);
    if (!ret) {
        IMAGE_LOGD("callback has registered.");
    }
    return IMAGE_SUCCESS;
}

Image_ErrorCode OH_ImageReceiverNative_OffImageArrive(OH_ImageReceiverNative *receiver,
    OH_ImageReceiver_ImageArriveCallback callback)
{
    if (nullptr == receiver) {
        IMAGE_LOGE("Invalid parameter: receiver=null.");
        return IMAGE_RECEIVER_INVALID_PARAMETER;
    }
    if (nullptr == receiver->ptrImgRcv) {
        IMAGE_LOGE("Bad parameter: receiver data empty.");
        return IMAGE_RECEIVER_INVALID_PARAMETER;
    }
    if (nullptr == callback) {
        receiver->ptrImgRcv->surfaceBufferAvaliableArriveListener_.reset();
        return IMAGE_SUCCESS;
    }
    if (receiver->ptrImgRcv->surfaceBufferAvaliableArriveListener_ == nullptr) {
        IMAGE_LOGE("listener is nullptr. not registered.");
        return IMAGE_RECEIVER_INVALID_PARAMETER;
    }
    if (!receiver->ptrImgRcv->surfaceBufferAvaliableArriveListener_->UnregisterCallback(callback)) {
        IMAGE_LOGE("callback is not registered.");
        return IMAGE_RECEIVER_INVALID_PARAMETER;
    }
    return IMAGE_SUCCESS;
}

#ifdef __cplusplus
};
#endif