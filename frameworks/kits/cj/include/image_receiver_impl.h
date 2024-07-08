/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef IMAGE_RECEIVER_IMPL_H
#define IMAGE_RECEIVER_IMPL_H

#include "ffi_remote_data.h"
#include "image_utils.h"
#include "image_receiver.h"
#include "image_receiver_manager.h"
#include "image_impl.h"

namespace OHOS {
namespace Media {
class ImageReceiverImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(ImageReceiverImpl, OHOS::FFI::FFIData)
public:
    explicit ImageReceiverImpl(std::shared_ptr<ImageReceiver> imageReceiver);
    static int64_t CreateImageReceiver(int32_t width, int32_t height, int32_t format, int32_t capacity);
    uint32_t GetSize(CSize *ret);
    uint32_t GetCapacity(int32_t *ret);
    uint32_t GetFormat(int32_t *ret);
    char *GetReceivingSurfaceId();
    sptr<ImageImpl> ReadNextImage();
    sptr<ImageImpl> ReadLatestImage();
    void Release();

private:
    std::shared_ptr<ImageReceiver> imageReceiver_;
};

}
}

#endif