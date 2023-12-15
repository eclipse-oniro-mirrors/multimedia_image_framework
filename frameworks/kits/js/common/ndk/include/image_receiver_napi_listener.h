/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_RECEIVER_NAPI_LISTENER_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_RECEIVER_NAPI_LISTENER_H

#include "image_receiver.h"
#include "image_receiver_mdk.h"

namespace OHOS {
namespace Media {
class ImageReceiverNapiListener : public SurfaceBufferAvaliableListener {
public:
    ~ImageReceiverNapiListener() override
    {
        callBack = nullptr;
    }
    void OnSurfaceBufferAvaliable() __attribute__((no_sanitize("cfi"))) override
    {
        if (callBack != nullptr) {
            callBack();
        }
    }
    OH_Image_Receiver_On_Callback callBack = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_RECEIVER_NAPI_LISTENER_H
