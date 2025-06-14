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
#ifndef IMAGE_CREATOR_IMPL_H
#define IMAGE_CREATOR_IMPL_H

#include "cj_ffi/cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "image_creator.h"

namespace OHOS {
namespace Media {
class ImageCreatorImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(ImageCreatorImpl, OHOS::FFI::FFIData)
public:
    ImageCreatorImpl(int32_t width, int32_t height, int32_t format, int32_t capacity);
    ~ImageCreatorImpl();
    std::shared_ptr<ImageCreator> GetImageCreator();
    void Release();
    uint32_t CjOn(std::string name, std::function<void()> callBack);
#ifdef IMAGE_DEBUG_FLAG
    bool isCallBackTest = false;
#endif

private:
    void release();
    bool isRelease = false;
    std::shared_ptr<ImageCreator> imageCreator_ = nullptr;
};

class CJImageCreatorReleaseListener : public SurfaceBufferReleaseListener {
public:
    ~CJImageCreatorReleaseListener() override
    {
        callBack = nullptr;
    }
    void OnSurfaceBufferRelease() override
    {
        if (callBack != nullptr) {
            callBack();
        }
    }
    std::string name;
    std::function<void()> callBack = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // IMAGE_CREATOR_IMPL_H
