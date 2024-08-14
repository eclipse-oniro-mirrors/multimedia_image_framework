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
#ifndef IMAGE_IMPL_H
#define IMAGE_IMPL_H

#include "ffi_remote_data.h"
#include "image_utils.h"
#include "image_holder_manager.h"
#include "native_image.h"

namespace OHOS {
namespace Media {

class ImageImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(ImageImpl, OHOS::FFI::FFIData)
public:
    explicit ImageImpl(std::shared_ptr<NativeImage> nativeImage);
    std::shared_ptr<NativeImage> GetNativeImage();
    uint32_t GetClipRect(CRegion *ret);
    uint32_t GetSize(CSize *ret);
    uint32_t GetFormat(int32_t *ret);
    uint32_t GetComponent(int32_t componentType, CRetComponent *ret);
    void Release();

private:
    static int64_t Create(ImageImpl *image, std::shared_ptr<NativeImage> nativeImage);
    std::shared_ptr<NativeImage> native_;
    bool isTestImage_;
    static ImageHolderManager<NativeImage> sNativeImageHolder_;
};
}
}

#endif