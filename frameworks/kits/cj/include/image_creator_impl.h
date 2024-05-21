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

#include "ffi_remote_data.h"
#include "cj_ffi/cj_common_ffi.h"
#include "image_log.h"
#include "image_creator.h"

namespace OHOS {
namespace Media {
class ImageCreatorImpl : public OHOS::FFI::FFIData {
public:
    ImageCreatorImpl(int32_t width, int32_t height, int32_t format, int32_t capacity);
    std::shared_ptr<ImageCreator> GetImageCreator();
    void Release()
    {
        real_.reset();
    }
    OHOS::FFI::RuntimeType *GetRuntimeType() override { return GetClassType(); }

private:
    friend class OHOS::FFI::RuntimeType;
    friend class OHOS::FFI::TypeBase;
    static OHOS::FFI::RuntimeType *GetClassType()
    {
        static OHOS::FFI::RuntimeType runtimeType =
            OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("ImageCreatorImpl");
        return &runtimeType;
    }
    std::shared_ptr<ImageCreator> real_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // IMAGE_CREATOR_IMPL_H