/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PICTURE_IMPL_H
#define PICTURE_IMPL_H

#include "ffi_remote_data.h"
#include "picture.h"

namespace OHOS {
namespace Media {
class PictureImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(PictureImpl, OHOS::FFI::FFIData)
public:
    explicit PictureImpl(std::shared_ptr<Picture> picture);
    ~PictureImpl();
    std::shared_ptr<Picture> GetPicture();
    uint32_t SetMetadata(MetadataType metadataType, std::shared_ptr<ImageMetadata> imageMetadata);
    std::shared_ptr<ImageMetadata> GetMetadata(MetadataType metadataType, uint32_t* errCode);

private:
    void release();
    std::shared_ptr<Picture> nativePicture_;
    bool isRelease = false;
    uint32_t uniqueId_ = 0;
};
} // namespace Media
} // namespace OHOS
#endif // PICTURE_IMPL_H