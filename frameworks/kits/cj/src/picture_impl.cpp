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

#include "picture_impl.h"

#include "image_common.h"
#include "image_log.h"

namespace OHOS {
namespace Media {
PictureImpl::PictureImpl(std::shared_ptr<Picture> picture)
{
    static std::atomic<uint32_t> currentId = 0;
    uniqueId_ = currentId.fetch_add(1, std::memory_order_relaxed);
    nativePicture_ = picture;
}

PictureImpl::~PictureImpl()
{
    release();
}

void PictureImpl::release()
{
    if (!isRelease) {
        if (nativePicture_ != nullptr) {
            nativePicture_ = nullptr;
        }
        isRelease = true;
    }
}

std::shared_ptr<Picture> PictureImpl::GetPicture()
{
    return nativePicture_;
}

uint32_t PictureImpl::SetMetadata(MetadataType metadataType, std::shared_ptr<ImageMetadata> imageMetadata)
{
    IMAGE_LOGD("SetMetadata IN");
    if (nativePicture_ == nullptr) {
        IMAGE_LOGE("Empty native picture");
        return IMAGE_BAD_PARAMETER;
    }
    if (metadataType != MetadataType::EXIF) {
        IMAGE_LOGE("Unsupport MetadataType");
        return IMAGE_UNSUPPORTED_METADATA;
    }
    return nativePicture_->SetExifMetadata(std::reinterpret_pointer_cast<ExifMetadata>(imageMetadata));
}

std::shared_ptr<ImageMetadata> PictureImpl::GetMetadata(MetadataType metadataType, uint32_t* errCode)
{
    IMAGE_LOGD("GetMetadata IN");
    if (nativePicture_ == nullptr) {
        IMAGE_LOGE("Empty native picture");
        return nullptr;
    }
    if (metadataType != MetadataType::EXIF) {
        *errCode = IMAGE_UNSUPPORTED_METADATA;
        IMAGE_LOGE("Unsupport MetadataType");
        return nullptr;
    }
    return std::reinterpret_pointer_cast<ImageMetadata>(nativePicture_->GetExifMetadata());
}
} // namespace Media
} // namespace OHOS