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
#include "image_creator_impl.h"

namespace OHOS {
namespace Media {
ImageCreatorImpl::ImageCreatorImpl(int32_t width, int32_t height, int32_t format, int32_t capacity)
{
    imageCreator_ = ImageCreator::CreateImageCreator(width, height, format, capacity);
}

std::shared_ptr<ImageCreator> ImageCreatorImpl::GetImageCreator()
{
    return imageCreator_;
}

ImageCreatorImpl::~ImageCreatorImpl()
{
    release();
}

void ImageCreatorImpl::Release()
{
    if (imageCreator_ != nullptr) {
        imageCreator_->~ImageCreator();
        imageCreator_ = nullptr;
    }
}

void ImageCreatorImpl::release()
{
    if (!isRelease) {
        Release();
        isRelease = true;
    }
}

uint32_t ImageCreatorImpl::CjOn(std::string name, std::function<void()> callBack)
{
    if (imageCreator_ == nullptr) {
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    std::shared_ptr<CJImageCreatorReleaseListener> listener = std::make_shared<CJImageCreatorReleaseListener>();
    listener->name = name;
    listener->callBack = callBack;
    imageCreator_->RegisterBufferReleaseListener((std::shared_ptr<SurfaceBufferReleaseListener>&)listener);
    return SUCCESS;
}
} // namespace Media
} // namespace OHOS
