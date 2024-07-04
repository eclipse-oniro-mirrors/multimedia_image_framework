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
#include "image_packer_impl.h"

namespace OHOS {
namespace Media {
extern "C" {
ImagePackerImpl::ImagePackerImpl()
{
    real_ = std::make_unique<ImagePacker>();
}

std::shared_ptr<ImagePacker> ImagePackerImpl::GetImagePacker()
{
    if (real_ == nullptr) {
        return nullptr;
    }
    std::shared_ptr<ImagePacker> res = real_;
    return res;
}

std::tuple<int32_t, uint8_t*, int64_t> ImagePackerImpl::Packing(PixelMap& source, const PackOption& option,
    uint64_t bufferSize)
{
    return CommonPacking<PixelMap>(source, option, bufferSize);
}

std::tuple<int32_t, uint8_t*, int64_t> ImagePackerImpl::Packing(ImageSource& source, const PackOption& option,
    uint64_t bufferSize)
{
    return CommonPacking<ImageSource>(source, option, bufferSize);
}

uint32_t ImagePackerImpl::PackToFile(PixelMap& source, int fd, const PackOption& option)
{
    return CommonPackToFile<PixelMap>(source, fd, option);
}

uint32_t ImagePackerImpl::PackToFile(ImageSource& source, int fd, const PackOption& option)
{
    return CommonPackToFile<ImageSource>(source, fd, option);
}
}
} // namespace Media
} // namespace OHOS
