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
#ifndef IMAGE_PACKER_IMPL_H
#define IMAGE_PACKER_IMPL_H

#include "cj_ffi/cj_common_ffi.h"
#include "ffi_remote_data.h"
#include "image_log.h"
#include "image_packer.h"
#include "inttypes.h"
#include "media_errors.h"
#include "picture_impl.h"
#include "pixel_map_impl.h"

namespace OHOS {
namespace Media {
class ImagePackerImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(ImagePackerImpl, OHOS::FFI::FFIData)
public:
    ImagePackerImpl();
    std::tuple<int32_t, uint8_t*, int64_t> Packing(PixelMap& source, const PackOption& option, uint64_t bufferSize);
    std::tuple<int32_t, uint8_t*, int64_t> Packing(ImageSource& source, const PackOption& option, uint64_t bufferSize);
    std::tuple<int32_t, uint8_t*, int64_t> PackToData(
        std::shared_ptr<PixelMap> source, const PackOption& option, uint64_t bufferSize);
    std::tuple<int32_t, uint8_t*, int64_t> PackToData(
        std::shared_ptr<ImageSource> source, const PackOption& option, uint64_t bufferSize);
    std::tuple<int32_t, uint8_t*, int64_t> PackToData(
        std::shared_ptr<Picture> source, const PackOption& option, uint64_t bufferSize);
    uint32_t PackToFile(std::shared_ptr<PixelMap> source, int fd, const PackOption& option);
    uint32_t PackToFile(std::shared_ptr<ImageSource> source, int fd, const PackOption& option);
    uint32_t PackToFile(std::shared_ptr<Picture> source, int fd, const PackOption& option);
    std::shared_ptr<ImagePacker> GetImagePacker();

    void Release()
    {
        real_.reset();
    }

private:
    std::shared_ptr<ImagePacker> real_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // IMAGE_PACKER_IMPL_H
