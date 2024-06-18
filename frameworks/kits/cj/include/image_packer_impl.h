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
#include "media_errors.h"
#include "image_log.h"
#include "pixel_map_impl.h"
#include "image_packer.h"
#include "inttypes.h"

namespace OHOS {
namespace Media {
class ImagePackerImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(ImagePackerImpl, OHOS::FFI::FFIData)
public:
    ImagePackerImpl();
    std::tuple<int32_t, uint8_t*, int64_t> Packing(PixelMap& source, const PackOption& option, uint64_t bufferSize);
    std::tuple<int32_t, uint8_t*, int64_t> Packing(ImageSource& source, const PackOption& option, uint64_t bufferSize);
    uint32_t PackToFile(PixelMap& source, int fd, const PackOption& option);
    uint32_t PackToFile(ImageSource& source, int fd, const PackOption& option);
    std::shared_ptr<ImagePacker> GetImagePacker();

    void Release()
    {
        real_.reset();
    }

    template<typename T>
    std::tuple<int32_t, uint8_t*, int64_t> CommonPacking(T& source, const PackOption& option, uint64_t bufferSize)
    {
        if (real_ == nullptr) {
            IMAGE_LOGE("Packing failed, real_ is nullptr");
            return std::make_tuple(ERR_IMAGE_INIT_ABNORMAL, nullptr, 0);
        }

        if (bufferSize <= 0) {
            IMAGE_LOGE("Packing failed, bufferSize cannot be less than or equal to 0");
            return std::make_tuple(ERR_IMAGE_INIT_ABNORMAL, nullptr, 0);
        }
        
        uint8_t* resultBuffer = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * bufferSize));
        if (resultBuffer == nullptr) {
            IMAGE_LOGE("Packing failed, malloc buffer failed");
            return std::make_tuple(ERR_IMAGE_INIT_ABNORMAL, nullptr, 0);
        }

        uint32_t packingRet = real_->StartPacking(resultBuffer, bufferSize, option);
        if (packingRet != SUCCESS) {
            IMAGE_LOGE("Packing failed, StartPacking failed, ret=%{public}u.", packingRet);
            free(resultBuffer);
            return std::make_tuple(packingRet, nullptr, 0);
        }

        uint32_t addImageRet = real_->AddImage(source);
        if (addImageRet != SUCCESS) {
            IMAGE_LOGE("Packing failed, AddImage failed, ret=%{public}u.", addImageRet);
            free(resultBuffer);
            return std::make_tuple(addImageRet, nullptr, 0);
        }

        int64_t packedSize = 0;
        uint32_t finalPackRet = real_->FinalizePacking(packedSize);
        if (finalPackRet != SUCCESS) {
            IMAGE_LOGE("Packing failed, FinalizePacking failed, ret=%{public}u.", finalPackRet);
            free(resultBuffer);
            return std::make_tuple(finalPackRet, nullptr, 0);
        }
        IMAGE_LOGD("packedSize=%{public}" PRId64, packedSize);

        return std::make_tuple(SUCCESS_CODE, resultBuffer, packedSize);
    }

    template<typename T>
    uint32_t CommonPackToFile(T& source, int fd, const PackOption& option)
    {
        if (real_ == nullptr) {
            IMAGE_LOGE("Packing failed, real_ is nullptr");
            return ERR_IMAGE_INIT_ABNORMAL;
        }

        uint32_t packingRet = real_->StartPacking(fd, option);
        if (packingRet != SUCCESS) {
            IMAGE_LOGE("Packing failed, StartPacking failed, ret=%{public}u.", packingRet);
            return packingRet;
        }

        uint32_t addImageRet = real_->AddImage(source);
        if (addImageRet != SUCCESS) {
            IMAGE_LOGE("Packing failed, AddImage failed, ret=%{public}u.", addImageRet);
            return addImageRet;
        }

        int64_t packedSize = 0;
        uint32_t finalPackRet = real_->FinalizePacking(packedSize);
        if (finalPackRet != SUCCESS) {
            IMAGE_LOGE("Packing failed, FinalizePacking failed, ret=%{public}u.", finalPackRet);
            return finalPackRet;
        }
        IMAGE_LOGD("packedSize=%{public}"  PRId64, packedSize);
        return SUCCESS;
    }

private:
    std::shared_ptr<ImagePacker> real_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // IMAGE_PACKER_IMPL_H
