/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_PACKER_NATIVE_IMPL_H
#define FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_PACKER_NATIVE_IMPL_H
#include <stdint.h>
#include "image_packer.h"
#include "image_source_native.h"
#include "pixelmap_native.h"

#ifdef __cplusplus
extern "C" {
#endif

struct OH_ImagePackerNative {
public:
    OH_ImagePackerNative();
    OH_ImagePackerNative(std::shared_ptr<OHOS::Media::ImagePacker> imagePacker);
    ~OH_ImagePackerNative();

    int32_t PackingFromImageSource(OHOS::Media::PackOption *option, struct OH_ImageSourceNative *imageSource,
        uint8_t *outData, int64_t *size);

    int32_t PackingFromPixelmap(OHOS::Media::PackOption *option, struct OH_PixelmapNative *pixelmap,
        uint8_t *outData, int64_t *size);

    int32_t PackToFileFromImageSource(OHOS::Media::PackOption *option, struct OH_ImageSourceNative *imageSource,
        const int fd);

    int32_t PackToFileFromPixelmap(OHOS::Media::PackOption *option, struct OH_PixelmapNative *pixelmap,
        const int32_t fd);

    std::shared_ptr<OHOS::Media::ImagePacker> GetInnerImagePacker();

private:
    std::shared_ptr<OHOS::Media::ImagePacker> imagePacker_;
};

#ifdef __cplusplus
};
#endif
/** @} */
#endif // FRAMEWORKS_KITS_JS_COMMON_INCLUDE_IMAGE_PACKER_NATIVE_IMPL_H