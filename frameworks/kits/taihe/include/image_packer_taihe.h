/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_PACKER_TAIHE_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_PACKER_TAIHE_H

#include "image_packer.h"
#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "taihe/runtime.hpp"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;

class ImagePackerImpl {
public:
    ImagePackerImpl();
    explicit ImagePackerImpl(std::shared_ptr<OHOS::Media::ImagePacker> imagePacker);
    ~ImagePackerImpl();

    array<uint8_t> Packing(int32_t packType, int64_t source, PackingOption const& options, bool needReturnError);
    void PackToFile(int32_t packType, int64_t source, int32_t fd, PackingOption const& options);

    void PackImageSourceToFileSync(weak::ImageSource source, int32_t fd, PackingOption const& options);
    void PackPixelMapToFileSync(weak::PixelMap source, int32_t fd, PackingOption const& options);
    void PackToFileFromPixelmapSequenceSync(array_view<PixelMap> pixelmapSequence, int32_t fd,
        PackingOptionsForSequence const& options);
    void PackPictureToFileSync(weak::Picture picture, int32_t fd, PackingOption const& options);

    array<uint8_t> PackingPictureSync(weak::Picture picture, PackingOption const& options);

    array<uint8_t> PackImageSourceToDataSync(weak::ImageSource source, PackingOption const& options);
    array<uint8_t> PackPixelMapToDataSync(weak::PixelMap source, PackingOption const& options);
    array<uint8_t> PackToDataFromPixelmapSequenceSync(array_view<PixelMap> pixelmapSequence,
        PackingOptionsForSequence const& options);

    void ReleaseSync();

    array<string> GetSupportedFormats();

private:
    std::shared_ptr<OHOS::Media::ImagePacker> nativeImagePacker_;
    bool isRelease = false;
};
}

#endif // FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_PACKER_TAIHE_H