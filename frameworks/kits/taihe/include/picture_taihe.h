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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_PICTURE_TAIHE_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_PICTURE_TAIHE_H

#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "picture.h"
#include "taihe/runtime.hpp"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;

class PictureImpl {
public:
    PictureImpl();
    explicit PictureImpl(std::shared_ptr<OHOS::Media::Picture> picture);
    PictureImpl(int64_t aniPtr);
    ~PictureImpl();
    int64_t GetImplPtr();
    std::shared_ptr<OHOS::Media::Picture> GetNativePtr();
    static Picture CreatePicture(std::shared_ptr<OHOS::Media::Picture> picture);

    PixelMap GetMainPixelmap();
    PixelMap GetHdrComposedPixelmapSync();
    GainMap GetGainmapPixelmap();
    void SetAuxiliaryPicture(AuxiliaryPictureType type, weak::AuxiliaryPicture auxiliaryPicture);
    AuxPicture GetAuxiliaryPicture(AuxiliaryPictureType type);
    void SetMetadataSync(MetadataType metadataType, weak::Metadata metadata);
    Metadata GetMetadataSync(MetadataType metadataType);
    void Marshalling(uintptr_t sequence);
    void Release();

private:
    std::shared_ptr<OHOS::Media::Picture> nativePicture_;
    bool isRelease = false;
};
} // namespace ANI::Image

#endif // FRAMEWORKS_KITS_TAIHE_INCLUDE_PICTURE_TAIHE_H