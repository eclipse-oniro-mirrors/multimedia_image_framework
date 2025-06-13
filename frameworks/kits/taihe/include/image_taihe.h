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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_TAIHE_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_TAIHE_H

#include "image_holder_manager.h"
#include "native_image.h"
#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "taihe/runtime.hpp"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;

class ImageImpl {
public:
    ImageImpl();
    explicit ImageImpl(std::shared_ptr<OHOS::Media::NativeImage> nativeImage);
    ~ImageImpl();

    int64_t GetImplPtr();
    std::shared_ptr<OHOS::Media::NativeImage> GetIncrementalImage() const
    {
        return nativeImage_;
    }

    Component GetComponentSync(ComponentType componentType);

    static struct Image Create(std::shared_ptr<OHOS::Media::NativeImage> nativeImage);
    void ReleaseSync();
    void NativeRelease();

    ohos::multimedia::image::image::Region GetClipRect();
    Size GetSize();
    int32_t GetFormat();
    int64_t GetTimestamp();

private:
    static OHOS::Media::ImageHolderManager<OHOS::Media::NativeImage> sNativeImageHolder_;
    std::shared_ptr<OHOS::Media::NativeImage> nativeImage_;
    bool isTestImage_;
};
} // namespace ANI::Image

#endif // FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_TAIHE_H