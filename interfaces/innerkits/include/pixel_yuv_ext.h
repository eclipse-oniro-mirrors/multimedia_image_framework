/*
* Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_INCLUDE_PIXEL_YUV_EXT_H
#define INTERFACES_INNERKITS_INCLUDE_PIXEL_YUV_EXT_H

#include "image_type.h"

#include "include/core/SkBitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkImage.h"
#include "memory_manager.h"
#include "pixel_yuv.h"

namespace OHOS {
namespace Media {

class PixelYuvExt : public PixelYuv {
public:
    PixelYuvExt() {}
    virtual ~PixelYuvExt();
    NATIVEEXPORT void rotate(float degrees) override;
    NATIVEEXPORT void scale(float xAxis, float yAxis) override;
    NATIVEEXPORT void scale(float xAxis, float yAxis, const AntiAliasingOption &option) override;
    NATIVEEXPORT bool resize(float xAxis, float yAxis) override;
    NATIVEEXPORT void flip(bool xAxis, bool yAxis) override;
    NATIVEEXPORT int32_t GetByteCount() override;
    NATIVEEXPORT void SetPixelsAddr(void *addr, void *context, uint32_t size, AllocatorType type,
                                    CustomFreePixelMap func) override;
#ifdef IMAGE_COLORSPACE_FLAG
    bool CheckColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace);
    int32_t ColorSpaceBGRAToYuv(uint8_t *bgraData, SkTransYuvInfo &dst, ImageInfo &imageInfo, PixelFormat &format,
        const OHOS::ColorManager::ColorSpace &grColorSpace);
    NATIVEEXPORT uint32_t ApplyColorSpace(const OHOS::ColorManager::ColorSpace &grColorSpace) override;
#endif
};
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_INNERKITS_INCLUDE_PIXEL_YUV_EXT_H