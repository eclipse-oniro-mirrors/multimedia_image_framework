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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_PIXEL_MAP_TAIHE_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_PIXEL_MAP_TAIHE_H

#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "pixel_map.h"
#include "taihe/runtime.hpp"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;
using namespace OHOS;

class PixelMapImpl {
public:
    PixelMapImpl();
    explicit PixelMapImpl(array_view<uint8_t> const& colors, InitializationOptions const& etsOptions);
    explicit PixelMapImpl(InitializationOptions const& etsOptions);
    explicit PixelMapImpl(std::shared_ptr<OHOS::Media::PixelMap> pixelMap);
    explicit PixelMapImpl(int64_t aniPtr);
    ~PixelMapImpl();

    int64_t GetImplPtr();
    std::shared_ptr<OHOS::Media::PixelMap> GetNativePtr();
    static std::shared_ptr<OHOS::Media::PixelMap> GetPixelMap(PixelMap etsPixelMap);
    static PixelMap CreatePixelMap(std::shared_ptr<OHOS::Media::PixelMap> pixelMap);

    ImageInfo GetImageInfoSync();
    void ReadPixelsToBufferSync(array_view<uint8_t> dst);
    void ReadPixelsSync(weak::PositionArea area);
    void WriteBufferToPixelsSync(array_view<uint8_t> src);
    void WritePixelsSync(weak::PositionArea area);
    PixelMap CreateAlphaPixelmapSync();
    int32_t GetBytesNumberPerRow();
    int32_t GetPixelBytesNumber();
    int32_t GetDensity();
    void ScaleSync(double x, double y);
    void ScaleWithAntiAliasingSync(double x, double y, AntiAliasingLevel level);
    void CropSync(ohos::multimedia::image::image::Region const& region);
    void RotateSync(double angle);
    void FlipSync(bool horizontal, bool vertical);
    void OpacitySync(double rate);
    void SetMemoryNameSync(string_view name);
    void SetTransferDetached(bool detached);
    void ConvertPixelFormatSync(PixelMapFormat targetPixelFormat);
    uintptr_t GetColorSpace();
    void SetColorSpace(uintptr_t colorSpace);
    void Marshalling(uintptr_t sequence);
    PixelMap UnmarshallingSync(uintptr_t sequence);
    void ToSdrSync();
    void ApplyColorSpaceSync(uintptr_t targetColorSpace);
    void ReleaseSync();
    bool GetIsEditable();
    bool GetIsStrideAlignment();
    void SetCaptureId(int32_t captureId);
    int32_t GetCaptureId();
    void SetTimestamp(int64_t timestamp);
    int64_t GetTimestamp();

private:
    std::shared_ptr<OHOS::Media::PixelMap> nativePixelMap_ = nullptr;
    bool aniEditable_ = true;
    bool transferDetach_ = false;
    bool Is10BitFormat(OHOS::Media::PixelFormat format);
    void ParseInitializationOptions(InitializationOptions const& etsOptions,
        OHOS::Media::InitializationOptions &options);
    void Release();
    int64_t timestamp_ = 0;
    int32_t captureId_ = 0;
};
} // namespace ANI::Image

#endif
