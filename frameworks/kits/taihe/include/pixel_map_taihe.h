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
    explicit PixelMapImpl(array_view<uint8_t> const& colors, InitializationOptions const& etsOptions,
        AllocatorType const& allocatorType);
    explicit PixelMapImpl(InitializationOptions const& etsOptions);
    explicit PixelMapImpl(InitializationOptions const& etsOptions, AllocatorType const& allocatorType);
    explicit PixelMapImpl(std::shared_ptr<OHOS::Media::PixelMap> pixelMap);
    explicit PixelMapImpl(int64_t aniPtr);
    ~PixelMapImpl();

    int64_t GetImplPtr();
    std::shared_ptr<OHOS::Media::PixelMap> GetNativePtr();
    static std::shared_ptr<OHOS::Media::PixelMap> GetPixelMap(PixelMap etsPixelMap);
    static PixelMap CreatePixelMap(std::shared_ptr<OHOS::Media::PixelMap> pixelMap);

    ImageInfo GetImageInfoAsync();
    ImageInfo GetImageInfoPromise();
    ImageInfo GetImageInfoSync();
    void ReadPixelsToBufferAsync(array_view<uint8_t> dst);
    void ReadPixelsToBufferPromise(array_view<uint8_t> dst);
    void ReadPixelsToBufferSync(array_view<uint8_t> dst);
    void ReadPixelsAsync(weak::PositionArea area);
    void ReadPixelsPromise(weak::PositionArea area);
    void ReadPixelsSync(weak::PositionArea area);
    void WriteBufferToPixelsAsync(array_view<uint8_t> src);
    void WriteBufferToPixelsPromise(array_view<uint8_t> src);
    void WriteBufferToPixelsSync(array_view<uint8_t> src);
    void WritePixelsAsync(weak::PositionArea area);
    void WritePixelsPromise(weak::PositionArea area);
    void WritePixelsSync(weak::PositionArea area);
    PixelMap CreateAlphaPixelmapAsync();
    PixelMap CreateAlphaPixelmapPromise();
    PixelMap CreateAlphaPixelmapSync();
    int32_t GetBytesNumberPerRow();
    int32_t GetPixelBytesNumber();
    int32_t GetDensity();
    void ScaleAsync(double x, double y);
    void ScalePromise(double x, double y);
    void ScaleSync(double x, double y);
    void ScaleWithAntiAliasingPromise(double x, double y, AntiAliasingLevel level);
    void ScaleWithAntiAliasingSync(double x, double y, AntiAliasingLevel level);
    PixelMap CreateCroppedAndScaledPixelMapPromise(ohos::multimedia::image::image::Region const& region,
        double x, double y, optional_view<AntiAliasingLevel> level);
    PixelMap CreateCroppedAndScaledPixelMapSync(ohos::multimedia::image::image::Region const& region,
        double x, double y, optional_view<AntiAliasingLevel> level);
    PixelMap CreateScaledPixelMapPromise(double x, double y, optional_view<AntiAliasingLevel> level);
    PixelMap CreateScaledPixelMapSync(double x, double y, optional_view<AntiAliasingLevel> level);
    PixelMap ClonePromise();
    PixelMap CloneSync();
    void TranslateAsync(double x, double y);
    void TranslatePromise(double x, double y);
    void TranslateSync(double x, double y);
    void CropAsync(ohos::multimedia::image::image::Region const& region);
    void CropPromise(ohos::multimedia::image::image::Region const& region);
    void CropSync(ohos::multimedia::image::image::Region const& region);
    void RotateAsync(double angle);
    void RotatePromise(double angle);
    void RotateSync(double angle);
    void FlipAsync(bool horizontal, bool vertical);
    void FlipPromise(bool horizontal, bool vertical);
    void FlipSync(bool horizontal, bool vertical);
    void OpacityAsync(double rate);
    void OpacityPromise(double rate);
    void OpacitySync(double rate);
    void SetMemoryNameSync(string_view name);
    void SetTransferDetached(bool detached);
    void ConvertPixelFormatPromise(PixelMapFormat targetPixelFormat);
    void ConvertPixelFormatSync(PixelMapFormat targetPixelFormat);
    uintptr_t GetColorSpace();
    void SetColorSpace(uintptr_t colorSpace);
    void Marshalling(uintptr_t sequence);
    PixelMap UnmarshallingPromise(uintptr_t sequence);
    PixelMap UnmarshallingSync(uintptr_t sequence);
    void ToSdrPromise();
    void ToSdrSync();
    void ApplyColorSpaceAsync(uintptr_t targetColorSpace);
    void ApplyColorSpacePromise(uintptr_t targetColorSpace);
    void ApplyColorSpaceSync(uintptr_t targetColorSpace);
    HdrMetadataValue GetMetadata(HdrMetadataKey key);
    void SetMetadataPromise(HdrMetadataKey key, HdrMetadataValue const& value);
    void SetMetadataSync(HdrMetadataKey key, HdrMetadataValue const& value);
    void ReleaseAsync();
    void ReleasePromise();
    void ReleaseSync();
    bool IsReleased();
    int32_t GetUniqueId();
    bool GetIsEditable();
    bool GetIsStrideAlignment();
    void SetCaptureId(int32_t captureId);
    int32_t GetCaptureId();
    void SetTimestamp(int64_t timestamp);
    int64_t GetTimestamp();

private:
    std::shared_ptr<OHOS::Media::PixelMap> nativePixelMap_ = nullptr;
    bool Is10BitFormat(OHOS::Media::PixelFormat format);
    bool Is10BitYuvFormat(OHOS::Media::PixelFormat format);
    void ParseInitializationOptions(InitializationOptions const& etsOptions,
        OHOS::Media::InitializationOptions &options);
    void Release();
    int64_t timestamp_ = 0;
    int32_t captureId_ = 0;
};
} // namespace ANI::Image

#endif
