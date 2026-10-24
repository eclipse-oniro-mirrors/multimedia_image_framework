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
    explicit PixelMapImpl(array_view<uint8_t> const& pixels, InitializationOptions const& etsOptions);
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
    void ReadAllPixelsToBuffer(array_view<uint8_t> dst);
    void ReadAllPixelsToBufferSync(array_view<uint8_t> dst);
    void ReadPixelsToAreaWrapper(weak::PositionArea area, array_view<uint8_t> pixels);
    void ReadPixelsToAreaSyncWrapper(weak::PositionArea area, array_view<uint8_t> pixels);
    void WriteAllPixelsFromBuffer(array_view<uint8_t> src);
    void WriteAllPixelsFromBufferSync(array_view<uint8_t> src);
    void WriteAllPixelsFromBufferWithSourcePixelFormat(array_view<uint8_t> src, PixelMapFormat sourcePixelFormat);
    void WriteAllPixelsFromBufferSyncWithSourcePixelFormat(array_view<uint8_t> src, PixelMapFormat sourcePixelFormat);
    void WritePixelsFromArea(weak::PositionArea area);
    void WritePixelsFromAreaSync(weak::PositionArea area);
    void WritePixelsFromAreaWithSourcePixelFormat(weak::PositionArea area, PixelMapFormat sourcePixelFormat);
    void WritePixelsFromAreaSyncWithSourcePixelFormat(weak::PositionArea area, PixelMapFormat sourcePixelFormat);
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
    PixelMap ExtractAlphaPixelMap();
    PixelMap ExtractAlphaPixelMapSync();
    PixelMap CreateAlphaPixelmapAsync();
    PixelMap CreateAlphaPixelmapPromise();
    PixelMap CreateAlphaPixelmapSync();
    int32_t GetBytesNumberPerRow();
    int32_t GetPixelBytesNumber();
    int32_t GetDensity();
    void ApplyScale(double x, double y, optional_view<AntiAliasingLevel> level);
    void ApplyScaleSync(double x, double y, optional_view<AntiAliasingLevel> level);
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
    void ApplyTranslate(double x, double y);
    void ApplyTranslateSync(double x, double y);
    void TranslateAsync(double x, double y);
    void TranslatePromise(double x, double y);
    void TranslateSync(double x, double y);
    void ApplyCrop(ohos::multimedia::image::image::Region const& region);
    void ApplyCropSync(ohos::multimedia::image::image::Region const& region);
    void CropAsync(ohos::multimedia::image::image::Region const& region);
    void CropPromise(ohos::multimedia::image::image::Region const& region);
    void CropSync(ohos::multimedia::image::image::Region const& region);
    void ApplyRotate(double angle);
    void ApplyRotateSync(double angle);
    void RotateAsync(double angle);
    void RotatePromise(double angle);
    void RotateSync(double angle);
    void ApplyFlip(bool horizontal, bool vertical);
    void ApplyFlipSync(bool horizontal, bool vertical);
    void FlipAsync(bool horizontal, bool vertical);
    void FlipPromise(bool horizontal, bool vertical);
    void FlipSync(bool horizontal, bool vertical);
    void SetOpacity(double value);
    void SetOpacitySync(double value);
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
    void ReadAllPixelsToBufferImpl(array_view<uint8_t> const& dst);
    void ReadPixelsToAreaWrapperImpl(weak::PositionArea const& area, array_view<uint8_t> const& pixels);
    void WriteAllPixelsFromBufferImpl(array_view<uint8_t> const& src);
    void WriteAllPixelsFromBufferWithSourcePixelFormatImpl(array_view<uint8_t> const& src,
        PixelMapFormat const& sourcePixelFormat);
    void WritePixelsFromAreaImpl(weak::PositionArea const& area);
    void WritePixelsFromAreaWithSourcePixelFormatImpl(weak::PositionArea const& area,
        PixelMapFormat const& sourcePixelFormat);
    bool Is10BitYuvFormat(OHOS::Media::PixelFormat format);
    void Release();
    int64_t timestamp_ = 0;
    int32_t captureId_ = 0;
};
} // namespace ANI::Image

#endif
