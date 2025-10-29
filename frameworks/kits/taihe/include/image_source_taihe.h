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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_SOURCE_TAIHE_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_SOURCE_TAIHE_H

#include "image_packer_taihe.h"
#include "image_source.h"
#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "taihe/runtime.hpp"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;

class ImageSourceImpl {
public:
    ImageSourceImpl();
    explicit ImageSourceImpl(std::shared_ptr<OHOS::Media::ImageSource> imageSource);
    ImageSourceImpl(std::shared_ptr<OHOS::Media::ImageSource> imageSource,
        std::shared_ptr<OHOS::Media::IncrementalPixelMap> incPixelMap);
    ImageSourceImpl(int64_t aniPtr);
    ~ImageSourceImpl();
    int64_t GetImplPtr();

    ImageInfo GetImageInfoSyncWithIndex(int32_t index);
    ImageInfo GetImageInfoSync();
    PixelMap CreatePixelMapSyncWithOptions(DecodingOptions const& options);
    PixelMap CreatePixelMapSync();
    PixelMap CreatePixelMapUsingAllocatorSync(optional_view<DecodingOptions> options,
        optional_view<AllocatorType> allocatorType);
    optional<PixelMap> CreateWideGamutSdrPixelMapSync();
    array<PixelMap> CreatePixelMapListSync();
    array<PixelMap> CreatePixelMapListSyncWithOptions(DecodingOptions const& options);
    array<PixelMap> CreatePixelMapListSyncWithOptionalOptions(optional_view<DecodingOptions> options);
    array<int32_t> GetDelayTimeListSync();
    array<int32_t> GetDisposalTypeListSync();
    int32_t GetFrameCountSync();
    string GetImagePropertyReturnsPromise(PropertyKey key, optional_view<ImagePropertyOptions> options);
    map<PropertyKey, PropertyValue> GetImagePropertiesSync(array_view<PropertyKey> key);
    optional<string> GetImagePropertySync(PropertyKey key);
    void ModifyImagePropertySync(PropertyKey key, string_view value);
    void ModifyImagePropertiesSync(map_view<PropertyKey, PropertyValue> records);
    void ModifyImagePropertiesEnhancedSync(map_view<string, PropertyValue> records);
    void UpdateDataSync(array_view<uint8_t> buf, bool isFinished, int32_t offset, int32_t length);
    void ReleaseSync();
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    Picture CreatePictureSync(optional_view<DecodingOptionsForPicture> options);
    optional<Picture> CreatePictureAtIndexSync(int32_t index);
#endif

    array<string> GetSupportedFormats();

    std::shared_ptr<OHOS::Media::ImageSource> nativeImgSrc = nullptr;
    std::shared_ptr<OHOS::Media::IncrementalPixelMap> GetIncrementalPixelMap() const
    {
        return navIncPixelMap_;
    }

    static thread_local std::string filePath_;
    static thread_local int fileDescriptor_;
    static thread_local void* fileBuffer_;
    static thread_local size_t fileBufferSize_;
private:
    std::shared_ptr<OHOS::Media::IncrementalPixelMap> navIncPixelMap_;
    bool isRelease = false;
};
} // namespace ANI::Image

#endif // FRAMEWORKS_KITS_TAIHE_INCLUDE_IMAGE_SOURCE_TAIHE_H