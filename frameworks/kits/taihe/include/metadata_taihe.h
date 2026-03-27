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

#ifndef FRAMEWORKS_KITS_TAIHE_INCLUDE_METADATA_TAIHE_H
#define FRAMEWORKS_KITS_TAIHE_INCLUDE_METADATA_TAIHE_H

#include "exif_metadata.h"
#include "heifs_metadata.h"
#include "metadata.h"
#include "ohos.multimedia.image.image.proj.hpp"
#include "ohos.multimedia.image.image.impl.hpp"
#include "taihe/runtime.hpp"
#include "webp_metadata.h"

namespace ANI::Image {
using namespace taihe;
using namespace ohos::multimedia::image::image;

class MetadataImpl {
public:
    MetadataImpl();
    explicit MetadataImpl(std::shared_ptr<OHOS::Media::ImageMetadata> imageMetadata);
    virtual ~MetadataImpl();
    
    int64_t GetImplPtr();
    std::shared_ptr<OHOS::Media::ImageMetadata> GetNativeMetadata();

    map<string, PropertyValue> GetPropertiesSync(array_view<string> key);
    void SetPropertiesSync(map_view<string, PropertyValue> records);
    optional<map<string, PropertyValue>> GetAllPropertiesSync();
    optional<Metadata> CloneMetadata();
    array<uint8_t> GetBlob();
    void SetBlob(array_view<uint8_t> blob);

    void Release();

protected:
    virtual OHOS::Media::ImageMetadata::PropertyMapPtr GetAllPropertiesInternal();

    std::shared_ptr<OHOS::Media::ImageMetadata> nativeMetadata_ = nullptr;
    bool isRelease = false;
};

class ExifMetadataImpl : public MetadataImpl {
public:
    ExifMetadataImpl();
    explicit ExifMetadataImpl(std::shared_ptr<OHOS::Media::ExifMetadata> metadata);
    ~ExifMetadataImpl();

    ExifMetadata CloneExifMetadata();

protected:
    OHOS::Media::ImageMetadata::PropertyMapPtr GetAllPropertiesInternal() override;
};

class MakerNoteHuaweiMetadataImpl : public MetadataImpl {
public:
    MakerNoteHuaweiMetadataImpl();
    explicit MakerNoteHuaweiMetadataImpl(std::shared_ptr<OHOS::Media::ExifMetadata> metadata);
    ~MakerNoteHuaweiMetadataImpl();

    MakerNoteHuaweiMetadata CloneMakerNoteHuaweiMetadata();

protected:
    OHOS::Media::ImageMetadata::PropertyMapPtr GetAllPropertiesInternal() override;
};

class HeifsMetadataImpl : public MetadataImpl {
public:
    HeifsMetadataImpl();
    explicit HeifsMetadataImpl(std::shared_ptr<OHOS::Media::HeifsMetadata> metadata);
    ~HeifsMetadataImpl();

    HeifsMetadata CloneHeifsMetadata();
};

class DngMetadataImpl : public MetadataImpl {
public:
    DngMetadataImpl();
    ~DngMetadataImpl();
};

class WebPMetadataImpl : public MetadataImpl {
public:
    WebPMetadataImpl();
    explicit WebPMetadataImpl(std::shared_ptr<OHOS::Media::WebPMetadata> metadata);
    ~WebPMetadataImpl();
};
} // namespace ANI::Image

#endif // FRAMEWORKS_KITS_TAIHE_INCLUDE_METADATA_TAIHE_H