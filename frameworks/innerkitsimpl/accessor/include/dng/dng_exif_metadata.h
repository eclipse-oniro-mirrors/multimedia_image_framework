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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_DNG_DNG_EXIF_METADATA_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_DNG_DNG_EXIF_METADATA_H

#include "dng/dng_sdk_helper.h"
#include "exif_metadata.h"

namespace OHOS {
namespace Media {
class DngExifMetadata : public ExifMetadata {
public:
    DngExifMetadata();
    DngExifMetadata(ExifData* exifData, std::unique_ptr<DngSdkInfo>& dngSdkInfo);
    virtual ~DngExifMetadata();
    virtual int GetValue(const std::string& key, std::string& value) const override;
    virtual bool SetValue(const std::string& key, const std::string& value) override;
    virtual bool RemoveEntry(const std::string& key) override;
    virtual std::shared_ptr<ImageMetadata> CloneMetadata() override;
    NATIVEEXPORT std::shared_ptr<DngExifMetadata> Clone();
    bool Marshalling(Parcel& parcel) const override;
    uint32_t GetExifProperty(MetadataValue& value);
    std::vector<MetadataValue> GetAllDngProperties();

private:
    std::unique_ptr<DngSdkInfo> dngSdkInfo_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_DNG_DNG_EXIF_METADATA_H
