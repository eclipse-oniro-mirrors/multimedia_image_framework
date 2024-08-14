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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_ABSTRACT_EXIF_METADATA_ACCESSOR_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_ABSTRACT_EXIF_METADATA_ACCESSOR_H

#include "image_log.h"
#include "exif_metadata.h"
#include "media_errors.h"
#include "metadata_accessor.h"

namespace OHOS {
namespace Media {
class AbstractExifMetadataAccessor : public MetadataAccessor {
public:
    AbstractExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream);
    virtual ~AbstractExifMetadataAccessor();

    virtual bool Create() override;
    virtual std::shared_ptr<ExifMetadata> Get() override;
    virtual void Set(std::shared_ptr<ExifMetadata> &ptr) override;
    virtual bool WriteToOutput(SkWStream &output) override;
    virtual std::shared_ptr<MetadataStream> GetOutputStream() override;
    virtual uint32_t GetFilterArea(const std::vector<std::string> &exifKeys,
                                   std::vector<std::pair<uint32_t, uint32_t>> &ranges) override;
    virtual long GetTiffOffset()
    {
        return tiffOffset_;
    }

protected:
    std::shared_ptr<ExifMetadata> exifMetadata_ = nullptr;
    std::shared_ptr<MetadataStream> imageStream_ = nullptr;
    long tiffOffset_ = 0;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_ABSTRACT_EXIF_METADATA_ACCESSOR_H
