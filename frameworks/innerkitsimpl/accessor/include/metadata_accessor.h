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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_METADATA_ACCESSOR_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_METADATA_ACCESSOR_H

#include <memory>

#include "data_buf.h"
#include "exif_metadata.h"
#include "metadata_stream.h"
#include "ext_wstream.h"

namespace OHOS {
namespace Media {
class MetadataAccessor {
public:
    virtual uint32_t Read() = 0;
    virtual uint32_t Write() = 0;
    virtual bool Create() = 0;
    virtual uint32_t WriteBlob(DataBuf &blob) = 0;
    virtual bool ReadBlob(DataBuf &blob) const = 0;
    virtual bool WriteToOutput(SkWStream &output) = 0;
    virtual std::shared_ptr<MetadataStream> GetOutputStream() = 0;
    virtual std::shared_ptr<ExifMetadata> Get() = 0;
    virtual void Set(std::shared_ptr<ExifMetadata> &ptr) = 0;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_METADATA_ACCESSOR_H
