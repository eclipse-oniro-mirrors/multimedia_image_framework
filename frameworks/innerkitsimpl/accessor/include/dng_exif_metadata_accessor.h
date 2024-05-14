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
#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_DNG_EXIF_METADATA_ACCESSOR_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_DNG_EXIF_METADATA_ACCESSOR_H

#include "abstract_exif_metadata_accessor.h"
#include "buffer_metadata_stream.h"
#include "data_buf.h"
#include "metadata_stream.h"

namespace OHOS {
namespace Media {
class DngExifMetadataAccessor : public AbstractExifMetadataAccessor {
public:
    DngExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream);
    ~DngExifMetadataAccessor();

    virtual uint32_t Read() override;
    bool ReadBlob(DataBuf &blob) const override;
    virtual uint32_t Write() override;
    uint32_t WriteBlob(DataBuf &blob) override;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_DNG_EXIF_METADATA_ACCESSOR_H