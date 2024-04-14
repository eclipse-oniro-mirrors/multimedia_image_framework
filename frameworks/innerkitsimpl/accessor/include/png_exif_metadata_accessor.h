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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_PNG_EXIF_METADATA_ACCESSOR_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_PNG_EXIF_METADATA_ACCESSOR_H

#include "abstract_exif_metadata_accessor.h"
#include "buffer_metadata_stream.h"

namespace OHOS {
namespace Media {
static unsigned char pngSignature[] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
};

class PngExifMetadataAccessor : public AbstractExifMetadataAccessor {
public:
    PngExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream);
    ~PngExifMetadataAccessor();

    virtual uint32_t Read() override;
    virtual uint32_t Write() override;
    bool ReadBlob(DataBuf &blob) const override;
    uint32_t WriteBlob(DataBuf &blob) override;

private:
    bool IsPngType() const;
    bool FindTiffFromText(const DataBuf &data, const std::string chunkType, DataBuf &tiffData) const;
    bool ProcessExifData(DataBuf &blob, std::string chunkType, uint32_t chunkLength) const;
    bool GetExifEncodedBlob(uint8_t **dataBlob, uint32_t &size);
    bool UpdateExifMetadata(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size);
    bool WriteData(BufferMetadataStream &bufStream, uint8_t *data, uint32_t size);
    bool WriteExifData(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size,
                       DataBuf &chunkBuf, std::string chunkType);
    ssize_t ReadChunk(DataBuf &buffer) const;
    uint32_t UpdateData(uint8_t *dataBlob, uint32_t size);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_PNG_EXIF_METADATA_ACCESSOR_H
