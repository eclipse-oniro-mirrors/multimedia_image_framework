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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_JPEG_EXIF_METADATA_ACCESSOR_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_JPEG_EXIF_METADATA_ACCESSOR_H

#include <tuple>

#include "abstract_exif_metadata_accessor.h"
#include "buffer_metadata_stream.h"
#include "data_buf.h"
#include "metadata_stream.h"

namespace OHOS {
namespace Media {
class JpegExifMetadataAccessor : public AbstractExifMetadataAccessor {
public:
    JpegExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream);
    ~JpegExifMetadataAccessor();

    virtual uint32_t Read() override;
    bool ReadBlob(DataBuf &blob) const override;
    virtual uint32_t Write() override;
    uint32_t WriteBlob(DataBuf &blob) override;

private:
    int FindNextMarker() const;
    std::pair<std::array<byte, 2>, uint16_t> ReadSegmentLength(uint8_t marker) const;
    DataBuf ReadNextSegment(byte marker);
    bool GetExifEncodeBlob(uint8_t **dataBlob, uint32_t &size);
    bool GetExifBlob(const DataBuf &blob, uint8_t **dataBlob, uint32_t &size);
    bool WriteHeader(BufferMetadataStream &tempStream);
    std::tuple<size_t, size_t> GetInsertPosAndMarkerAPP1();
    bool WriteSegment(BufferMetadataStream &bufStream, uint8_t marker, const DataBuf &buf);
    bool WriteTail(BufferMetadataStream &bufStream);
    bool CopyRestData(BufferMetadataStream &bufStream);
    bool WriteData(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size);
    bool UpdateExifMetadata(BufferMetadataStream &tempStream, uint8_t *dataBlob, uint32_t size);
    uint32_t UpdateData(uint8_t *dataBlob, uint32_t size);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_JPEG_EXIF_METADATA_ACCESSOR_H