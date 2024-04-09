/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_WEBP_EXIF_METADATA_ACCESSOR_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_WEBP_EXIF_METADATA_ACCESSOR_H


#include <tuple>

#include "abstract_exif_metadata_accessor.h"
#include "buffer_metadata_stream.h"
#include "data_buf.h"
#include "metadata_stream.h"
#include "securec.h"

namespace OHOS {
namespace Media {
enum class Vp8xAndExifInfo : int32_t {
    UNKNOWN = 0,
    VP8X_NOT_EXIST = 1,
    EXIF_NOT_EXIST = 2,
    EXIF_EXIST = 3
};

class WebpExifMetadataAccessor : public AbstractExifMetadataAccessor {
public:
    WebpExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream);
    ~WebpExifMetadataAccessor();

    virtual uint32_t Read() override;
    bool ReadBlob(DataBuf &blob) const override;
    virtual uint32_t Write() override;
    uint32_t WriteBlob(DataBuf &blob) override;

private:
    bool CheckChunkVp8x(Vp8xAndExifInfo &exifFlag) const;
    bool GetExifBlob(const DataBuf &blob, uint8_t **dataBlob, uint32_t &size);
    uint32_t UpdateData(uint8_t *dataBlob, uint32_t size);
    bool UpdateExifMetadata(BufferMetadataStream &tempStream, uint8_t *dataBlob, uint32_t size);
    bool GetExifEncodeBlob(uint8_t **dataBlob, uint32_t &size);
    bool WriteHeader(BufferMetadataStream &bufStream, uint32_t size, Vp8xAndExifInfo &exifFlag);
    bool WirteChunkVp8x(BufferMetadataStream &bufStream, const Vp8xAndExifInfo &exifFlag);
    bool CopyRestData(BufferMetadataStream &bufStream);
    bool InsertExifMetadata(BufferMetadataStream &bufStream, uint8_t *dataBlob, uint32_t size);
    std::tuple<uint32_t, uint32_t> GetImageWidthAndHeight();
    std::tuple<uint32_t, uint32_t> GetWidthAndHeightFormChunk(const std::string &strChunkId, const DataBuf &chunkData);
};
} // namespace Media
} // namespace OHOS

#endif
