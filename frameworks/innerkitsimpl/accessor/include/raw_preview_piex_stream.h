/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_RAW_PREVIEW_PIEX_STREAM_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_RAW_PREVIEW_PIEX_STREAM_H

#include <limits>

#include "metadata_stream.h"
#include "src/piex.h"

namespace OHOS {
namespace Media {
// PIEX performs random reads on the metadata stream. This adapter bounds every read and
// restores the stream cursor on all paths so the caller's parsing state is never changed.
class RawPreviewPiexStream final : public piex::StreamInterface {
public:
    explicit RawPreviewPiexStream(MetadataStream &stream) : stream_(stream) {}

    piex::Error GetData(const size_t offset, const size_t length, uint8_t *data) override
    {
        ssize_t size = stream_.GetSize();
        if (data == nullptr || size < 0 || offset > static_cast<size_t>(size) ||
            length > static_cast<size_t>(size) - offset ||
            offset > static_cast<size_t>(std::numeric_limits<long>::max()) ||
            length > static_cast<size_t>(std::numeric_limits<long>::max()) || stream_.IsFileSizeChanged()) {
            return piex::kFail;
        }
        if (length == 0) {
            return piex::kOk;
        }
        long position = stream_.Tell();
        if (position < 0) {
            return piex::kFail;
        }
        bool seekOk = stream_.Seek(static_cast<long>(offset), SeekPos::BEGIN) == static_cast<long>(offset);
        ssize_t readSize = seekOk ? stream_.Read(data, static_cast<ssize_t>(length)) : -1;
        bool restored = stream_.Seek(position, SeekPos::BEGIN) == position;
        return restored && readSize == static_cast<ssize_t>(length) ? piex::kOk : piex::kFail;
    }

private:
    MetadataStream &stream_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_RAW_PREVIEW_PIEX_STREAM_H
