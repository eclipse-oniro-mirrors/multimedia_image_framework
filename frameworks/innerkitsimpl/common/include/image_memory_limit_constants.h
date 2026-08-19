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

#ifndef FRAMEWORKS_INNERKITSIMPL_COMMON_INCLUDE_IMAGE_MEMORY_LIMIT_CONSTANTS_H
#define FRAMEWORKS_INNERKITSIMPL_COMMON_INCLUDE_IMAGE_MEMORY_LIMIT_CONSTANTS_H

namespace OHOS {
namespace Media {
/**
 * @brief Maximum allowed size (in bytes) for an input stream passed to
 *        ImageSource::DoImageSourceCreate (istream / file path / fd / fd+offset).
 *
 * When the stream total length exceeds this limit, DoImageSourceCreate returns
 * ERR_IMAGE_TOO_LARGE and no ImageSource is created.  BufferSourceStream is
 * excluded from this check because CreateImageSource(data, size) already
 * enforces its own MAX_SOURCE_SIZE (300 MB) before calling DoImageSourceCreate.
 *
 * Value: 1 GB.  Aligned with IncrementalSourceStream::MAX_SOURCE_SIZE and
 * IstreamSourceStream::GetData which rejects single reads larger than
 * MALLOC_MAX_LENTH (1 GB).  This constant guards the *overall* stream length
 * before any incremental read takes place.
 */
constexpr size_t MAX_INPUT_STREAM_SIZE = 1 * 1024 * 1024 * 1024;
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_COMMON_INCLUDE_IMAGE_MEMORY_LIMIT_CONSTANTS_H
