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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_METADATA_ACCESSOR_FACTORY_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_METADATA_ACCESSOR_FACTORY_H

#include <memory>
#include <string>

#include "buffer_metadata_stream.h"
#include "image_type.h"
#include "metadata_accessor.h"
#include "metadata_stream.h"

namespace OHOS {
namespace Media {
class MetadataAccessorFactory {
public:
    static std::shared_ptr<MetadataAccessor> Create(uint8_t *buffer, const uint32_t size,
        BufferMetadataStream::MemoryMode mode = BufferMetadataStream::Fix);
    static std::shared_ptr<MetadataAccessor> Create(const int fd);
    static std::shared_ptr<MetadataAccessor> Create(const std::string &path);

private:
    static std::shared_ptr<MetadataAccessor> Create(std::shared_ptr<MetadataStream> &stream);
    static EncodedFormat GetImageType(std::shared_ptr<MetadataStream> &stream);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_METADATA_ACCESSOR_FACTORY_H
