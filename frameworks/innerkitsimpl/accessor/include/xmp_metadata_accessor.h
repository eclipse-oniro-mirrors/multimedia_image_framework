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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_METADATA_ACCESSOR_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_METADATA_ACCESSOR_H

#include <cstdint>
#include <memory>

#include "xmp_metadata.h"

namespace OHOS {
namespace Media {

enum class XMPAccessMode {
    READ_ONLY_XMP,
    READ_WRITE_XMP,
};

class XMPMetadataAccessor {
public:
    virtual ~XMPMetadataAccessor() = default;

    virtual uint32_t Read() = 0;
    virtual uint32_t Write() = 0;
    virtual std::shared_ptr<XMPMetadata> Get();
    virtual void Set(std::shared_ptr<XMPMetadata> &xmpMetadata);

    enum class IOType : uint8_t {
        UNKNOWN,
        XMP_FILE_PATH,
        XMP_BUFFER_IO,
        XMP_FD_IO,
    };

protected:
    std::shared_ptr<XMPMetadata> xmpMetadata_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_METADATA_ACCESSOR_H
