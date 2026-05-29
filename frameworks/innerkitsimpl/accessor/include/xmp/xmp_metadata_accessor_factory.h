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

#ifndef FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_METADATA_ACCESSOR_FACTORY_H
#define FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_METADATA_ACCESSOR_FACTORY_H

#include <cstdint>
#include <memory>
#include <string>

#include "xmp_metadata_accessor.h"

namespace OHOS {
namespace Media {

class XMPMetadataAccessorFactory {
public:
    static std::unique_ptr<XMPMetadataAccessor> Create(const uint8_t *data, uint32_t size, XMPAccessMode mode,
        const std::string &mimeType);
    static std::unique_ptr<XMPMetadataAccessor> Create(const std::string &filePath, XMPAccessMode mode,
        const std::string &mimeType);
    static std::unique_ptr<XMPMetadataAccessor> Create(int32_t fileDescriptor, XMPAccessMode mode,
        const std::string &mimeType);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_ACCESSOR_INCLUDE_XMP_METADATA_ACCESSOR_FACTORY_H
