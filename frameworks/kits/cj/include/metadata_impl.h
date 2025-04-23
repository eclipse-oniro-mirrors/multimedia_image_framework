/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CJ_INCLUDE_METADATA_IMPL_H
#define CJ_INCLUDE_METADATA_IMPL_H

#include <memory>
#include <vector>

#include "ffi_remote_data.h"
#include "metadata.h"

namespace OHOS {
namespace Media {
class MetadataImpl : public OHOS::FFI::FFIData {
    DECL_TYPE(MetadataImpl, OHOS::FFI::FFIData)
public:
    explicit MetadataImpl(std::shared_ptr<ImageMetadata> metadata);
    ~MetadataImpl();
    std::vector<std::pair<std::string, std::string>> GetAllProperties(uint32_t* errCode);
    std::shared_ptr<ImageMetadata> GetNativeMetadata()
    {
        return nativeMetadata_;
    }

private:
    void release();
    std::shared_ptr<ImageMetadata> nativeMetadata_;
    bool isRelease = false;
    uint32_t uniqueId_ = 0;
};
} // namespace Media
} // namespace OHOS
#endif // CJ_INCLUDE_METADATA_IMPL_H