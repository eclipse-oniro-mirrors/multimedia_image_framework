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

#ifndef FRAMEWORKS_INNERKITSIMPL_HDR_INCLUDE_XMP_PARSER_H
#define FRAMEWORKS_INNERKITSIMPL_HDR_INCLUDE_XMP_PARSER_H

#include <vector>
#include "hdr_type.h"
#include "src/xml/SkDOM.h"

namespace OHOS {
namespace Media {

class XmpParser {
public:
    bool ParseBaseImageXmp(const uint8_t* data, uint32_t size, uint8_t& gainMapIndex);
    bool ParseGainMapMetadata(const uint8_t* data, uint32_t size, IsoMetadata& metadata);
private:
    bool BuildDom(const uint8_t* data, uint32_t size);
    uint8_t GetGainMapIndex(const SkDOMNode* element, std::string& containerPrefix, std::string& itemPrefix);
    SkDOM xmpDom_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_HDR_INCLUDE_HDR_TYPE_H