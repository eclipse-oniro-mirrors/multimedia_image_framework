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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HDR_HDR_HELPER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HDR_HDR_HELPER_H


#include "include/codec/SkCodec.h"
#include "hdr_type.h"

namespace OHOS {
namespace Media {
class HdrHelper {
public:
    static HdrType CheckHdrType(SkCodec* codec, uint32_t& offset);
    static bool GetMetadata(SkCodec* codec, HdrType type, HdrMetadata& metadata);
    static std::vector<uint8_t> PackJpegVividBaseInfo(uint32_t offset, uint32_t gainMapSize);
    static std::vector<uint8_t> PackJpegVividMetadata(HdrMetadata metadata);
};
} // namespace Media
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HDR_HDR_HELPER_H