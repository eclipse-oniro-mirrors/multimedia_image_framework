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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_UTILS_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_UTILS_H

#include <string>
#include "heif_constant.h"

namespace OHOS {
namespace ImagePlugin {
std::string code_to_fourcc(uint32_t code);

constexpr inline uint32_t fourcc_to_code(const char *string)
{
    return (string[BUFFER_INDEX_ZERO] << THREE_BYTES_SHIFT) |
           (string[BUFFER_INDEX_ONE] << TWO_BYTES_SHIFT) |
           (string[BUFFER_INDEX_TWO] << ONE_BYTE_SHIFT) |
           (string[BUFFER_INDEX_THREE]);
}
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_UTILS_H
