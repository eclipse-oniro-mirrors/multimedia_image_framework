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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_CONSTANT_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_CONSTANT_H

namespace OHOS {
namespace ImagePlugin {
const uint8_t ONE_BYTE_SHIFT = 8;
const uint8_t TWO_BYTES_SHIFT = 16;
const uint8_t THREE_BYTES_SHIFT = 24;
const uint8_t FOUR_BYTES_SHIFT = 32;
const uint8_t FIVE_BYTES_SHIFT = 40;
const uint8_t SIX_BYTES_SHIFT = 48;
const uint8_t SEVEN_BYTES_SHIFT = 56;

const uint8_t UINT8_BYTES_NUM = 1;
const uint8_t UINT16_BYTES_NUM = 2;
const uint8_t UINT32_BYTES_NUM = 4;
const uint8_t UINT64_BYTES_NUM = 8;

const uint8_t BUFFER_INDEX_ZERO = 0;
const uint8_t BUFFER_INDEX_ONE = 1;
const uint8_t BUFFER_INDEX_TWO = 2;
const uint8_t BUFFER_INDEX_THREE = 3;
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_CONSTANT_H
