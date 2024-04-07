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

#include "heif_utils.h"

namespace OHOS {
namespace ImagePlugin {
std::string code_to_fourcc(uint32_t code)
{
    std::string fourcc = "    ";
    fourcc[BUFFER_INDEX_ZERO] = static_cast<char>((code >> THREE_BYTES_SHIFT) & 0xFF);
    fourcc[BUFFER_INDEX_ONE] = static_cast<char>((code >> TWO_BYTES_SHIFT) & 0xFF);
    fourcc[BUFFER_INDEX_TWO] = static_cast<char>((code >> ONE_BYTE_SHIFT) & 0xFF);
    fourcc[BUFFER_INDEX_THREE] = static_cast<char>(code & 0xFF);
    return fourcc;
}
} // namespace ImagePlugin
} // namespace OHOS
