/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hwe_checkPara.h"
constexpr int32_t LOG_SHUT_OFF_MASK = 0x00000080;
namespace OHOS {
namespace ImagePlugin {
static void LogDefault(const int8_t *fileName, uint32_t line, LogLevel eLevel,
    const int8_t *pszFmt, va_list arg)
{
    if (!fileName) {
        HWE_LOGE("LogDefault fileName is nullptr");
    }
    const char *levelMsg = nullptr;
    switch (eLevel) {
        case LOG_ERROR:
            levelMsg = "TextureEncode error";
            break;
        case LOG_WARN:
            levelMsg = "TextureEncode warning";
            break;
        case LOG_INFO:
            levelMsg = "TextureEncode info";
            break;
        case LOG_DEBUG:
            levelMsg = "TextureEncode debug";
            break;
        default:
            levelMsg = "TextureEncode unknown";
            break;
    }
    int32_t ret = fprintf(stderr, "[%s\t]: %s %u: ", levelMsg, fileName, line);
    if (ret < 0) {
        return;
    }
    ret = vfprintf(stderr, const_cast<const char *>(pszFmt), arg);
    if (ret < 0) {
        return;
    }
}

bool CheckValidParam(const TextureEncodeOptions *encodeParams)
{
    if (encodeParams) {
        return true;
    }
    return false;
}
} // namespace ImagePlugin
} // namespace OHOS