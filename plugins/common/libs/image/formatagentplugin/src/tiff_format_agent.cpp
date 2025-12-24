/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "tiff_format_agent.h"

#include "image_log.h"
#include "plugin_service.h"
#include "sched.h"
#include "securec.h"
#include "string"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "TiffFormatAgent"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;

static const std::string FORMAT_TYPE = "image/tiff";
static constexpr uint8_t TIFF_HEAD_SIZE = 8;
constexpr auto TIFF_BYTEORDER_SIZE = 4;
static const std::array<uint8_t, TIFF_BYTEORDER_SIZE> tiffByteOrderII { 0x49, 0x49, 0x2a, 0x00 };
static const std::array<uint8_t, TIFF_BYTEORDER_SIZE> tiffByteOrderMM { 0x4d, 0x4d, 0x00, 0x2a };

std::string TiffFormatAgent::GetFormatType() { return FORMAT_TYPE; }

uint32_t TiffFormatAgent::GetHeaderSize() { return TIFF_HEAD_SIZE; }

// tiff header is order(2B) + version(2B)=42 + offset(4B)
bool TiffFormatAgent::CheckFormat(const void* headerData, uint32_t dataSize)
{
    if (headerData == nullptr) {
        IMAGE_LOGE("check format failed: header data is null.");
        return false;
    }

    if (dataSize < TIFF_HEAD_SIZE) {
        IMAGE_LOGE("read head size:[%{public}u] less than header size:[%{public}u].", dataSize, TIFF_HEAD_SIZE);
        return false;
    }
    uint8_t tmpBuff[TIFF_HEAD_SIZE];
    if (memcpy_s(tmpBuff, TIFF_HEAD_SIZE, headerData, dataSize) != 0) {
        IMAGE_LOGE("memcpy headerData data size:[%{public}d] error.", dataSize);
        return false;
    }

    if (memcmp(tmpBuff, tiffByteOrderII.data(), tiffByteOrderII.size()) == 0 ||
        memcmp(tmpBuff, tiffByteOrderMM.data(), tiffByteOrderMM.size()) == 0) {
        return true;
    }
    return false;
}

} // namespace ImagePlugin
} // namespace OHOS