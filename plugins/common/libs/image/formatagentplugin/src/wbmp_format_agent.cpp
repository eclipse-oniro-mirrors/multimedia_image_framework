/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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


#include "wbmp_format_agent.h"

#include "image_log.h"
#include "image_plugin_type.h"
#include "plugin_service.h"
#include "string"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "WbmpFormatAgent"

namespace OHOS {
namespace ImagePlugin {
using namespace ImagePlugin;
using namespace MultimediaPlugin;

const std::string FORMAT_TYPE = "image/vnd.wap.wbmp";
constexpr uint32_t HEADER_SIZE = 32;
constexpr uint8_t SHIF_BIT_MASK = 7;
constexpr uint8_t LOW_BIT_MASK = 0x7F;
constexpr uint8_t HIGH_BIT_MASK = 0x80;

bool WbmpFormatAgent::read_byte(uint8_t *stream, uint8_t &value, uint32_t &offset, uint32_t dataSize)
{
    if (stream == nullptr) {
        IMAGE_LOGE("read_byte: stream is nullptr");
        return false;
    }
    if (offset >= dataSize) {
        IMAGE_LOGE("read_header data offset %{public}u. dataSize %{public}u", offset, dataSize);
        return false;
    }
    value = *(stream + offset);
    offset++;
    return true;
}

bool WbmpFormatAgent::read_mbf(uint8_t *stream, uint64_t &value, uint32_t &offset, uint32_t dataSize)
{
    uint64_t n = 0;
    uint8_t data;
    const uint64_t kLimit = 0xFE00000000000000;
    do {
        if (n & kLimit) { // Will overflow on shift by 7.
            return false;
        }
        if (!read_byte(stream, data, offset, dataSize)) {
            return false;
        }
        n = (n << SHIF_BIT_MASK) | (data & LOW_BIT_MASK);
    } while (data & HIGH_BIT_MASK);
    value = n;
    return true;
}

bool WbmpFormatAgent::read_header(const void *stream, uint32_t dataSize)
{
    uint8_t data;
    uint8_t *pData = static_cast<uint8_t *>(const_cast<void *>(stream));
    uint32_t offset = 0;

    if (!read_byte(pData, data, offset, dataSize) || data != 0) { // unknown type
        return false;
    }
    IMAGE_LOGD("read_header data %{public}d.", data);

    if (!read_byte(pData, data, offset, dataSize) || (data & 0x9F)) { // skip fixed header
        return false;
    }
    IMAGE_LOGD("read_header data %{public}d.", data);

    uint64_t width;
    uint64_t height;
    if (!read_mbf(pData, width, offset, dataSize) || width > 0xFFFF || !width) {
        return false;
    }
    IMAGE_LOGD("read_header width %{public}lld.", static_cast<long long>(width));

    bool cond = !read_mbf(pData, height, offset, dataSize) || height > 0xFFFF || !height;
    CHECK_ERROR_RETURN_RET(cond, false);
    IMAGE_LOGD("read_header height %{public}lld.", static_cast<long long>(height));

    return true;
}


std::string WbmpFormatAgent::GetFormatType()
{
    return FORMAT_TYPE;
}

uint32_t WbmpFormatAgent::GetHeaderSize()
{
    return HEADER_SIZE;
}

bool WbmpFormatAgent::CheckFormat(const void *headerData, uint32_t dataSize)
{
    if (headerData == nullptr) {
        IMAGE_LOGE("check format failed: header data is null.");
        return false;
    }

    if (!read_header(headerData, dataSize)) {
        IMAGE_LOGD("not wbmp image format.");
        return false;
    }

    IMAGE_LOGD("wbmp image format ok.");
    return true;
}
} // namespace ImagePlugin
} // namespace OHOS
