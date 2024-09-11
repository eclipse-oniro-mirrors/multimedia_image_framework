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

#include "bmp_format_agent.h"

#include "image_log.h"
#include "plugin_service.h"
#include "sched.h"
#include "string"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "BmpFormatAgent"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;
namespace {
const std::string FORMAT_TYPE = "image/bmp";
constexpr uint8_t BMP_HEADER[] = { 0x42, 0x4D };
} // namespace

std::string BmpFormatAgent::GetFormatType()
{
    return FORMAT_TYPE;
}

uint32_t BmpFormatAgent::GetHeaderSize()
{
    return sizeof(BMP_HEADER);
}

bool BmpFormatAgent::CheckFormat(const void *headerData, uint32_t dataSize)
{
    if (headerData == nullptr) {
        IMAGE_LOGE("check format failed: header data is null.");
        return false;
    }
    uint32_t headerSize = sizeof(BMP_HEADER);
    if (dataSize < headerSize) {
        IMAGE_LOGE("read head size:[%{public}u] less than header size:[%{public}u].", dataSize, headerSize);
        return false;
    }

    if (memcmp(headerData, BMP_HEADER, headerSize) != 0) {
        IMAGE_LOGD("header stamp mismatch.");
        return false;
    }
    return true;
}
} // namespace ImagePlugin
} // namespace OHOS
