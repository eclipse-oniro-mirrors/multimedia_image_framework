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

#include "gif_format_agent.h"

#include "image_log.h"
#include "plugin_service.h"
#include "sched.h"
#include "string"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "GifFormatAgent"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;

static const std::string FORMAT_TYPE = "image/gif";
static const char GIF87_STAMP[] = "GIF87a";
static const char GIF89_STAMP[] = "GIF89a";
static const uint8_t GIF_STAMP_LEN = 6;

std::string GifFormatAgent::GetFormatType()
{
    return FORMAT_TYPE;
}

uint32_t GifFormatAgent::GetHeaderSize()
{
    return GIF_STAMP_LEN;
}

bool GifFormatAgent::CheckFormat(const void *headerData, uint32_t dataSize)
{
    if (headerData == nullptr) {
        IMAGE_LOGE("check format failed: header data is null.");
        return false;
    }

    if (dataSize < GIF_STAMP_LEN) {
        IMAGE_LOGE("read head size:[%{public}u] less than header size:[%{public}u].", dataSize, GIF_STAMP_LEN);
        return false;
    }

    if (memcmp(GIF87_STAMP, headerData, GIF_STAMP_LEN) != 0 && memcmp(GIF89_STAMP, headerData, GIF_STAMP_LEN) != 0) {
        IMAGE_LOGI("header stamp mismatch.");
        return false;
    }
    return true;
}
} // namespace ImagePlugin
} // namespace OHOS
