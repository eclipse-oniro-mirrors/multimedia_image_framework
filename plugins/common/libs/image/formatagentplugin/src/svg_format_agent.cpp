/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "svg_format_agent.h"
#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "log_tags.h"
#include "plugin_service.h"
#include "sched.h"
#include "string"

namespace OHOS {
namespace ImagePlugin {
using namespace OHOS::HiviewDFX;
using namespace MultimediaPlugin;

namespace {
static const std::string FORMAT_TYPE = "image/svg+xml";
static const char SVG_STAMP[] = "<?xml";
static constexpr uint8_t SVG_STAMP_LEN = 5;
static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_PLUGIN, "SvgFormatAgent" };
}

std::string SvgFormatAgent::GetFormatType()
{
    return FORMAT_TYPE;
}

uint32_t SvgFormatAgent::GetHeaderSize()
{
    return SVG_STAMP_LEN;
}

bool SvgFormatAgent::CheckFormat(const void *headerData, uint32_t dataSize)
{
    if (headerData == nullptr) {
        HiLog::Error(LABEL, "check format failed: header data is null.");
        return false;
    }

    if (dataSize < SVG_STAMP_LEN) {
        HiLog::Error(LABEL, "read head size:[%{public}u] less than header size:[%{public}u].", dataSize, SVG_STAMP_LEN);
        return false;
    }

    if (memcmp(SVG_STAMP, headerData, SVG_STAMP_LEN) != 0) {
        HiLog::Error(LABEL, "header stamp mismatch.");
        return false;
    }

    return true;
}
} // namespace ImagePlugin
} // namespace OHOS