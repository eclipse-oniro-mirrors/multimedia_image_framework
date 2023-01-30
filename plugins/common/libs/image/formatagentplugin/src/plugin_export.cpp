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

#include "plugin_export.h"
#include "bmp_format_agent.h"
#include "gif_format_agent.h"
#include "heif_format_agent.h"
#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "iosfwd"
#include "jpeg_format_agent.h"
#include "log_tags.h"
#include "map"
#include "plugin_class_base.h"
#include "plugin_utils.h"
#include "png_format_agent.h"
#include "raw_format_agent.h"
#include "svg_format_agent.h"
#include "string"
#include "utility"
#include "wbmp_format_agent.h"
#include "webp_format_agent.h"


// plugin package name same as metadata.
namespace {
    const std::string PACKAGE_NAME = ("LibImageFormatAgent");
}

// register implement classes of this plugin.
PLUGIN_EXPORT_REGISTER_CLASS_BEGIN
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::JpegFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::PngFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::GifFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::HeifFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::WebpFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::BmpFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::RawFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::SvgFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::WbmpFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS_END

using std::string;
using namespace OHOS::HiviewDFX;

static constexpr HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_PLUGIN, "LibImageFormatAgent" };

#define PLUGIN_LOG_D(...) HiLog::Debug(LABEL, __VA_ARGS__)
#define PLUGIN_LOG_E(...) HiLog::Error(LABEL, __VA_ARGS__)

// define the external interface of this plugin.
PLUGIN_EXPORT_DEFAULT_EXTERNAL_START()
PLUGIN_EXPORT_DEFAULT_EXTERNAL_STOP()
OHOS::MultimediaPlugin::PluginClassBase *PluginExternalCreate(const string &className)
{
    HiLog::Debug(LABEL, "PluginExternalCreate: create object for package: %{public}s, class: %{public}s.",
                 PACKAGE_NAME.c_str(), className.c_str());

    auto iter = implClassMap.find(className);
    if (iter == implClassMap.end()) {
        HiLog::Error(LABEL, "PluginExternalCreate: failed to find class: %{public}s, in package: %{public}s.",
                     className.c_str(), PACKAGE_NAME.c_str());
        return nullptr;
    }

    auto creator = iter->second;
    if (creator == nullptr) {
        HiLog::Error(LABEL, "PluginExternalCreate: null creator for class: %{public}s, in package: %{public}s.",
                     className.c_str(), PACKAGE_NAME.c_str());
        return nullptr;
    }

    return creator();
}
