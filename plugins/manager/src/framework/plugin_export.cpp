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

#include "plugin_export.h"
#include "bmp_decoder.h"
#include "bmp_format_agent.h"
#include "gif_decoder.h"
#include "gif_format_agent.h"
#include "image_log.h"
#include "iosfwd"
#include "jpeg_decoder.h"
#include "jpeg_encoder.h"
#include "jpeg_format_agent.h"
#include "map"
#include "plugin_class_base.h"
#include "plugin_utils.h"
#include "png_decoder.h"
#include "png_format_agent.h"
#include "raw_decoder.h"
#include "raw_format_agent.h"
#include "string"
#include "svg_decoder.h"
#include "svg_format_agent.h"
#include "utility"
#include "wbmp_format_agent.h"
#include "webp_decoder.h"
#include "webp_encoder.h"
#include "webp_format_agent.h"
#include "ext_decoder.h"
#include "ext_encoder.h"
#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN
#undef LOG_TAG
#define LOG_TAG "BmpFormatAgent"

namespace {
    const std::string PACKAGE_NAME = ("LibImagePluginsExport");
}

// register implement classes of this plugin.
PLUGIN_EXPORT_REGISTER_CLASS_BEGIN
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::BmpDecoder)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::BmpFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::JpegDecoder)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::JpegEncoder)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::JpegFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::PngDecoder)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::PngFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::GifDecoder)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::GifFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::WebpDecoder)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::WebpEncoder)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::WebpFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::WbmpFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::RawDecoder)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::RawFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::SvgDecoder)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::SvgFormatAgent)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::ExtDecoder)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::ImagePlugin::ExtEncoder)
PLUGIN_EXPORT_REGISTER_CLASS_END

using std::string;

// define the external interface of this plugin.
PLUGIN_EXPORT_DEFAULT_EXTERNAL_START()
PLUGIN_EXPORT_DEFAULT_EXTERNAL_STOP()
OHOS::MultimediaPlugin::PluginClassBase *PluginExternalCreate(const string &className)
{
    IMAGE_LOGD("LibImagePluginsExport: create object for package: %{public}s, class: %{public}s.",
        PACKAGE_NAME.c_str(), className.c_str());

    auto iter = implClassMap.find(className);
    if (iter == implClassMap.end()) {
        IMAGE_LOGE("LibImagePluginsExport: failed to find class: %{public}s, in package: %{public}s.",
            className.c_str(), PACKAGE_NAME.c_str());
        return nullptr;
    }

    auto creator = iter->second;
    if (creator == nullptr) {
        IMAGE_LOGE("LibImagePluginsExport: null creator for class: %{public}s, in package: %{public}s.",
            className.c_str(), PACKAGE_NAME.c_str());
        return nullptr;
    }

    return creator();
}