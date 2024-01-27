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
#include "image_log.h"
#include "plugin_utils.h"
#include "cloud_label_detector3.h"
#include "label_detector3.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "plugin_example3"

// this file shows how to easily write the plugin_export.cpp file using the code elements provided by plugin_utils.h.
// but sometimes you may need to write this file directly, see plugin_example1.
namespace {
    const std::string PACKAGE_NAME = ("plugin_example3");
}

// register implement classes of this plugin.
PLUGIN_EXPORT_REGISTER_CLASS_BEGIN
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::PluginExample::LabelDetector3)
PLUGIN_EXPORT_REGISTER_CLASS(OHOS::PluginExample::CloudLabelDetector3)
PLUGIN_EXPORT_REGISTER_CLASS_END

using std::string;

// define the external interface of this plugin
PLUGIN_EXPORT_DEFAULT_EXTERNAL_START()
PLUGIN_EXPORT_DEFAULT_EXTERNAL_STOP()
OHOS::MultimediaPlugin::PluginClassBase *PluginExternalCreate(const string &className)
{
    IMAGE_LOGD("PluginExternalCreate: create object for package: %{public}s, class: %{public}s.",
        PACKAGE_NAME.c_str(), className.c_str());

    auto iter = implClassMap.find(className);
    if (iter == implClassMap.end()) {
        IMAGE_LOGE("PluginExternalCreate: failed to find class: %{public}s, in package: %{public}s.",
            className.c_str(), PACKAGE_NAME.c_str());
        return nullptr;
    }

    auto creator = iter->second;
    if (creator == nullptr) {
        IMAGE_LOGE("PluginExternalCreate: null creator for class: %{public}s, in package: %{public}s.",
            className.c_str(), PACKAGE_NAME.c_str());
        return nullptr;
    }

    return creator();
}

