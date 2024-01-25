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

#include "plugin_server.h"
#include "gst_plugin_fw.h"
#include "image_log.h"
#include "map"
#include "new"
#include "platform_adp.h"
#include "plugin_common_type.h"
#include "plugin_errors.h"
#include "plugin_fw.h"
#include "singleton.h"
#include "string"
#include "type_traits"
#include "vector"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "PluginServer"

namespace OHOS {
namespace MultimediaPlugin {
using std::map;
using std::string;
using std::vector;

uint32_t PluginServer::Register(vector<string> &&pluginPaths)
{
    if (pluginPaths.empty()) {
        return pluginFw_.Register(pluginPaths);
    }
    vector<string> canonicalPaths;
    vector<string> gstCanonicalPaths;
    for (string &path : pluginPaths) {
        if (platformAdp_.CheckAndNormalizePath(path) != SUCCESS) {
            IMAGE_LOGE("failed to check and normalize path: %{public}s.", path.c_str());
            continue;
        }

        PluginFWType fwType = AnalyzeFWType(path);
        switch (fwType) {
            case PluginFWType::PLUGIN_FW_GENERAL: {
                // directory path parameters, usually not too much, will not cause massive logs.
                IMAGE_LOGD("PluginFW path: %{public}s.", path.c_str());
                canonicalPaths.push_back(std::move(path));
                break;
            }
            case PluginFWType::PLUGIN_FW_GSTREAMER: {
                // directory path parameters, usually not too much, will not cause massive logs.
                IMAGE_LOGD("GstPluginFW path: %{public}s.", path.c_str());
                gstCanonicalPaths.push_back(std::move(path));
                break;
            }
            default: {
                IMAGE_LOGE("unknown FWType: %{public}d.", fwType);
            }
        }
    }

    if (canonicalPaths.empty() && gstCanonicalPaths.empty()) {
        IMAGE_LOGE("failed to find any valid plugin path.");
        return ERR_INVALID_PARAMETER;
    }

    if (!gstCanonicalPaths.empty()) {
        uint32_t result = gstPluginFw_.Register(gstCanonicalPaths);
        if (result != SUCCESS) {
            IMAGE_LOGE("failed to register gst plugin path, ERRNO: %{public}u.", result);
            return result;
        }
    }

    if (!canonicalPaths.empty()) {
        uint32_t result = pluginFw_.Register(canonicalPaths);
        if (result != SUCCESS) {
            IMAGE_LOGE("failed to register plugin path, ERRNO: %{public}u.", result);
            return result;
        }
    }

    return SUCCESS;
}

// ------------------------------- private method -------------------------------
PluginServer::PluginServer()
    : platformAdp_(DelayedRefSingleton<PlatformAdp>::GetInstance()),
      pluginFw_(DelayedRefSingleton<PluginFw>::GetInstance()),
      gstPluginFw_(DelayedRefSingleton<GstPluginFw>::GetInstance()) {}

PluginServer::~PluginServer() {}

PluginClassBase *PluginServer::CreateObject(uint16_t interfaceID, const string &className, uint32_t &errorCode)
{
    IMAGE_LOGD("create object iid: %{public}u, className: %{public}s.", interfaceID, className.c_str());
    PluginClassBase *obj = nullptr;
    // if it is a pipeline service, use the gstreamer framework first.
    if (GetInterfaceIDType(interfaceID) == IID_TYPE_PIPELINE) {
        IMAGE_LOGD("it is a pipeline interface type.");
        obj = gstPluginFw_.CreateObject(interfaceID, className, errorCode);
        if (obj != nullptr) {
            return obj;
        }
    }

    obj = pluginFw_.CreateObject(interfaceID, className, errorCode);
    return obj;
}

PluginClassBase *PluginServer::CreateObject(uint16_t interfaceID, uint16_t serviceType,
                                            const map<string, AttrData> &capabilities,
                                            const PriorityScheme &priorityScheme, uint32_t &errorCode)
{
    IMAGE_LOGD("create object iid: %{public}hu, service Type: %{public}u.", interfaceID, serviceType);
    PluginClassBase *obj = nullptr;
    // if it is a pipeline service, use the gstreamer framework first.
    if (GetInterfaceIDType(interfaceID) == IID_TYPE_PIPELINE) {
        IMAGE_LOGD("it is a pipeline interface type.");
        obj = gstPluginFw_.CreateObject(interfaceID, serviceType, capabilities, priorityScheme, errorCode);
        if (obj != nullptr) {
            return obj;
        }
    }

    obj = pluginFw_.CreateObject(interfaceID, serviceType, capabilities, priorityScheme, errorCode);
    return obj;
}

uint32_t PluginServer::PluginServerGetClassInfo(uint16_t interfaceID, uint16_t serviceType,
                                                const map<std::string, AttrData> &capabilities,
                                                vector<ClassInfo> &classesInfo)
{
    if (!classesInfo.empty()) {
        classesInfo.clear();
    }

    uint32_t resultGst = ERR_MATCHING_PLUGIN;
    // if it is a pipeline service, use the gstreamer framework first.
    if (GetInterfaceIDType(interfaceID) == IID_TYPE_PIPELINE) {
        resultGst = gstPluginFw_.GstPluginFwGetClassInfo(interfaceID, serviceType, capabilities, classesInfo);
    }

    // if the previous process has added classesInfo, the effect here is to append some other classesInfo.
    uint32_t resultFw = pluginFw_.PluginFwGetClassInfo(interfaceID, serviceType, capabilities, classesInfo);

    // if both gstreamer and self-developing plugin can not get class information, then considered fail.
    if ((resultGst != SUCCESS) && (resultFw != SUCCESS)) {
        IMAGE_LOGE("failed to get class by serviceType, resultGst: %{public}u, resultFw: %{public}u.",
            resultGst, resultFw);
        return resultFw;
    }

    return SUCCESS;
}

PluginFWType PluginServer::AnalyzeFWType(const string &canonicalPath)
{
    // for the current rule, contains the word "/gstreamer" is considered to be the gstreamer plugin directory.
    if (canonicalPath.find(platformAdp_.DIR_SEPARATOR + "gstreamer") != string::npos) {
        return PluginFWType::PLUGIN_FW_GSTREAMER;
    }

    return PluginFWType::PLUGIN_FW_GENERAL;
}
} // namespace MultimediaPlugin
} // namespace OHOS
