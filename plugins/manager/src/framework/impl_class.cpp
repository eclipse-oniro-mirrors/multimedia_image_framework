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

#include "impl_class.h"
#include <algorithm>
#include "image_log.h"
#include "impl_class_key.h"
#include "json_helper.h"
#include "plugin.h"
#include "plugin_class_base.h"
#include "plugin_common_type.h"
#include "plugin_export.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ImplClass"

namespace OHOS {
namespace MultimediaPlugin {
using nlohmann::json;
using std::map;
using std::recursive_mutex;
using std::set;
using std::shared_ptr;
using std::size_t;
using std::string;
using std::weak_ptr;
string ImplClass::emptyString_;

ImplClass::ImplClass() : selfKey_(*this)
{}

uint32_t ImplClass::Register(const weak_ptr<Plugin> &plugin, const json &classInfo)
{
    if (state_ != ClassState::CLASS_STATE_UNREGISTER) {
        // repeat registration
        IMAGE_LOGI("repeat registration.");
        return ERR_INTERNAL;
    }

    if (JsonHelper::GetStringValue(classInfo, "className", className_) != SUCCESS) {
        IMAGE_LOGE("read className failed.");
        return ERR_INVALID_PARAMETER;
    }
    IMAGE_LOGD("register class: %{public}s.", className_.c_str());

    if (!AnalysisServices(classInfo)) {
        IMAGE_LOGE("failed to analysis services for class %{public}s.", className_.c_str());
        return ERR_INVALID_PARAMETER;
    }

    uint32_t result = JsonHelper::GetUint16Value(classInfo, "priority", priority_);
    if (result != SUCCESS) {
        if (result != ERR_NO_TARGET) {
            IMAGE_LOGE("read priority failed, result: %{public}u.", result);
            return ERR_INVALID_PARAMETER;
        }
        // priority is optional, and default zero.
        priority_ = 0;
    }
    IMAGE_LOGD("get class priority: %{public}u.", priority_);

    if (!AnalysisMaxInstance(classInfo)) {
        IMAGE_LOGE("failed to analysis maxInstance for class %{public}s.", className_.c_str());
        return ERR_INVALID_PARAMETER;
    }
    IMAGE_LOGD("get class maxInstance: %{public}u.", maxInstance_);

    if (JsonHelper::CheckElementExistence(classInfo, "capabilities") == SUCCESS) {
        capability_.SetCapability(classInfo["capabilities"]);
    }
    pluginRef_ = plugin;
    state_ = ClassState::CLASS_STATE_REGISTERED;
    return SUCCESS;
}

PluginClassBase *ImplClass::CreateObject(uint32_t &errorCode)
{
    errorCode = ERR_INTERNAL;
    if (state_ != ClassState::CLASS_STATE_REGISTERED) {
        IMAGE_LOGE("failed to create for unregistered, className: %{public}s.", className_.c_str());
        return nullptr;
    }

    auto sharedPlugin = pluginRef_.lock();
    if (sharedPlugin == nullptr) {
        IMAGE_LOGE("failed to dereference Plugin, className: %{public}s.", className_.c_str());
        return nullptr;
    }

    IMAGE_LOGD("create object, className: %{public}s.", className_.c_str());

    std::unique_lock<std::recursive_mutex> guard(dynDataLock_);
    if (maxInstance_ != INSTANCE_NO_LIMIT_NUM && instanceNum_ >= maxInstance_) {
        IMAGE_LOGE("failed to create for limit, currentNum: %{public}u, maxNum: %{public}u, \
            className: %{public}s.", instanceNum_, maxInstance_, className_.c_str());
        guard.unlock();
        errorCode = ERR_INSTANCE_LIMIT;
        return nullptr;
    }

    if (instanceNum_ == 0) {
        if (sharedPlugin->Ref() != SUCCESS) {
            return nullptr;
        }
    }

    PluginClassBase *object = DoCreateObject(sharedPlugin);
    if (object == nullptr) {
        IMAGE_LOGE("create object result null, className: %{public}s.", className_.c_str());
        if (instanceNum_ == 0) {
            sharedPlugin->DeRef();
        }
        return nullptr;
    }

    ++instanceNum_;
    IMAGE_LOGD("create object success, InstanceNum: %{public}u.", instanceNum_);
    guard.unlock();

    errorCode = SUCCESS;
    return object;
}

weak_ptr<Plugin> ImplClass::GetPluginRef() const
{
    if (state_ != ClassState::CLASS_STATE_REGISTERED) {
        return weak_ptr<Plugin>();
    }

    return pluginRef_;
}

const string &ImplClass::GetClassName() const
{
    return className_;
}

const string &ImplClass::GetPackageName() const
{
    if (state_ != ClassState::CLASS_STATE_REGISTERED) {
        IMAGE_LOGE("get package name, className: %{public}s, state error: %{public}d.", className_.c_str(), state_);
        return emptyString_;
    }

    auto sharedPlugin = pluginRef_.lock();
    if (sharedPlugin == nullptr) {
        IMAGE_LOGE("get package name, failed to dereference Plugin, className: %{public}s.", className_.c_str());
        return emptyString_;
    }

    return sharedPlugin->GetPackageName();
}

bool ImplClass::IsSupport(uint16_t interfaceID) const
{
    IMAGE_LOGD("search for support iid: %{public}u, className: %{public}s.", interfaceID, className_.c_str());
    for (uint32_t serviceFlag : services_) {
        if (MakeIID(serviceFlag) == interfaceID) {
            return true;
        }
    }

    IMAGE_LOGD("there is no matching interfaceID");
    return false;
}

void ImplClass::OnObjectDestroy()
{
    // this situation does not happen in design.
    // the process context can guarantee that this will not happen.
    // the judgment statement here is for protection and positioning purposes only.
    if (state_ != ClassState::CLASS_STATE_REGISTERED) {
        IMAGE_LOGE("failed to destroy object because class unregistered, className: %{public}s.", className_.c_str());
        return;
    }

    std::unique_lock<std::recursive_mutex> guard(dynDataLock_);
    // this situation does not happen in design.
    if (instanceNum_ == 0) {
        guard.unlock();
        IMAGE_LOGE("destroy object while instanceNum is zero.");
        return;
    }

    --instanceNum_;

    auto sharedPlugin = pluginRef_.lock();
    // this situation does not happen in design.
    if (sharedPlugin == nullptr) {
        guard.unlock();
        IMAGE_LOGE("destroy object failed because failed to dereference Plugin, className: %{public}s.",
            className_.c_str());
        return;
    }

    IMAGE_LOGD("destroy object: className: %{public}s", className_.c_str());
    if (instanceNum_ == 0) {
        sharedPlugin->DeRef();
    }

    IMAGE_LOGD("destroy object success, InstanceNum: %{public}u.", instanceNum_);
}

const set<uint32_t> &ImplClass::GetServices() const
{
    return services_;
}

bool ImplClass::IsCompatible(const map<string, AttrData> &caps) const
{
    return capability_.IsCompatible(caps);
}

const AttrData *ImplClass::GetCapability(const string &key) const
{
    if (state_ != ClassState::CLASS_STATE_REGISTERED) {
        return nullptr;
    }

    return capability_.GetCapability(key);
}

const std::map<std::string, AttrData> &ImplClass::GetCapability() const
{
    return capability_.GetCapability();
}

// ------------------------------- private method -------------------------------
bool ImplClass::AnalysisServices(const json &classInfo)
{
    size_t serviceNum;
    if (JsonHelper::GetArraySize(classInfo, "services", serviceNum) != SUCCESS) {
        IMAGE_LOGE("read array size of services failed.");
        return false;
    }
    IMAGE_LOGD("class service num: %{public}zu.", serviceNum);

    uint16_t interfaceID;
#ifndef PLUGIN_FLAG_RTTI_ENABLE
    uint32_t lastInterfaceID = UINT32_MAX_VALUE;
#endif
    uint16_t serviceType;
    bool serviceAdded = false;
    const json &servicesInfo = classInfo["services"];
    for (size_t i = 0; i < serviceNum; i++) {
        const json &serviceInfo = servicesInfo[i];
        if (JsonHelper::GetUint16Value(serviceInfo, "interfaceID", interfaceID) != SUCCESS) {
            IMAGE_LOGE("read interfaceID failed at %{public}zu.", i);
#ifndef PLUGIN_FLAG_RTTI_ENABLE
            // when -frtti is not enable, to ensure correct base class side-to-side conversion, we require that
            // the plugin class inherit only one service interface class and the PluginClassBase class,
            // while the location of the service interface class is in front of the PluginClassBase.
            // below, we check only one business interface class is allowed to inherit.
            IMAGE_LOGE("no valid service info or encounter the risk of more than one business \
                                interface base class.");
            return false;
#else
            continue;
#endif
        }

#ifndef PLUGIN_FLAG_RTTI_ENABLE
        // check only one business interface class is allowed to inherit.
        if (lastInterfaceID != UINT32_MAX_VALUE && lastInterfaceID != interfaceID) {
            IMAGE_LOGE("more than one business interface base class.");
            return false;
        }
        lastInterfaceID = interfaceID;
#endif
        uint32_t result = JsonHelper::GetUint16Value(serviceInfo, "serviceType", serviceType);
        if (result != SUCCESS) {
            if (result != ERR_NO_TARGET) {
                IMAGE_LOGE("read serviceType failed at %{public}zu.", i);
                continue;
            }
            // serviceType is optional, and default zero.
            serviceType = 0;
        }

        IMAGE_LOGD("insert service iid: %{public}hu, serviceType: %{public}hu.", interfaceID, serviceType);
        services_.insert(MakeServiceFlag(interfaceID, serviceType));
        serviceAdded = true;
    }

    return serviceAdded;
}

bool ImplClass::AnalysisMaxInstance(const json &classInfo)
{
    uint32_t result = JsonHelper::GetUint16Value(classInfo, "maxInstance", maxInstance_);
    if (result == SUCCESS) {
        IMAGE_LOGD("class maxInstance num: %{public}u.", maxInstance_);
        if (maxInstance_ == 0) {
            IMAGE_LOGE("class maxInstance num is invalid zero.");
            return false;
        }
        return true;
    }

    if (result != ERR_NO_TARGET) {
        IMAGE_LOGE("read maxInstance failed.");
        return false;
    }

    // maxInstance is optional, and value for this case is not limited.
    maxInstance_ = INSTANCE_NO_LIMIT_NUM;
    return true;
}

PluginClassBase *CfiFactory(PluginCreateFunc factory, const string &className) __attribute__((no_sanitize("cfi")))
{
    return factory(className);
}

PluginClassBase *ImplClass::DoCreateObject(shared_ptr<Plugin> &plugin) __attribute__((no_sanitize("cfi")))
{
    // since the plugin library may be unloaded and reloaded, the pointer cannot guarantee a constant value,
    // so it is reread every time here.
    PluginCreateFunc factory = plugin->GetCreateFunc();
    if (factory == nullptr) {
        IMAGE_LOGE("failed to get create func, className: %{public}s.", className_.c_str());
        return nullptr;
    }

    PluginClassBase *pluginBaseObj = CfiFactory(factory, className_);
    if (pluginBaseObj == nullptr) {
        IMAGE_LOGE("create object result null, className: %{public}s.", className_.c_str());
        return nullptr;
    }

#ifndef PLUGIN_FLAG_RTTI_ENABLE
    // when -frtti is not enable, to ensure correct base class side-to-side conversion,
    // we require that the plugin class inherit only one service interface class and the PluginClassBase class,
    // while the location of the service interface class is in front of the PluginClassBase.
    // below, we check the inherited position constraint.
    void *obj = dynamic_cast<void *>(pluginBaseObj);  // adjust pointer position when multiple inheritance.
    if (obj == pluginBaseObj) {
        // PluginClassBase is the first base class, not allowed.
        IMAGE_LOGE("service interface class is not the first base class. className: %{public}s.", className_.c_str());
        delete pluginBaseObj;
        return nullptr;
    }
#endif

    if (pluginBaseObj->SetImplClassKey(selfKey_) != PluginClassBase::MAGIC_CODE) {
        IMAGE_LOGE("failed to set key, className: %{public}s.", className_.c_str());
        delete pluginBaseObj;
        return nullptr;
    }

    return pluginBaseObj;
}
} // namespace MultimediaPlugin
} // namespace OHOS
