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

#include "impl_class_mgr.h"
#include "image_log.h"
#include "impl_class.h"
#include "plugin.h"
#include "plugin_class_base.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ImplClassMgr"

namespace OHOS {
namespace MultimediaPlugin {
using nlohmann::json;
using std::list;
using std::map;
using std::multimap;
using std::mutex;
using std::set;
using std::shared_ptr;
using std::string;
using std::weak_ptr;

uint32_t ImplClassMgr::AddClass(weak_ptr<Plugin> &plugin, const json &classInfo)
{
    shared_ptr<ImplClass> implClass = std::make_shared<ImplClass>();
    if (implClass == nullptr) {
        IMAGE_LOGE("AddClass: failed to create ImplClass.");
        return ERR_INTERNAL;
    }

    auto ret = implClass->Register(plugin, classInfo);
    if (ret != SUCCESS) {
        IMAGE_LOGE("AddClass: failed to register impClass.ERRNO: %{public}u.", ret);
        return ret;
    }

    const string &key = implClass->GetClassName();
    CHECK_ERROR_RETURN_RET_LOG(key.empty(), ERR_INTERNAL, "AddClass: empty className.");

    IMAGE_LOGD("AddClass: insert Class: %{public}s.", key.c_str());
    classMultimap_.insert(NameClassMultimap::value_type(&key, implClass));

    // for fast search by service flag
    const set<uint32_t> &services = implClass->GetServices();
    for (const uint32_t &srv : services) {
        IMAGE_LOGD("AddClass: insert service: %{public}u.", srv);
        srvSearchMultimap_.insert(ServiceClassMultimap::value_type(srv, implClass));
    }

    return SUCCESS;
}

void ImplClassMgr::DeleteClass(const weak_ptr<Plugin> &plugin)
{
    // delete all ImplClass under the specified plugin.
    auto targetPlugin = plugin.lock();

    for (auto iter = srvSearchMultimap_.begin(); iter != srvSearchMultimap_.end();) {
        auto tmpPlugin = iter->second->GetPluginRef().lock();
        if (tmpPlugin != targetPlugin) {
            ++iter;
            continue;
        }
        iter = srvSearchMultimap_.erase(iter);
    }

    for (auto iter = classMultimap_.begin(); iter != classMultimap_.end();) {
        auto tmpPlugin = iter->second->GetPluginRef().lock();
        if (tmpPlugin != targetPlugin) {
            ++iter;
            continue;
        }
        iter = classMultimap_.erase(iter);
    }
}

PluginClassBase *ImplClassMgr::CreateObject(uint16_t interfaceID, const string &className, uint32_t &errorCode)
{
    IMAGE_LOGD("create object iid: %{public}hu, className: %{public}s.", interfaceID, className.c_str());

    NameClassMultimap::iterator iter = classMultimap_.lower_bound(&className);
    NameClassMultimap::iterator endIter = classMultimap_.upper_bound(&className);
    if (iter == endIter) {
        IMAGE_LOGE("failed to find matching class by className: %{public}s.", className.c_str());
        errorCode = ERR_MATCHING_PLUGIN;
        return nullptr;
    }

    for (; iter != endIter; ++iter) {
        CHECK_ERROR_RETURN_RET(iter->second->IsSupport(interfaceID), iter->second->CreateObject(errorCode));
    }

    // no this class
    IMAGE_LOGE("failed to find matching class for iid: %{public}hu, className: %{public}s.", interfaceID,
        className.c_str());
    errorCode = ERR_MATCHING_PLUGIN;
    return nullptr;
}

PluginClassBase *ImplClassMgr::CreateObject(uint16_t interfaceID, uint16_t serviceType,
                                            const map<string, AttrData> &capabilities,
                                            const PriorityScheme &priorityScheme, uint32_t &errorCode)
{
    uint32_t serviceFlag = ImplClass::MakeServiceFlag(interfaceID, serviceType);
    list<shared_ptr<ImplClass>> candidates;

    IMAGE_LOGD("create object iid: %{public}u, serviceType: %{public}u.", interfaceID, serviceType);

    auto iter = srvSearchMultimap_.lower_bound(serviceFlag);
    auto endIter = srvSearchMultimap_.upper_bound(serviceFlag);
    for (; iter != endIter; ++iter) {
        shared_ptr<ImplClass> &temp = iter->second;
        if ((!capabilities.empty()) && (!temp->IsCompatible(capabilities))) {
            continue;
        }
        candidates.push_back(temp);
    }

    shared_ptr<ImplClass> target = SearchByPriority(candidates, priorityScheme);
    if (target == nullptr) {
        IMAGE_LOGD("failed to find class by priority.");
        errorCode = ERR_MATCHING_PLUGIN;
        return nullptr;
    }

    IMAGE_LOGD("search by priority result, className: %{public}s.", target->GetClassName().c_str());
    return target->CreateObject(errorCode);
}

uint32_t ImplClassMgr::ImplClassMgrGetClassInfo(uint16_t interfaceID, uint16_t serviceType,
                                                const std::map<std::string, AttrData> &capabilities,
                                                std::vector<ClassInfo> &classesInfo)
{
    // get service flag by interfaceID and serviceType
    uint32_t serviceFlag = ImplClass::MakeServiceFlag(interfaceID, serviceType);

    IMAGE_LOGD("get classinfo iid: %{public}u, serviceType: %{public}u.", interfaceID, serviceType);
    auto iter = srvSearchMultimap_.lower_bound(serviceFlag);
    auto endIter = srvSearchMultimap_.upper_bound(serviceFlag);
    if (iter == endIter) {
        IMAGE_LOGE("failed to get class by serviceFlag, iid: %{public}u, serviceType: %{public}u.",
            interfaceID, serviceType);
        return ERR_MATCHING_PLUGIN;
    }

    for (; iter != endIter; ++iter) {
        shared_ptr<ImplClass> &temp = iter->second;
        if ((capabilities.size() != 0) && (!temp->IsCompatible(capabilities))) {
            continue;
        }
        // after multiple filtering, there are only a few instances here, which will not cause massive logs.
        IMAGE_LOGD("found by serviceFlag & capabilities, className: %{public}s.", temp->GetClassName().c_str());
        ClassInfo classInfo;
        classInfo.packageName = temp->GetPackageName();
        classInfo.className = temp->GetClassName();
        classInfo.priority = temp->GetPriority();
        classInfo.capabilities = temp->GetCapability();
        classesInfo.emplace_back(std::move(classInfo));
    }

    CHECK_ERROR_RETURN_RET_LOG(classesInfo.empty(), ERR_MATCHING_PLUGIN,
        "failed to get class by capabilities, iid: %{public}u, serviceType: %{public}u.", interfaceID, serviceType);

    return SUCCESS;
}

shared_ptr<ImplClass> ImplClassMgr::GetImplClass(const string &packageName, const string &className)
{
    IMAGE_LOGD("search ImplClass, className: %{public}s.", className.c_str());
    shared_ptr<ImplClass> implClass = nullptr;
    auto iter = classMultimap_.lower_bound(&className);
    auto endIter = classMultimap_.upper_bound(&className);
    for (; iter != endIter; ++iter) {
        if (packageName == iter->second->GetPackageName()) {
            implClass = iter->second;
            break;
        }
    }

    if (implClass == nullptr) {
        IMAGE_LOGE("failed to get ImplClass, className: %{public}s.", className.c_str());
    }

    return implClass;
}

// ------------------------------- private method -------------------------------
ImplClassMgr::ImplClassMgr()
{}

ImplClassMgr::~ImplClassMgr()
{}

shared_ptr<ImplClass> ImplClassMgr::SearchByPriority(const list<shared_ptr<ImplClass>> &candidates,
                                                     const PriorityScheme &priorityScheme)
{
    auto size = candidates.size();
    if (size == 0) {  // 0 means class no candidate,  return empty directly.
        IMAGE_LOGD("SearchByPriority: candidates size is zero.");
        return nullptr;
    }

    if (size == 1) {  // 1 means class only one candidate, no need to handle priority, return directly.
        return candidates.front();
    }

    if (priorityScheme.GetPriorityType() == PriorityType::PRIORITY_TYPE_NULL) {
        // no attribute priority policy, we only compare static priority
        return SearchSimplePriority(candidates);
    }

    PriorityType priorityType = priorityScheme.GetPriorityType();
    const string &attrKey = priorityScheme.GetAttrKey();

    auto targetIter = candidates.begin();
    // targetAttr is allowed to be empty.
    // when the target ImplClass does not have this attribute, the value of targetAttr is null,
    // and the subsequent priority comparison process will judge and handle this situation.
    const AttrData *targetAttr = ((*targetIter)->GetCapability)(attrKey);

    auto tempIter = targetIter;
    for (++tempIter; tempIter != candidates.end(); ++tempIter) {
        const AttrData *attrData = ((*tempIter)->GetCapability)(attrKey);
        if (attrData == nullptr) {
            continue;
        }

        if (targetAttr == nullptr) {
            targetIter = tempIter;
            targetAttr = attrData;
            continue;
        }

        // the result value is used later, the targetIter and targetAttr assignment structures cannot be merged,
        // and the the merged logic will not understand well.
        uint32_t result = ComparePriority(*attrData, *targetAttr, priorityType);
        if (result == ERR_COMP_HIGHER) {
            targetIter = tempIter;
            targetAttr = attrData;
            continue;
        }

        // if the priority attribute are equal, we further compare the static priority.
        if (result == ERR_COMP_EQUAL) {
            if (((*tempIter)->GetPriority()) > ((*targetIter)->GetPriority())) {
                targetIter = tempIter;
                targetAttr = attrData;
            }
        }
    }

    return *targetIter;
}

shared_ptr<ImplClass> ImplClassMgr::SearchSimplePriority(const list<shared_ptr<ImplClass>> &candidates)
{
    if (candidates.size() == 0) {
        IMAGE_LOGE("SearchSimplePriority: candidates size is zero.");
        return nullptr;
    }
    auto targetIter = candidates.begin();
    auto tempIter = targetIter;

    for (++tempIter; tempIter != candidates.end(); ++tempIter) {
        if (((*tempIter)->GetPriority()) > ((*targetIter)->GetPriority())) {
            targetIter = tempIter;
        }
    }

    return *targetIter;
}

uint32_t ImplClassMgr::ComparePriority(const AttrData &lhs, const AttrData &rhs, PriorityType type)
{
    if (lhs.GetType() != rhs.GetType()) {
        IMAGE_LOGE("compare between different types, %{public}d and %{public}d.", lhs.GetType(),
            rhs.GetType());
        return ERR_COMP_ERROR;
    }

    switch (lhs.GetType()) {
        case AttrDataType::ATTR_DATA_NULL: {
            return ERR_COMP_EQUAL;
        }
        case AttrDataType::ATTR_DATA_BOOL: {
            return CompareBoolPriority(lhs, rhs, type);
        }
        case AttrDataType::ATTR_DATA_UINT32:
        case AttrDataType::ATTR_DATA_UINT32_SET:
        case AttrDataType::ATTR_DATA_UINT32_RANGE: {
            return CompareUint32Priority(lhs, rhs, type);
        }
        case AttrDataType::ATTR_DATA_STRING:
        case AttrDataType::ATTR_DATA_STRING_SET: {
            return CompareStringPriority(lhs, rhs, type);
        }
        default: {
            IMAGE_LOGE("invalid data type: %{public}d.", lhs.GetType());
            return ERR_COMP_ERROR;
        }
    }
}

// for the bool type, the meaning of the size is unknown. we artificially define true greater than false here.
uint32_t ImplClassMgr::CompareBoolPriority(const AttrData &lhs, const AttrData &rhs, PriorityType type)
{
    bool lhsValue = false;
    bool rhsValue = false;

    if ((lhs.GetValue(lhsValue) != SUCCESS) || (rhs.GetValue(rhsValue) != SUCCESS)) {
        IMAGE_LOGE("CompareBoolPriority: failed to get attribute value.");
        return ERR_COMP_ERROR;
    }

    if (type == PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING) {
        if (lhsValue) {
            if (!rhsValue) {
                return ERR_COMP_LOWER;
            }
            return ERR_COMP_EQUAL;
        }

        if (rhsValue) {
            return ERR_COMP_HIGHER;
        }

        return ERR_COMP_EQUAL;
    }

    if (lhsValue) {
        if (!rhsValue) {
            return ERR_COMP_HIGHER;
        }
        return ERR_COMP_EQUAL;
    }

    if (rhsValue) {
        return ERR_COMP_LOWER;
    }

    return ERR_COMP_EQUAL;
}

uint32_t ImplClassMgr::CompareUint32Priority(const AttrData &lhs, const AttrData &rhs, PriorityType type)
{
    uint32_t lhsValue = 0;
    uint32_t rhsValue = 0;

    if (type == PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING) {
        if ((lhs.GetMinValue(lhsValue) != SUCCESS) || (rhs.GetMinValue(rhsValue) != SUCCESS)) {
            IMAGE_LOGE("CompareUint32Priority: failed to get attribute min value.");
            return ERR_COMP_ERROR;
        }

        if (lhsValue < rhsValue) {
            return ERR_COMP_HIGHER;
        }

        if (lhsValue == rhsValue) {
            return ERR_COMP_EQUAL;
        }

        return ERR_COMP_LOWER;
    }

    bool cond = (lhs.GetMaxValue(lhsValue) != SUCCESS) || (rhs.GetMaxValue(rhsValue) != SUCCESS);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_COMP_ERROR, "CompareUint32Priority: failed to get attribute max value.");

    if (lhsValue < rhsValue) {
        return ERR_COMP_LOWER;
    }

    if (lhsValue == rhsValue) {
        return ERR_COMP_EQUAL;
    }

    return ERR_COMP_HIGHER;
}

uint32_t ImplClassMgr::CompareStringPriority(const AttrData &lhs, const AttrData &rhs, PriorityType type)
{
    const string *lhsValue = nullptr;
    const string *rhsValue = nullptr;

    if (type == PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING) {
        if ((lhs.GetMinValue(lhsValue) != SUCCESS) || (rhs.GetMinValue(rhsValue) != SUCCESS)) {
            IMAGE_LOGE("CompareStringPriority: failed to get attribute min value.");
            return ERR_COMP_ERROR;
        }

        if (lhsValue == nullptr || rhsValue == nullptr) {
            IMAGE_LOGE("CompareStringPriority: value is null.");
            return ERR_COMP_ERROR;
        }

        if (*lhsValue < *rhsValue) {
            return ERR_COMP_HIGHER;
        }

        if (*lhsValue == *rhsValue) {
            return ERR_COMP_EQUAL;
        }

        return ERR_COMP_LOWER;
    }

    if ((lhs.GetMaxValue(lhsValue) != SUCCESS) || (rhs.GetMaxValue(rhsValue) != SUCCESS)) {
        IMAGE_LOGE("CompareStringPriority: failed to get attribute max value.");
        return ERR_COMP_ERROR;
    }

    if (lhsValue == nullptr || rhsValue == nullptr) {
        IMAGE_LOGE("CompareStringPriority: value is null.");
        return ERR_COMP_ERROR;
    }

    if (*lhsValue < *rhsValue) {
        return ERR_COMP_LOWER;
    }

    if (*lhsValue == *rhsValue) {
        return ERR_COMP_EQUAL;
    }

    return ERR_COMP_HIGHER;
}
} // namespace MultimediaPlugin
} // namespace OHOS
