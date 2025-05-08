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
#define private public
#include <gtest/gtest.h>
#include "attr_data.h"
#include "capability.h"
#include "impl_class_key.h"
#include "impl_class_mgr.h"
#include "impl_class.h"
#include "json_helper.h"
#include "media_errors.h"
#include "plugin_fw.h"
#include "plugin_info_lock.h"
#include "plugin_mgr.h"
#include "plugin.h"
#include "priority_scheme.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::MultimediaPlugin;

struct OHOS::MultimediaPlugin::VersionNum {
    uint16_t major = 0;
    uint16_t minor = 0;
    uint16_t micro = 0;
    uint16_t nano = 0;
};

namespace OHOS {
namespace Multimedia {
static constexpr uint32_t SUCCESS = 0;
static constexpr uint16_t UINT16_ONE = 1;
static const std::string OVER_UINT16_VALUE_STRING = "70000";
static constexpr uint32_t MOCKRANGESIZE = 2;
static constexpr uint32_t MOCKSIZE = 1;
static constexpr uint32_t LOWERRANGE = 1;
static constexpr uint32_t UPPERRANGE = 3;

static void StopFunction() {}
static bool StartFunction()
{
    return false;
}

class PluginsManagerSrcFrameWorkTest : public testing::Test {
public:
    PluginsManagerSrcFrameWorkTest() {}
    ~PluginsManagerSrcFrameWorkTest() {}
};

/**
 * @tc.name: CapabilityTest001
 * @tc.desc: SetCapability
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CapabilityTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CapabilityTest001 start";
    Capability capability;
    const nlohmann::json classInfo;
    uint32_t ret = capability.SetCapability(classInfo);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CapabilityTest001 end";
}

/**
 * @tc.name: CapabilityTest002
 * @tc.desc: SetCapability
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CapabilityTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CapabilityTest002 start";
    Capability capability;
    const nlohmann::json classInfo;
    uint32_t ret = capability.SetCapability(classInfo);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CapabilityTest002 end";
}

/**
 * @tc.name: CapabilityTest003
 * @tc.desc: IsCompatible
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CapabilityTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CapabilityTest003 start";
    Capability capability;
    std::map<string, AttrData> caps;
    bool ret = capability.IsCompatible(caps);
    ASSERT_NE(ret, false);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CapabilityTest003 end";
}

/**
 * @tc.name: CapabilityTest004
 * @tc.desc: *GetCapability
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CapabilityTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CapabilityTest004 start";
    Capability capability;
    std::string key;
    const AttrData *ret = capability.GetCapability(key);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CapabilityTest004 end";
}

/**
 * @tc.name: CapabilityTest005
 * @tc.desc: GetCapability
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CapabilityTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CapabilityTest005 start";
    Capability capability;
    std::map<std::string, AttrData> ret = capability.GetCapability();
    ASSERT_NE(&ret, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CapabilityTest005 end";
}

/**
 * @tc.name: ImplClassKeyTest001
 * @tc.desc: OnObjectDestroy
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassKeyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassKeyTest001 start";
    ImplClass key;
    ImplClassKey implClassKey(key);
    implClassKey.OnObjectDestroy();
    ASSERT_NE(&implClassKey, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassKeyTest001 end";
}

/**
 * @tc.name: ImplClassMgrTest001
 * @tc.desc: AddClass
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassMgrTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest001 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    std::weak_ptr<Plugin> plugin;
    const nlohmann::json classInfo;
    uint32_t ret = implClassMgr.AddClass(plugin, classInfo);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest001 end";
}

/**
 * @tc.name: ImplClassMgrTest002
 * @tc.desc: DeleteClass
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassMgrTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest002 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    std::weak_ptr<Plugin> plugin;
    implClassMgr.DeleteClass(plugin);
    std::shared_ptr<ImplClass> implClass = implClassMgr.GetImplClass("plugin", "plugin");
    ASSERT_EQ(implClass, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest002 end";
}

/**
 * @tc.name: ImplClassMgrTest003
 * @tc.desc: CreateObject
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassMgrTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest003 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    const string implClassName = "";
    uint16_t id = 0;
    uint32_t errorCode;
    PluginClassBase *obj = implClassMgr.CreateObject(id, implClassName, errorCode);
    EXPECT_EQ(errorCode, ERR_MATCHING_PLUGIN);
    ASSERT_EQ(obj, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest003 end";
}

/**
 * @tc.name: ImplClassMgrTest004
 * @tc.desc: CreateObject
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassMgrTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest004 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    uint16_t id = 0;
    uint16_t serviceType = 0;
    const map<string, AttrData> capabilities;
    PriorityScheme priorityScheme;
    uint32_t errorCode;
    PluginClassBase *obj = implClassMgr.CreateObject(id, serviceType, capabilities, priorityScheme, errorCode);
    EXPECT_EQ(errorCode, ERR_MATCHING_PLUGIN);
    ASSERT_EQ(obj, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest004 end";
}

/**
 * @tc.name: ImplClassMgrTest005
 * @tc.desc: ImplClassMgrGetClassInfo
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassMgrTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest005 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    uint16_t id = 0;
    uint16_t serviceType = 0;
    const map<string, AttrData> capabilities;
    std::vector<ClassInfo> classesInfo;
    uint32_t ret = implClassMgr.ImplClassMgrGetClassInfo(id, serviceType, capabilities, classesInfo);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest005 end";
}

/**
 * @tc.name: ImplClassMgrTest006
 * @tc.desc: GetImplClass
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassMgrTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest006 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    const string className = "";
    const string packageName = "";
    std::shared_ptr<ImplClass> implClass = implClassMgr.GetImplClass(packageName, className);
    ASSERT_EQ(implClass, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassMgrTest006 end";
}

/**
 * @tc.name: ImplClassTest001
 * @tc.desc: MakeServiceFlag
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest001 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    uint16_t id = 0;
    uint16_t serviceType = 0;
    uint32_t ret = implClass.MakeServiceFlag(id, serviceType);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest001 end";
}

/**
 * @tc.name: ImplClassTest002
 * @tc.desc: MakeIID
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest002 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    uint32_t serviceFlag = 0;
    uint16_t ret = implClass.MakeIID(serviceFlag);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest002 end";
}

/**
 * @tc.name: ImplClassTest004
 * @tc.desc: CreateObject
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest004 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    uint32_t errorCode;
    PluginClassBase *obj = implClass.CreateObject(errorCode);
    EXPECT_EQ(errorCode, ERR_INTERNAL);
    ASSERT_EQ(obj, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest004 end";
}

/**
 * @tc.name: ImplClassTest005
 * @tc.desc: GetPluginRef
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest005 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    std::weak_ptr<Plugin> obj = implClass.GetPluginRef();
    std::shared_ptr<Plugin> ret = obj.lock();
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest005 end";
}

/**
 * @tc.name: ImplClassTest006
 * @tc.desc: GetClassName
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest006 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    const std::string obj = implClass.GetClassName();
    ASSERT_EQ(obj, "");
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest006 end";
}

/**
 * @tc.name: ImplClassTest007
 * @tc.desc: GetClassName
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest007 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    const std::string obj = implClass.GetPackageName();
    ASSERT_EQ(obj, "");
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest007 end";
}

/**
 * @tc.name: ImplClassTest008
 * @tc.desc: IsSupport
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest008 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    uint16_t id = 0;
    bool obj = implClass.IsSupport(id);
    ASSERT_EQ(obj, false);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest008 end";
}

/**
 * @tc.name: ImplClassTest009
 * @tc.desc: OnObjectDestroy
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest009 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    implClass.OnObjectDestroy();
    ASSERT_NE(&implClass, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest009 end";
}

/**
 * @tc.name: ImplClassTest0010
 * @tc.desc: GetServices
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0010 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    const std::set<uint32_t> ret = implClass.GetServices();
    ASSERT_NE(&ret, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0010 end";
}

/**
 * @tc.name: ImplClassTest0011
 * @tc.desc: IsCompatible
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0011 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    const map<string, AttrData> caps;
    bool ret = implClass.IsCompatible(caps);
    ASSERT_NE(ret, false);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0011 end";
}

/**
 * @tc.name: ImplClassTest0012
 * @tc.desc: GetPriority
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0012 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    uint16_t ret = implClass.GetPriority();
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0012 end";
}

/**
 * @tc.name: ImplClassTest0013
 * @tc.desc: GetCapability
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0013 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    const std::string key = "";
    const AttrData *ret = implClass.GetCapability(key);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0013 end";
}

/**
 * @tc.name: ImplClassTest0014
 * @tc.desc: GetCapability
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0014 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    const std::map<std::string, AttrData> ret = implClass.GetCapability();
    ASSERT_EQ(ret.empty(), true);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0014 end";
}

/**
 * @tc.name: ImplClassTest0015
 * @tc.desc: GetCapability
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ImplClassTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0015 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    std::weak_ptr<Plugin> plugin;
    const nlohmann::json classInfo;
    uint32_t ret = implClass.Register(plugin, classInfo);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ImplClassTest0015 end";
}

/**
 * @tc.name: JsonHelperTest001
 * @tc.desc: CheckElementExistence
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, JsonHelperTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest001 start";
    const nlohmann::json jsonObject;
    const std::string key;
    uint32_t ret = JsonHelper::CheckElementExistence(jsonObject, key);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest001 end";
}

/**
 * @tc.name: JsonHelperTest002
 * @tc.desc: GetStringValue
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, JsonHelperTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest002 start";
    const nlohmann::json jsonString;
    std::string value;
    uint32_t ret = JsonHelper::GetStringValue(jsonString, value);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest002 end";
}

/**
 * @tc.name: JsonHelperTest003
 * @tc.desc: GetStringValue
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, JsonHelperTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest003 start";
    const nlohmann::json jsonObject;
    const std::string key;
    std::string value;
    uint32_t ret = JsonHelper::GetStringValue(jsonObject, key, value);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest003 end";
}

/**
 * @tc.name: JsonHelperTest004
 * @tc.desc: GetUint32Value
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, JsonHelperTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest004 start";
    const nlohmann::json jsonNum;
    uint32_t value = 0;
    uint32_t ret = JsonHelper::GetUint32Value(jsonNum, value);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest004 end";
}

/**
 * @tc.name: JsonHelperTest005
 * @tc.desc: GetUint32Value
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, JsonHelperTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest005 start";
    const nlohmann::json jsonObject;
    const std::string key;
    uint32_t value = 0;
    uint32_t ret = JsonHelper::GetUint32Value(jsonObject, key, value);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest005 end";
}

/**
 * @tc.name: JsonHelperTest006
 * @tc.desc: GetUint32Value
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, JsonHelperTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest006 start";
    const nlohmann::json jsonObject;
    const std::string key;
    uint16_t value = 0;
    uint32_t ret = JsonHelper::GetUint16Value(jsonObject, key, value);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest006 end";
}

/**
 * @tc.name: JsonHelperTest007
 * @tc.desc: GetArraySize
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, JsonHelperTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest007 start";
    const nlohmann::json jsonObject;
    const std::string key;
    size_t size;
    uint16_t ret = JsonHelper::GetArraySize(jsonObject, key, size);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: JsonHelperTest007 end";
}

/**
 * @tc.name: PluginFwTest001
 * @tc.desc: Register
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginFwTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginFwTest001 start";
    PluginFw &pluginFw = DelayedRefSingleton<PluginFw>::GetInstance();
    const std::vector<std::string> canonicalPaths;
    uint32_t ret = pluginFw.Register(canonicalPaths);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginFwTest001 end";
}

/**
 * @tc.name: PluginFwTest002
 * @tc.desc: CreateObject
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginFwTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginFwTest002 start";
    PluginFw &pluginFw = DelayedRefSingleton<PluginFw>::GetInstance();
    const string implClassName = "";
    uint16_t id = 0;
    uint32_t errorCode;
    PluginClassBase *obj = pluginFw.CreateObject(id, implClassName, errorCode);
    EXPECT_EQ(errorCode, ERR_MATCHING_PLUGIN);
    ASSERT_EQ(obj, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginFwTest002 end";
}

/**
 * @tc.name: PluginFwTest003
 * @tc.desc: CreateObject
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginFwTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginFwTest003 start";
    PluginFw &pluginFw = DelayedRefSingleton<PluginFw>::GetInstance();
    uint16_t id = 0;
    uint16_t serviceType = 0;
    const map<string, AttrData> capabilities;
    PriorityScheme priorityScheme;
    uint32_t errorCode;
    PluginClassBase *obj = pluginFw.CreateObject(id, serviceType, capabilities, priorityScheme, errorCode);
    EXPECT_EQ(errorCode, ERR_MATCHING_PLUGIN);
    ASSERT_EQ(obj, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginFwTest003 end";
}

/**
 * @tc.name: PluginFwTest004
 * @tc.desc: CreateObject
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginFwTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginFwTest004 start";
    PluginFw &pluginFw = DelayedRefSingleton<PluginFw>::GetInstance();
    uint16_t id = 0;
    uint16_t serviceType = 0;
    const map<string, AttrData> capabilities;
    std::vector<ClassInfo> classesInfo;
    uint32_t ret = pluginFw.PluginFwGetClassInfo(id, serviceType, capabilities, classesInfo);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginFwTest004 end";
}

/**
 * @tc.name: PluginMgrTest001
 * @tc.desc: Register
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginMgrTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginMgrTest001 start";
    PluginMgr &pluginMgr = DelayedRefSingleton<PluginMgr>::GetInstance();
    const std::vector<std::string> canonicalPaths;
    uint32_t ret = pluginMgr.Register(canonicalPaths);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginMgrTest001 end";
}

/**
 * @tc.name: PluginTest001
 * @tc.desc: Ref
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest001 start";
    Plugin plugin;
    uint32_t ret = plugin.Ref();
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest001 end";
}

/**
 * @tc.name: PluginTest002
 * @tc.desc: DeRef
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest002 start";
    Plugin plugin;
    plugin.Ref();
    plugin.DeRef();
    ASSERT_NE(&plugin, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest002 end";
}

/**
 * @tc.name: PluginTest003
 * @tc.desc: Block
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest003 start";
    Plugin plugin;
    plugin.Block();
    ASSERT_NE(&plugin, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest003 end";
}

/**
 * @tc.name: PluginTest004
 * @tc.desc: Unblock
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest004 start";
    Plugin plugin;
    plugin.Unblock();
    ASSERT_NE(&plugin, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest004 end";
}

/**
 * @tc.name: PluginTest005
 * @tc.desc: GetCreateFunc
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest005 start";
    Plugin plugin;
    PluginCreateFunc ret = plugin.GetCreateFunc();
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest005 end";
}

/**
 * @tc.name: PluginTest006
 * @tc.desc: GetLibraryPath
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest006 start";
    Plugin plugin;
    const std::string ret = plugin.GetLibraryPath();
    ASSERT_EQ(ret, "");
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest006 end";
}

/**
 * @tc.name: PluginTest007
 * @tc.desc: GetPackageName
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, PluginTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest007 start";
    Plugin plugin;
    const std::string ret = plugin.GetPackageName();
    ASSERT_EQ(ret, "");
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: PluginTest007 end";
}

/**
 * @tc.name: SetCapabilityTest001
 * @tc.desc: SetCapability
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, SetCapabilityTest001, TestSize.Level3)
{
    std::map<std::string, AttrData> caps;
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: SetCapabilityTest001 start";
    Capability capability(caps);
    const nlohmann::json classInfo;
    uint32_t ret = capability.SetCapability(classInfo);
    capability.IsCompatible(caps);
    std::map<std::string, AttrData> cap = capability.GetCapability();
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: SetCapabilityTest001 end";
}

/**
 * @tc.name: SearchByPriority001
 * @tc.desc: SearchByPriority
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, SearchByPriority001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: SearchByPriority001 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    std::list<std::shared_ptr<ImplClass>> candidates;
    PriorityScheme priorityScheme;
    priorityScheme.type_ = PriorityType::PRIORITY_TYPE_NULL;
    std::shared_ptr<ImplClass> implClass = implClassMgr.SearchByPriority(candidates, priorityScheme);
    ASSERT_EQ(implClass, nullptr);
    auto ptr = std::make_shared<ImplClass>();
    candidates.push_back(ptr);
    implClass = implClassMgr.SearchByPriority(candidates, priorityScheme);
    ASSERT_NE(implClass, nullptr);
    auto ptr2 = std::make_shared<ImplClass>();
    candidates.push_back(ptr2);
    implClass = implClassMgr.SearchByPriority(candidates, priorityScheme);
    ASSERT_NE(implClass, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: SearchByPriority001 end";
}

/**
 * @tc.name: SearchSimplePriority001
 * @tc.desc: SearchSimplePriority
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, SearchSimplePriority001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: SearchSimplePriority001 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    std::list<std::shared_ptr<ImplClass>> candidates;
    std::shared_ptr<ImplClass> implClass = implClassMgr.SearchSimplePriority(candidates);
    ASSERT_EQ(implClass, nullptr);
    auto ptr = std::make_shared<ImplClass>();
    candidates.push_back(ptr);
    implClass = implClassMgr.SearchSimplePriority(candidates);
    ASSERT_NE(implClass, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: SearchSimplePriority001 end";
}

/**
 * @tc.name: CompareBoolPriority001
 * @tc.desc: CompareBoolPriority
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CompareBoolPriority001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CompareBoolPriority001 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    AttrData rhs;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING;
    uint32_t ret;
    ret = implClassMgr.CompareBoolPriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_ERROR);
    lhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    rhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    ret = implClassMgr.CompareBoolPriority(lhs, rhs, type);
    ASSERT_NE(ret, ERR_COMP_ERROR);
    type = PriorityType::PRIORITY_TYPE_NULL;
    ret = implClassMgr.CompareBoolPriority(lhs, rhs, type);
    ASSERT_NE(ret, ERR_COMP_ERROR);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CompareBoolPriority001 end";
}

/**
 * @tc.name: CompareUint32Priority001
 * @tc.desc: CompareUint32Priority
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CompareUint32Priority001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CompareUint32Priority001 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    AttrData rhs;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING;
    uint32_t ret;
    ret = implClassMgr.CompareUint32Priority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_ERROR);
    lhs.type_ = AttrDataType::ATTR_DATA_UINT32;
    rhs.type_ = AttrDataType::ATTR_DATA_UINT32;
    ret = implClassMgr.CompareUint32Priority(lhs, rhs, type);
    ASSERT_NE(ret, ERR_COMP_ERROR);
    type = PriorityType::PRIORITY_TYPE_NULL;
    ret = implClassMgr.CompareUint32Priority(lhs, rhs, type);
    ASSERT_NE(ret, ERR_COMP_ERROR);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CompareUint32Priority001 end";
}

/**
 * @tc.name: CompareStringPriority001
 * @tc.desc: CompareStringPriority
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CompareStringPriority001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CompareStringPriority001 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    AttrData rhs;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING;
    uint32_t ret;
    ret = implClassMgr.CompareStringPriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_ERROR);
    lhs.type_ = AttrDataType::ATTR_DATA_STRING;
    rhs.type_ = AttrDataType::ATTR_DATA_STRING;
    string *str1 = new std::string("test");
    string *str2 = new std::string("test");
    lhs.value_.stringValue = str1;
    rhs.value_.stringValue = str2;
    ret = implClassMgr.CompareStringPriority(lhs, rhs, type);
    ASSERT_NE(ret, ERR_COMP_ERROR);
    type = PriorityType::PRIORITY_TYPE_NULL;
    AttrData lhs2;
    AttrData rhs2;
    ret = implClassMgr.CompareStringPriority(lhs2, rhs2, type);
    ASSERT_EQ(ret, ERR_COMP_ERROR);
    lhs2.type_ = AttrDataType::ATTR_DATA_STRING;
    rhs2.type_ = AttrDataType::ATTR_DATA_STRING;
    string *str3 = new std::string("test");
    string *str4 = new std::string("test");
    lhs2.value_.stringValue = str3;
    rhs2.value_.stringValue = str4;
    ret = implClassMgr.CompareStringPriority(lhs, rhs, type);
    ASSERT_NE(ret, ERR_COMP_ERROR);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CompareStringPriority001 end";
}

/**
 * @tc.name: AnalyzeBoolTest001
 * @tc.desc: AnalyzeBool
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeBoolTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeBoolTest001 start";
    auto capability = std::make_shared<Capability>();
    const nlohmann::json capInfo;
    AttrData attrData;
    uint32_t ret = capability->AnalyzeBool(capInfo, attrData);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeBoolTest001 end";
}

/**
 * @tc.name: AnalyzeUint32Test001
 * @tc.desc: AnalyzeUint32
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeUint32Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeUint32Test001 start";
    auto capability = std::make_shared<Capability>();
    const nlohmann::json capInfo;
    AttrData attrData;
    uint32_t ret = capability->AnalyzeUint32(capInfo, attrData);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeUint32Test001 end";
}

/**
 * @tc.name: AnalyzeStringTest001
 * @tc.desc: AnalyzeString
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeStringTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeStringTest001 start";
    auto capability = std::make_shared<Capability>();
    const nlohmann::json capInfo;
    AttrData attrData;
    uint32_t ret = capability->AnalyzeString(capInfo, attrData);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeStringTest001 end";
}

/**
 * @tc.name: AnalyzeUint32SetTest001
 * @tc.desc: AnalyzeUint32Set
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeUint32SetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeUint32SetTest001 start";
    auto capability = std::make_shared<Capability>();
    const nlohmann::json capInfo;
    AttrData attrData;
    uint32_t ret = capability->AnalyzeUint32Set(capInfo, attrData);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeUint32SetTest001 end";
}

/**
 * @tc.name: AnalyzeUint32RangeTest001
 * @tc.desc: AnalyzeUint32Range
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeUint32RangeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeUint32RangeTest001 start";
    auto capability = std::make_shared<Capability>();
    const nlohmann::json capInfo;
    AttrData attrData;
    uint32_t ret = capability->AnalyzeUint32Range(capInfo, attrData);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeUint32RangeTest001 end";
}

/**
 * @tc.name: AnalyzeStringSetTest001
 * @tc.desc: AnalyzeStringSet
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeStringSetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeStringSetTest001 start";
    auto capability = std::make_shared<Capability>();
    const nlohmann::json capInfo;
    AttrData attrData;
    uint32_t ret = capability->AnalyzeStringSet(capInfo, attrData);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeStringSetTest001 end";
}

/**
 * @tc.name: RegisterTest001
 * @tc.desc: Register
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, RegisterTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: RegisterTest001 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    std::weak_ptr<Plugin> plugin;
    const nlohmann::json classInfo;
    uint32_t ret = implClass.Register(plugin, classInfo);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    implClass.state_ = ClassState::CLASS_STATE_REGISTERED;
    ret = implClass.Register(plugin, classInfo);
    ASSERT_EQ(ret, ERR_INTERNAL);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: RegisterTest001 end";
}

/**
 * @tc.name: CreateObjectTest001
 * @tc.desc: CreateObject
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CreateObjectTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CreateObjectTest001 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    uint32_t errorCode;
    PluginClassBase *ret = implClass.CreateObject(errorCode);
    ASSERT_EQ(errorCode, ERR_INTERNAL);
    ASSERT_EQ(ret, nullptr);
    implClass.state_ = ClassState::CLASS_STATE_REGISTERED;
    implClass.maxInstance_ = 1;
    implClass.instanceNum_ = 1;
    ret = implClass.CreateObject(errorCode);
    ASSERT_EQ(ret, nullptr);
    implClass.maxInstance_ = 0;
    implClass.instanceNum_ = 0;
    ret = implClass.CreateObject(errorCode);
    ASSERT_EQ(ret, nullptr);
    implClass.pluginRef_.lock() = nullptr;
    ret = implClass.CreateObject(errorCode);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CreateObjectTest001 end";
}

/**
 * @tc.name: GetPackageNameTest002
 * @tc.desc: GetPackageName
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetPackageNameTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetPackageNameTest002 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    implClass.state_ = ClassState::CLASS_STATE_REGISTERED;
    implClass.pluginRef_.lock() = nullptr;
    const std::string ret = implClass.GetPackageName();
    ASSERT_EQ(ret, "");
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetPackageNameTest002 end";
}

/**
 * @tc.name: IsSupportTest002
 * @tc.desc: IsSupport
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, IsSupportTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: IsSupportTest002 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    uint16_t interfaceID = 0;
    bool ret = implClass.IsSupport(interfaceID);
    ASSERT_EQ(ret, false);
    implClass.services_.insert(0x0000);
    ret = implClass.IsSupport(interfaceID);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: IsSupportTest002 end";
}

/**
 * @tc.name: OnObjectDestroyTest002
 * @tc.desc: OnObjectDestroy
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, OnObjectDestroyTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: OnObjectDestroyTest002 start";
    ImplClass implClass;
    implClass.OnObjectDestroy();
    ASSERT_NE(implClass.state_, ClassState::CLASS_STATE_REGISTERED);
    implClass.state_ = ClassState::CLASS_STATE_REGISTERED;
    implClass.OnObjectDestroy();
    ASSERT_EQ(implClass.instanceNum_, 0);
    implClass.instanceNum_ = 1;
    implClass.OnObjectDestroy();
    ASSERT_EQ(implClass.instanceNum_, 0);
    implClass.instanceNum_ = 1;
    implClass.pluginRef_.lock() = nullptr;
    implClass.OnObjectDestroy();
    ASSERT_EQ(implClass.instanceNum_, 0);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: OnObjectDestroyTest002 end";
}

/**
 * @tc.name: GetCapabilityTest002
 * @tc.desc: GetCapability
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetCapabilityTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetCapabilityTest002 start";
    ImplClass &implClass = DelayedRefSingleton<ImplClass>::GetInstance();
    const std::string key = "";
    const AttrData *ret = implClass.GetCapability(key);
    ASSERT_EQ(ret, nullptr);
    implClass.state_ = ClassState::CLASS_STATE_REGISTERED;
    ret = implClass.GetCapability(key);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetCapabilityTest002 end";
}

/**
 * @tc.name: ExecuteVersionAnalysis001
 * @tc.desc: ExecuteVersionAnalysis
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ExecuteVersionAnalysis001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ExecuteVersionAnalysis001 start";
    Plugin plugin;
    string input = "";
    VersionParseStep step = static_cast<OHOS::MultimediaPlugin::VersionParseStep> (0);
    uint16_t versionArray[4] = {0};
    uint32_t ret = plugin.ExecuteVersionAnalysis(input, step, versionArray);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    step = static_cast<OHOS::MultimediaPlugin::VersionParseStep> (1);
    ret = plugin.ExecuteVersionAnalysis(input, step, versionArray);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    step = static_cast<OHOS::MultimediaPlugin::VersionParseStep> (2);
    ret = plugin.ExecuteVersionAnalysis(input, step, versionArray);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    step = static_cast<OHOS::MultimediaPlugin::VersionParseStep> (3);
    ret = plugin.ExecuteVersionAnalysis(input, step, versionArray);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    step = static_cast<OHOS::MultimediaPlugin::VersionParseStep> (7);
    ret = plugin.ExecuteVersionAnalysis(input, step, versionArray);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ExecuteVersionAnalysis001 end";
}

/**
 * @tc.name: GetUint16ValueFromDecimal001
 * @tc.desc: GetUint16ValueFromDecimal
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetUint16ValueFromDecimal001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint16ValueFromDecimal001 start";
    Plugin plugin;
    string source = "";
    uint16_t result;
    uint32_t ret = plugin.GetUint16ValueFromDecimal(source, result);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    source = "testtest";
    ret = plugin.GetUint16ValueFromDecimal(source, result);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    source = "12test";
    ret = plugin.GetUint16ValueFromDecimal(source, result);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint16ValueFromDecimal001 end";
}

/**
 * @tc.name: ComparePriorityTest001
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ != rhs.type_ , return ERR_COMP_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest001 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_NULL;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    PriorityType type = PriorityType::PRIORITY_TYPE_NULL;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_ERROR);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest001 end";
}

/**
 * @tc.name: ComparePriorityTest002
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_NULL,
             return ERR_COMP_EQUAL
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest002 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_NULL;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_NULL;
    PriorityType type = PriorityType::PRIORITY_TYPE_NULL;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_EQUAL);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest002 end";
}

/**
 * @tc.name: ComparePriorityTest003
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_BOOL,
             and type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.boolValue == true, and rhs.value_.boolValue == false,
             return ERR_COMP_LOWER
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest003 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    lhs.value_.boolValue = true;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    rhs.value_.boolValue = false;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_LOWER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest003 end";
}

/**
 * @tc.name: ComparePriorityTest004
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_BOOL,
             and type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.boolValue == true, and rhs.value_.boolValue == true,
             return ERR_COMP_EQUAL
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest004 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    lhs.value_.boolValue = true;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    rhs.value_.boolValue = true;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_EQUAL);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest004 end";
}

/**
 * @tc.name: ComparePriorityTest005
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_BOOL,
             and type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.boolValue == false, and rhs.value_.boolValue == true,
             return ERR_COMP_HIGHER
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest005 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    lhs.value_.boolValue = false;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    rhs.value_.boolValue = true;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_HIGHER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest005 end";
}

/**
 * @tc.name: ComparePriorityTest006
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_BOOL,
             and type != PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.boolValue == true, and rhs.value_.boolValue == false,
             return ERR_COMP_HIGHER
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest006 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    lhs.value_.boolValue = true;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    rhs.value_.boolValue = false;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_DESCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_HIGHER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest006 end";
}

/**
 * @tc.name: ComparePriorityTest007
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_BOOL,
             and type != PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.boolValue == true, and rhs.value_.boolValue == true,
             return ERR_COMP_EQUAL
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest007 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    lhs.value_.boolValue = true;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    rhs.value_.boolValue = true;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_DESCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_EQUAL);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest007 end";
}

/**
 * @tc.name: ComparePriorityTest008
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_BOOL,
             and type != PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.boolValue == false, and rhs.value_.boolValue == true,
             return ERR_COMP_LOWER
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest008 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    lhs.value_.boolValue = false;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_BOOL;
    rhs.value_.boolValue = true;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_DESCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_LOWER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest008 end";
}

/**
 * @tc.name: ComparePriorityTest009
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_UINT32,
             and type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.uint32Value < rhs.value_.uint32Value,
             return ERR_COMP_HIGHER
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest009 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_UINT32;
    lhs.value_.uint32Value = 1;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_UINT32;
    rhs.value_.uint32Value = 2;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_HIGHER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest009 end";
}

/**
 * @tc.name: ComparePriorityTest010
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_UINT32,
             and type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.uint32Value > rhs.value_.uint32Value,
             return ERR_COMP_LOWER
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest010 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_UINT32;
    lhs.value_.uint32Value = 2;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_UINT32;
    rhs.value_.uint32Value = 1;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_LOWER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest010 end";
}

/**
 * @tc.name: ComparePriorityTest011
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_UINT32,
             and type != PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.uint32Value < rhs.value_.uint32Value,
             return ERR_COMP_LOWER
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest011 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_UINT32;
    lhs.value_.uint32Value = 1;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_UINT32;
    rhs.value_.uint32Value = 2;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_DESCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_LOWER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest011 end";
}

/**
 * @tc.name: ComparePriorityTest012
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_UINT32,
             and type != PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.uint32Value > rhs.value_.uint32Value,
             return ERR_COMP_HIGHER
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest012 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_UINT32;
    lhs.value_.uint32Value = 2;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_UINT32;
    rhs.value_.uint32Value = 1;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_DESCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_HIGHER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest012 end";
}

/**
 * @tc.name: ComparePriorityTest013
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_STRING,
             and type == PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.stringValue == nullptr, and rhs.value_.stringValue == nullptr,
             return ERR_COMP_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest013 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_STRING;
    lhs.value_.stringValue = nullptr;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_STRING;
    rhs.value_.stringValue = nullptr;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_ERROR);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest013 end";
}

/**
 * @tc.name: ComparePriorityTest014
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_STRING,
             and type != PriorityType::PRIORITY_ORDER_BY_ATTR_ASCENDING,
             and lhs.value_.stringValue == nullptr, and rhs.value_.stringValue == nullptr,
             return ERR_COMP_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest014 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_STRING;
    lhs.value_.stringValue = nullptr;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_STRING;
    rhs.value_.stringValue = nullptr;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_DESCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_ERROR);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest014 end";
}

/**
 * @tc.name: ComparePriorityTest015
 * @tc.desc: test the ComparePriority of ImplClassMgr
             when lhs.type_ == rhs.type_  and lhs.type_ == AttrDataType::ATTR_DATA_TYPE_INVALID,
             return ERR_COMP_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, ComparePriorityTest015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest015 start";
    ImplClassMgr &implClassMgr = DelayedRefSingleton<ImplClassMgr>::GetInstance();
    AttrData lhs;
    lhs.type_ = AttrDataType::ATTR_DATA_TYPE_INVALID;
    AttrData rhs;
    rhs.type_ = AttrDataType::ATTR_DATA_TYPE_INVALID;
    PriorityType type = PriorityType::PRIORITY_ORDER_BY_ATTR_DESCENDING;
    uint32_t ret = implClassMgr.ComparePriority(lhs, rhs, type);
    ASSERT_EQ(ret, ERR_COMP_ERROR);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: ComparePriorityTest015 end";
}

/**
 * @tc.name: GetUint32ValueTest011
 * @tc.desc: test the GetUint32Value when in the normal scen
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetUint32ValueTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint32ValueTest011 start";
    const nlohmann::json jsonNum = 0;
    uint32_t value = 0;
    uint32_t ret = JsonHelper::GetUint32Value(jsonNum, value);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint32ValueTest011 end";
}

/**
 * @tc.name: GetUint32ValueTest012
 * @tc.desc: test the GetUint32Value when in the normal scen
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetUint32ValueTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint32ValueTest012 start";
    const std::string key = "Num_0";
    const nlohmann::json jsonNum = 0;
    const nlohmann::json jsonObject = {{"Num_0", jsonNum}};
    uint32_t value = 0;

    uint32_t ret = JsonHelper::GetUint32Value(jsonObject, key, value);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint32ValueTest012 end";
}

/**
 * @tc.name: GetUint16ValueTest011
 * @tc.desc: test the GetUint16Value when in the jsonNum is not integer
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetUint16ValueTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint16ValueTest011 start";
    const nlohmann::json jsonNum;
    const std::string key = "key";
    const nlohmann::json jsonObject = {{"key", jsonNum}};
    uint16_t value = 0;

    uint32_t ret = JsonHelper::GetUint16Value(jsonObject, key, value);
    EXPECT_EQ(ret, ERR_DATA_TYPE);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint16ValueTest011 end";
}

/**
 * @tc.name: GetUint16ValueTest012
 * @tc.desc: test the GetUint16Value when in the jsonNum is less than 0
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetUint16ValueTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint16ValueTest012 start";
    const nlohmann::json jsonNum = -1;
    const std::string key = "key";
    const nlohmann::json jsonObject = {{"key", jsonNum}};
    uint16_t value = 0;

    uint32_t ret = JsonHelper::GetUint16Value(jsonObject, key, value);
    EXPECT_EQ(ret, ERR_DATA_TYPE);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint16ValueTest012 end";
}

/**
 * @tc.name: GetUint16ValueTest013
 * @tc.desc: test the GetUint16Value when in the jsonNum is over than UINT16_MAX_VALUE
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetUint16ValueTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint16ValueTest013 start";
    const nlohmann::json jsonNum = UINT16_MAX_VALUE + 1;
    const std::string key = "key";
    const nlohmann::json jsonObject = {{"key", jsonNum}};
    uint16_t value = 0;

    uint32_t ret = JsonHelper::GetUint16Value(jsonObject, key, value);
    EXPECT_EQ(ret, ERR_DATA_TYPE);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint16ValueTest013 end";
}

/**
 * @tc.name: GetArraySizeTest011
 * @tc.desc: test the GetArraySize when jsonArray is not array
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetArraySizeTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetArraySizeTest011 start";
    const nlohmann::json jsonNum = 0;
    const std::string key = "Num_0";
    size_t size = 0;

    uint32_t ret = JsonHelper::GetArraySize(jsonNum, key, size);
    EXPECT_EQ(ret, ERR_DATA_TYPE);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetArraySizeTest011 end";
}

/**
 * @tc.name: RegisterTest011
 * @tc.desc: test the Register when state is not PLUGIN_STATE_UNREGISTER
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, RegisterTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: RegisterTest011 start";
    std::istringstream istream("");
    std::string libraryPath = "libraryPath";
    std::weak_ptr<Plugin> pluginWptr;
    Plugin plugin;
    plugin.state_ = PluginState::PLUGIN_STATE_REGISTERED;

    uint32_t res = plugin.Register(istream, move(libraryPath), pluginWptr);
    EXPECT_EQ(res, ERR_INTERNAL);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: RegisterTest011 end";
}

/**
 * @tc.name: RefTest011
 * @tc.desc: test the Ref when state is PLUGIN_STATE_REGISTERED and ResolveLibrary fail
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, RefTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: RefTest011 start";
    Plugin plugin;
    plugin.state_ = PluginState::PLUGIN_STATE_REGISTERED;
    plugin.libraryPath_ = "";

    uint32_t errCode = plugin.Ref();
    EXPECT_EQ(errCode, ERR_GENERAL);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: RefTest011 end";
}

/**
 * @tc.name: RefTest012
 * @tc.desc: test the Ref when state is PLUGIN_STATE_RESOLVE and startFun return false
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, RefTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: RefTest012 start";
    Plugin plugin;
    plugin.state_ = PluginState::PLUGIN_STATE_RESOLVED;
    plugin.startFunc_ = (PluginStartFunc)StartFunction;

    uint32_t errCode = plugin.Ref();
    EXPECT_EQ(errCode, ERR_GENERAL);
    EXPECT_EQ(plugin.state_, PluginState::PLUGIN_STATE_REGISTERED);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: RefTest012 end";
}

/**
 * @tc.name: GetCreateFuncTest011
 * @tc.desc: test the GetCreateFunc when state is PluginState::PLUGIN_STATE_ACTIVE or not or refNum_ is 0
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetCreateFuncTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetCreateFuncTest011 start";
    Plugin plugin;
    plugin.state_ = PluginState::PLUGIN_STATE_UNREGISTER;

    auto res = plugin.GetCreateFunc();
    EXPECT_EQ(res, nullptr);

    plugin.state_ = PluginState::PLUGIN_STATE_ACTIVE;
    plugin.refNum_ = 0;
    res = plugin.GetCreateFunc();
    EXPECT_EQ(res, nullptr);

    plugin.state_ = PluginState::PLUGIN_STATE_ACTIVE;
    plugin.refNum_++;
    res = plugin.GetCreateFunc();
    EXPECT_EQ(res, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetCreateFuncTest011 end";
}

/**
 * @tc.name: FreeLibraryTest011
 * @tc.desc: test the FreeLibrary when state is PLUGIN_STATE_STARTING or PLUGIN_STATE_ACTIVE and stopFunc_ is nullptr
 *           or not and handle is nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, FreeLibraryTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: FreeLibraryTest011 start";
    std::string handleStr = "handle";
    void* handle = reinterpret_cast<void*>(handleStr.data());
    Plugin plugin;
    plugin.state_ = PluginState::PLUGIN_STATE_UNREGISTER;
    plugin.handle_ = handle;

    plugin.FreeLibrary();
    EXPECT_EQ(plugin.handle_, nullptr);

    plugin.handle_ = handle;
    plugin.state_ = PluginState::PLUGIN_STATE_STARTING;
    plugin.stopFunc_ = (PluginStopFunc)StopFunction;
    plugin.FreeLibrary();
    EXPECT_EQ(plugin.stopFunc_, nullptr);

    plugin.handle_ = handle;
    plugin.state_ = PluginState::PLUGIN_STATE_ACTIVE;
    plugin.startFunc_ = (PluginStartFunc)StartFunction;
    plugin.stopFunc_= nullptr;
    plugin.FreeLibrary();
    EXPECT_EQ(plugin.startFunc_, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: FreeLibraryTest011 end";
}

/**
 * @tc.name: CheckTargetVersionTest011
 * @tc.desc: test the CheckTargetVersion when versionNum is empty
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CheckTargetVersionTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CheckTargetVersionTest011 start";
    Plugin plugin;
    const std::string versionStr = "";

    uint32_t errCode = plugin.CheckTargetVersion(versionStr);
    EXPECT_NE(errCode, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CheckTargetVersionTest011 end";
}

/**
 * @tc.name: AnalyzeVersionTest011
 * @tc.desc: test the AnalyzeVersion when versionNum is error
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeVersionTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeVersionTest011 start";
    Plugin plugin;
    const std::string errVersionStr = ".0";

    uint32_t errCode = plugin.CheckTargetVersion(errVersionStr);
    EXPECT_EQ(errCode, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeVersionTest011 end";
}

/**
 * @tc.name: AnalyzeVersionTest012
 * @tc.desc: test the AnalyzeVersion when versionNum is full
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeVersionTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeVersionTest011 start";
    Plugin plugin;
    const std::string versionStr = "1.2.3.4";
    VersionNum versionNum;

    uint32_t errCode = plugin.AnalyzeVersion(versionStr, versionNum);
    EXPECT_EQ(errCode, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeVersionTest011 end";
}

/**
 * @tc.name: GetUint16ValueFromDecimalTest011
 * @tc.desc: test the GetUint16ValueFromDecimal when the character in source is invalid
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetUint16ValueFromDecimalTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint16ValueFromDecimalTest011 start";
    Plugin plugin;
    std::string source = "-0123";
    uint16_t result = 0;
    uint32_t errCode = plugin.GetUint16ValueFromDecimal(source, result);
    EXPECT_EQ(errCode, ERR_INVALID_PARAMETER);

    source = "abc";
    result = 0;
    errCode = plugin.GetUint16ValueFromDecimal(source, result);
    EXPECT_EQ(errCode, ERR_INVALID_PARAMETER);

    source = OVER_UINT16_VALUE_STRING;
    result = 0;
    errCode = plugin.GetUint16ValueFromDecimal(source, result);
    EXPECT_EQ(errCode, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetUint16ValueFromDecimalTest011 end";
}

/**
 * @tc.name: TraverseFilesTest011
 * @tc.desc: test the TraverseFiles when strFiles is empty
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, TraverseFilesTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: TraverseFilesTest011 start";
    PluginMgr &pluginMgr = DelayedRefSingleton<PluginMgr>::GetInstance();
    std::string canonicalPath = "";
    uint32_t errCode = pluginMgr.TraverseFiles(canonicalPath);
    EXPECT_EQ(errCode, ERR_GENERAL);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: TraverseFilesTest011 end";
}

/**
 * @tc.name: CheckPluginMetaFileTest011
 * @tc.desc: test the CheckPluginMetaFile when candidateFile is invalid or fileExt is invalid
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, CheckPluginMetaFileTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CheckPluginMetaFileTest011 start";
    const std::string libraryFileSuffix = "so";
    PluginMgr &pluginMgr = DelayedRefSingleton<PluginMgr>::GetInstance();
    std::string canonicalPath = "test.test";
    std::string libraryPath = "libraryPath.test";
    bool res = pluginMgr.CheckPluginMetaFile(canonicalPath, libraryPath, libraryFileSuffix);
    EXPECT_FALSE(res);

    canonicalPath = "test.pluginmeta";
    libraryPath = "libraryPath.test";
    res = pluginMgr.CheckPluginMetaFile(canonicalPath, libraryPath, libraryFileSuffix);
    EXPECT_FALSE(res);

    canonicalPath = "test.pluginmeta";
    libraryPath = "/test/libraryPath.so";
    res = pluginMgr.CheckPluginMetaFile(canonicalPath, libraryPath, libraryFileSuffix);
    EXPECT_FALSE(res);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: CheckPluginMetaFileTest011 end";
}

/**
 * @tc.name: RegisterPluginTest011
 * @tc.desc: test the RegisterPlugin when metadataJson is empty or not json format
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, RegisterPluginTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: RegisterPluginTest011 start";
    PluginMgr &pluginMgr = DelayedRefSingleton<PluginMgr>::GetInstance();
    std::string metadataJson = "";
    uint32_t errCode = pluginMgr.RegisterPlugin(metadataJson);
    EXPECT_EQ(errCode, ERR_INVALID_PARAMETER);

    metadataJson = "error_json_format";
    errCode = pluginMgr.RegisterPlugin(metadataJson);
    EXPECT_EQ(errCode, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: RegisterPluginTest011 end";
}

/**
 * @tc.name: AnalysisServicesTest011
 * @tc.desc: test the AnalysisServices when classInfo is invalid
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalysisServicesTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalysisServicesTest011 start";
    ImplClass implClass;
    const nlohmann::json classInfo;
    bool res = implClass.AnalysisServices(classInfo);
    EXPECT_FALSE(res);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalysisServicesTest011 end";
}

/**
 * @tc.name: AnalysisMaxInstanceTest011
 * @tc.desc: test the AnalysisMaxInstance when maxInstance is 0 or result is not ERR_NO_TARGET
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalysisMaxInstanceTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalysisMaxInstanceTest011 start";
    ImplClass implClass;
    nlohmann::json jsonNum = 0;
    nlohmann::json classInfo = {{"maxInstance", jsonNum}};
    bool res = implClass.AnalysisMaxInstance(classInfo);
    EXPECT_FALSE(res);
    EXPECT_EQ(implClass.maxInstance_, 0);

    classInfo = "error_json_format";
    res = implClass.AnalysisMaxInstance(classInfo);
    EXPECT_FALSE(res);

    jsonNum = 1;
    classInfo = {{"maxInstance", jsonNum}};
    res = implClass.AnalysisMaxInstance(classInfo);
    EXPECT_TRUE(res);
    EXPECT_EQ(implClass.maxInstance_, UINT16_ONE);

    classInfo = {{"key", jsonNum}};
    res = implClass.AnalysisMaxInstance(classInfo);
    EXPECT_TRUE(res);
    EXPECT_EQ(implClass.maxInstance_, ImplClass::INSTANCE_NO_LIMIT_NUM);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalysisMaxInstanceTest011 end";
}

/**
 * @tc.name: DoCreateObjectTest011
 * @tc.desc: test the DoCreateObject when factory is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, DoCreateObjectTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: DoCreateObjectTest011 start";
    auto pluginSptr = std::make_shared<Plugin>();
    ASSERT_NE(pluginSptr, nullptr);
    pluginSptr->state_ = PluginState::PLUGIN_STATE_UNREGISTER;
    ASSERT_EQ(pluginSptr->GetCreateFunc(), nullptr);

    ImplClass implClass;
    auto res = implClass.DoCreateObject(pluginSptr);
    EXPECT_EQ(res, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: DoCreateObjectTest011 end";
}

/**
 * @tc.name: SetCapabilityTest002
 * @tc.desc: Verify that SetCapability when caps_ is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, SetCapabilityTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: SetCapabilityTest002 start";
    std::map<std::string, AttrData> mockCaps;
    mockCaps["mockKey"] = AttrData{std::string("mockValue")};
    Capability mockCapability{mockCaps};
    std::array<char, 4> mockArr{'m', 'o', 'c', 'k'};
    nlohmann::json mockJson{mockArr};
    auto ret = mockCapability.SetCapability(mockJson);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: SetCapabilityTest002 end";
}

/**
 * @tc.name: IsCompatibleTest001
 * @tc.desc: Verify that IsCompatible when the src does not contain a member of des.
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, IsCompatibleTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: IsCompatibleTest001 start";
    std::map<std::string, AttrData> mockCaps, mockMap;
    mockCaps["mockKey"] = AttrData{std::string("mockValue")};
    mockMap["mapKey"] = AttrData{std::string("mapValue")};
    Capability mockCapability{mockCaps};
    auto ret = mockCapability.IsCompatible(mockMap);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: IsCompatibleTest001 end";
}

/**
 * @tc.name: GetCapabilityTest001
 * @tc.desc: Verify that GetCapability when input parameter is correct.
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, GetCapabilityTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetCapabilityTest001 start";
    std::map<std::string, AttrData> mockCaps;
    mockCaps["mockKey"] = AttrData{std::string("mockValue")};
    Capability mockCapability{mockCaps};
    auto ret = mockCapability.GetCapability(std::string("mockKey"));
    ASSERT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: GetCapabilityTest001 end";
}

/**
 * @tc.name: AnalyzeAttrDataTest001
 * @tc.desc: Verify that AnalyzeAttrData when type is bool.
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeAttrDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest001 start";
    AttrData mockAttrData;
    Capability mockCapability;
    nlohmann::json mockJson;
    mockJson["type"] = "bool";
    mockJson["value"] = "true";
    auto ret = mockCapability.AnalyzeAttrData(mockJson, mockAttrData);
    ASSERT_EQ(ret, SUCCESS);
    mockJson["value"] = "false";
    ret = mockCapability.AnalyzeAttrData(mockJson, mockAttrData);
    ASSERT_EQ(ret, SUCCESS);
    mockJson["value"] = "mock";
    ret = mockCapability.AnalyzeAttrData(mockJson, mockAttrData);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest001 end";
}

/**
 * @tc.name: AnalyzeAttrDataTest002
 * @tc.desc: Verify that AnalyzeAttrData when type is mock.
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeAttrDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest002 start";
    AttrData mockAttrData;
    Capability mockCapability;
    nlohmann::json mockJson;
    mockJson["type"] = "mock";
    auto ret = mockCapability.AnalyzeAttrData(mockJson, mockAttrData);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest002 end";
}

/**
 * @tc.name: AnalyzeAttrDataTest003
 * @tc.desc: Verify that AnalyzeAttrData when type is uint32.
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeAttrDataTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest003 start";
    AttrData mockAttrData;
    Capability mockCapability;
    nlohmann::json mockJson;
    mockJson["type"] = "uint32";
    mockJson["value"] = uint32_t(0);
    auto ret = mockCapability.AnalyzeAttrData(mockJson, mockAttrData);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest003 end";
}

/**
 * @tc.name: AnalyzeAttrDataTest004
 * @tc.desc: Verify that AnalyzeAttrData when type is uint32Set.
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeAttrDataTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest004 start";
    AttrData mockAttrData;
    Capability mockCapability;
    nlohmann::json mockJson;
    mockJson["type"] = "uint32Set";
    std::array<uint32_t, MOCKSIZE> mockArr{0};
    mockJson["value"] = mockArr;
    auto ret = mockCapability.AnalyzeAttrData(mockJson, mockAttrData);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest004 end";
}

/**
 * @tc.name: AnalyzeAttrDataTest005
 * @tc.desc: Verify that AnalyzeAttrData when type is stringSet.
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeAttrDataTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest005 start";
    AttrData mockAttrData;
    Capability mockCapability;
    nlohmann::json mockJson;
    mockJson["type"] = "stringSet";
    std::array<std::string, MOCKSIZE> mockArr{"mock"};
    mockJson["value"] = mockArr;
    auto ret = mockCapability.AnalyzeAttrData(mockJson, mockAttrData);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest005 end";
}

/**
 * @tc.name: AnalyzeAttrDataTest006
 * @tc.desc: Verify that AnalyzeAttrData when type is uint32Range.
 * @tc.type: FUNC
 */
HWTEST_F(PluginsManagerSrcFrameWorkTest, AnalyzeAttrDataTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest006 start";
    AttrData mockAttrData;
    Capability mockCapability;
    nlohmann::json mockJson;
    mockJson["type"] = "uint32Range";
    std::array<uint32_t, MOCKRANGESIZE> mockArr{LOWERRANGE, UPPERRANGE};
    mockJson["value"] = mockArr;
    auto ret = mockCapability.AnalyzeAttrData(mockJson, mockAttrData);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginsManagerSrcFrameWorkTest: AnalyzeAttrDataTest006 end";
}
}
}