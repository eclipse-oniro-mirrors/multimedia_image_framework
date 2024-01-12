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

#include <gtest/gtest.h>
#include <iostream>
#include "gst_plugin_fw.h"
#include "__mutex_base"
#include "map"
#include "plugin_errors.h"
#include "priority_scheme.h"
#include "vector"

using OHOS::DelayedRefSingleton;
using std::string;
using std::vector;
using namespace testing::ext;
using namespace OHOS::MultimediaPlugin;

namespace OHOS {
namespace Multimedia {
class GstPluginFwTest : public testing::Test {
public:
    GstPluginFwTest() {}
    ~GstPluginFwTest() {}
};
/**
 * @tc.name: GstPluginFwTest001
 * @tc.desc: Register
 * @tc.type: FUNC
 */
HWTEST_F(GstPluginFwTest, GstPluginFwTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "GstPluginFwTest: GstPluginFwTest001 start";
    GstPluginFw &gstPluginFw_ = DelayedRefSingleton<GstPluginFw>::GetInstance();
    const vector<string> canonicalPaths;
    uint32_t ret = gstPluginFw_.Register(canonicalPaths);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "GstPluginFwTest: GstPluginFwTest001 end";
}

/**
 * @tc.name: GstPluginFwTest002
 * @tc.desc: CreateObject
 * @tc.type: FUNC
 */
HWTEST_F(GstPluginFwTest, GstPluginFwTest002, TestSize.Level3) {
    GTEST_LOG_(INFO) << "GstPluginFwTest: GstPluginFwTest002 start";
    GstPluginFw &gstPluginFw_ = DelayedRefSingleton<GstPluginFw>::GetInstance();
    vector<string> canonicalPaths;
    const string implClassName = "";
    uint16_t id = 0;
    uint32_t errorCode;
    PluginClassBase *obj = gstPluginFw_.CreateObject(id, implClassName, errorCode);
    EXPECT_EQ(errorCode, ERR_MATCHING_PLUGIN);
    ASSERT_EQ(obj, nullptr);
    GTEST_LOG_(INFO) << "GstPluginFwTest: GstPluginFwTest002 end";
}

/**
 * @tc.name: GstPluginFwTest003
 * @tc.desc: CreateObject
 * @tc.type: FUNC
 */
HWTEST_F(GstPluginFwTest, GstPluginFwTest003, TestSize.Level3) {
    GTEST_LOG_(INFO) << "GstPluginFwTest: GstPluginFwTest003 start";
    GstPluginFw &gstPluginFw_ = DelayedRefSingleton<GstPluginFw>::GetInstance();
    uint16_t id = 0;
    uint16_t serviceType = 0;
    const map<string, AttrData> capabilities;
    PriorityScheme priorityScheme;
    uint32_t errorCode;
    PluginClassBase *obj = gstPluginFw_.CreateObject(id, serviceType, capabilities, priorityScheme, errorCode);
    EXPECT_EQ(errorCode, ERR_MATCHING_PLUGIN);
    ASSERT_EQ(obj, nullptr);
    GTEST_LOG_(INFO) << "GstPluginFwTest: GstPluginFwTest003 end";
}

/**
 * @tc.name: GstPluginFwTest004
 * @tc.desc: CreateObject
 * @tc.type: FUNC
 */
HWTEST_F(GstPluginFwTest, GstPluginFwTest004, TestSize.Level3) {
    GTEST_LOG_(INFO) << "GstPluginFwTest: GstPluginFwTest004 start";
    GstPluginFw &gstPluginFw_ = DelayedRefSingleton<GstPluginFw>::GetInstance();
    uint16_t id = 0;
    uint16_t serviceType = 0;
    const map<string, AttrData> capabilities;
    vector<ClassInfo> classesInfo;
    uint32_t resultGst = gstPluginFw_.GstPluginFwGetClassInfo(id, serviceType, capabilities, classesInfo);
    ASSERT_EQ(resultGst, ERR_MATCHING_PLUGIN);
    GTEST_LOG_(INFO) << "GstPluginFwTest: GstPluginFwTest004 end";
}
}
}