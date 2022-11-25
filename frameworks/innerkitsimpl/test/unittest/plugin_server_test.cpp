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
#include "abs_image_detector.h"
#include "image_source.h"
#include "plugin_server.h"
#include "webp_encoder.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::PluginExample;
namespace OHOS {
namespace MultimediaPlugin {
class PluginServerTest : public testing::Test {
public:
    PluginServerTest() {}
    ~PluginServerTest() {}
};

/**
 * @tc.name: TestRegister001
 * @tc.desc: Verify that the plugin management module supports the basic scenario of
 *           registering and managing one plugin package in one directory.
 * @tc.type: FUNC
 */
HWTEST_F(PluginServerTest, TestRegister001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. Register one directory with one plugin package.
     * @tc.expected: step1. The directory was registered successfully.
     */
    PluginServer &pluginServer = DelayedRefSingleton<PluginServer>::GetInstance();
    vector<string> pluginPaths;
    string str = "";
    pluginPaths.push_back(str);
    uint32_t ret = pluginServer.Register(std::move(pluginPaths));
    bool result = (ret != SUCCESS);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: TestRegister002
 * @tc.desc: Verify that the plugin management module supports the basic scenario of
 *           registering and managing one plugin package in one directory.
 * @tc.type: FUNC
 */
HWTEST_F(PluginServerTest, TestRegister002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. Register one directory with one plugin package.
     * @tc.expected: step1. The directory was registered successfully.
     */
    PluginServer &pluginServer = DelayedRefSingleton<PluginServer>::GetInstance();
    vector<string> pluginPaths;
    string str = "/system/etc/multimediaplugin/testplugins";
    pluginPaths.push_back(str);
    uint32_t ret = pluginServer.Register(std::move(pluginPaths));
    bool result = (ret != SUCCESS);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: TestRegister003
 * @tc.desc: Verify that the plugin management module supports the basic scenario of
 *           registering and managing one plugin package in one directory.
 * @tc.type: FUNC
 */
HWTEST_F(PluginServerTest, TestRegister003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. Register one directory with one plugin package.
     * @tc.expected: step1. The directory was registered successfully.
     */
    PluginServer &pluginServer = DelayedRefSingleton<PluginServer>::GetInstance();
    vector<string> pluginPaths;
    string str = "/system/etc/multimediaplugin/gstreamer";
    pluginPaths.push_back(str);
    uint32_t ret = pluginServer.Register(std::move(pluginPaths));
    bool result = (ret != SUCCESS);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: CreateObject001
 * @tc.desc: Verify that the plugin management module supports the basic scenario of
 *           registering and managing one plugin package in one directory.
 * @tc.type: FUNC
 */
HWTEST_F(PluginServerTest, CreateObject001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. Register one directory with one plugin package.
     * @tc.expected: step1. The directory was registered successfully.
     */
    string implClassName = "OHOS::PluginExample::CloudLabelDetector";
    PluginServer &pluginServer = DelayedRefSingleton<PluginServer>::GetInstance();
    vector<string> pluginPaths = { "/system/etc/multimediaplugin/testplugins" };
    pluginServer.Register(std::move(pluginPaths));
    AbsImageDetector *labelDetector =
        pluginServer.CreateObject<AbsImageDetector>(implClassName);
    ASSERT_EQ(labelDetector, nullptr);
}
}
}