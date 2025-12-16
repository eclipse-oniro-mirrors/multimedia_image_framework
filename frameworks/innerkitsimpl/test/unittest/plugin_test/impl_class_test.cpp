/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "impl_class.h"
#include "plugin.h"

using namespace testing::ext;
namespace OHOS {
namespace MultimediaPlugin {
static const uint16_t INTERFACE_ID = 1U;
static const uint16_t INSTANCE_NUM = 1U;
static const uint16_t MAX_INSTANCE = 1U;
static const uint32_t SERVICE_ELEM = 1U;

class ImplClassTest : public testing::Test {
public:
    ImplClassTest() {}
    ~ImplClassTest() {}
};

/**
 * @tc.name: RegisterTest001
 * @tc.desc: Test Register ensures json fields parsed and state registered.
 * @tc.type: FUNC
 */
HWTEST_F(ImplClassTest, RegisterTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImplClassTest: RegisterTest001 start";
    ImplClass implClass;
    std::weak_ptr<Plugin> pluginWeak;
    nlohmann::json classInfo = {
        {"className", "TestImplClass"},
        {"services", {{
            {"interfaceID", INTERFACE_ID},
            {"serviceType", 0}
        }}}
    };

    uint32_t ret = implClass.Register(pluginWeak, classInfo);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ImplClassTest: RegisterTest001 end";
}

/**
 * @tc.name: CreateObjectTest001
 * @tc.desc: Test CreateObject ensures errors on failure or instance limit.
 * @tc.type: FUNC
 */
HWTEST_F(ImplClassTest, CreateObjectTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImplClassTest: CreateObjectTest001 start";
    ImplClass implClass;
    std::shared_ptr<Plugin> pluginShared = std::make_shared<Plugin>();
    implClass.pluginRef_ = pluginShared;
    implClass.instanceNum_ = INSTANCE_NUM;
    implClass.state_ = ClassState::CLASS_STATE_REGISTERED;
    uint32_t errorCode = 0;

    implClass.CreateObject(errorCode);
    ASSERT_EQ(errorCode, ERR_INTERNAL);

    implClass.maxInstance_ = MAX_INSTANCE;
    implClass.CreateObject(errorCode);
    ASSERT_EQ(errorCode, ERR_INSTANCE_LIMIT);

    implClass.instanceNum_ = 0;
    implClass.CreateObject(errorCode);
    ASSERT_EQ(errorCode, ERR_INTERNAL);
    GTEST_LOG_(INFO) << "ImplClassTest: CreateObjectTest001 end";
}

/**
 * @tc.name: IsSupportTest001
 * @tc.desc: Test IsSupport ensures unmatched interfaceID returns false.
 * @tc.type: FUNC
 */
HWTEST_F(ImplClassTest, IsSupportTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImplClassTest: IsSupportTest001 start";
    ImplClass implClass;
    implClass.services_.insert(SERVICE_ELEM);

    bool ret = implClass.IsSupport(INTERFACE_ID);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ImplClassTest: IsSupportTest001 end";
}

/**
 * @tc.name: AnalysisServicesTest001
 * @tc.desc: Test AnalysisServices ensures default serviceType zero and services added.
 * @tc.type: FUNC
 */
HWTEST_F(ImplClassTest, AnalysisServicesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImplClassTest: AnalysisServicesTest001 start";
    ImplClass implClass;
    nlohmann::json classInfo = {
        {"services", {{
            {"interfaceID", INTERFACE_ID}
        }}}
    };

    bool analysisResult = implClass.AnalysisServices(classInfo);
    ASSERT_EQ(analysisResult, true);
    GTEST_LOG_(INFO) << "ImplClassTest: AnalysisServicesTest001 end";
}

/**
 * @tc.name: AnalysisServicesTest002
 * @tc.desc: Test AnalysisServices ensures invalid serviceType triggers JsonHelper error.
 * @tc.type: FUNC
 */
HWTEST_F(ImplClassTest, AnalysisServicesTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImplClassTest: AnalysisServicesTest002 start";
    ImplClass implClass;
    nlohmann::json classInfo = {
        {"services", {{
            {"interfaceID", INTERFACE_ID},
            {"serviceType", "invalid_type"}
        }}}
    };

    bool analysisResult = implClass.AnalysisServices(classInfo);
    ASSERT_EQ(analysisResult, false);
    GTEST_LOG_(INFO) << "ImplClassTest: AnalysisServicesTest002 end";
}
} // namespace MultimediaPlugin
} // namespace OHOS
