/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <fstream>
#include "hitrace_meter.h"

using namespace testing::ext;
namespace OHOS {
namespace Multimedia {
class MockHitraceMeterTest : public testing::Test {
public:
    MockHitraceMeterTest() {}
    ~MockHitraceMeterTest() {}
};

/**
 * @tc.name: StartTrace001
 * @tc.desc: test StartTrace
 * @tc.type: FUNC
 */
HWTEST_F(MockHitraceMeterTest, StartTrace001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockHitraceMeterTest: StartTrace001 start";
    uint64_t label = 6;
    std::string value = "aaa";
    float limit = 1.1;
    StartTrace(label, value, limit);
    GTEST_LOG_(INFO) << "MockHitraceMeterTest: StartTrace001 end";
}

/**
 * @tc.name: FinishTrace001
 * @tc.desc: test FinishTrace
 * @tc.type: FUNC
 */
HWTEST_F(MockHitraceMeterTest, FinishTrace001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockHitraceMeterTest: FinishTrace001 start";
    uint64_t label = 8;
    FinishTrace(label);
    GTEST_LOG_(INFO) << "MockHitraceMeterTest: FinishTrace001 end";
}
} // namespace Multimedia
} // namespace OHOS