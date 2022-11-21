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
#include "string_ex.h"

using namespace testing::ext;
namespace OHOS {
namespace Multimedia {
class MockStringExTest : public testing::Test {
public:
    MockStringExTest() {}
    ~MockStringExTest() {}
};

/**
 * @tc.name: IsNumericStr001
 * @tc.desc: test IsNumericStr
 * @tc.type: FUNC
 */
HWTEST_F(MockStringExTest, IsNumericStr001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockStringExTest: IsNumericStr001 start";
    string str = "";
    bool getread = IsNumericStr(str);
    ASSERT_EQ(getread, false);
    GTEST_LOG_(INFO) << "MockStringExTest: IsNumericStr001 end";
}

/**
 * @tc.name: TrimStr001
 * @tc.desc: test TrimStr
 * @tc.type: FUNC
 */
HWTEST_F(MockStringExTest, TrimStr001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockStringExTest: TrimStr001 start";
    const string str = "";
    const char cTrim = 'a';
    string trinstr = TrimStr(str, cTrim);
    ASSERT_EQ(trinstr, "");
    GTEST_LOG_(INFO) << "MockStringExTest: TrimStr001 end";
}

/**
 * @tc.name: UpperStr001
 * @tc.desc: test UpperStr
 * @tc.type: FUNC
 */
HWTEST_F(MockStringExTest, UpperStr001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockStringExTest: UpperStr001 start";
    string str = "";
    string uppstr = UpperStr(str);
    ASSERT_EQ(uppstr, "");
    GTEST_LOG_(INFO) << "MockStringExTest: UpperStr001 end";
}

/**
 * @tc.name: IsSameTextStr001
 * @tc.desc: test IsSameTextStr
 * @tc.type: FUNC
 */
HWTEST_F(MockStringExTest, IsSameTextStr001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockStringExTest: IsSameTextStr001 start";
    string first = "a";
    string second = "b";
    bool isamestr = IsSameTextStr(first, second);
    ASSERT_EQ(isamestr, false);
    GTEST_LOG_(INFO) << "MockStringExTest: IsSameTextStr001 end";
}

/**
 * @tc.name: SplitStr001
 * @tc.desc: test SplitStr
 * @tc.type: FUNC
 */
HWTEST_F(MockStringExTest, SplitStr001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockStringExTest: SplitStr001 start";
    const string str = "";
    const string sep = "";
    vector<string> strs;
    bool canEmpty = true;
    bool needTrim = true;
    SplitStr(str, sep, strs, canEmpty, needTrim);
    GTEST_LOG_(INFO) << "MockStringExTest: SplitStr001 end";
}
} // namespace Multimedia
} // namespace OHOS