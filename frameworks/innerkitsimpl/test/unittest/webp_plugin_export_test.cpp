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
#include "plugin_export.h"

using namespace testing::ext;
namespace OHOS {
namespace Multimedia {
class WebpPluginExportTest : public testing::Test {
public:
    WebpPluginExportTest() {}
    ~WebpPluginExportTest() {}
};

/**
 * @tc.name: PluginExternalCreate001
 * @tc.desc: test PluginExternalCreate
 * @tc.type: FUNC
 */
HWTEST_F(WebpPluginExportTest, PluginExternalCreate001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WebpPluginExportTest: PluginExternalCreate001 start";
    string testStr = "";
    auto test = PluginExternalCreate(testStr);
    bool result = (test == nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "WebpPluginExportTest: PluginExternalCreate001 end";
}
} // namespace Multimedia
} // namespace OHOS