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

#define private public
#include <gtest/gtest.h>
#include "platform_adp.h"
#include "plugin_errors.h"

using namespace testing::ext;
using namespace OHOS::MultimediaPlugin;

namespace OHOS {
namespace Multimedia {
class PlatformAdpTest : public testing::Test {
public:
    PlatformAdpTest() {}
    ~PlatformAdpTest() {}
};

/**
 * @tc.name: CheckAndNormalizePathTest001
 * @tc.desc: test CheckAndNormalizePath when path is empty
 * @tc.type: FUNC
 */
HWTEST_F(PlatformAdpTest, CheckAndNormalizePathTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PlatformAdpTest: CheckAndNormalizePathTest001 start";
    PlatformAdp platformAdp;
    std::string path = "";
    ASSERT_TRUE(path.empty());

    uint32_t errCode = platformAdp.CheckAndNormalizePath(path);
    EXPECT_EQ(errCode, ERR_GENERAL);
    GTEST_LOG_(INFO) << "PlatformAdpTest: CheckAndNormalizePathTest001 end";
}
}
}