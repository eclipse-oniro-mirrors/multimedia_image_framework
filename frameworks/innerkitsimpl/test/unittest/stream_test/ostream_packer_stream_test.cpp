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
#define private public
#include "ostream_packer_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class OstreamPackerStreamTest : public testing::Test {
public:
    OstreamPackerStreamTest() {}
    ~OstreamPackerStreamTest() {}
};

/**
 * @tc.name: Write001
 * @tc.desc: test Write method when buffer is nullptr or size is 0
 * @tc.type: FUNC
 */
HWTEST_F(OstreamPackerStreamTest, Write001, TestSize.Level3)
{
    std::ostringstream outputStream;
    auto stream = std::make_shared<OstreamPackerStream>(outputStream);
    ASSERT_NE(stream, nullptr);
    uint8_t buffer[] = {0, 0, 0, 0, 0};

    bool res = stream->Write(nullptr, 0);
    EXPECT_FALSE(res);

    res = stream->Write(buffer, 0);
    EXPECT_FALSE(res);
}
}
}

