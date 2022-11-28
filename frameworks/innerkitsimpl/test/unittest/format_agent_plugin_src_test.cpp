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
#include <fstream>
#include "bmp_format_agent.h"
#include "gif_format_agent.h"
#include "heif_format_agent.h"
#include "jpeg_format_agent.h"
#include "png_format_agent.h"
#include "raw_format_agent.h"
#include "wbmp_format_agent.h"
#include "webp_format_agent.h"

using namespace testing::ext;
using namespace OHOS::MultimediaPlugin;
using namespace OHOS::ImagePlugin;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";
constexpr uint32_t LEAST_SIZE = 8;

class FormatAgentPluginSrcTest : public testing::Test {
public:
    FormatAgentPluginSrcTest() {}
    ~FormatAgentPluginSrcTest() {}
};

/**
 * @tc.name: CheckFormat001
 * @tc.desc: test SetData and ClearData data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSrcTest, CheckFormat001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormat start";
    HeifFormatAgent heifFormatAgent;
    const void *headerData = nullptr;
    uint32_t dataSize = 0;
    heifFormatAgent.CheckFormat(headerData, dataSize);
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormat end";
}

/**
 * @tc.name: CheckFormat002
 * @tc.desc: test SetData and ClearData data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSrcTest, CheckFormat002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormat002 start";
    HeifFormatAgent heifFormatAgent;
    uint32_t head[10];
    head[0] = 0;
    head[1] = 'f';
    uint32_t dataSize = 0;
    heifFormatAgent.CheckFormat(head, dataSize);
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormat002 end";
}

/**
 * @tc.name: CheckFormat003
 * @tc.desc: test SetData and ClearData data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSrcTest, CheckFormat003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormat003 start";
    HeifFormatAgent heifFormatAgent;
    const void *headerData = nullptr;
    uint32_t dataSize = LEAST_SIZE;
    heifFormatAgent.CheckFormat(headerData, dataSize);
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormat003 end";
}
}
}