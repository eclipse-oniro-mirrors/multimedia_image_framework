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
    bool res = heifFormatAgent.CheckFormat(headerData, dataSize);
    ASSERT_EQ(res, false);
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
    bool res = heifFormatAgent.CheckFormat(head, dataSize);
    ASSERT_EQ(res, false);
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
    bool res = heifFormatAgent.CheckFormat(headerData, dataSize);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormat003 end";
}

/**
 * @tc.name: IsHeif64001
 * @tc.desc: IsHeif64
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSrcTest, IsHeif64001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::IsHeif64001 start";
    HeifFormatAgent heifFormatAgent;
    void *buffer = malloc(4);
    size_t bytesRead = 1;
    int64_t offset = 1;
    uint64_t chunkSize = 1;
    bool res = heifFormatAgent.IsHeif64(buffer, bytesRead, offset, chunkSize);
    ASSERT_EQ(res, false);
    free(buffer);
    buffer = nullptr;
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::IsHeif64001 end";
}

/**
 * @tc.name: IsHeif64002
 * @tc.desc: IsHeif64
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSrcTest, IsHeif64002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::IsHeif64002 start";
    HeifFormatAgent heifFormatAgent;
    void *buffer = malloc(4);
    size_t bytesRead = 1;
    int64_t offset = 1;
    uint64_t chunkSize = 2;
    bool res = heifFormatAgent.IsHeif64(buffer, bytesRead, offset, chunkSize);
    ASSERT_EQ(res, false);
    chunkSize = 10;
    res = heifFormatAgent.IsHeif64(buffer, bytesRead, offset, chunkSize);
    ASSERT_EQ(res, true);
    free(buffer);
    buffer = nullptr;
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::IsHeif64002 end";
}

/**
 * @tc.name: CheckFormat004
 * @tc.desc: CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSrcTest, CheckFormat004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormat004 start";
    HeifFormatAgent heifFormatAgent;
    void *headerData = malloc(4);
    uint32_t dataSize = 9;
    bool res = heifFormatAgent.CheckFormat(headerData, dataSize);
    ASSERT_EQ(res, false);
    dataSize = 20;
    res = heifFormatAgent.CheckFormat(headerData, dataSize);
    ASSERT_EQ(res, false);
    free(headerData);
    headerData = nullptr;
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormat004 end";
}

/**
 * @tc.name: EndianSwap64Test001
 * @tc.desc: EndianSwap64
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSrcTest, EndianSwap64Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::EndianSwap64Test001 start";
    HeifFormatAgent heifFormatAgent;
    uint64_t value = 0;
    uint64_t res = heifFormatAgent.EndianSwap64(value);
    ASSERT_EQ(res, 0);
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::EndianSwap64Test001 end";
}

/**
 * @tc.name: IsHeif64Test003
 * @tc.desc: IsHeif64
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSrcTest, IsHeif64Test003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::IsHeif64Test003 start";
    HeifFormatAgent heifFormatAgent;
    uint64_t data = 0;
    void *buffer = &data;
    size_t bytesRead = 20;
    int64_t offset = 0;
    uint64_t chunkSize = 1;
    auto *ptr = static_cast<const uint64_t *>(buffer);
    ASSERT_EQ(*ptr, 0);
    auto *chunkSizePtr = static_cast<const uint64_t *>(buffer) + (offset / sizeof(uint64_t));
    ASSERT_EQ(*chunkSizePtr, 0);
    bool res = heifFormatAgent.IsHeif64(buffer, bytesRead, offset, chunkSize);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::IsHeif64Test003 end";
}

/**
 * @tc.name: CheckFormatTest005
 * @tc.desc: CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSrcTest, CheckFormatTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormatTest005 start";
    HeifFormatAgent heifFormatAgent;
    uint32_t dataSize = 10;
    uint32_t data[10] = { 1 };
    void *headerData = &data;
    ASSERT_NE(headerData, nullptr);
    bool res = heifFormatAgent.CheckFormat(headerData, dataSize);
    res = heifFormatAgent.CheckFormat(headerData, dataSize);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginSrcTest: HeifFormatAgent::CheckFormatTest005 end";
}
}
}