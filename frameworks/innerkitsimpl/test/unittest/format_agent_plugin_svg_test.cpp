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
#include "image_source.h"
#include "media_errors.h"
#include "svg_format_agent.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_SVG_PATH = "/data/local/tmp/image/test.svg";
static const std::string SVG_FORMAT_TYPE = "image/svg+xml";
static constexpr uint8_t SVG_HEADER[] = { '<', '?', 'x', 'm', 'l' };

class FormatAgentPluginSvgTest : public testing::Test {
public:
    FormatAgentPluginSvgTest() {}
    ~FormatAgentPluginSvgTest() {}
};

/**
 * @tc.name: SvgFormatAgentPluginTest001
 * @tc.desc: svg GetFormatType
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgFormatAgentPluginTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest001 start";
    ImagePlugin::SvgFormatAgent formatAgent;
    auto ret = formatAgent.GetFormatType();
    ASSERT_EQ(ret, SVG_FORMAT_TYPE);
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest001 end";
}

/**
 * @tc.name: SvgFormatAgentPluginTest002
 * @tc.desc: svg GetHeaderSize
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgFormatAgentPluginTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest002 start";
    ImagePlugin::SvgFormatAgent formatAgent;
    auto ret = formatAgent.GetHeaderSize();
    ASSERT_EQ(ret, sizeof(SVG_HEADER));
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest002 end";
}

/**
 * @tc.name: SvgFormatAgentPluginTest003
 * @tc.desc: svg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgFormatAgentPluginTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest003 start";
    ImagePlugin::SvgFormatAgent formatAgent;
    auto datasize = formatAgent.GetHeaderSize();
    void *headerData = nullptr;
    auto ret = formatAgent.CheckFormat(headerData, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest003 end";
}

/**
 * @tc.name: SvgFormatAgentPluginTest004
 * @tc.desc: svg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgFormatAgentPluginTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest004 start";
    ImagePlugin::SvgFormatAgent formatAgent;
    auto datasize = formatAgent.GetHeaderSize();
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = SVG_FORMAT_TYPE;
    auto imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_SVG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    auto ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest004 end";
}

/**
 * @tc.name: SvgFormatAgentPluginTest005
 * @tc.desc: svg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgFormatAgentPluginTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest005 start";
    ImagePlugin::SvgFormatAgent formatAgent;
    auto datasize = formatAgent.GetHeaderSize();
    auto ret = formatAgent.CheckFormat(nullptr, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest005 end";
}

/**
 * @tc.name: SvgFormatAgentPluginTest006
 * @tc.desc: svg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgFormatAgentPluginTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest006 start";
    ImagePlugin::SvgFormatAgent formatAgent;
    auto datasize = formatAgent.GetHeaderSize() - 10;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = SVG_FORMAT_TYPE;
    auto imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_SVG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    auto pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    
    auto ret = formatAgent.CheckFormat(pixelMap->GetPixels(), datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest006 end";
}
}
}