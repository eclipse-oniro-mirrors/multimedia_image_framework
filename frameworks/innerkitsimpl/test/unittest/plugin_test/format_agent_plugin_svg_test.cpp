/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

class FormatAgentPluginSvgTest : public testing::Test {};

/**
 * @tc.name: SvgGetFormatTypeTest
 * @tc.desc: svg GetFormatType
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgGetFormatTypeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest start";
    ImagePlugin::SvgFormatAgent formatAgent;
    auto ret = formatAgent.GetFormatType();
    ASSERT_EQ(ret, SVG_FORMAT_TYPE);
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest end";
}

/**
 * @tc.name: SvgGetHeaderSize
 * @tc.desc: svg GetHeaderSize
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgGetHeaderSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest002 start";
    ImagePlugin::SvgFormatAgent formatAgent;
    auto ret = formatAgent.GetHeaderSize();
    ASSERT_EQ(ret, sizeof(SVG_HEADER));
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgFormatAgentPluginTest002 end";
}

/**
 * @tc.name: SvgCheckFormatTest
 * @tc.desc: svg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgCheckFormatTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgCheckFormatTest start";
    ImagePlugin::SvgFormatAgent formatAgent;
    auto datasize = formatAgent.GetHeaderSize();
    void *headerData = nullptr;
    auto ret = formatAgent.CheckFormat(headerData, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgCheckFormatTest end";
}

/**
 * @tc.name: SvgCreatePixelMapTest
 * @tc.desc: svg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgCreatePixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgCreatePixelMapTest start";
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
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgCreatePixelMapTest end";
}

/**
 * @tc.name: SvgCheckFormat
 * @tc.desc: svg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgCheckFormat, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgCheckFormat start";
    ImagePlugin::SvgFormatAgent formatAgent;
    auto datasize = formatAgent.GetHeaderSize();
    auto ret = formatAgent.CheckFormat(nullptr, datasize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgCheckFormat end";
}

/**
 * @tc.name: SvgGetPixelsTest
 * @tc.desc: svg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgGetPixelsTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgGetPixelsTest start";
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
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgGetPixelsTest end";
}

/**
 * @tc.name: SvgCheckFormatTest002
 * @tc.desc: svg CheckFormat
 * @tc.type: FUNC
 */
HWTEST_F(FormatAgentPluginSvgTest, SvgCheckFormatTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgCheckFormatTest002 start";
    ImagePlugin::SvgFormatAgent formatAgent;
    uint32_t data = 0;
    void *headerData = &data;
    ASSERT_NE(headerData, nullptr);
    uint32_t dataSize = 4;
    auto ret = formatAgent.CheckFormat(headerData, dataSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormatAgentPluginSvgTest: SvgCheckFormatTest002 end";
}
}
}