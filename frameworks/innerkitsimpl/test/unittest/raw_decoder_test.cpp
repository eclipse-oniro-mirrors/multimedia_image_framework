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
#include "raw_decoder.h"
#include "raw_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Multimedia {
class RawDecoderTest : public testing::Test {
public:
    RawDecoderTest() {}
    ~RawDecoderTest() {}
};

/**
 * @tc.name: RawDecoderTest001
 * @tc.desc: HasProperty
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest001 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    string key = "1";
    bool res = rawDecoder->HasProperty(key);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest001 end";
}

/**
 * @tc.name: RawDecoderTest002
 * @tc.desc: PromoteIncrementalDecode
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest002 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    ProgDecodeContext progContext;
    uint32_t index = 1;
    uint32_t res = rawDecoder->PromoteIncrementalDecode(index, progContext);
    ASSERT_EQ(res, ERR_IMAGE_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest002 end";
}

/**
 * @tc.name: RawDecoderTest003
 * @tc.desc: GetTopLevelImageNum
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest003 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 1;
    uint32_t res = rawDecoder->GetTopLevelImageNum(index);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest003 end";
}

/**
 * @tc.name: RawDecoderTest004
 * @tc.desc: SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest004 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 1;
    const PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t res = rawDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(res, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest004 end";
}

/**
 * @tc.name: RawDecoderTest005
 * @tc.desc: SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest005 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    const PixelDecodeOptions opts;
    PlImageInfo info;
    uint32_t res = rawDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(res, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest005 end";
}

/**
 * @tc.name: RawDecoderTest006
 * @tc.desc: GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest006 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    PlSize size;
    size.width = 3;
    size.height = 4;
    uint32_t res = rawDecoder->GetImageSize(index, size);
    ASSERT_EQ(res, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest006 end";
}

/**
 * @tc.name: RawDecoderTest007
 * @tc.desc: Decode
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest007 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 0;
    DecodeContext context;
    uint32_t res = rawDecoder->Decode(index, context);
    ASSERT_EQ(res, ERR_MEDIA_INVALID_OPERATION);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest007 end";
}

/**
 * @tc.name: RawDecoderTest008
 * @tc.desc: Decode
 * @tc.type: FUNC
 */
HWTEST_F(RawDecoderTest, RawDecoderTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest008 start";
    auto rawDecoder = std::make_shared<RawDecoder>();
    uint32_t index = 1;
    DecodeContext context;
    uint32_t res = rawDecoder->Decode(index, context);
    ASSERT_EQ(res, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "RawDecoderTest: RawDecoderTest008 end";
}
}
}