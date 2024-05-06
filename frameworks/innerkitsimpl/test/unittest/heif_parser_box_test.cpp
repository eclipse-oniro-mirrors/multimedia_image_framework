/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#define protected public
#include <gtest/gtest.h>
#include "item_data_box.h"
#include "item_property_transform_box.h"
#include "item_property_color_box.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {
class HeifParserBoxTest : public testing::Test {
public:
    HeifParserBoxTest() {}
    ~HeifParserBoxTest() {}
};

/**
 * @tc.name: ParseContentTest001
 * @tc.desc: HeifImirBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, ParseContentTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest001 start";
    HeifImirBox heifImirBox;
    auto stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, true);
    HeifStreamReader reader(stream, 0, 0);
    heifImirBox.ParseContent(reader);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: ParseContentTest001 end";
}

/**
 * @tc.name: WriteTest001
 * @tc.desc: HeifImirBox
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, WriteTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest001 start";
    HeifImirBox heifImirBox;
    heifImirBox.direction_ = HeifTransformMirrorDirection::INVALID;
    HeifStreamWriter write;
    heif_error ret = heifImirBox.Write(write);
    ASSERT_EQ(ret, heif_invalid_mirror_direction);
    heifImirBox.direction_ = HeifTransformMirrorDirection::HORIZONTAL;
    ret = heifImirBox.Write(write);
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest001 end";
}

/**
 * @tc.name: WriteTest002
 * @tc.desc: HeifNclxColorProfile
 * @tc.type: FUNC
 */
HWTEST_F(HeifParserBoxTest, WriteTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest002 start";
    HeifNclxColorProfile heifNclx(0, 0, 0, 0);
    HeifStreamWriter write;
    heif_error ret = heifNclx.Write(write);
    ASSERT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "HeifParserBoxTest: WriteTest002 end";
}
}
}