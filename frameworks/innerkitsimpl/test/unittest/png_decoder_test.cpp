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
#include "png_decoder.h"
#include "media_errors.h"
#include "securec.h"
#include "memory.h"

using namespace testing::ext;
namespace OHOS {
namespace Multimedia {
class PngDecoderTest : public testing::Test {
public:
    PngDecoderTest() {}
    ~PngDecoderTest() {}
};

/**
 * @tc.name: HasProperty001
 * @tc.desc: test HasProperty
 * @tc.type: FUNC
 */
HWTEST_F(PngDecoderTest, HasProperty001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngDecoderTest: HasProperty001 start";
    ImagePlugin::PngDecoder pngdcod;
    std::string key = "";
    bool haspro = pngdcod.HasProperty(key);
    ASSERT_EQ(haspro, false);
    GTEST_LOG_(INFO) << "PngDecoderTest: HasProperty001 end";
}
} // namespace Multimedia
} // namespace OHOS