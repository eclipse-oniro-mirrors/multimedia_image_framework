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
#include <arpa/inet.h>
#include <fstream>
#include "png_ninepatch_res.h"

using namespace testing::ext;
namespace OHOS {
namespace Multimedia {
class PngNinepatchResTest : public testing::Test {
public:
    PngNinepatchResTest() {}
    ~PngNinepatchResTest() {}
};

/**
 * @tc.name: DeviceToFile001
 * @tc.desc: test DeviceToFile
 * @tc.type: FUNC
 */
HWTEST_F(PngNinepatchResTest, DeviceToFile001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngNinepatchResTest: DeviceToFile001 start";
    ImagePlugin::PngNinePatchRes pngnp;
    pngnp.DeviceToFile();
    GTEST_LOG_(INFO) << "PngNinepatchResTest: DeviceToFile001 end";
}

/**
 * @tc.name: FileToDevice001
 * @tc.desc: test FileToDevice
 * @tc.type: FUNC
 */
HWTEST_F(PngNinepatchResTest, FileToDevice001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngNinepatchResTest: FileToDevice001 start";
    ImagePlugin::PngNinePatchRes pngnp;
    pngnp.FileToDevice();
    GTEST_LOG_(INFO) << "PngNinepatchResTest: FileToDevice001 end";
}

/**
 * @tc.name: SerializedSize001
 * @tc.desc: test SerializedSize
 * @tc.type: FUNC
 */
HWTEST_F(PngNinepatchResTest, SerializedSize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PngNinepatchResTest: SerializedSize001 start";
    ImagePlugin::PngNinePatchRes pngnp;
    const size_t sersize = pngnp.SerializedSize();
    ASSERT_EQ(sersize, 32);
    GTEST_LOG_(INFO) << "PngNinepatchResTest: SerializedSize001 end";
}
} // namespace Multimedia
} // namespace OHOS