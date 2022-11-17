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
#include <cmath>
#include <log_tags.h>
#include "hilog/log.h"
#include "securec.h"
#include "memory.h"
#include "nine_patch_listener.h"

using namespace testing::ext;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Multimedia {
class NinePathListenerTest : public testing::Test {
public:
    NinePathListenerTest() {}
    ~NinePathListenerTest() {}
};

/**
 * @tc.name: ReadChunk001
 * @tc.desc: test ReadChunk
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, ReadChunk001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk001 start";
    ImagePlugin::NinePatchListener ninepath;
    const std::string tag = "";
    void *data = nullptr;
    ASSERT_EQ(data, nullptr);
    size_t length = 1;
    bool readck = ninepath.ReadChunk(tag, data, length);
    ASSERT_EQ(readck, true);
    GTEST_LOG_(INFO) << "NinePathListenerTest: ReadChunk001 end";
}

/**
 * @tc.name: Scale001
 * @tc.desc: test Scale
 * @tc.type: FUNC
 */
HWTEST_F(NinePathListenerTest, Scale001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NinePathListenerTest: Scale001 start";
    ImagePlugin::NinePatchListener ninepath;
    float scaleX = 1.0;
    float scaleY = 2.0;
    int32_t scaledWidth = 3;
    int32_t scaledHeight = 4;
    ninepath.Scale(scaleX, scaleY, scaledWidth, scaledHeight);
    GTEST_LOG_(INFO) << "NinePathListenerTest: Scale001 end";
}
} // namespace Multimedia
} // namespace OHOS