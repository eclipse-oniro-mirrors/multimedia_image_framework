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
#include <fstream>
#include "parcel.h"

using namespace testing::ext;
namespace OHOS {
namespace Multimedia {
static const size_t SIZE_TEST = 0;
class MockParcelTest : public testing::Test {
public:
    MockParcelTest() {}
    ~MockParcelTest() {}
};

/**
 * @tc.name: GetDataCapacity001
 * @tc.desc: test GetDataCapacity
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, GetDataCapacity001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: GetDataCapacity001 start";
    Parcel parcel;
    size_t gd = parcel.GetDataCapacity();
    ASSERT_EQ(gd, 0);
    GTEST_LOG_(INFO) << "MockParcelTest: GetDataCapacity001 end";
}

/**
 * @tc.name: SetDataCapacity001
 * @tc.desc: test SetDataCapacity
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, SetDataCapacity001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: SetDataCapacity001 start";
    Parcel parcel;
    size_t newCapacity = 3;
    bool setdc = parcel.SetDataCapacity(newCapacity);
    ASSERT_EQ(setdc, false);
    GTEST_LOG_(INFO) << "MockParcelTest: SetDataCapacity001 end";
}

/**
 * @tc.name: WriteUnpadBuffer001
 * @tc.desc: test WriteUnpadBuffer
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, WriteUnpadBuffer001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: WriteUnpadBuffer001 start";
    Parcel parcel;
    void *data = nullptr;
    size_t size = 7;
    bool wub = parcel.WriteUnpadBuffer(data, size);
    ASSERT_EQ(wub, false);
    GTEST_LOG_(INFO) << "MockParcelTest: WriteUnpadBuffer001 end";
}

/**
 * @tc.name: WriteInt32001
 * @tc.desc: test WriteInt32
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, WriteInt32001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: WriteInt32001 start";
    Parcel parcel;
    int32_t value = 0;
    bool writein = parcel.WriteInt32(value);
    ASSERT_EQ(writein, false);
    GTEST_LOG_(INFO) << "MockParcelTest: WriteInt32001 end";
}

/**
 * @tc.name: ReadBuffer001
 * @tc.desc: test ReadBuffer
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, ReadBuffer001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: ReadBuffer001 start";
    Parcel parcel;
    size_t length = 6;
    const uint8_t *rbuffer = parcel.ReadBuffer(length);
    ASSERT_EQ(rbuffer, nullptr);
    GTEST_LOG_(INFO) << "MockParcelTest: ReadBuffer001 end";
}
} // namespace Multimedia
} // namespace OHOS