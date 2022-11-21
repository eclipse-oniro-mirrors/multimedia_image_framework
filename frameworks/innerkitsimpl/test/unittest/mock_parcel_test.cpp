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
 * @tc.name: GetWritableBytes001
 * @tc.desc: test GetWritableBytes
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, GetWritableBytes001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: GetWritableBytes001 start";
    Parcel parcel;
    const size_t gw = parcel.GetWritableBytes();
    ASSERT_EQ(gw, SIZE_TEST);
    GTEST_LOG_(INFO) << "MockParcelTest: GetWritableBytes001 end";
}

/**
 * @tc.name: GetReadableBytes001
 * @tc.desc: test GetReadableBytes
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, GetReadableBytes001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: GetReadableBytes001 start";
    Parcel parcel;
    const size_t gr = parcel.GetReadableBytes();
    ASSERT_EQ(gr, SIZE_TEST);
    GTEST_LOG_(INFO) << "MockParcelTest: GetReadableBytes001 end";
}

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
 * @tc.name: SetMaxCapacity001
 * @tc.desc: test SetMaxCapacity
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, SetMaxCapacity001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: SetMaxCapacity001 start";
    Parcel parcel;
    size_t maxCapacity = 1;
    bool smc = parcel.SetMaxCapacity(maxCapacity);
    ASSERT_EQ(smc, false);
    GTEST_LOG_(INFO) << "MockParcelTest: SetMaxCapacity001 end";
}

/**
 * @tc.name: SetAllocator001
 * @tc.desc: test SetAllocator
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, SetAllocator001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: SetAllocator001 start";
    Parcel parcel;
    Allocator *allocator = nullptr;
    bool seta = parcel.SetAllocator(allocator);
    ASSERT_EQ(seta, true);
    GTEST_LOG_(INFO) << "MockParcelTest: SetAllocator001 end";
}

/**
 * @tc.name: CheckOffsets001
 * @tc.desc: test CheckOffsets
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, CheckOffsets001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: CheckOffsets001 start";
    Parcel parcel;
    bool checkof = parcel.CheckOffsets();
    ASSERT_EQ(checkof, false);
    GTEST_LOG_(INFO) << "MockParcelTest: CheckOffsets001 end";
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
 * @tc.name: SetDataSize001
 * @tc.desc: test SetDataSize
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, SetDataSize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: SetDataSize001 start";
    Parcel parcel;
    size_t dataSize = 4;
    bool setds = parcel.SetDataSize(dataSize);
    ASSERT_EQ(setds, true);
    GTEST_LOG_(INFO) << "MockParcelTest: SetDataSize001 end";
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
 * @tc.name: WriteUint32001
 * @tc.desc: test WriteUint32
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, WriteUint32001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: WriteUint32001 start";
    Parcel parcel;
    uint32_t value = 1;
    bool writeuin = parcel.WriteUint32(value);
    ASSERT_EQ(writeuin, false);
    GTEST_LOG_(INFO) << "MockParcelTest: WriteUint32001 end";
}

/**
 * @tc.name: WriteRemoteObject001
 * @tc.desc: test WriteRemoteObject
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, WriteRemoteObject001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: WriteRemoteObject001 start";
    Parcel parcel;
    Parcelable *object = nullptr;
    bool wrob = parcel.WriteRemoteObject(object);
    ASSERT_EQ(wrob, false);
    GTEST_LOG_(INFO) << "MockParcelTest: WriteRemoteObject001 end";
}

/**
 * @tc.name: WriteParcelable001
 * @tc.desc: test WriteParcelable
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, WriteParcelable001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: WriteParcelable001 start";
    Parcel parcel;
    Parcelable *object = nullptr;
    bool wplab = parcel.WriteParcelable(object);
    ASSERT_EQ(wplab, false);
    GTEST_LOG_(INFO) << "MockParcelTest: WriteParcelable001 end";
}

/**
 * @tc.name: ParseFrom001
 * @tc.desc: test ParseFrom
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, ParseFrom001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: ParseFrom001 start";
    Parcel parcel;
    uintptr_t data = 0;
    size_t size = 1;
    bool parf = parcel.ParseFrom(data, size);
    ASSERT_EQ(parf, false);
    GTEST_LOG_(INFO) << "MockParcelTest: ParseFrom001 end";
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

/**
 * @tc.name: ReadUnpadBuffer001
 * @tc.desc: test ReadUnpadBuffer
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, ReadUnpadBuffer001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: ReadUnpadBuffer001 start";
    Parcel parcel;
    size_t length = 8;
    const uint8_t *rubuffer = parcel.ReadUnpadBuffer(length);
    ASSERT_EQ(rubuffer, nullptr);
    GTEST_LOG_(INFO) << "MockParcelTest: ReadUnpadBuffer001 end";
}

/**
 * @tc.name: GetReadPosition001
 * @tc.desc: test GetReadPosition
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, GetReadPosition001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: GetReadPosition001 start";
    Parcel parcel;
    size_t getreadp = parcel.GetReadPosition();
    ASSERT_EQ(getreadp, 0);
    GTEST_LOG_(INFO) << "MockParcelTest: GetReadPosition001 end";
}

/**
 * @tc.name: ReadInt32001
 * @tc.desc: test ReadInt32
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, ReadInt32001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: ReadInt32001 start";
    Parcel parcel;
    int32_t readint1 = parcel.ReadInt32();
    ASSERT_EQ(readint1, 0);
    GTEST_LOG_(INFO) << "MockParcelTest: ReadInt32001 end";
}

/**
 * @tc.name: ReadUint32001
 * @tc.desc: test ReadUint32
 * @tc.type: FUNC
 */
HWTEST_F(MockParcelTest, ReadUint32001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockParcelTest: ReadUint32001 start";
    Parcel parcel;
    uint32_t readint2 = parcel.ReadUint32();
    ASSERT_EQ(readint2, 0);
    GTEST_LOG_(INFO) << "MockParcelTest: ReadUint32001 end";
}
} // namespace Multimedia
} // namespace OHOS