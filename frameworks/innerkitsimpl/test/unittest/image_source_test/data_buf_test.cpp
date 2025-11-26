/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "data_buf.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
static const size_t MOCKOFFSET = 4;
static const size_t MOCKSIZE = 4;
static const size_t DATA_BUFFER_SIZE = 2;
static const size_t OFFSET = 100;
static const size_t INVALID_BUFFER_SIZE = -10;
static const size_t COMPARE_FAIL = -1;
class DataBufTest : public testing::Test {
public:
    DataBufTest() {}
    ~DataBufTest() override {}
};

/**
 * @tc.name: DataBufTest_Write001
 * @tc.desc: 验证DataBuf的write_uint8函数
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, DataBufTest_Write001, TestSize.Level3)
{
    DataBuf dataBuf(10);
    dataBuf.WriteUInt8(0, 123);
    EXPECT_EQ(dataBuf.ReadUInt8(0), 123);
}

/**
 * @tc.name: DataBufTest_GetUShort001
 * @tc.desc: Validate the GetUShort function of DataBuf
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, DataBufTest_GetUShort001, TestSize.Level3)
{
    // Define test data
    byte buf[2] = {0x01, 0x02};

    // Test the littleEndian case
    uint16_t result = GetUShort(buf, littleEndian);
    ASSERT_EQ(result, 0x0201);

    // Test the bigEndian case
    result = GetUShort(buf, bigEndian);
    ASSERT_EQ(result, 0x0102);
}

/**
 * @tc.name: DataBufTest_US2Data001
 * @tc.desc: Validate the US2Data function of DataBuf
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, DataBufTest_US2Data001, TestSize.Level3)
{
    // Define test data
    byte buf[2];
    uint16_t value = 0x0201;

    // Test the littleEndian case
    US2Data(buf, value, littleEndian);
    ASSERT_EQ(buf[0], 0x01);
    ASSERT_EQ(buf[1], 0x02);

    // Test the bigEndian case
    US2Data(buf, value, bigEndian);
    ASSERT_EQ(buf[0], 0x02);
    ASSERT_EQ(buf[1], 0x01);
}

/**
 * @tc.name: DataBufTest_UL2Data001
 * @tc.desc: Validate the UL2Data function of DataBuf
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, DataBufTest_UL2Data001, TestSize.Level3)
{
    // Define test data
    byte buf[4];
    uint32_t value = 0x04030201;

    // Test the littleEndian case
    UL2Data(buf, value, littleEndian);
    ASSERT_EQ(buf[0], 0x01);
    ASSERT_EQ(buf[1], 0x02);
    ASSERT_EQ(buf[2], 0x03);
    ASSERT_EQ(buf[3], 0x04);

    // Test the bigEndian case
    UL2Data(buf, value, bigEndian);
    ASSERT_EQ(buf[0], 0x04);
    ASSERT_EQ(buf[1], 0x03);
    ASSERT_EQ(buf[2], 0x02);
    ASSERT_EQ(buf[3], 0x01);
}

/**
 * @tc.name: DataBufTest_GetULong001
 * @tc.desc: Validate the GetULong function of DataBuf
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, DataBufTest_GetULong001, TestSize.Level3)
{
    // Define test data
    byte buf[4] = {0x01, 0x02, 0x03, 0x04};

    // Test the littleEndian case
    uint32_t result = GetULong(buf, littleEndian);
    ASSERT_EQ(result, 0x04030201);

    // Test the bigEndian case
    result = GetULong(buf, bigEndian);
    ASSERT_EQ(result, 0x01020304);
}

/**
 * @tc.name: ReadUInt8Test002
 * @tc.desc: Verify that DataBuf call ReadUInt8 when offset larger than pData_.size().
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, ReadUInt8Test002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DataBufTest: ReadUInt8Test002 start";
    DataBuf dataBuf;
    auto ret = dataBuf.ReadUInt8(MOCKOFFSET);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "DataBufTest: ReadUInt8Test002 end";
}

/**
 * @tc.name: ReadUInt32Test002
 * @tc.desc: Verify that DataBuf call ReadUInt32 when pData_.size() less than UINT32_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, ReadUInt32Test002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DataBufTest: ReadUInt32Test002 start";
    DataBuf dataBuf;
    auto ret = dataBuf.ReadUInt32(MOCKOFFSET, ByteOrder::invalidByteOrder);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "DataBufTest: ReadUInt32Test002 end";
}

/**
 * @tc.name: CmpBytesTest002
 * @tc.desc: Verify that DataBuf call CmpBytes when offset larger than pData_.size().
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, CmpBytesTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DataBufTest: CmpBytesTest002 start";
    DataBuf dataBuf;
    auto ret = dataBuf.CmpBytes(MOCKOFFSET, nullptr, MOCKSIZE);
    ASSERT_EQ(ret, -1);
    GTEST_LOG_(INFO) << "DataBufTest: CmpBytesTest002 end";
}

/**
 * @tc.name: CmpBytesTest003
 * @tc.desc: Test the CmpBytes return -1 when bufsize is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, CmpBytesTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DataBufTest: CmpBytesTest003 start";
    const void *buf = nullptr;
    DataBuf dataBuf(DATA_BUFFER_SIZE);
    int ret = dataBuf.CmpBytes(OFFSET, buf, INVALID_BUFFER_SIZE);
    ASSERT_EQ(ret, COMPARE_FAIL);
    GTEST_LOG_(INFO) << "DataBufTest: CmpBytesTest003 end";
}

/**
 * @tc.name: ReadUInt8Test001
 * @tc.desc: test the ReadUInt8 function of DataBuf
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, ReadUInt8Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DataBufTest: ReadUInt8Test001 start";
    size_t size = 2;
    size_t offset = 4;
    DataBuf dataBuf(size);
    uint8_t ret = dataBuf.ReadUInt8(offset);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "DataBufTest: ReadUInt8Test001 end";
}

/**
 * @tc.name: ReadUInt32Test001
 * @tc.desc: test the ReadUInt32 function of DataBuf
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, ReadUInt32Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DataBufTest: ReadUInt32Test001 start";
    size_t size = 2;
    size_t offset = 4;
    ByteOrder byteOrder = littleEndian;
    DataBuf dataBuf(size);
    uint32_t ret = dataBuf.ReadUInt32(offset, byteOrder);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "DataBufTest: ReadUInt32Test001 end";
}

/**
 * @tc.name: CmpBytesTest001
 * @tc.desc: test the CmpBytes function of DataBuf
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, CmpBytesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DataBufTest: CmpBytesTest001 start";
    size_t size = 2;
    size_t offset = 4;
    const void *buf = nullptr;
    size_t bufsize = 8;
    DataBuf dataBuf(size);
    int ret = dataBuf.CmpBytes(offset, buf, bufsize);
    ASSERT_EQ(ret, -1);
    GTEST_LOG_(INFO) << "DataBufTest: CmpBytesTest001 end";
}

/**
 * @tc.name: CDataTest001
 * @tc.desc: test the CData function of DataBuf
 * @tc.type: FUNC
 */
HWTEST_F(DataBufTest, CDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DataBufTest: CDataTest001 start";
    size_t size = 2;
    size_t offset = 4;
    DataBuf dataBuf(size);
    const byte *ret = dataBuf.CData(offset);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "DataBufTest: CDataTest001 end";
}
} // namespace Media
} // namespace OHOS