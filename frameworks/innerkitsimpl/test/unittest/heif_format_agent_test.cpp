/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "heif_format_agent.h"
#include "plugin_service.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

static constexpr uint32_t HEADER_SIZE = 32;
static constexpr uint32_t HEADER_SIZE_2 = 2;
static constexpr uint32_t DATA_SIZE_SMALL = 4;
static constexpr uint32_t DATA_SIZE_EIGHT = 8;
static constexpr size_t BYTES_READ_ELEVEN = 11;
static constexpr size_t BYTES_READ_SIXTEEN = 16;
static constexpr size_t BYTES_READ_TEN = 10;
static constexpr size_t HEIF64_LARGE_TEST_BUFFER_COUNT = 100;
static constexpr size_t HEIF64_DUAL_ELEMENT_BUFFER_COUNT = 2;
static constexpr size_t HEIF64_SINGLE_ELEMENT_BUFFER_COUNT = 1;
static constexpr size_t HEIF64_CHUNK_CORRECTION_BUFFER_COUNT = 4;
static constexpr uint64_t HEIF64_CHUNK_SIZE_1 = 1;
static constexpr uint64_t HEIF64_CHUNK_SIZE_10 = 10;
static constexpr uint64_t HEIF64_CHUNK_SIZE_20 = 20;
static constexpr uint32_t FOURCC_FTYP_BE = 0x70797466;
static constexpr uint32_t FOURCC_MIF1_BE = 0x3166696D;
static constexpr uint32_t FOURCC_HEIC_BE = 0x63696568;
static constexpr uint32_t FOURCC_XXXX_BE = 0x78787878;
static constexpr uint32_t FOURCC_YYYY_BE = 0x79797979;
static constexpr uint32_t CHUNK_SIZE_10_BE = 0x0A000000;
static constexpr uint32_t CHUNK_SIZE_16_BE = 0x10000000;
static constexpr uint32_t CHUNK_SIZE_24_BE = 0x18000000;
static constexpr uint32_t CHUNK_SIZE_32_BE = 0x20000000;
static constexpr uint32_t INVALID_CHUNK_TYPE_BE = 0x78563412;
static constexpr uint32_t MINOR_VERSION_123_BE = 0x7B000000;
static constexpr uint64_t CHUNK_SIZE_64_10_BE = 0x0A00000000000000ULL;
static constexpr uint64_t BUFFER_VALUE_0F_BE = 0x0F00000000000000ULL;

class HeifFormatAgentTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: CheckFormat001
 * @tc.desc: Test CheckFormat with invalid header data, expect CheckFormatHead return false.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, CheckFormat001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat001 start";
    HeifFormatAgent heifFormatAgent;
    uint32_t invalidHeaderData[] = {0};
    uint32_t dataSize = DATA_SIZE_SMALL;
    auto ret = heifFormatAgent.CheckFormat(invalidHeaderData, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat001 end";
}

/**
 * @tc.name: CheckFormat002
 * @tc.desc: Test memcpy_s failure, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, CheckFormat002, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat002 start";
    HeifFormatAgent heifFormatAgent;
    uint32_t headerData[HEADER_SIZE_2] = {0};
    uint32_t dataSize = DATA_SIZE_EIGHT;
    auto ret = heifFormatAgent.CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat002 end";
}

/**
 * @tc.name: CheckFormat003
 * @tc.desc: Test invalid chunk type, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, CheckFormat003, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat003 start";
    HeifFormatAgent heifFormatAgent;
    uint32_t headerData[HEADER_SIZE] = {
        0,
        INVALID_CHUNK_TYPE_BE,
    };
    uint32_t dataSize = HEADER_SIZE;
    auto ret = heifFormatAgent.CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat003 end";
}

/**
 * @tc.name: CheckFormat004
 * @tc.desc: Test IsHeif64 returns false, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, CheckFormat004, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat004 start";
    HeifFormatAgent heifFormatAgent;
    uint32_t headerData[HEADER_SIZE] = {0};
    uint32_t dataSize = HEADER_SIZE;
    auto ret = heifFormatAgent.CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat004 end";
}

/**
 * @tc.name: CheckFormat005
 * @tc.desc: Test chunkDataSize smaller than HEADER_LEAST_SIZE, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, CheckFormat005, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat005 start";
    HeifFormatAgent heifFormatAgent;
    uint32_t headerData[HEADER_SIZE] = {
        CHUNK_SIZE_10_BE,
        0,
    };
    uint32_t dataSize = HEADER_SIZE;
    auto ret = heifFormatAgent.CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat005 end";
}

/**
 * @tc.name: CheckFormat006
 * @tc.desc: Test numCompatibleBrands == 0 and non-zero, expect correct behavior.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, CheckFormat006, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat006 start";
    HeifFormatAgent heifFormatAgent;
    uint32_t dataSize = HEADER_SIZE;

    uint32_t headerDataZero[HEADER_SIZE] = {
        CHUNK_SIZE_16_BE,
        FOURCC_FTYP_BE,
        FOURCC_XXXX_BE,
        0,
    };
    auto ret = heifFormatAgent.CheckFormat(headerDataZero, dataSize);
    EXPECT_EQ(ret, false);

    uint32_t headerDataNonZero[HEADER_SIZE] = {
        CHUNK_SIZE_24_BE,
        FOURCC_FTYP_BE,
        FOURCC_MIF1_BE,
        0,
        FOURCC_XXXX_BE,
        FOURCC_YYYY_BE,
    };
    ret = heifFormatAgent.CheckFormat(headerDataNonZero, dataSize);
    EXPECT_EQ(ret, true);

    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat006 end";
}

/**
 * @tc.name: CheckFormat007
 * @tc.desc: Test valid compatible brand 'heic', expect return true.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, CheckFormat007, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat007 start";
    HeifFormatAgent heifFormatAgent;
    uint32_t headerData[HEADER_SIZE] = {
        CHUNK_SIZE_24_BE,
        FOURCC_FTYP_BE,
        FOURCC_XXXX_BE,
        MINOR_VERSION_123_BE,
        FOURCC_HEIC_BE,
        FOURCC_YYYY_BE,
    };
    uint32_t dataSize = HEADER_SIZE;
    auto ret = heifFormatAgent.CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat007 end";
}

/**
 * @tc.name: CheckFormat008
 * @tc.desc: Test i == MAX_LOOP_SIZE, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, CheckFormat008, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat008 start";
    HeifFormatAgent heifFormatAgent;
    uint32_t headerData[HEADER_SIZE] = {
        CHUNK_SIZE_32_BE,
        FOURCC_FTYP_BE,
        FOURCC_XXXX_BE,
        0,
        FOURCC_XXXX_BE,
        FOURCC_XXXX_BE,
        FOURCC_XXXX_BE,
        FOURCC_XXXX_BE,
    };
    uint32_t dataSize = HEADER_SIZE;
    auto ret = heifFormatAgent.CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: CheckFormat008 end";
}

/**
 * @tc.name: IsHeif64Test001
 * @tc.desc: Test CheckFormat with typical buffer and chunk size, expect return true.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, IsHeif64Test001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: IsHeif64Test001 start";
    HeifFormatAgent heifFormatAgent;
    uint64_t buffer[HEIF64_LARGE_TEST_BUFFER_COUNT] = {0};
    int64_t offset = 0;
    size_t bytesRead = BYTES_READ_ELEVEN;
    uint64_t chunkSize = HEIF64_CHUNK_SIZE_10;
    auto ret = heifFormatAgent.IsHeif64(buffer, bytesRead, offset, chunkSize);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: IsHeif64Test001 end";
}

/**
 * @tc.name: IsHeif64Test002
 * @tc.desc: chunkSize == 1 and 64-bit chunkSize < HEADER_NEXT_SIZE, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, IsHeif64Test002, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: IsHeif64Test002 start";
    HeifFormatAgent heifFormatAgent;
    uint64_t buffer[HEIF64_DUAL_ELEMENT_BUFFER_COUNT] = {
        0,
        CHUNK_SIZE_64_10_BE,
    };
    int64_t offset = DATA_SIZE_EIGHT;
    size_t bytesRead = BYTES_READ_SIXTEEN;
    uint64_t chunkSize = HEIF64_CHUNK_SIZE_1;
    auto ret = heifFormatAgent.IsHeif64(buffer, bytesRead, offset, chunkSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: IsHeif64Test002 end";
}

/**
 * @tc.name: IsHeif64Test003
 * @tc.desc: chunkSize == 1 and after EndianSwap64 < HEADER_NEXT_SIZE, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, IsHeif64Test003, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: IsHeif64Test003 start";
    HeifFormatAgent heifFormatAgent;
    uint64_t buffer[HEIF64_SINGLE_ELEMENT_BUFFER_COUNT] = {BUFFER_VALUE_0F_BE};
    int64_t offset = 0;
    size_t bytesRead = BYTES_READ_SIXTEEN;
    uint64_t chunkSize = HEIF64_CHUNK_SIZE_1;
    auto ret = heifFormatAgent.IsHeif64(buffer, bytesRead, offset, chunkSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: IsHeif64Test003 end";
}

/**
 * @tc.name: IsHeif64Test004
 * @tc.desc: chunkSize != 1 and < HEADER_LEAST_SIZE, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, IsHeif64Test004, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: IsHeif64Test004 start";
    HeifFormatAgent heifFormatAgent;
    uint64_t buffer[HEIF64_DUAL_ELEMENT_BUFFER_COUNT] = {0};
    int64_t offset = 0;
    size_t bytesRead = BYTES_READ_SIXTEEN;
    uint64_t chunkSize = DATA_SIZE_SMALL;
    auto ret = heifFormatAgent.IsHeif64(buffer, bytesRead, offset, chunkSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: IsHeif64Test004 end";
}

/**
 * @tc.name: IsHeif64Test005
 * @tc.desc: chunkSize > bytesRead, expect chunkSize corrected to bytesRead and return true.
 * @tc.type: FUNC
 */
HWTEST_F(HeifFormatAgentTest, IsHeif64Test005, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: IsHeif64Test005 start";
    HeifFormatAgent heifFormatAgent;
    uint64_t buffer[HEIF64_CHUNK_CORRECTION_BUFFER_COUNT] = {0};
    int64_t offset = 0;
    size_t bytesRead = BYTES_READ_TEN;
    uint64_t chunkSize = HEIF64_CHUNK_SIZE_20;
    auto ret = heifFormatAgent.IsHeif64(buffer, bytesRead, offset, chunkSize);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "HeifFormatAgentTest: IsHeif64Test005 end";
}
} // namespace ImagePlugin
} // namespace OHOS