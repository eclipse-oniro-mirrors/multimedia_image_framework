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
#include <securec.h>
#include "cr3_format_agent.h"
#include "plugin_service.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

static constexpr uint32_t HEADER_DATA_SIZE = 100;
static constexpr uint32_t SMALL_HEADER_DATA_SIZE = 10;
static constexpr uint32_t FTYP_SIZE = 12;
static constexpr uint8_t MOVE_BITS_8 = 8;
static constexpr uint8_t MOVE_BITS_16 = 16;
static constexpr uint8_t MOVE_BITS_24 = 24;
static constexpr uint8_t WRONG_UUID_SIZE_16 = 16;
static constexpr uint8_t FTYP_FLAG_OFFSET = 4;
static constexpr uint8_t CANON_UUID_FLAG_OFFSET = 28;
static constexpr uint8_t CANON_CR3_FLAG_OFFSET = 52;
static constexpr uint8_t FILE_TYPE_CRX_FLAG[] = {
    'f', 't', 'y', 'p', 'c', 'r', 'x', ' '
};
static constexpr uint8_t CANON_UUID_FLAG[] = {
    0x85, 0xC0, 0xB6, 0x87, 0x82, 0x0F, 0x11, 0xE0, 0x81, 0x11, 0xF4, 0xCE, 0x46, 0x2B, 0x6A, 0x48
};
static constexpr uint8_t CANON_CR3_FLAG[] = {
    'C', 'a', 'n', 'o', 'n', 'C', 'R', '3'
};

class Cr3FormatAgentTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: CheckFormatTest001
 * @tc.desc: Test CheckFormat with valid CR3 header, expect return true.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3FormatAgentTest, CheckFormatTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest001 start";
    auto cr3Agent = std::make_shared<Cr3FormatAgent>();
    uint32_t ftypSize = FTYP_SIZE;
    uint8_t headerData[HEADER_DATA_SIZE] = {(ftypSize >> MOVE_BITS_24) & 0xFF, (ftypSize >> MOVE_BITS_16) & 0xFF,
        (ftypSize >> MOVE_BITS_8) & 0xFF, ftypSize & 0xFF};

    auto memcpyRet1 = memcpy_s(headerData + FTYP_FLAG_OFFSET, HEADER_DATA_SIZE - FTYP_FLAG_OFFSET,
        FILE_TYPE_CRX_FLAG, sizeof(FILE_TYPE_CRX_FLAG));
    ASSERT_EQ(memcpyRet1, 0);

    auto memcpyRet2 = memcpy_s(headerData + CANON_UUID_FLAG_OFFSET, HEADER_DATA_SIZE - CANON_UUID_FLAG_OFFSET,
        CANON_UUID_FLAG, sizeof(CANON_UUID_FLAG));
    ASSERT_EQ(memcpyRet2, 0);

    auto memcpyRet3 = memcpy_s(headerData + CANON_CR3_FLAG_OFFSET, HEADER_DATA_SIZE - CANON_CR3_FLAG_OFFSET,
        CANON_CR3_FLAG, sizeof(CANON_CR3_FLAG));
    ASSERT_EQ(memcpyRet3, 0);

    uint32_t dataSize = sizeof(headerData);
    bool ret = cr3Agent->CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest001 end";
}

/**
 * @tc.name: CheckFormatTest002
 * @tc.desc: Test CheckFormat with invalid FILE_TYPE_CRX_FLAG, other fields valid, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3FormatAgentTest, CheckFormatTest002, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest002 start";
    auto cr3Agent = std::make_shared<Cr3FormatAgent>();
    uint32_t ftypSize = FTYP_SIZE;
    uint8_t headerData[HEADER_DATA_SIZE] = {(ftypSize >> MOVE_BITS_24) & 0xFF, (ftypSize >> MOVE_BITS_16) & 0xFF,
        (ftypSize >> MOVE_BITS_8) & 0xFF, ftypSize & 0xFF};
    uint8_t wrongFtyp[] = {'x', 'y', 'z', ' ', ' ', ' ', ' ', ' '};

    auto memcpyRet1 = memcpy_s(headerData + FTYP_FLAG_OFFSET, HEADER_DATA_SIZE - FTYP_FLAG_OFFSET,
        wrongFtyp, sizeof(wrongFtyp));
    ASSERT_EQ(memcpyRet1, 0);

    auto memcpyRet2 = memcpy_s(headerData + CANON_UUID_FLAG_OFFSET, HEADER_DATA_SIZE - CANON_UUID_FLAG_OFFSET,
        CANON_UUID_FLAG, sizeof(CANON_UUID_FLAG));
    ASSERT_EQ(memcpyRet2, 0);
    
    auto memcpyRet3 = memcpy_s(headerData + CANON_CR3_FLAG_OFFSET, HEADER_DATA_SIZE - CANON_CR3_FLAG_OFFSET,
        CANON_CR3_FLAG, sizeof(CANON_CR3_FLAG));
    ASSERT_EQ(memcpyRet3, 0);

    uint32_t dataSize = sizeof(headerData);
    bool ret = cr3Agent->CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest002 end";
}

/**
 * @tc.name: CheckFormatTest003
 * @tc.desc: Test CheckFormat with invalid CANON_UUID_FLAG (filled with zeros), other fields valid, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3FormatAgentTest, CheckFormatTest003, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest003 start";
    auto cr3Agent = std::make_shared<Cr3FormatAgent>();
    uint32_t ftypSize = FTYP_SIZE;
    uint8_t headerData[HEADER_DATA_SIZE] = {(ftypSize >> MOVE_BITS_24) & 0xFF, (ftypSize >> MOVE_BITS_16) & 0xFF,
        (ftypSize >> MOVE_BITS_8) & 0xFF, ftypSize & 0xFF};

    auto memcpyRet1 = memcpy_s(headerData + FTYP_FLAG_OFFSET, HEADER_DATA_SIZE - FTYP_FLAG_OFFSET,
        FILE_TYPE_CRX_FLAG, sizeof(FILE_TYPE_CRX_FLAG));
    ASSERT_EQ(memcpyRet1, 0);

    uint8_t wrongUUID[WRONG_UUID_SIZE_16] = {0};
    auto memcpyRet2 = memcpy_s(headerData + CANON_UUID_FLAG_OFFSET, HEADER_DATA_SIZE - CANON_UUID_FLAG_OFFSET,
        wrongUUID, sizeof(wrongUUID));
    ASSERT_EQ(memcpyRet2, 0);

    auto memcpyRet3 = memcpy_s(headerData + CANON_CR3_FLAG_OFFSET, HEADER_DATA_SIZE - CANON_CR3_FLAG_OFFSET,
        CANON_CR3_FLAG, sizeof(CANON_CR3_FLAG));
    ASSERT_EQ(memcpyRet3, 0);

    uint32_t dataSize = sizeof(headerData);
    bool ret = cr3Agent->CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest003 end";
}

/**
 * @tc.name: CheckFormatTest004
 * @tc.desc: Test CheckFormat with invalid CANON_CR3_FLAG, other fields valid, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3FormatAgentTest, CheckFormatTest004, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest004 start";

    auto cr3Agent = std::make_shared<Cr3FormatAgent>();
    uint32_t ftypSize = FTYP_SIZE;
    uint8_t headerData[HEADER_DATA_SIZE] = {(ftypSize >> MOVE_BITS_24) & 0xFF, (ftypSize >> MOVE_BITS_16) & 0xFF,
        (ftypSize >> MOVE_BITS_8) & 0xFF, ftypSize & 0xFF};

    auto memcpyRet1 = memcpy_s(headerData + FTYP_FLAG_OFFSET, HEADER_DATA_SIZE - FTYP_FLAG_OFFSET,
        FILE_TYPE_CRX_FLAG, sizeof(FILE_TYPE_CRX_FLAG));
    ASSERT_EQ(memcpyRet1, 0);

    auto memcpyRet2 = memcpy_s(headerData + CANON_UUID_FLAG_OFFSET, HEADER_DATA_SIZE - CANON_UUID_FLAG_OFFSET,
        CANON_UUID_FLAG, sizeof(CANON_UUID_FLAG));
    ASSERT_EQ(memcpyRet2, 0);

    uint8_t wrongCR3[] = {'X', 'Y', 'Z', '1', '2', '3', '4', '5'};
    auto memcpyRet3 = memcpy_s(headerData + CANON_CR3_FLAG_OFFSET, HEADER_DATA_SIZE - CANON_CR3_FLAG_OFFSET,
        wrongCR3, sizeof(wrongCR3));
    ASSERT_EQ(memcpyRet3, 0);

    uint32_t dataSize = sizeof(headerData);
    bool ret = cr3Agent->CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest004 end";
}

/**
 * @tc.name: CheckFormatTest005
 * @tc.desc: Test CheckFormat with nullptr headerData (invalid input), expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3FormatAgentTest, CheckFormatTest005, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest005 start";
    auto cr3Agent = std::make_shared<Cr3FormatAgent>();
    uint32_t dataSize = HEADER_DATA_SIZE;
    bool ret = cr3Agent->CheckFormat(nullptr, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest005 end";
}

/**
 * @tc.name: CheckFormatTest006
 * @tc.desc: Test CheckFormat with header data size smaller than CR3_HEADER_SIZE, expect return false.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3FormatAgentTest, CheckFormatTest006, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest006 start";
    auto cr3Agent = std::make_shared<Cr3FormatAgent>();
    uint8_t headerData[SMALL_HEADER_DATA_SIZE] = {0};
    uint32_t dataSize = sizeof(headerData);
    bool ret = cr3Agent->CheckFormat(headerData, dataSize);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "Cr3FormatAgentTest: CheckFormatTest006 end";
}
} // namespace ImagePlugin
} // namespace OHOS