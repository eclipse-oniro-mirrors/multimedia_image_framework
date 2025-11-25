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
#include <vector>
#include "heif_stream.h"
#include "heif_constant.h"

using namespace testing::ext;

static constexpr size_t STREAM_LEN_DEFAULT = 100;
static constexpr size_t STREAM_LEN_SMALL = 5;
static constexpr size_t STREAM_LEN_MINI = 1;
static constexpr size_t LENGTH_VALID = 1;
static constexpr size_t LENGTH_SIZE_MAX = SIZE_MAX;
static constexpr int64_t SEEK_POS_OVER = 10;
static constexpr int64_t SEEK_POS_NEG1 = -1;
static constexpr int64_t SEEK_POS_NEG2 = -2;
static constexpr int64_t SEEK_POS_VALID = 3;
static constexpr uint32_t ERROR_TARGET_SIZE = static_cast<uint32_t>(-1);

namespace OHOS {
namespace ImagePlugin {

class HeifStreamTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: CheckSizeTest001
 * @tc.desc: CheckSize with invalid target_size, expect false
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, CheckSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: CheckSizeTest001 start";
    uint8_t data[STREAM_LEN_DEFAULT] = {0};
    size_t size = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifBufferInputStream> heifBufferInputStream =
        std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    heifBufferInputStream->pos_ = 0;
    size_t targetSize = ERROR_TARGET_SIZE;
    int64_t end = 0;
    auto ret = heifBufferInputStream->CheckSize(targetSize, end);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifStreamTest: CheckSizeTest001 end";
}

/**
 * @tc.name: ReadTest001
 * @tc.desc: Read when memcpy_s fails, expect false
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, ReadTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: ReadTest001 start";
    uint8_t* data = nullptr;
    size_t size = 0;
    bool needCopy = false;
    std::shared_ptr<HeifBufferInputStream> heifBufferInputStream =
        std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    heifBufferInputStream->pos_ = 0;
    heifBufferInputStream->length_ = LENGTH_VALID;
    auto ret = heifBufferInputStream->Read(data, size);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifStreamTest: ReadTest001 end";
}

/**
 * @tc.name: SeekTest001
 * @tc.desc: Seek: (pos>length) true, (pos<0) false, expect false
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, SeekTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: SeekTest001 start";
    uint8_t data[STREAM_LEN_SMALL] = {1, 2, 3, 4, 5};
    std::shared_ptr<HeifBufferInputStream> stream =
        std::make_shared<HeifBufferInputStream>(data, STREAM_LEN_SMALL, false);

    int64_t position = SEEK_POS_OVER;
    bool ret = stream->Seek(position);

    EXPECT_EQ(ret, false);
    EXPECT_EQ(stream->pos_, 0);
    GTEST_LOG_(INFO) << "HeifStreamTest: SeekTest001 end";
}

/**
 * @tc.name: SeekTest002
 * @tc.desc: Seek: (pos>length) false, (pos<0) true, expect false
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, SeekTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: SeekTest002 start";
    uint8_t data[STREAM_LEN_MINI] = {0};
    std::shared_ptr<HeifBufferInputStream> stream =
        std::make_shared<HeifBufferInputStream>(data, STREAM_LEN_MINI, false);
    stream->length_ = LENGTH_SIZE_MAX;

    int64_t position = SEEK_POS_NEG1;
    bool ret = stream->Seek(position);

    EXPECT_EQ(ret, false);
    EXPECT_EQ(stream->pos_, 0);
    GTEST_LOG_(INFO) << "HeifStreamTest: SeekTest002 end";
}

/**
 * @tc.name: SeekTest003
 * @tc.desc: Seek: (pos>length) true, (pos<0) true, expect false
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, SeekTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: SeekTest003 start";
    uint8_t data[STREAM_LEN_SMALL] = {0};
    std::shared_ptr<HeifBufferInputStream> stream =
        std::make_shared<HeifBufferInputStream>(data, STREAM_LEN_SMALL, false);

    int64_t position = SEEK_POS_NEG2;
    bool ret = stream->Seek(position);

    EXPECT_EQ(ret, false);
    EXPECT_EQ(stream->pos_, 0);
    GTEST_LOG_(INFO) << "HeifStreamTest: SeekTest003 end";
}

/**
 * @tc.name: SeekTest004
 * @tc.desc: Seek: (pos>length) false, (pos<0) false, expect true
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, SeekTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: SeekTest004 start";
    uint8_t data[STREAM_LEN_SMALL] = {0};
    std::shared_ptr<HeifBufferInputStream> stream =
        std::make_shared<HeifBufferInputStream>(data, STREAM_LEN_SMALL, false);

    int64_t position = SEEK_POS_VALID;
    bool ret = stream->Seek(position);

    EXPECT_EQ(ret, true);
    EXPECT_EQ(stream->pos_, position);
    GTEST_LOG_(INFO) << "HeifStreamTest: SeekTest004 end";
}

/**
 * @tc.name: Read8Test001
 * @tc.desc: Read8 when stream->Read fails, expect return 0 and set hasError_ to true
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, Read8Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: Read8Test001 start";

    uint8_t* nullData = nullptr;
    size_t streamSize = 0;
    bool needCopy = false;
    std::shared_ptr<HeifBufferInputStream> heifBufferInputStream =
        std::make_shared<HeifBufferInputStream>(nullData, streamSize, needCopy);

    heifBufferInputStream->pos_ = 0;
    heifBufferInputStream->length_ = 1;
    std::shared_ptr<HeifInputStream> inputStream = heifBufferInputStream;
    int64_t readerStart = 0;
    size_t readerLength = 0;
    std::shared_ptr<HeifStreamReader> heifStreamReader =
        std::make_shared<HeifStreamReader>(inputStream, readerStart, readerLength);

    heifStreamReader->end_ = readerStart + 1;
    heifStreamReader->hasError_ = false;
    auto ret = heifStreamReader->Read8();
    EXPECT_EQ(ret, 0U);
    EXPECT_EQ(heifStreamReader->hasError_, true);
    GTEST_LOG_(INFO) << "HeifStreamTest: Read8Test001 end";
}

/**
 * @tc.name: Read16Test001
 * @tc.desc: Read16 when stream->Read fails, expect return 0 and set hasError_ to true
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, Read16Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: Read16Test001 start";
    uint8_t* nullData = nullptr;
    size_t streamSize = 0;
    bool needCopy = false;
    std::shared_ptr<HeifBufferInputStream> heifBufferInputStream =
        std::make_shared<HeifBufferInputStream>(nullData, streamSize, needCopy);
    heifBufferInputStream->pos_ = 0;
    heifBufferInputStream->length_ = UINT16_BYTES_NUM;

    std::shared_ptr<HeifInputStream> inputStream = heifBufferInputStream;
    int64_t readerStart = 0;
    size_t readerLength = 0;
    std::shared_ptr<HeifStreamReader> heifStreamReader =
        std::make_shared<HeifStreamReader>(inputStream, readerStart, readerLength);

    heifStreamReader->end_ = readerStart + UINT16_BYTES_NUM;
    heifStreamReader->hasError_ = false;
    auto ret = heifStreamReader->Read16();
    EXPECT_EQ(ret, 0U);
    EXPECT_EQ(heifStreamReader->hasError_, true);
    GTEST_LOG_(INFO) << "HeifStreamTest: Read16Test001 end";
}

/**
 * @tc.name: Read32Test001
 * @tc.desc: Read32 when stream->Read fails, expect return 0 and set hasError_ to true
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, Read32Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: Read32Test001 start";
    uint8_t* nullData = nullptr;
    size_t streamSize = 0;
    bool needCopy = false;
    std::shared_ptr<HeifBufferInputStream> heifBufferInputStream =
        std::make_shared<HeifBufferInputStream>(nullData, streamSize, needCopy);
    heifBufferInputStream->pos_ = 0;
    heifBufferInputStream->length_ = UINT32_BYTES_NUM;

    std::shared_ptr<HeifInputStream> inputStream = heifBufferInputStream;
    int64_t readerStart = 0;
    size_t readerLength = 0;
    std::shared_ptr<HeifStreamReader> heifStreamReader =
        std::make_shared<HeifStreamReader>(inputStream, readerStart, readerLength);
    
    heifStreamReader->end_ = readerStart + UINT32_BYTES_NUM;
    heifStreamReader->hasError_ = false;
    auto ret = heifStreamReader->Read32();
    EXPECT_EQ(ret, 0U);
    EXPECT_EQ(heifStreamReader->hasError_, true);

    GTEST_LOG_(INFO) << "HeifStreamTest: Read32Test001 end";
}

/**
 * @tc.name: Read64Test001
 * @tc.desc: Read64 when stream->Read fails, expect return 0 and set hasError_ to true
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, Read64Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: Read64Test001 start";
    uint8_t* nullData = nullptr;
    size_t streamSize = 0;
    bool needCopy = false;
    std::shared_ptr<HeifBufferInputStream> heifBufferInputStream =
        std::make_shared<HeifBufferInputStream>(nullData, streamSize, needCopy);

    heifBufferInputStream->pos_ = 0;
    heifBufferInputStream->length_ = UINT64_BYTES_NUM;

    std::shared_ptr<HeifInputStream> inputStream = heifBufferInputStream;
    int64_t readerStart = 0;
    size_t readerLength = 0;
    std::shared_ptr<HeifStreamReader> heifStreamReader =
        std::make_shared<HeifStreamReader>(inputStream, readerStart, readerLength);

    heifStreamReader->end_ = readerStart + UINT64_BYTES_NUM;
    heifStreamReader->hasError_ = false;
    uint64_t ret = heifStreamReader->Read64();

    EXPECT_EQ(ret, 0U);
    EXPECT_EQ(heifStreamReader->hasError_, true);

    GTEST_LOG_(INFO) << "HeifStreamTest: Read64Test001 end";
}

/**
 * @tc.name: ReadDataTest001
 * @tc.desc: ReadData when stream->Read fails, expect return false and set hasError_ to true
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, ReadDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: ReadDataTest001 start";

    uint8_t* nullData = nullptr;
    size_t streamSize = 0;
    bool needCopy = false;
    std::shared_ptr<HeifBufferInputStream> heifBufferInputStream =
        std::make_shared<HeifBufferInputStream>(nullData, streamSize, needCopy);
    size_t readSize = 8;
    heifBufferInputStream->pos_ = 0;
    heifBufferInputStream->length_ = readSize;
    std::shared_ptr<HeifInputStream> inputStream = heifBufferInputStream;
    int64_t readerStart = 0;
    size_t readerLength = 0;
    std::shared_ptr<HeifStreamReader> heifStreamReader =
        std::make_shared<HeifStreamReader>(inputStream, readerStart, readerLength);
    heifStreamReader->end_ = readerStart + readSize;
    heifStreamReader->hasError_ = false;
    std::vector<uint8_t> targetBuf(readSize, 0);
    bool ret = heifStreamReader->ReadData(targetBuf.data(), readSize);

    EXPECT_FALSE(ret);
    EXPECT_EQ(heifStreamReader->hasError_, true);

    GTEST_LOG_(INFO) << "HeifStreamTest: ReadDataTest001 end";
}

/**
 * @tc.name: ReadStringTest001
 * @tc.desc: ReadString when CheckSize fails in loop, expect return empty string and set hasError_ to true
 * @tc.type: FUNC
 */
HWTEST_F(HeifStreamTest, ReadStringTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifStreamTest: ReadStringTest001 start";
    uint8_t streamData[2] = {1, 2};
    size_t streamSize = sizeof(streamData);
    bool needCopy = false;
    std::shared_ptr<HeifBufferInputStream> heifBufferInputStream =
        std::make_shared<HeifBufferInputStream>(streamData, streamSize, needCopy);
    heifBufferInputStream->pos_ = 0;
    heifBufferInputStream->length_ = streamSize;
    std::shared_ptr<HeifInputStream> inputStream = heifBufferInputStream;
    int64_t readerStart = 0;
    size_t readerLength = 0;
    std::shared_ptr<HeifStreamReader> heifStreamReader =
        std::make_shared<HeifStreamReader>(inputStream, readerStart, readerLength);
    heifStreamReader->end_ = readerStart + 1;
    heifStreamReader->hasError_ = false;
    std::string ret = heifStreamReader->ReadString();
    EXPECT_TRUE(ret.empty());
    EXPECT_EQ(heifStreamReader->hasError_, true);

    GTEST_LOG_(INFO) << "HeifStreamTest: ReadStringTest001 end";
}
} // namespace ImagePlugin
} // namespace OHOS
