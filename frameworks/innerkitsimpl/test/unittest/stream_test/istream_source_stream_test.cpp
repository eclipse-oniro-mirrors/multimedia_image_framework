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
#define private public
#include "istream_source_stream.h"

constexpr size_t MOCK_STREAM_SIZE = 1;
constexpr size_t MOCK_STREAM_OFFSET = 0;
constexpr uint32_t MALLOC_MAX_LENTH = 0x40000000;

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class IstreamSourceStreamTest : public testing::Test {
public:
    IstreamSourceStreamTest() {}
    ~IstreamSourceStreamTest() {}
};

class MockStream : public std::istringstream {
public:
    MockStream() : std::istringstream("Mock data") {}
    std::streambuf* rdbuf() const
    {
        return nullptr;
    }
};

/**
 * @tc.name: CreateSourceStreamTest001
 * @tc.desc: Test CreateSourceStream when input stream is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IstreamSourceStreamTest, CreateSourceStreamTest001, TestSize.Level3)
{
    auto sourceStream = IstreamSourceStream::CreateSourceStream(nullptr);
    EXPECT_EQ(sourceStream, nullptr);
}

/**
 * @tc.name: CreateSourceStreamTest002
 * @tc.desc: Test CreateSourceStream when stream rdbuf return nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IstreamSourceStreamTest, CreateSourceStreamTest002, TestSize.Level3)
{
    auto istreamPtr = std::make_unique<MockStream>();
    ASSERT_NE(istreamPtr, nullptr);
    auto sourceStream = IstreamSourceStream::CreateSourceStream(std::move(istreamPtr));
    EXPECT_NE(sourceStream, nullptr);
}

/**
 * @tc.name: CreateSourceStreamTest003
 * @tc.desc: Test CreateSourceStream when input stream is empty
 * @tc.type: FUNC
 */
HWTEST_F(IstreamSourceStreamTest, CreateSourceStreamTest003, TestSize.Level3)
{
    std::istringstream istream("");
    auto istreamPtr = std::make_unique<std::istringstream>(istream.str());
    ASSERT_NE(istreamPtr, nullptr);
    auto sourceStream = IstreamSourceStream::CreateSourceStream(std::move(istreamPtr));
    EXPECT_EQ(sourceStream, nullptr);
}

/**
 * @tc.name: ReadTest001
 * @tc.desc: Test Read when desiredSize is 0 or GetData return false
 * @tc.type: FUNC
 */
HWTEST_F(IstreamSourceStreamTest, ReadTest001, TestSize.Level3)
{
    std::istringstream istream("Test istream");
    auto istreamPtr = std::make_unique<std::istringstream>(istream.str());
    ASSERT_NE(istreamPtr, nullptr);
    auto sourceStream = IstreamSourceStream::CreateSourceStream(std::move(istreamPtr));
    ASSERT_NE(sourceStream, nullptr);
    ImagePlugin::DataStreamBuffer streamBuf;

    bool res = sourceStream->Read(0, streamBuf);
    EXPECT_FALSE(res);

    std::string content = istream.str();
    sourceStream->streamSize_ = 0;
    res = sourceStream->Read(content.size(), streamBuf);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: ReadTest002
 * @tc.desc: Test Read when desiredSize is 0，outBuffer is nullptr, desiredSize over bufferSize or GetData return false
 * @tc.type: FUNC
 */
HWTEST_F(IstreamSourceStreamTest, ReadTest002, TestSize.Level3)
{
    std::istringstream istream("Test istream");
    auto istreamPtr = std::make_unique<std::istringstream>(istream.str());
    ASSERT_NE(istreamPtr, nullptr);
    auto sourceStream = IstreamSourceStream::CreateSourceStream(std::move(istreamPtr));
    ASSERT_NE(sourceStream, nullptr);
    uint8_t outBuffer[] = {0, 0, 0, 0, 0};
    uint32_t outBufferSize = sizeof(outBuffer);
    uint32_t readSize = 0;

    bool res = sourceStream->Read(0, outBuffer, outBufferSize, readSize);
    EXPECT_FALSE(res);

    res = sourceStream->Read(outBufferSize, nullptr, outBufferSize, readSize);
    EXPECT_FALSE(res);

    res = sourceStream->Read(outBufferSize + 1, outBuffer, outBufferSize, readSize);
    EXPECT_FALSE(res);

    sourceStream->streamSize_ = 0;
    res = sourceStream->Read(outBufferSize, outBuffer, outBufferSize, readSize);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: PeekTest001
 * @tc.desc: Test Peek when desiredSize is 0 or GetData return false
 * @tc.type: FUNC
 */
HWTEST_F(IstreamSourceStreamTest, PeekTest001, TestSize.Level3)
{
    std::istringstream istream("Test istream");
    auto istreamPtr = std::make_unique<std::istringstream>(istream.str());
    ASSERT_NE(istreamPtr, nullptr);
    auto sourceStream = IstreamSourceStream::CreateSourceStream(std::move(istreamPtr));
    ASSERT_NE(sourceStream, nullptr);
    ImagePlugin::DataStreamBuffer streamBuf;

    bool res = sourceStream->Peek(0, streamBuf);
    EXPECT_FALSE(res);

    std::string content = istream.str();
    sourceStream->streamSize_ = 0;
    res = sourceStream->Peek(content.size(), streamBuf);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: PeekTest002
 * @tc.desc: Test Peek when desiredSize is 0，outBuffer is nullptr, desiredSize over bufferSize or GetData return false
 * @tc.type: FUNC
 */
HWTEST_F(IstreamSourceStreamTest, PeekTest002, TestSize.Level3)
{
    std::istringstream istream("Test istream");
    auto istreamPtr = std::make_unique<std::istringstream>(istream.str());
    ASSERT_NE(istreamPtr, nullptr);
    auto sourceStream = IstreamSourceStream::CreateSourceStream(std::move(istreamPtr));
    ASSERT_NE(sourceStream, nullptr);
    uint8_t outBuffer[] = {0, 0, 0, 0, 0};
    uint32_t outBufferSize = sizeof(outBuffer);
    uint32_t readSize = 0;

    bool res = sourceStream->Peek(0, outBuffer, outBufferSize, readSize);
    EXPECT_FALSE(res);

    res = sourceStream->Peek(outBufferSize, nullptr, outBufferSize, readSize);
    EXPECT_FALSE(res);

    res = sourceStream->Peek(outBufferSize + 1, outBuffer, outBufferSize, readSize);
    EXPECT_FALSE(res);

    sourceStream->streamSize_ = 0;
    res = sourceStream->Peek(outBufferSize, outBuffer, outBufferSize, readSize);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: SeekTest001
 * @tc.desc: Test Seek when position over streamSize
 * @tc.type: FUNC
 */
HWTEST_F(IstreamSourceStreamTest, SeekTest001, TestSize.Level3)
{
    std::istringstream istream("Test istream");
    auto istreamPtr = std::make_unique<std::istringstream>(istream.str());
    ASSERT_NE(istreamPtr, nullptr);
    auto sourceStream = IstreamSourceStream::CreateSourceStream(std::move(istreamPtr));
    ASSERT_NE(sourceStream, nullptr);
    uint32_t position = 0;

    sourceStream->streamSize_ = 0;
    bool res = sourceStream->Seek(position + 1);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: GetDataTest001
 * @tc.desc: Test GetData when streamSize is 0 or streamOffset over streamSize
 * @tc.type: FUNC
 */
HWTEST_F(IstreamSourceStreamTest, GetDataTest001, TestSize.Level3)
{
    std::istringstream istream("Test istream");
    auto istreamPtr = std::make_unique<std::istringstream>(istream.str());
    ASSERT_NE(istreamPtr, nullptr);
    auto sourceStream = IstreamSourceStream::CreateSourceStream(std::move(istreamPtr));
    ASSERT_NE(sourceStream, nullptr);
    uint32_t readSize = 0;
    ImagePlugin::DataStreamBuffer outData;

    sourceStream->streamSize_ = 0;
    bool res = sourceStream->GetData(0, nullptr, 0, readSize);
    EXPECT_FALSE(res);
    res = sourceStream->GetData(0, outData);
    EXPECT_FALSE(res);

    sourceStream->streamSize_ = MOCK_STREAM_SIZE;
    sourceStream->streamOffset_ = MOCK_STREAM_OFFSET + 1;
    res = sourceStream->GetData(0, nullptr, 0, readSize);
    EXPECT_FALSE(res);
    res = sourceStream->GetData(0, outData);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: GetDataTest002
 * @tc.desc: Test GetData when desiredSize is 0 or desiredSize over MALLOC_MAX_LENTH or desiredSize over
 *           streamSize minus streamOffset
 * @tc.type: FUNC
 */
HWTEST_F(IstreamSourceStreamTest, GetDataTest002, TestSize.Level3)
{
    std::istringstream istream("Test istream");
    auto istreamPtr = std::make_unique<std::istringstream>(istream.str());
    ASSERT_NE(istreamPtr, nullptr);
    auto sourceStream = IstreamSourceStream::CreateSourceStream(std::move(istreamPtr));
    ASSERT_NE(sourceStream, nullptr);
    ImagePlugin::DataStreamBuffer outData;

    sourceStream->streamSize_ = MOCK_STREAM_SIZE;
    sourceStream->streamOffset_ = MOCK_STREAM_OFFSET;
    bool res = sourceStream->GetData(0, outData);
    EXPECT_FALSE(res);

    res = sourceStream->GetData(MALLOC_MAX_LENTH + 1, outData);
    EXPECT_FALSE(res);

    sourceStream->streamSize_ = MOCK_STREAM_SIZE;
    sourceStream->streamOffset_ = MOCK_STREAM_OFFSET;
    res = sourceStream->GetData(MALLOC_MAX_LENTH, outData);
    EXPECT_TRUE(res);
}
}
}