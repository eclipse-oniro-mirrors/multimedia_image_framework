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
#include <memory>
#include "ext_stream.h"
#include "image_log.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {
static constexpr uint8_t BUFFER_SIZE = 16;
static constexpr size_t SIZE_ZERO = 0;

class MockInputDataStream : public InputDataStream {
public:
    bool Read(uint32_t, uint8_t*, uint32_t, uint32_t&) override { return false; }
    bool Read(uint32_t, DataStreamBuffer&) override { return false; }
    bool Peek(uint32_t, uint8_t*, uint32_t, uint32_t&) override { return false; }
    bool Peek(uint32_t, DataStreamBuffer&) override { return false; }
    uint32_t Tell() override { return 0; }
    bool Seek(uint32_t) override { return false; }
    size_t GetStreamSize() override { return 0; }
};

class ExtStreamTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: Read001
 * @tc.desc: Test ExtStream::read - when internal stream_ is nullptr, expect return SIZE_ZERO.
 * @tc.type: FUNC
 */
HWTEST_F(ExtStreamTest, Read001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtStreamTest: Read001 start";
    uint8_t buffer[BUFFER_SIZE] = {0};
    size_t size = sizeof(buffer);
    ExtStream extStream(nullptr);
    auto ret = extStream.read(buffer, size);
    EXPECT_EQ(ret, SIZE_ZERO);
    GTEST_LOG_(INFO) << "ExtStreamTest: Read001 end";
}

/**
 * @tc.name: Peek001
 * @tc.desc: Test ExtStream::peek - when stream_ is nullptr and buffer is nullptr, expect return SIZE_ZERO.
 * @tc.type: FUNC
 */
HWTEST_F(ExtStreamTest, Peek001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtStreamTest: Peek001 start";
    uint8_t *buffer = nullptr;
    size_t size = BUFFER_SIZE;
    ExtStream extStream(nullptr);
    auto ret = extStream.peek(buffer, size);
    EXPECT_EQ(ret, SIZE_ZERO);
    GTEST_LOG_(INFO) << "ExtStreamTest: Peek001 end";
}

/**
 * @tc.name: Peek002
 * @tc.desc: Test ExtStream::peek - when buffer is nullptr (stream_ is valid), expect return SIZE_ZERO.
 * @tc.type: FUNC
 */
HWTEST_F(ExtStreamTest, Peek002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtStreamTest: Peek002 start";
    uint8_t *buffer = nullptr;
    size_t size = BUFFER_SIZE;
    ExtStream extStream;
    MockInputDataStream mockStream;
    extStream.stream_ = &mockStream;
    auto ret = extStream.peek(buffer, size);
    EXPECT_EQ(ret, SIZE_ZERO);
    GTEST_LOG_(INFO) << "ExtStreamTest: Peek002 end";
}

/**
 * @tc.name: IsAtEnd001
 * @tc.desc: Test ExtStream::isAtEnd - when stream_ is nullptr, expect return true.
 * @tc.type: FUNC
 */
HWTEST_F(ExtStreamTest, isAtEnd001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtStreamTest: isAtEnd001 start";
    ExtStream extStream(nullptr);
    auto ret = extStream.isAtEnd();
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExtStreamTest: isAtEnd001 end";
}
} // namespace ImagePlugin
} // namespace OHOS