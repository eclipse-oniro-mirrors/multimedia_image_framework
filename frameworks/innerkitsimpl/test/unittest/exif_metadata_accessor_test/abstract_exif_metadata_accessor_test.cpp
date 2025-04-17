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

#include "abstract_exif_metadata_accessor.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
constexpr uint32_t MOCK_ERR_CODE = 0;
constexpr uint32_t MOCK_BLOB = 0;
constexpr ssize_t MOCK_SIZE = 0;
constexpr long MOCK_FTELL = -1;
constexpr int MOCK_BYTE = 0;

class AbstractExifMetadataAccessorTest : public testing::Test {
public:
    AbstractExifMetadataAccessorTest() {}
    ~AbstractExifMetadataAccessorTest() {}
};

class MockMetadataStream : public MetadataStream {
public:
    bool Open(OpenMode mode = OpenMode::ReadWrite) override
    {
        return true;
    }

    bool IsOpen() override
    {
        return true;
    }

    bool Flush() override
    {
        return true;
    }

    ssize_t Write(byte *data, ssize_t size) override
    {
        return MOCK_SIZE;
    }

    ssize_t Read(byte *data, ssize_t size) override
    {
        return MOCK_SIZE;
    }

    int ReadByte() override
    {
        return MOCK_BYTE;
    }

    long Seek(long offset, SeekPos pos) override
    {
        return MOCK_FTELL;
    }

    long Tell() override
    {
        return MOCK_FTELL;
    }

    bool IsEof() override
    {
        return true;
    }

    byte *GetAddr(bool isWriteable = false) override
    {
        return nullptr;
    }

    bool CopyFrom(MetadataStream &src) override
    {
        return true;
    }

    ssize_t GetSize() override
    {
        return MOCK_SIZE;
    }

private:
    void Close() override {}
};

class MockAbstractExifMetadataAccessor : public AbstractExifMetadataAccessor {
public:
    explicit MockAbstractExifMetadataAccessor(std::shared_ptr<MetadataStream> &stream)
        : AbstractExifMetadataAccessor(stream) {}
    ~MockAbstractExifMetadataAccessor() = default;

    virtual uint32_t Read() override
    {
        return MOCK_ERR_CODE;
    }

    virtual uint32_t Write() override
    {
        return MOCK_ERR_CODE;
    }

    bool ReadBlob(DataBuf &blob) override
    {
        return true;
    }

    uint32_t WriteBlob(DataBuf &blob) override
    {
        return MOCK_BLOB;
    }
};

/**
 * @tc.name: Create001
 * @tc.desc: test the Create method in normal scene
 * @tc.type: FUNC
 */
HWTEST_F(AbstractExifMetadataAccessorTest, Create001, TestSize.Level3)
{
    auto stream = std::make_shared<MockMetadataStream>();
    ASSERT_NE(stream, nullptr);
    std::shared_ptr<MetadataStream> metaStream = stream;
    auto accessor = std::make_shared<MockAbstractExifMetadataAccessor>(metaStream);
    ASSERT_NE(accessor, nullptr);
    auto exifMetadata = std::make_shared<ExifMetadata>();
    ASSERT_NE(exifMetadata, nullptr);
    accessor->Set(exifMetadata);

    bool res = accessor->Create();
    EXPECT_TRUE(res);
}

/**
 * @tc.name: Create002
 * @tc.desc: test the Create method with exifMetadata is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbstractExifMetadataAccessorTest, Create002, TestSize.Level3)
{
    auto stream = std::make_shared<MockMetadataStream>();
    ASSERT_NE(stream, nullptr);
    std::shared_ptr<MetadataStream> metaStream = stream;
    auto accessor = std::make_shared<MockAbstractExifMetadataAccessor>(metaStream);
    ASSERT_NE(accessor, nullptr);
    std::shared_ptr<ExifMetadata> exifMetadata = nullptr;
    accessor->Set(exifMetadata);

    bool res = accessor->Create();
    EXPECT_TRUE(res);
}

/**
 * @tc.name: WriteTooutput001
 * @tc.desc: test the WriteTooutput method in normal scene
 * @tc.type: FUNC
 */
HWTEST_F(AbstractExifMetadataAccessorTest, WriteTooutput001, TestSize.Level3)
{
    auto stream = std::make_shared<MockMetadataStream>();
    ASSERT_NE(stream, nullptr);
    std::shared_ptr<MetadataStream> metaStream = stream;
    auto accessor = std::make_shared<MockAbstractExifMetadataAccessor>(metaStream);
    ASSERT_NE(accessor, nullptr);
    SkDynamicMemoryWStream skWStream;

    bool res = accessor->WriteToOutput(skWStream);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: WriteTooutput002
 * @tc.desc: test the Create method with imageStream is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AbstractExifMetadataAccessorTest, WriteTooutput002, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> metaStream = nullptr;
    auto accessor = std::make_shared<MockAbstractExifMetadataAccessor>(metaStream);
    ASSERT_NE(accessor, nullptr);
    SkDynamicMemoryWStream skWStream;

    bool res = accessor->WriteToOutput(skWStream);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: GetoutputStream001
 * @tc.desc: test the GetoutputStream in normal scene
 * @tc.type: FUNC
 */
HWTEST_F(AbstractExifMetadataAccessorTest, GetoutputStream001, TestSize.Level3)
{
    auto stream = std::make_shared<MockMetadataStream>();
    ASSERT_NE(stream, nullptr);
    std::shared_ptr<MetadataStream> metaStream = stream;
    auto accessor = std::make_shared<MockAbstractExifMetadataAccessor>(metaStream);
    ASSERT_NE(accessor, nullptr);
    auto res = accessor->GetOutputStream();
    ASSERT_EQ(res, stream);
}
} // namespace Multimedia
} // namespace OHOS