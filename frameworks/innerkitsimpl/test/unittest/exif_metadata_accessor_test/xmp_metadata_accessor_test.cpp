/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define private public
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <unistd.h>
#include <vector>

#include "media_errors.h"
#include "xmp_metadata_accessor.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_JPEG_XMP_PATH = "/data/local/tmp/image/jpeg_xmp.jpg";
static const std::string IMAGE_ERROR_XMP_PATH = "/error/path";

class XMPMetadataAccessorTest : public testing::Test {
public:
    XMPMetadataAccessorTest() = default;
    ~XMPMetadataAccessorTest() = default;
};

static std::vector<uint8_t> ReadFile(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    EXPECT_TRUE(file.is_open());
    file.seekg(0, std::ios::end);

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buf(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(buf.data()), size);
    return buf;
}

/**
 * @tc.name: CreateTest001
 * @tc.desc: test Create method when input data and mode is READ_ONLY_XMP.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, CreateTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest001 start";
    auto data = ReadFile(IMAGE_JPEG_XMP_PATH);
    ASSERT_FALSE(data.empty());

    auto accessor = XMPMetadataAccessor::Create(data.data(), data.size(), XMPAccessMode::READ_ONLY_XMP);
    ASSERT_NE(accessor, nullptr);

    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest001 end";
}

/**
 * @tc.name: CreateTest002
 * @tc.desc: test Create method when input data and mode is READ_WRITE_XMP.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, CreateTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest002 start";
    auto data = ReadFile(IMAGE_JPEG_XMP_PATH);
    ASSERT_FALSE(data.empty());

    auto accessor = XMPMetadataAccessor::Create(data.data(), data.size(), XMPAccessMode::READ_WRITE_XMP);
    ASSERT_NE(accessor, nullptr);

    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest002 end";
}

/**
 * @tc.name: CreateTest003
 * @tc.desc: test Create method when input path and mode is READ_ONLY_XMP.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, CreateTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest003 start";
    auto accessor = XMPMetadataAccessor::Create(IMAGE_JPEG_XMP_PATH, XMPAccessMode::READ_ONLY_XMP);
    ASSERT_NE(accessor, nullptr);
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest003 end";
}

/**
 * @tc.name: CreateTest004
 * @tc.desc: test Create method when input path mode is READ_WRITE_XMP.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, CreateTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest004 start";
    auto accessor = XMPMetadataAccessor::Create(IMAGE_JPEG_XMP_PATH, XMPAccessMode::READ_WRITE_XMP);
    ASSERT_NE(accessor, nullptr);
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest004 end";
}

/**
 * @tc.name: CreateTest005
 * @tc.desc: test Create method when input fd and mode is READ_ONLY_XMP.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, CreateTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest005 start";
    int32_t fd = open(IMAGE_JPEG_XMP_PATH.c_str(), O_RDONLY);
    ASSERT_NE(fd, 0);

    auto accessor = XMPMetadataAccessor::Create(fd, XMPAccessMode::READ_ONLY_XMP);
    ASSERT_NE(accessor, nullptr);
    close(fd);

    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest005 end";
}

/**
 * @tc.name: CreateTest006
 * @tc.desc: test Create method when input fd and mode is READ_WRITE_XMP.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, CreateTest006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest006 start";
    int32_t fd = open(IMAGE_JPEG_XMP_PATH.c_str(), O_RDWR);
    ASSERT_NE(fd, 0);

    auto accessor = XMPMetadataAccessor::Create(fd, XMPAccessMode::READ_WRITE_XMP);
    ASSERT_NE(accessor, nullptr);
    close(fd);

    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest006 end";
}

/**
 * @tc.name: CreateTest007
 * @tc.desc: test Create method when input path is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, CreateTest007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest007 start";
    auto accessor = XMPMetadataAccessor::Create(IMAGE_ERROR_XMP_PATH, XMPAccessMode::READ_WRITE_XMP);
    ASSERT_EQ(accessor, nullptr);
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: CreateTest007 end";
}

/**
 * @tc.name: ReadTest001
 * @tc.desc: test Read method in normal scene.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, ReadTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: ReadTest001 start";
    auto accessor = XMPMetadataAccessor::Create(IMAGE_JPEG_XMP_PATH, XMPAccessMode::READ_ONLY_XMP);
    ASSERT_NE(accessor, nullptr);

    uint32_t ret = accessor->Read();
    ASSERT_EQ(ret, SUCCESS);

    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: ReadTest001 end";
}

/**
 * @tc.name: ReadTest002
 * @tc.desc: test Read method when xmpFiles is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, ReadTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: ReadTest002 start";
    auto accessor = XMPMetadataAccessor::Create(IMAGE_JPEG_XMP_PATH, XMPAccessMode::READ_ONLY_XMP);
    ASSERT_NE(accessor, nullptr);

    accessor->xmpFiles_ = nullptr;
    uint32_t ret = accessor->Read();
    ASSERT_EQ(ret, ERR_XMP_INVALID_FILE);

    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: ReadTest002 end";
}

/**
 * @tc.name: WriteTest001
 * @tc.desc: test write method in normal scene.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, WriteTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: WriteTest001 start";
    auto accessor = XMPMetadataAccessor::Create(IMAGE_JPEG_XMP_PATH, XMPAccessMode::READ_WRITE_XMP);
    ASSERT_NE(accessor, nullptr);

    uint32_t ret = accessor->Read();
    ASSERT_EQ(ret, SUCCESS);

    ret = accessor->Write();
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: WriteTest001 end";
}

/**
 * @tc.name: WriteTest002
 * @tc.desc: test write method when metadata is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(XMPMetadataAccessorTest, WriteTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: WriteTest002 start";
    auto accessor = XMPMetadataAccessor::Create(IMAGE_JPEG_XMP_PATH, XMPAccessMode::READ_WRITE_XMP);
    ASSERT_NE(accessor, nullptr);

    uint32_t ret = accessor->Read();
    ASSERT_EQ(ret, SUCCESS);

    accessor->xmpMetadata_ = nullptr;
    ret = accessor->Write();
    ASSERT_EQ(ret, ERR_MEDIA_NULL_POINTER);
    GTEST_LOG_(INFO) << "XMPMetadataAccessorTest: WriteTest002 end";
}
} // namespace Multimedia
} // namespace OHOS