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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <map>
#include "buffer_metadata_stream.h"
#include "heif_exif_metadata_accessor.h"
#include "image_log.h"


using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

static constexpr uint32_t DATASIZE = 1024;
static const string INPUTPATH = "/data/local/tmp/image/test.cr3";
class HeifExifMetadataAccessorTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ReadCr3001
 * @tc.desc: Test ReadCr3, input empty stream, expect error source data
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, ReadCr3001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadCr3001 start";

    std::shared_ptr<Media::MetadataStream> metadataStream = std::make_shared<Media::BufferMetadataStream>();
    Media::HeifExifMetadataAccessor heifExifMetadataAccessor(metadataStream);
    auto res = heifExifMetadataAccessor.ReadCr3();
    EXPECT_EQ(res, Media::ERR_IMAGE_SOURCE_DATA);

    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadCr3001 end";
}

/**
 * @tc.name: ReadCr3002
 * @tc.desc: Test ReadCr3. input not empty stream  but meaningless, expect error source data
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, ReadCr3002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadCr3002 start";

    uint8_t originData[DATASIZE];
    size_t size = DATASIZE;
    int fd = open(INPUTPATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

    std::shared_ptr<Media::MetadataStream> metadataStream = std::make_shared<Media::BufferMetadataStream>(
        originData, size, Media::BufferMetadataStream::MemoryMode::Dynamic, fd, INPUTPATH);
    Media::HeifExifMetadataAccessor heifExifMetadataAccessor(metadataStream);
    auto res = heifExifMetadataAccessor.ReadCr3();
    EXPECT_EQ(res, Media::ERR_IMAGE_SOURCE_DATA);
    close(fd);

    GTEST_LOG_(INFO) << "Cr3BoxTest: ReadCr3002 end";
}

} // namespace ImagePlugin
} // namespace OHOS