/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <memory>
#include <sstream>
#include <iostream>

#include "kv_metadata.h"
#include "gif_metadata.h"
#include "heifs_metadata.h"
#include "media_errors.h"
#include "image_type.h"
#include "securec.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace {
    static const std::string MOCK_DELAY_TIME = "40";
    static const uint32_t MOCK_BUFFER_SIZE = 40;
}

namespace OHOS {
namespace Media {
class HeifsMetadataTest : public testing::Test {
public:
    HeifsMetadataTest() {}
    ~HeifsMetadataTest() {}
};

static std::unique_ptr<HeifsMetadata> ConstructHeifsMetadata(bool isNull)
{
    std::unique_ptr<HeifsMetadata> metadata = std::make_unique<HeifsMetadata>();
    if (metadata && !isNull) {
        metadata->SetValue(HEIFS_METADATA_KEY_DELAY_TIME, MOCK_DELAY_TIME);
    }
    return metadata;
}

/**
 * @tc.name: GetBlobTest001
 * @tc.desc: Test GetBlob when metadata has properties and dst buffer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, GetBlobTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest001 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(false);
    ASSERT_NE(metadata, nullptr);
    uint8_t *dst = nullptr;
    ASSERT_EQ(metadata->GetBlob(0, dst), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest001 end";
}

/**
 * @tc.name: GetBlobTest002
 * @tc.desc: Test GetBlob when metadata properties is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, GetBlobTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest002 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(true);
    ASSERT_NE(metadata, nullptr);
    metadata->properties_.reset();
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(MOCK_BUFFER_SIZE);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(metadata->GetBlob(MOCK_BUFFER_SIZE, dst.get()), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest002 end";
}

/**
 * @tc.name: GetBlobTest003
 * @tc.desc: Test GetBlob when metadata has properties.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, GetBlobTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest003 start";
    std::unique_ptr<HeifsMetadata> metadataSrc = ConstructHeifsMetadata(false);
    ASSERT_NE(metadataSrc, nullptr);
    std::unique_ptr<HeifsMetadata> metadataDst = ConstructHeifsMetadata(true);
    uint32_t size = metadataSrc->GetBlobSize();
    ASSERT_NE(size, 0);
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(size);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(metadataSrc->GetBlob(size, dst.get()), SUCCESS);
    ASSERT_EQ(metadataDst->SetBlob(dst.get(), size), SUCCESS);
    std::string delayTimeSrc;
    ASSERT_EQ(metadataSrc->GetValue(HEIFS_METADATA_KEY_DELAY_TIME, delayTimeSrc), SUCCESS);
    std::string delayTimeDst;
    ASSERT_EQ(metadataDst->GetValue(HEIFS_METADATA_KEY_DELAY_TIME, delayTimeDst), SUCCESS);
    ASSERT_EQ(delayTimeDst, delayTimeSrc);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest003 end";
}

/**
 * @tc.name: SetBlobTest001
 * @tc.desc: Test SetBlob when metadata properties is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, SetBlobTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest001 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(true);
    ASSERT_NE(metadata, nullptr);
    metadata->properties_.reset();
    std::unique_ptr<uint8_t[]> src = std::make_unique<uint8_t[]>(MOCK_BUFFER_SIZE);
    ASSERT_NE(src, nullptr);
    ASSERT_EQ(metadata->SetBlob(src.get(), MOCK_BUFFER_SIZE), ERR_IMAGE_GET_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest001 end";
}

/**
 * @tc.name: SetBlobTest002
 * @tc.desc: Test SetBlob when source is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, SetBlobTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest002 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(true);
    ASSERT_NE(metadata, nullptr);
    ASSERT_EQ(metadata->SetBlob(nullptr, 0), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest002 end";
}

/**
 * @tc.name: SetBlobTest003
 * @tc.desc: Test SetBlob when metadata type changes.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, SetBlobTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest003 start";
    std::unique_ptr<HeifsMetadata> heifsMetadata = ConstructHeifsMetadata(true);
    GifMetadata gifMetadata;
    gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, MOCK_DELAY_TIME);
    uint32_t gifSize = gifMetadata.GetBlobSize();
    ASSERT_NE(gifSize, 0);
    std::unique_ptr<uint8_t[]> src = std::make_unique<uint8_t[]>(gifSize);
    ASSERT_NE(src, nullptr);
    ASSERT_EQ(gifMetadata.GetBlob(gifSize, src.get()), SUCCESS);
    ASSERT_EQ(heifsMetadata->SetBlob(src.get(), gifSize), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest003 end";
}

/**
 * @tc.name: SetBlobTest004
 * @tc.desc: Test SetBlob when setting properties with null metadata.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, SetBlobTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest004 start";
    std::unique_ptr<HeifsMetadata> metadataSrc = ConstructHeifsMetadata(true);
    ASSERT_NE(metadataSrc, nullptr);
    std::unique_ptr<HeifsMetadata> metadataDst = ConstructHeifsMetadata(false);
    ASSERT_NE(metadataDst, nullptr);
    uint32_t size = metadataSrc->GetBlobSize();
    ASSERT_NE(size, 0);
    std::unique_ptr<uint8_t[]> src = std::make_unique<uint8_t[]>(size);
    ASSERT_NE(src, nullptr);
    ASSERT_EQ(metadataSrc->GetBlob(size, src.get()), SUCCESS);
    ASSERT_EQ(metadataDst->SetBlob(src.get(), size), SUCCESS);
    ASSERT_EQ(metadataDst->properties_->size(), 0);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest004 end";
}

} // namespace Media
} // namespace OHOS