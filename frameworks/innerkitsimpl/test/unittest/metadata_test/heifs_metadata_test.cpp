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
#include "heifs_metadata.h"
#include "media_errors.h"
#include "image_type.h"
#include "securec.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace {
    static const std::string MOCK_DELAY_TIME = "40";
    static const uint32_t FIXED_BUFFER_SIZE = sizeof(uint32_t) + sizeof(uint64_t);
    static const uint32_t MOCK_BUFFER_SIZE = FIXED_BUFFER_SIZE + sizeof(uint32_t) * 2 + 14 + 2;
    static const uint32_t LARGE_BUFFER_SIZE = MOCK_BUFFER_SIZE * 2;
    static const uint32_t MAX_KV_METADATA_COUNT = 10;
    static const uint8_t MOCK_METADATA_COUNT = MAX_KV_METADATA_COUNT + 1;
    static const uint8_t ALPHA_E = 0x65;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    static const uint32_t METADATA_TYPE_INDEX = 0;
    static const uint32_t METADATA_COUNT_INDEX = 4;
    static const uint32_t METADATA_KEY_INDEX = 12;
    static const uint8_t MOCK_METADATA[] = { 0x0F, 0x00, 0x00, 0x00,
                                             0x01, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00,
                                             0x0E, 0x00, 0x00, 0x00,
                                             0x48, 0x65, 0x69, 0x66, 0x73,
                                             0x44, 0x65, 0x6C, 0x61, 0x79,
                                             0x54, 0x69, 0x6D, 0x65,
                                             0x02, 0x00, 0x00, 0x00,
                                             0x34, 0x30 };
    static const uint8_t NULL_METADATA[] = { 0x0F, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00 };
#else
    static const uint32_t METADATA_TYPE_INDEX = 3;
    static const uint32_t METADATA_COUNT_INDEX = 11;
    static const uint32_t METADATA_KEY_INDEX = 15;
    static const uint8_t MOCK_METADATA[] = { 0x00, 0x00, 0x00, 0x0F,
                                             0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x01,
                                             0x00, 0x00, 0x00, 0x0E,
                                             0x48, 0x65, 0x69, 0x66, 0x73,
                                             0x44, 0x65, 0x6C, 0x61, 0x79,
                                             0x54, 0x69, 0x6D, 0x65,
                                             0x00, 0x00, 0x00, 0x02,
                                             0x34, 0x30 };
    static const uint8_t NULL_METADATA[] = { 0x00, 0x00, 0x00, 0x0F,
                                             0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00 };
#endif
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
 * @tc.desc: Test GetBlob when metadata has properties and dst buffer is too small.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, GetBlobTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest001 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(false);
    ASSERT_NE(metadata, nullptr);
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(FIXED_BUFFER_SIZE);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(metadata->GetBlob(FIXED_BUFFER_SIZE, dst.get()), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest001 end";
}

/**
 * @tc.name: GetBlobTest002
 * @tc.desc: Test GetBlob when metadata has properties and dst buffer is sufficient.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, GetBlobTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest002 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(false);
    ASSERT_NE(metadata, nullptr);
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(MOCK_BUFFER_SIZE);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(metadata->GetBlobSize(), MOCK_BUFFER_SIZE);
    ASSERT_EQ(metadata->GetBlob(MOCK_BUFFER_SIZE, dst.get()), SUCCESS);
    for (uint32_t i = 0; i < MOCK_BUFFER_SIZE; i++) {
        ASSERT_EQ(dst[i], MOCK_METADATA[i]);
    }
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest002 end";
}

/**
 * @tc.name: GetBlobTest003
 * @tc.desc: Test GetBlob when metadata has properties and dst buffer is large.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, GetBlobTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest003 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(false);
    ASSERT_NE(metadata, nullptr);
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(LARGE_BUFFER_SIZE);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(metadata->GetBlob(LARGE_BUFFER_SIZE, dst.get()), SUCCESS);
    for (uint32_t i = 0; i < MOCK_BUFFER_SIZE; i++) {
        ASSERT_EQ(dst[i], MOCK_METADATA[i]);
    }
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest003 end";
}

/**
 * @tc.name: GetBlobTest004
 * @tc.desc: Test GetBlob when metadata has properties and dst buffer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, GetBlobTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest004 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(true);
    ASSERT_NE(metadata, nullptr);
    uint8_t *dst = nullptr;
    ASSERT_EQ(metadata->GetBlob(LARGE_BUFFER_SIZE, dst), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest004 end";
}

/**
 * @tc.name: GetBlobTest005
 * @tc.desc: Test GetBlob when metadata doesn't have properties.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, GetBlobTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest005 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(true);
    ASSERT_NE(metadata, nullptr);
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(FIXED_BUFFER_SIZE);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(metadata->GetBlobSize(), FIXED_BUFFER_SIZE);
    ASSERT_EQ(metadata->GetBlob(FIXED_BUFFER_SIZE, dst.get()), SUCCESS);
    for (uint32_t i = 0; i < FIXED_BUFFER_SIZE; i++) {
        ASSERT_EQ(dst[i], NULL_METADATA[i]);
    }
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest005 end";
}

/**
 * @tc.name: GetBlobTest006
 * @tc.desc: Test GetBlob when metadata properties is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, GetBlobTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest006 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(true);
    ASSERT_NE(metadata, nullptr);
    metadata->properties_.reset();
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(FIXED_BUFFER_SIZE);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(metadata->GetBlob(FIXED_BUFFER_SIZE, dst.get()), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: GetBlobTest006 end";
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
    ASSERT_EQ(metadata->SetBlob(MOCK_METADATA, MOCK_BUFFER_SIZE), SUCCESS);
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
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(true);
    ASSERT_NE(metadata, nullptr);
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(MOCK_BUFFER_SIZE);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(memcpy_s(dst.get(), MOCK_BUFFER_SIZE, MOCK_METADATA, MOCK_BUFFER_SIZE), 0);
    dst[METADATA_TYPE_INDEX] = static_cast<uint8_t>(MetadataType::EXIF);
    ASSERT_EQ(metadata->SetBlob(dst.get(), MOCK_BUFFER_SIZE), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest003 end";
}

/**
 * @tc.name: SetBlobTest004
 * @tc.desc: Test SetBlob when metadata count is too many.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, SetBlobTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest004 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(true);
    ASSERT_NE(metadata, nullptr);
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(MOCK_BUFFER_SIZE);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(memcpy_s(dst.get(), MOCK_BUFFER_SIZE, MOCK_METADATA, MOCK_BUFFER_SIZE), 0);
    dst[METADATA_COUNT_INDEX] = MOCK_METADATA_COUNT;
    ASSERT_EQ(metadata->SetBlob(dst.get(), MOCK_BUFFER_SIZE), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest004 end";
}

/**
 * @tc.name: SetBlobTest005
 * @tc.desc: Test SetBlob when metadata key is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, SetBlobTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest005 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(true);
    ASSERT_NE(metadata, nullptr);
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(MOCK_BUFFER_SIZE);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(memcpy_s(dst.get(), MOCK_BUFFER_SIZE, MOCK_METADATA, MOCK_BUFFER_SIZE), 0);
    dst[METADATA_KEY_INDEX] = ALPHA_E;
    ASSERT_EQ(metadata->SetBlob(dst.get(), MOCK_BUFFER_SIZE), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest005 end";
}

/**
 * @tc.name: SetBlobTest006
 * @tc.desc: Test SetBlob when setting properties with null metadata.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, SetBlobTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest006 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(true);
    ASSERT_NE(metadata, nullptr);
    ASSERT_EQ(metadata->SetBlob(MOCK_METADATA, MOCK_BUFFER_SIZE), SUCCESS);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest006 end";
}

/**
 * @tc.name: SetBlobTest007
 * @tc.desc: Test SetBlob when setting null properties with metadata.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, SetBlobTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest007 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(false);
    ASSERT_NE(metadata, nullptr);
    ASSERT_EQ(metadata->SetBlob(NULL_METADATA, FIXED_BUFFER_SIZE), SUCCESS);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest007 end";
}

/**
 * @tc.name: SetBlobTest008
 * @tc.desc: Test SetBlob when buffer size is smaller than truth.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsMetadataTest, SetBlobTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest008 start";
    std::unique_ptr<HeifsMetadata> metadata = ConstructHeifsMetadata(false);
    ASSERT_NE(metadata, nullptr);
    ASSERT_EQ(metadata->SetBlob(MOCK_METADATA, FIXED_BUFFER_SIZE), ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "HeifsMetadataTest: SetBlobTest008 end";
}
} // namespace Media
} // namespace OHOS