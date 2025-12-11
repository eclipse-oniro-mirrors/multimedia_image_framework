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

#define PRIVATE_PUBLIC
#define PROTECTED_PUBLIC
#include "kv_metadata.h"
#include "media_errors.h"
#undef PRIVATE_PUBLIC
#undef PROTECTED_PUBLIC

using namespace OHOS::Media;
using namespace testing::ext;

const uint64_t METADATA_SIZE = 1;
const uint64_t LENGTH = 129;

namespace OHOS {
namespace Media {
class KvMetadataTest : public testing::Test {
public:
    KvMetadataTest() {}
    ~KvMetadataTest() {}

    void SetUp() override
    {
        oldCout = std::cout.rdbuf();
        captureStream.clear();
    }

    void TearDown() override
    {
        std::cout.rdbuf(oldCout);
    }

    std::string GetCapturedOutput()
    {
        return captureStream.str();
    }

protected:
    std::stringstream captureStream;
    std::streambuf *oldCout = nullptr;
};

/**
 * @tc.name: ImageKvMetadata_IsValidKey_InvalidMetadataType_Test
 * @tc.desc: Test GetValue fails and returns error when using unsupported metadata type like EXIF
 * @tc.type: FUNC
 */
HWTEST_F(KvMetadataTest, ImageKvMetadata_IsValidKey_InvalidMetadataType_Test, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "KvMetadataTest: IsValidKey_InvalidMetadataType_Test start";
    
    ImageKvMetadata metadata(MetadataType::EXIF);
    std::string value;
    int ret = metadata.GetValue("test_key", value);
    
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "KvMetadataTest: IsValidKey_InvalidMetadataType_Test end";
}

/**
 * @tc.name: ImageKvMetadata_Marshalling_InvalidKey_Test
 * @tc.desc: Test Marshalling detects and rejects unsupported keys during serialization
 * @tc.type: FUNC
 */
HWTEST_F(KvMetadataTest, ImageKvMetadata_Marshalling_InvalidKey_Test, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "KvMetadataTest: Marshalling_InvalidKey_Test start";
    
    ImageKvMetadata metadata(MetadataType::FRAGMENT);
    metadata.properties_->insert(std::make_pair("invalid_key", "test_value"));
    
    Parcel parcel;
    bool result = metadata.Marshalling(parcel);
    
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "KvMetadataTest: Marshalling_InvalidKey_Test end";
}

/**
 * @tc.name: ImageKvMetadata_Marshalling_ExceedsMaxStringLength_Test
 * @tc.desc: Test Marshalling rejects metadata when string length exceeds 128 character limit
 * @tc.type: FUNC
 */
HWTEST_F(KvMetadataTest, ImageKvMetadata_Marshalling_ExceedsMaxStringLength_Test, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "KvMetadataTest: Marshalling_ExceedsMaxStringLength_Test start";
    
    ImageKvMetadata metadata(MetadataType::FRAGMENT);
    std::string longValue(LENGTH, 'a');
    metadata.properties_->insert(std::make_pair(FRAGMENT_METADATA_KEY_X, longValue));
    
    Parcel parcel;
    bool result = metadata.Marshalling(parcel);
    
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "KvMetadataTest: Marshalling_ExceedsMaxStringLength_Test end";
}

/**
 * @tc.name: ImageKvMetadata_Unmarshalling_InvalidKey_Test
 * @tc.desc: Test Unmarshalling validates key names and rejects unsupported keys from parcel data
 * @tc.type: FUNC
 */
HWTEST_F(KvMetadataTest, ImageKvMetadata_Unmarshalling_InvalidKey_Test, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "KvMetadataTest: Unmarshalling_InvalidKey_Test start";
    
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(MetadataType::FRAGMENT));
    parcel.WriteUint64(METADATA_SIZE);
    parcel.WriteString("invalid_key");
    parcel.WriteString("test_value");
    
    ImageKvMetadata *result = ImageKvMetadata::Unmarshalling(parcel);
    
    ASSERT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "KvMetadataTest: Unmarshalling_InvalidKey_Test end";
}

/**
 * @tc.name: ImageKvMetadata_Unmarshalling_ExceedsMaxStringLength_Test
 * @tc.desc: Test Unmarshalling enforces maximum string length constraint during deserialization
 * @tc.type: FUNC
 */
HWTEST_F(KvMetadataTest, ImageKvMetadata_Unmarshalling_ExceedsMaxStringLength_Test, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "KvMetadataTest: Unmarshalling_ExceedsMaxStringLength_Test start";
    
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(MetadataType::FRAGMENT));
    parcel.WriteUint64(METADATA_SIZE);
    parcel.WriteString(FRAGMENT_METADATA_KEY_X);
    std::string longValue(LENGTH, 'b');
    parcel.WriteString(longValue);
    
    ImageKvMetadata *result = ImageKvMetadata::Unmarshalling(parcel);
    
    ASSERT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "KvMetadataTest: Unmarshalling_ExceedsMaxStringLength_Test end";
}

/**
 * @tc.name: ImageKvMetadata_Unmarshalling_WithError_Test
 * @tc.desc: Test Unmarshalling handles invalid metadata type and properly logs error information
 * @tc.type: FUNC
 */
HWTEST_F(KvMetadataTest, ImageKvMetadata_Unmarshalling_WithError_Test, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "KvMetadataTest: Unmarshalling_WithError_Test start";
    
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(MetadataType::EXIF));
    
    ImageKvMetadata *result = ImageKvMetadata::Unmarshalling(parcel);
    
    ASSERT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "KvMetadataTest: Unmarshalling_WithError_Test end";
}
} // namespace Media
} // namespace OHOS
