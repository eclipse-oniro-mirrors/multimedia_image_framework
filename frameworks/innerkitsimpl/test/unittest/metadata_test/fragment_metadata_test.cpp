/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#define private public
#define protected public
#include "media_errors.h"
#include "metadata.h"
#include "fragment_metadata.h"
#include "image_log.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
constexpr int32_t TEST_INVALID_METADATA_TYPE = 999;
constexpr uint64_t TEST_PARCEL_SIZE_ONE = 1;
const static uint64_t MAX_FRAGMENT_MAP_META_COUNT = 10;
const static uint64_t MAX_FRAGMENT_MAP_META_LENGTH = 128;

class FragmentMetadataTest : public testing::Test {
public:
    FragmentMetadataTest() {}
    ~FragmentMetadataTest() {}
};

/**
 * @tc.name: SetValueTest001
 * @tc.desc: Pass in the supported key and set the value.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, SetValueTest001, TestSize.Level1)
{
    FragmentMetadata fragmentMetadata;
    EXPECT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_X, "300"));
    EXPECT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_Y, "256"));
    EXPECT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_WIDTH, "1000"));
    EXPECT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_HEIGHT, "1001"));
}

/**
 * @tc.name: SetValueTest002
 * @tc.desc: Pass in unsupported key and set value.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, SetValueTest002, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    EXPECT_FALSE(fragmentMetadata.SetValue("BitsPerSample", "1002"));
}

/**
 * @tc.name: GetValueTest001
 * @tc.desc: Set supported keys and values and use getValue to obtain this value.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, GetValueTest001, TestSize.Level1)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_X, "300"));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_Y, "256"));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_WIDTH, "1000"));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_HEIGHT, "1001"));
    std::string value;
    uint32_t state = fragmentMetadata.GetValue(FRAGMENT_METADATA_KEY_X, value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "300");
    state = fragmentMetadata.GetValue(FRAGMENT_METADATA_KEY_Y, value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "256");
    state = fragmentMetadata.GetValue(FRAGMENT_METADATA_KEY_WIDTH, value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "1000");
    state = fragmentMetadata.GetValue(FRAGMENT_METADATA_KEY_HEIGHT, value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "1001");
}

/**
 * @tc.name: GetValueTest002
 * @tc.desc: Set the value of supported keys, and use getValue to pass in unsupported keys.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, GetValueTest002, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_HEIGHT, "1001"));
    std::string value;
    uint32_t state = fragmentMetadata.GetValue("ERRORCODE", value);
    EXPECT_EQ(state, ERR_IMAGE_INVALID_PARAMETER);
    EXPECT_EQ(value, "");
}

/**
 * @tc.name: GetValueTest003
 * @tc.desc: Set the value of the supported key, and use getValue to pass in the supported key that has not been set.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, GetValueTest003, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_HEIGHT, "1001"));
    std::string value;
    uint32_t state = fragmentMetadata.GetValue("WIDTH", value);
    EXPECT_EQ(state, ERR_IMAGE_INVALID_PARAMETER);
    EXPECT_EQ(value, "");
}

/**
 * @tc.name: GetValueTest004
 * @tc.desc: Set a key twice, getValue to get the latest value.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, GetValueTest004, TestSize.Level1)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_HEIGHT, "1001"));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_HEIGHT, "1000"));
    std::string value;
    uint32_t state = fragmentMetadata.GetValue(FRAGMENT_METADATA_KEY_HEIGHT, value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "1000");
}

/**
 * @tc.name: GetAllPropertiesTest001
 * @tc.desc: Obtain all set keys and values.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, GetAllPropertiesTest001, TestSize.Level1)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_HEIGHT, "1001"));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_WIDTH, "1000"));
    ImageMetadata::PropertyMapPtr propertyMap = fragmentMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    std::map<std::string, std::string> KValueStr = *(propertyMap);
    EXPECT_EQ(KValueStr.size(), 2);
    EXPECT_EQ(KValueStr.find(FRAGMENT_METADATA_KEY_HEIGHT)->second, "1001");
    EXPECT_EQ(KValueStr.find(FRAGMENT_METADATA_KEY_WIDTH)->second, "1000");
}

/**
 * @tc.name: GetAllPropertiesTest002
 * @tc.desc: When setting a key, set an unsupported key. getAllProperties only retrieves supported keys and values.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, GetAllPropertiesTest002, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_HEIGHT, "1001"));
    ASSERT_FALSE(fragmentMetadata.SetValue("ERRORCODE", "1000"));
    ImageMetadata::PropertyMapPtr propertyMap = fragmentMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    std::map<std::string, std::string> KValueStr = *(propertyMap);
    EXPECT_EQ(KValueStr.size(), 1);
    EXPECT_EQ(KValueStr.find(FRAGMENT_METADATA_KEY_HEIGHT)->second, "1001");
    EXPECT_EQ(KValueStr.find("ERRORCODE"), KValueStr.end());
}

/**
 * @tc.name: GetAllPropertiesTest003
 * @tc.desc: If you set the same key value twice, only one pair of values can be obtained for the FHIR llProperties.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, GetAllPropertiesTest003, TestSize.Level1)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_HEIGHT, "1001"));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_HEIGHT, "1000"));
    ImageMetadata::PropertyMapPtr propertyMap = fragmentMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    std::map<std::string, std::string> KValueStr = *(propertyMap);
    ASSERT_EQ(KValueStr.find(FRAGMENT_METADATA_KEY_HEIGHT)->second, "1000");
}

/**
 * @tc.name: CloneMetadataTest001
 * @tc.desc: Obtain a clone of FragmentMetadata.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, CloneMetadataTest001, TestSize.Level1)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_WIDTH, "1000"));
    std::shared_ptr<ImageMetadata> newmetadata = fragmentMetadata.CloneMetadata();
    std::string oldValue, newValue;
    newmetadata->GetValue(FRAGMENT_METADATA_KEY_WIDTH, newValue);
    fragmentMetadata.GetValue(FRAGMENT_METADATA_KEY_WIDTH, oldValue);
    EXPECT_EQ(newValue, oldValue);
    ImageMetadata::PropertyMapPtr propertyMap = fragmentMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    std::map<std::string, std::string> oldKValueStr = *(propertyMap);
    propertyMap = newmetadata->GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    std::map<std::string, std::string> newKValueStr = *propertyMap;
    EXPECT_EQ(oldKValueStr.size(), newKValueStr.size());
}

/**
 * @tc.name: RemoveEntryTest001
 * @tc.desc: Remove a supported key and subtract one from the length obtained by getAllProperties.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, RemoveEntryTest001, TestSize.Level1)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_X, "300"));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_Y, "256"));
    ImageMetadata::PropertyMapPtr propertyMap = fragmentMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    std::map<std::string, std::string> KValueStr = *propertyMap;
    ASSERT_EQ(KValueStr.size(), 2);
    fragmentMetadata.RemoveEntry(FRAGMENT_METADATA_KEY_X);
    propertyMap = fragmentMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    KValueStr = *propertyMap;
    EXPECT_EQ(KValueStr.size(), 1);
    EXPECT_EQ(KValueStr.find(FRAGMENT_METADATA_KEY_X), KValueStr.end());
}

/**
 * @tc.name: RemoveEntryTest002
 * @tc.desc: Delete unsupported keys and keys that have not been set before.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, RemoveEntryTest002, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_X, "300"));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_Y, "256"));
    ImageMetadata::PropertyMapPtr propertyMap = fragmentMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    std::map<std::string, std::string> KValueStr = *(propertyMap);
    ASSERT_EQ(KValueStr.size(), 2);
    fragmentMetadata.RemoveEntry("ERRORCODE");
    propertyMap = fragmentMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    KValueStr = *propertyMap;
    EXPECT_EQ(KValueStr.size(), 2);
    fragmentMetadata.RemoveEntry(FRAGMENT_METADATA_KEY_WIDTH);
    propertyMap = fragmentMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    KValueStr = *propertyMap;
    EXPECT_EQ(KValueStr.size(), 2);
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Correct serialization.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, MarshallingTest001, TestSize.Level1)
{
    Parcel parcel;
    FragmentMetadata fragmentMetadata;
    EXPECT_TRUE(fragmentMetadata.Marshalling(parcel));
}

/**
 * @tc.name: UnmarshallingTest001
 * @tc.desc: Correct serialization and deserialization to obtain FragmentMetadata.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, UnmarshallingTest001, TestSize.Level1)
{
    Parcel parcel;
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_X, "300"));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_Y, "256"));
    ASSERT_TRUE(fragmentMetadata.Marshalling(parcel));
    ImageKvMetadata* newfragmentMetadata = fragmentMetadata.Unmarshalling(parcel);
    ASSERT_NE(newfragmentMetadata, nullptr);
    std::map<std::string, std::string> KValueStr = *(newfragmentMetadata->GetAllProperties());
    EXPECT_EQ(KValueStr.size(), 2);
    EXPECT_EQ(KValueStr.find(FRAGMENT_METADATA_KEY_X)->second, "300");
    EXPECT_EQ(KValueStr.find(FRAGMENT_METADATA_KEY_Y)->second, "256");
    delete newfragmentMetadata;
}

/**
 * @tc.name: UnmarshallingTest002
 * @tc.desc: Operate after serialization and compare after deserialization.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, UnmarshallingTest002, TestSize.Level2)
{
    Parcel parcel;
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.Marshalling(parcel));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_X, "300"));
    ASSERT_TRUE(fragmentMetadata.SetValue(FRAGMENT_METADATA_KEY_Y, "256"));
    ImageKvMetadata* newfragmentMetadata = fragmentMetadata.Unmarshalling(parcel);
    ASSERT_NE(newfragmentMetadata, nullptr);
    std::map<std::string, std::string> KValueStr = *(newfragmentMetadata->GetAllProperties());
    EXPECT_EQ(KValueStr.size(), 0);
    delete newfragmentMetadata;
}

/**
 * @tc.name: GetValueTest005
 * @tc.desc: Test GetValue when properties is nullptr or didn't find key in properties.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, GetValueTest005, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    std::string key = "key";
    std::string value = "value";
    fragmentMetadata.properties_ = nullptr;

    int errCode = fragmentMetadata.GetValue(key, value);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);

    fragmentMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(fragmentMetadata.properties_, nullptr);
    errCode = fragmentMetadata.GetValue(key, value);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);
    key = FRAGMENT_METADATA_KEY_X;

    errCode = fragmentMetadata.GetValue(key, value);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: SetValueTest003
 * @tc.desc: Test SetValue when properties is nullptr or value is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, SetValueTest003, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    std::string key = FRAGMENT_METADATA_KEY_X;
    std::string value = "";
    fragmentMetadata.properties_ = nullptr;

    bool res = fragmentMetadata.SetValue(key, value);
    EXPECT_FALSE(res);

    fragmentMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(fragmentMetadata.properties_, nullptr);
    res = fragmentMetadata.SetValue(key, value);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: SetValueTest004
 * @tc.desc: Test SetValue when the size of properties is invalid or the length of value is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, SetValueTest004, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    fragmentMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(fragmentMetadata.properties_, nullptr);
    *fragmentMetadata.properties_ = {
        {"key0", "value0"}, {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}, {"key4", "value4"},
        {"key5", "value5"}, {"key6", "value6"}, {"key7", "value7"}, {"key8", "value8"}, {"key9", "value9"}
    };
    std::string key = FRAGMENT_METADATA_KEY_X;
    std::string value = "value";
    ASSERT_EQ(fragmentMetadata.properties_->size(), MAX_FRAGMENT_MAP_META_COUNT);

    bool res = fragmentMetadata.SetValue(key, value);
    EXPECT_FALSE(res);

    while (value.length() > MAX_FRAGMENT_MAP_META_LENGTH) {
        value += value;
    }
    res = fragmentMetadata.SetValue(key, value);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: RemoveEntryTest003
 * @tc.desc: Test RemoveEntry when propertie is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, RemoveEntryTest003, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    std::string key = "key";
    fragmentMetadata.properties_ = nullptr;

    bool res = fragmentMetadata.RemoveEntry(key);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: CloneMetadataTest002
 * @tc.desc: Test CloneMetadata when the size of properties is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, CloneMetadataTest002, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    fragmentMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(fragmentMetadata.properties_, nullptr);
    *fragmentMetadata.properties_ = {
        {"key0", "value0"}, {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}, {"key4", "value4"},
        {"key5", "value5"}, {"key6", "value6"}, {"key7", "value7"}, {"key8", "value8"}, {"key9", "value9"},
        {"over_size", "over_size"}
    };
    ASSERT_EQ(fragmentMetadata.properties_->size(), MAX_FRAGMENT_MAP_META_COUNT + 1);

    auto res = fragmentMetadata.CloneMetadata();
    ASSERT_EQ(res, nullptr);
}

/**
 * @tc.name: MarshallingTest002
 * @tc.desc: Test Marshalling when properties is nullptr or the size of properties is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, MarshallingTest002, TestSize.Level2)
{
    Parcel parcel;
    FragmentMetadata fragmentMetadata;
    fragmentMetadata.properties_ = nullptr;

    bool res = fragmentMetadata.Marshalling(parcel);
    EXPECT_FALSE(res);

    fragmentMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(fragmentMetadata.properties_, nullptr);
    *fragmentMetadata.properties_ = {
        {"key0", "value0"}, {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}, {"key4", "value4"},
        {"key5", "value5"}, {"key6", "value6"}, {"key7", "value7"}, {"key8", "value8"}, {"key9", "value9"},
        {"over_size", "over_size"}
    };
    ASSERT_EQ(fragmentMetadata.properties_->size(), MAX_FRAGMENT_MAP_META_COUNT + 1);
    res = fragmentMetadata.Marshalling(parcel);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: UnmarshallingInvalidKeyTest001
 * @tc.desc: Test Unmarshalling with invalid key
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, UnmarshallingInvalidKeyTest001, TestSize.Level3)
{
    Parcel parcel;
    
    parcel.WriteInt32(static_cast<int32_t>(MetadataType::FRAGMENT));
    parcel.WriteUint64(TEST_PARCEL_SIZE_ONE);
    parcel.WriteString("invalid_key");
    parcel.WriteString("value");
    
    FragmentMetadata fragmentMetadata;
    ImageKvMetadata* result = fragmentMetadata.Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: UnmarshallingStringLengthExceedTest001
 * @tc.desc: Test Unmarshalling when string length exceeds limit
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, UnmarshallingStringLengthExceedTest001, TestSize.Level3)
{
    Parcel parcel;
    
    std::string longString(MAX_FRAGMENT_MAP_META_LENGTH + 1, 'a');
    
    parcel.WriteInt32(static_cast<int32_t>(MetadataType::FRAGMENT));
    parcel.WriteUint64(TEST_PARCEL_SIZE_ONE);
    parcel.WriteString(FRAGMENT_METADATA_KEY_X);
    parcel.WriteString(longString);
    
    FragmentMetadata fragmentMetadata;
    ImageKvMetadata* result = fragmentMetadata.Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: UnmarshallingErrorLogTest001
 * @tc.desc: Test Unmarshalling error logging branch expect result is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, UnmarshallingErrorLogTest001, TestSize.Level3)
{
    Parcel parcel;
    
    parcel.WriteInt32(TEST_INVALID_METADATA_TYPE);
    
    FragmentMetadata fragmentMetadata;
    ImageKvMetadata* result = fragmentMetadata.Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: MarshallingInvalidKeyTest001
 * @tc.desc: Test Marshalling with invalid key in properties
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, MarshallingInvalidKeyTest001, TestSize.Level3)
{
    Parcel parcel;
    FragmentMetadata fragmentMetadata;
    
    fragmentMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    fragmentMetadata.properties_->insert(std::make_pair("invalid_key", "value"));
    
    bool res = fragmentMetadata.Marshalling(parcel);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: MarshallingStringLengthExceedTest001
 * @tc.desc: Test Marshalling when string length exceeds limit
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, MarshallingStringLengthExceedTest001, TestSize.Level3)
{
    Parcel parcel;
    FragmentMetadata fragmentMetadata;
    
    std::string longString(MAX_FRAGMENT_MAP_META_LENGTH + 1, 'a');
    
    fragmentMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    fragmentMetadata.properties_->insert(std::make_pair(FRAGMENT_METADATA_KEY_X, longString));
    
    bool res = fragmentMetadata.Marshalling(parcel);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: IsValidKeyInvalidMetadataTypeTest001
 * @tc.desc: Test IsValidKey with invalid metadata type
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, IsValidKeyInvalidMetadataTypeTest001, TestSize.Level3)
{
    FragmentMetadata fragmentMetadata;
    fragmentMetadata.metadataType_ = static_cast<MetadataType>(TEST_INVALID_METADATA_TYPE);
    
    std::string key = FRAGMENT_METADATA_KEY_X;
    std::string value = "100";
    
    bool res = fragmentMetadata.SetValue(key, value);
    EXPECT_FALSE(res);
}
} // namespace OHOS
} // namespace Multimedia