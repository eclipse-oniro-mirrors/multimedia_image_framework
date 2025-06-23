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
#define private public
#define protected public
#include "gif_metadata.h"
#include "image_log.h"
#include "media_errors.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
const static uint64_t MAX_GIF_META_COUNT = 10;
const static uint64_t MAX_GIF_META_LENGTH = 128;

class GifMetadataTest : public testing::Test {
public:
    GifMetadataTest() {}
    ~GifMetadataTest() {}
};

/**
 * @tc.name: SetValueTest001
 * @tc.desc: Pass in the supported key and set the value.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, SetValueTest001, TestSize.Level1)
{
    GifMetadata gifMetadata;
    EXPECT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "33"));
    EXPECT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DISPOSAL_TYPE, "1"));
}

/**
 * @tc.name: SetValueTest002
 * @tc.desc: Pass in unsupported key and set value.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, SetValueTest002, TestSize.Level2)
{
    GifMetadata gifMetadata;
    EXPECT_FALSE(gifMetadata.SetValue("BitsPerSample", "1002"));
}

/**
 * @tc.name: GetValueTest001
 * @tc.desc: Set supported keys and values and use getValue to obtain this value.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, GetValueTest001, TestSize.Level1)
{
    GifMetadata gifMetadata;
    EXPECT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "33"));
    EXPECT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DISPOSAL_TYPE, "1"));

    std::string value;
    uint32_t state = gifMetadata.GetValue(GIF_METADATA_KEY_DELAY_TIME, value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "33");
    state = gifMetadata.GetValue(GIF_METADATA_KEY_DISPOSAL_TYPE, value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "1");
}

/**
 * @tc.name: GetValueTest002
 * @tc.desc: Set the value of supported keys, and use getValue to pass in unsupported keys.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, GetValueTest002, TestSize.Level2)
{
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "50"));

    std::string value;
    uint32_t state = gifMetadata.GetValue(FRAGMENT_METADATA_KEY_X, value);
    EXPECT_EQ(state, ERR_IMAGE_INVALID_PARAMETER);
    EXPECT_EQ(value, "");
}

/**
 * @tc.name: GetValueTest003
 * @tc.desc: Set the value of the supported key, and use getValue to pass in the supported key that has not been set.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, GetValueTest003, TestSize.Level2)
{
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "50"));

    std::string value;
    uint32_t state = gifMetadata.GetValue(GIF_METADATA_KEY_DISPOSAL_TYPE, value);
    EXPECT_EQ(state, ERR_IMAGE_INVALID_PARAMETER);
    EXPECT_EQ(value, "");
}

/**
 * @tc.name: GetValueTest004
 * @tc.desc: Set a key twice, getValue to get the latest value.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, GetValueTest004, TestSize.Level1)
{
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "50"));
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "30"));

    std::string value;
    uint32_t state = gifMetadata.GetValue(GIF_METADATA_KEY_DELAY_TIME, value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "30");
}

/**
 * @tc.name: GetAllPropertiesTest001
 * @tc.desc: Obtain all set keys and values.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, GetAllPropertiesTest001, TestSize.Level1)
{
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "33"));
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DISPOSAL_TYPE, "1"));

    ImageMetadata::PropertyMapPtr propertyMap = gifMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    std::map<std::string, std::string> KValueStr = *(propertyMap);
    EXPECT_EQ(KValueStr.size(), 2);
    EXPECT_EQ(KValueStr.find(GIF_METADATA_KEY_DELAY_TIME)->second, "33");
    EXPECT_EQ(KValueStr.find(GIF_METADATA_KEY_DISPOSAL_TYPE)->second, "1");
}

/**
 * @tc.name: GetAllPropertiesTest002
 * @tc.desc: When setting a key, set an unsupported key. getAllProperties only retrieves supported keys and values.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, GetAllPropertiesTest002, TestSize.Level2)
{
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "33"));
    ASSERT_FALSE(gifMetadata.SetValue("ERRORCODE", "1000"));

    ImageMetadata::PropertyMapPtr propertyMap = gifMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    std::map<std::string, std::string> KValueStr = *(propertyMap);
    EXPECT_EQ(KValueStr.size(), 1);
    EXPECT_EQ(KValueStr.find(GIF_METADATA_KEY_DELAY_TIME)->second, "33");
    EXPECT_EQ(KValueStr.find("ERRORCODE"), KValueStr.end());
}

/**
 * @tc.name: GetAllPropertiesTest003
 * @tc.desc: If you set the same key value twice, only one pair of values can be obtained for the FHIR llProperties.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, GetAllPropertiesTest003, TestSize.Level1)
{
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "33"));
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "50"));

    ImageMetadata::PropertyMapPtr propertyMap = gifMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);
    std::map<std::string, std::string> KValueStr = *(propertyMap);
    ASSERT_EQ(KValueStr.find(GIF_METADATA_KEY_DELAY_TIME)->second, "50");
}

/**
 * @tc.name: CloneMetadataTest001
 * @tc.desc: Obtain a clone of GifMetadata.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, CloneMetadataTest001, TestSize.Level1)
{
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "33"));
    std::shared_ptr<ImageMetadata> newMetadata = gifMetadata.CloneMetadata();

    std::string oldValue, newValue;
    newMetadata->GetValue(GIF_METADATA_KEY_DELAY_TIME, newValue);
    gifMetadata.GetValue(GIF_METADATA_KEY_DELAY_TIME, oldValue);
    EXPECT_EQ(newValue, oldValue);

    ImageMetadata::PropertyMapPtr propertyMap = gifMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);

    std::map<std::string, std::string> oldKValueStr = *(propertyMap);
    propertyMap = newMetadata->GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);

    std::map<std::string, std::string> newKValueStr = *propertyMap;
    EXPECT_EQ(oldKValueStr.size(), newKValueStr.size());
}

/**
 * @tc.name: RemoveEntryTest001
 * @tc.desc: Remove a supported key and subtract one from the length obtained by getAllProperties.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, RemoveEntryTest001, TestSize.Level1)
{
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "33"));
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DISPOSAL_TYPE, "1"));

    ImageMetadata::PropertyMapPtr propertyMap = gifMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);

    std::map<std::string, std::string> KValueStr = *propertyMap;
    ASSERT_EQ(KValueStr.size(), 2);

    gifMetadata.RemoveEntry(GIF_METADATA_KEY_DELAY_TIME);
    propertyMap = gifMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);

    KValueStr = *propertyMap;
    EXPECT_EQ(KValueStr.size(), 1);
    EXPECT_EQ(KValueStr.find(GIF_METADATA_KEY_DELAY_TIME), KValueStr.end());
}

/**
 * @tc.name: RemoveEntryTest002
 * @tc.desc: Delete unsupported keys and keys that have not been set before.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, RemoveEntryTest002, TestSize.Level2)
{
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "33"));

    ImageMetadata::PropertyMapPtr propertyMap = gifMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);

    std::map<std::string, std::string> KValueStr = *(propertyMap);
    ASSERT_EQ(KValueStr.size(), 1);

    gifMetadata.RemoveEntry("ERRORCODE");
    propertyMap = gifMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);

    KValueStr = *propertyMap;
    EXPECT_EQ(KValueStr.size(), 1);

    gifMetadata.RemoveEntry(GIF_METADATA_KEY_DISPOSAL_TYPE);
    propertyMap = gifMetadata.GetAllProperties();
    ASSERT_NE(propertyMap, nullptr);

    KValueStr = *propertyMap;
    EXPECT_EQ(KValueStr.size(), 1);
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Correct serialization.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, MarshallingTest001, TestSize.Level1)
{
    Parcel parcel;
    GifMetadata gifMetadata;
    EXPECT_TRUE(gifMetadata.Marshalling(parcel));
}

/**
 * @tc.name: UnmarshallingTest001
 * @tc.desc: Correct serialization and deserialization to obtain GifMetadata.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, UnmarshallingTest001, TestSize.Level1)
{
    Parcel parcel;
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "33"));
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DISPOSAL_TYPE, "1"));

    ASSERT_TRUE(gifMetadata.Marshalling(parcel));
    ImageKvMetadata* newGifMetadata = gifMetadata.Unmarshalling(parcel);
    ASSERT_NE(newGifMetadata, nullptr);

    std::map<std::string, std::string> KValueStr = *(newGifMetadata->GetAllProperties());
    EXPECT_EQ(KValueStr.size(), 2);
    EXPECT_EQ(KValueStr.find(GIF_METADATA_KEY_DELAY_TIME)->second, "33");
    EXPECT_EQ(KValueStr.find(GIF_METADATA_KEY_DISPOSAL_TYPE)->second, "1");
    delete newGifMetadata;
}

/**
 * @tc.name: UnmarshallingTest002
 * @tc.desc: Operate after serialization and compare after deserialization.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, UnmarshallingTest002, TestSize.Level2)
{
    Parcel parcel;
    GifMetadata gifMetadata;
    ASSERT_TRUE(gifMetadata.Marshalling(parcel));
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DELAY_TIME, "33"));
    ASSERT_TRUE(gifMetadata.SetValue(GIF_METADATA_KEY_DISPOSAL_TYPE, "1"));

    ImageKvMetadata* newGifMetadata = gifMetadata.Unmarshalling(parcel);
    ASSERT_NE(newGifMetadata, nullptr);

    std::map<std::string, std::string> KValueStr = *(newGifMetadata->GetAllProperties());
    EXPECT_EQ(KValueStr.size(), 0);
    delete newGifMetadata;
}

/**
 * @tc.name: GetValueTest005
 * @tc.desc: Test GetValue when properties is nullptr or didn't find key in properties.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, GetValueTest005, TestSize.Level2)
{
    GifMetadata gifMetadata;
    std::string key = "key";
    std::string value = "value";
    gifMetadata.properties_ = nullptr;

    int errCode = gifMetadata.GetValue(key, value);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);

    gifMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(gifMetadata.properties_, nullptr);
    errCode = gifMetadata.GetValue(key, value);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);

    errCode = gifMetadata.GetValue(GIF_METADATA_KEY_DELAY_TIME, value);
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: SetValueTest003
 * @tc.desc: Test SetValue when properties is nullptr or value is empty.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, SetValueTest003, TestSize.Level2)
{
    GifMetadata gifMetadata;
    std::string key = GIF_METADATA_KEY_DELAY_TIME;
    std::string value = "";
    gifMetadata.properties_ = nullptr;

    bool res = gifMetadata.SetValue(key, value);
    EXPECT_FALSE(res);

    gifMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(gifMetadata.properties_, nullptr);
    res = gifMetadata.SetValue(key, value);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: SetValueTest004
 * @tc.desc: Test SetValue when the size of properties is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, SetValueTest004, TestSize.Level2)
{
    GifMetadata gifMetadata;
    gifMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(gifMetadata.properties_, nullptr);
    *gifMetadata.properties_ = {
        {"key0", "value0"}, {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}, {"key4", "value4"},
        {"key5", "value5"}, {"key6", "value6"}, {"key7", "value7"}, {"key8", "value8"}, {"key9", "value9"}
    };
    std::string key = GIF_METADATA_KEY_DELAY_TIME;
    std::string value = "value";
    ASSERT_EQ(gifMetadata.properties_->size(), MAX_GIF_META_COUNT);

    bool res = gifMetadata.SetValue(key, value);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: SetValueTest005
 * @tc.desc: Test SetValue when the length of value is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, SetValueTest005, TestSize.Level2)
{
    GifMetadata gifMetadata;
    gifMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(gifMetadata.properties_, nullptr);

    std::string key = GIF_METADATA_KEY_DELAY_TIME;
    std::string value = "value";
    while (value.length() <= MAX_GIF_META_LENGTH) {
        value += value;
    }
    bool res = gifMetadata.SetValue(key, value);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: RemoveEntryTest003
 * @tc.desc: Test RemoveEntry when propertie is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, RemoveEntryTest003, TestSize.Level2)
{
    GifMetadata gifMetadata;
    std::string key = "key";
    gifMetadata.properties_ = nullptr;

    bool res = gifMetadata.RemoveEntry(key);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: CloneMetadataTest002
 * @tc.desc: Test CloneMetadata when the size of properties is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, CloneMetadataTest002, TestSize.Level2)
{
    GifMetadata gifMetadata;
    gifMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(gifMetadata.properties_, nullptr);
    *gifMetadata.properties_ = {
        {"key0", "value0"}, {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}, {"key4", "value4"},
        {"key5", "value5"}, {"key6", "value6"}, {"key7", "value7"}, {"key8", "value8"}, {"key9", "value9"},
        {"over_size", "over_size"}
    };
    ASSERT_EQ(gifMetadata.properties_->size(), MAX_GIF_META_COUNT + 1);

    auto res = gifMetadata.CloneMetadata();
    ASSERT_EQ(res, nullptr);
}

/**
 * @tc.name: MarshallingTest002
 * @tc.desc: Test Marshalling when properties is nullptr or the size of properties is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(GifMetadataTest, MarshallingTest002, TestSize.Level2)
{
    Parcel parcel;
    GifMetadata gifMetadata;
    gifMetadata.properties_ = nullptr;

    bool res = gifMetadata.Marshalling(parcel);
    EXPECT_FALSE(res);

    gifMetadata.properties_ = std::make_shared<ImageMetadata::PropertyMap>();
    ASSERT_NE(gifMetadata.properties_, nullptr);
    *gifMetadata.properties_ = {
        {"key0", "value0"}, {"key1", "value1"}, {"key2", "value2"}, {"key3", "value3"}, {"key4", "value4"},
        {"key5", "value5"}, {"key6", "value6"}, {"key7", "value7"}, {"key8", "value8"}, {"key9", "value9"},
        {"over_size", "over_size"}
    };
    ASSERT_EQ(gifMetadata.properties_->size(), MAX_GIF_META_COUNT + 1);
    res = gifMetadata.Marshalling(parcel);
    EXPECT_FALSE(res);
}
} // namespace OHOS
} // namespace Multimedia