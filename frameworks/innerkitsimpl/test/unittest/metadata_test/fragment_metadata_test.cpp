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
#include "media_errors.h"
#include "metadata.h"
#include "fragment_metadata.h"
#include "image_log.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
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
    EXPECT_TRUE(fragmentMetadata.SetValue("X_IN_ORIGINAL", "300"));
    EXPECT_TRUE(fragmentMetadata.SetValue("Y_IN_ORIGINAL", "256"));
    EXPECT_TRUE(fragmentMetadata.SetValue("WIDTH", "1000"));
    EXPECT_TRUE(fragmentMetadata.SetValue("HEIGHT", "1001"));
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
    ASSERT_TRUE(fragmentMetadata.SetValue("X_IN_ORIGINAL", "300"));
    ASSERT_TRUE(fragmentMetadata.SetValue("Y_IN_ORIGINAL", "256"));
    ASSERT_TRUE(fragmentMetadata.SetValue("WIDTH", "1000"));
    ASSERT_TRUE(fragmentMetadata.SetValue("HEIGHT", "1001"));
    std::string value;
    uint32_t state = fragmentMetadata.GetValue("X_IN_ORIGINAL", value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "300");
    state = fragmentMetadata.GetValue("Y_IN_ORIGINAL", value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "256");
    state = fragmentMetadata.GetValue("WIDTH", value);
    EXPECT_EQ(state, SUCCESS);
    EXPECT_EQ(value, "1000");
    state = fragmentMetadata.GetValue("HEIGHT", value);
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
    ASSERT_TRUE(fragmentMetadata.SetValue("HEIGHT", "1001"));
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
    ASSERT_TRUE(fragmentMetadata.SetValue("HEIGHT", "1001"));
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
    ASSERT_TRUE(fragmentMetadata.SetValue("HEIGHT", "1001"));
    ASSERT_TRUE(fragmentMetadata.SetValue("HEIGHT", "1000"));
    std::string value;
    uint32_t state = fragmentMetadata.GetValue("HEIGHT", value);
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
    ASSERT_TRUE(fragmentMetadata.SetValue("HEIGHT", "1001"));
    ASSERT_TRUE(fragmentMetadata.SetValue("WIDTH", "1000"));
    std::map<std::string, std::string> KValueStr = *(fragmentMetadata.GetAllProperties());
    EXPECT_EQ(KValueStr.size(), 2);
    EXPECT_EQ(KValueStr.find("HEIGHT")->second, "1001");
    EXPECT_EQ(KValueStr.find("WIDTH")->second, "1000");
}

/**
 * @tc.name: GetAllPropertiesTest002
 * @tc.desc: When setting a key, set an unsupported key. getAllProperties only retrieves supported keys and values.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, GetAllPropertiesTest002, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue("HEIGHT", "1001"));
    ASSERT_FALSE(fragmentMetadata.SetValue("ERRORCODE", "1000"));
    std::map<std::string, std::string> KValueStr = *(fragmentMetadata.GetAllProperties());
    EXPECT_EQ(KValueStr.size(), 1);
    EXPECT_EQ(KValueStr.find("HEIGHT")->second, "1001");
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
    ASSERT_TRUE(fragmentMetadata.SetValue("HEIGHT", "1001"));
    ASSERT_TRUE(fragmentMetadata.SetValue("HEIGHT", "1000"));
    std::map<std::string, std::string> KValueStr = *(fragmentMetadata.GetAllProperties());
    ASSERT_EQ(KValueStr.find("HEIGHT")->second, "1000");
}

/**
 * @tc.name: CloneMetadataTest001
 * @tc.desc: Obtain a clone of FragmentMetadata.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, CloneMetadataTest001, TestSize.Level1)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue("WIDTH", "1000"));
    std::shared_ptr<ImageMetadata> newmetadata = fragmentMetadata.CloneMetadata();
    std::string oldValue, newValue;
    newmetadata->GetValue("WIDTH", newValue);
    fragmentMetadata.GetValue("WIDTH", oldValue);
    EXPECT_EQ(newValue, oldValue);
    std::map<std::string, std::string> oldKValueStr = *(fragmentMetadata.GetAllProperties());
    std::map<std::string, std::string> newKValueStr = *(newmetadata->GetAllProperties());
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
    ASSERT_TRUE(fragmentMetadata.SetValue("X_IN_ORIGINAL", "300"));
    ASSERT_TRUE(fragmentMetadata.SetValue("Y_IN_ORIGINAL", "256"));
    std::map<std::string, std::string> KValueStr = *(fragmentMetadata.GetAllProperties());
    ASSERT_EQ(KValueStr.size(), 2);
    fragmentMetadata.RemoveEntry("X_IN_ORIGINAL");
    KValueStr = *(fragmentMetadata.GetAllProperties());
    EXPECT_EQ(KValueStr.size(), 1);
    EXPECT_EQ(KValueStr.find("X_IN_ORIGINAL"), KValueStr.end());
}

/**
 * @tc.name: RemoveEntryTest002
 * @tc.desc: Delete unsupported keys and keys that have not been set before.
 * @tc.type: FUNC
 */
HWTEST_F(FragmentMetadataTest, RemoveEntryTest002, TestSize.Level2)
{
    FragmentMetadata fragmentMetadata;
    ASSERT_TRUE(fragmentMetadata.SetValue("X_IN_ORIGINAL", "300"));
    ASSERT_TRUE(fragmentMetadata.SetValue("Y_IN_ORIGINAL", "256"));
    std::map<std::string, std::string> KValueStr = *(fragmentMetadata.GetAllProperties());
    ASSERT_EQ(KValueStr.size(), 2);
    fragmentMetadata.RemoveEntry("ERRORCODE");
    KValueStr = *(fragmentMetadata.GetAllProperties());
    EXPECT_EQ(KValueStr.size(), 2);
    fragmentMetadata.RemoveEntry("WIDTH");
    KValueStr = *(fragmentMetadata.GetAllProperties());
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
    ASSERT_TRUE(fragmentMetadata.SetValue("X_IN_ORIGINAL", "300"));
    ASSERT_TRUE(fragmentMetadata.SetValue("Y_IN_ORIGINAL", "256"));
    ASSERT_TRUE(fragmentMetadata.Marshalling(parcel));
    FragmentMetadata* newfragmentMetadata = fragmentMetadata.Unmarshalling(parcel);
    ASSERT_NE(newfragmentMetadata, nullptr);
    std::map<std::string, std::string> KValueStr = *(newfragmentMetadata->GetAllProperties());
    EXPECT_EQ(KValueStr.size(), 2);
    EXPECT_EQ(KValueStr.find("X_IN_ORIGINAL")->second, "300");
    EXPECT_EQ(KValueStr.find("Y_IN_ORIGINAL")->second, "256");
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
    ASSERT_TRUE(fragmentMetadata.SetValue("X_IN_ORIGINAL", "300"));
    ASSERT_TRUE(fragmentMetadata.SetValue("Y_IN_ORIGINAL", "256"));
    FragmentMetadata* newfragmentMetadata = fragmentMetadata.Unmarshalling(parcel);
    ASSERT_NE(newfragmentMetadata, nullptr);
    std::map<std::string, std::string> KValueStr = *(newfragmentMetadata->GetAllProperties());
    EXPECT_EQ(KValueStr.size(), 0);
}

} // namespace OHOS
} // namespace Multimedia