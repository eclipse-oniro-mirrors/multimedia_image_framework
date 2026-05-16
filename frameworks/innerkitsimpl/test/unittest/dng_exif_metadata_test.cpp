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
#include "dng/dng_exif_metadata.h"
#include "dng/dng_sdk_info.h"
#include "exif_metadata.h"
#include "media_errors.h"
#include <memory>
#include <gtest/gtest.h>

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "DngExifMetadata"

using namespace testing::ext;

namespace OHOS {
namespace Media {

class DngExifMetadataTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: GetExifPropertyTest001
 * @tc.desc: Test GetExifProperty when dngSdkInfo_ is nullptr, expect return ERR_IMAGE_DECODE_EXIF_UNSUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataTest, GetExifPropertyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetExifPropertyTest001 start";
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    dngExifMetadata->dngSdkInfo_ = nullptr;
    MetadataValue value;
    auto ret = dngExifMetadata->GetExifProperty(value);
    EXPECT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetExifPropertyTest001 end";
}

/**
 * @tc.name: GetExifPropertyTest002
 * @tc.desc: Test GetExifProperty when key is empty string, expect return DngSdkHelper's result for empty key.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataTest, GetExifPropertyTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetExifPropertyTest002 start";
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    ASSERT_NE(dngExifMetadata, nullptr);
    dngExifMetadata->dngSdkInfo_ = std::make_unique<DngSdkInfo>();
    ASSERT_NE(dngExifMetadata->dngSdkInfo_, nullptr);
    MetadataValue value;
    value.key = "";
    auto ret = dngExifMetadata->GetExifProperty(value);
    EXPECT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetExifPropertyTest002 end";
}

/**
 * @tc.name: GetExifPropertyTest003
 * @tc.desc: Test GetExifProperty when key is HwUnknow and DngExifMetadata's inherited exifData_ is nullptr,
 *           expect return ERR_IMAGE_DECODE_EXIF_UNSUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataTest, GetExifPropertyTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetExifPropertyTest003 start";
    std::unique_ptr<DngSdkInfo> sdkInfo = std::make_unique<DngSdkInfo>();
    auto dngExifMetadata = std::make_shared<DngExifMetadata>(nullptr, sdkInfo);
    ASSERT_NE(dngExifMetadata, nullptr);
    MetadataValue value;
    value.key = "HwUnknow";
    auto ret = dngExifMetadata->GetExifProperty(value);
    EXPECT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetExifPropertyTest003 end";
}

/**
 * @tc.name: GetAllDngPropertiesTest001
 * @tc.desc: Test GetAllDngProperties when dngSdkInfo_ is nullptr, expect return empty vector.
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataTest, GetAllDngPropertiesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetAllDngPropertiesTest001 start";
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    dngExifMetadata->dngSdkInfo_ = nullptr;
    auto ret = dngExifMetadata->GetAllDngProperties();
    EXPECT_TRUE(ret.empty());
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetAllDngPropertiesTest001 end";
}

/**
 * @tc.name: GetAllDngPropertiesTest002
 * @tc.desc: Test GetAllDngProperties with valid dngSdkInfo_, verify function executes normally
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataTest, GetAllDngPropertiesTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetAllDngPropertiesTest002 start";
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    dngExifMetadata->dngSdkInfo_ = std::make_unique<DngSdkInfo>();
    ASSERT_NE(dngExifMetadata->dngSdkInfo_, nullptr);
    auto properties = dngExifMetadata->GetAllDngProperties();
    EXPECT_EQ(properties.size(), 0);
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetAllDngPropertiesTest002 end";
}

/**
 * @tc.name: GetImageRawDataTest001
 * @tc.desc: Test GetImageRawData with null stream
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataTest, GetImageRawDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetImageRawDataTest001 start";
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    std::vector<uint8_t> data;
    uint32_t bitsPerSample = 0;
    uint32_t ret = dngExifMetadata->GetImageRawData(nullptr, data, bitsPerSample);
    EXPECT_EQ(ret, ERR_IMAGE_GET_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetImageRawDataTest001 end";
}

/**
 * @tc.name: GetValueTest001
 * @tc.desc: Test GetValue with empty key
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataTest, GetValueTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetValueTest001 start";
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    std::string value;
    uint32_t ret = dngExifMetadata->GetValue("", value);
    EXPECT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "DngExifMetadataTest: GetValueTest001 end";
}

/**
 * @tc.name: SetValueTest001
 * @tc.desc: Test SetValue with empty key
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataTest, SetValueTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngExifMetadataTest: SetValueTest001 start";
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    bool ret = dngExifMetadata->SetValue("", "test_value");
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "DngExifMetadataTest: SetValueTest001 end";
}

/**
 * @tc.name: RemoveEntryTest001
 * @tc.desc: Test RemoveEntry with empty key
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataTest, RemoveEntryTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngExifMetadataTest: RemoveEntryTest001 start";
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    bool ret = dngExifMetadata->RemoveEntry("");
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "DngExifMetadataTest: RemoveEntryTest001 end";
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Test Marshalling with null exifData_
 * @tc.type: FUNC
 */
HWTEST_F(DngExifMetadataTest, MarshallingTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngExifMetadataTest: MarshallingTest001 start";
    std::shared_ptr<DngExifMetadata> dngExifMetadata = std::make_shared<DngExifMetadata>();
    Parcel parcel;
    bool ret = dngExifMetadata->Marshalling(parcel);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "DngExifMetadataTest: MarshallingTest001 end";
}
} // namespace Media
} // namespace OHOS