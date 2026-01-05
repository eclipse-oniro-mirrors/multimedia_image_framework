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
} // namespace Media
} // namespace OHOS