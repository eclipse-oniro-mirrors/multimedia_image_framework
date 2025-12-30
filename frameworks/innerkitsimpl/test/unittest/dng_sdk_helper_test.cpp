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
#include "dng/dng_sdk_helper.h"
#include "dng/dng_sdk_info.h"
#include "image_log.h"
#include "media_errors.h"

#include "dng_host.h"
#include "dng_stream.h"
#include "metadata_stream.h"
#include <memory>
#include <gtest/gtest.h>

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "DngSdkHelperTest"

using namespace testing::ext;

namespace OHOS {
namespace Media {

class DngSdkHelperTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: ParseInfoFromStreamTest001
 * @tc.desc: NullStream_ReturnsNullptr
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkHelperTest, ParseInfoFromStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ParseInfoFromStreamTeset001 start";
    std::shared_ptr<MetadataStream> nullStream = nullptr;
    auto result = DngSdkHelper::ParseInfoFromStream(nullStream);
    EXPECT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "ParseInfoFromStreamTest001 end";
}

/**
 * @tc.name: GetExifPropertyTest001
 * @tc.desc: NullInfo_ReturnsError
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkHelperTest, GetExifPropertyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetExifPropertyTest001 start";
    std::unique_ptr<DngSdkInfo> nullInfo = nullptr;
    MetadataValue value;
    auto ret = DngSdkHelper::GetExifProperty(nullInfo, value);
    EXPECT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "GetExifPropertyTest001 end";
}

/**
 * @tc.name: GetExifPropertyTest002
 * @tc.desc: All property options fail to retrieve, expect ERR_IMAGE_DECODE_EXIF_UNSUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkHelperTest, GetExifPropertyTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetExifPropertyTest002 start";

    class MockDngSdkInfo : public DngSdkInfo {
    public:
        uint32_t GetProperty(MetadataValue& value, const DngPropertyOption& option) {
            return ERR_IMAGE_GET_DATA_ABNORMAL;
        }
    };

    auto mockInfo = std::make_unique<MockDngSdkInfo>();
    std::unique_ptr<DngSdkInfo> baseInfo = std::move(mockInfo);
    MetadataValue value;
    value.key = "HwMnoteCaptureMode";

    auto ret = DngSdkHelper::GetExifProperty(baseInfo, value);
    EXPECT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    GTEST_LOG_(INFO) << "GetExifPropertyTest002 end";
}

/**
 * @tc.name: SetExifPropertyTest001
 * @tc.desc: Test SetExifProperty with null DngSdkInfo, expect return ERR_IMAGE_DECODE_EXIF_UNSUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkHelperTest, SetExifPropertyTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetExifPropertyTest001";
    std::unique_ptr<DngSdkInfo> nullInfo = nullptr;
    MetadataValue value;
    value.key = "HwMnoteCaptureMode";
    value.type = PropertyValueType::STRING;
    value.stringValue = "Normal";

    auto ret = DngSdkHelper::SetExifProperty(nullInfo, value);
    EXPECT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "SetExifPropertyTest001 end";
}

/**
 * @tc.name: SetExifPropertyTest002
 * @tc.desc: All property options fail to set, expect ERR_IMAGE_DECODE_EXIF_UNSUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkHelperTest, SetExifPropertyTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "SetExifPropertyTest002 start";

    class MockDngSdkInfo : public DngSdkInfo {
    public:
        uint32_t SetProperty(const MetadataValue& value, const DngPropertyOption& option) {
            return ERR_IMAGE_GET_DATA_ABNORMAL;
        }
    };

    auto mockInfo = std::make_unique<MockDngSdkInfo>();
    std::unique_ptr<DngSdkInfo> baseInfo = std::move(mockInfo);
    MetadataValue value;
    value.key = "HwMnoteCaptureMode";
    value.type = PropertyValueType::STRING;
    value.stringValue = "HDR";

    auto ret = DngSdkHelper::SetExifProperty(baseInfo, value);
    EXPECT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    GTEST_LOG_(INFO) << "SetExifPropertyTest002 end";
}
} // namespace Media
} // namespace OHOS