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
#include "dng/dng_sdk_info.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <memory>
#include <vector>

#include "dng_memory.h"
#include "image_log.h"
#include "image_utils.h"
#include "media_errors.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {

class MockDngStream : public dng_stream {
public:
    MockDngStream() : dng_stream() {}
    ~MockDngStream() = default;

    void SetTestData(const uint8_t* data, size_t size)
    {
        testData_ = data;
        testDataSize_ = size;
        position_ = 0;
        getCallCount_ = 0;
    }

    uint64_t Position() const { return position_; }
    uint64_t Length() const { return testDataSize_; }

    void SetReadPosition(uint64_t pos)
    {
        position_ = std::min(pos, static_cast<uint64_t>(testDataSize_));
    }

    void Get(void* data, uint32_t count)
    {
        getCallCount_++;
        if (!data || count == 0) {
            return;
        }
        if (position_ >= testDataSize_) {
            std::fill_n(static_cast<unsigned char*>(data), count, 0);
            position_ += count;
            return;
        }
        size_t remaining = testDataSize_ - position_;
        size_t toCopy = std::min(static_cast<size_t>(count), remaining);
        std::copy_n(testData_ + position_, toCopy, static_cast<char*>(data));
        position_ += toCopy;
        if (toCopy < count) {
            std::fill_n(static_cast<unsigned char*>(data) + toCopy, count - toCopy, 0);
            position_ += (count - toCopy);
        }
    }

    size_t GetCallCount() const { return getCallCount_; }
    void ResetCallCount() { getCallCount_ = 0; }

private:
    const uint8_t* testData_ = nullptr;
    size_t testDataSize_ = 0;
    uint64_t position_ = 0;
    size_t getCallCount_ = 0;
};

class DngSdkInfoTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};


/**
 * @tc.name: GetExifExifVersionTest001
 * @tc.desc: Cover all if/else if branches of GetExifExifVersion (all EXIF versions + default branch)
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetExifExifVersionTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifExifVersionTest001 start";
    constexpr uint32_t exifVersionUintUnknown = 0x00000000;
    constexpr uint32_t exifVersionUint0110 = 0x30313130;
    constexpr uint32_t exifVersionUint0120 = 0x30313230;
    constexpr uint32_t exifVersionUint0200 = 0x30323030;
    constexpr uint32_t exifVersionUint0210 = 0x30323130;
    constexpr uint32_t exifVersionUint0220 = 0x30323230;
    constexpr uint32_t exifVersionUint0221 = 0x30323231;
    constexpr uint32_t exifVersionUint0230 = 0x30323330;
    constexpr uint32_t exifVersionUint0231 = 0x30323331;
    constexpr uint32_t exifVersionUint0232 = 0x30323332;

    const std::vector<std::pair<uint32_t, std::string>> versionMap = {
        {exifVersionUint0110, "Exif Version 1.1"},
        {exifVersionUint0120, "Exif Version 1.2"},
        {exifVersionUint0200, "Exif Version 2.0"},
        {exifVersionUint0210, "Exif Version 2.1"},
        {exifVersionUint0220, "Exif Version 2.2"},
        {exifVersionUint0221, "Exif Version 2.21"},
        {exifVersionUint0230, "Exif Version 2.3"},
        {exifVersionUint0231, "Exif Version 2.31"},
        {exifVersionUint0232, "Exif Version 2.32"},
        {exifVersionUintUnknown, "Unknown Exif Version"}
    };

    for (const auto& [versionVal, expectedStr] : versionMap) {
        dng_exif fExif{};
        fExif.fExifVersion = versionVal;
        MetadataValue value{};

        const uint32_t ret = DngSdkInfo::GetExifExifVersion(fExif, value);

        EXPECT_EQ(ret, SUCCESS)
            << "Return value is not SUCCESS for version: " << versionVal;
        EXPECT_EQ(value.type, PropertyValueType::STRING)
            << "Type mismatch for version: " << versionVal;
        EXPECT_EQ(value.stringValue, expectedStr)
            << "StringValue mismatch for version: " << versionVal
            << "\nExpected: " << expectedStr
            << "\nActual:   " << value.stringValue;
    }
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifExifVersionTest001 end";
}

/**
 * @tc.name: GetExifComponentsConfigurationTest001
 * @tc.desc: Cover first if branch (component <= MAX_INDEX / component > MAX_INDEX)
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetExifComponentsConfigurationTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifComponentsConfigurationTest001 start";
    constexpr uint32_t componentLabelMaxIndex = 6;
    constexpr uint32_t componentMinInvalidIndex = 7;
    constexpr uint32_t shiftBits24 = 24;
    
    dng_exif fExifValid{};
    fExifValid.fComponentsConfiguration = componentLabelMaxIndex << shiftBits24;
    MetadataValue valueValid{};
    uint32_t retValid = DngSdkInfo::GetExifComponentsConfiguration(fExifValid, valueValid);
    EXPECT_EQ(retValid, SUCCESS);
    EXPECT_EQ(valueValid.type, PropertyValueType::STRING);
    EXPECT_NE(valueValid.stringValue.find(" B"), std::string::npos);

    dng_exif fExifInvalid{};
    fExifInvalid.fComponentsConfiguration = componentMinInvalidIndex << shiftBits24;
    MetadataValue valueInvalid{};
    uint32_t retInvalid = DngSdkInfo::GetExifComponentsConfiguration(fExifInvalid, valueInvalid);
    EXPECT_EQ(retInvalid, SUCCESS);
    EXPECT_NE(valueInvalid.stringValue.find(" Reserved"), std::string::npos);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifComponentsConfigurationTest001 end";
}

/**
 * @tc.name: GetExifFlashPixVersionTest001
 * @tc.desc: Cover if (1.0)/else if (1.01)/else (unknown) branches of GetExifFlashPixVersion
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetExifFlashPixVersionTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifFlashPixVersionTest001 start";
    constexpr uint32_t flashVersionUint10 = 0x30313030;
    constexpr uint32_t flashVersionUint101 = 0x30313031;
    constexpr uint32_t flashVersionUintUnknown = 0x30323030;

    dng_exif fExifV10{};
    fExifV10.fFlashPixVersion = flashVersionUint10;
    MetadataValue valueV10{};
    uint32_t retV10 = DngSdkInfo::GetExifFlashPixVersion(fExifV10, valueV10);
    EXPECT_EQ(retV10, SUCCESS);
    EXPECT_EQ(valueV10.type, PropertyValueType::STRING);
    EXPECT_EQ(valueV10.stringValue, "FlashPix Version 1.0");

    dng_exif fExifV101{};
    fExifV101.fFlashPixVersion = flashVersionUint101;
    MetadataValue valueV101{};
    uint32_t retV101 = DngSdkInfo::GetExifFlashPixVersion(fExifV101, valueV101);
    EXPECT_EQ(retV101, SUCCESS);
    EXPECT_EQ(valueV101.type, PropertyValueType::STRING);
    EXPECT_EQ(valueV101.stringValue, "FlashPix Version 1.01");

    dng_exif fExifUnknown{};
    fExifUnknown.fFlashPixVersion = flashVersionUintUnknown;
    MetadataValue valueUnknown{};
    uint32_t retUnknown = DngSdkInfo::GetExifFlashPixVersion(fExifUnknown, valueUnknown);
    EXPECT_EQ(retUnknown, SUCCESS);
    EXPECT_EQ(valueUnknown.type, PropertyValueType::STRING);
    EXPECT_EQ(valueUnknown.stringValue, "Unknown FlashPix Version");
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifFlashPixVersionTest001 end";
}

/**
 * @tc.name: ParseShortTagToStringTest001
 * @tc.desc: Test ParseShortTagToString when tagRecord.tagCount is 0, expect no stream read and empty string.
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, ParseShortTagToStringTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: ParseShortTagToStringTest001 start";

    DngTagRecord tagRecord = {};
    tagRecord.tagCount = 0;

    MockDngStream mockStream;
    uint8_t fakeData[] = {0x12, 0x34, 0x56, 0x78};
    mockStream.SetTestData(fakeData, sizeof(fakeData));

    MetadataValue value;
    DngSdkInfo dngSdkInfo;

    uint32_t result = dngSdkInfo.ParseShortTagToString(tagRecord, mockStream, value);

    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::STRING);
    EXPECT_TRUE(value.stringValue.empty());
    EXPECT_EQ(mockStream.GetCallCount(), 0U);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: ParseShortTagToStringTest001 end";
}

/**
 * @tc.name: ParseIntTagTest001
 * @tc.desc: Test ParseIntTag with tagCount = 0, expect empty intArrayValue and SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, ParseIntTagTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: ParseIntTagTest001 start";

    DngTagRecord tagRecord = {};
    tagRecord.tagCount = 0;
    tagRecord.tagType = ttShort;

    MockDngStream stream;
    uint8_t dummy[] = {0x01, 0x02};
    stream.SetTestData(dummy, sizeof(dummy));

    MetadataValue value;
    uint32_t result = DngSdkInfo::ParseIntTag(tagRecord, stream, value);

    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::INT);
    EXPECT_TRUE(value.intArrayValue.empty());
    EXPECT_EQ(stream.GetCallCount(), 0U);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: ParseIntTagTest001 end";
}

/**
 * @tc.name: ParseDoubleTagTest001
 * @tc.desc: Test ParseDoubleTag with tagCount = 0, expect empty doubleArrayValue and SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, ParseDoubleTtagTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: ParseDoubleTagTest001 start";

    DngTagRecord tagRecord = {};
    tagRecord.tagCount = 0;
    tagRecord.tagType = ttDouble;
    MockDngStream stream;
    MetadataValue value;
    uint32_t result = DngSdkInfo::ParseDoubleTag(tagRecord, stream, value);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::DOUBLE);
    EXPECT_TRUE(value.doubleArrayValue.empty());

    GTEST_LOG_(INFO) << "DngSdkInfoTest: ParseDoubleTagTest001 end";
}
} // namespace Media
} // namespace OHOS