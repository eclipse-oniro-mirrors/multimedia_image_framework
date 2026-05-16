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
HWTEST_F(DngSdkInfoTest, ParseDoubleTagTest001, TestSize.Level3)
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

/**
 * @tc.name: GetExifCopyrightTest001
 * @tc.desc: Test GetExifCopyright with empty photographer/editor fields
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetExifCopyrightTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifCopyrightTest001 start";

    dng_exif fExif{};
    fExif.fCopyright.Clear();
    fExif.fCopyright2.Clear();
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetExifCopyright(fExif, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::STRING);
    EXPECT_NE(value.stringValue.find("[None]"), std::string::npos);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifCopyrightTest001 end";
}

/**
 * @tc.name: GetExifCopyrightTest002
 * @tc.desc: Test GetExifCopyright with valid photographer and editor fields
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetExifCopyrightTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifCopyrightTest002 start";

    dng_exif fExif{};
    fExif.fCopyright.Set("Photographer Name");
    fExif.fCopyright2.Set("Editor Name");
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetExifCopyright(fExif, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::STRING);
    EXPECT_NE(value.stringValue.find("Photographer Name"), std::string::npos);
    EXPECT_NE(value.stringValue.find("Editor Name"), std::string::npos);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifCopyrightTest002 end";
}

/**
 * @tc.name: GetExifUserCommentTest001
 * @tc.desc: Test GetExifUserComment with empty comment
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetExifUserCommentTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifUserCommentTest001 start";

    dng_exif fExif{};
    fExif.fUserComment.Clear();
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetExifUserComment(fExif, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::STRING);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifUserCommentTest001 end";
}

/**
 * @tc.name: GetExifFileSourceTest001
 * @tc.desc: Test GetExifFileSource returns BLOB type
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetExifFileSourceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifFileSourceTest001 start";

    dng_exif fExif{};
    fExif.fFileSource = 3;
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetExifFileSource(fExif, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::BLOB);
    EXPECT_EQ(value.bufferValue.size(), 1U);
    EXPECT_EQ(value.bufferValue[0], static_cast<uint8_t>(3));

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifFileSourceTest001 end";
}

/**
 * @tc.name: GetExifSceneTypeTest001
 * @tc.desc: Test GetExifSceneType returns BLOB type
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetExifSceneTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifSceneTypeTest001 start";

    dng_exif fExif{};
    fExif.fSceneType = 1;
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetExifSceneType(fExif, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::BLOB);
    EXPECT_EQ(value.bufferValue.size(), 1U);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetExifSceneTypeTest001 end";
}

/**
 * @tc.name: GetSharedDNGVersionTest001
 * @tc.desc: Test GetSharedDNGVersion returns INT_ARRAY type with 4 elements
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetSharedDNGVersionTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetSharedDNGVersionTest001 start";

    dng_shared fShared{};
    fShared.fDNGVersion = 0x01040000;
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetSharedDNGVersion(fShared, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::INT_ARRAY);
    EXPECT_EQ(value.intArrayValue.size(), 4U);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetSharedDNGVersionTest001 end";
}

/**
 * @tc.name: GetIfdDefaultCropSizeTest001
 * @tc.desc: Test GetIfdDefaultCropSize with denominator != 0
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetIfdDefaultCropSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdDefaultCropSizeTest001 start";

    dng_ifd fIFD{};
    fIFD.fDefaultCropSizeH.n = 100;
    fIFD.fDefaultCropSizeH.d = 1;
    fIFD.fDefaultCropSizeV.n = 200;
    fIFD.fDefaultCropSizeV.d = 1;
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetIfdDefaultCropSize(fIFD, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::INT_ARRAY);
    EXPECT_EQ(value.intArrayValue.size(), 2U);
    EXPECT_EQ(value.intArrayValue[0], 100);
    EXPECT_EQ(value.intArrayValue[1], 200);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdDefaultCropSizeTest001 end";
}

/**
 * @tc.name: GetIfdDefaultCropSizeTest002
 * @tc.desc: Test GetIfdDefaultCropSize with denominator == 0 (edge case)
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetIfdDefaultCropSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdDefaultCropSizeTest002 start";

    dng_ifd fIFD{};
    fIFD.fDefaultCropSizeH.n = 100;
    fIFD.fDefaultCropSizeH.d = 0;
    fIFD.fDefaultCropSizeV.n = 200;
    fIFD.fDefaultCropSizeV.d = 0;
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetIfdDefaultCropSize(fIFD, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::INT_ARRAY);
    EXPECT_EQ(value.intArrayValue.size(), 2U);
    EXPECT_EQ(value.intArrayValue[0], 0);
    EXPECT_EQ(value.intArrayValue[1], 0);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdDefaultCropSizeTest002 end";
}

/**
 * @tc.name: GetIfdYCbCrCoefficientsTest001
 * @tc.desc: Test GetIfdYCbCrCoefficients returns DOUBLE_ARRAY with 3 elements
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetIfdYCbCrCoefficientsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdYCbCrCoefficientsTest001 start";

    dng_ifd fIFD{};
    fIFD.fYCbCrCoefficientR = 0.299;
    fIFD.fYCbCrCoefficientG = 0.587;
    fIFD.fYCbCrCoefficientB = 0.114;
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetIfdYCbCrCoefficients(fIFD, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::DOUBLE_ARRAY);
    EXPECT_EQ(value.doubleArrayValue.size(), 3U);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdYCbCrCoefficientsTest001 end";
}

/**
 * @tc.name: GetIfdYCbCrSubSamplingTest001
 * @tc.desc: Test GetIfdYCbCrSubSampling returns INT_ARRAY with 2 elements
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetIfdYCbCrSubSamplingTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdYCbCrSubSamplingTest001 start";

    dng_ifd fIFD{};
    fIFD.fYCbCrSubSampleH = 2;
    fIFD.fYCbCrSubSampleV = 1;
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetIfdYCbCrSubSampling(fIFD, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::INT_ARRAY);
    EXPECT_EQ(value.intArrayValue.size(), 2U);
    EXPECT_EQ(value.intArrayValue[0], 2);
    EXPECT_EQ(value.intArrayValue[1], 1);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdYCbCrSubSamplingTest001 end";
}

/**
 * @tc.name: GetIfdBlackLevelRepeatDimTest001
 * @tc.desc: Test GetIfdBlackLevelRepeatDim returns INT_ARRAY with 2 elements
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetIfdBlackLevelRepeatDimTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdBlackLevelRepeatDimTest001 start";

    dng_ifd fIFD{};
    fIFD.fBlackLevelRepeatRows = 2;
    fIFD.fBlackLevelRepeatCols = 2;
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetIfdBlackLevelRepeatDim(fIFD, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::INT_ARRAY);
    EXPECT_EQ(value.intArrayValue.size(), 2U);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdBlackLevelRepeatDimTest001 end";
}

/**
 * @tc.name: GetIfdActiveAreaTest001
 * @tc.desc: Test GetIfdActiveArea returns INT_ARRAY with 4 elements
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetIfdActiveAreaTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdActiveAreaTest001 start";

    dng_ifd fIFD{};
    fIFD.fActiveArea.t = 0;
    fIFD.fActiveArea.l = 0;
    fIFD.fActiveArea.b = 100;
    fIFD.fActiveArea.r = 100;
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetIfdActiveArea(fIFD, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::INT_ARRAY);
    EXPECT_EQ(value.intArrayValue.size(), 4U);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdActiveAreaTest001 end";
}

/**
 * @tc.name: GetIfdSubTileBlockSizeTest001
 * @tc.desc: Test GetIfdSubTileBlockSize returns INT_ARRAY with 2 elements
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetIfdSubTileBlockSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdSubTileBlockSizeTest001 start";

    dng_ifd fIFD{};
    fIFD.fSubTileBlockRows = 1;
    fIFD.fSubTileBlockCols = 1;
    MetadataValue value{};
    uint32_t ret = DngSdkInfo::GetIfdSubTileBlockSize(fIFD, value);
    EXPECT_EQ(ret, SUCCESS);
    EXPECT_EQ(value.type, PropertyValueType::INT_ARRAY);
    EXPECT_EQ(value.intArrayValue.size(), 2U);

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetIfdSubTileBlockSizeTest001 end";
}

/**
 * @tc.name: IsSpecialTagNameTest001
 * @tc.desc: Test IsSpecialTagName with known special tag name
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, IsSpecialTagNameTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: IsSpecialTagNameTest001 start";

    DngSdkInfo sdkInfo;
    EXPECT_TRUE(sdkInfo.IsSpecialTagName("SubfileType"));
    EXPECT_TRUE(sdkInfo.IsSpecialTagName("ExposureTime"));
    EXPECT_FALSE(sdkInfo.IsSpecialTagName("UnknownTag"));
    EXPECT_FALSE(sdkInfo.IsSpecialTagName(""));

    GTEST_LOG_(INFO) << "DngSdkInfoTest: IsSpecialTagNameTest001 end";
}

/**
 * @tc.name: GetAllPropertyKeysTest001
 * @tc.desc: Test GetAllPropertyKeys returns non-empty set
 * @tc.type: FUNC
 */
HWTEST_F(DngSdkInfoTest, GetAllPropertyKeysTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetAllPropertyKeysTest001 start";

    std::set<std::string> keys = DngSdkInfo::GetAllPropertyKeys();
    EXPECT_FALSE(keys.empty());
    EXPECT_TRUE(keys.find("Make") != keys.end());
    EXPECT_TRUE(keys.find("Model") != keys.end());
    EXPECT_TRUE(keys.find("GPSLatitude") != keys.end());
    EXPECT_TRUE(keys.find("DNGVersion") != keys.end());

    GTEST_LOG_(INFO) << "DngSdkInfoTest: GetAllPropertyKeysTest001 end";
}
} // namespace Media
} // namespace OHOS