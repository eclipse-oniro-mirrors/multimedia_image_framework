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

#if defined(SUPPORT_LIBTIFF)
#include <algorithm>
#include <gtest/gtest.h>
#include <vector>

#include "media_errors.h"
#include "tiff_exif_metadata.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
const std::string IMAGE_TIFF_PATH = "/data/local/tmp/image/read_test.tiff";
const std::string IMAGE_TIFF_XMP_PATH = "/data/local/tmp/image/tiff_xmp.tiff";
}

class TiffExifMetadataTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: GetExifPropertyTest001
 * @tc.desc: Test TIFF metadata reports unsupported when the TIFF handle is absent.
 * @tc.type: FUNC
 */
HWTEST_F(TiffExifMetadataTest, GetExifPropertyTest001, TestSize.Level3)
{
    TiffExifMetadata metadata;
    MetadataValue value = {.key = "TiffMake"};

    EXPECT_EQ(metadata.GetExifProperty(value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    std::vector<MetadataValue> properties = {{.key = "seed"}};
    metadata.GetAllTiffProperties(properties);
    EXPECT_EQ(properties.size(), 1U);
    EXPECT_EQ(metadata.Clone(), nullptr);
}

/**
 * @tc.name: GetExifPropertyTest002
 * @tc.desc: Test TIFF IFD tags are read from a valid TIFF handle.
 * @tc.type: FUNC
 */
HWTEST_F(TiffExifMetadataTest, GetExifPropertyTest002, TestSize.Level3)
{
    TIFF* tiffHandle = TIFFOpen(IMAGE_TIFF_PATH.c_str(), "r");
    ASSERT_NE(tiffHandle, nullptr);
    TiffExifMetadata metadata(nullptr, tiffHandle);

    MetadataValue description = {.key = "TiffImageDescription"};
    EXPECT_EQ(metadata.GetExifProperty(description), SUCCESS);
    EXPECT_EQ(description.stringValue, "Test image with comprehensive tags");

    MetadataValue compression = {.key = "TiffCompression"};
    EXPECT_EQ(metadata.GetExifProperty(compression), SUCCESS);
    ASSERT_EQ(compression.intArrayValue.size(), 1U);
    EXPECT_EQ(compression.intArrayValue[0], 1);
}

/**
 * @tc.name: GetExifPropertyTest003
 * @tc.desc: Test absent TIFF tags become unsupported after TIFF and EXIF directory lookup.
 * @tc.type: FUNC
 */
HWTEST_F(TiffExifMetadataTest, GetExifPropertyTest003, TestSize.Level3)
{
    TIFF* tiffHandle = TIFFOpen(IMAGE_TIFF_XMP_PATH.c_str(), "r");
    ASSERT_NE(tiffHandle, nullptr);
    TiffExifMetadata metadata(nullptr, tiffHandle);
    MetadataValue value = {.key = "TiffTileWidth"};

    EXPECT_EQ(metadata.GetExifProperty(value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
}

/**
 * @tc.name: GetExifPropertyTest004
 * @tc.desc: Test non-TIFF keys fall back to ExifMetadata lookup.
 * @tc.type: FUNC
 */
HWTEST_F(TiffExifMetadataTest, GetExifPropertyTest004, TestSize.Level3)
{
    TIFF* tiffHandle = TIFFOpen(IMAGE_TIFF_PATH.c_str(), "r");
    ASSERT_NE(tiffHandle, nullptr);
    TiffExifMetadata metadata(nullptr, tiffHandle);
    ASSERT_TRUE(metadata.CreateExifdata());
    ASSERT_TRUE(metadata.SetValue("ImageWidth", "64"));
    MetadataValue value = {.key = "ImageWidth"};

    EXPECT_EQ(metadata.GetExifProperty(value), SUCCESS);
    EXPECT_EQ(value.intArrayValue, std::vector<int64_t>({64}));

    MetadataValue unsupported = {.key = "UnknownProperty"};
    EXPECT_EQ(metadata.GetExifProperty(unsupported), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
}

/**
 * @tc.name: GetAllTiffPropertiesTest001
 * @tc.desc: Test available TIFF properties are collected from the TIFF metadata map.
 * @tc.type: FUNC
 */
HWTEST_F(TiffExifMetadataTest, GetAllTiffPropertiesTest001, TestSize.Level3)
{
    TIFF* tiffHandle = TIFFOpen(IMAGE_TIFF_PATH.c_str(), "r");
    ASSERT_NE(tiffHandle, nullptr);
    TiffExifMetadata metadata(nullptr, tiffHandle);
    std::vector<MetadataValue> properties;

    metadata.GetAllTiffProperties(properties);

    EXPECT_FALSE(properties.empty());
    auto it = std::find_if(properties.begin(), properties.end(), [](const MetadataValue& value) {
        return value.key == "TiffImageDescription" &&
            value.stringValue == "Test image with comprehensive tags";
    });
    EXPECT_NE(it, properties.end());
}
} // namespace Media
} // namespace OHOS
#endif // defined(SUPPORT_LIBTIFF)
