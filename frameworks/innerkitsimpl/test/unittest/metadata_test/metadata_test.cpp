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
#include "libexif/exif-tag.h"
#include "media_errors.h"
#include "tiff_parser.h"
#include "exif_metadata.h"
#include "exif_metadata_formatter.h"
#include "image_log.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_metadata.jpg";
class MetadataTest : public testing::Test {
public:
    MetadataTest() {}
    ~MetadataTest() {}
};

/**
* @tc.name: GetAllPropertiesTest001
* @tc.desc: Obtain all keys and values by setting supported keys.
*           Set exif metadata with unformated value and get exif metadata with formated value.
* @tc.type: FUNC
*/
HWTEST_F(MetadataTest, GetAllPropertiesTest001, TestSize.Level1)
{
    ImageMetadata::PropertyMapPtr KValueStr;
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    ExifMetadata metadata(exifData);

    ASSERT_TRUE(metadata.SetValue("BitsPerSample", "9,9,9"));
    ASSERT_TRUE(metadata.SetValue("GPSLatitude", "39,54,20"));

    KValueStr = metadata.GetAllProperties();
    EXPECT_EQ(KValueStr->find("BitsPerSample")->second, "9, 9, 9");
    EXPECT_EQ(KValueStr->find("GPSLatitude")->second, "39, 54, 20");
}

/**
* @tc.name: GetAllPropertiesTest002
* @tc.desc: Obtain all keys and values by setting unsupported keys.
* @tc.type: FUNC
*/
HWTEST_F(MetadataTest, GetAllPropertiesTest002, TestSize.Level2)
{
    ImageMetadata::PropertyMapPtr KValueStr;
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    ExifMetadata metadata(exifData);

    ASSERT_FALSE(metadata.SetValue("ERRORCODE", "120,52"));
    KValueStr = metadata.GetAllProperties();
    EXPECT_EQ(KValueStr->find("ERRORCODE"), KValueStr->end());
}

/**
* @tc.name: CloneMetadataTest001
* @tc.desc: Set the correct exifdata to obtain a clone.
* @tc.type: FUNC
*/
HWTEST_F(MetadataTest, CloneMetadataTest001, TestSize.Level1)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("ImageLength", "1000"));
    std::shared_ptr<ImageMetadata> newmetadata = metadata.CloneMetadata();
    std::string oldValue, newValue;
    newmetadata->GetValue("ImageLength", newValue);
    metadata.GetValue("ImageLength", oldValue);
    EXPECT_EQ(newValue, oldValue);
}

/**
* @tc.name: CloneMetadataTest002
* @tc.desc: Reset the value after cloning and check if the values are not equal.
* @tc.type: FUNC
*/
HWTEST_F(MetadataTest, CloneMetadataTest002, TestSize.Level1)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    ExifMetadata metadata(exifData);
    ASSERT_TRUE(metadata.SetValue("ImageLength", "1000"));
    std::shared_ptr<ImageMetadata> newmetadata = metadata.CloneMetadata();
    std::string oldValue, newValue;
    ASSERT_TRUE(metadata.SetValue("ImageLength", "1005"));
    newmetadata->GetValue("ImageLength", newValue);
    metadata.GetValue("ImageLength", oldValue);
    EXPECT_NE(newValue, oldValue);
}

/**
* @tc.name: CloneMetadataTest003
* @tc.desc: Set empty exifdata to obtain clones.
* @tc.type: FUN
*/
HWTEST_F(MetadataTest, CloneMetadataTest003, TestSize.Level2)
{
    auto exifData = exif_data_new_from_file(nullptr);
    ExifMetadata metadata(exifData);
    std::shared_ptr<ImageMetadata> newmetadata = metadata.CloneMetadata();
    ASSERT_EQ(newmetadata, nullptr);
}
} // namespace OHOS
} // namespace Multimedia