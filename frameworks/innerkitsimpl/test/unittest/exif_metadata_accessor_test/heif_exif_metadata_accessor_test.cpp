/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <memory>

#include "buffer_metadata_stream.h"
#include "file_metadata_stream.h"
#include "heif_exif_metadata_accessor.h"
#include "log_tags.h"
#include "media_errors.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
namespace {
static const std::string IMAGE_INPUT_HEIF_EXIF_PATH = "/data/local/tmp/image/test_exif.heic";
static const std::string IMAGE_INPUT_HEIF_HW_EXIF_PATH = "/data/local/tmp/image/test_hw_property.heic";
static const std::string IMAGE_INPUT_HEIF_NO_EXIF_PATH = "/data/local/tmp/image/test.heic";
static const std::string IMAGE_INPUT_HEIF_APPEND_EXIF_PATH = "/data/local/tmp/image/test_append_exif.heic";
static const std::string IMAGE_HEIF_DEST = "/data/local/tmp/image/test_exif_packer.heic";
static const std::string IMAGE_OUTPUT_WRITE1_HEIF_PATH = "/data/local/tmp/image/test_heif_writemetadata002.heic";
}

class HeifExifMetadataAccessorTest : public testing::Test {
public:
    HeifExifMetadataAccessorTest() {}
    ~HeifExifMetadataAccessorTest() {}
    std::string GetProperty(const std::shared_ptr<ExifMetadata> &metadata, const std::string &key);
};

std::string HeifExifMetadataAccessorTest::GetProperty(const std::shared_ptr<ExifMetadata> &metadata,
    const std::string &key)
{
    std::string value;
    metadata->GetValue(key, value);
    return value;
}

/**
 * @tc.name: Read001
 * @tc.desc: test the Heif format get exif properties
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read001 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_EXIF_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    ASSERT_NE(exifMetadata, nullptr);

    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "E");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitude"), "31, 15, 4.71");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitude"), "121, 35, 43.32");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2024:03:18 18:15:41");
    ASSERT_EQ(GetProperty(exifMetadata, "Make"), "Apple");
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "iPhone 13");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTimeOriginal"), "2024:03:18 18:15:41");
    ASSERT_EQ(GetProperty(exifMetadata, "SceneType"), "Directly photographed");
    ASSERT_EQ(GetProperty(exifMetadata, "DateTime"), "2024:03:18 18:15:41");
    ASSERT_EQ(GetProperty(exifMetadata, "WhiteBalance"), "Auto white balance");

    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read001 end";
}

/**
 * @tc.name: Read002
 * @tc.desc: test the Heif format get no exif
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read002 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_NO_EXIF_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA);

    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read002 end";
}


/**
 * @tc.name: Read003
 * @tc.desc: test the Heif format get exif HW properties
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read003 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_HW_EXIF_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteBurstNumber"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteCaptureMode"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceConf"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceCount"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceLeyeCenter"), "1 2 3 4");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceMouthCenter"), "1 2 3 4 5 6 7 8");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFacePointer"), "122");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceRect"), "1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceReyeCenter"), "5 6 7 8");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceSmileScore"), "1 2 3 4 5 6 7 8");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFaceVersion"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFocusMode"), "7");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteFrontCamera"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnotePhysicalAperture"), "6");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnotePitchAngle"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteRollAngle"), "4");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneBeachConf"), "6");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneBlueSkyConf"), "4");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneFlowersConf"), "9");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneFoodConf"), "2");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneGreenPlantConf"), "5");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneNightConf"), "10");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteScenePointer"), "256");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneSnowConf"), "7");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneStageConf"), "3");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneSunsetConf"), "8");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneTextConf"), "11");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteSceneVersion"), "1");
    ASSERT_EQ(GetProperty(exifMetadata, "MakerNote"), "HwMnoteCaptureMode:1,HwMnoteBurstNumber:2,HwMnoteFrontCamera:3,"
        "HwMnoteRollAngle:4,HwMnotePitchAngle:5,HwMnotePhysicalAperture:6,"
        "HwMnoteFocusMode:7,HwMnoteFacePointer:122,HwMnoteFaceVersion:1,"
        "HwMnoteFaceCount:2,HwMnoteFaceConf:3,HwMnoteFaceSmileScore:1 2 3 4 5 6 7 8,"
        "HwMnoteFaceRect:1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8,"
        "HwMnoteFaceLeyeCenter:1 2 3 4,HwMnoteFaceReyeCenter:5 6 7 8,"
        "HwMnoteFaceMouthCenter:1 2 3 4 5 6 7 8,HwMnoteScenePointer:256,"
        "HwMnoteSceneVersion:1,HwMnoteSceneFoodConf:2,HwMnoteSceneStageConf:3,"
        "HwMnoteSceneBlueSkyConf:4,HwMnoteSceneGreenPlantConf:5,HwMnoteSceneBeachConf:6,"
        "HwMnoteSceneSnowConf:7,HwMnoteSceneSunsetConf:8,HwMnoteSceneFlowersConf:9,"
        "HwMnoteSceneNightConf:10,HwMnoteSceneTextConf:11");

    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read003 end";
}

/**
 * @tc.name: Write001
 * @tc.desc: test the Heif format get exif properties
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Write001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Write001 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_EXIF_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    exifMetadata->SetValue("Model", "test heif");
    uint32_t errcode = imageAccessor.Write();
    ASSERT_EQ(errcode, SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "test heif");

    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Write001 end";
}

/**
 * @tc.name: Write002
 * @tc.desc: test Write from nonexisting image file, return error number
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Write002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Write002 start";

    std::shared_ptr<MetadataStream> writeStream = std::make_shared<FileMetadataStream>(IMAGE_OUTPUT_WRITE1_HEIF_PATH);
    ASSERT_TRUE(writeStream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageWriteAccessor(writeStream);
    uint32_t errcode = imageWriteAccessor.Write();
    ASSERT_EQ(errcode, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Write002 end";
}

/**
 * @tc.name: Read001
 * @tc.desc: test the Heif format get exif properties
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Append001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Append001 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_APPEND_EXIF_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA);
    auto exifMetadata = imageAccessor.Get();

    if (exifMetadata == nullptr) {
        bool ret = imageAccessor.Create();
        ASSERT_EQ(ret, true);
        GTEST_LOG_(INFO) << "Create exif matadata success...";
        exifMetadata = imageAccessor.Get();
    }

    bool retSet = exifMetadata->SetValue("Model", "test");
    ASSERT_EQ(retSet, true);
    retSet = exifMetadata->SetValue("GPSLatitudeRef", "N");
    ASSERT_EQ(retSet, true);
    retSet = exifMetadata->SetValue("GPSLongitudeRef", "E");
    ASSERT_EQ(retSet, true);
    uint32_t errcode = imageAccessor.Write();
    ASSERT_EQ(errcode, SUCCESS);

    std::shared_ptr<MetadataStream> newStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_APPEND_EXIF_PATH);
    ASSERT_TRUE(newStream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessorNew(newStream);
    result = imageAccessorNew.Read();
    ASSERT_EQ(result, 0);
    auto newExifdata = imageAccessorNew.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "Model"), "test");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLatitudeRef"), "N");
    ASSERT_EQ(GetProperty(exifMetadata, "GPSLongitudeRef"), "E");

    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Append001 end";
}


} // namespace Multimedia
} // namespace OHOS