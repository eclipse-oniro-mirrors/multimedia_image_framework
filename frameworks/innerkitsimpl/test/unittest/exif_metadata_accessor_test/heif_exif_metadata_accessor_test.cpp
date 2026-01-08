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

#define private public
#define protected public

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
static const std::string IMAGE_INPUT_CR3_PATH = "/data/local/tmp/image/test.cr3";

static const size_t TIFF_BYTE_SIZE = 1;
static const uint8_t TIFF_MAGIC_NUMBER = 0x2A;
static const uint8_t TIFF_MAGIC_NUMBER_LOW = 0x00;
static const uint8_t TIFF_IFD_OFFSET = 0x08;
constexpr size_t RANDOM_DATA_SIZE = 100;
constexpr int DIRECTORY_PERMISSIONS = 0777;
constexpr size_t INVALID_FILE_SIZE = 256;
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
 * @tc.name: Read004
 * @tc.desc: test read when parse cr3 file.
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read004 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_CR3_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read004 end";
}

/**
 * @tc.name: Read005
 * @tc.desc: test read when checkTiffPos return false.
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read005 start";
    const std::string invalidTiffPath = "/data/local/tmp/image/invalid_tiff.heic";
    {
        FILE *fp = fopen(invalidTiffPath.c_str(), "wb");
        ASSERT_NE(fp, nullptr);
        const char dummy[] = "NOT_A_TIFF";
        fwrite(dummy, TIFF_BYTE_SIZE, sizeof(dummy), fp);
        fclose(fp);
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(invalidTiffPath);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA);
    remove(invalidTiffPath.c_str());
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read005 end";
}

/**
 * @tc.name: Read006
 * @tc.desc: test read when exifData is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read006 start";
    const unsigned char invalidTiffData[] = {
        'I', 'I', TIFF_MAGIC_NUMBER, TIFF_MAGIC_NUMBER_LOW,
        TIFF_IFD_OFFSET, TIFF_MAGIC_NUMBER_LOW, TIFF_MAGIC_NUMBER_LOW, TIFF_MAGIC_NUMBER_LOW,
    };
    DataBuf dataBuf(const_cast<unsigned char*>(invalidTiffData), sizeof(invalidTiffData));
    const std::string invalidHeifPath = "/data/local/tmp/image/invalid_heif_for_read006.heic";
    {
        FILE *fp = fopen(invalidHeifPath.c_str(), "wb");
        ASSERT_NE(fp, nullptr);
        fwrite(invalidTiffData, TIFF_BYTE_SIZE, sizeof(invalidTiffData), fp);
        fclose(fp);
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(invalidHeifPath);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA);
    remove(invalidHeifPath.c_str());
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read006 end";
}

/**
 * @tc.name: Read007_HEIF
 * @tc.desc: test when both HEIF and CR3 parsing fail
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read007_HEIF, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read007_HEIF start";
    const std::string testDir = "/data/local/tmp/image/";
    mkdir(testDir.c_str(), DIRECTORY_PERMISSIONS);
    const std::string invalidPath = testDir + "random.bin";
    FILE* fp = fopen(invalidPath.c_str(), "wb");
    if (fp == nullptr) {
        GTEST_SKIP() << "Cannot create test file";
    }
    uint8_t randomData[RANDOM_DATA_SIZE];
    for (int i = 0; i < RANDOM_DATA_SIZE; i++) {
        randomData[i] = rand() % (RANDOM_DATA_SIZE + 1);
    }
    fwrite(randomData, 1, RANDOM_DATA_SIZE, fp);
    fclose(fp);
    struct stat st;
    if (stat(invalidPath.c_str(), &st) != 0) {
        GTEST_SKIP() << "Test file was not created";
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(invalidPath);
    if (!stream->Open(OpenMode::ReadWrite)) {
        remove(invalidPath.c_str());
        GTEST_SKIP() << "Failed to open test file";
    }
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, ERR_IMAGE_SOURCE_DATA);
    remove(invalidPath.c_str());
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read007_HEIF end";
}

/**
 * @tc.name: Read008_EmptyFile
 * @tc.desc: Test with empty file (size = 0)
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read008_EmptyFile, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read008_EmptyFile start";
    
    const std::string emptyPath = "/data/local/tmp/test_empty.heic";
    {
        FILE* fp = fopen(emptyPath.c_str(), "wb");
        ASSERT_NE(fp, nullptr);
        fclose(fp);
    }
    
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(emptyPath);
    ASSERT_TRUE(stream->Open(OpenMode::Read));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();

    ASSERT_NE(result, SUCCESS);
    
    stream->Close();
    remove(emptyPath.c_str());
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read008_EmptyFile end";
}

/**
 * @tc.name: Read009_InvalidCr3File
 * @tc.desc: Test with invalid CR3 file (not HEIF and invalid CR3)
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read009_InvalidCr3File, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read009_InvalidCr3File start";
    
    const std::string fakeCr3Path = "/data/local/tmp/test_fake.cr3";
    {
        FILE* fp = fopen(fakeCr3Path.c_str(), "wb");
        ASSERT_NE(fp, nullptr);
        const char fakeHeader[] = "CR3_FAKE_FILE";
        fwrite(fakeHeader, 1, sizeof(fakeHeader), fp);
        fclose(fp);
    }
    
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(fakeCr3Path);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();

    ASSERT_NE(result, SUCCESS);
    
    remove(fakeCr3Path.c_str());
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read009_InvalidCr3File end";
}

/**
 * @tc.name: Read010_NullStream
 * @tc.desc: Test Read with null metadata stream
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read010_NullStream, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read011_NullStream start";
    const std::string invalidPath = "/data/local/tmp/nonexistent_file.heic";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(invalidPath);
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_NE(result, SUCCESS);
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: Read010_NullStream end";
}

/**
 * @tc.name: ReadBlobTest001
 * @tc.desc: Test ReadBlob always returns false (placeholder)
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, ReadBlobTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: ReadBlobTest001 start";
    std::shared_ptr<MetadataStream> nullStream = nullptr;
    HeifExifMetadataAccessor accessor(nullStream);
    DataBuf blob;
    bool result = accessor.ReadBlob(blob);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: ReadBlobTest001 end";
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

/**
 * @tc.name: Read011
 * @tc.desc: test the Read method
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read011, TestSize.Level3)
{
    auto fileStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_EXIF_PATH);
    ASSERT_NE(fileStream, nullptr);
    fileStream->fp_ = nullptr;
    std::shared_ptr<MetadataStream> stream = fileStream;
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t res = imageAccessor.Read();
    EXPECT_EQ(res, SUCCESS);
}

/**
 * @tc.name: Write011
 * @tc.desc: test the Write method when exifData is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Write011, TestSize.Level3)
{
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_EXIF_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    exifMetadata->SetValue("Model", "test heif");

    imageAccessor.Get()->exifData_ = nullptr;
    uint32_t res = imageAccessor.Write();
    EXPECT_EQ(res, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
}

/**
 * @tc.name: WriteMetadata001
 * @tc.desc: test the WriteMetadata method when fp is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, WriteMetadata001, TestSize.Level3)
{
    DataBuf dataBuf;
    auto fileStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_EXIF_PATH);
    ASSERT_NE(fileStream, nullptr);
    fileStream->fp_ = nullptr;
    std::shared_ptr<MetadataStream> stream = fileStream;
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t res = imageAccessor.WriteMetadata(dataBuf);
    EXPECT_EQ(res, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
}

/**
 * @tc.name: WriteMetadata002
 * @tc.desc: test the WriteMetadata method when buff is nullptr and size is 0
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, WriteMetadata002, TestSize.Level3)
{
    size_t byteOrderPos = 0;
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_EXIF_PATH);
    ASSERT_NE(stream, nullptr);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    bool res = imageAccessor.CheckTiffPos(nullptr, 0, byteOrderPos);
    EXPECT_FALSE(res);

    std::string buffer = "buffer";
    byte* buff = reinterpret_cast<byte*>(buffer.data());
    res = imageAccessor.CheckTiffPos(buff, 0, byteOrderPos);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: WriteMetadata003
 * @tc.desc: test the WriteMetadata expect return ERR_IMAGE_DECODE_EXIF_UNSUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, WriteMetadata003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: WriteMetadata003 start";
    const std::string invalidHeifPath = "/data/local/tmp/image/invalid_for_write_metadata.heic";
    {
        FILE *fp = fopen(invalidHeifPath.c_str(), "wb");
        ASSERT_NE(fp, nullptr);
        const char dummy[] = "NOT_A_HEIF";
        fwrite(dummy, TIFF_BYTE_SIZE, sizeof(dummy), fp);
        fclose(fp);
    }
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(invalidHeifPath);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);

    DataBuf dataBuf;
    uint32_t result = imageAccessor.WriteMetadata(dataBuf);
    ASSERT_EQ(result, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: WriteMetadata003 end";
}

/**
 * @tc.name: WriteMetadata004
 * @tc.desc: WriteMetadata_Success
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, WriteMetadata004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WriteMetadata_Success start";

    std::string path = "/data/local/tmp/image/test_remove_exif.heic";
    auto fileStream = std::make_shared<FileMetadataStream>(path);
    ASSERT_NE(fileStream, nullptr);

    EXPECT_TRUE(fileStream->Open(OpenMode::ReadWrite));

    std::shared_ptr<MetadataStream> stream = fileStream;
    HeifExifMetadataAccessor accessor(stream);

    uint8_t exifData[] = {
        0x4d, 0x4d, 0x00, 0x2a,
        0x00, 0x00, 0x00, 0x08,
        0x00, 0x01,
        0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00
    };
    DataBuf dataBuf(exifData, sizeof(exifData));

    uint32_t result = accessor.WriteMetadata(dataBuf);
    EXPECT_EQ(result, SUCCESS) << "Expected SUCCESS when writing valid EXIF to valid HEIF";

    GTEST_LOG_(INFO) << "WriteMetadata_Success end";
}

/**
 * @tc.name: WriteMetadata005
 * @tc.desc: WriteMetadata_EmptyExifBuffer
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, WriteMetadata005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "WriteMetadata_EmptyExifBuffer start";

    std::string path = "/data/local/tmp/image/test_remove_exif.heic";
    auto filestream = std::make_shared<FileMetadataStream>(path);
    ASSERT_NE(filestream, nullptr);
    EXPECT_TRUE(filestream->Open(OpenMode::ReadWrite));
    std::shared_ptr<MetadataStream> stream = filestream;
    HeifExifMetadataAccessor accessor(stream);
    DataBuf dataBuf;

    uint32_t result = accessor.WriteMetadata(dataBuf);
    if (result != SUCCESS && result != ERR_IMAGE_DECODE_EXIF_UNSUPPORT) {
        FAIL() << "Unexpected return code: " << result;
    }

    GTEST_LOG_(INFO) << "WriteMetadata_EmptyExifBuffer end";
}

/**
 * @tc.name: WriteBlobTest001
 * @tc.desc: Test WriteBlob always returns SUCCESS (stub function)
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, WriteBlobTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: WriteBlobTest001 start";
    std::shared_ptr<MetadataStream> nullStream = nullptr;
    HeifExifMetadataAccessor accessor(nullStream);
    DataBuf dummyBlob;
    uint32_t result = accessor.WriteBlob(dummyBlob);
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: WriteBlobTest001 end";
}

/**
 * @tc.name: ReadCr3001
 * @tc.desc: test the ReadCr3 when imageStream_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, ReadCr3001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: ReadCr3001 start";
    std::shared_ptr<MetadataStream> nullStream = nullptr;
    HeifExifMetadataAccessor accessor(nullStream);
    uint32_t ret = accessor.ReadCr3();
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: ReadCr3001 end";
}

/**
 * @tc.name: ReadCr3002
 * @tc.desc: test the ReadCr3 expect return SUCCESS.
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, ReadCr3002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: ReadCr3002 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_CR3_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor accessor(stream);
    uint32_t ret = accessor.ReadCr3();
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: ReadCr3002 end";
}

/**
 * @tc.name: ReadCr3003_InvalidCr3_ParseFailParserNull
 * @tc.desc: Test ReadCr3 when parseRet is not ok and parser is null
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, ReadCr3003_InvalidCr3_ParseFailParserNull, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: ReadCr3003 start - case 1";
    const std::string invalidPath = "/data/local/tmp/not_cr3_random.bin";
    FILE* fp = fopen(invalidPath.c_str(), "wb");
    ASSERT_NE(fp, nullptr);
    uint8_t randomData[INVALID_FILE_SIZE];
    for (int i = 0; i < INVALID_FILE_SIZE; i++) {
        randomData[i] = i;
    }
    fwrite(randomData, 1, INVALID_FILE_SIZE, fp);
    fclose(fp);
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(invalidPath);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor accessor(stream);
    uint32_t ret = accessor.ReadCr3();
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);
    remove(invalidPath.c_str());
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: ReadCr3003 end - covered case 1";
}

/**
 * @tc.name: Read012
 * @tc.desc: test the Read method when fp_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, Read012, TestSize.Level3)
{
    auto fileStream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_EXIF_PATH);
    ASSERT_NE(fileStream, nullptr);
    std::shared_ptr<MetadataStream> stream = fileStream;
    ASSERT_NE(stream, nullptr);
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t res = imageAccessor.Read();
    EXPECT_EQ(res, ERR_IMAGE_SOURCE_DATA);
}

/**
 * @tc.name: TestWriteAndReadFnumberWithTwoDecimal001
 * @tc.desc: test write Fnumber with two decimal, and read with two decimal format.
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, TestWriteAndReadFnumberWithTwoDecimal001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: TestWriteAndReadFnumberWithTwoDecimal001 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_EXIF_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);

    auto exifMetadata = imageAccessor.Get();
    exifMetadata->SetValue("FNumber", "1.49");
    uint32_t errcode = imageAccessor.Write();
    ASSERT_EQ(errcode, SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/1.49");

    exifMetadata->SetValue("FNumber", "1.80");
    errcode = imageAccessor.Write();
    ASSERT_EQ(errcode, SUCCESS);

    exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "FNumber"), "f/1.8");

    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: TestWriteAndReadFnumberWithTwoDecimal001 end";
}

/**
 * @tc.name: TestWriteAndReadHwTagAnnotationEdit001
 * @tc.desc: test write and read exif tag AnnotationEdit.
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, TestWriteAndReadHwTagAnnotationEdit001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: TestWriteAndReadHwTagAnnotationEdit001 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_EXIF_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    exifMetadata->SetValue("HwMnoteAnnotationEdit", "1");
    uint32_t errcode = imageAccessor.Write();
    ASSERT_EQ(errcode, SUCCESS);
    exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteAnnotationEdit"), "1");
    exifMetadata->SetValue("HwMnoteAnnotationEdit", "2");
    errcode = imageAccessor.Write();
    ASSERT_EQ(errcode, SUCCESS);
    exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteAnnotationEdit"), "2");
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: TestWriteAndReadHwTagAnnotationEdit001 end";
}
} // namespace Multimedia
} // namespace OHOS