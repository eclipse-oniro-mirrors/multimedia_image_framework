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
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: ReadCr3003 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_CR3_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor accessor(stream);
    uint32_t ret = accessor.ReadCr3();
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: ReadCr3002 end";
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

/**
 * @tc.name: TestWriteAndReadHwTagVignettingAndNoise001
 * @tc.desc: test write and read exif tags Vignetting and Noise.
 * @tc.type: FUNC
 */
HWTEST_F(HeifExifMetadataAccessorTest, TestWriteAndReadHwTagVignettingAndNoise001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: TestWriteAndReadHwTagVignettingAndNoise001 start";
    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(IMAGE_INPUT_HEIF_EXIF_PATH);
    ASSERT_TRUE(stream->Open(OpenMode::ReadWrite));
    HeifExifMetadataAccessor imageAccessor(stream);
    uint32_t result = imageAccessor.Read();
    ASSERT_EQ(result, 0);
    auto exifMetadata = imageAccessor.Get();
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXtStyleVignetting", "0.666666"));
    ASSERT_TRUE(exifMetadata->SetValue("HwMnoteXtStyleNoise", "0.666666"));
    uint32_t errcode = imageAccessor.Write();
    ASSERT_EQ(errcode, SUCCESS);
    exifMetadata = imageAccessor.Get();
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXtStyleVignetting"), "0.666666 ");
    ASSERT_EQ(GetProperty(exifMetadata, "HwMnoteXtStyleNoise"), "0.666666 ");
    GTEST_LOG_(INFO) << "HeifExifMetadataAccessorTest: TestWriteAndReadHwTagVignettingAndNoise001 end";
}
} // namespace Multimedia
} // namespace OHOS