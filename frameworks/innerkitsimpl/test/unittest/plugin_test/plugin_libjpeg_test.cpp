/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#define IMAGE_COLORSPACE_FLAG
#define private public
#include <fcntl.h>
#include "buffer_source_stream.h"
#include "exif_info.h"
#include "plugin_export.h"
#include "icc_profile_info.h"
#include "jpeg_decoder.h"
#include "jpeg_encoder.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Media {
static const std::string IMAGE_INPUT_NULL_JPEG_PATH = "/data/local/tmp/image/test_null.jpg";
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";
static const std::string IMAGE_INPUT_TXT_PATH = "/data/local/tmp/image/test.txt";
constexpr uint32_t COMPONENT_NUM_RGBA = 4;
constexpr uint32_t COMPONENT_NUM_BGRA = 4;
constexpr uint32_t COMPONENT_NUM_RGB = 3;
constexpr uint32_t COMPONENT_NUM_GRAY = 1;
constexpr uint8_t COMPONENT_NUM_YUV420SP = 3;
class PluginLibJpegTest : public testing::Test {
public:
    PluginLibJpegTest() {}
    ~PluginLibJpegTest() {}
};

/**
 * @tc.name: exif_info001
 * @tc.desc: ParseExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info001 start";
    EXIFInfo exinfo;
    unsigned char *buf = nullptr;
    unsigned len = 1000;
    exinfo.ParseExifData(buf, len);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info001 end";
}

/**
 * @tc.name: exif_info001_1
 * @tc.desc: ParseExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info001_1, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info001_1 start";
    EXIFInfo exinfo;
    unsigned char buf = 'n';
    unsigned len = 1000;
    exinfo.ParseExifData(&buf, len);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info001_1 end";
}

/**
 * @tc.name: exif_info001_2
 * @tc.desc: ParseExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info001_2, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info001_2 start";
    EXIFInfo exinfo;
    unsigned char *buf = nullptr;
    unsigned len = 0;
    exinfo.ParseExifData(buf, len);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info001_2 end";
}

/**
 * @tc.name: exif_info001_3
 * @tc.desc: ParseExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info001_3, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info001_3 start";
    EXIFInfo exinfo;
    string data = "";
    exinfo.ParseExifData(data);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info001_3 end";
}

/**
 * @tc.name: exif_info001_4
 * @tc.desc: ParseExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info001_4, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info001_4 start";
    EXIFInfo exinfo;
    string data = "aaaaaaa";
    exinfo.ParseExifData(data);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info001_4 end";
}

/**
 * @tc.name: exif_info002
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info002 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    string value = "111";
    uint32_t ret = exinfo.ModifyExifData(tag, value, "");
    ASSERT_EQ(ret, ERR_MEDIA_IO_ABNORMAL);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info002 end";
}

/**
 * @tc.name: exif_info003
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info003 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    string value = "111";
    uint32_t ret = exinfo.ModifyExifData(tag, value, IMAGE_INPUT_NULL_JPEG_PATH);
    ASSERT_EQ(ret, ERR_MEDIA_BUFFER_TOO_SMALL);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info003 end";
}

/**
 * @tc.name: exif_info004
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info004 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    string value = "111";
    uint32_t ret = exinfo.ModifyExifData(tag, value, IMAGE_INPUT_TXT_PATH);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info004 end";
}

/**
 * @tc.name: exif_info005
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info005 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    string value = "111";
    int fd = open("/data/local/tmp/image/test_noexit.jpg", O_RDWR, S_IRUSR | S_IWUSR);
    uint32_t ret = exinfo.ModifyExifData(tag, value, fd);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info005 end";
}

/**
 * @tc.name: exif_info006
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info006 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    string value = "111";
    const int fd = open("/data/local/tmp/image/test_null.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    uint32_t ret = exinfo.ModifyExifData(tag, value, fd);
    ASSERT_EQ(ret, ERR_MEDIA_BUFFER_TOO_SMALL);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info006 end";
}

/**
 * @tc.name: exif_info007
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info007 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    string value = "111";
    const int fd = open("/data/local/tmp/image/test.txt", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    uint32_t ret = exinfo.ModifyExifData(tag, value, fd);
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info007 end";
}

/**
 * @tc.name: exif_info008
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info008 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    unsigned char *data = nullptr;
    string value = "111";
    uint32_t size = 0;
    uint32_t ret = exinfo.ModifyExifData(tag, value, data, size);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info008 end";
}

/**
 * @tc.name: exif_info009
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info009 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    unsigned char data = 'n';
    string value = "111";
    uint32_t size = 0;
    uint32_t ret = exinfo.ModifyExifData(tag, value, &data, size);
    ASSERT_EQ(ret, ERR_MEDIA_BUFFER_TOO_SMALL);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info009 end";
}

/**
 * @tc.name: exif_info010
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info010 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    unsigned char data = 'n';
    std::string value = "111";
    uint32_t size = 1;
    uint32_t ret = exinfo.ModifyExifData(tag, value, &data, size);
    ASSERT_EQ(ret, ERR_IMAGE_MISMATCHED_FORMAT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info010 end";
}

/**
 * @tc.name: exif_info011
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info011 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    unsigned char data = 0xFF;
    std::string value = "111";
    uint32_t size = 1;
    uint32_t ret = exinfo.ModifyExifData(tag, value, &data, size);
    ASSERT_EQ(ret, ERR_IMAGE_MISMATCHED_FORMAT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info011 end";
}

/**
 * @tc.name: exif_info012
 * @tc.desc: GetFilterArea
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info012 start";
    EXIFInfo exinfo;
    const uint32_t bufSize = 5;
    uint8_t buf[bufSize] = "exif";
    int filterType = 0;
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    exinfo.GetFilterArea(buf, bufSize, filterType, ranges);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info012 end";
}

/**
 * @tc.name: exif_info013
 * @tc.desc: GetFilterArea
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info013 start";
    EXIFInfo exinfo;
    const uint32_t bufSize = 5;
    uint8_t buf[bufSize] = "exif";
    int filterType = 0;
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = exinfo.GetFilterArea(buf, bufSize, filterType, ranges);
    ASSERT_EQ(ret, 1);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info013 end";
}

/**
 * @tc.name: exif_info014
 * @tc.desc: IsIFDPointerTag
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: IsIFDPointerTag start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    bool ret;
    ret = byteorder.IsIFDPointerTag(0x014a);
    ASSERT_EQ(ret, true);
    ret = byteorder.IsIFDPointerTag(0x8769);
    ASSERT_EQ(ret, true);
    ret = byteorder.IsIFDPointerTag(0x8825);
    ASSERT_EQ(ret, true);
    ret = byteorder.IsIFDPointerTag(0xa005);
    ASSERT_EQ(ret, true);
    ret = byteorder.IsIFDPointerTag(0xa301);
    ASSERT_EQ(ret, false);
    ret = byteorder.IsIFDPointerTag(-1);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: IsIFDPointerTag end";
}

/**
 * @tc.name: exif_info015
 * @tc.desc: GetIFDOfIFDPointerTag
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetIFDOfIFDPointerTag start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    ExifIfd ret;
    ret = byteorder.GetIFDOfIFDPointerTag(0x8769);
    ASSERT_EQ(ret, EXIF_IFD_EXIF);
    ret = byteorder.GetIFDOfIFDPointerTag(0x8825);
    ASSERT_EQ(ret, EXIF_IFD_GPS);
    ret = byteorder.GetIFDOfIFDPointerTag(0xa005);
    ASSERT_EQ(ret, EXIF_IFD_INTEROPERABILITY);
    ret = byteorder.GetIFDOfIFDPointerTag(-1);
    ASSERT_EQ(ret, EXIF_IFD_COUNT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetIFDOfIFDPointerTag end";
}

/**
 * @tc.name: exif_info016
 * @tc.desc: CheckExifEntryValid
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CheckExifEntryValid start";
    EXIFInfo exinfo;
    bool ret;
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_0, EXIF_TAG_ORIENTATION);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_EXIF, EXIF_TAG_DATE_TIME_ORIGINAL);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_GPS, EXIF_TAG_GPS_LATITUDE);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CheckExifEntryValid end";
}

/**
 * @tc.name: CreateExifData001
 * @tc.desc: CreateExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifData001 start";
    EXIFInfo exinfo;
    unsigned char buf[20] = "ttttttExif";
    ExifData *ptrData = exif_data_new();
    bool isNewExifData = true;
    bool ret = exinfo.CreateExifData(buf, 5, &ptrData, isNewExifData);
    ASSERT_EQ(ret, true);
    if (ptrData != nullptr) {
        exif_data_unref(ptrData);
        ptrData = nullptr;
    }
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifData001 end";
}

/**
 * @tc.name: CreateExifData002
 * @tc.desc: CreateExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifData002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifData002 start";
    EXIFInfo exinfo;
    unsigned char buf[20] = "tttttttttt";
    ExifData *ptrData = exif_data_new();
    bool isNewExifData = true;
    bool ret = exinfo.CreateExifData(buf, 5, &ptrData, isNewExifData);
    ASSERT_EQ(ret, true);
    if (ptrData != nullptr) {
        exif_data_unref(ptrData);
        ptrData = nullptr;
    }
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifData002 end";
}

/**
 * @tc.name: GetExifByteOrder001
 * @tc.desc: GetExifByteOrder
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetExifByteOrder001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifByteOrder001 start";
    EXIFInfo exinfo;
    unsigned char *buf = new unsigned char;
    ExifByteOrder ret = exinfo.GetExifByteOrder(true, buf);
    ASSERT_EQ(ret, EXIF_BYTE_ORDER_INTEL);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifByteOrder001 end";
}

/**
 * @tc.name: GetExifByteOrder002
 * @tc.desc: GetExifByteOrder
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetExifByteOrder002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifByteOrder002 start";
    EXIFInfo exinfo;
    unsigned char buf[20] = "ttttttttttttMM";
    ExifByteOrder ret = exinfo.GetExifByteOrder(false, buf);
    ASSERT_EQ(ret, EXIF_BYTE_ORDER_MOTOROLA);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifByteOrder002 end";
}

/**
 * @tc.name: GetExifByteOrder003
 * @tc.desc: GetExifByteOrder
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetExifByteOrder003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifByteOrder003 start";
    EXIFInfo exinfo;
    unsigned char buf[20] = "tttttttttttttt";
    ExifByteOrder ret = exinfo.GetExifByteOrder(false, buf);
    ASSERT_EQ(ret, EXIF_BYTE_ORDER_INTEL);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifByteOrder003 end";
}

/**
 * @tc.name: WriteExifDataToFile001
 * @tc.desc: WriteExifDataToFile
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, WriteExifDataToFile001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: WriteExifDataToFile001 start";
    EXIFInfo exinfo;
    bool ret = exinfo.WriteExifDataToFile(nullptr, 5, 20, nullptr, nullptr);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: WriteExifDataToFile001 end";
}

/**
 * @tc.name: ReleaseSource001
 * @tc.desc: ReleaseSource
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ReleaseSource001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ReleaseSource001 start";
    EXIFInfo exinfo;
    unsigned char *ptrBuf = new unsigned char;
    FILE *file = fopen("/data/local/tmp/image/test.txt", "r+");
    exinfo.ReleaseSource(&ptrBuf, &file);
    ASSERT_EQ(ptrBuf, nullptr);
    ASSERT_EQ(file, nullptr);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ReleaseSource001 end";
}

/**
 * @tc.name: UpdateCacheExifData001
 * @tc.desc: UpdateCacheExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, UpdateCacheExifData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: UpdateCacheExifData001 start";
    EXIFInfo exinfo;
    FILE *file = fopen("/data/local/tmp/image/test.txt", "rb");
    exinfo.UpdateCacheExifData(file);
    fclose(file);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: UpdateCacheExifData001 end";
}

/**
 * @tc.name: GetAreaFromExifEntries001
 * @tc.desc: GetAreaFromExifEntries
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetAreaFromExifEntries001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetAreaFromExifEntries001 start";
    EXIFInfo exinfo;
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteOrderedBuffer(buf, 10);
    byteOrderedBuffer.GenerateDEArray();
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    exinfo.GetAreaFromExifEntries(1, byteOrderedBuffer.directoryEntryArray_, ranges);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetAreaFromExifEntries001 end";
}

/**
 * @tc.name: TransformTiffOffsetToFilePos001
 * @tc.desc: TransformTiffOffsetToFilePos
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, TransformTiffOffsetToFilePos001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: TransformTiffOffsetToFilePos001 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    uint32_t ret = byteorder.TransformTiffOffsetToFilePos(20);
    ASSERT_EQ(ret, 32);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: TransformTiffOffsetToFilePos001 end";
}

/**
 * @tc.name: ReadShort001
 * @tc.desc: ReadShort
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ReadShort001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ReadShort001 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    byteorder.curPosition_ = 5;
    byteorder.bufferLength_ = 1;
    int16_t ret = byteorder.ReadShort();
    ASSERT_EQ(ret, -1);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ReadShort001 end";
}

/**
 * @tc.name: ReadShort002
 * @tc.desc: ReadShort
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ReadShort002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ReadShort002 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    byteorder.bufferLength_ = 100;
    byteorder.byteOrder_ = EXIF_BYTE_ORDER_MOTOROLA;
    int16_t ret = byteorder.ReadShort();
    ASSERT_NE(ret, -1);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ReadShort002 end";
}

/**
 * @tc.name: ReadShort003
 * @tc.desc: ReadShort
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ReadShort003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ReadShort003 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    byteorder.bufferLength_ = 100;
    byteorder.byteOrder_ = EXIF_BYTE_ORDER_INTEL;
    int16_t ret = byteorder.ReadShort();
    ASSERT_NE(ret, -1);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ReadShort003 end";
}

/**
 * @tc.name: GetDataRangeFromIFD001
 * @tc.desc: GetDataRangeFromIFD
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetDataRangeFromIFD001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetDataRangeFromIFD001 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    byteorder.curPosition_ = 0;
    byteorder.bufferLength_ = 20;
    byteorder.GetDataRangeFromIFD(EXIF_IFD_0);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetDataRangeFromIFD001 end";
}

/**
 * @tc.name: GetDataRangeFromIFD002
 * @tc.desc: GetDataRangeFromIFD
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetDataRangeFromIFD002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetDataRangeFromIFD002 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    byteorder.bufferLength_ = 8;
    byteorder.GetDataRangeFromIFD(EXIF_IFD_0);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetDataRangeFromIFD002 end";
}

/**
 * @tc.name: ParseIFDPointerTag001
 * @tc.desc: ParseIFDPointerTag
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ParseIFDPointerTag001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ParseIFDPointerTag001 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    uint16_t tagNumber = byteorder.ReadUnsignedShort();
    const ExifIfd ifd = byteorder.GetIFDOfIFDPointerTag(tagNumber);;
    const uint16_t dataFormat = byteorder.ReadUnsignedShort();
    byteorder.ParseIFDPointerTag(ifd, dataFormat);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ParseIFDPointerTag001 end";
}

/**
 * @tc.name: IsIFDhandled001
 * @tc.desc: IsIFDhandled
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, IsIFDhandled001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: IsIFDhandled001 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    byteorder.handledIfdOffsets_.clear();
    bool ret = byteorder.IsIFDhandled(1);
    ASSERT_EQ(ret, false);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: IsIFDhandled001 end";
}

/**
 * @tc.name: IsIFDhandled002
 * @tc.desc: IsIFDhandled
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, IsIFDhandled002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: IsIFDhandled002 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    byteorder.handledIfdOffsets_.push_back(1);
    bool ret = byteorder.IsIFDhandled(1);
    ASSERT_EQ(ret, true);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: IsIFDhandled002 end";
}

/**
 * @tc.name: GetNextIfdFromLinkList001
 * @tc.desc: GetNextIfdFromLinkList
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetNextIfdFromLinkList001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetNextIfdFromLinkList001 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    ExifIfd ret = byteorder.GetNextIfdFromLinkList(EXIF_IFD_0);
    ASSERT_EQ(ret, EXIF_IFD_1);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetNextIfdFromLinkList001 end";
}

/**
 * @tc.name: GetNextIfdFromLinkList002
 * @tc.desc: GetNextIfdFromLinkList
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetNextIfdFromLinkList002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetNextIfdFromLinkList002 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    ExifIfd ret = byteorder.GetNextIfdFromLinkList(EXIF_IFD_EXIF);
    ASSERT_EQ(ret, EXIF_IFD_COUNT);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetNextIfdFromLinkList002 end";
}

/**
 * @tc.name: IsExifDataParsed001
 * @tc.desc: IsExifDataParsed
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, IsExifDataParsed001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: IsExifDataParsed001 start";
    EXIFInfo exinfo;
    exinfo.isExifDataParsed_ = false;
    bool ret = exinfo.IsExifDataParsed();
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: IsExifDataParsed001 end";
}

/**
 * @tc.name: SetExifTagValues001
 * @tc.desc: SetExifTagValues
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetExifTagValues001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValues001 start";
    EXIFInfo exinfo;
    const std::string val = "111";
    exinfo.SetExifTagValues(EXIF_TAG_BITS_PER_SAMPLE, val);
    ASSERT_EQ(exinfo.bitsPerSample_, val);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValues001 end";
}

/**
 * @tc.name: SetExifTagValues002
 * @tc.desc: SetExifTagValues
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetExifTagValues002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValues002 start";
    EXIFInfo exinfo;
    const std::string val = "222";
    exinfo.SetExifTagValues(EXIF_TAG_ORIENTATION, val);
    ASSERT_EQ(exinfo.orientation_, val);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValues002 end";
}

/**
 * @tc.name: SetExifTagValues003
 * @tc.desc: SetExifTagValues
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetExifTagValues003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValues003 start";
    EXIFInfo exinfo;
    const std::string val = "333";
    exinfo.SetExifTagValues(EXIF_TAG_IMAGE_LENGTH, val);
    ASSERT_EQ(exinfo.imageLength_, val);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValues003 end";
}

/**
 * @tc.name: SetExifTagValues004
 * @tc.desc: SetExifTagValues
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetExifTagValues004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValues004 start";
    EXIFInfo exinfo;
    const std::string val = "444";
    exinfo.SetExifTagValues(EXIF_TAG_IMAGE_WIDTH, val);
    ASSERT_EQ(exinfo.imageWidth_, val);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValues004 end";
}

/**
 * @tc.name: SetExifTagValues005
 * @tc.desc: SetExifTagValues
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetExifTagValues005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValues005 start";
    EXIFInfo exinfo;
    const std::string val = "test";
    exinfo.SetExifTagValues(EXIF_TAG_GPS_LATITUDE, val);
    ASSERT_EQ(exinfo.gpsLatitude_, val);
    exinfo.SetExifTagValues(EXIF_TAG_GPS_LONGITUDE, val);
    ASSERT_EQ(exinfo.gpsLongitude_, val);
    exinfo.SetExifTagValues(EXIF_TAG_GPS_LATITUDE_REF, val);
    ASSERT_EQ(exinfo.gpsLatitudeRef_, val);
    exinfo.SetExifTagValues(EXIF_TAG_GPS_LONGITUDE_REF, val);
    ASSERT_EQ(exinfo.gpsLongitudeRef_, val);
    exinfo.SetExifTagValues(EXIF_TAG_DATE_TIME_ORIGINAL, val);
    ASSERT_EQ(exinfo.dateTimeOriginal_, val);
    exinfo.SetExifTagValues(EXIF_TAG_EXPOSURE_TIME, val);
    ASSERT_EQ(exinfo.exposureTime_, val);
    exinfo.SetExifTagValues(EXIF_TAG_FNUMBER, val);
    ASSERT_EQ(exinfo.fNumber_, val);
    exinfo.SetExifTagValues(EXIF_TAG_ISO_SPEED_RATINGS, val);
    ASSERT_EQ(exinfo.isoSpeedRatings_, val);
    exinfo.SetExifTagValues(EXIF_TAG_SCENE_TYPE, val);
    ASSERT_EQ(exinfo.sceneType_, val);
    exinfo.SetExifTagValues(EXIF_TAG_COMPRESSED_BITS_PER_PIXEL, val);
    ASSERT_EQ(exinfo.compressedBitsPerPixel_, val);
    exinfo.SetExifTagValues(EXIF_TAG_DATE_TIME, val);
    ASSERT_EQ(exinfo.dateTime_, val);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValues005 end";
}

/**
 * @tc.name: SetExifTagValuesEx001
 * @tc.desc: SetExifTagValuesEx
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetExifTagValuesEx001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValuesEx001 start";
    EXIFInfo exinfo;
    const std::string val = "test";
    exinfo.SetExifTagValuesEx(EXIF_TAG_DATE_TIME, val);
    ASSERT_EQ(exinfo.dateTime_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_GPS_TIME_STAMP, val);
    ASSERT_EQ(exinfo.gpsTimeStamp_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_GPS_DATE_STAMP, val);
    ASSERT_EQ(exinfo.gpsDateStamp_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_IMAGE_DESCRIPTION, val);
    ASSERT_EQ(exinfo.imageDescription_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_MAKE, val);
    ASSERT_EQ(exinfo.make_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_MODEL, val);
    ASSERT_EQ(exinfo.model_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_JPEG_PROC, val);
    ASSERT_EQ(exinfo.photoMode_, val);
    exinfo.SetExifTagValuesEx(static_cast<ExifTag>(0x8830), val);
    ASSERT_EQ(exinfo.sensitivityType_, val);
    exinfo.SetExifTagValuesEx(static_cast<ExifTag>(0x8831), val);
    ASSERT_EQ(exinfo.standardOutputSensitivity_, val);
    exinfo.SetExifTagValuesEx(static_cast<ExifTag>(0x8832), val);
    ASSERT_EQ(exinfo.recommendedExposureIndex_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_APERTURE_VALUE, val);
    ASSERT_EQ(exinfo.apertureValue_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_EXPOSURE_BIAS_VALUE, val);
    ASSERT_EQ(exinfo.exposureBiasValue_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_METERING_MODE, val);
    ASSERT_EQ(exinfo.meteringMode_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_FLASH, val);
    ASSERT_EQ(exinfo.flash_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_FOCAL_LENGTH, val);
    ASSERT_EQ(exinfo.focalLength_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_USER_COMMENT, val);
    ASSERT_EQ(exinfo.userComment_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_PIXEL_X_DIMENSION, val);
    ASSERT_EQ(exinfo.pixelXDimension_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_PIXEL_Y_DIMENSION, val);
    ASSERT_EQ(exinfo.pixelYDimension_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_WHITE_BALANCE, val);
    ASSERT_EQ(exinfo.whiteBalance_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_FOCAL_LENGTH_IN_35MM_FILM, val);
    ASSERT_EQ(exinfo.focalLengthIn35mmFilm_, val);
    exinfo.SetExifTagValuesEx(EXIF_TAG_COMPRESSED_BITS_PER_PIXEL, val);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValuesEx001 end";
}

/**
 * @tc.name: CreateExifEntry001
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry001 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test,test,test,test,test,test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_BITS_PER_SAMPLE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, false);
    ExifEntry *ptrEntry = new ExifEntry;
    ret = exinfo.CreateExifEntry(EXIF_TAG_BITS_PER_SAMPLE, ptrExifData, value, order, &ptrEntry);
    ASSERT_EQ(ret, false);
    ret = exinfo.CreateExifEntry(EXIF_TAG_BITS_PER_SAMPLE, ptrExifData, "test,test", order, &ptrEntry);
    ASSERT_EQ(ret, true);
    delete ptrEntry;
    ptrEntry = nullptr;
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry001 end";
}

/**
 * @tc.name: CreateExifEntry002
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry002 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_ORIENTATION, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry002 end";
}

/**
 * @tc.name: CreateExifEntry003
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry003 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_IMAGE_LENGTH, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry003 end";
}

/**
 * @tc.name: CreateExifEntry004
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry004 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_IMAGE_WIDTH, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry004 end";
}

/**
 * @tc.name: CreateExifEntry005
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry005 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "1.0";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_COMPRESSED_BITS_PER_PIXEL, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry005 end";
}

/**
 * @tc.name: CreateExifEntry006
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry006 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test,test,test,test,test,test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_GPS_LATITUDE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, false);
    ExifEntry *ptrEntry = new ExifEntry;
    ret = exinfo.CreateExifEntry(EXIF_TAG_GPS_LATITUDE, ptrExifData, "test,test", order, &ptrEntry);
    ASSERT_EQ(ret, true);
    delete ptrEntry;
    ptrEntry = nullptr;
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry006 end";
}

/**
 * @tc.name: CreateExifEntry007
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry007 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test,test,test,test,test,test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_GPS_LONGITUDE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, false);
    ExifEntry *ptrEntry = nullptr;
    ret = exinfo.CreateExifEntry(EXIF_TAG_GPS_LONGITUDE, ptrExifData, "test,test", order, &ptrEntry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry007 end";
}

/**
 * @tc.name: CreateExifEntry008
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry008 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test,test,test,test,test,test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_GPS_LATITUDE_REF, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry008 end";
}

/**
 * @tc.name: CreateExifEntry009
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry009 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test,test,test,test,test,test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_GPS_LONGITUDE_REF, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry009 end";
}

/**
 * @tc.name: CreateExifEntry0010
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry0010 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test,test,test,test,test,test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_WHITE_BALANCE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_FOCAL_LENGTH_IN_35MM_FILM, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_FLASH, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry0010 end";
}

/**
 * @tc.name: CreateExifEntry0011
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry0011 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test/test/test/test/test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_APERTURE_VALUE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, false);
    ret = exinfo.CreateExifEntry(EXIF_TAG_APERTURE_VALUE, ptrExifData, "test/test", order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_DATE_TIME_ORIGINAL, ptrExifData, "test", order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_DATE_TIME, ptrExifData, "test", order, &entry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry0011 end";
}

/**
 * @tc.name: CreateExifEntry0012
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry0012 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test/test/test/test/test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_EXPOSURE_BIAS_VALUE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, false);
    ret = exinfo.CreateExifEntry(EXIF_TAG_EXPOSURE_BIAS_VALUE, ptrExifData, "test/test", order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_EXPOSURE_TIME, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, false);
    ret = exinfo.CreateExifEntry(EXIF_TAG_EXPOSURE_TIME, ptrExifData, "test/test", order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_FNUMBER, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, false);
    ret = exinfo.CreateExifEntry(EXIF_TAG_FNUMBER, ptrExifData, "test/test", order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_FOCAL_LENGTH, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, false);
    ret = exinfo.CreateExifEntry(EXIF_TAG_FOCAL_LENGTH, ptrExifData, "test/test", order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_GPS_TIME_STAMP, ptrExifData, "test:test", order, &entry);
    ASSERT_EQ(ret, false);
    ret = exinfo.CreateExifEntry(EXIF_TAG_GPS_TIME_STAMP, ptrExifData, "test:test:test", order, &entry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry0012 end";
}

/**
 * @tc.name: CreateExifEntry0013
 * @tc.desc: CreateExifEntry
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifEntry0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry0013 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData;
    bool isNewExifData = false;
    unsigned long fileLength = 100;
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    ExifByteOrder order = exinfo.GetExifByteOrder(isNewExifData, fileBuf);
    ExifEntry *entry = nullptr;
    const std::string value = "test/test/test/test/test";
    bool ret = exinfo.CreateExifEntry(EXIF_TAG_GPS_DATE_STAMP, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_IMAGE_DESCRIPTION, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_ISO_SPEED_RATINGS, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_ISO_SPEED, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_LIGHT_SOURCE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_MAKE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_METERING_MODE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_MODEL, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_PIXEL_X_DIMENSION, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_PIXEL_Y_DIMENSION, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_RECOMMENDED_EXPOSURE_INDEX, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_SCENE_TYPE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_SENSITIVITY_TYPE, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_STANDARD_OUTPUT_SENSITIVITY, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    ret = exinfo.CreateExifEntry(EXIF_TAG_USER_COMMENT, ptrExifData, value, order, &entry);
    ASSERT_EQ(ret, true);
    free(fileBuf);
    fileBuf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifEntry0013 end";
}

/**
 * @tc.name: SetDEDataByteCount001
 * @tc.desc: SetDEDataByteCount
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetDEDataByteCount001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetDEDataByteCount001 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    uint16_t dataFormat = byteorder.ReadUnsignedShort();
    int32_t numberOfComponents = byteorder.ReadInt32();
    uint32_t byteCount = 0;
    bool ret = byteorder.SetDEDataByteCount(0x0000, dataFormat, numberOfComponents, byteCount);
    ASSERT_EQ(ret, false);
    ret = byteorder.SetDEDataByteCount(0x0133, -1, numberOfComponents, byteCount);
    ASSERT_EQ(ret, false);
    ret = byteorder.SetDEDataByteCount(0x0133, 1, numberOfComponents, byteCount);
    ASSERT_EQ(ret, true);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetDEDataByteCount001 end";
}

/**
 * @tc.name: ParseIFDPointerTag002
 * @tc.desc: ParseIFDPointerTag
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ParseIFDPointerTag002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ParseIFDPointerTag002 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    uint16_t tagNumber = byteorder.ReadUnsignedShort();
    const ExifIfd ifd = byteorder.GetIFDOfIFDPointerTag(tagNumber);;
    byteorder.ParseIFDPointerTag(ifd, EXIF_FORMAT_SHORT);
    byteorder.ParseIFDPointerTag(ifd, EXIF_FORMAT_SSHORT);
    byteorder.ParseIFDPointerTag(ifd, EXIF_FORMAT_LONG);
    byteorder.ParseIFDPointerTag(ifd, EXIF_FORMAT_SLONG);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ParseIFDPointerTag002 end";
}

/**
 * @tc.name: GetOrginExifDataLength001
 * @tc.desc: GetOrginExifDataLength
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetOrginExifDataLength001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetOrginExifDataLength001 start";
    EXIFInfo exinfo;
    unsigned char buf[10] = "testtest";
    unsigned int ret = exinfo.GetOrginExifDataLength(true, buf);
    ASSERT_EQ(ret, 0);
    ret = exinfo.GetOrginExifDataLength(false, buf);
    ASSERT_NE(ret, 0);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetOrginExifDataLength001 end";
}

/**
 * @tc.name: GenerateDEArray001
 * @tc.desc: GenerateDEArray
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GenerateDEArray001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GenerateDEArray001 start";
    EXIFInfo exinfo;
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteOrderedBuffer(buf, 10);
    byteOrderedBuffer.bufferLength_ = 0;
    byteOrderedBuffer.GenerateDEArray();
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GenerateDEArray001 end";
}

/**
 * @tc.name: GenerateDEArray002
 * @tc.desc: GenerateDEArray
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GenerateDEArray002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GenerateDEArray002 start";
    EXIFInfo exinfo;
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteOrderedBuffer(buf, 10);
    byteOrderedBuffer.bufferLength_ = 21;
    byteOrderedBuffer.GenerateDEArray();
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GenerateDEArray002 end";
}

/**
 * @tc.name: ReadInt32001
 * @tc.desc: ReadInt32
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ReadInt32001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ReadInt32001 start";
    EXIFInfo exinfo;
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteOrderedBuffer(buf, 10);
    byteOrderedBuffer.bufferLength_ = 1;
    int32_t ret = byteOrderedBuffer.ReadInt32();
    ASSERT_EQ(ret, -1);
    byteOrderedBuffer.bufferLength_ = 100;
    byteOrderedBuffer.byteOrder_ = EXIF_BYTE_ORDER_MOTOROLA;
    ret = byteOrderedBuffer.ReadInt32();
    ASSERT_NE(ret, -1);
    byteOrderedBuffer.byteOrder_ = EXIF_BYTE_ORDER_INTEL;
    ret = byteOrderedBuffer.ReadInt32();
    ASSERT_NE(ret, -1);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ReadInt32001 end";
}

/**
 * @tc.name: CheckExifEntryValid002
 * @tc.desc: CheckExifEntryValid
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CheckExifEntryValid002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CheckExifEntryValid002 start";
    EXIFInfo exinfo;
    bool ret;
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_0, EXIF_TAG_BITS_PER_SAMPLE);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_0, EXIF_TAG_IMAGE_LENGTH);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_0, EXIF_TAG_IMAGE_WIDTH);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_EXIF, EXIF_TAG_EXPOSURE_TIME);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_EXIF, EXIF_TAG_FNUMBER);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_EXIF, EXIF_TAG_ISO_SPEED_RATINGS);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_EXIF, EXIF_TAG_SCENE_TYPE);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_EXIF, EXIF_TAG_COMPRESSED_BITS_PER_PIXEL);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_GPS, EXIF_TAG_GPS_LONGITUDE);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_GPS, EXIF_TAG_GPS_LATITUDE_REF);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValid(EXIF_IFD_GPS, EXIF_TAG_GPS_LONGITUDE_REF);
    ASSERT_EQ(ret, true);
    const ExifIfd ifd = EXIF_IFD_COUNT;
    ret = exinfo.CheckExifEntryValid(ifd, EXIF_TAG_GPS_DATE_STAMP);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CheckExifEntryValid002 end";
}

/**
 * @tc.name: SetExifTagValuesEx002
 * @tc.desc: SetExifTagValuesEx
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetExifTagValuesEx002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValuesEx002 start";
    EXIFInfo exinfo;
    const std::string val = "test";
    exinfo.SetExifTagValuesEx(EXIF_TAG_LIGHT_SOURCE, val);
    ASSERT_EQ(exinfo.lightSource_, val);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetExifTagValuesEx002 end";
}

/**
 * @tc.name: CheckExifEntryValidEx001
 * @tc.desc: CheckExifEntryValidEx
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CheckExifEntryValidEx001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CheckExifEntryValidEx001 start";
    EXIFInfo exinfo;
    bool ret;
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_0, EXIF_TAG_DATE_TIME);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_0, EXIF_TAG_IMAGE_DESCRIPTION);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_0, EXIF_TAG_MAKE);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_0, EXIF_TAG_MODEL);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, static_cast<ExifTag>(0x8830));
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, static_cast<ExifTag>(0x8831));
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, static_cast<ExifTag>(0x8832));
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_APERTURE_VALUE);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_EXPOSURE_BIAS_VALUE);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_METERING_MODE);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_LIGHT_SOURCE);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_FLASH);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_FOCAL_LENGTH);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_USER_COMMENT);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_PIXEL_X_DIMENSION);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_PIXEL_Y_DIMENSION);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_WHITE_BALANCE);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_EXIF, EXIF_TAG_FOCAL_LENGTH_IN_35MM_FILM);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_GPS, EXIF_TAG_GPS_TIME_STAMP);
    ASSERT_EQ(ret, true);
    ret = exinfo.CheckExifEntryValidEx(EXIF_IFD_GPS, EXIF_TAG_GPS_DATE_STAMP);
    ASSERT_EQ(ret, true);
    const ExifIfd ifd = EXIF_IFD_COUNT;
    ret = exinfo.CheckExifEntryValidEx(ifd, EXIF_TAG_GPS_DATE_STAMP);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CheckExifEntryValidEx001 end";
}

/**
 * @tc.name: GetExifData001
 * @tc.desc: GetExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetExifData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifData001 start";
    EXIFInfo exinfo;
    std::string value = "test";
    const std::string name = "DateTimeOriginalForMedia";
    uint32_t ret;
    ret = exinfo.GetExifData(name, value);
    ASSERT_NE(ret, Media::ERR_MEDIA_STATUS_ABNORMAL);
    const std::string name2 = "OrientationInt";
    ret = exinfo.GetExifData(name2, value);
    ASSERT_NE(ret, Media::ERR_MEDIA_STATUS_ABNORMAL);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifData001 end";
}

/**
 * @tc.name: ModifyExifData001
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ModifyExifData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ModifyExifData001 start";
    EXIFInfo exinfo;
    const std::string value = "test";
    const std::string name = "test";
    std::string path = "test";
    uint32_t ret;
    ret = exinfo.ModifyExifData(name, value, path);
    ASSERT_EQ(ret, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ModifyExifData001 end";
}

/**
 * @tc.name: ModifyExifData002
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ModifyExifData002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ModifyExifData002 start";
    EXIFInfo exinfo;
    const std::string value = "test";
    const std::string name = "test";
    const int fd = 0;
    uint32_t ret;
    ret = exinfo.ModifyExifData(name, value, fd);
    ASSERT_EQ(ret, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ModifyExifData002 end";
}

/**
 * @tc.name: ModifyExifData003
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ModifyExifData003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ModifyExifData003 start";
    EXIFInfo exinfo;
    const std::string value = "test";
    const std::string name = "test";
    unsigned char data[2];
    uint32_t size = 2;
    uint32_t ret;
    ret = exinfo.ModifyExifData(name, value, data, size);
    ASSERT_EQ(ret, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ModifyExifData003 end";
}

/**
 * @tc.name: WriteExifDataToFile002
 * @tc.desc: WriteExifDataToFile
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, WriteExifDataToFile002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: WriteExifDataToFile002 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData = nullptr;
    FILE *file = fopen("/data/local/tmp/image/test_noexit.jpg", "w+");
    ASSERT_NE(file, nullptr);
    bool isNewExifData = false;
    unsigned long fileLength = exinfo.GetFileSize(file);
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    exinfo.CreateExifData(fileBuf, fileLength, &ptrExifData, isNewExifData);
    unsigned int orginExifDataLength = exinfo.GetOrginExifDataLength(isNewExifData, fileBuf);
    bool ret = exinfo.WriteExifDataToFile(ptrExifData, orginExifDataLength, fileLength, fileBuf, file);
    ASSERT_EQ(ret, false);
    free(fileBuf);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: WriteExifDataToFile002 end";
}

/**
 * @tc.name: GetDataRangeFromDE001
 * @tc.desc: GetDataRangeFromDE
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetDataRangeFromDE001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetDataRangeFromDE001 start";
    EXIFInfo exinfo;
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteOrderedBuffer(buf, 10);
    int16_t entryCount = byteOrderedBuffer.ReadShort();
    byteOrderedBuffer.GetDataRangeFromDE(EXIF_IFD_0, entryCount);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetDataRangeFromDE001 end";
}

/**
 * @tc.name: CreateExifTag001
 * @tc.desc: CreateExifTag
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, CreateExifTag001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifTag001 start";
    EXIFInfo exinfo;
    ExifEntry *ptrEntry = nullptr;
    ExifData *data;
    FILE *file = fopen("/data/local/tmp/image/test_noexit.jpg", "w+");
    ASSERT_NE(file, nullptr);
    unsigned long fileLength = exinfo.GetFileSize(file);
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    bool isNewExifData = false;
    exinfo.CreateExifData(fileBuf, fileLength, &data, isNewExifData);
    ptrEntry = exinfo.CreateExifTag(data, EXIF_IFD_GPS, EXIF_TAG_GPS_LATITUDE, 20, EXIF_FORMAT_RATIONAL);
    ASSERT_NE(ptrEntry, nullptr);
    free(fileBuf);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: CreateExifTag001 end";
}

/**
 * @tc.name: GetExifTag001
 * @tc.desc: GetExifTagTag
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetExifTag001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifTag001 start";
    EXIFInfo exinfo;
    ExifEntry *ptrEntry = nullptr;
    ExifData *data;
    FILE *file = fopen("/data/local/tmp/image/test_noexit.jpg", "rb+");
    ASSERT_NE(file, nullptr);
    unsigned long fileLength = exinfo.GetFileSize(file);
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    bool isNewExifData = false;
    exinfo.CreateExifData(fileBuf, fileLength, &data, isNewExifData);
    ptrEntry = exinfo.GetExifTag(data, EXIF_IFD_GPS, EXIF_TAG_GPS_LATITUDE, 20);

    // There is no latitude exif in test_noexit.jpg, modify failed
    ASSERT_EQ(ptrEntry, nullptr);
    free(fileBuf);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifTag001 end";
}

/**
 * @tc.name: GetExifTag002
 * @tc.desc: GetExifTag
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetExifTag002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifTag002 start";
    EXIFInfo exinfo;
    ExifEntry *ptrEntry = nullptr;
    ExifData *data;
    FILE *file = fopen("/data/local/tmp/image/test_exif.jpg", "rb+");
    ASSERT_NE(file, nullptr);
    unsigned long fileLength = exinfo.GetFileSize(file);
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    bool isNewExifData = false;
    (void)fseek(file, 0L, 0);
    int ret = fread(fileBuf, fileLength, 1, file);
    ASSERT_EQ(ret, 1);
    exinfo.CreateExifData(fileBuf, fileLength, &data, isNewExifData);
    ptrEntry = exinfo.GetExifTag(data, EXIF_IFD_GPS, EXIF_TAG_GPS_LATITUDE, 20);

    // There is latitude exif in test_exif.jpg, modify succeeded
    ASSERT_NE(ptrEntry, nullptr);
    free(fileBuf);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifTag002 end";
}

/**
 * @tc.name: ParseExifData001
 * @tc.desc: ParseExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ParseExifData001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ParseExifData001 start";
    EXIFInfo exinfo;
    FILE *file = fopen("/data/local/tmp/image/test_noexit.jpg", "w+");
    ASSERT_NE(file, nullptr);
    unsigned long fileLength = exinfo.GetFileSize(file);
    unsigned char *fileBuf = static_cast<unsigned char *>(malloc(fileLength));
    bool isNewExifData = false;
    exinfo.CreateExifData(fileBuf, fileLength, &exinfo.exifData_, isNewExifData);
    unsigned char buf = 'n';
    unsigned len = 0;
    int ret = exinfo.ParseExifData(&buf, len);
    ASSERT_EQ(ret, 0);
    free(fileBuf);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ParseExifData001 end";
}

/**
 * @tc.name: ByteOrderedBuffer001
 * @tc.desc: ByteOrderedBuffer
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ByteOrderedBuffer001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ByteOrderedBuffer001 start";
    uint8_t buf[20];
    buf[12] = 'M';
    buf[13] = 'M';
    ByteOrderedBuffer byteOrderedBuffer(buf, 20);
    ASSERT_EQ(byteOrderedBuffer.byteOrder_, EXIF_BYTE_ORDER_MOTOROLA);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ByteOrderedBuffer001 end";
}

/**
 * @tc.name: ByteOrderedBuffer002
 * @tc.desc: ByteOrderedBuffer
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ByteOrderedBuffer002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ByteOrderedBuffer002 start";
    uint8_t buf[20];
    buf[12] = 'M';
    buf[13] = 'x';
    ByteOrderedBuffer byteOrderedBuffer(buf, 20);
    ASSERT_EQ(byteOrderedBuffer.byteOrder_, EXIF_BYTE_ORDER_INTEL);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ByteOrderedBuffer002 end";
}

/**
 * @tc.name: SetDEDataByteCount002
 * @tc.desc: SetDEDataByteCount
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetDEDataByteCount002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetDEDataByteCount002 start";
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteorder(buf, 10);
    uint16_t dataFormat = byteorder.ReadUnsignedShort();
    int32_t numberOfComponents = byteorder.ReadInt32();
    uint32_t byteCount = 0;
    bool ret = byteorder.SetDEDataByteCount(0xa436, dataFormat, numberOfComponents, byteCount);
    ASSERT_EQ(ret, false);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetDEDataByteCount002 end";
}

/**
 * @tc.name: GenerateDEArray003
 * @tc.desc: GenerateDEArray
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GenerateDEArray003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GenerateDEArray003 start";
    EXIFInfo exinfo;
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteOrderedBuffer(buf, 10);
    byteOrderedBuffer.bufferLength_ = 1;
    byteOrderedBuffer.GenerateDEArray();
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GenerateDEArray003 end";
}

/**
 * @tc.name: ParseExifData002
 * @tc.desc: ParseExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, ParseExifData002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ParseExifData002 start";
    EXIFInfo exinfo;
    unsigned char *buf = nullptr;
    unsigned len = 1000;
    exinfo.exifData_ = exif_data_new();
    exinfo.imageFileDirectory_ = EXIF_IFD_COUNT;
    int ret = exinfo.ParseExifData(buf, len);
    ASSERT_NE(ret, 10001);
    exif_data_unref(exinfo.exifData_);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: ParseExifData002 end";
}

/**
 * @tc.name: UpdateCacheExifData002
 * @tc.desc: UpdateCacheExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, UpdateCacheExifData002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: UpdateCacheExifData002 start";
    EXIFInfo exinfo;
    FILE *file = fopen("/data/local/tmp/image/testtest.txt", "w+");
    exinfo.UpdateCacheExifData(file);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: UpdateCacheExifData002 end";
}

/**
 * @tc.name: GetAreaFromExifEntries002
 * @tc.desc: GetAreaFromExifEntries
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetAreaFromExifEntries002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetAreaFromExifEntries002 start";
    EXIFInfo exinfo;
    const uint8_t *buf = new uint8_t;
    ByteOrderedBuffer byteOrderedBuffer(buf, 10);
    byteOrderedBuffer.GenerateDEArray();
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    DirectoryEntry Direc;
    Direc.ifd = EXIF_IFD_GPS;
    byteOrderedBuffer.directoryEntryArray_.push_back(Direc);
    exinfo.GetAreaFromExifEntries(1, byteOrderedBuffer.directoryEntryArray_, ranges);
    delete buf;
    buf = nullptr;
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetAreaFromExifEntries002 end";
}

/**
 * @tc.name: PluginExternalCreateTest001
 * @tc.desc: PluginExternalCreate
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, PluginExternalCreateTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginExportTest: PluginExternalCreateTest001 start";
    string className = "";
    OHOS::MultimediaPlugin::PluginClassBase *result = PluginExternalCreate(className);
    ASSERT_EQ(result, nullptr);
    className = "#ImplClassType";
    result = PluginExternalCreate(className);
    ASSERT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "PluginExportTest: PluginExternalCreateTest001 end";
}

/**
 * @tc.name: getGrColorSpaceTest001
 * @tc.desc: getGrColorSpace
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, getGrColorSpaceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IccProfileInfoTest: getGrColorSpaceTest001 start";
    ICCProfileInfo iccProfileInfo;
    iccProfileInfo.getGrColorSpace();
    GTEST_LOG_(INFO) << "IccProfileInfoTest: getGrColorSpaceTest001 end";
}

/**
 * @tc.name: PackingICCProfileTest001
 * @tc.desc: PackingICCProfile
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, PackingICCProfileTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IccProfileInfoTest: PackingICCProfileTest001 start";
    ICCProfileInfo iccProfileInfo;
    j_compress_ptr cinfo = nullptr;
    const SkImageInfo info;
    uint32_t result = iccProfileInfo.PackingICCProfile(cinfo, info);
    ASSERT_EQ(result, OHOS::Media::ERR_IMAGE_ENCODE_ICC_FAILED);
    GTEST_LOG_(INFO) << "IccProfileInfoTest: PackingICCProfileTest001 end";
}

/**
 * @tc.name: exif_info017
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info017 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    std::string value = "111";
    unsigned char data[3] = {0xFF, 0xD8, 0x12};
    uint32_t size = 1;
    uint32_t ret = exinfo.ModifyExifData(tag, value, data, size);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info017 end";
}

/**
 * @tc.name: exif_info018
 * @tc.desc: SetGpsRationals
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info018 start";
    EXIFInfo exinfo;
    ExifData *data = nullptr;
    ExifEntry *ptrEntry = nullptr;
    ExifByteOrder order = EXIF_BYTE_ORDER_INTEL;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    std::vector<ExifRational> exifRationals;
    bool ret = exinfo.SetGpsRationals(data, &ptrEntry, order, tag, exifRationals);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info018 end";
}

/**
 * @tc.name: exif_info019
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info019 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    std::string value = "111";
    std::string path = IMAGE_INPUT_JPEG_PATH;
    uint32_t ret = exinfo.ModifyExifData(tag, value, path);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info019 end";
}

/**
 * @tc.name: exif_info020
 * @tc.desc: ModifyExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info020 start";
    EXIFInfo exinfo;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    std::string value = "111";
    int fd = open("/data/local/tmp/image/test_test.text", O_RDWR | O_CREAT, 0777);
    char buffer[3] = {0xFF, 0xD8, 0x11};
    write(fd, buffer, strlen(buffer));
    uint32_t ret = exinfo.ModifyExifData(tag, value, fd);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: exif_info020 end";
}

/**
 * @tc.name: Jpeg_EncoderTest001
 * @tc.desc: GetEncodeFormat
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, Jpeg_EncoderTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: Jpeg_EncoderTest001 start";
    auto Jpegencoder = std::make_shared<JpegEncoder>();
    PixelFormat format = PixelFormat::RGBA_F16;
    int32_t componentsNum = 1;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_RGBA);
    format = PixelFormat::RGBA_8888;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_RGBA);
    format = PixelFormat::BGRA_8888;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_BGRA);
    format = PixelFormat::ALPHA_8;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_GRAY);
    format = PixelFormat::RGB_565;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_RGB);
    format = PixelFormat::RGB_888;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_RGB);
    format = PixelFormat::NV12;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_YUV420SP);
    format = PixelFormat::NV21;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_YUV420SP);
    format = PixelFormat::CMYK;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, COMPONENT_NUM_RGBA);
    format = PixelFormat::UNKNOWN;
    Jpegencoder->GetEncodeFormat(format, componentsNum);
    ASSERT_EQ(componentsNum, 0);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: Jpeg_EncoderTest001 end";
}

/**
 * @tc.name: GenerateDEArray004
 * @tc.desc: GenerateDEArray
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GenerateDEArray004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GenerateDEArray004 start";
    const uint8_t buf = 'a';
    ByteOrderedBuffer byteorder(&buf, 10);
    byteorder.curPosition_ = 2;
    byteorder.bufferLength_ = 7;
    byteorder.GenerateDEArray();
    ASSERT_EQ(true, byteorder.curPosition_ + 2 > byteorder.bufferLength_);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GenerateDEArray004 end";
}

/**
 * @tc.name: GetExifData002
 * @tc.desc: GetExifData
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetExifData002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifData002 start";
    EXIFInfo exinfo;
    std::string value = "test";
    const std::string name = "test";
    uint32_t ret = exinfo.GetExifData(name, value);
    ASSERT_EQ(ret, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifData002 end";
}

/**
 * @tc.name: GetExifIfdByExifTag001
 * @tc.desc: GetExifIfdByExifTag
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetExifIfdByExifTag001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifIfdByExifTag001 start";
    EXIFInfo exinfo;
    ExifTag tag = static_cast<ExifTag>(0xea1c);
    ExifIfd ret = exinfo.GetExifIfdByExifTag(tag);
    ASSERT_EQ(ret, EXIF_IFD_COUNT);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifIfdByExifTag001 end";
}

/**
 * @tc.name: GetExifFormatByExifTag001
 * @tc.desc: GetExifFormatByExifTag
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, GetExifFormatByExifTag001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifFormatByExifTag001 start";
    EXIFInfo exinfo;
    ExifTag tag = static_cast<ExifTag>(0xea1c);
    ExifFormat ret = exinfo.GetExifFormatByExifTag(tag);
    ASSERT_EQ(ret, EXIF_FORMAT_UNDEFINED);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetExifFormatByExifTag001 end";
}

/**
 * @tc.name: SetGpsRationals001
 * @tc.desc: SetGpsRationals
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetGpsRationals001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetGpsRationals001 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData = nullptr;
    ExifEntry *ptrEntry = nullptr;
    ExifByteOrder order = EXIF_BYTE_ORDER_INTEL;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    std::vector<ExifRational> exifRationals;
    exifRationals.resize(3);
    ASSERT_EQ(exifRationals.size(), 3);
    unsigned char data = 'a';
    uint32_t size = 10;
    bool isNewExifData = true;
    exinfo.CreateExifData(&data, size, &ptrExifData, isNewExifData);
    bool ret = exinfo.SetGpsRationals(ptrExifData, &ptrEntry, order, tag, exifRationals);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetGpsRationals001 end";
}

/**
 * @tc.name: SetGpsDegreeRational001
 * @tc.desc: SetGpsDegreeRational
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, SetGpsDegreeRational001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetGpsDegreeRational001 start";
    EXIFInfo exinfo;
    ExifData *ptrExifData = nullptr;
    ExifEntry *ptrEntry = nullptr;
    ExifByteOrder order = EXIF_BYTE_ORDER_INTEL;
    ExifTag tag = EXIF_TAG_GPS_LATITUDE;
    std::vector<std::string> exifRationals;
    exifRationals.resize(3);
    ASSERT_NE(exifRationals.size(), 2);
    unsigned char data = 'a';
    uint32_t size = 10;
    bool isNewExifData = true;
    exinfo.CreateExifData(&data, size, &ptrExifData, isNewExifData);
    bool ret = exinfo.SetGpsDegreeRational(ptrExifData, &ptrEntry, order, tag, exifRationals);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: SetGpsDegreeRational001 end";
}
} // namespace Multimedia
} // namespace OHOS