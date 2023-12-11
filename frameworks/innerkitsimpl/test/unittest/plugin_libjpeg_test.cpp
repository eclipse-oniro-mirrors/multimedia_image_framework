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
#define private public
#include <fcntl.h>
#include "buffer_source_stream.h"
#include "exif_info.h"
#include "jpeg_decoder.h"
#include "jpeg_encoder.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImagePlugin;
namespace OHOS {
namespace Media {
static const std::string IMAGE_INPUT_NULL_JPEG_PATH = "/data/local/tmp/image/test_null.jpg";
static const std::string IMAGE_INPUT_TXT_PATH = "/data/local/tmp/image/test.txt";
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
 * @tc.name: exif_info018
 * @tc.desc: GetEncodeFormat
 * @tc.type: FUNC
 */
HWTEST_F(PluginLibJpegTest, exif_info018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetEncodeFormat start";
    auto jpegEncoder = std::make_shared<JpegEncoder>();
    int32_t componentsNum;
    jpegEncoder->GetEncodeFormat(PixelFormat::RGBA_F16, componentsNum);
    ASSERT_EQ(componentsNum, 4);
    jpegEncoder->GetEncodeFormat(PixelFormat::RGBA_8888, componentsNum);
    ASSERT_EQ(componentsNum, 4);
    jpegEncoder->GetEncodeFormat(PixelFormat::BGRA_8888, componentsNum);
    ASSERT_EQ(componentsNum, 4);
    jpegEncoder->GetEncodeFormat(PixelFormat::ARGB_8888, componentsNum);
    ASSERT_EQ(componentsNum, 4);
    jpegEncoder->GetEncodeFormat(PixelFormat::ALPHA_8, componentsNum);
    ASSERT_EQ(componentsNum, 1);
    jpegEncoder->GetEncodeFormat(PixelFormat::RGB_565, componentsNum);
    ASSERT_EQ(componentsNum, 3);
    jpegEncoder->GetEncodeFormat(PixelFormat::RGB_888, componentsNum);
    ASSERT_EQ(componentsNum, 3);
    jpegEncoder->GetEncodeFormat(PixelFormat::NV12, componentsNum);
    ASSERT_EQ(componentsNum, 3);
    jpegEncoder->GetEncodeFormat(PixelFormat::NV21, componentsNum);
    ASSERT_EQ(componentsNum, 3);
    jpegEncoder->GetEncodeFormat(PixelFormat::CMYK, componentsNum);
    ASSERT_EQ(componentsNum, 4);
    GTEST_LOG_(INFO) << "PluginLibJpegTest: GetEncodeFormat end";
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
    byteorder.bufferLength_ = -1;
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
    byteorder.bufferLength_ = -1;
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
} // namespace Multimedia
} // namespace OHOS