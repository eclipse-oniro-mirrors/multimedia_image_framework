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
#include <fcntl.h>
#include "buffer_source_stream.h"
#include "exif_info.h"
#include "jpeg_decoder.h"
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
    exinfo.ModifyExifData(tag, value, IMAGE_INPUT_TXT_PATH);
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
    exinfo.ModifyExifData(tag, value, fd);
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
    exinfo.ModifyExifData(tag, value, fd);
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
} // namespace Multimedia
} // namespace OHOS