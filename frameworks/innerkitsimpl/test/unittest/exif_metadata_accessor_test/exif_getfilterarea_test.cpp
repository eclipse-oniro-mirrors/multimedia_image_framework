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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <memory>

#include "file_metadata_stream.h"
#include "image_source.h"
#include "media_errors.h"
#include "metadata_accessor.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
namespace {
static const std::string IMAGE_GET_FILTER_AREA_HEIF_PATH = "/data/local/tmp/image/get_filter_area.heic";
static const std::string IMAGE_GET_FILTER_AREA_JPEG_PATH = "/data/local/tmp/image/get_filter_area.jpg";
static const std::string IMAGE_GET_FILTER_AREA_PNG_PATH = "/data/local/tmp/image/get_filter_area.png";
static const std::string IMAGE_GET_FILTER_AREA_WEBP_PATH = "/data/local/tmp/image/get_filter_area.webp";
static const std::string IMAGE_GET_FILTER_AREA_DNG_PATH = "/data/local/tmp/image/get_filter_area.dng";
static const std::string IMAGE_GET_FILTER_AREA_DNG_FILTERED_PATH = "/data/local/tmp/image/get_filter_area_filtered.dng";
static const std::string IMAGE_NO_GPS_HEIF_PATH = "/data/local/tmp/image/test.heic";
static const std::string IMAGE_NO_GPS_JPEG_PATH = "/data/local/tmp/image/test_jpeg_readexifblob003.jpg";
static const std::string IMAGE_NO_GPS_PNG_PATH = "/data/local/tmp/image/test_exif.png";
static const std::string IMAGE_NO_GPS_WEBP_PATH = "/data/local/tmp/image/test_webp_readmetadata008.webp";
static const std::string IMAGE_INPUT_ITXT_WITHCOMPRESS_PNG_PATH =
    "/data/local/tmp/image/test_chunk_itxt_withcompress.png";
static const uint8_t GPSAltitude[] = {0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
static const uint8_t GPSSatellites[] = {0x35, 0x20, 0x38, 0x20, 0x32, 0x30};
static const uint8_t GPSStatus[] = {0x56};
static const uint8_t GPSMeasureMode[] = {0x32};
static const uint8_t GPSDOP[] = {0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
static const uint8_t GPSSpeed[] = {0x46, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
static const uint8_t GPSTrackRef[] = {0x54};
static const uint8_t GPSTrack[] = {0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
static const uint8_t GPSImgDirection[] = {0x4a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
static const int MAX_FILE_SIZE = 1000 * 1000 * 100;
static const std::vector<std::string> gpsExifKeys{
    "GPSAltitude",
    "GPSSatellites",
    "GPSStatus",
    "GPSMeasureMode",
    "GPSDOP",
    "GPSSpeed",
    "GPSTrackRef",
    "GPSTrack",
    "GPSImgDirection"
};
static const std::vector<std::string> dngExifKeys{
        "GPSVersionID",
        "GPSLatitudeRef",
        "GPSLatitude",
        "GPSLongitudeRef",
        "GPSLongitude",
        "GPSAltitude",
        "GPSSatellites",
        "GPSStatus",
        "GPSMeasureMode",
        "GPSDOP",
        "GPSSpeed",
        "GPSTrackRef",
        "GPSTrack",
        "GPSImgDirection",
        "GPSDateStamp",
        "GPSHPositioningError",
        "Make",
        "Model",
        "DateTimeOriginal",
        "LensMake",
};
}

class ExifGetFilterAreaTest : public testing::Test {
public:
    ExifGetFilterAreaTest() {}
    ~ExifGetFilterAreaTest() {}

    void CopyFileStream(std::fstream &src, std::fstream &dst);
};

void ExifGetFilterAreaTest::CopyFileStream(std::fstream &src, std::fstream &dst)
{
    src.seekg(0, src.end);
    long size = src.tellg();
    src.seekg(0);
    if (size > MAX_FILE_SIZE) {
        return;
    }
    char* buffer = new char[size];
    src.read(buffer, size);
    dst.write(buffer, size);
    delete[] buffer;
    dst.seekg(0);
}

/**
 * @tc.name: GetFilterArea001
 * @tc.desc: test GetFilterArea(filterType, ranges)
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea001, TestSize.Level3)
{
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_GET_FILTER_AREA_HEIF_PATH, std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::fstream& fileStream = *fs;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    std::vector<std::vector<char>> contents;
    uint32_t ret = imageSource->GetFilterArea(gpsExifKeys, ranges);
    ASSERT_EQ(ret, SUCCESS);
    for (const auto& range : ranges) {
        fileStream.seekg(range.first, std::ios::beg);
        std::vector<char> content(range.second);
        fileStream.read(reinterpret_cast<char *>(content.data()), range.second);
        contents.push_back(content);
    }
    int i = 0;
    ASSERT_EQ(std::memcmp(GPSAltitude, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSSatellites, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSStatus, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSMeasureMode, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSDOP, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSSpeed, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSTrackRef, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSTrack, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSImgDirection, contents[i].data(), contents[i].size()), SUCCESS);
}

/**
 * @tc.name: GetFilterArea002
 * @tc.desc: test GetFilterArea(filterType, ranges)
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea002, TestSize.Level3)
{
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_GET_FILTER_AREA_PNG_PATH, std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::fstream& fileStream = *fs;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    std::vector<std::vector<char>> contents;
    uint32_t ret = imageSource->GetFilterArea(gpsExifKeys, ranges);
    ASSERT_EQ(ret, SUCCESS);
    for (const auto& range : ranges) {
        fileStream.seekg(range.first, std::ios::beg);
        std::vector<char> content(range.second);
        fileStream.read(reinterpret_cast<char *>(content.data()), range.second);
        contents.push_back(content);
    }
    int i = 0;
    ASSERT_EQ(std::memcmp(GPSAltitude, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSSatellites, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSStatus, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSMeasureMode, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSDOP, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSSpeed, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSTrackRef, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSTrack, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSImgDirection, contents[i].data(), contents[i].size()), SUCCESS);
}

/**
 * @tc.name: GetFilterArea003
 * @tc.desc: test GetFilterArea(filterType, ranges)
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea003, TestSize.Level3)
{
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_GET_FILTER_AREA_JPEG_PATH, std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::fstream& fileStream = *fs;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    std::vector<std::vector<char>> contents;
    uint32_t ret = imageSource->GetFilterArea(gpsExifKeys, ranges);
    ASSERT_EQ(ret, SUCCESS);
    for (const auto& range : ranges) {
        fileStream.seekg(range.first, std::ios::beg);
        std::vector<char> content(range.second);
        fileStream.read(reinterpret_cast<char *>(content.data()), range.second);
        contents.push_back(content);
    }
    int i = 0;
    ASSERT_EQ(std::memcmp(GPSAltitude, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSSatellites, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSStatus, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSMeasureMode, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSDOP, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSSpeed, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSTrackRef, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSTrack, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSImgDirection, contents[i].data(), contents[i].size()), SUCCESS);
}

/**
 * @tc.name: GetFilterArea004
 * @tc.desc: test GetFilterArea(filterType, ranges)
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea004, TestSize.Level3)
{
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_GET_FILTER_AREA_WEBP_PATH, std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::fstream& fileStream = *fs;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    std::vector<std::vector<char>> contents;
    uint32_t ret = imageSource->GetFilterArea(gpsExifKeys, ranges);
    ASSERT_EQ(ret, SUCCESS);
    for (const auto& range : ranges) {
        fileStream.seekg(range.first, std::ios::beg);
        std::vector<char> content(range.second);
        fileStream.read(reinterpret_cast<char *>(content.data()), range.second);
        contents.push_back(content);
    }
    int i = 0;
    ASSERT_EQ(std::memcmp(GPSAltitude, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSSatellites, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSStatus, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSMeasureMode, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSDOP, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSSpeed, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSTrackRef, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSTrack, contents[i].data(), contents[i].size()), SUCCESS);
    i++;
    ASSERT_EQ(std::memcmp(GPSImgDirection, contents[i].data(), contents[i].size()), SUCCESS);
}

/**
 * @tc.name: GetFilterArea
 * @tc.desc: test GetFilterArea005
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea005, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_GET_FILTER_AREA_WEBP_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    std::vector<std::string> keys;
    uint32_t ret = imageSource->GetFilterArea(keys, ranges);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: GetFilterArea
 * @tc.desc: test GetFilterArea006
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea006, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_ITXT_WITHCOMPRESS_PNG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = imageSource->GetFilterArea(gpsExifKeys, ranges);
    ASSERT_EQ(ret, E_NO_EXIF_TAG);
}

/**
 * @tc.name: GetFilterArea
 * @tc.desc: test GetFilterArea007
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea007, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_NO_GPS_HEIF_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = imageSource->GetFilterArea(gpsExifKeys, ranges);
    ASSERT_EQ(ret, E_NO_EXIF_TAG);
}

/**
 * @tc.name: GetFilterArea
 * @tc.desc: test GetFilterArea008
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea008, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_NO_GPS_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = imageSource->GetFilterArea(gpsExifKeys, ranges);
    ASSERT_EQ(ret, E_NO_EXIF_TAG);
}

/**
 * @tc.name: GetFilterArea
 * @tc.desc: test GetFilterArea009
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea009, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_NO_GPS_PNG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = imageSource->GetFilterArea(gpsExifKeys, ranges);
    ASSERT_EQ(ret, E_NO_EXIF_TAG);
}

/**
 * @tc.name: GetFilterArea
 * @tc.desc: test GetFilterArea010
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea010, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_NO_GPS_WEBP_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = imageSource->GetFilterArea(gpsExifKeys, ranges);
    ASSERT_EQ(ret, E_NO_EXIF_TAG);
}

/**
 * @tc.name: GetFilterArea011
 * @tc.desc: test GetFilterArea dng
 * @tc.type: FUNC
 */
HWTEST_F(ExifGetFilterAreaTest, GetFilterArea011, TestSize.Level3)
{
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    std::unique_ptr<std::fstream> fsOut = std::make_unique<std::fstream>();
    fs->open(IMAGE_GET_FILTER_AREA_DNG_PATH, std::fstream::binary | std::fstream::in);
    fsOut->open(IMAGE_GET_FILTER_AREA_DNG_FILTERED_PATH,
                std::fstream::binary | std::fstream::out);
    bool isOpen = fs->is_open();
    bool isOutOpen = fsOut->is_open();
    ASSERT_EQ(isOpen && isOutOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::fstream& fileStream = *fs;
    std::fstream& fileOutStream = *fsOut;
    CopyFileStream(fileStream, fileOutStream);
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(
            IMAGE_GET_FILTER_AREA_DNG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    std::vector<std::string> values;
    for (int i = 0; i < dngExifKeys.size(); ++i) {
        std::string tmp = "";
        errorCode = imageSource->GetImagePropertyString(0, dngExifKeys[i], tmp);
        ASSERT_EQ(errorCode, SUCCESS);
        values.emplace_back(tmp);
    }
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    uint32_t ret = imageSource->GetFilterArea(dngExifKeys, ranges);
    ASSERT_EQ(ret, SUCCESS);
    for (const auto& range : ranges) {
        fileOutStream.seekg(range.first, std::ios::beg);
        std::vector<char> buf(range.second, 0);
        fileOutStream.write(reinterpret_cast<char *>(buf.data()), range.second);
    }
    fileOutStream.seekg(0);
    fileOutStream.close();
    fileStream.close();
    std::unique_ptr<ImageSource> imageSource2 = ImageSource::CreateImageSource(
            IMAGE_GET_FILTER_AREA_DNG_FILTERED_PATH, opts, errorCode);
    ASSERT_NE(imageSource2, nullptr);
    std::vector<std::string> filteredValues;
    for (int i = 0; i < dngExifKeys.size(); ++i) {
        std::string tmp = "";
        errorCode = imageSource2->GetImagePropertyString(0, dngExifKeys[i], tmp);
        ASSERT_EQ(errorCode, SUCCESS);
        filteredValues.emplace_back(tmp);
    }
    ASSERT_EQ(values.size(), filteredValues.size());
    for (int i = 0; i < dngExifKeys.size(); ++i) {
        ASSERT_NE(values[i], filteredValues[i]);
    }
}
} // namespace Multimedia
} // namespace OHOS