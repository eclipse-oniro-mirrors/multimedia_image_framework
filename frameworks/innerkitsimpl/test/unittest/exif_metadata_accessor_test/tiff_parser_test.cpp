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
#include "tiff_parser.h"
#include "image_log.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";
constexpr uint32_t TEST_BUFFER_SIZE = 100;

class TiffParserTest : public testing::Test {
public:
    TiffParserTest() {}
    ~TiffParserTest() {}
};

HWTEST_F(TiffParserTest, DecodeJpegExif001, TestSize.Level3)
{
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);

    unsigned char* buf = nullptr;
    unsigned int len = 0;
    exif_data_save_data(exifData, &buf, &len);
    GTEST_LOG_(INFO) << "TiffParserTest: DecodeJpegExif001" << " buffer length: " << len;
    ASSERT_NE(len, 0);

    ExifData *exifData_ = nullptr;
    TiffParser::DecodeJpegExif(buf, len, &exifData_);
    ASSERT_NE(exifData_, nullptr);
}

HWTEST_F(TiffParserTest, EncodeJpegExif001, TestSize.Level3)
{
    TiffParser parser;
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);

    unsigned char* buf = nullptr;
    unsigned int len = 0;
    exif_data_save_data(exifData, &buf, &len);
    ASSERT_NE(len, 0);

    ExifData *exifData_ = nullptr;
    parser.DecodeJpegExif(buf, len, &exifData_);
    ASSERT_NE(exifData_, nullptr);

    unsigned char *dataPtr = nullptr;
    uint32_t size;
    parser.EncodeJpegExif(&dataPtr, size, exifData_);
    ASSERT_NE(dataPtr, nullptr);
}

HWTEST_F(TiffParserTest, Decode001, TestSize.Level3)
{
    TiffParser parser;
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);

    unsigned char* buf = nullptr;
    unsigned int len = 0;
    exif_data_save_data(exifData, &buf, &len);
    ASSERT_NE(len, 0);

    ExifData *exifData_ = nullptr;
    parser.Decode(buf + 6, len - 6, &exifData_);
    ASSERT_NE(exifData_, nullptr);
}

HWTEST_F(TiffParserTest, Encode001, TestSize.Level3)
{
    TiffParser parser;
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);

    unsigned char* buf = nullptr;
    unsigned int len = 0;
    exif_data_save_data(exifData, &buf, &len);
    ASSERT_NE(len, 0);

    ExifData *exifData_ = nullptr;
    parser.Decode(buf + 6, len - 6, &exifData_);
    ASSERT_NE(exifData_, nullptr);

    unsigned char *dataPtr = nullptr;
    uint32_t size;
    parser.Encode(&dataPtr, size, exifData_);
    ASSERT_NE(dataPtr, nullptr);
}

/**
 * @tc.name: DecodeNullptrTest001
 * @tc.desc: Test Decode with nullptr input buffer
 * @tc.type: FUNC
 */
HWTEST_F(TiffParserTest, DecodeNullptrTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffParserTest: DecodeNullptrTest001 start";
    TiffParser parser;
    ExifData *exifData_ = nullptr;
    parser.Decode(nullptr, TEST_BUFFER_SIZE, &exifData_);
    EXPECT_EQ(exifData_, nullptr);
    GTEST_LOG_(INFO) << "TiffParserTest: DecodeNullptrTest001 end";
}

/**
 * @tc.name: EncodeNullptrTest001
 * @tc.desc: Test Encode with nullptr ExifData input
 * @tc.type: FUNC
 */
HWTEST_F(TiffParserTest, EncodeNullptrTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffParserTest: EncodeNullptrTest001 start";
    TiffParser parser;
    unsigned char *dataPtr = nullptr;
    uint32_t size = 0;
    parser.Encode(&dataPtr, size, nullptr);
    EXPECT_EQ(dataPtr, nullptr);
    EXPECT_EQ(size, 0);
    GTEST_LOG_(INFO) << "TiffParserTest: EncodeNullptrTest001 end";
}

/**
 * @tc.name: DecodeJpegExifNullptrTest001
 * @tc.desc: Test DecodeJpegExif with nullptr input buffer
 * @tc.type: FUNC
 */
HWTEST_F(TiffParserTest, DecodeJpegExifNullptrTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffParserTest: DecodeJpegExifNullptrTest001 start";
    TiffParser parser;
    ExifData *exifData_ = nullptr;
    parser.DecodeJpegExif(nullptr, TEST_BUFFER_SIZE, &exifData_);
    EXPECT_EQ(exifData_, nullptr);
    GTEST_LOG_(INFO) << "TiffParserTest: DecodeJpegExifNullptrTest001 end";
}

/**
 * @tc.name: EncodeJpegExifNullptrTest001
 * @tc.desc: Test EncodeJpegExif with nullptr ExifData input
 * @tc.type: FUNC
 */
HWTEST_F(TiffParserTest, EncodeJpegExifNullptrTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffParserTest: EncodeJpegExifNullptrTest001 start";
    TiffParser parser;
    unsigned char *dataPtr = nullptr;
    uint32_t size = 0;
    parser.EncodeJpegExif(&dataPtr, size, nullptr);
    EXPECT_EQ(dataPtr, nullptr);
    EXPECT_EQ(size, 0);
    GTEST_LOG_(INFO) << "TiffParserTest: EncodeJpegExifNullptrTest001 end";
}

/**
 * @tc.name: DecodeDataSetInvalidTest001
 * @tc.desc: Test Decode with invalid dataSet to cover byteOrderPos not found branch
 * @tc.type: FUNC
 */
HWTEST_F(TiffParserTest, DecodeDataSetInvalidTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "TiffParserTest: DecodeDataSetInvalidTest001 start";
    TiffParser parser;

    std::vector<std::vector<uint8_t>> dataSet;
    std::vector<uint8_t> invalidData = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    dataSet.push_back(invalidData);

    ExifData *exifData_ = nullptr;
    parser.Decode(dataSet, &exifData_);
    ASSERT_NE(exifData_, nullptr);
    GTEST_LOG_(INFO) << "TiffParserTest: DecodeDataSetInvalidTest001 end";
}
} // namespace Multimedia
} // namespace OHOS
