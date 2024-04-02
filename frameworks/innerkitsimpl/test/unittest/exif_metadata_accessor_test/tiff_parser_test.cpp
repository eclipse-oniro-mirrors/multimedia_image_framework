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
} // namespace Multimedia
} // namespace OHOS
