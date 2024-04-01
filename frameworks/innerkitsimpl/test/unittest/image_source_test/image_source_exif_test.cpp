/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "image_source.h"
#include "source_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {

static const std::string IMAGE_INPUT_EXIF_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";
static const std::string IMAGE_INPUT_NO_EXIF_JPEG_PATH = "/data/local/tmp/image/hasNoExif.jpg";

class ImageSourceExifTest : public testing::Test {
public:
    ImageSourceExifTest() {}
    ~ImageSourceExifTest() {}
};

/**
 * @tc.name: ModifyImageProperty001
 * @tc.desc: test ModifyImageProperty fd
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceExifTest, ModifyImageProperty001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ModifyImageProperty001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode);
    std::string valueGetIn;
    uint32_t index = 0;
    std::string key = "GPSLongitudeRef";
    uint32_t retGetIn = imageSource->GetImagePropertyString(index, key, valueGetIn);
    ASSERT_EQ(retGetIn, OHOS::Media::SUCCESS);
    ASSERT_EQ(valueGetIn, "W");
    std::string valueModify = "E";
    const int fd = open(IMAGE_INPUT_EXIF_JPEG_PATH.c_str(), O_RDWR | S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    int32_t retModify = imageSource->ModifyImageProperty(index, key, valueModify, fd);
    ASSERT_EQ(retModify, OHOS::Media::SUCCESS);

    std::string checkStr;
    imageSource->GetImagePropertyString(index, key, checkStr);
    ASSERT_EQ(checkStr, "E");

    std::string value;
    std::unique_ptr<ImageSource> imageSourceOut =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSourceOut, nullptr);
    uint32_t retGet = imageSourceOut->GetImagePropertyString(index, key, value);
    ASSERT_EQ(retGet, OHOS::Media::SUCCESS);
    ASSERT_EQ(value, "E");
    retModify = imageSource->ModifyImageProperty(index, key, "W", fd);
    ASSERT_EQ(retModify, OHOS::Media::SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ModifyImageProperty001 end";
}

/**
 * @tc.name: ModifyImageProperty002
 * @tc.desc: test ModifyImageProperty const std::string &path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceExifTest, ModifyImageProperty002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ModifyImageProperty002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode);
    std::string valueGetIn;
    uint32_t index = 0;
    std::string key = "GPSLongitudeRef";
    uint32_t retGetIn = imageSource->GetImagePropertyString(index, key, valueGetIn);
    ASSERT_EQ(retGetIn, OHOS::Media::SUCCESS);
    ASSERT_EQ(valueGetIn, "W");
    std::string valueModify = "E";
    uint32_t retModify = imageSource->ModifyImageProperty(index, key, valueModify, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(retModify, OHOS::Media::SUCCESS);

    std::string checkStr;
    imageSource->GetImagePropertyString(index, key, checkStr);
    ASSERT_EQ(checkStr, "E");

    std::string value;
    std::unique_ptr<ImageSource> imageSourceOut =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSourceOut, nullptr);
    uint32_t retGet = imageSourceOut->GetImagePropertyString(index, key, value);
    ASSERT_EQ(retGet, OHOS::Media::SUCCESS);
    ASSERT_EQ(value, "E");

    retModify = imageSource->ModifyImageProperty(index, key, "W", IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(retModify, OHOS::Media::SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ModifyImageProperty002 end";
}


/**
 * @tc.name: ModifyImageProperty003
 * @tc.desc: test ModifyImageProperty path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceExifTest, ModifyImageProperty003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ModifyImageProperty003 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_NO_EXIF_JPEG_PATH, opts, errorCode);
    std::string valueGetIn;
    uint32_t index = 0;
    std::string key = "GPSLongitudeRef";
    std::string valueModify = "E";

    int32_t retModify = imageSource->ModifyImageProperty(index, key, valueModify, IMAGE_INPUT_NO_EXIF_JPEG_PATH);
    ASSERT_EQ(retModify, OHOS::Media::SUCCESS);

    std::string checkStr;
    imageSource->GetImagePropertyString(index, key, checkStr);
    ASSERT_EQ(checkStr, "E");

    const int fd = open(IMAGE_INPUT_NO_EXIF_JPEG_PATH.c_str(), O_RDWR | S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    std::string value;
    std::unique_ptr<ImageSource> imageSourceOut =
        ImageSource::CreateImageSource(fd, opts, errorCode);
    ASSERT_NE(imageSourceOut, nullptr);
    uint32_t retGet = imageSourceOut->GetImagePropertyString(index, key, value);
    ASSERT_EQ(retGet, OHOS::Media::SUCCESS);
    ASSERT_EQ(value, "E");

    GTEST_LOG_(INFO) << "ImageSourceExifTest: ModifyImageProperty003 end";
}

} // namespace Multimedia
} // namespace OHOS