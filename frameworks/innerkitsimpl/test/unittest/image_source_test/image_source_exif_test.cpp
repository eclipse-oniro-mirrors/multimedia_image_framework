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
static const std::string IMAGE_REMOVE_EXIF_JPEG_PATH = "/data/local/tmp/image/test_remove_exif.jpg";
static const std::string IMAGE_REMOVE_EXIF_PNG_PATH = "/data/local/tmp/image/test_remove_exif.png";
static const std::string IMAGE_REMOVE_EXIF_WEBP_PATH = "/data/local/tmp/image/test_remove_exif.webp";
static const std::string IMAGE_REMOVE_EXIF_HEIF_PATH = "/data/local/tmp/image/test_remove_exif.heic";
static const std::string IMAGE_REMOVE_HW_EXIF_PATH = "/data/local/tmp/image/test_remove_hw_exif.jpg";
static const std::string IMAGE_REMOVE_NO_EXIF_JPEG_PATH = "/data/local/tmp/image/test_remove_no_exif.jpg";

class ImageSourceExifTest : public testing::Test {
public:
    ImageSourceExifTest() {}
    ~ImageSourceExifTest() {}
};

static std::string GetProperty(std::unique_ptr<ImageSource> &imageSource, const std::string &prop)
{
    std::string value;
    imageSource->GetImagePropertyString(0, prop, value);
    return value;
}

/**
 * @tc.name: ModifyImageProperty001
 * @tc.desc: test ModifyImageProperty fd jpeg
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
    close(fd);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: ModifyImageProperty001 end";
}

/**
 * @tc.name: ModifyImageProperty002
 * @tc.desc: test ModifyImageProperty const std::string &path jpeg
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

HWTEST_F(ImageSourceExifTest, ModifyImageProperty004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ModifyImageProperty004 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::string path = IMAGE_INPUT_EXIF_JPEG_PATH;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    std::string valueGetIn;
    uint32_t index = 0;
    std::string key = "GPSLongitudeRef";
    errorCode = imageSource->GetImagePropertyString(index, key, valueGetIn);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(valueGetIn, "W");

    int32_t retModify = imageSource->ModifyImageProperty(index, key, "E");
    ASSERT_EQ(retModify, OHOS::Media::SUCCESS);
    std::string checkStr;
    imageSource->GetImagePropertyString(index, key, checkStr);
    ASSERT_EQ(checkStr, "E");

    std::string value;
    std::unique_ptr<ImageSource> imageSourceOut = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = imageSourceOut->GetImagePropertyString(index, key, value);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(value, "W");

    GTEST_LOG_(INFO) << "ImageSourceExifTest: ModifyImageProperty004 end";
}

HWTEST_F(ImageSourceExifTest, GetImagePropertyInt001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: GetImagePropertyInt001 start";

    const int fd = open(IMAGE_INPUT_NO_EXIF_JPEG_PATH.c_str(), O_RDWR | S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);

    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(fd, opts, errorCode);

    uint32_t index = 0;
    int32_t value = 0;
    std::string strValue;

    std::string key = "Orientation";
    imageSource->ModifyImageProperty(index, key, "1", fd);
    imageSource->GetImagePropertyString(index, key, strValue);
    ASSERT_EQ(strValue, "Top-left");
    imageSource->GetImagePropertyInt(index, key, value);
    ASSERT_EQ(value, 0);

    imageSource->ModifyImageProperty(index, key, "3", fd);
    imageSource->GetImagePropertyString(index, key, strValue);
    ASSERT_EQ(strValue, "Bottom-right");
    imageSource->GetImagePropertyInt(index, key, value);
    ASSERT_EQ(value, 180);

    imageSource->ModifyImageProperty(index, key, "6", fd);
    imageSource->GetImagePropertyString(index, key, strValue);
    ASSERT_EQ(strValue, "Right-top");
    imageSource->GetImagePropertyInt(index, key, value);
    ASSERT_EQ(value, 90);

    imageSource->ModifyImageProperty(index, key, "8", fd);
    imageSource->GetImagePropertyString(index, key, strValue);
    ASSERT_EQ(strValue, "Left-bottom");
    imageSource->GetImagePropertyInt(index, key, value);
    ASSERT_EQ(value, 270);

    imageSource->ModifyImageProperty(index, key, "4", fd);
    imageSource->GetImagePropertyString(index, key, strValue);
    ASSERT_EQ(strValue, "Bottom-left");
    auto ret = imageSource->GetImagePropertyInt(index, key, value);
    ASSERT_EQ(ret, Media::ERR_IMAGE_SOURCE_DATA);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: GetImagePropertyInt001 end";
}

HWTEST_F(ImageSourceExifTest, GetImagePropertyInt002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: GetImagePropertyInt002 start";

    const int fd = open(IMAGE_INPUT_EXIF_JPEG_PATH.c_str(), O_RDWR | S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);

    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(fd, opts, errorCode);
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);

    uint32_t index = 0;
    int32_t value = 0;
    std::string strValue;

    imageSource->GetImagePropertyInt(index, "DelayTime", value);
    ASSERT_EQ(value, 0);

    imageSource->GetImagePropertyInt(index, "DisposalType", value);
    ASSERT_EQ(value, 0);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: GetImagePropertyInt002 end";
}

HWTEST_F(ImageSourceExifTest, RemoveImageProperty001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty001 start";

    std::string path =IMAGE_REMOVE_EXIF_JPEG_PATH;
    const int fd = open(path.c_str(), O_RDWR | S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(fd, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(GetProperty(imageSource, "DateTimeOriginal"), "2024:01:11 09:39:58");
    ASSERT_EQ(GetProperty(imageSource, "ExposureTime"), "1/590 sec.");
    ASSERT_EQ(GetProperty(imageSource, "SceneType"), "Directly photographed");
    std::set<std::string> keys = {"DateTimeOriginal", "ExposureTime", "SceneType"};
    errorCode = imageSource->RemoveImageProperties(0, keys, fd);
    ASSERT_EQ(errorCode, SUCCESS);

    std::unique_ptr<ImageSource> imageSourceNew = ImageSource::CreateImageSource(path, opts, errorCode);
    std::string value;
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "DateTimeOriginal", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "ExposureTime", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "SceneType", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty001 end";
}

HWTEST_F(ImageSourceExifTest, RemoveImageProperty002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty002 start";

    uint32_t errorCode = 0;
    std::string path = IMAGE_REMOVE_EXIF_PNG_PATH;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(GetProperty(imageSource, "DateTime"), "2015:11:05 23:04:30");
    ASSERT_EQ(GetProperty(imageSource, "YCbCrPositioning"), "Centered");

    std::set<std::string> keys = {"DateTime", "YCbCrPositioning"};
    errorCode = imageSource->RemoveImageProperties(0, keys, path);
    ASSERT_EQ(errorCode, SUCCESS);
    std::unique_ptr<ImageSource> imageSourceNew = ImageSource::CreateImageSource(path, opts, errorCode);
    std::string value;
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "DateTime", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "YCbCrPositioning", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty002 end";
}

HWTEST_F(ImageSourceExifTest, RemoveImageProperty003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty003 start";

    uint32_t errorCode = 0;
    std::string path = IMAGE_REMOVE_EXIF_WEBP_PATH;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(GetProperty(imageSource, "DateTimeOriginal"), "2022:06:02 15:51:35");
    ASSERT_EQ(GetProperty(imageSource, "ExposureTime"), "1/33 sec.");
    ASSERT_EQ(GetProperty(imageSource, "SceneType"), "Directly photographed");
    std::set<std::string> keys = {"DateTimeOriginal", "ExposureTime", "SceneType"};
    errorCode = imageSource->RemoveImageProperties(0, keys, path);
    ASSERT_EQ(errorCode, SUCCESS);

    std::unique_ptr<ImageSource> imageSourceNew = ImageSource::CreateImageSource(path, opts, errorCode);
    std::string value;
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "DateTimeOriginal", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "ExposureTime", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "SceneType", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty003 end";
}

HWTEST_F(ImageSourceExifTest, RemoveImageProperty004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty004 start";

    uint32_t errorCode = 0;
    std::string path = IMAGE_REMOVE_HW_EXIF_PATH;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    ASSERT_EQ(GetProperty(imageSource, "HwMnoteBurstNumber"), "2");
    ASSERT_EQ(GetProperty(imageSource, "HwMnoteCaptureMode"), "1");
    ASSERT_EQ(GetProperty(imageSource, "HwMnoteFaceConf"), "3");
    std::set<std::string> keys = {"HwMnoteBurstNumber", "HwMnoteCaptureMode", "HwMnoteFaceConf"};
    errorCode = imageSource->RemoveImageProperties(0, keys, path);
    ASSERT_EQ(errorCode, SUCCESS);

    ASSERT_EQ(GetProperty(imageSource, "HwMnoteBurstNumber"), "2");
    ASSERT_EQ(GetProperty(imageSource, "HwMnoteCaptureMode"), "default_exif_value");
    ASSERT_EQ(GetProperty(imageSource, "HwMnoteFaceConf"), "3");

    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty004 end";
}

HWTEST_F(ImageSourceExifTest, RemoveImageProperty005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty005 start";

    uint32_t errorCode = 0;
    std::string path = IMAGE_REMOVE_EXIF_HEIF_PATH;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(GetProperty(imageSource, "DateTimeOriginal"), "2024:02:28 09:23:06");
    ASSERT_EQ(GetProperty(imageSource, "ExposureTime"), "1/50 sec.");
    ASSERT_EQ(GetProperty(imageSource, "SceneType"), "Directly photographed");
    std::set<std::string> keys = {"DateTimeOriginal", "ExposureTime", "SceneType"};
    errorCode = imageSource->RemoveImageProperties(0, keys, path);
    ASSERT_EQ(errorCode, SUCCESS);

    std::unique_ptr<ImageSource> imageSourceNew = ImageSource::CreateImageSource(path, opts, errorCode);
    std::string value;
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "DateTimeOriginal", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "ExposureTime", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    ASSERT_EQ(imageSourceNew->GetImagePropertyString(0, "SceneType", value), ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty005 end";
}

HWTEST_F(ImageSourceExifTest, RemoveImageProperty006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty006 start";

    uint32_t errorCode = 0;
    std::string path = IMAGE_REMOVE_NO_EXIF_JPEG_PATH;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    std::set<std::string> keys = {"DateTimeOriginal", "ExposureTime", "SceneType"};
    errorCode = imageSource->RemoveImageProperties(0, keys, path);
    ASSERT_EQ(errorCode, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty006 end";
}

} // namespace Multimedia
} // namespace OHOS
