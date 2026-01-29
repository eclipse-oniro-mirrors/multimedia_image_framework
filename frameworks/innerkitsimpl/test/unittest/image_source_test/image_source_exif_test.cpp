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

#include "exif_metadata.h"

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
static const std::string IMAGE_REMOVE_EXIF_DNG_PATH = "/data/local/tmp/image/test_remove_exif.dng";
static const std::string IMAGE_REMOVE_HW_EXIF_PATH = "/data/local/tmp/image/test_remove_hw_exif.jpg";
static const std::string IMAGE_REMOVE_NO_EXIF_JPEG_PATH = "/data/local/tmp/image/test_remove_no_exif.jpg";
static const  std::string DEFAULT_EXIF_VALUE = "default_exif_value";

static const std::vector<std::string> hwExifReadKey = {
    "HwMnoteIsXmageSupported",
    "HwMnoteXmageMode",
    "HwMnoteXmageLeft",
    "HwMnoteXmageTop",
    "HwMnoteXmageRight",
    "HwMnoteXmageBottom",
    "HwMnoteCloudEnhancementMode",
    "HwMnoteWindSnapshotMode",
};

static const std::vector<std::string> hwExifWriteKey = {
    "HwMnoteIsXmageSupported",
    "HwMnoteXmageMode",
    "HwMnoteXmageLeft",
    "HwMnoteXmageTop",
    "HwMnoteXmageRight",
    "HwMnoteXmageBottom",
    "HwMnoteCloudEnhancementMode",
};

static const std::vector<std::string> jpgValues = {
    "1",
    "0",
    "0",
    "0",
    "0",
    "0",
    "default_exif_value",
    "default_exif_value",
};

static const std::vector<std::string> modifyValues = {
    "1",
    "10",
    "11",
    "259",
    "12",
    "999",
    "100",
};

static const std::vector<std::string> XMAGE_COORDINATE_KEYS = {
    "HwMnoteXmageLeft",
    "HwMnoteXmageTop",
    "HwMnoteXmageRight",
    "HwMnoteXmageBottom",
    "ImageWidth",
    "ImageLength",
};

static const std::vector<std::string> VALID_COORDINATE_VALUES = {
    "100",    // left
    "200",    // top
    "500",    // right
    "300",    // bottom
    "600",    // ImageWidth
    "700",    // ImageLength
};

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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);
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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);
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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);
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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);
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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);

    uint32_t index = 0;
    int32_t value = 0;
    std::string strValue;

    std::string key = "Orientation";
    imageSource->ModifyImageProperty(index, key, "1", fd);
    imageSource->GetImagePropertyString(index, key, strValue);
    ASSERT_EQ(strValue, "Top-left");
    imageSource->GetImagePropertyInt(index, key, value);

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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);

    uint32_t index = 0;
    int32_t value = 0;
    std::string strValue;

    uint32_t ret = imageSource->GetImagePropertyInt(index, "DelayTime", value);
    ASSERT_NE(ret, SUCCESS);

    ret = imageSource->GetImagePropertyInt(index, "DisposalType", value);
    ASSERT_NE(ret, SUCCESS);

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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);
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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);
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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);
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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);

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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);
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
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);
    std::set<std::string> keys = {"DateTimeOriginal", "ExposureTime", "SceneType"};
    errorCode = imageSource->RemoveImageProperties(0, keys, path);
    ASSERT_EQ(errorCode, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: RemoveImageProperty006 end";
}

HWTEST_F(ImageSourceExifTest, HwXmageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: HwXmageTest001 start";

    uint32_t errorCode = 0;
    std::string path = IMAGE_REMOVE_EXIF_JPEG_PATH;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);

    std::string value = "";
    for (int i = 0; i < hwExifReadKey.size(); ++i) {
        errorCode = imageSource->GetImagePropertyString(0, hwExifReadKey[i], value);
        ASSERT_EQ(value, jpgValues[i]);
    }

    ASSERT_EQ(hwExifWriteKey.size(), modifyValues.size());
    for (int i = 0; i < hwExifWriteKey.size(); ++i) {
        errorCode = imageSource->ModifyImageProperty(0, hwExifWriteKey[i], modifyValues[i]);
        ASSERT_EQ(errorCode, SUCCESS);
    }

    for (int i = 0; i < hwExifWriteKey.size(); ++i) {
        errorCode = imageSource->GetImagePropertyString(0, hwExifWriteKey[i], value);
        ASSERT_EQ(value, modifyValues[i]);
    }
    GTEST_LOG_(INFO) << "ImageSourceExifTest: HwXmageTest001 end";
}

HWTEST_F(ImageSourceExifTest, HwXmageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: HwXmageTest002 start";

    uint32_t errorCode = 0;
    std::string path = IMAGE_REMOVE_EXIF_PNG_PATH;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);

    std::string value = "";
    for (auto key : hwExifReadKey) {
        errorCode = imageSource->GetImagePropertyString(0, key, value);
        ASSERT_EQ(value, DEFAULT_EXIF_VALUE);
    }

    for (int i = 0; i < hwExifWriteKey.size(); ++i) {
        errorCode = imageSource->ModifyImageProperty(0, hwExifWriteKey[i], modifyValues[i]);
        ASSERT_EQ(errorCode, SUCCESS);
    }

    for (int i = 0; i < hwExifWriteKey.size(); ++i) {
        errorCode = imageSource->GetImagePropertyString(0, hwExifWriteKey[i], value);
        ASSERT_EQ(value, modifyValues[i]);
    }
    GTEST_LOG_(INFO) << "ImageSourceExifTest: HwXmageTest002 end";
}

HWTEST_F(ImageSourceExifTest, HwXmageTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: HwXmageTest003 start";

    uint32_t errorCode = 0;
    std::string path = IMAGE_REMOVE_EXIF_WEBP_PATH;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);

    std::string value = "";
    for (auto key : hwExifReadKey) {
        errorCode = imageSource->GetImagePropertyString(0, key, value);
        ASSERT_EQ(value, DEFAULT_EXIF_VALUE);
    }

    ASSERT_EQ(hwExifWriteKey.size(), modifyValues.size());
    for (int i = 0; i < hwExifWriteKey.size(); ++i) {
        errorCode = imageSource->ModifyImageProperty(0, hwExifWriteKey[i], modifyValues[i]);
        ASSERT_EQ(errorCode, SUCCESS);
    }

    for (int i = 0; i < hwExifWriteKey.size(); ++i) {
        errorCode = imageSource->GetImagePropertyString(0, hwExifWriteKey[i], value);
        ASSERT_EQ(value, modifyValues[i]);
    }
    GTEST_LOG_(INFO) << "ImageSourceExifTest: HwXmageTest003 end";
}

HWTEST_F(ImageSourceExifTest, HwXmageTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: HwXmageTest004 start";

    uint32_t errorCode = 0;
    std::string path = IMAGE_REMOVE_EXIF_HEIF_PATH;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);

    std::string value = "";
    for (auto key : hwExifReadKey) {
        errorCode = imageSource->GetImagePropertyString(0, key, value);
        ASSERT_EQ(value, DEFAULT_EXIF_VALUE);
    }

    ASSERT_EQ(hwExifWriteKey.size(), modifyValues.size());
    for (int i = 0; i < hwExifWriteKey.size(); ++i) {
        errorCode = imageSource->ModifyImageProperty(0, hwExifWriteKey[i], modifyValues[i]);
        ASSERT_EQ(errorCode, SUCCESS);
    }

    for (int i = 0; i < hwExifWriteKey.size(); ++i) {
        errorCode = imageSource->GetImagePropertyString(0, hwExifWriteKey[i], value);
        ASSERT_EQ(value, modifyValues[i]);
    }
    GTEST_LOG_(INFO) << "ImageSourceExifTest: HwXmageTest004 end";
}

HWTEST_F(ImageSourceExifTest, HwXmageTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: HwXmageTest005 start";

    uint32_t errorCode = 0;
    std::string path = IMAGE_REMOVE_EXIF_DNG_PATH;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(imageSource->GetiTxtLength(), 0);

    std::string value = "";
    for (int i = 0; i < hwExifReadKey.size()-1; ++i) {
        errorCode = imageSource->GetImagePropertyString(0, hwExifReadKey[i], value);
        ASSERT_EQ(value, DEFAULT_EXIF_VALUE);
    }
    errorCode = imageSource->GetImagePropertyString(0, hwExifReadKey[hwExifReadKey.size()-1], value);
    ASSERT_EQ(value, "8");
    GTEST_LOG_(INFO) << "ImageSourceExifTest: HwXmageTest005 end";
}

/**
 • @tc.name: ExtractXMageCoordinatesTest001
 • @tc.desc: Test the ExtractXMageCoordinates function with valid XMAGE coordinate values
 •           to ensure coordinates are successfully extracted and parsed.
 • @tc.type: FUNC
 */
HWTEST_F(ImageSourceExifTest, ExtractXMageCoordinatesTest001, TestSize.Level3)
{
    std::shared_ptr<ExifMetadata> metadata = std::make_shared<ExifMetadata>();
    ASSERT_NE(metadata, nullptr);
    ASSERT_TRUE(metadata->CreateExifdata());
    
    for (size_t i = 0; i < XMAGE_COORDINATE_KEYS.size(); ++i) {
        ASSERT_TRUE(metadata->SetValue(XMAGE_COORDINATE_KEYS[i], VALID_COORDINATE_VALUES[i]));
    }
    XmageCoordinateMetadata coordMetadata;
    bool result = metadata->ExtractXmageCoordinates(coordMetadata);
    
    ASSERT_TRUE(result);
    ASSERT_EQ(coordMetadata.left, 100);
    ASSERT_EQ(coordMetadata.top, 200);
    ASSERT_EQ(coordMetadata.right, 500);
    ASSERT_EQ(coordMetadata.bottom, 300);
    ASSERT_EQ(coordMetadata.ImageWidth, 600);
    ASSERT_EQ(coordMetadata.ImageLength, 700);
}
/**
 • @tc.name: ExtractXMageCoordinatesTest002
 • @tc.desc: Test the GetValue function for XMAGE coordinates when no custom values are set,
 •           verifying that the system returns the expected default values successfully.
 • @tc.type: FUNC
 */
HWTEST_F(ImageSourceExifTest, ExtractXMageCoordinatesTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest002 start";

    std::shared_ptr<ExifMetadata> metadata = std::make_shared<ExifMetadata>();
    ASSERT_NE(metadata, nullptr);
    ASSERT_TRUE(metadata->CreateExifdata());
    
    std::string leftValue, topValue, rightValue, bottomValue;
    
    int ret = metadata->GetValue("HwMnoteXmageLeft", leftValue);
    ASSERT_EQ(ret, SUCCESS);
    ASSERT_EQ(leftValue, DEFAULT_EXIF_VALUE);
    
    ret = metadata->GetValue("HwMnoteXmageTop", topValue);
    ASSERT_EQ(ret, SUCCESS);
    ASSERT_EQ(topValue, DEFAULT_EXIF_VALUE);
    
    ret = metadata->GetValue("HwMnoteXmageRight", rightValue);
    ASSERT_EQ(ret, SUCCESS);
    ASSERT_EQ(rightValue, DEFAULT_EXIF_VALUE);
    
    ret = metadata->GetValue("HwMnoteXmageBottom", bottomValue);
    ASSERT_EQ(ret, SUCCESS);
    ASSERT_EQ(bottomValue, DEFAULT_EXIF_VALUE);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest002 end";
}
/**
 • @tc.name: ExtractXMageCoordinatesTest003
 • @tc.desc: Test ExtractXMageCoordinates when all XMAGE coordinate values are default values.
 • @tc.type: FUNC
 */
HWTEST_F(ImageSourceExifTest, ExtractXMageCoordinatesTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest003 start";

    std::shared_ptr<ExifMetadata> metadata = std::make_shared<ExifMetadata>();
    ASSERT_NE(metadata, nullptr);
    ASSERT_TRUE(metadata->CreateExifdata());
    for (const auto& key : XMAGE_COORDINATE_KEYS) {
        int ret = metadata->SetValue(key, DEFAULT_EXIF_VALUE);
        ASSERT_EQ(ret, SUCCESS) << "Failed to set default value for key: " << key;
    }
    XmageCoordinateMetadata coordMetadata;
    bool result = metadata->ExtractXmageCoordinates(coordMetadata);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest003 end";
}

/**
 • @tc.name: ExtractXMageCoordinatesTest004
 • @tc.desc: Test ExtractXMageCoordinates when three XMAGE coordinate values are not set and one is valid.
 • @tc.type: FUNC

 */
HWTEST_F(ImageSourceExifTest, ExtractXMageCoordinatesTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest004 start";

    std::shared_ptr<ExifMetadata> metadata = std::make_shared<ExifMetadata>();
    ASSERT_NE(metadata, nullptr);
    ASSERT_TRUE(metadata->CreateExifdata());
    
    for (const auto& key : XMAGE_COORDINATE_KEYS) {
        int ret = metadata->SetValue(key, DEFAULT_EXIF_VALUE);
        ASSERT_EQ(ret, SUCCESS) << "Failed to set default value for key: " << key;
    }
    
    ASSERT_TRUE(metadata->SetValue(XMAGE_COORDINATE_KEYS[0], VALID_COORDINATE_VALUES[0]));
    
    XmageCoordinateMetadata coordMetadata;
    bool result = metadata->ExtractXmageCoordinates(coordMetadata);

    ASSERT_FALSE(result);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest004 end";
}

/**
 • @tc.name: ExtractXMageCoordinatesTest005
 • @tc.desc: Test ExtractXMageCoordinates when two XMAGE coordinate values are not set and two are valid.
 • @tc.type: FUNC
 */
HWTEST_F(ImageSourceExifTest, ExtractXMageCoordinatesTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest005 start";

    std::shared_ptr<ExifMetadata> metadata = std::make_shared<ExifMetadata>();
    ASSERT_NE(metadata, nullptr);
    ASSERT_TRUE(metadata->CreateExifdata());
    
    ASSERT_TRUE(metadata->SetValue(XMAGE_COORDINATE_KEYS[0], VALID_COORDINATE_VALUES[0]));
    ASSERT_TRUE(metadata->SetValue(XMAGE_COORDINATE_KEYS[1], VALID_COORDINATE_VALUES[1]));
    
    XmageCoordinateMetadata coordMetadata;
    bool result = metadata->ExtractXmageCoordinates(coordMetadata);
    
    ASSERT_FALSE(result);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest005 end";
}

/**
 • @tc.name: ExtractXMageCoordinatesTest006
 • @tc.desc: Test ExtractXMageCoordinates when one XMAGE coordinate value is not set and three are valid.
 • @tc.type: FUNC
 */
HWTEST_F(ImageSourceExifTest, ExtractXMageCoordinatesTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest006 start";

    std::shared_ptr<ExifMetadata> metadata = std::make_shared<ExifMetadata>();
    ASSERT_NE(metadata, nullptr);
    ASSERT_TRUE(metadata->CreateExifdata());
    
    ASSERT_TRUE(metadata->SetValue(XMAGE_COORDINATE_KEYS[0], VALID_COORDINATE_VALUES[0]));
    ASSERT_TRUE(metadata->SetValue(XMAGE_COORDINATE_KEYS[1], VALID_COORDINATE_VALUES[1]));
    ASSERT_TRUE(metadata->SetValue(XMAGE_COORDINATE_KEYS[2], VALID_COORDINATE_VALUES[2]));

    XmageCoordinateMetadata coordMetadata;
    bool result = metadata->ExtractXmageCoordinates(coordMetadata);
    
    ASSERT_FALSE(result);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest006 end";
}

/**
 • @tc.name: ExtractXMageCoordinatesTest007
 • @tc.desc: Test ExtractXMageCoordinates when no XMAGE coordinate values are set (all should be default).
 • @tc.type: FUNC
 */
HWTEST_F(ImageSourceExifTest, ExtractXMageCoordinatesTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest007 start";

    std::shared_ptr<ExifMetadata> metadata = std::make_shared<ExifMetadata>();
    ASSERT_NE(metadata, nullptr);
    ASSERT_TRUE(metadata->CreateExifdata());
    
    XmageCoordinateMetadata coordMetadata;
    bool result = metadata->ExtractXmageCoordinates(coordMetadata);
    ASSERT_FALSE(result);

    GTEST_LOG_(INFO) << "ImageSourceExifTest: ExtractXMageCoordinatesTest007 end";
}
} // namespace Multimedia
} // namespace OHOS
