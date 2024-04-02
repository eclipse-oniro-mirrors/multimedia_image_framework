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

#include <gtest/gtest.h>
#include <fstream>
#include <fcntl.h>
#include "directory_ex.h"
#include "image_log.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "incremental_pixel_map.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "image_receiver.h"
#include "image_source_util.h"
#include "file_source_stream.h"
#include "graphic_common.h"
#include "image_receiver_manager.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSourceJpegTest"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
static constexpr uint32_t DEFAULT_DELAY_UTIME = 10000;  // 10 ms.
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_INPUT_HW_JPEG_PATH = "/data/local/tmp/image/test_hw.jpg";
static const std::string IMAGE_INPUT_EXIF_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";
static const std::string IMAGE_OUTPUT_JPEG_FILE_PATH = "/data/test/test_file.jpg";
static const std::string IMAGE_OUTPUT_JPEG_BUFFER_PATH = "/data/test/test_buffer.jpg";
static const std::string IMAGE_OUTPUT_JPEG_ISTREAM_PATH = "/data/test/test_istream.jpg";
static const std::string IMAGE_OUTPUT_JPEG_INC_PATH = "/data/test/test_inc.jpg";
static const std::string IMAGE_OUTPUT_HW_JPEG_FILE_PATH = "/data/test/test_hw_file.jpg";
static const std::string IMAGE_OUTPUT_JPEG_MULTI_FILE1_PATH = "/data/test/test_file1.jpg";
static const std::string IMAGE_OUTPUT_JPEG_MULTI_FILE2_PATH = "/data/test/test_file2.jpg";
static const std::string IMAGE_OUTPUT_JPEG_MULTI_INC1_PATH = "/data/test/test_inc1.jpg";
static const std::string IMAGE_OUTPUT_JPEG_MULTI_ONETIME1_PATH = "/data/test/test_onetime1.jpg";
static const std::string IMAGE_OUTPUT_JPEG_MULTI_INC2_PATH = "/data/test/test_inc2.jpg";
static const std::string IMAGE_OUTPUT_JPEG_MULTI_ONETIME2_PATH = "/data/test/test_onetime2.jpg";
static const std::string IMAGE_HW_EXIF_PATH = "/data/local/tmp/image/test_jpeg_readmetadata004.jpg";
static const std::string IMAGE_NO_EXIF_PATH = "/data/local/tmp/image/hasNoExif.jpg";

const std::string ORIENTATION = "Orientation";
const std::string IMAGE_HEIGHT = "ImageHeight";
const std::string IMAGE_WIDTH = "ImageWidth";
const std::string GPS_LATITUDE = "GPSLatitude";
const std::string GPS_LONGITUDE = "GPSLongitude";
const std::string GPS_LATITUDE_REF = "GPSLatitudeRef";
const std::string GPS_LONGITUDE_REF = "GPSLongitudeRef";

static constexpr size_t FILE_SIZE = 10;
static constexpr size_t SIZE_T = 0;

class ImageSourceJpegTest : public testing::Test {
public:
    ImageSourceJpegTest() {}
    ~ImageSourceJpegTest() {}
};

static void CreateImageSourceFromFilePath(std::unique_ptr<ImageSource>& imageSource)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    imageSource.reset(ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode).release());
    ASSERT_EQ(errorCode, 0);
    ASSERT_NE(imageSource.get(), nullptr);
}

static void CreateImageSourceFromHWPath(std::unique_ptr<ImageSource>& imageSource)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    imageSource.reset(ImageSource::CreateImageSource(IMAGE_HW_EXIF_PATH, opts, errorCode).release());
    ASSERT_EQ(errorCode, 0);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: TC028
 * @tc.desc: Create ImageSource(stream)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC028, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg stream and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: TC029
 * @tc.desc: Create ImageSource(path)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC029, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HW_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: TC030
 * @tc.desc: Create ImageSource(data)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC030, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, bufferSize, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: TC032
 * @tc.desc: Test GetImageInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC032, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    ImageInfo imageInfo;
    uint32_t index = 0;
    uint32_t ret = imageSource->GetImageInfo(index, imageInfo);
    ASSERT_EQ(ret, SUCCESS);
    ret = imageSource->GetImageInfo(imageInfo);
    ASSERT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: TC033
 * @tc.desc: Test GetImagePropertyInt(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC033, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    int32_t value = 0;
    std::string key;
    imageSource->GetImagePropertyInt(index, key, value);
}

/**
 * @tc.name: TC035
 * @tc.desc: Test CreatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC035, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;

    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
}

/**
 * @tc.name: TC036
 * @tc.desc: Test Area decoding,configure area
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC036, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create jpg image source by istream source stream and default format hit
     * @tc.expected: step1. create jpg image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. crop jpg image source to pixel map crop options
     * @tc.expected: step2. crop jpg image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(200, pixelMap->GetWidth());
    EXPECT_EQ(400, pixelMap->GetHeight());
}

/**
 * @tc.name: TC037
 * @tc.desc: Test CreatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC037, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    IncrementalSourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: TC038
 * @tc.desc: Test jpeg decode
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC038, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
}

/**
 * @tc.name: TC055
 * @tc.desc: Test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC055, TestSize.Level3)
{
GTEST_LOG_(INFO) << "ImageSourceJpegTest: TC055 start";
/**
     * @tc.steps: step1. create image source by buffer source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, bufferSize, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);

    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    decodeOpts.CropRect = { imageInfo.size.width - 1, imageInfo.size.height - 1, 1, 1 };
    std::unique_ptr<PixelMap> cropPixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(cropPixelMap, nullptr);
    ASSERT_NE(cropPixelMap.get(), nullptr);
    cropPixelMap->GetImageInfo(imageInfo);
    ASSERT_EQ(imageInfo.size.width, 1);
    ASSERT_EQ(imageInfo.size.height, 1);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    ImagePacker imagePacker;
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_BUFFER_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
    free(buffer);

    GTEST_LOG_(INFO) << "ImageSourceJpegTest: TC055 end";
}

/**
 * @tc.name: TC056
 * @tc.desc: Test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC056, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: TC056 start";
/**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get support decode image format.
     * @tc.expected: step2. get support format info success.
     */
    std::set<string> formats;
    uint32_t ret = imageSource->GetSupportedFormats(formats);
    ASSERT_EQ(ret, SUCCESS);
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    /**
     * @tc.steps: step4. get image source information.
     * @tc.expected: step4. get image source information success and source state is parsed.
     */
    SourceInfo sourceInfo = imageSource->GetSourceInfo(errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(sourceInfo.state, SourceInfoState::FILE_INFO_PARSED);
    /**
     * @tc.steps: step5. compress the pixel map to jpeg file.
     * @tc.expected: step5. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: TC056 end";
}

/**
 * @tc.name: TC057
 * @tc.desc: Test StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC057, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: TC057 start";
   /**
     * @tc.steps: step1. create image source by istream source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_INPUT_JPEG_PATH, std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_ISTREAM_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);

    GTEST_LOG_(INFO) << "ImageSourceJpegTest: TC057 end";
}

/**
 * @tc.name: TC059
 * @tc.desc: Test AddImage ImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC059, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: TC059 start";
    /**
     * @tc.steps: step1. create iamgesource
     * @tc.expected: step1. create iamgesource success
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ImagePacker imagePacker;
    imagePacker.AddImage(*imageSource);
    ASSERT_NE(pixelMap.get(), nullptr);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: TC059 end";
}

/**
 * @tc.name: TC061
 * @tc.desc: Test GetSupportedFormats
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, TC061, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: TC061 start";
    /**
     * @tc.steps: step1.GetSupportedFormats(formats)
     * @tc.expected: step1. GetSupportedFormats(formats) success
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    std::set<std::string> formats;
    uint32_t ret = imageSource->GetSupportedFormats(formats);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: TC061 end";
}

/**
 * @tc.name: JpegImageDecode001
 * @tc.desc: Decode jpeg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get support decode image format.
     * @tc.expected: step2. get support format info success.
     */
    std::set<string> formats;
    uint32_t ret = imageSource->GetSupportedFormats(formats);
    ASSERT_EQ(ret, SUCCESS);
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    ASSERT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    /**
     * @tc.steps: step4. get image source information.
     * @tc.expected: step4. get image source information success and source state is parsed.
     */
    SourceInfo sourceInfo = imageSource->GetSourceInfo(errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(sourceInfo.state, SourceInfoState::FILE_INFO_PARSED);
    /**
     * @tc.steps: step5. compress the pixel map to jpeg file.
     * @tc.expected: step5. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: JpegImageDecode002
 * @tc.desc: Create image source by correct jpeg file path and wrong format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and default format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get image info from input image.
     * @tc.expected: step2. get image info success.
     */
    ImageInfo imageInfo;
    uint32_t ret = imageSource->GetImageInfo(0, imageInfo);
    ASSERT_EQ(ret, SUCCESS);
    ret = imageSource->GetImageInfo(imageInfo);
    ASSERT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: JpegImageDecode003
 * @tc.desc: Create image source by correct jpeg file path and wrong format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and wrong format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
}

/**
 * @tc.name: JpegImageDecode004
 * @tc.desc: Create image source by wrong jpeg file path and default format hit.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode004, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by wrong jpeg file path and default format hit.
     * @tc.expected: step1. create image source error.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource("/data/jpeg/test.jpg", opts, errorCode);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    ASSERT_EQ(imageSource.get(), nullptr);
}

/**
 * @tc.name: JpegImageDecode005
 * @tc.desc: Decode jpeg image from buffer source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode005, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by buffer source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    ret = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(ret, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(buffer, bufferSize, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    decodeOpts.CropRect = { imageInfo.size.width - 1, imageInfo.size.height - 1, 1, 1 };
    std::unique_ptr<PixelMap> cropPixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    cropPixelMap->GetImageInfo(imageInfo);
    ASSERT_EQ(imageInfo.size.width, 1);
    ASSERT_EQ(imageInfo.size.height, 1);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    ImagePacker imagePacker;
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_BUFFER_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
    free(buffer);
}

/**
 * @tc.name: JpegImageDecode006
 * @tc.desc: Decode jpeg image from istream source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode006, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by istream source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open(IMAGE_INPUT_JPEG_PATH, std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_ISTREAM_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: JpegImageDecode007
 * @tc.desc: Decode jpeg image from incremental source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode007, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by incremental source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool fileRet = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(fileRet, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    fileRet = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(fileRet, true);
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. update incremental stream every 10 ms with random data size and promote decode
     * image to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(0, decodeOpts,
        errorCode);
    ASSERT_NE(incPixelMap, nullptr);
    uint32_t updateSize = 0;
    srand(time(nullptr));
    bool isCompleted = false;
    while (updateSize < bufferSize) {
        uint32_t updateOnceSize = rand() % 1024;
        if (updateSize + updateOnceSize > bufferSize) {
            updateOnceSize = bufferSize - updateSize;
            isCompleted = true;
        }
        uint32_t ret = imageSource->UpdateData(buffer + updateSize, updateOnceSize, isCompleted);
        ASSERT_EQ(ret, SUCCESS);
        uint8_t decodeProgress = 0;
        incPixelMap->PromoteDecoding(decodeProgress);
        updateSize += updateOnceSize;
        usleep(DEFAULT_DELAY_UTIME);
    }
    incPixelMap->DetachFromDecoding();
    IncrementalDecodingStatus status = incPixelMap->GetDecodingStatus();
    ASSERT_EQ(status.decodingProgress, 100);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_INC_PATH, std::move(incPixelMap));
    ASSERT_NE(packSize, 0);
    free(buffer);
}

/**
 * @tc.name: JpegImageDecode008
 * @tc.desc: Decode jpeg image multiple times from one ImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode008, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by jpeg file path.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options.
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap1 = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap1, nullptr);
    ASSERT_NE(pixelMap1.get(), nullptr);
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options again.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    std::unique_ptr<PixelMap> pixelMap2 = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap2, nullptr);
    ASSERT_NE(pixelMap2.get(), nullptr);
    /**
     * @tc.steps: step4. compress the pixel map to jpeg file.
     * @tc.expected: step4. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_MULTI_FILE1_PATH, std::move(pixelMap1));
    ASSERT_NE(packSize, 0);
    packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_MULTI_FILE2_PATH, std::move(pixelMap2));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: JpegImageDecode009
 * @tc.desc: Decode jpeg image by incremental mode and then decode again by one-time mode.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode009, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by incremental source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool fileRet = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(fileRet, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    fileRet = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(fileRet, true);
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. update incremental stream every 10 ms with random data size and promote decode
     * image to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(0, decodeOpts,
        errorCode);
    ASSERT_NE(incPixelMap, nullptr);
    uint32_t updateSize = 0;
    srand(time(nullptr));
    bool isCompleted = false;
    while (updateSize < bufferSize) {
        uint32_t updateOnceSize = rand() % 1024;
        if (updateSize + updateOnceSize > bufferSize) {
            updateOnceSize = bufferSize - updateSize;
            isCompleted = true;
        }
        uint32_t ret = imageSource->UpdateData(buffer + updateSize, updateOnceSize, isCompleted);
        ASSERT_EQ(ret, SUCCESS);
        uint8_t decodeProgress = 0;
        incPixelMap->PromoteDecoding(decodeProgress);
        updateSize += updateOnceSize;
        usleep(DEFAULT_DELAY_UTIME);
    }
    incPixelMap->DetachFromDecoding();
    IncrementalDecodingStatus status = incPixelMap->GetDecodingStatus();
    ASSERT_EQ(status.decodingProgress, 100);
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options again.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    std::unique_ptr<PixelMap> pixelMap1 = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap1, nullptr);
    ASSERT_NE(pixelMap1.get(), nullptr);
    /**
     * @tc.steps: step4. compress the pixel map to jpeg file.
     * @tc.expected: step4. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_MULTI_INC1_PATH, std::move(incPixelMap));
    ASSERT_NE(packSize, 0);
    packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_MULTI_ONETIME1_PATH, std::move(pixelMap1));
    ASSERT_NE(packSize, 0);
    free(buffer);
}

/**
 * @tc.name: JpegImageDecode010
 * @tc.desc: Decode jpeg image by one-time mode and then decode again by incremental mode.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode010, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by incremental source stream and default format hit
     * @tc.expected: step1. create image source success.
     */
    size_t bufferSize = 0;
    bool fileRet = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(fileRet, true);
    uint8_t *buffer = static_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    fileRet = OHOS::ImageSourceUtil::ReadFileToBuffer(IMAGE_INPUT_JPEG_PATH, buffer, bufferSize);
    ASSERT_EQ(fileRet, true);
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. update incremental stream every 10 ms with random data size.
     * @tc.expected: step2. update success.
     */
    uint32_t updateSize = 0;
    srand(time(nullptr));
    bool isCompleted = false;
    while (updateSize < bufferSize) {
        uint32_t updateOnceSize = rand() % 1024;
        if (updateSize + updateOnceSize > bufferSize) {
            updateOnceSize = bufferSize - updateSize;
            isCompleted = true;
        }
        uint32_t ret = imageSource->UpdateData(buffer + updateSize, updateOnceSize, isCompleted);
        ASSERT_EQ(ret, SUCCESS);
        updateSize += updateOnceSize;
        usleep(DEFAULT_DELAY_UTIME);
    }

    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap1 = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap1, nullptr);
    ASSERT_NE(pixelMap1.get(), nullptr);

    /**
     * @tc.steps: step4. decode image source to pixel map by incremental mode again.
     * @tc.expected: step4. decode image source to pixel map success.
     */
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(0, decodeOpts,
        errorCode);
    ASSERT_NE(incPixelMap, nullptr);
    uint8_t decodeProgress = 0;
    incPixelMap->PromoteDecoding(decodeProgress);
    incPixelMap->DetachFromDecoding();
    IncrementalDecodingStatus status = incPixelMap->GetDecodingStatus();
    ASSERT_EQ(status.decodingProgress, 100);
    /**
     * @tc.steps: step4. compress the pixel map to jpeg file.
     * @tc.expected: step4. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_MULTI_INC2_PATH, std::move(incPixelMap));
    ASSERT_NE(packSize, 0);
    packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_JPEG_MULTI_ONETIME2_PATH, std::move(pixelMap1));
    ASSERT_NE(packSize, 0);
    free(buffer);
}

/**
 * @tc.name: JpegImageDecode011
 * @tc.desc: PixelMap to tlv test
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageDecode011, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create new image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create new image source success.
     */
    uint32_t status = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HW_JPEG_PATH, opts, status);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    /**
     * @tc.steps: step2. decode created image source to pixel map by default decode options
     * @tc.expected: step2. decode created image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, status);
    IMAGE_LOGD("create pixel map ret=%{public}u.", status);
    ASSERT_EQ(status, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    /**
     * @tc.steps: step3. encode the pixel map to buffer.
     * @tc.expected: step3. encode the pixel map to buffer success.
     */
    std::vector<uint8_t> buff;
    bool res = pixelMap->EncodeTlv(buff);
    ASSERT_EQ(res, true);

    /**
     * @tc.steps: step4. decode the pixel map from buffer.
     * @tc.expected: step4. decode success and pack pixel map success and the jpeg compress file size not equals to 0.
     */
    PixelMap *pixelMap2 = PixelMap::DecodeTlv(buff);
    std::unique_ptr<PixelMap> p(pixelMap2);
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HW_JPEG_FILE_PATH, std::move(p));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: JpgImageCrop001
 * @tc.desc: Crop jpg image from istream source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpgImageCrop001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create jpg image source by istream source stream and default format hit
     * @tc.expected: step1. create jpg image source success.
     */
    std::unique_ptr<std::fstream> fs = std::make_unique<std::fstream>();
    fs->open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    bool isOpen = fs->is_open();
    ASSERT_EQ(isOpen, true);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(std::move(fs), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. crop jpg image source to pixel map crop options
     * @tc.expected: step2. crop jpg image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    decodeOpts.CropRect.top = 3;
    decodeOpts.CropRect.width = 100;
    decodeOpts.CropRect.left = 3;
    decodeOpts.CropRect.height = 200;
    decodeOpts.desiredSize.width = 200;
    decodeOpts.desiredSize.height = 400;
    decodeOpts.rotateDegrees = 90;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map error code=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(200, pixelMap->GetWidth());
    EXPECT_EQ(400, pixelMap->GetHeight());
}

/**
 * @tc.name: JpegImageHwDecode001
 * @tc.desc: Hardware decode jpeg image from file source stream
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, JpegImageHwDecode001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HW_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    IMAGE_LOGD("create pixel map ret=%{public}u.", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. compress the pixel map to jpeg file.
     * @tc.expected: step3. pack pixel map success and the jpeg compress file size equals to JPEG_PACK_SIZE.
     */
    int64_t packSize = OHOS::ImageSourceUtil::PackImage(IMAGE_OUTPUT_HW_JPEG_FILE_PATH, std::move(pixelMap));
    ASSERT_NE(packSize, 0);
}

/**
 * @tc.name: GetImagePropertyIntTest001
 * @tc.desc: Test GetImagePropertyInt(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyIntTest001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyIntTest001 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    int32_t value = 0;
    std::string key = "BitsPerSample";
    uint32_t res = imageSource->GetImagePropertyInt(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyIntTest001 end";
}

/**
 * @tc.name: GetImagePropertyIntTest002
 * @tc.desc: Test GetImagePropertyInt(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyIntTest002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyIntTest002 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    int32_t value = 0;
    std::string key = "Orientation";
    uint32_t res = imageSource->GetImagePropertyInt(index, key, value);
    ASSERT_EQ(res, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyIntTest002 end";
}

/**
 * @tc.name: GetImagePropertyStringTest001
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest001 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "";
    std::string key = "Aaaab";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest001 end";
}

/**
 * @tc.name: GetImagePropertyStringTest002
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest002 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "";
    std::string key = "ImageLength";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest002 end";
}

/**
 * @tc.name: GetImagePropertyStringTest003
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest003 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "";
    std::string key = "ISOSpeedRatings";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest003 end";
}

/**
 * @tc.name: GetImagePropertyStringTest004
 * @tc.desc: Test GetImagePropertyInt(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest004, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest004 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "";
    std::string key = "Orientation";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest004 end";
}

/**
 * @tc.name: GetImagePropertyStringTest005
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest005, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest005 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "";
    std::string key = "GPSLatitude";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest005 end";
}

/**
 * @tc.name: GetImagePropertyStringTest006
 * @tc.desc: Test GetImagePropertyv(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest006, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest006 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "GPSLatitudeRef";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest006 end";
}

/**
 * @tc.name: GetImagePropertyStringTest007
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest007, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest007 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "GPSLongitudeRef";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest007 end";
}

/**
 * @tc.name: GetImagePropertyStringTest008
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest008, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest008 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "DateTimeOriginal";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest008 end";
}

/**
 * @tc.name: GetImagePropertyStringTest009
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest009, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest009 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "ExposureTime";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest009 end";
}


/**
 * @tc.name: GetImagePropertyStringTest010
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest010, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest010 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "SceneType";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest010 end";
}

/**
 * @tc.name: GetImagePropertyStringTest011
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest011, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest011 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "ISOSpeedRatings";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest011 end";
}

/**
 * @tc.name: GetImagePropertyStringTest012
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest012, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest012 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "FNumber";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest012 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0013
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0013, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0013 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "BitsPerSample";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0013 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0014
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0014, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0014 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "ImageWidth";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0013 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0015
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0015, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0015 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "GPSLongitude";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0015 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0016
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0016, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0016 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "DateTime";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0016 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0017
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0017, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0017 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "11:37:56";
    std::string key = "GPSTimeStamp";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0017 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0018
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0018, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0018 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2023:12:01";
    std::string key = "GPSDateStamp";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0018 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0019
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0019, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0019 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "this is a test picture";
    std::string key = "ImageDescription";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0019 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0020
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0020, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0020 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "Make";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0020 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0021
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0021, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0021 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "Model";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0021 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0022
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0022, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0022 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "252";
    std::string key = "PhotoMode";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0022 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0023
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0023, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0023 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "SensitivityType";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0023 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0024
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0024, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0024 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "StandardOutputSensitivity";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0024 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0025
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0025, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0025 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "241";
    std::string key = "RecommendedExposureIndex";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0025 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0026
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0026, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0026 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "ApertureValue";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0026 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0027
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0027, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0027 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "ExposureBiasValue";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0027 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0028
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0028, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0028 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "MeteringMode";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0028 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0029
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0029, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0029 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "LightSource";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0029 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0030
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0030, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0030 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "Flash";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0030 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0031
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0031, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0031 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "FocalLength";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0031 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0032
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0032, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0032 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "UserComment";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0032 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0033
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0033, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0033 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "PixelXDimension";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0033 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0034
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0034, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0034 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "PixelYDimension";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0034 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0035
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0035, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0035 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "WhiteBalance";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0035 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0036
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0036, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0036 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "FocalLengthIn35mmFilm";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0036 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0037
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0037, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0037 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteCaptureMode";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0037 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0038
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0038, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0038 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnotePhysicalAperture";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0038 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0039
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0039, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0039 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteRollAngle";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0039 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0038
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0040, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0040 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnotePitchAngle";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0040 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0041
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0041, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0041 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteSceneFoodConf";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0041 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0042
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0042, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0042 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteSceneStageConf";
    auto res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0042 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0043
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0043, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0043 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteSceneBlueSkyConf";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0043 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0044
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0044, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0044 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteSceneGreenPlantConf";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0044 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0045
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0045, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0045 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteSceneBeachConf";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0045 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0046
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0046, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0046 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteSceneSnowConf";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0046 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0047
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0047, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0047 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteSceneSunsetConf";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0047 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0048
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0048, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0048 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteSceneFlowersConf";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0048 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0049
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0049, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0049 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteSceneNightConf";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0049 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0050
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0050, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0050 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteSceneTextConf";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0050 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0051
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0051, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0051 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteFaceCount";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0051 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0052
 * @tc.desc: Test GetImagePropertyString(index, key, value)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0052, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0052 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromHWPath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteFocusMode";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0052 end";
}

/**
 * @tc.name: GetImagePropertyStringTest0053
 * @tc.desc: image exif does not exist and get Hw* property, return success ,value is default_exif_value
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetImagePropertyStringTest0053, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0053 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_NO_EXIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "HwMnoteFocusMode";
    uint32_t res = imageSource->GetImagePropertyString(index, key, value);
    ASSERT_EQ(res, SUCCESS);
    ASSERT_EQ(value, "default_exif_value");
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetImagePropertyStringTest0053 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest001
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest001 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "9,9,8";
    std::string key = "BitsPerSample";
    std::string path = "";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, path);
    ASSERT_EQ(res, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest001 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest002
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest002 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "9,9,8";
    std::string key = "BitsPerSample";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest002 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest003
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest003 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "9, 9, 8";
    std::string key = "BitsPerSample";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest003 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest004
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest004, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest004 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "9 9 8";
    std::string key = "BitsPerSample";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest004 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest006
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest006, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest006 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "100";
    std::string key = "111";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_EXIF_JPEG_PATH);
    ASSERT_EQ(res, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest006 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest007
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest007, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest007 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2";
    std::string key = "Orientation";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest007 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest008
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest008, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest008 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2222";
    std::string key = "ImageLength";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest008 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest009
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest009, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest009 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2022:09:06 15:48:00";
    std::string key = "DateTimeOriginal";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest009 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0010
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0010, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0010 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2022:09:06 15:48:00";
    std::string key = "DateTimeOriginal";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0010 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0011
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0011, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0011 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2";
    std::string key = "SceneType";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0011 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0012
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0012, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0012 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "300";
    std::string key = "ISOSpeedRatings";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0012 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0013
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0013, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0013 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "1/2";
    std::string key = "FNumber";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0013 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0014
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0014, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0014 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2022:09:06 15:48:00";
    std::string key = "DateTime";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0014 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0015
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0015, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0015 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    // GPSTimeStamp is like "xx:xx:xx"
    std::string value = "11:37:56";
    std::string key = "GPSTimeStamp";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0015 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0016
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0016, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0016 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2023:10:23";
    std::string key = "GPSDateStamp";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0016 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0017
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0017, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0017 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "aaaa";
    std::string key = "ImageDescription";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0017 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0018
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0018, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0018 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "aaaa";
    std::string key = "ImageDescription";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0018 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0019
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0019, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0019 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "XIAOMI";
    std::string key = "Make";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0019 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0020
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0020, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0020 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "TNY-AL02";
    std::string key = "Model";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0020 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0021
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0021, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0021 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "TNY-AL02";
    std::string key = "Model";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0021 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0022
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0022, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0022 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2";
    std::string key = "SensitivityType";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0022 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0023
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0023, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0023 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2";
    std::string key = "StandardOutputSensitivity";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0023 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0024
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0024, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0024 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "3";
    std::string key = "ISOSpeedRatings";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0024 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0025
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0025, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0025 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "1/2";
    std::string key = "ApertureValue";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0025 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0026
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0026, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0026 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "1/2";
    std::string key = "ApertureValue";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0026 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0027
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0027, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0027 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "1/2";
    std::string key = "ExposureBiasValue";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0027 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0028
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0028, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0028 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2";
    std::string key = "MeteringMode";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0028 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0029
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0029, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0029 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "2";
    std::string key = "LightSource";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0029 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0030
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0030, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0030 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "31";
    std::string key = "Flash";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0030 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0031
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0031, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0031 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    std::string value = "1/2";
    std::string key = "FocalLength";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0031 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0032
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0032, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0032 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "aaaa";
    std::string key = "UserComment";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0032 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0033
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0033, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0033 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "3456";
    std::string key = "PixelXDimension";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0033 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0034
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0034, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0034 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "3456";
    std::string key = "PixelYDimension";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0034 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0035
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0035, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0035 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "1";
    std::string key = "WhiteBalance";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0035 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0036
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0036, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0036 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "35";
    std::string key = "FocalLengthIn35mmFilm";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0036 end";
}

/**
 * @tc.name: ModifyImagePropertyPathTest0037
 * @tc.desc: Test ModifyImageProperty width path
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyPathTest0037, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0037 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "300";
    std::string key = "RecommendedExposureIndex";
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, IMAGE_INPUT_JPEG_PATH);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyPathTest0037 end";
}

/**
 * @tc.name: ModifyImagePropertyFdTest001
 * @tc.desc: Test ModifyImageProperty width fd
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyFdTest001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyFdTest001 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "9, 9, 9";
    std::string key = "BitsPerSample";
    //要返回ERR_MEDIA_BUFFER_TOO_SMALL需要文件大小为空或者大小超过最大值，这里取空
    int fd = open("/data/local/tmp/image/test_1111.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, fd);
    ASSERT_EQ(res, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyFdTest001 end";
}

/**
 * @tc.name: ModifyImagePropertyFdTest002
 * @tc.desc: Test ModifyImageProperty width fd
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyFdTest002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyFdTest002 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "a";
    std::string key = "BitsPerSample";
    int fd = open("/data/local/tmp/image/test_exif.jpg", std::fstream::binary | std::fstream::in);
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, fd);
    ASSERT_EQ(res, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyFdTest002 end";
}

/**
 * @tc.name: ModifyImagePropertyFdTest003
 * @tc.desc: Test ModifyImageProperty width fd
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyFdTest003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyFdTest003 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "100";
    std::string key = "Width";
    int fd = open("/data/local/tmp/image/test_exif.jpg", std::fstream::binary | std::fstream::in);
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, fd);
    ASSERT_EQ(res, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyFdTest003 end";
}

/**
 * @tc.name: ModifyImagePropertyFdTest004
 * @tc.desc: Test ModifyImageProperty width fd
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyFdTest004, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyFdTest004 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "9, 7, 8";
    std::string key = "BitsPerSample";
    int fd = open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, fd);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyFdTest004 end";
}

/**
 * @tc.name: ModifyImagePropertyFdTest006
 * @tc.desc: Test ModifyImageProperty width fd
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyFdTest006, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyFdTest006 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "100";
    std::string key = "1111";
    int fd = open("/data/local/tmp/image/test.jpg", std::fstream::binary | std::fstream::in);
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, fd);
    ASSERT_EQ(res, ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyFdTest006 end";
}

/**
 * @tc.name: ModifyImagePropertyBufferTest001
 * @tc.desc: Test ModifyImageProperty width buffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyBufferTest001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest001 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "BitsPerSample";
    uint8_t *data = nullptr;
    uint32_t size = 0;
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, data, size);
    ASSERT_EQ(res, ERR_MEDIA_WRITE_PARCEL_FAIL);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest001 end";
}

/**
 * @tc.name: ModifyImagePropertyBufferTest002
 * @tc.desc: Test ModifyImageProperty width buffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyBufferTest002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest002 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "0";
    std::string key = "BitsPerSample";
    size_t size = 0;
    bool fileRet = ImageUtils::GetFileSize(IMAGE_INPUT_EXIF_JPEG_PATH, size);
    ASSERT_EQ(fileRet, true);
    uint8_t *data = reinterpret_cast<uint8_t *>(malloc(size));
    ASSERT_NE(data, nullptr);

    uint32_t res = imageSource->ModifyImageProperty(index, key, value, data, size);
    ASSERT_EQ(res, ERR_MEDIA_WRITE_PARCEL_FAIL);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest002 end";
}

/**
 * @tc.name: ModifyImagePropertyBufferTest003
 * @tc.desc: Test ModifyImageProperty width buffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyBufferTest003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest003 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "aaa";
    std::string key = "BitsPerSample";
    size_t size = 0;
    bool fileRet = ImageUtils::GetFileSize(IMAGE_INPUT_EXIF_JPEG_PATH, size);
    ASSERT_EQ(fileRet, true);
    uint8_t *data = reinterpret_cast<uint8_t *>(malloc(size));
    ASSERT_NE(data, nullptr);

    uint32_t res = imageSource->ModifyImageProperty(index, key, value, data, size);
    ASSERT_EQ(res, ERR_MEDIA_WRITE_PARCEL_FAIL);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest003 end";
}

/**
 * @tc.name: ModifyImagePropertyBufferTest004
 * @tc.desc: Test ModifyImageProperty width buffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyBufferTest004, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest004 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "aaa";
    std::string key = "BitsPerSample";
    size_t size = 0;
    bool fileRet = ImageUtils::GetFileSize(IMAGE_INPUT_EXIF_JPEG_PATH, size);
    ASSERT_EQ(fileRet, true);
    uint8_t *data = reinterpret_cast<uint8_t *>(malloc(size));
    ASSERT_NE(data, nullptr);

    uint32_t res = imageSource->ModifyImageProperty(index, key, value, data, size);
    ASSERT_EQ(res, ERR_MEDIA_WRITE_PARCEL_FAIL);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest004 end";
}

/**
 * @tc.name: ModifyImagePropertyBufferTest005
 * @tc.desc: Test ModifyImageProperty width buffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyBufferTest005, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest005 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "100";
    std::string key = "BitsPerSample";
    size_t size = 0;
    bool fileRet = ImageUtils::GetFileSize(IMAGE_INPUT_EXIF_JPEG_PATH, size);
    ASSERT_EQ(fileRet, true);
    uint8_t *data = reinterpret_cast<uint8_t *>(malloc(size));
    ASSERT_NE(data, nullptr);

    uint32_t size1 = 0;
    uint32_t res = imageSource->ModifyImageProperty(index, key, value, data, size1);
    ASSERT_EQ(res, ERR_MEDIA_WRITE_PARCEL_FAIL);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest005 end";
}

/**
 * @tc.name: ModifyImagePropertyBufferTest006
 * @tc.desc: Test ModifyImageProperty width buffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyBufferTest006, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest006 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "100";
    std::string key = "BitsPerSample";
    size_t size = 0;
    bool fileRet = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, size);
    ASSERT_EQ(fileRet, true);
    uint8_t *data = reinterpret_cast<uint8_t *>(malloc(size));
    ASSERT_NE(data, nullptr);

    uint32_t res = imageSource->ModifyImageProperty(index, key, value, data, size);
    ASSERT_EQ(res, ERR_MEDIA_WRITE_PARCEL_FAIL);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest006 end";
}

/**
 * @tc.name: ModifyImagePropertyBufferTest007
 * @tc.desc: Test ModifyImageProperty width buffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyBufferTest007, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest007 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource("/data/local/tmp/image/test.png", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    std::string value = "100";
    std::string key = "BitsPerSample";
    size_t size = 0;
    bool fileRet = ImageUtils::GetFileSize("/data/local/tmp/image/test.png", size);
    ASSERT_EQ(fileRet, true);
    uint8_t *data = reinterpret_cast<uint8_t *>(malloc(size));
    ASSERT_NE(data, nullptr);

    uint32_t res = imageSource->ModifyImageProperty(index, key, value, data, size);
    ASSERT_EQ(res, ERR_MEDIA_WRITE_PARCEL_FAIL);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest007 end";
}

/**
 * @tc.name: ModifyImagePropertyBufferTest008
 * @tc.desc: Test ModifyImageProperty width buffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, ModifyImagePropertyBufferTest008, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest008 start";
    std::unique_ptr<ImageSource> imageSource = std::unique_ptr<ImageSource>();
    CreateImageSourceFromFilePath(imageSource);

    uint32_t index = 0;
    std::string value = "100";
    std::string key = "111";
    size_t size = 0;
    bool fileRet = ImageUtils::GetFileSize(IMAGE_INPUT_EXIF_JPEG_PATH, size);
    ASSERT_EQ(fileRet, true);
    uint8_t *data = reinterpret_cast<uint8_t *>(malloc(size));
    ASSERT_NE(data, nullptr);
    uint32_t bufferSize = static_cast<uint32_t>(size);

    uint32_t res = imageSource->ModifyImageProperty(index, key, value, data, bufferSize);
    ASSERT_EQ(res, ERR_MEDIA_WRITE_PARCEL_FAIL);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: ModifyImagePropertyBufferTest008 end";
}

/**
 * @tc.name: GetAstcInfoTest001
 * @tc.desc: Test GetAstcInfoTest001(streamptr,streamsize,astcinfo)
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetAstcInfoTest001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg data and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetAstcInfoTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    const int fd = open("/data/local/tmp/image/test.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(fd, SIZE_T, FILE_SIZE);
    ASSERT_NE(fileSourceStream, nullptr);
    ASTCInfo astcinfo;
    bool ret = imageSource->GetASTCInfo(fileSourceStream->GetDataPtr(), fileSourceStream->GetStreamSize(), astcinfo);
    ASSERT_NE(ret, true);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetAstcInfoTest001 end";
}

/**
 * @tc.name: GetEncodedFormat001
 * @tc.desc: The GetEncodedFormat001
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetEncodedFormat001, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string IMAGE_ENCODEDFORMAT = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options(RGBA_8888).
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. get imageInfo encodedformat from imageSource.
     * @tc.expected: step3. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo1;
    uint32_t ret1 = imageSource->GetImageInfo(imageinfo1);
    ASSERT_EQ(ret1, SUCCESS);
    ASSERT_EQ(imageinfo1.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetEncodedFormat001 imageinfo1: " << imageinfo1.encodedFormat;
    /**
     * @tc.steps: step4. get imageInfo encodedformat from pixelMap.
     * @tc.expected: step4. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo2;
    pixelMap->GetImageInfo(imageinfo2);
    EXPECT_EQ(imageinfo2.encodedFormat.empty(), false);
    ASSERT_EQ(imageinfo2.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetEncodedFormat001 imageinfo2: " << imageinfo2.encodedFormat;
}

/**
 * @tc.name: GetEncodedFormat002
 * @tc.desc: The GetEncodedFormat002
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetEncodedFormat002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string IMAGE_ENCODEDFORMAT = "image/jpeg";
    opts.formatHint = "image/bmp";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HW_JPEG_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. decode image source to pixel map by default decode options(RGBA_8888).
     * @tc.expected: step2. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step3. get imageInfo encodedformat from imageSource.
     * @tc.expected: step3. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo1;
    uint32_t ret1 = imageSource->GetImageInfo(imageinfo1);
    ASSERT_EQ(ret1, SUCCESS);
    ASSERT_EQ(imageinfo1.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetEncodedFormat002 imageinfo1: " << imageinfo1.encodedFormat;
    /**
     * @tc.steps: step4. get imageInfo encodedformat from pixelMap.
     * @tc.expected: step4. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo2;
    pixelMap->GetImageInfo(imageinfo2);
    EXPECT_EQ(imageinfo2.encodedFormat.empty(), false);
    ASSERT_EQ(imageinfo2.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetEncodedFormat002 imageinfo2: " << imageinfo2.encodedFormat;
}

/**
 * @tc.name: GetEncodedFormat003
 * @tc.desc: The GetEncodedFormat003
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceJpegTest, GetEncodedFormat003, TestSize.Level3)
{
    /**
     * @tc.steps: step1. create image source by correct jpeg file path and jpeg format hit.
     * @tc.expected: step1. create image source success.
     */
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string IMAGE_ENCODEDFORMAT = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_EXIF_JPEG_PATH,
        opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    /**
     * @tc.steps: step2. get imageInfo encodedformat from imageSource.
     * @tc.expected: step2. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo1;
    uint32_t ret1 = imageSource->GetImageInfo(imageinfo1);
    ASSERT_EQ(ret1, SUCCESS);
    ASSERT_EQ(imageinfo1.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetEncodedFormat003 imageinfo1: " << imageinfo1.encodedFormat;
    /**
     * @tc.steps: step3. decode image source to pixel map by default decode options.
     * @tc.expected: step3. decode image source to pixel map success.
     */
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    /**
     * @tc.steps: step4. get imageInfo encodedformat from pixelMap.
     * @tc.expected: step4. imageInfo encodedformat is the same as image.
     */
    ImageInfo imageinfo2;
    pixelMap->GetImageInfo(imageinfo2);
    EXPECT_EQ(imageinfo2.encodedFormat.empty(), false);
    ASSERT_EQ(imageinfo2.encodedFormat, IMAGE_ENCODEDFORMAT);
    GTEST_LOG_(INFO) << "ImageSourceJpegTest: GetEncodedFormat003 imageinfo2: " << imageinfo2.encodedFormat;
}
} // namespace Multimedia
} // namespace OHOS