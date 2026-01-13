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

#define private public
#define protected public
#include <gtest/gtest.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include "image/abs_image_encoder.h"
#include "image_packer.h"
#include "image_utils.h"
#include "image_log.h"
#include "hilog/log.h"
#include "log_tags.h"
#include "media_errors.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "HeifHwEncoderTest"

using namespace OHOS::Media;
using namespace testing::ext;
using namespace OHOS::HiviewDFX;
using namespace OHOS::ImagePlugin;
using namespace OHOS::MultimediaPlugin;
namespace OHOS {
namespace Multimedia {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL_TEST = {
    LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "ImageSourceHdrTest"
};
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_packing.jpg";
static const std::string IMAGE_JPG_SRC = "/data/local/tmp/image/test_packing_exif.jpg";
static const std::string IMAGE_JPG2HEIF_DEST = "/data/local/tmp/image/test_jpeg2heif_out.jpg";
static const std::string IMAGE_INPUT_JPEG_HDR_PATH = "/data/local/tmp/image/hdr.jpg";
static const std::string IMAGE_INPUT_NO_EXIF_PATH = "/data/local/tmp/image/hasNoExif.jpg";
static const std::string IMAGE_INPUT_ODD_IMAGE_PATH = "/data/local/tmp/image/test_odd_image_size.jpg";
static const std::string IMAGE_INPUT_ODD_HEIGHT_IMAGE_PATH = "/data/local/tmp/image/test_odd_height_image_size.jpg";
static const std::string IMAGE_INPUT_ODD_WIDTH_IMAGE_PATH = "/data/local/tmp/image/test_odd_width_image_size.jpg";

class HeifHwEncoderTest : public testing::Test {
public:
    HeifHwEncoderTest() {}
    ~HeifHwEncoderTest() {}
};

void EncodeHeifWithImage(const std::string& imagePath)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(imagePath.c_str(), opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    DecodeOptions dstOpts;
    dstOpts.desiredPixelFormat = PixelFormat::NV12;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMapEx(0, dstOpts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(pixelMap, nullptr);

    const int fileSize = 1024 * 1024 * 35;
    std::vector<uint8_t> outputData(fileSize);
    ImagePacker pack;
    PackOption option;
    option.format = "image/heif";

    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
}

/**
 * @tc.name: EncodeHeif001
 * @tc.desc: test encode heif by fd
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeif001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeif001 start";

    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_JPG_SRC, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    ImagePacker pack;
    const int fd = open(IMAGE_JPG2HEIF_DEST.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    PackOption option;
    option.format = "image/heif";
    uint32_t startpc = pack.StartPacking(fd, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddimgae = pack.AddImage(*imageSource);
    ASSERT_EQ(retAddimgae, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    const int fdDest = open(IMAGE_JPG2HEIF_DEST.c_str(), O_RDWR, S_IRUSR | S_IWUSR);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(fdDest, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);

    close(fd);
    close(fdDest);

    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeif001 end";
}

/**
 * @tc.name: EncodeHeif002
 * @tc.desc: test encode heif by data
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeif002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeif002 start";

    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string srcJpeg = IMAGE_INPUT_JPEG_PATH;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcJpeg.c_str(), opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions dstOpts;
    dstOpts.desiredPixelFormat = PixelFormat::NV21;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMapEx(0, dstOpts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(pixelMap, nullptr);

    const int fileSize = 1024 * 1024 * 35;
    std::vector<uint8_t> outputData(fileSize);
    std::string outJpeg = "/data/local/tmp/image/pack1.heif";
    ImagePacker pack;
    PackOption option;
    option.format = "image/heif";
    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeif002 end";
}

/**
 * @tc.name: EncodeHeif003
 * @tc.desc: test encode heif by data, NV12
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeif003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeif002 start";

    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string srcJpeg = IMAGE_INPUT_JPEG_PATH;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcJpeg.c_str(), opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions dstOpts;
    dstOpts.desiredPixelFormat = PixelFormat::NV12;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMapEx(0, dstOpts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(pixelMap, nullptr);

    const int fileSize = 1024 * 1024 * 35;
    std::vector<uint8_t> outputData(fileSize);
    ImagePacker pack;
    PackOption option;
    option.format = "image/heif";
    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeif002 end";
}


/**
 * @tc.name: EncodeDualHeif001
 * @tc.desc: test encode dual hdr heif by data
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeDualHdrHeif001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeDualHdrHeif001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::AUTO;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const int fileSize = 1024 * 1024 * 35;
    ImagePacker pack;
    std::vector<uint8_t> outputData(fileSize);
    PackOption option;
    option.format = "image/heif";
    option.desiredDynamicRange = EncodeDynamicRange::SDR;
    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeDualHdrHeif001 end";
}


/**
 * @tc.name: EncodeDualHeif002
 * @tc.desc: test encode dual hdr heif by data
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeDualHdrHeif002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeDualHdrHeif002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::AUTO;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const int fileSize = 1024 * 1024 * 35;
    ImagePacker pack;
    std::vector<uint8_t> outputData(fileSize);
    PackOption option;
    option.format = "image/heif";
    option.desiredDynamicRange = EncodeDynamicRange::AUTO;
    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeDualHdrHeif002 end";
}

/**
 * @tc.name: EncodeHeifByAuto001
 * @tc.desc: test encode
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeifByAuto001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifByAuto001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const int fileSize = 1024 * 1024 * 35;
    ImagePacker pack;
    std::vector<uint8_t> outputData(fileSize);
    PackOption option;
    option.format = "image/heif";
    option.desiredDynamicRange = EncodeDynamicRange::AUTO;
    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifByAuto001 end";
}


/**
 * @tc.name: EncodeHeifExif001
 * @tc.desc: test encode dual hdr heif by data
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeifExif001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifExif001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const int fileSize = 1024 * 1024 * 35;
    ImagePacker pack;
    std::vector<uint8_t> outputData(fileSize);
    PackOption option;
    option.format = "image/heif";
    option.needsPackProperties = true;
    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifExif001 end";
}

/**
 * @tc.name: EncodeHeifExif002
 * @tc.desc: test encode dual hdr heif with exif
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeifExif002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifExif002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::AUTO;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const int fileSize = 1024 * 1024 * 35;
    ImagePacker pack;
    std::vector<uint8_t> outputData(fileSize);
    PackOption option;
    option.format = "image/heif";
    option.desiredDynamicRange = EncodeDynamicRange::AUTO;
    option.needsPackProperties = true;
    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifExif002 end";
}

/**
 * @tc.name: EncodeHeifExif003
 * @tc.desc: test encode without exif
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeifExif003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifExif002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::SDR;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const int fileSize = 1024 * 1024 * 35;
    ImagePacker pack;
    std::vector<uint8_t> outputData(fileSize);
    PackOption option;
    option.format = "image/heif";
    option.needsPackProperties = false;
    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifExif002 end";
}

/**
 * @tc.name: EncodeHeifExif004
 * @tc.desc: test encode without exif
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeifExif004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifExif004 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_NO_EXIF_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    const int fileSize = 1024 * 1024 * 35;
    ImagePacker pack;
    std::vector<uint8_t> outputData(fileSize);
    PackOption option;
    option.format = "image/heif";
    option.needsPackProperties = true;
    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifExif004 end";
}

/**
 * @tc.name: EncodeHeifWithOddImage001
 * @tc.desc: test image with odd image size and encode to heif, NV12
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeifWithOddImage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifWithOddImage001 start";
    EncodeHeifWithImage(IMAGE_INPUT_ODD_IMAGE_PATH);
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifWithOddImage001 end";
}

/**
 * @tc.name: EncodeHeifWithOddImage002
 * @tc.desc: test image with only odd height and encode to heif, NV12
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeifWithOddImage002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifWithOddImage002 start";
    EncodeHeifWithImage(IMAGE_INPUT_ODD_HEIGHT_IMAGE_PATH);
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifWithOddImage002 end";
}

/**
 * @tc.name: EncodeHeifWithOddImage003
 * @tc.desc: test image with only odd width and encode to heif, NV12
 * @tc.type: FUNC
 */
HWTEST_F(HeifHwEncoderTest, EncodeHeifWithOddImage003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifWithOddImage003 start";
    EncodeHeifWithImage(IMAGE_INPUT_ODD_WIDTH_IMAGE_PATH);
    GTEST_LOG_(INFO) << "HeifHwEncoderTest: EncodeHeifWithOddImage003 end";
}
}
}
