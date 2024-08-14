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
#include <fstream>
#include <fcntl.h>
#include "hilog/log.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "log_tags.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "image_source_util.h"
#include "file_source_stream.h"
#include "buffer_source_stream.h"
#include "ext_stream.h"
#include "jpeg_mpf_parser.h"
#include "image_packer.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::HiviewDFX;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL_TEST = {
    LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "ImageSourceHdrTest"
};

static const std::string IMAGE_INPUT_JPEG_SDR_PATH = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_INPUT_HEIF_SDR_PATH = "/data/local/tmp/image/test.heic";
static const std::string IMAGE_INPUT_HEIF_10BIT_SDR_PATH = "/data/local/tmp/image/test-10bit-1.heic";
static const std::string IMAGE_INPUT_JPEG_HDR_PATH = "/data/local/tmp/image/hdr.jpg";
static const std::string IMAGE_INPUT_JPEG_HDR_VIVID_PATH = "/data/local/tmp/image/HdrVivid.jpg";

class ImageSourceHdrTest : public testing::Test {
public:
    ImageSourceHdrTest() {}
    ~ImageSourceHdrTest() {}
};

/**
 * @tc.name: CheckImageSourceHdr001
 * @tc.desc: Test IsHdrImage()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckImageSourceHdr001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_SDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    bool isHdr = imageSource->IsHdrImage();
    ASSERT_EQ(isHdr, false);
}

/**
 * @tc.name: CheckImageSourceHdr002
 * @tc.desc: Test IsHdrImage()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckImageSourceHdr002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_SDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    bool isHdr = imageSource->IsHdrImage();
    ASSERT_EQ(isHdr, false);
}

/**
 * @tc.name: CheckImageSourceHdr003
 * @tc.desc: Test IsHdrImage()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckImageSourceHdr003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_10BIT_SDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    bool isHdr = imageSource->IsHdrImage();
    ASSERT_EQ(isHdr, false);
}

/**
 * @tc.name: CheckImageSourceHdr004
 * @tc.desc: Test IsHdrImage()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckImageSourceHdr004, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    bool isHdr = imageSource->IsHdrImage();
#ifdef IMAGE_VPE_FLAG
    ASSERT_EQ(isHdr, true);
#else
    ASSERT_EQ(isHdr, false);
#endif
}

/**
 * @tc.name: CheckPixelMapHdr001
 * @tc.desc: Test PixelMap IsHdr()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPixelMapHdr001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_SDR_PATH, opts, errorCode);
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

    bool isHdr = pixelMap->IsHdr();
    ASSERT_EQ(isHdr, false);
}

/**
 * @tc.name: CheckPixelMapHdr002
 * @tc.desc: Test PixelMap IsHdr()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPixelMapHdr002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_SDR_PATH, opts, errorCode);
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

    bool isHdr = pixelMap->IsHdr();
    ASSERT_EQ(isHdr, false);
}

/**
 * @tc.name: CheckPixelMapHdr003
 * @tc.desc: Test PixelMap IsHdr()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPixelMapHdr003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_10BIT_SDR_PATH, opts, errorCode);
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

    bool isHdr = pixelMap->IsHdr();
    ASSERT_EQ(isHdr, false);
}

/**
 * @tc.name: CheckPixelMapHdr004
 * @tc.desc: Test PixelMap IsHdr()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPixelMapHdr004, TestSize.Level3)
{
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

    bool isHdr = pixelMap->IsHdr();
#ifdef IMAGE_VPE_FLAG
    ASSERT_EQ(isHdr, true);
#else
    ASSERT_EQ(isHdr, false);
#endif
}

/**
 * @tc.name: CheckPixelMapHdr005
 * @tc.desc: Test HdrVivid PixelMap IsHdr()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPixelMapHdr005, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_VIVID_PATH, opts, errorCode);
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

    bool isHdr = pixelMap->IsHdr();
#ifdef IMAGE_VPE_FLAG
    ASSERT_EQ(isHdr, true);
#else
    ASSERT_EQ(isHdr, false);
#endif
}

/**
 * @tc.name: CheckPixelMapDynamicRangeSdr001
 * @tc.desc: Test PixelMap IsHdr()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPixelMapDynamicRangeSdr001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_SDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::SDR;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    bool isHdr = pixelMap->IsHdr();
    ASSERT_EQ(isHdr, false);
}

/**
 * @tc.name: CheckPixelMapDynamicRangeSdr002
 * @tc.desc: Test PixelMap IsHdr()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPixelMapDynamicRangeSdr002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIF_SDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::SDR;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    bool isHdr = pixelMap->IsHdr();
    ASSERT_EQ(isHdr, false);
}

/**
 * @tc.name: CheckPixelMapDynamicRangeSdr003
 * @tc.desc: Test PixelMap IsHdr()
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPixelMapDynamicRangeSdr003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::SDR;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    HiLog::Debug(LABEL_TEST, "pixel map create");
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);

    bool isHdr = pixelMap->IsHdr();
    ASSERT_EQ(isHdr, false);
}

/**
 * @tc.name: ToSdr001
 * @tc.desc: ToSdr test
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, ToSdr001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceHdrTest: ToSdr001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string path = "/data/local/tmp/image/hdr.jpg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    DecodeOptions decopts;
    decopts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    uint32_t ret = SUCCESS;
    auto pixelMap = imageSource->CreatePixelMap(decopts, ret);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t errCode = pixelMap->ToSdr();
#ifdef IMAGE_VPE_FLAG
    ASSERT_EQ(errCode, SUCCESS);
#else
    ASSERT_NE(errCode, SUCCESS);
#endif
}

/**
 * @tc.name: ToSdr002
 * @tc.desc: ToSdr test
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, ToSdr002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceHdrTest: ToSdr002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::string path = "/data/local/tmp/image/test.jpg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);

    DecodeOptions decopts;
    decopts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    uint32_t ret = SUCCESS;
    auto pixelMap = imageSource->CreatePixelMap(decopts, ret);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t errCode = pixelMap->ToSdr();
    ASSERT_NE(errCode, SUCCESS);
}

/**
 * @tc.name: PackHdrPixelMap001
 * @tc.desc: Test pack hdr pixelmap
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, PackHdrPixelMap001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_VIVID_PATH, opts, errorCode);
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
    std::vector<uint8_t> outputData(fileSize);
    ImagePacker pack;
    PackOption option;
    option.format = "image/jpeg";
    option.desiredDynamicRange = EncodeDynamicRange::AUTO;
    errorCode = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    errorCode = pack.AddImage(*(pixelMap.get()));
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    std::unique_ptr<ImageSource> outImageSource =
        ImageSource::CreateImageSource(outputData.data(), outputData.size(), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(outImageSource.get(), nullptr);
    bool isHdr = outImageSource->IsHdrImage();
#ifdef IMAGE_VPE_FLAG
    ASSERT_EQ(isHdr, true);
#else
    ASSERT_EQ(isHdr, false);
#endif
}

/**
 * @tc.name: JpegMpfPackerTest001
 * @tc.desc: test PackHdrJpegMpfMarker
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, JpegMpfPackerTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageSourceHdrTest: JpegMpfPackerTest001 start";
    SingleJpegImage baseImage = {
        .offset = 0,
        .size = 1000,
    };
    SingleJpegImage gainmapImage = {
        .offset = 1000,
        .size = 1000,
    };
    std::vector<uint8_t> data = JpegMpfPacker::PackHdrJpegMpfMarker(baseImage, gainmapImage);
    ASSERT_NE(data.size(), 0);
}
}
}