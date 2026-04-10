/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <surface.h>

#include "picture.h"
#include "image_source.h"
#include "ext_decoder.h"
#include "heif_stream.h"
#include "item_movie_box.h"
#include "image_mime_type.h"
#include "heif_parser.h"
#include "AvifDecoderImpl.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace ImagePlugin {

class AvifDecodeTest : public testing::Test {
public:
    AvifDecodeTest() {}
    ~AvifDecodeTest() {}
};

static const uint32_t MONO_BYTES = 1;
static const uint32_t YUV420_BYTES = 2;
static const uint32_t YUV444_BYTES = 3;

#ifdef AVIF_DECODE_ENABLE
namespace {
    enum class ImageType {
        AVIF,
        AVIS,
    };
    struct AvifImageInfo {
        ImageType GetImageType() const
        {
            return type;
        }
        std::string GetEncodedFormat() const
        {
            return encodedFormat;
        }
        std::string path;
        uint32_t width = 0;
        uint32_t height = 0;
        uint32_t bitNum = 0;
        std::string encodedFormat = IMAGE_AVIF_FORMAT;
        ImageType type = ImageType::AVIF;
        uint32_t delayTime = 0;
        uint32_t frameCount = 0;
    };
}

static const std::string IMAGE_INPUT_8BIT_AVIF_PATH =
    "/data/local/tmp/image/8bit_I420_497_323.avif";
static const std::string IMAGE_INPUT_10BIT_AVIF_PATH =
    "/data/local/tmp/image/10bit_I010_1080_720.avif";
static const std::string IMAGE_INPUT_8BIT_AVIS_PATH =
    "/data/local/tmp/image/bird_8bit_I420_599x359_fps10.avif";
static const std::string IMAGE_INPUT_10BIT_AVIS_PATH =
    "/data/local/tmp/image/lizard_10bit_I010_599x338_fps24.avif";
static const uint32_t IMAGE_8BIT_AVIF_WIDTH = 497;
static const uint32_t IMAGE_8BIT_AVIF_HEIGHT = 323;
static const uint32_t IMAGE_10BIT_AVIF_WIDTH = 1080;
static const uint32_t IMAGE_10BIT_AVIF_HEIGHT = 720;
static const uint32_t IMAGE_8BIT_AVIS_WIDTH = 599;
static const uint32_t IMAGE_8BIT_AVIS_HEIGHT = 359;
static const uint32_t IMAGE_8BIT_AVIS_FRAMECOUNT = 90;
static const uint32_t IMAGE_8BIT_AVIS_DELAYTIME = 100;
static const uint32_t IMAGE_10BIT_AVIS_WIDTH = 599;
static const uint32_t IMAGE_10BIT_AVIS_HEIGHT = 338;
static const uint32_t IMAGE_10BIT_AVIS_FRAMECOUNT = 30;
static const uint32_t IMAGE_10BIT_AVIS_DELAYTIME = 41;
static const uint32_t IMAGE_BIT_NUM_8 = 8;
static const uint32_t IMAGE_BIT_NUM_10 = 10;
static const uint32_t SEQUENTIAL_DECODING = 1;
static const uint32_t DECODING_WITH_2_FRAME_SKIP = 2;
static const uint32_t DECODING_WITH_5_FRAME_SKIP = 5;
static const uint32_t DECODING_WITH_10_FRAME_SKIP = 10;
static const uint32_t MAX_FRAMECOUNT = 1000;

static AvifImageInfo Get8bitAvifImage()
{
    AvifImageInfo res;
    res.path = IMAGE_INPUT_8BIT_AVIF_PATH;
    res.width = IMAGE_8BIT_AVIF_WIDTH;
    res.height = IMAGE_8BIT_AVIF_HEIGHT;
    res.bitNum = IMAGE_BIT_NUM_8;
    res.encodedFormat = IMAGE_AVIF_FORMAT;
    res.type = ImageType::AVIF;
    return res;
}

static AvifImageInfo Get10bitAvifImage()
{
    AvifImageInfo res;
    res.path = IMAGE_INPUT_10BIT_AVIF_PATH;
    res.width = IMAGE_10BIT_AVIF_WIDTH;
    res.height = IMAGE_10BIT_AVIF_HEIGHT;
    res.bitNum = IMAGE_BIT_NUM_10;
    res.encodedFormat = IMAGE_AVIF_FORMAT;
    res.type = ImageType::AVIF;
    return res;
}

static AvifImageInfo Get8bitAvisImage()
{
    AvifImageInfo res;
    res.path = IMAGE_INPUT_8BIT_AVIS_PATH;
    res.width = IMAGE_8BIT_AVIS_WIDTH;
    res.height = IMAGE_8BIT_AVIS_HEIGHT;
    res.bitNum = IMAGE_BIT_NUM_8;
    res.encodedFormat = IMAGE_AVIS_FORMAT;
    res.type = ImageType::AVIS;
    res.delayTime = IMAGE_8BIT_AVIS_DELAYTIME;
    res.frameCount = IMAGE_8BIT_AVIS_FRAMECOUNT;
    return res;
}

static AvifImageInfo Get10bitAvisImage()
{
    AvifImageInfo res;
    res.path = IMAGE_INPUT_10BIT_AVIS_PATH;
    res.width = IMAGE_10BIT_AVIS_WIDTH;
    res.height = IMAGE_10BIT_AVIS_HEIGHT;
    res.bitNum = IMAGE_BIT_NUM_10;
    res.encodedFormat = IMAGE_AVIS_FORMAT;
    res.type = ImageType::AVIS;
    res.delayTime = IMAGE_10BIT_AVIS_DELAYTIME;
    res.frameCount = IMAGE_10BIT_AVIS_FRAMECOUNT;
    return res;
}

static bool JudgeIsNumericStr(const std::string &str)
{
    return std::all_of(str.begin(), str.end(), [](const char &c) {
        return std::isdigit(c);
    });
}

static void MarshallingAndUnMarshalling(Picture* picture)
{
    ASSERT_NE(picture, nullptr);
    Parcel data;
    ASSERT_EQ(picture->Marshalling(data), true);
    std::unique_ptr<Picture> dstPicture;
    dstPicture.reset(picture->Unmarshalling(data));
    ASSERT_NE(dstPicture, nullptr);
}

static std::vector<std::pair<PixelFormat, bool>> GetDesiredFormatAndExceptedResult(uint32_t bitNum)
{
    std::vector<std::pair<PixelFormat, bool>> res;
    res.emplace_back(std::make_pair(PixelFormat::NV12, true));
    res.emplace_back(std::make_pair(PixelFormat::NV21, true));
    res.emplace_back(std::make_pair(PixelFormat::RGBA_8888, true));
    res.emplace_back(std::make_pair(PixelFormat::BGRA_8888, true));
    res.emplace_back(std::make_pair(PixelFormat::YCBCR_P010, false));
    res.emplace_back(std::make_pair(PixelFormat::YCRCB_P010, false));
    if (bitNum == IMAGE_BIT_NUM_8) {
        res.emplace_back(std::make_pair(PixelFormat::RGB_565, true));
    } else {
        res.emplace_back(std::make_pair(PixelFormat::RGB_565, false));
    }
    return res;
}

static void CreatePixelMapTest(const AvifImageInfo &imageInfo)
{
    DecodeOptions opts;
    opts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    auto formats = GetDesiredFormatAndExceptedResult(imageInfo.bitNum);
    for (const auto &pair : formats) {
        opts.desiredPixelFormat = pair.first;
        SourceOptions sourceOptions;
        uint32_t errorCode = 0;
        std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(imageInfo.path, sourceOptions, errorCode);
        ASSERT_NE(imageSource, nullptr);
        uint32_t frameCount = imageSource->GetFrameCount(errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
        ASSERT_EQ(frameCount < MAX_FRAMECOUNT, true);
        for (uint32_t i = 0; i < frameCount; i++) {
            std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(i, opts, errorCode);
            if (pair.second) {
                ASSERT_NE(pixelMap, nullptr);
                ImageInfo pixelMapInfo;
                pixelMap->GetImageInfo(pixelMapInfo);
                ASSERT_EQ(pixelMapInfo.encodedFormat, imageInfo.encodedFormat);
                ASSERT_EQ(pixelMapInfo.size.width, imageInfo.width);
                ASSERT_EQ(pixelMapInfo.size.height, imageInfo.height);
                ASSERT_EQ(pixelMapInfo.pixelFormat, pair.first);
            } else {
                ASSERT_EQ(pixelMap, nullptr);
            }
        }
    }
}

static void CreatePixelMapListTest(const AvifImageInfo &imageInfo)
{
    DecodeOptions opts;
    opts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    opts.isAnimationDecode = imageInfo.GetEncodedFormat() == IMAGE_AVIS_FORMAT ? true : false;
    auto formats = GetDesiredFormatAndExceptedResult(imageInfo.bitNum);
    for (const auto &pair : formats) {
        opts.desiredPixelFormat = pair.first;
        SourceOptions sourceOptions;
        uint32_t errorCode = 0;
        std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(imageInfo.path, sourceOptions, errorCode);
        ASSERT_NE(imageSource, nullptr);
        std::unique_ptr<std::vector<std::unique_ptr<PixelMap>>> pixelMapLists =
            imageSource->CreatePixelMapList(opts, errorCode);
        if (pair.second) {
            ASSERT_NE(pixelMapLists, nullptr);
            const std::vector<std::unique_ptr<PixelMap>> &pixelMapVec = *pixelMapLists;
            ASSERT_EQ(pixelMapVec.empty(), false);
            for (const auto &pixelMap : pixelMapVec) {
                ASSERT_NE(pixelMap, nullptr);
                ImageInfo pixelMapInfo;
                pixelMap->GetImageInfo(pixelMapInfo);
                ASSERT_EQ(pixelMapInfo.encodedFormat, imageInfo.encodedFormat);
                ASSERT_EQ(pixelMapInfo.size.width, imageInfo.width);
                ASSERT_EQ(pixelMapInfo.size.height, imageInfo.height);
                ASSERT_EQ(pixelMapInfo.pixelFormat, pair.first);
            }
        } else {
            ASSERT_EQ(pixelMapLists, nullptr);
        }
    }
}

static void CreatePictureTest(const AvifImageInfo &imageInfo)
{
#if !defined(CROSS_PLATFORM)
    ASSERT_EQ(imageInfo.GetImageType(), ImageType::AVIF);
    DecodingOptionsForPicture opts;
    opts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    auto formats = GetDesiredFormatAndExceptedResult(imageInfo.bitNum);
    for (const auto &pair : formats) {
        opts.desiredPixelFormat = pair.first;
        SourceOptions sourceOptions;
        uint32_t errorCode = 0;
        std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(imageInfo.path, sourceOptions, errorCode);
        ASSERT_NE(imageSource, nullptr);
        std::unique_ptr<Picture> picture = imageSource->CreatePicture(opts, errorCode);
        if (pair.second) {
            ASSERT_NE(picture, nullptr);
            std::shared_ptr<PixelMap> pixelMap = picture->GetMainPixel();
            ASSERT_NE(pixelMap, nullptr);
            ImageInfo pixelMapInfo;
            pixelMap->GetImageInfo(pixelMapInfo);
            ASSERT_EQ(pixelMapInfo.encodedFormat, imageInfo.encodedFormat);
            ASSERT_EQ(pixelMapInfo.size.width, imageInfo.width);
            ASSERT_EQ(pixelMapInfo.size.height, imageInfo.height);
            ASSERT_EQ(pixelMapInfo.pixelFormat, pair.first);
        } else {
            ASSERT_EQ(picture, nullptr);
        }
    }
#endif
}

static void CreatePictureAtIndexTest(const AvifImageInfo &avisImageInfo, uint32_t skipIndex = SEQUENTIAL_DECODING)
{
#if !defined(CROSS_PLATFORM)
    ASSERT_EQ(avisImageInfo.GetImageType(), ImageType::AVIS);
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(avisImageInfo.path, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    uint32_t frameCount = imageSource->GetFrameCount(errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(frameCount, avisImageInfo.frameCount);
    for (uint32_t index = 0; index < frameCount; index += skipIndex) {
        std::unique_ptr<Picture> picture = imageSource->CreatePictureAtIndex(index, errorCode);
        ASSERT_NE(picture, nullptr);
        auto metaData = picture->GetMetadata(MetadataType::AVIS);
        ASSERT_NE(metaData, nullptr);
        std::string delayTimeStr;
        ASSERT_EQ(metaData->GetValue(AVIS_METADATA_KEY_DELAY_TIME, delayTimeStr), SUCCESS);
        ASSERT_EQ(JudgeIsNumericStr(delayTimeStr), true);
        ASSERT_EQ(std::stoi(delayTimeStr), avisImageInfo.delayTime);
        auto pixelMap = picture->GetMainPixel();
        ASSERT_NE(pixelMap, nullptr);
        ASSERT_EQ(pixelMap->GetWidth(), avisImageInfo.width);
        ASSERT_EQ(pixelMap->GetHeight(), avisImageInfo.height);
        MarshallingAndUnMarshalling(picture.get());
    }
#endif
}

/**
 * @tc.name: CreatePixelMapTest001
 * @tc.desc: Test use CreatePixelMap decode 8bit avif image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePixelMapTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapTest001 start";
    CreatePixelMapTest(Get8bitAvifImage());
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapTest001 end";
}

/**
 * @tc.name: CreatePixelMapTest002
 * @tc.desc: Test use CreatePixelMap decode 10bit avif image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePixelMapTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapTest002 start";
    CreatePixelMapTest(Get10bitAvifImage());
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapTest002 end";
}

/**
 * @tc.name: CreatePixelMapTest003
 * @tc.desc: Test use CreatePixelMap decode 8bit avis image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePixelMapTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapTest003 start";
    CreatePixelMapTest(Get8bitAvisImage());
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapTest003 end";
}

/**
 * @tc.name: CreatePixelMapTest004
 * @tc.desc: Test use CreatePixelMap decode 10bit avis image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePixelMapTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapTest004 start";
    CreatePixelMapTest(Get10bitAvisImage());
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapTest004 end";
}

/**
 * @tc.name: CreatePixelMapListTest001
 * @tc.desc: Test use CreatePixelMapList decode 8bit avif image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePixelMapListTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapListTest001 start";
    CreatePixelMapListTest(Get8bitAvifImage());
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapListTest001 end";
}

/**
 * @tc.name: CreatePixelMapListTest002
 * @tc.desc: Test use CreatePixelMapList decode 10bit avif image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePixelMapListTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapListTest002 start";
    CreatePixelMapListTest(Get10bitAvifImage());
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapListTest002 end";
}

/**
 * @tc.name: CreatePixelMapListTest003
 * @tc.desc: Test use CreatePixelMapList decode 8bit avis image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePixelMapListTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapListTest003 start";
    CreatePixelMapListTest(Get8bitAvisImage());
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapListTest003 end";
}

/**
 * @tc.name: CreatePixelMapListTest004
 * @tc.desc: Test use CreatePixelMapList decode 10bit avis image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePixelMapListTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapListTest004 start";
    CreatePixelMapListTest(Get10bitAvisImage());
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePixelMapListTest004 end";
}

/**
 * @tc.name: CreatePictureTest001
 * @tc.desc: Test use CreatePicture decode 8bit avif image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePictureTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePictureTest001 start";
    CreatePictureTest(Get8bitAvifImage());
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePictureTest001 end";
}

/**
 * @tc.name: CreatePictureTest002
 * @tc.desc: Test use CreatePicture decode 10bit avif image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePictureTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePictureTest002 start";
    CreatePictureTest(Get10bitAvifImage());
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePictureTest002 end";
}

/**
 * @tc.name: CreatePictureAtIndexTest001
 * @tc.desc: Test use CreatePictureAtIndex decode 8bit avis image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePictureAtIndexTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePictureAtIndexTest001 start";
    auto image = Get8bitAvisImage();
    CreatePictureAtIndexTest(image, SEQUENTIAL_DECODING);
    CreatePictureAtIndexTest(image, DECODING_WITH_2_FRAME_SKIP);
    CreatePictureAtIndexTest(image, DECODING_WITH_5_FRAME_SKIP);
    CreatePictureAtIndexTest(image, DECODING_WITH_10_FRAME_SKIP);
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePictureAtIndexTest001 end";
}

/**
 * @tc.name: CreatePictureAtIndexTest002
 * @tc.desc: Test use CreatePictureAtIndex decode 10bit avis image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, CreatePictureAtIndexTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePictureAtIndexTest002 start";
    auto image = Get10bitAvisImage();
    CreatePictureAtIndexTest(image, SEQUENTIAL_DECODING);
    CreatePictureAtIndexTest(image, DECODING_WITH_2_FRAME_SKIP);
    CreatePictureAtIndexTest(image, DECODING_WITH_5_FRAME_SKIP);
    CreatePictureAtIndexTest(image, DECODING_WITH_10_FRAME_SKIP);
    GTEST_LOG_(INFO) << "AvifDecodeTest: CreatePictureAtIndexTest002 end";
}
#endif

/**
 * @tc.name: GetPixelBytesTest001
 * @tc.desc: Test GetPixelBytes use different HeifPixelFormat.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, GetPixelBytesTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetPixelBytesTest001 start";
    std::shared_ptr<AvifDecoderImpl> avifDecoderImpl = std::make_shared<AvifDecoderImpl>();
    ASSERT_NE(avifDecoderImpl, nullptr);
    ASSERT_EQ(avifDecoderImpl->GetPixelBytes(HeifPixelFormat::MONOCHROME), MONO_BYTES);
    ASSERT_EQ(avifDecoderImpl->GetPixelBytes(HeifPixelFormat::YUV420), YUV420_BYTES);
    ASSERT_EQ(avifDecoderImpl->GetPixelBytes(HeifPixelFormat::YUV422), YUV420_BYTES);
    ASSERT_EQ(avifDecoderImpl->GetPixelBytes(HeifPixelFormat::YUV444), YUV444_BYTES);
    ASSERT_EQ(avifDecoderImpl->GetPixelBytes(HeifPixelFormat::UNDEFINED), 0);
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetPixelBytesTest001 end";
}

/**
 * @tc.name: GetAVIFPixelFormatTest001
 * @tc.desc: Test GetAVIFPixelFormat use different config.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, GetAVIFPixelFormatTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetAVIFPixelFormatTest001 start";
    std::shared_ptr<HeifAv1CBox> av1c = std::make_shared<HeifAv1CBox>();
    ASSERT_NE(av1c, nullptr);
    av1c->config_.monochrome = 1;
    ASSERT_EQ(av1c->GetAVIFPixelFormat(), HeifPixelFormat::MONOCHROME);
    av1c->config_.monochrome = 0;
    av1c->config_.chromaSubsamplingX = 1;
    av1c->config_.chromaSubsamplingY = 1;
    ASSERT_EQ(av1c->GetAVIFPixelFormat(), HeifPixelFormat::YUV420);
    av1c->config_.chromaSubsamplingY = 0;
    ASSERT_EQ(av1c->GetAVIFPixelFormat(), HeifPixelFormat::YUV422);
    av1c->config_.chromaSubsamplingX = 0;
    ASSERT_EQ(av1c->GetAVIFPixelFormat(), HeifPixelFormat::YUV444);
    av1c->config_.chromaSubsamplingY = 1;
    ASSERT_EQ(av1c->GetAVIFPixelFormat(), HeifPixelFormat::UNDEFINED);
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetAVIFPixelFormatTest001 end";
}

/**
 * @tc.name: GetBitDepthTest001
 * @tc.desc: Test GetBitDepth use different config.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, GetBitDepthTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetBitDepthTest001 start";
    std::shared_ptr<HeifAv1CBox> av1c = std::make_shared<HeifAv1CBox>();
    ASSERT_NE(av1c, nullptr);
    av1c->config_.twelveBit = 1;
    av1c->config_.highBitDepth = 1;
    ASSERT_EQ(av1c->GetBitDepth(), AvifBitDepth::Bit_12);
    av1c->config_.twelveBit = 0;
    ASSERT_EQ(av1c->GetBitDepth(), AvifBitDepth::Bit_10);
    av1c->config_.highBitDepth = 0;
    ASSERT_EQ(av1c->GetBitDepth(), AvifBitDepth::Bit_8);
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetBitDepthTest001 end";
}

/**
 * @tc.name: IsAvisImageTest001
 * @tc.desc: Test IsAvisImage when ftypBox is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, IsAvisImageTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: IsAvisImageTest001 start";
    std::shared_ptr<HeifParser> heifParser = std::make_shared<HeifParser>();
    ASSERT_NE(heifParser, nullptr);
    heifParser->ftypBox_.reset();
    ASSERT_EQ(heifParser->IsAvisImage(), false);
    GTEST_LOG_(INFO) << "AvifDecodeTest: IsAvisImageTest001 end";
}

/**
 * @tc.name: IsAvisImageTest002
 * @tc.desc: Test IsAvisImage when ftypBox majorBrand is not avis.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, IsAvisImageTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: IsAvisImageTest002 start";
    std::shared_ptr<HeifParser> heifParser = std::make_shared<HeifParser>();
    ASSERT_NE(heifParser, nullptr);
    heifParser->ftypBox_ = std::make_shared<HeifFtypBox>();
    ASSERT_NE(heifParser->ftypBox_, nullptr);
    ASSERT_EQ(heifParser->IsAvisImage(), false);
    GTEST_LOG_(INFO) << "AvifDecodeTest: IsAvisImageTest002 end";
}

/**
 * @tc.name: IsAvisImageTest003
 * @tc.desc: Test IsAvisImage when hdlrBox is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, IsAvisImageTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: IsAvisImageTest003 start";
    std::shared_ptr<HeifParser> heifParser = std::make_shared<HeifParser>();
    ASSERT_NE(heifParser, nullptr);
    heifParser->ftypBox_ = std::make_shared<HeifFtypBox>();
    ASSERT_NE(heifParser->ftypBox_, nullptr);
    heifParser->ftypBox_->majorBrand_ = AVIF_BRAND_TYPE_AVIS;
    heifParser->hdlrBox_.reset();
    ASSERT_EQ(heifParser->IsAvisImage(), false);
    GTEST_LOG_(INFO) << "AvifDecodeTest: IsAvisImageTest003 end";
}

/**
 * @tc.name: IsAvisImageTest004
 * @tc.desc: Test IsAvisImage when hdlrBox handler type is not pict.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, IsAvisImageTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: IsAvisImageTest004 start";
    std::shared_ptr<HeifParser> heifParser = std::make_shared<HeifParser>();
    ASSERT_NE(heifParser, nullptr);
    heifParser->ftypBox_ = std::make_shared<HeifFtypBox>();
    ASSERT_NE(heifParser->ftypBox_, nullptr);
    heifParser->ftypBox_->majorBrand_ = AVIF_BRAND_TYPE_AVIS;
    heifParser->hdlrBox_ = std::make_shared<HeifHdlrBox>();
    ASSERT_NE(heifParser->hdlrBox_, nullptr);
    heifParser->hdlrBox_->handlerType_ = 0;
    ASSERT_EQ(heifParser->IsAvisImage(), false);
    GTEST_LOG_(INFO) << "AvifDecodeTest: IsAvisImageTest004 end";
}

/**
 * @tc.name: IsSupportedAvifPixelTest001
 * @tc.desc: Test IsSupportedAvifPixel when format is MONOCHROME or bit num is 12.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, IsSupportedAvifPixelTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: IsSupportedAvifPixelTest001 start";
    std::shared_ptr<HeifParser> heifParser = std::make_shared<HeifParser>();
    ASSERT_NE(heifParser, nullptr);
    ASSERT_EQ(heifParser->IsSupportedAvifPixel(HeifPixelFormat::MONOCHROME, AvifBitDepth::Bit_10), false);
    ASSERT_EQ(heifParser->IsSupportedAvifPixel(HeifPixelFormat::YUV420, AvifBitDepth::Bit_12), false);
    GTEST_LOG_(INFO) << "AvifDecodeTest: IsSupportedAvifPixelTest001 end";
}

/**
 * @tc.name: GetAvisFrameDataTest001
 * @tc.desc: Test GetAvisFrameData when stsd box is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, GetAvisFrameDataTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetAvisFrameDataTest001 start";
    std::shared_ptr<HeifParser> heifParser = std::make_shared<HeifParser>();
    heifParser->stsdBox_.reset();
    std::vector<uint8_t> dest;
    ASSERT_EQ(heifParser->GetAvisFrameData(0, dest), heif_error_no_stsd);
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetAvisFrameDataTest001 end";
}

/**
 * @tc.name: isSequenceMajorBrandTest001
 * @tc.desc: Test GetAvisFrameData when ftyp box is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, isSequenceMajorBrandTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: isSequenceMajorBrandTest001 start";
    std::shared_ptr<HeifParser> heifParser = std::make_shared<HeifParser>();
    ASSERT_NE(heifParser, nullptr);
    heifParser->ftypBox_.reset();
    ASSERT_EQ(heifParser->isSequenceMajorBrand(), false);
    GTEST_LOG_(INFO) << "AvifDecodeTest: isSequenceMajorBrandTest001 end";
}

/**
 * @tc.name: GetAvisFrameCountTest001
 * @tc.desc: Test GetAvisFrameCount when is not avis image.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, GetAvisFrameCountTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetAvisFrameCountTest001 start";
    std::shared_ptr<HeifParser> heifParser = std::make_shared<HeifParser>();
    ASSERT_NE(heifParser, nullptr);
    uint32_t sampleCount = 0;
    ASSERT_EQ(heifParser->GetAvisFrameCount(sampleCount), heif_error_not_avis);
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetAvisFrameCountTest001 end";
}

/**
 * @tc.name: GetAvisFrameCountTest002
 * @tc.desc: Test GetAvisFrameCount when stsz box is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AvifDecodeTest, GetAvisFrameCountTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetAvisFrameCountTest002 start";
    std::shared_ptr<HeifParser> heifParser = std::make_shared<HeifParser>();
    ASSERT_NE(heifParser, nullptr);
    heifParser->ftypBox_ = std::make_shared<HeifFtypBox>();
    ASSERT_NE(heifParser->ftypBox_, nullptr);
    heifParser->ftypBox_->majorBrand_ = AVIF_BRAND_TYPE_AVIS;
    heifParser->hdlrBox_ = std::make_shared<HeifHdlrBox>();
    ASSERT_NE(heifParser->hdlrBox_, nullptr);
    heifParser->hdlrBox_->handlerType_ = HANDLER_TYPE_PICT;
    uint32_t sampleCount = 0;
    heifParser->stszBox_.reset();
    ASSERT_EQ(heifParser->GetAvisFrameCount(sampleCount), heif_error_no_stsz);
    GTEST_LOG_(INFO) << "AvifDecodeTest: GetAvisFrameCountTest002 end";
}
} // namespace Media
} // namespace OHOS