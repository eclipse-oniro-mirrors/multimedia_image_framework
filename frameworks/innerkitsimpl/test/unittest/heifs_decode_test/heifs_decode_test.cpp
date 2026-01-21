/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "heif_parser.h"
#ifdef HEIF_HW_DECODE_ENABLE
#include "HeifDecoderImpl.h"
#endif

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace ImagePlugin {

class HeifsDecodeTest : public testing::Test {
public:
    HeifsDecodeTest() {}
    ~HeifsDecodeTest() {}
};

static const uint32_t MOCK_DATA_SIZE = 4 * 20;
static const uint8_t MOCK_DATA_VALUE = 255;
static const uint32_t MOCK_DATA = 1;
static const uint32_t MOCK_INDEX = 1;
static const uint32_t MOCK_INDEX_TWO = 2;
static const uint32_t MOCK_INDEX_THREE = 3;
#ifdef HEIF_HW_DECODE_ENABLE
static const std::string IMAGE_INPUT_HEIFS_PATH = "/data/local/tmp/image/heifs.heic";
static const std::string IMAGE_INPUT_HEIC_PATH = "/data/local/tmp/image/test-10bit-1.heic";
static const std::string IMAGE_STATIC_IMAGE_HEIFS_PATH = "/data/local/tmp/image/C046.heic";
static const std::string IMAGE_ALL_REF_FRAME_HEIFS_PATH = "/data/local/tmp/image/C001.heic";
static const std::string IMAGE_MOOV_HEIC_PATH = "/data/local/tmp/image/moov.heic";
static const std::string HEIFS_MIME_TYPE = "image/heif-sequence";
static const uint32_t INPUT_HEIFS_FRAMECOUNT = 120;
static const uint32_t INPUT_HEIFS_DELAYTIME = 40;
static const uint32_t MOCK_INPUT_HEIGHT = 144;
static const uint32_t MOCK_INPUT_WIDTH = 256;
static const uint32_t INPUT_STATIC_IMAGE_DELAYTIME = 1800;
static const uint32_t INPUT_STATIC_IMAGE_HEIGHT = 720;
static const uint32_t INPUT_STATIC_IMAGE_WIDTH = 1280;
static const uint32_t INPUT_ALL_REF_IMAGE_DELAYTIME = 200;
static const uint32_t MOCK_FRAME_INDEX = 1000;
static const uint32_t MOCK_TIMES_ONE = 1;
static const uint32_t MOCK_TIMES_TWO = 2;
static const uint32_t MOCK_SKIP_NUM_ONE = 1;
static const uint32_t MOCK_SKIP_NUM_TWO = 2;
static const uint32_t MOCK_SKIP_NUM_FIVE = 5;
static const uint32_t MOCK_SKIP_NUM_TEN = 10;
static const uint32_t MOCK_ITEM_ID = 1003;
static const uint8_t CONSTRUCTION_METHOD_FILE_OFFSET = 0;
static const uint8_t CONSTRUCTION_METHOD_IDAT_OFFSET = 1;
static const uint8_t CONSTRUCTION_METHOD_OTHER_OFFSET = 2;

namespace {
    struct HeifsImageInfo {
        HeifsImageInfo(const std::string &p, uint32_t time, uint32_t w, uint32_t h)
            : path(p), delayTime(time), width(w), height(h) {}
        std::string path;
        uint32_t delayTime = 0;
        uint32_t width = 0;
        uint32_t height = 0;
    };
}

static std::vector<HeifsImageInfo> GetHeifsImages()
{
    std::vector<HeifsImageInfo> images;
    images.emplace_back(HeifsImageInfo(IMAGE_INPUT_HEIFS_PATH, INPUT_HEIFS_DELAYTIME,
        MOCK_INPUT_WIDTH, MOCK_INPUT_HEIGHT));
    images.emplace_back(HeifsImageInfo(IMAGE_STATIC_IMAGE_HEIFS_PATH, INPUT_STATIC_IMAGE_DELAYTIME,
        INPUT_STATIC_IMAGE_WIDTH, INPUT_STATIC_IMAGE_HEIGHT));
    images.emplace_back(HeifsImageInfo(IMAGE_ALL_REF_FRAME_HEIFS_PATH, INPUT_ALL_REF_IMAGE_DELAYTIME,
        INPUT_STATIC_IMAGE_WIDTH, INPUT_STATIC_IMAGE_HEIGHT));
    return images;
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

static void CreatePictureAtIndexUseSpecificAlloc(uint32_t skipIndex = MOCK_SKIP_NUM_ONE)
{
    std::vector<HeifsImageInfo> heifsImages = GetHeifsImages();
    for (const auto &image : heifsImages) {
        SourceOptions sourceOptions;
        uint32_t errorCode = 0;
        std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(image.path, sourceOptions, errorCode);
        ASSERT_NE(imageSource, nullptr);
        uint32_t frameCount = imageSource->GetFrameCount(errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
        for (uint32_t index = 0; index < frameCount; index += skipIndex) {
            std::unique_ptr<Picture> picture = imageSource->CreatePictureAtIndex(index, errorCode);
            ASSERT_NE(picture, nullptr);
            auto metaData = picture->GetMetadata(MetadataType::HEIFS);
            ASSERT_NE(metaData, nullptr);
            std::string delayTimeStr = "";
            ASSERT_EQ(metaData->GetValue(HEIFS_METADATA_KEY_DELAY_TIME, delayTimeStr), SUCCESS);
            ASSERT_EQ(JudgeIsNumericStr(delayTimeStr), true);
            ASSERT_EQ(std::stoi(delayTimeStr), image.delayTime);
            auto pixelMap = picture->GetMainPixel();
            ASSERT_NE(pixelMap, nullptr);
            ASSERT_EQ(pixelMap->GetWidth(), image.width);
            ASSERT_EQ(pixelMap->GetHeight(), image.height);
            MarshallingAndUnMarshalling(picture.get());
        }
    }
}

static void GetHeifDecoderImplFromImageSource(ImageSource* imageSource, HeifDecoderImpl*& heifDecoderImpl)
{
    ASSERT_NE(imageSource, nullptr);
    ASSERT_NE(imageSource->mainDecoder_, nullptr);
    ASSERT_EQ(imageSource->mainDecoder_->GetPluginType(), "ext");
    ExtDecoder* extDecoder = reinterpret_cast<ExtDecoder*>(imageSource->mainDecoder_.get());
    ASSERT_NE(extDecoder, nullptr);
    ASSERT_NE(extDecoder->codec_, nullptr);
    heifDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(heifDecoderImpl, nullptr);
}

static void GetHeifParserFromImageSource(ImageSource* imageSource, std::shared_ptr<HeifParser>& heifParser)
{
    HeifDecoderImpl* heifDecoderImpl = nullptr;
    GetHeifDecoderImplFromImageSource(imageSource, heifDecoderImpl);
    ASSERT_NE(heifDecoderImpl->parser_, nullptr);
    heifParser = heifDecoderImpl->parser_;
}

static void CreateAndDeleteHeifsSwDecoder(int32_t createTimes, int32_t deleteTimes)
{
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    HeifDecoderImpl* decoder = nullptr;
    GetHeifDecoderImplFromImageSource(imageSource.get(), decoder);
    ASSERT_NE(decoder, nullptr);
    HevcSoftDecodeParam param;
    param.gridInfo.tileWidth = MOCK_INPUT_WIDTH;
    param.gridInfo.tileHeight = MOCK_INPUT_HEIGHT;
    for (int32_t i = 0; i < createTimes; i++) {
        ASSERT_EQ(decoder->CreateHeifsSwDecoder(param), true);
    }
    for (int32_t i = 0; i < deleteTimes; i++) {
        decoder->DeleteHeifsSwDecoder();
        ASSERT_EQ(decoder->swDecHeifsHandle_, nullptr);
    }
}
#endif

static void ParseContentAndWriteForFullBox(HeifFullBox& box, bool versionOne)
{
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(MOCK_DATA_SIZE);
    ASSERT_NE(mockData, nullptr);
    std::fill(mockData.get(), mockData.get() + MOCK_DATA_SIZE, MOCK_DATA_VALUE);
    if (versionOne) {
        mockData[0] = static_cast<uint8_t>(MOCK_DATA);
        mockData[MOCK_INDEX] = static_cast<uint8_t>(0);
        mockData[MOCK_INDEX_TWO] = static_cast<uint8_t>(0);
        mockData[MOCK_INDEX_THREE] = static_cast<uint8_t>(0);
    }
    std::shared_ptr<HeifBufferInputStream> mockBuffer =
        std::make_shared<HeifBufferInputStream>(mockData.get(), MOCK_DATA_SIZE, false);
    ASSERT_NE(mockBuffer, nullptr);
    HeifStreamReader reader(mockBuffer, 0, MOCK_DATA_SIZE);
    ASSERT_EQ(box.ParseContent(reader), heif_error_ok);
    if (versionOne) {
        box.version_ = HEIF_BOX_VERSION_ONE;
    }
    HeifStreamWriter writer;
    ASSERT_EQ(box.Write(writer), heif_error_ok);
}

/**
 * @tc.name: CreatePictureAtIndexTest001
 * @tc.desc: Create an Picture list use heif-sequence image and DMA_ALLOC.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, CreatePictureAtIndexTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: CreatePictureAtIndexTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    CreatePictureAtIndexUseSpecificAlloc();
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: CreatePictureAtIndexTest001 end";
}

/**
 * @tc.name: CreatePictureAtIndexTest002
 * @tc.desc: Create an Picture list use heif-sequence image and skip two index.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, CreatePictureAtIndexTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: CreatePictureAtIndexTest002 start";
#ifdef HEIF_HW_DECODE_ENABLE
    CreatePictureAtIndexUseSpecificAlloc(MOCK_SKIP_NUM_TWO);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: CreatePictureAtIndexTest002 end";
}

/**
 * @tc.name: CreatePictureAtIndexTest003
 * @tc.desc: Create an Picture list use heif-sequence image and skip five index.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, CreatePictureAtIndexTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: CreatePictureAtIndexTest003 start";
#ifdef HEIF_HW_DECODE_ENABLE
    CreatePictureAtIndexUseSpecificAlloc(MOCK_SKIP_NUM_FIVE);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: CreatePictureAtIndexTest003 end";
}

/**
 * @tc.name: CreatePictureAtIndexTest004
 * @tc.desc: Create an Picture list use heif-sequence image and skip ten index.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, CreatePictureAtIndexTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: CreatePictureAtIndexTest004 start";
#ifdef HEIF_HW_DECODE_ENABLE
    CreatePictureAtIndexUseSpecificAlloc(MOCK_SKIP_NUM_TEN);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: CreatePictureAtIndexTest004 end";
}

/**
 * @tc.name: GetImageInfoEncodedFormatTest001
 * @tc.desc: Get the encoding format from the heif-sequence image information.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetImageInfoEncodedFormatTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetImageInfoEncodedFormatTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    ImageInfo imageInfo;
    errorCode = imageSource->GetImageInfo(0, imageInfo);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(imageInfo.encodedFormat, HEIFS_MIME_TYPE);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetImageInfoEncodedFormatTest001 end";
}

/**
 * @tc.name: GetHeifsFrameCountTest001
 * @tc.desc: Get frame count from Heic images.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetHeifsFrameCountTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameCountTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIC_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions decOpt;
    auto pixelMap = imageSource->CreatePixelMap(0, decOpt, errorCode);
    ASSERT_NE(pixelMap, nullptr);
    HeifDecoderImpl* decoder = nullptr;
    GetHeifDecoderImplFromImageSource(imageSource.get(), decoder);
    ASSERT_NE(decoder, nullptr);
    uint32_t frameCount = 0;
    ASSERT_EQ(decoder->GetHeifsFrameCount(frameCount), false);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameCountTest001 end";
}

/**
 * @tc.name: GetHeifsFrameCountTest002
 * @tc.desc: GetHeifsFrameCount when image is not heifs image.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetHeifsFrameCountTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameCountTest002 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    imageSource->opts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->hdlrBox_, nullptr);
    uint32_t frameCount = 0;
    parser->stszBox_.reset();
    ASSERT_EQ(parser->GetHeifsFrameCount(frameCount), heif_error_no_stsz);
    parser->hdlrBox_->handlerType_ = BOX_TYPE_FTYP;
    ASSERT_EQ(parser->GetHeifsFrameCount(frameCount), heif_error_not_heifs);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameCountTest002 end";
}

/**
 * @tc.name: HeifsDecoderTest001
 * @tc.desc: Create one times and Delete one times heif-sequence decoder.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, HeifsDecoderTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: HeifsDecoderTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    CreateAndDeleteHeifsSwDecoder(MOCK_TIMES_ONE, MOCK_TIMES_ONE);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: HeifsDecoderTest001 end";
}

/**
 * @tc.name: HeifsDecoderTest002
 * @tc.desc: Create two times and Delete one times heif-sequence decoder.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, HeifsDecoderTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: HeifsDecoderTest002 start";
#ifdef HEIF_HW_DECODE_ENABLE
    CreateAndDeleteHeifsSwDecoder(MOCK_TIMES_TWO, MOCK_TIMES_ONE);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: HeifsDecoderTest002 end";
}

/**
 * @tc.name: HeifsDecoderTest003
 * @tc.desc: Create two times and Delete two times heif-sequence decoder.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, HeifsDecoderTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: HeifsDecoderTest003 start";
#ifdef HEIF_HW_DECODE_ENABLE
    CreateAndDeleteHeifsSwDecoder(MOCK_TIMES_TWO, MOCK_TIMES_TWO);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: HeifsDecoderTest003 end";
}

/**
 * @tc.name: ExtractMovieImagePropertiesTest001
 * @tc.desc: ExtractMovieImageProperties when stsdBox_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, ExtractMovieImagePropertiesTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: ExtractMovieImagePropertiesTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    imageSource->opts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    std::shared_ptr<HeifImage> heifImage = std::make_shared<HeifImage>(MOCK_ITEM_ID);
    ASSERT_NE(heifImage, nullptr);
    parser->stsdBox_.reset();
    parser->ExtractMovieImageProperties(heifImage);
    ASSERT_EQ(heifImage->GetOriginalWidth(), 0);
    ASSERT_EQ(heifImage->GetOriginalHeight(), 0);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: ExtractMovieImagePropertiesTest001 end";
}

/**
 * @tc.name: IsHeifsImageTest001
 * @tc.desc: IsHeifsImage when major brand is not msf1 or hdlr is not pict.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, IsHeifsImageTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: IsHeifsImageTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    imageSource->opts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->ftypBox_, nullptr);
    ASSERT_NE(parser->hdlrBox_, nullptr);
    bool isHeifs = false;
    parser->hdlrBox_->handlerType_ = BOX_TYPE_FTYP;
    ASSERT_EQ(parser->IsHeifsImage(isHeifs), heif_error_invalid_handler);
    parser->hdlrBox_.reset();
    ASSERT_EQ(parser->IsHeifsImage(isHeifs), heif_error_invalid_handler);
    parser->ftypBox_->majorBrand_ = BOX_TYPE_FTYP;
    ASSERT_EQ(parser->IsHeifsImage(isHeifs), heif_error_invalid_major_brand);
    parser->ftypBox_.reset();
    ASSERT_EQ(parser->IsHeifsImage(isHeifs), heif_error_invalid_major_brand);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: IsHeifsImageTest001 end";
}

/**
 * @tc.name: GetHeifsMovieFrameDataTest001
 * @tc.desc: GetHeifsMovieFrameData when stsd is invalid box.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetHeifsMovieFrameDataTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsMovieFrameDataTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    imageSource->opts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->stsdBox_, nullptr);
    parser->stsdBox_->entries_.clear();
    parser->stsdBox_->entries_.shrink_to_fit();
    std::vector<uint8_t> dest;
    ASSERT_EQ(parser->GetHeifsMovieFrameData(0, dest), heif_error_no_hvcc);
    parser->stsdBox_.reset();
    ASSERT_EQ(parser->GetHeifsMovieFrameData(0, dest), heif_error_no_stsd);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsMovieFrameDataTest001 end";
}

/**
 * @tc.name: GetHeifsFrameDataTest001
 * @tc.desc: GetHeifsFrameData when stsz is invalid box.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetHeifsFrameDataTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameDataTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    imageSource->opts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->stszBox_, nullptr);
    std::vector<uint8_t> dest;
    ASSERT_EQ(parser->GetHeifsFrameData(MOCK_FRAME_INDEX, dest), heif_error_invalid_index);
    parser->stszBox_.reset();
    ASSERT_EQ(parser->GetHeifsFrameData(MOCK_FRAME_INDEX, dest), heif_error_no_stsz);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameDataTest001 end";
}

/**
 * @tc.name: GetHeifsFrameDataTest002
 * @tc.desc: GetHeifsFrameData when stco is invalid box.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetHeifsFrameDataTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameDataTest002 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    imageSource->opts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->stcoBox_, nullptr);
    std::vector<uint8_t> dest;
    parser->stcoBox_->chunkOffsets_.clear();
    parser->stcoBox_->chunkOffsets_.shrink_to_fit();
    ASSERT_EQ(parser->GetHeifsFrameData(MOCK_FRAME_INDEX, dest), heif_error_invalid_index);
    parser->stcoBox_.reset();
    ASSERT_EQ(parser->GetHeifsFrameData(MOCK_FRAME_INDEX, dest), heif_error_no_stco);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameDataTest002 end";
}

/**
 * @tc.name: GetHeifsFrameDataTest003
 * @tc.desc: Test GetHeifsFrameData when sample size larger than HEIF_MAX_SAMPLE_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetHeifsFrameDataTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameDataTest003 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(MOCK_DATA_SIZE);
    ASSERT_NE(mockData, nullptr);
    std::fill(mockData.get(), mockData.get() + MOCK_DATA_SIZE, MOCK_DATA_VALUE);
    std::shared_ptr<HeifBufferInputStream> mockBuffer =
        std::make_shared<HeifBufferInputStream>(mockData.get(), MOCK_DATA_SIZE, false);
    ASSERT_NE(mockBuffer, nullptr);
    HeifParser parser(mockBuffer);
    parser.stcoBox_ = std::make_shared<HeifStcoBox>();
    ASSERT_NE(parser.stcoBox_, nullptr);
    parser.stcoBox_->chunkOffsets_.emplace_back(0);
    parser.stszBox_ = std::make_shared<HeifStszBox>();
    ASSERT_NE(parser.stszBox_, nullptr);
    parser.stszBox_->entrySizes_.emplace_back(std::numeric_limits<uint32_t>::max());
    std::vector<uint8_t> dest;
    ASSERT_EQ(parser.GetHeifsFrameData(0, dest), heif_error_sample_size_too_large);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameDataTest003 end";
}

/**
 * @tc.name: GetHeifsFrameDataTest004
 * @tc.desc: Test GetHeifsFrameData when inputStream_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetHeifsFrameDataTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameDataTest004 start";
    HeifParser parser;
    parser.stcoBox_ = std::make_shared<HeifStcoBox>();
    ASSERT_NE(parser.stcoBox_, nullptr);
    parser.stcoBox_->chunkOffsets_.emplace_back(0);
    parser.stszBox_ = std::make_shared<HeifStszBox>();
    ASSERT_NE(parser.stszBox_, nullptr);
    parser.stszBox_->entrySizes_.emplace_back(MOCK_DATA);
    std::vector<uint8_t> dest;
    ASSERT_EQ(parser.GetHeifsFrameData(0, dest), heif_error_eof);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsFrameDataTest004 end";
}

/**
 * @tc.name: GetHeifsDelayTimeTest001
 * @tc.desc: GetHeifsDelayTime when stts is invalid box.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetHeifsDelayTimeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsDelayTimeTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    imageSource->opts_.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    parser->sttsBox_.reset();
    int32_t value = 0;
    ASSERT_EQ(parser->GetHeifsDelayTime(MOCK_FRAME_INDEX, value), heif_error_no_stts);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHeifsDelayTimeTest001 end";
}

/**
 * @tc.name: ItemMovieBoxTest001
 * @tc.desc: Test Item movie box when entry count is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, ItemMovieBoxTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: ItemMovieBoxTest001 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(MOCK_DATA_SIZE);
    ASSERT_NE(mockData, nullptr);
    std::fill(mockData.get(), mockData.get() + MOCK_DATA_SIZE, MOCK_DATA_VALUE);
    std::shared_ptr<HeifBufferInputStream> mockBuffer =
        std::make_shared<HeifBufferInputStream>(mockData.get(), MOCK_DATA_SIZE, false);
    ASSERT_NE(mockBuffer, nullptr);
    HeifStreamReader reader(mockBuffer, 0, MOCK_DATA_SIZE);
    HeifDrefBox drefBox;
    ASSERT_EQ(drefBox.ParseContent(reader), heif_error_invalid_dref);
    HeifStsdBox stsdBox;
    ASSERT_EQ(stsdBox.ParseContent(reader), heif_error_invalid_stsd);
    HeifSttsBox sttsBox;
    ASSERT_EQ(sttsBox.ParseContent(reader), heif_error_invalid_stts);
    HeifStscBox stscBox;
    ASSERT_EQ(stscBox.ParseContent(reader), heif_error_invalid_stsc);
    HeifStcoBox stcoBox;
    ASSERT_EQ(stcoBox.ParseContent(reader), heif_error_invalid_stco);
    HeifStssBox stssBox;
    ASSERT_EQ(stssBox.ParseContent(reader), heif_error_invalid_stss);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: ItemMovieBoxTest001 end";
}

/**
 * @tc.name: FullBoxParseContentAndWriteTest001
 * @tc.desc: Test Full Box Child Box when ParseContent and Write version is different.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, FullBoxParseContentAndWriteTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: FullBoxParseContentAndWriteTest001 start";
    std::vector<HeifFullBox> boxList {
        HeifMvhdBox(),
        HeifTkhdBox(),
        HeifMdhdBox(),
    };
    for (auto& box : boxList) {
        ParseContentAndWriteForFullBox(box, true);
        ParseContentAndWriteForFullBox(box, false);
    }
    GTEST_LOG_(INFO) << "HeifsDecodeTest: FullBoxParseContentAndWriteTest001 end";
}

/**
 * @tc.name: GetSampleEntryWidthHeightTest001
 * @tc.desc: Test GetSampleEntryWidthHeight when index >= entries_.size().
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetSampleEntryWidthHeightTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetSampleEntryWidthHeightTest001 start";
    HeifStsdBox box;
    uint32_t width = 0;
    uint32_t height = 0;
    ASSERT_EQ(box.GetSampleEntryWidthHeight(0, width, height), heif_error_invalid_index);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetSampleEntryWidthHeightTest001 end";
}

/**
 * @tc.name: GetSampleEntryWidthHeightTest002
 * @tc.desc: Test GetSampleEntryWidthHeight when return heif_error_ok.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetSampleEntryWidthHeightTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetSampleEntryWidthHeightTest002 start";
    HeifStsdBox box;
    uint32_t width = 0;
    uint32_t height = 0;
    std::shared_ptr<HeifBox> tmpBox;
    box.entries_.emplace_back(tmpBox);
    ASSERT_EQ(box.GetSampleEntryWidthHeight(0, width, height), heif_error_ok);
    box.entries_[0] = std::make_shared<HeifStsdBox>();
    ASSERT_NE(box.entries_[0], nullptr);
    ASSERT_EQ(box.GetSampleEntryWidthHeight(0, width, height), heif_error_ok);
    box.entries_[0].reset();
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetSampleEntryWidthHeightTest002 end";
}

/**
 * @tc.name: GetHvccBoxTest001
 * @tc.desc: Test GetHvccBox when index >= entries_.size().
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetHvccBoxTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHvccBoxTest001 start";
    HeifStsdBox box;
    ASSERT_EQ(box.GetHvccBox(0), nullptr);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHvccBoxTest001 end";
}

/**
 * @tc.name: GetHvccBoxTest002
 * @tc.desc: Test GetHvccBox when get hvcc condition is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetHvccBoxTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHvccBoxTest002 start";
    HeifStsdBox box;
    std::shared_ptr<HeifBox> tmpBox;
    box.entries_.emplace_back(tmpBox);
    ASSERT_EQ(box.GetHvccBox(0), nullptr);
    box.entries_[0] = std::make_shared<HeifStsdBox>();
    ASSERT_NE(box.entries_[0], nullptr);
    ASSERT_EQ(box.GetHvccBox(0), nullptr);
    box.entries_[0].reset();
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetHvccBoxTest002 end";
}

/**
 * @tc.name: GetDelayTimeTest001
 * @tc.desc: Test GetDelayTime when stts data is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetDelayTimeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetDelayTimeTest001 start";
    HeifSttsBox box;
    HeifSttsBox::TimeToSampleEntry tmpData;
    tmpData.sampleCount = MOCK_DATA;
    tmpData.sampleDelta = MOCK_DATA;
    box.entries_.emplace_back(tmpData);
    int32_t value = 0;
    ASSERT_EQ(box.GetDelayTime(MOCK_INDEX, value), heif_error_invalid_stts);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetDelayTimeTest001 end";
}

/**
 * @tc.name: GetChunkOffsetTest001
 * @tc.desc: Test GetChunkOffset when index is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetChunkOffsetTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetChunkOffsetTest001 start";
    HeifStcoBox box;
    uint32_t value = 0;
    ASSERT_EQ(box.GetChunkOffset(MOCK_INDEX, value), heif_error_invalid_index);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetChunkOffsetTest001 end";
}

/**
 * @tc.name: GetSampleSizeTest001
 * @tc.desc: Test GetSampleSize when index is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetSampleSizeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetSampleSizeTest001 start";
    HeifStszBox box;
    uint32_t value = 0;
    ASSERT_EQ(box.GetSampleSize(MOCK_INDEX, value), heif_error_invalid_index);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetSampleSizeTest001 end";
}

/**
 * @tc.name: GetSampleNumbersTest001
 * @tc.desc: Test GetSampleNumbers when index is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetSampleNumbersTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetSampleNumbersTest001 start";
    HeifStssBox box;
    std::vector<uint32_t> value;
    ASSERT_EQ(box.GetSampleNumbers(value), heif_error_invalid_stss);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetSampleNumbersTest001 end";
}


/**
 * @tc.name: GetSampleNumbersTest002
 * @tc.desc: Test GetSampleNumbers when sampleNumbers is not strictly increasing.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetSampleNumbersTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetSampleNumbersTest002 start";
    HeifStssBox box;
    std::vector<uint32_t> value;
    std::vector<uint32_t> sampleNumbers;
    sampleNumbers.emplace_back(MOCK_INDEX_THREE);
    box.sampleNumbers_ = sampleNumbers;
    ASSERT_EQ(box.GetSampleNumbers(value), heif_error_ok);
    sampleNumbers.emplace_back(MOCK_INDEX_TWO);
    box.sampleNumbers_ = sampleNumbers;
    ASSERT_EQ(box.GetSampleNumbers(value), heif_error_invalid_stss);
    sampleNumbers.emplace_back(MOCK_INDEX);
    box.sampleNumbers_ = sampleNumbers;
    ASSERT_EQ(box.GetSampleNumbers(value), heif_error_invalid_stss);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetSampleNumbersTest002 end";
}

/**
 * @tc.name: DoubleDecodeTest001
 * @tc.desc: Test use imagesource createPictureAtIndex double times.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, DoubleDecodeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: DoubleDecodeTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    imageSource->opts_.allocatorType = AllocatorType::DMA_ALLOC;
    std::unique_ptr<Picture> picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    imageSource->opts_.allocatorType = AllocatorType::DMA_ALLOC;
    std::unique_ptr<Picture> doublePicture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(doublePicture, nullptr);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: DoubleDecodeTest001 end";
}

/**
 * @tc.name: GetPreSampleSizeTest001
 * @tc.desc: Test GetPreSampleSize when index > deltaIndex.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetPreSampleSizeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPreSampleSizeTest001 start";
    std::unique_ptr<uint8_t[]> mockData = std::make_unique<uint8_t[]>(MOCK_DATA_SIZE);
    ASSERT_NE(mockData, nullptr);
    std::fill(mockData.get(), mockData.get() + MOCK_DATA_SIZE, MOCK_DATA_VALUE);
    std::shared_ptr<HeifBufferInputStream> mockBuffer =
        std::make_shared<HeifBufferInputStream>(mockData.get(), MOCK_DATA_SIZE, false);
    ASSERT_NE(mockBuffer, nullptr);
    HeifParser parser(mockBuffer);
    uint32_t preSampleSize = 0;
    ASSERT_EQ(parser.GetPreSampleSize(MOCK_INDEX, preSampleSize), heif_error_no_stsz);
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPreSampleSizeTest001 end";
}

/**
 * @tc.name: GetPrimaryImageFileOffsetTest001
 * @tc.desc: Test GetPrimaryImageFileOffset when item.extents is empty.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetPrimaryImageFileOffsetTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPrimaryImageFileOffsetTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_STATIC_IMAGE_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->ilocBox_, nullptr);
    ASSERT_NE(parser->ilocBox_->items_.size(), 0);
    decltype(parser->ilocBox_->items_[0].extents) mockExtents;
    std::swap(parser->ilocBox_->items_[0].extents, mockExtents);
    uint64_t offset = 0;
    ASSERT_EQ(parser->ilocBox_->GetPrimaryImageFileOffset(MOCK_ITEM_ID, offset, parser->idatBox_),
        heif_error_item_data_not_found);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPrimaryImageFileOffsetTest001 end";
}

/**
 * @tc.name: GetPrimaryImageFileOffsetTest002
 * @tc.desc: Test GetPrimaryImageFileOffset when constructionMethod is CONSTRUCTION_METHOD_FILE_OFFSET.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetPrimaryImageFileOffsetTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPrimaryImageFileOffsetTest002 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_STATIC_IMAGE_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->ilocBox_, nullptr);
    ASSERT_NE(parser->ilocBox_->items_.size(), 0);
    parser->ilocBox_->items_[0].constructionMethod = CONSTRUCTION_METHOD_FILE_OFFSET;
    uint64_t offset = 0;
    ASSERT_EQ(parser->ilocBox_->GetPrimaryImageFileOffset(MOCK_ITEM_ID, offset, parser->idatBox_), heif_error_ok);
    parser->ilocBox_->items_[0].baseOffset = std::numeric_limits<uint64_t>::max();
    ASSERT_EQ(parser->ilocBox_->GetPrimaryImageFileOffset(MOCK_ITEM_ID, offset, parser->idatBox_), heif_error_eof);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPrimaryImageFileOffsetTest002 end";
}

/**
 * @tc.name: GetPrimaryImageFileOffsetTest003
 * @tc.desc: Test GetPrimaryImageFileOffset when constructionMethod is CONSTRUCTION_METHOD_IDAT_OFFSET.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetPrimaryImageFileOffsetTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPrimaryImageFileOffsetTest003 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_STATIC_IMAGE_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->ilocBox_, nullptr);
    ASSERT_NE(parser->ilocBox_->items_.size(), 0);
    parser->ilocBox_->items_[0].constructionMethod = CONSTRUCTION_METHOD_IDAT_OFFSET;
    ASSERT_EQ(parser->idatBox_, nullptr);
    uint64_t offset = 0;
    ASSERT_EQ(parser->ilocBox_->GetPrimaryImageFileOffset(MOCK_ITEM_ID, offset, parser->idatBox_), heif_error_no_idat);
    parser->idatBox_ = std::make_shared<HeifIdatBox>();
    ASSERT_NE(parser->idatBox_, nullptr);
    ASSERT_EQ(parser->ilocBox_->GetPrimaryImageFileOffset(MOCK_ITEM_ID, offset, parser->idatBox_), heif_error_ok);
    parser->ilocBox_->items_[0].baseOffset = std::numeric_limits<uint64_t>::max();
    ASSERT_EQ(parser->ilocBox_->GetPrimaryImageFileOffset(MOCK_ITEM_ID, offset, parser->idatBox_), heif_error_eof);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPrimaryImageFileOffsetTest003 end";
}

/**
 * @tc.name: GetPrimaryImageFileOffsetTest004
 * @tc.desc: Test GetPrimaryImageFileOffset when constructionMethod is CONSTRUCTION_METHOD_OTHER_OFFSET.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetPrimaryImageFileOffsetTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPrimaryImageFileOffsetTest004 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_STATIC_IMAGE_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->ilocBox_, nullptr);
    ASSERT_NE(parser->ilocBox_->items_.size(), 0);
    parser->ilocBox_->items_[0].constructionMethod = CONSTRUCTION_METHOD_OTHER_OFFSET;
    uint64_t offset = 0;
    ASSERT_EQ(parser->ilocBox_->GetPrimaryImageFileOffset(MOCK_ITEM_ID, offset, parser->idatBox_),
        heif_error_item_data_not_found);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPrimaryImageFileOffsetTest004 end";
}

/**
 * @tc.name: GetPrimaryImageFileOffsetTest005
 * @tc.desc: Test GetPrimaryImageFileOffset when item id is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, GetPrimaryImageFileOffsetTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPrimaryImageFileOffsetTest005 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_STATIC_IMAGE_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->ilocBox_, nullptr);
    ASSERT_NE(parser->ilocBox_->items_.size(), 0);
    uint64_t offset = 0;
    ASSERT_EQ(parser->ilocBox_->GetPrimaryImageFileOffset(0, offset, parser->idatBox_),
        heif_error_primary_item_not_found);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: GetPrimaryImageFileOffsetTest005 end";
}

/**
 * @tc.name: IsNeedDecodeHeifsStaticImageTest001
 * @tc.desc: Test IsNeedDecodeHeifsStaticImage when relevant HEIF box is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, IsNeedDecodeHeifsStaticImageTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: IsNeedDecodeHeifsStaticImageTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_STATIC_IMAGE_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->ilocBox_, nullptr);
    ASSERT_NE(parser->pitmBox_, nullptr);
    ASSERT_NE(parser->stcoBox_, nullptr);
    std::shared_ptr<HeifPtimBox> pitm = parser->pitmBox_;
    parser->pitmBox_.reset();
    ASSERT_EQ(parser->IsNeedDecodeHeifsStaticImage(), false);
    parser->pitmBox_ = pitm;
    std::shared_ptr<HeifIlocBox> iloc = parser->ilocBox_;
    parser->ilocBox_.reset();
    ASSERT_EQ(parser->IsNeedDecodeHeifsStaticImage(), false);
    parser->ilocBox_ = iloc;
    std::shared_ptr<HeifStcoBox> stco = parser->stcoBox_;
    parser->stcoBox_.reset();
    ASSERT_EQ(parser->IsNeedDecodeHeifsStaticImage(), false);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: IsNeedDecodeHeifsStaticImageTest001 end";
}

/**
 * @tc.name: IsNeedDecodeHeifsStaticImageTest002
 * @tc.desc: Test IsNeedDecodeHeifsStaticImage when GetPrimaryImageFileOffset does not return heif_error_ok.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, IsNeedDecodeHeifsStaticImageTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: IsNeedDecodeHeifsStaticImageTest002 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_STATIC_IMAGE_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->ilocBox_, nullptr);
    ASSERT_NE(parser->pitmBox_, nullptr);
    ASSERT_NE(parser->stcoBox_, nullptr);
    ASSERT_NE(parser->ilocBox_->items_.size(), 0);
    parser->ilocBox_->items_[0].constructionMethod = CONSTRUCTION_METHOD_OTHER_OFFSET;
    ASSERT_EQ(parser->IsNeedDecodeHeifsStaticImage(), false);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: IsNeedDecodeHeifsStaticImageTest002 end";
}

/**
 * @tc.name: IsNeedDecodeHeifsStaticImageTest003
 * @tc.desc: Test IsNeedDecodeHeifsStaticImage when GetChunkOffset does not return heif_error_ok.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, IsNeedDecodeHeifsStaticImageTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: IsNeedDecodeHeifsStaticImageTest003 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_STATIC_IMAGE_HEIFS_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    auto picture = imageSource->CreatePictureAtIndex(0, errorCode);
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<HeifParser> parser;
    GetHeifParserFromImageSource(imageSource.get(), parser);
    ASSERT_NE(parser->ilocBox_, nullptr);
    ASSERT_NE(parser->pitmBox_, nullptr);
    ASSERT_NE(parser->stcoBox_, nullptr);
    std::vector<uint32_t> chunks;
    std::swap(parser->stcoBox_->chunkOffsets_, chunks);
    ASSERT_EQ(parser->IsNeedDecodeHeifsStaticImage(), false);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: IsNeedDecodeHeifsStaticImageTest003 end";
}

/**
 * @tc.name: CreatePixelMapTest001
 * @tc.desc: Test CreatePixelMap when heif image include moov boxes.
 * @tc.type: FUNC
 */
HWTEST_F(HeifsDecodeTest, CreatePixelMapTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HeifsDecodeTest: CreatePixelMapTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_MOOV_HEIC_PATH, sourceOptions, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions decOpts;
    auto pixelMap = imageSource->CreatePixelMap(decOpts, errorCode);
    ASSERT_NE(pixelMap, nullptr);
#endif
    GTEST_LOG_(INFO) << "HeifsDecodeTest: CreatePixelMapTest001 end";
}
} // namespace Media
} // namespace OHOS