/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include "ext_pixel_convert.h"
#include "ext_wstream.h"
#include "ext_decoder.h"
#include "plugin_export.h"
#include "image_packer.h"
#include "ext_encoder.h"
#include "ext_stream.h"
#include "image_format_convert.h"
#include "mock_data_stream.h"
#include "mock_skw_stream.h"
#include "file_source_stream.h"
#include "image_data_statistics.h"
#include "image_source.h"
#include "HeifDecoderImpl.h"
#include "heif_impl/heif_parser/heif_image.h"
#ifdef SK_ENABLE_OHOS_CODEC
#include "sk_ohoscodec.h"
#endif

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::HDI::Base;
using namespace OHOS::MultimediaPlugin;
namespace OHOS {
namespace ImagePlugin {
constexpr int32_t PIXEL_MAP_MAX_RAM_SIZE = 600 * 1024 * 1024;
constexpr static int32_t ZERO = 0;
constexpr static size_t SIZE_ZERO = 0;
constexpr static uint32_t NO_EXIF_TAG = 1;
constexpr static uint32_t OFFSET_2 = 2;
constexpr static uint32_t INVALID_ENCODE_DYNAMIC_RANGE_VALUE = 20;
#ifdef EXIF_INFO_ENABLE
constexpr static uint32_t INVALID_COLOR_TYPE = 100;
constexpr static int DEFAULT_SCALE_SIZE = 1;
constexpr static int FOURTH_SCALE_SIZE = 4;
constexpr static int MAX_SCALE_SIZE = 8;
constexpr static int SUBSET_SIZE_SMALL = 5;
constexpr static int SUBSET_SIZE_LARGE = 9;
constexpr static int DEFAULT_SAMPLE_SIZE = 10;
#endif
const static string CODEC_INITED_KEY = "CodecInited";
const static string ENCODED_FORMAT_KEY = "EncodedFormat";
const static string SUPPORT_SCALE_KEY = "SupportScale";
const static string SUPPORT_CROP_KEY = "SupportCrop";
const static string EXT_SHAREMEM_NAME = "EXT RawData";
const static string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_hw1.jpg";
static const std::string IMAGE_DEST = "/data/local/tmp/image/test_encode_out.dat";
static const std::string IMAGE_HEIFHDR_SRC = "/data/local/tmp/image/test_heif_hdr.heic";
static const std::string IMAGE_JPG_THREE_GAINMAP_HDR_PATH = "/data/local/tmp/image/three_gainmap_hdr.jpg";
static const std::string IMAGE_HEIC_THREE_GAINMAP_HDR_PATH = "/data/local/tmp/image/three_gainmap_hdr.jpg";
static const std::string IMAGE_INCOMPLETE_GIF_PATH = "/data/local/tmp/image/test_broken.gif";
class ExtDecoderTest : public testing::Test {
public:
    ExtDecoderTest() {}
    ~ExtDecoderTest() {}
};

struct MockHeifStream : public HeifStream {
    virtual size_t read(void*, size_t)
    {
        return 0;
    }
    virtual bool rewind()
    {
        return false;
    }
    virtual bool seek(size_t)
    {
        return false;
    }
    virtual bool hasLength() const
    {
        return false;
    }
    virtual size_t getLength() const
    {
        return 0;
    }
    virtual bool hasPosition() const
    {
        return false;
    }
    virtual size_t getPosition() const
    {
        return 0;
    }
};

/**
 * @tc.name: ResetTest001
 * @tc.desc: Test of Reset
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, ResetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: ResetTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    extDecoder->Reset();
    ASSERT_EQ(extDecoder->dstSubset_.fLeft, 0);
    ASSERT_EQ(extDecoder->codec_, nullptr);
    ASSERT_EQ(extDecoder->info_.isEmpty(), true);
    GTEST_LOG_(INFO) << "ExtDecoderTest: ResetTest001 end";
}

/**
 * @tc.name: CheckCodecTest001
 * @tc.desc: Test of CheckCodec
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, CheckCodecTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: CheckCodecTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    extDecoder->codec_ = nullptr;
    bool ret = extDecoder->CheckCodec();
    ASSERT_EQ(ret, false);
    extDecoder->stream_ = new MockInputDataStream;
    ret = extDecoder->CheckCodec();
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: CheckCodecTest001 end";
}

/**
 * @tc.name: GetHardwareScaledSizeTest001
 * @tc.desc: Test of GetHardwareScaledSize
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetHardwareScaledSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetHardwareScaledSizeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    int dWidth = 0;
    int dHeight = 0;
    float scale = ZERO;
    extDecoder->codec_ = nullptr;
    bool ret = extDecoder->GetHardwareScaledSize(dWidth, dHeight, scale);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetHardwareScaledSizeTest001 end";
}

/**
 * @tc.name: IsSupportScaleOnDecodeTest001
 * @tc.desc: Test of IsSupportScaleOnDecode
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, IsSupportScaleOnDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsSupportScaleOnDecodeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    extDecoder->codec_ = nullptr;
    bool ret = extDecoder->IsSupportScaleOnDecode();
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsSupportScaleOnDecodeTest001 end";
}

/**
 * @tc.name: IsSupportCropOnDecodeTest001
 * @tc.desc: Test of IsSupportCropOnDecode
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, IsSupportCropOnDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsSupportCropOnDecodeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    extDecoder->codec_ = nullptr;
    bool ret = extDecoder->IsSupportCropOnDecode();
    ASSERT_EQ(ret, false);
    SkIRect target;
    ret = extDecoder->IsSupportCropOnDecode(target);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsSupportCropOnDecodeTest001 end";
}

/**
 * @tc.name: HasPropertyTest001
 * @tc.desc: Test of HasProperty
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HasPropertyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HasPropertyTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    extDecoder->codec_ = nullptr;
    string key = CODEC_INITED_KEY;
    bool ret = extDecoder->HasProperty(key);
    ASSERT_EQ(ret, false);
    key = ENCODED_FORMAT_KEY;
    ret = extDecoder->HasProperty(key);
    ASSERT_EQ(ret, true);
    key = SUPPORT_SCALE_KEY;
    ret = extDecoder->HasProperty(key);
    ASSERT_EQ(ret, false);
    key = SUPPORT_CROP_KEY;
    ret = extDecoder->HasProperty(key);
    ASSERT_EQ(ret, false);
    key = EXT_SHAREMEM_NAME;
    ret = extDecoder->HasProperty(key);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: HasPropertyTest001 end";
}

/**
 * @tc.name: GetImageSizeTest001
 * @tc.desc: Test of GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetImageSizeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    extDecoder->codec_ = nullptr;
    uint32_t index = 0;
    Size size;
    uint32_t ret = extDecoder->GetImageSize(index, size);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    extDecoder->frameCount_ = 2;
    index = 1;
    ret = extDecoder->GetImageSize(index, size);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_HEAD_ABNORMAL);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetImageSizeTest001 end";
}

/**
 * @tc.name: CheckDecodeOptionsTest001
 * @tc.desc: Test of CheckDecodeOptions IsValidCrop
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, CheckDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: CheckDecodeOptionsTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint32_t index = 0;
    PixelDecodeOptions opts;
    uint32_t ret = extDecoder->CheckDecodeOptions(index, opts);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);

    extDecoder->dstInfo_.fDimensions = {1, 1};
    extDecoder->dstInfo_.fColorInfo.fColorType = SkColorType::kAlpha_8_SkColorType;
    opts.CropRect.left = -1;
    opts.CropRect.top = -1;
    ret = extDecoder->CheckDecodeOptions(index, opts);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);

    opts.CropRect.left = 0;
    opts.CropRect.top = 0;
    opts.CropRect.width = 1;
    opts.CropRect.height = 1;
    extDecoder->info_.fDimensions = {0, 0};
    ret = extDecoder->CheckDecodeOptions(index, opts);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: CheckDecodeOptionsTest001 end";
}

/**
 * @tc.name: SetDecodeOptionsTest001
 * @tc.desc: Test of SetDecodeOptions
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, SetDecodeOptionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: SetDecodeOptionsTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint32_t index = ZERO;
    PixelDecodeOptions opts;
    PlImageInfo info;
    extDecoder->codec_ = nullptr;
    uint32_t ret = extDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    extDecoder->frameCount_ = 1;
    opts.sampleSize = OFFSET_2;
    ret = extDecoder->SetDecodeOptions(index, opts, info);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ExtDecoderTest: SetDecodeOptionsTest001 end";
}

/**
 * @tc.name: SetContextPixelsBufferTest001
 * @tc.desc: Test of SetContextPixelsBuffer ShareMemAlloc DmaMemAlloc
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, SetContextPixelsBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: SetContextPixelsBufferTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint64_t byteCount = ZERO;
    DecodeContext context;
    uint32_t ret = extDecoder->SetContextPixelsBuffer(byteCount, context);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    byteCount = 128;
    ret = extDecoder->SetContextPixelsBuffer(byteCount, context);
    ASSERT_EQ(ret, SUCCESS);
    context.allocatorType = Media::AllocatorType::DMA_ALLOC;
    ret = extDecoder->SetContextPixelsBuffer(byteCount, context);
    ASSERT_EQ(ret, ERR_DMA_NOT_EXIST);
    context.allocatorType = Media::AllocatorType::CUSTOM_ALLOC;
    byteCount = PIXEL_MAP_MAX_RAM_SIZE + 1;
    ret = extDecoder->SetContextPixelsBuffer(byteCount, context);
    ASSERT_EQ(ret, ERR_IMAGE_DATA_ABNORMAL);
    byteCount = 128;
    ret = extDecoder->SetContextPixelsBuffer(byteCount, context);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: SetContextPixelsBufferTest001 end";
}

/**
 * @tc.name: PreDecodeCheckTest001
 * @tc.desc: Test of PreDecodeCheck
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, PreDecodeCheckTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: PreDecodeCheckTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint32_t index = 0;
    extDecoder->codec_ = nullptr;
    uint32_t ret = extDecoder->PreDecodeCheck(index);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ExtDecoderTest: PreDecodeCheckTest001 end";
}

/**
 * @tc.name: DecodeTest001
 * @tc.desc: Test of Decode
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, DecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: DecodeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint32_t index = 0;
    DecodeContext context;
    const int fd = open("/data/local/tmp/image/test_hw1.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    ASSERT_NE(extDecoder->codec_, nullptr);
    uint32_t ret = extDecoder->Decode(index, context);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_FAILED);
    GTEST_LOG_(INFO) << "ExtDecoderTest: DecodeTest001 end";
}

/**
 * @tc.name: ReportImageTypeTest001
 * @tc.desc: Test of ReportImageType GetFormatStr
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, ReportImageTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: ReportImageTypeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    ASSERT_NE(extDecoder, nullptr);
    EXIFInfo exifInfo_;
    SkEncodedImageFormat skEncodeFormat = SkEncodedImageFormat::kBMP;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kGIF;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kICO;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kJPEG;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kPNG;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kWBMP;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kWEBP;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kPKM;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kKTX;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kASTC;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kDNG;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kHEIF;
    extDecoder->ReportImageType(skEncodeFormat);
    skEncodeFormat = SkEncodedImageFormat::kAVIF;
    extDecoder->ReportImageType(skEncodeFormat);
    GTEST_LOG_(INFO) << "ExtDecoderTest: ReportImageTypeTest001 end";
}

/**
 * @tc.name: ConvertInfoToAlphaTypeTest001
 * @tc.desc: Test of ConvertInfoToAlphaType
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, ConvertInfoToAlphaTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: ConvertInfoToAlphaTypeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    SkAlphaType alphaType;
    AlphaType outputType;
    bool ret = extDecoder->ConvertInfoToAlphaType(alphaType, outputType);
    ASSERT_EQ(extDecoder->info_.isEmpty(), true);
    ASSERT_EQ(ret, false);
    extDecoder->info_.fDimensions = {2, 2};
    ret = extDecoder->ConvertInfoToAlphaType(alphaType, outputType);
    ASSERT_EQ(extDecoder->info_.isEmpty(), false);
    ASSERT_EQ(ret, false);
    extDecoder->info_.fColorInfo.fAlphaType = kPremul_SkAlphaType;
    ret = extDecoder->ConvertInfoToAlphaType(alphaType, outputType);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExtDecoderTest: ConvertInfoToAlphaTypeTest001 end";
}

/**
 * @tc.name: ConvertInfoToColorTypeTest001
 * @tc.desc: Test of ConvertInfoToColorType
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, ConvertInfoToColorTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: ConvertInfoToColorTypeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    SkColorType format;
    PixelFormat outputFormat;
    bool ret = extDecoder->ConvertInfoToColorType(format, outputFormat);
    ASSERT_EQ(extDecoder->info_.isEmpty(), true);
    ASSERT_EQ(ret, false);
    extDecoder->info_.fDimensions = {2, 2};
    ret = extDecoder->ConvertInfoToColorType(format, outputFormat);
    ASSERT_EQ(extDecoder->info_.isEmpty(), false);
    ASSERT_EQ(ret, false);
    extDecoder->info_.fColorInfo.fColorType = kRGBA_8888_SkColorType;
    ret = extDecoder->ConvertInfoToColorType(format, outputFormat);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExtDecoderTest: ConvertInfoToColorTypeTest001 end";
}

/**
 * @tc.name: ConvertToAlphaTypeTest001
 * @tc.desc: Test of ConvertToAlphaType
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, ConvertToAlphaTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: ConvertToAlphaTypeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    AlphaType desiredType;
    AlphaType outputType;
    desiredType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    auto ret = extDecoder->ConvertToAlphaType(desiredType, outputType);
    ASSERT_EQ(outputType, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
    ASSERT_EQ(ret, SkAlphaType::kOpaque_SkAlphaType);

    desiredType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    ret = extDecoder->ConvertToAlphaType(desiredType, outputType);
    ASSERT_EQ(outputType, AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    ASSERT_EQ(ret, SkAlphaType::kPremul_SkAlphaType);

    extDecoder->info_.fDimensions = {2, 2};
    extDecoder->info_.fColorInfo.fAlphaType = kPremul_SkAlphaType;
    ret = extDecoder->ConvertToAlphaType(desiredType, outputType);
    ASSERT_EQ(ret, SkAlphaType::kPremul_SkAlphaType);
    GTEST_LOG_(INFO) << "ExtDecoderTest: ConvertToAlphaTypeTest001 end";
}

/**
 * @tc.name: ConvertToColorTypeTest001
 * @tc.desc: Test of ConvertToColorType
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, ConvertToColorTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: ConvertToColorTypeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    PixelFormat format;
    PixelFormat outputFormat;
    format = PixelFormat::RGBA_8888;
    auto ret = extDecoder->ConvertToColorType(format, outputFormat);
    ASSERT_EQ(outputFormat, PixelFormat::RGBA_8888);
    ASSERT_EQ(ret, kRGBA_8888_SkColorType);

    format = PixelFormat::UNKNOWN;
    ret = extDecoder->ConvertToColorType(format, outputFormat);
    ASSERT_EQ(outputFormat, PixelFormat::RGBA_8888);
    ASSERT_EQ(ret, kRGBA_8888_SkColorType);

    extDecoder->info_.fDimensions = {2, 2};
    extDecoder->info_.fColorInfo.fColorType = kRGBA_8888_SkColorType;
    ret = extDecoder->ConvertToColorType(format, outputFormat);
    ASSERT_EQ(ret, kRGBA_8888_SkColorType);
    GTEST_LOG_(INFO) << "ExtDecoderTest: ConvertToColorTypeTest001 end";
}

/**
 * @tc.name: GetPropertyCheckTest001
 * @tc.desc: Test of GetPropertyCheck
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetPropertyCheckTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetPropertyCheckTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint32_t index = 0;
    std::string key = ACTUAL_IMAGE_ENCODED_FORMAT;
    uint32_t res = 0;
    bool ret = extDecoder->GetPropertyCheck(index, key, res);
    ASSERT_EQ(res, Media::ERR_MEDIA_VALUE_INVALID);
    ASSERT_EQ(ret, false);
    key = "format";
    extDecoder->codec_ = nullptr;
    ret = extDecoder->GetPropertyCheck(index, key, res);
    ASSERT_EQ(res, Media::ERR_IMAGE_DECODE_HEAD_ABNORMAL);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetPropertyCheckTest001 end";
}

/**
 * @tc.name: GetImagePropertyIntTest001
 * @tc.desc: Test of GetImagePropertyInt
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetImagePropertyIntTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetImagePropertyIntTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint32_t index = 0;
    std::string key = ACTUAL_IMAGE_ENCODED_FORMAT;
    int32_t value = 0;
    uint32_t ret = extDecoder->GetImagePropertyInt(index, key, value);
    ASSERT_EQ(ret, Media::ERR_MEDIA_VALUE_INVALID);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetImagePropertyIntTest001 end";
}

/**
 * @tc.name: GetMakerImagePropertyStringTest001
 * @tc.desc: Test of GetMakerImagePropertyString
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetMakerImagePropertyStringTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetMakerImagePropertyStringTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    std::string key = "string";
    std::string value = "propretyString";
    uint32_t ret = extDecoder->GetMakerImagePropertyString(key, value);
    ASSERT_EQ(ret, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    extDecoder->exifInfo_.makerInfoTagValueMap.insert(pair<std::string, std::string>
        ("getMaker", "getMakerImagePropertyString"));
    key = "getMaker";
    ret = extDecoder->GetMakerImagePropertyString(key, value);
    ASSERT_EQ(value, "getMakerImagePropertyString");
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetMakerImagePropertyStringTest001 end";
}

/**
 * @tc.name: ModifyImagePropertyTest001
 * @tc.desc: Test of ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, ModifyImagePropertyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: ModifyImagePropertyTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint32_t index = 0;
    std::string key = "Path";
    std::string value = "void";
    std::string path = "void";
    uint32_t ret = extDecoder->ModifyImageProperty(index, key, value, path);
    ASSERT_EQ(ret, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    int fd = 0;
    ret = extDecoder->ModifyImageProperty(index, key, value, fd);
    ASSERT_EQ(ret, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    uint8_t *data = nullptr;
    uint32_t size = 0;
    ret = extDecoder->ModifyImageProperty(index, key, value, data, size);
    ASSERT_EQ(ret, Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);
    GTEST_LOG_(INFO) << "ExtDecoderTest: ModifyImagePropertyTest001 end";
}

/**
 * @tc.name: GetFilterAreaTest001
 * @tc.desc: Test of GetFilterArea
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetFilterAreaTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetFilterAreaTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    int privacyType = 0;
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    extDecoder->codec_ = nullptr;
    uint32_t ret = extDecoder->GetFilterArea(privacyType, ranges);
    ASSERT_EQ(ret, NO_EXIF_TAG);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetFilterAreaTest001 end";
}

/**
 * @tc.name: GetTopLevelImageNumTest001
 * @tc.desc: Test of GetTopLevelImageNum
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetTopLevelImageNumTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetTopLevelImageNumTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint32_t num = 0;
    extDecoder->codec_ = nullptr;
    uint32_t ret = extDecoder->GetTopLevelImageNum(num);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_HEAD_ABNORMAL);
    extDecoder->frameCount_ = 1;
    ret = extDecoder->GetTopLevelImageNum(num);
    ASSERT_EQ(num, extDecoder->frameCount_);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetTopLevelImageNumTest001 end";
}

/**
 * @tc.name: IsSupportHardwareDecodeTest001
 * @tc.desc: Test of IsSupportHardwareDecode
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, IsSupportHardwareDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsSupportHardwareDecodeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    extDecoder->codec_ = nullptr;
    bool ret = extDecoder->IsSupportHardwareDecode();
    ASSERT_EQ(extDecoder->info_.isEmpty(), true);
    ASSERT_EQ(ret, false);

    const int fd = open("/data/local/tmp/image/test_hw1.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    ASSERT_NE(extDecoder->codec_, nullptr);
    extDecoder->info_.fDimensions = {2, 2};
    ret = extDecoder->IsSupportHardwareDecode();
    ASSERT_EQ(extDecoder->info_.isEmpty(), false);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsSupportHardwareDecodeTest001 end";
}

/**
 * @tc.name: RGBxToRGBTest001
 * @tc.desc: Test of RGBxToRGB
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, RGBxToRGBTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: RGBxToRGBTest001 start";
    ExtPixels src;
    ExtPixels dst;
    src.data = new uint8_t;
    dst.data = new uint8_t;
    src.byteCount = 5;
    uint32_t ret = ExtPixelConvert::RGBxToRGB(src, dst);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    src.byteCount = 4;
    dst.byteCount = 2;
    ret = ExtPixelConvert::RGBxToRGB(src, dst);
    ASSERT_EQ(ret, ERR_IMAGE_TOO_LARGE);
    dst.byteCount = 4;
    ret = ExtPixelConvert::RGBxToRGB(src, dst);
    ASSERT_EQ(ret, SUCCESS);
    delete src.data;
    delete dst.data;
    GTEST_LOG_(INFO) << "ExtDecoderTest: RGBxToRGBTest001 end";
}

/**
 * @tc.name: RGBToRGBxTest001
 * @tc.desc: Test of RGBToRGBx
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, RGBToRGBxTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: RGBToRGBxTest001 start";
    ExtPixels src;
    ExtPixels dst;
    src.data = new uint8_t;
    dst.data = new uint8_t;
    src.byteCount = 4;
    uint32_t ret = ExtPixelConvert::RGBToRGBx(src, dst);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    src.byteCount = 3;
    dst.byteCount = 3;
    ret = ExtPixelConvert::RGBToRGBx(src, dst);
    ASSERT_EQ(ret, ERR_IMAGE_TOO_LARGE);
    dst.byteCount = 5;
    ret = ExtPixelConvert::RGBToRGBx(src, dst);
    ASSERT_EQ(ret, SUCCESS);
    delete src.data;
    delete dst.data;
    GTEST_LOG_(INFO) << "ExtDecoderTest: RGBToRGBxTest001 end";
}

/**
 * @tc.name: writeTest001
 * @tc.desc: Test of write
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, writeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: writeTest001 start";
    ExtWStream extWStream;
    std::string str = "write";
    void* buffer = &str;
    size_t size = 128;
    extWStream.stream_ = nullptr;
    bool ret = extWStream.write(buffer, size);
    ASSERT_EQ(ret, false);
    extWStream.stream_ = new MockOutputDataStream;
    ret = extWStream.write(buffer, size);
    ASSERT_NE(extWStream.stream_, nullptr);
    ASSERT_EQ(ret, false);
    delete extWStream.stream_;
    GTEST_LOG_(INFO) << "ExtDecoderTest: writeTest001 end";
}

/**
 * @tc.name: flushTest001
 * @tc.desc: Test of flush
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, flushTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: flushTest001 start";
    ExtWStream extWStream;
    extWStream.stream_ = nullptr;
    extWStream.flush();
    extWStream.stream_ = new MockOutputDataStream;
    extWStream.flush();
    ASSERT_NE(extWStream.stream_, nullptr);
    delete extWStream.stream_;
    GTEST_LOG_(INFO) << "ExtDecoderTest: flushTest001 end";
}

/**
 * @tc.name: bytesWrittenTest001
 * @tc.desc: Test of bytesWritten
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, bytesWrittenTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: bytesWrittenTest001 start";
    ExtWStream extWStream;
    extWStream.stream_ = nullptr;
    size_t ret = extWStream.bytesWritten();
    ASSERT_EQ(ret, SIZE_ZERO);
    extWStream.stream_ = new MockOutputDataStream;
    ret = extWStream.bytesWritten();
    ASSERT_NE(extWStream.stream_, nullptr);
    ASSERT_EQ(ret, SIZE_ZERO);
    delete extWStream.stream_;
    GTEST_LOG_(INFO) << "ExtDecoderTest: bytesWrittenTest001 end";
}

/**
 * @tc.name: PluginExternalCreateTest001
 * @tc.desc: Test of PluginExternalCreate
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, PluginExternalCreateTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: PluginExternalCreateTest001 start";
    string className = "ClassName";
    auto ret = PluginExternalCreate(className);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "ExtDecoderTest: PluginExternalCreateTest001 end";
}

/**
 * @tc.name: FinalizeEncodeTest001
 * @tc.desc: Test of FinalizeEncode
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, FinalizeEncodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: FinalizeEncodeTest001 start";
    ExtEncoder extEncoder;
    uint32_t ret = extEncoder.FinalizeEncode();
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    extEncoder.pixelmap_ = new PixelMap;
    extEncoder.output_ = new MockOutputDataStream;
    extEncoder.opts_.format = "image/";
    ret = extEncoder.FinalizeEncode();
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    extEncoder.opts_.format = "image/jpeg";
    ret = extEncoder.FinalizeEncode();
    ASSERT_EQ(ret, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "ExtDecoderTest: FinalizeEncodeTest001 end";
}

/**
 * @tc.name: FinalizeEncodeTest002
 * @tc.desc: Verify FinalizePacking() returns expected error with invalid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, FinalizeEncodeTest002, TestSize.Level3)
{
    ImagePacker pack;
    PackOption option;
    option.format = "image/jpeg";
    uint32_t ret = pack.StartPacking(IMAGE_DEST, option);
    ASSERT_EQ(ret, OHOS::Media::SUCCESS);
    ret = pack.FinalizePacking();
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: readTest001
 * @tc.desc: Test of read
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, readTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: readTest001 start";
    ExtStream extStream;
    void *buffer = nullptr;
    size_t size = 0;
    extStream.stream_ = nullptr;
    size_t ret = extStream.read(buffer, size);
    ASSERT_EQ(ret, SIZE_ZERO);
    extStream.stream_ = new MockInputDataStream;
    ret = extStream.read(buffer, size);
    ASSERT_NE(extStream.stream_, nullptr);
    ASSERT_EQ(ret, SIZE_ZERO);
    GTEST_LOG_(INFO) << "ExtDecoderTest: readTest001 end";
}

/**
 * @tc.name: CheckCodecTest002
 * @tc.desc: Test of CheckCodec
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, CheckCodecTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: CheckCodecTest002 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    const int fd = open("/data/local/tmp/image/test_hw1.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExtDecoderTest: CheckCodecTest002 end";
}

/**
 * @tc.name: GetHardwareScaledSizeTest002
 * @tc.desc: Test of GetHardwareScaledSize
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetHardwareScaledSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetHardwareScaledSizeTest002 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    extDecoder->info_.fDimensions = {20, 20};
    ASSERT_EQ(extDecoder->info_.isEmpty(), false);
    float scale = ZERO;
    int dWidth = 2;
    int dHeight = 1;
    bool ret = extDecoder->GetHardwareScaledSize(dWidth, dHeight, scale);
    ASSERT_EQ(ret, true);
    dWidth = 4;
    dHeight = 2;
    ret = extDecoder->GetHardwareScaledSize(dWidth, dHeight, scale);
    ASSERT_EQ(ret, true);
    dWidth = 6;
    dHeight = 3;
    ret = extDecoder->GetHardwareScaledSize(dWidth, dHeight, scale);
    ASSERT_EQ(ret, true);
    dWidth = 20;
    dHeight = 10;
    ret = extDecoder->GetHardwareScaledSize(dWidth, dHeight, scale);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetHardwareScaledSizeTest002 end";
}

/**
 * @tc.name: PreDecodeCheckTest002
 * @tc.desc: Test of PreDecodeCheck
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, PreDecodeCheckTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: PreDecodeCheckTest002 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint32_t index = 0;
    extDecoder->codec_ = nullptr;
    uint32_t ret = extDecoder->PreDecodeCheck(index);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);

    extDecoder->frameCount_ = 1;
    ret = extDecoder->PreDecodeCheck(index);
    ASSERT_EQ(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_FAILED);

    const int fd = open("/data/local/tmp/image/test_hw1.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    ASSERT_NE(extDecoder->codec_, nullptr);
    ret = extDecoder->PreDecodeCheck(index);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_FAILED);

    extDecoder->dstInfo_.fDimensions = {1, 1};
    ret = extDecoder->PreDecodeCheck(index);
    ASSERT_EQ(extDecoder->dstInfo_.isEmpty(), false);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: PreDecodeCheckTest002 end";
}

/**
 * @tc.name: PreDecodeCheckYuvTest001
 * @tc.desc: Test of PreDecodeCheckYuv
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, PreDecodeCheckYuvTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: PreDecodeCheckYuvTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    extDecoder->codec_ = nullptr;
    uint32_t index = 0;
    PixelFormat desiredFormat = PixelFormat::UNKNOWN;
    uint32_t ret = extDecoder->PreDecodeCheckYuv(index, desiredFormat);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);

    extDecoder->frameCount_ = 1;
    const int fd = open("/data/local/tmp/image/test_hw1.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    ASSERT_NE(extDecoder->codec_, nullptr);
    extDecoder->dstInfo_.fDimensions = {1, 1};
    ASSERT_EQ(extDecoder->dstInfo_.isEmpty(), false);
    extDecoder->stream_ = nullptr;
    ret = extDecoder->PreDecodeCheckYuv(index, desiredFormat);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);

    MockInputDataStream inputDataStream;
    extDecoder->stream_ = &inputDataStream;
    ret = extDecoder->PreDecodeCheckYuv(index, desiredFormat);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);

    desiredFormat = PixelFormat::NV21;
    ret = extDecoder->PreDecodeCheckYuv(index, desiredFormat);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ExtDecoderTest: PreDecodeCheckYuvTest001 end";
}

/**
 * @tc.name: ReadJpegDataTest001
 * @tc.desc: Test of ReadJpegData
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, ReadJpegDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: ReadJpegDataTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    uint8_t *jpegBuffer = nullptr;
    uint32_t jpegBufferSize = 0;
    extDecoder->stream_ = nullptr;
    uint32_t ret = extDecoder->ReadJpegData(jpegBuffer, jpegBufferSize);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);

    MockInputDataStream inputDataStream;
    extDecoder->stream_ = &inputDataStream;
    ret = extDecoder->ReadJpegData(jpegBuffer, jpegBufferSize);
    ASSERT_EQ(ret, ERR_IMAGE_GET_DATA_ABNORMAL);

    uint8_t buffer = 16;
    jpegBuffer = &buffer;
    jpegBufferSize = 128;
    ret = extDecoder->ReadJpegData(jpegBuffer, jpegBufferSize);
    ASSERT_EQ(extDecoder->stream_->Seek(0), false);
    ASSERT_EQ(ret, ERR_IMAGE_GET_DATA_ABNORMAL);

    inputDataStream.returnValue_ = true;
    ASSERT_EQ(extDecoder->stream_->Seek(0), true);
    ret = extDecoder->ReadJpegData(jpegBuffer, jpegBufferSize);
    ASSERT_EQ(ret, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ExtDecoderTest: ReadJpegDataTest001 end";
}

/**
 * @tc.name: GetJpegYuvOutFmtTest001
 * @tc.desc: Test of GetJpegYuvOutFmt
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetJpegYuvOutFmtTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetJpegYuvOutFmtTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    PixelFormat desiredFormat = PixelFormat::UNKNOWN;
    auto ret = extDecoder->GetJpegYuvOutFmt(desiredFormat);
    ASSERT_EQ(ret, JpegYuvFmt::OutFmt_NV12);
    desiredFormat = PixelFormat::NV12;
    ret = extDecoder->GetJpegYuvOutFmt(desiredFormat);
    ASSERT_EQ(ret, JpegYuvFmt::OutFmt_NV12);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetJpegYuvOutFmtTest001 end";
}

/**
@tc.name: IsHardwareEncodeSupportedTest001
@tc.desc: Test of IsHardwareEncodeSupported
@tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, IsHardwareEncodeSupportedTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsHardwareEncodeSupportedTest001 start";
    ExtEncoder extEncoder;
    const PlEncodeOptions opts;
    Media::PixelMap* pixelMap = nullptr;
    bool ret = extEncoder.IsHardwareEncodeSupported(opts, pixelMap);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsHardwareEncodeSupportedTest001 end";
}

/**
 * @tc.name: IsHardwareEncodeSupportedTest002
 * @tc.desc: Verify hardware encoding is not supported with invalid PixelMap parameter.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, IsHardwareEncodeSupportedTest002, TestSize.Level3)
{
    ExtEncoder encoder;
    PlEncodeOptions opts;
    Media::PixelMap *pixelMap = nullptr;
    bool res = encoder.IsHardwareEncodeSupported(opts, pixelMap);
    EXPECT_FALSE(res);
}

/**
@tc.name: DoHardWareEncodeTest001
@tc.desc: Test of DoHardWareEncode
@tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, DoHardWareEncodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: DoHardWareEncodeTest001 start";
    ExtEncoder extEncoder;
    MockSkWStream* skStream = nullptr;
    Media::PixelMap pixelMap;
    extEncoder.pixelmap_ = &pixelMap;
    uint32_t ret = extEncoder.DoHardWareEncode(skStream);
    ASSERT_EQ(ret, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "ExtDecoderTest: DoHardWareEncodeTest001 end";
}

/**
@tc.name: EncodeImageBySurfaceBufferTest001
@tc.desc: Test of EncodeImageBySurfaceBuffer
@tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, EncodeImageBySurfaceBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeImageBySurfaceBufferTest001 start";
    ExtEncoder extEncoder;
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    SkImageInfo info;
    bool needExif = false;
    MockSkWStream mockSkWStream;
    uint32_t ret = extEncoder.EncodeImageBySurfaceBuffer(surfaceBuffer, info, needExif, mockSkWStream);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    surfaceBuffer = SurfaceBuffer::Create();
    ASSERT_NE(surfaceBuffer, nullptr);
    ret = extEncoder.EncodeImageBySurfaceBuffer(surfaceBuffer, info, needExif, mockSkWStream);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    auto result = extEncoder.GetImageEncodeData(surfaceBuffer, info, needExif);
    ASSERT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeImageBySurfaceBufferTest001 end";
}

/**
@tc.name: EncodeSingleVividTest001
@tc.desc: Test of EncodeSingleVivid
@tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, EncodeSingleVividTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeSingleVividTest001 start";
    ExtEncoder extEncoder;
    ExtWStream outputStream;
    uint32_t ret = extEncoder.EncodeSingleVivid(outputStream);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeSingleVividTest001 end";
}

/**
@tc.name: EncodeDualVividTest001
@tc.desc: Test of EncodeDualVivid
@tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, EncodeDualVividTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeDualVividTest001 start";
    ExtEncoder extEncoder;
    ExtWStream outputStream;
    Media::PixelMap pixelMap;
    extEncoder.pixelmap_ = &pixelMap;
    extEncoder.pixelmap_->imageInfo_.pixelFormat = Media::PixelFormat::UNKNOWN;
    uint32_t ret = extEncoder.EncodeDualVivid(outputStream);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    extEncoder.pixelmap_->imageInfo_.pixelFormat = Media::PixelFormat::RGBA_1010102;
    extEncoder.encodeFormat_ = SkEncodedImageFormat::kJPEG;
    extEncoder.pixelmap_->allocatorType_ = AllocatorType::DEFAULT;
    ret = extEncoder.EncodeDualVivid(outputStream);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    extEncoder.pixelmap_->allocatorType_ = AllocatorType::DMA_ALLOC;
    extEncoder.encodeFormat_ = SkEncodedImageFormat::kHEIF;
    ret = extEncoder.EncodeDualVivid(outputStream);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeDualVividTest001 end";
}

/**
@tc.name: EncodeSdrImageTest001
@tc.desc: Test of EncodeSdrImage
@tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, EncodeSdrImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeSdrImageTest001 start";
    ExtEncoder extEncoder;
    ExtWStream outputStream;
    Media::PixelMap pixelMap;
    extEncoder.pixelmap_ = &pixelMap;
    extEncoder.pixelmap_->imageInfo_.pixelFormat = Media::PixelFormat::UNKNOWN;
    uint32_t ret = extEncoder.EncodeSdrImage(outputStream);
    extEncoder.pixelmap_->imageInfo_.pixelFormat = Media::PixelFormat::RGBA_1010102;
    ret = extEncoder.EncodeSdrImage(outputStream);
    ASSERT_EQ(ret, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeSdrImageTest001 end";
}

/**
 * @tc.name: DataStatisticsNullTest
 * @tc.desc: test DataStatistics Null
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, DataStatisticsNUllTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: DataStatisticsNUllTest start";
    ImageDataStatistics imageDataStatistics(nullptr);
    ASSERT_EQ(imageDataStatistics.title_, "ImageDataTraceFmt Param invalid");
    GTEST_LOG_(INFO) << "ExtDecoderTest: DataStatisticsNUllTest end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of WriteJpegCodedData
             when auxPicture == nullptr, return ERR_IMAGE_DATA_ABNORMAL
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, WriteJpegCodedDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegCodedDataTest001 start";
    ExtEncoder extEncoder;
    auto auxPicture = std::make_shared<AuxiliaryPicture>();
    auxPicture = nullptr;
    MockSkWStream skStream;
    uint32_t ret = extEncoder.WriteJpegCodedData(auxPicture, skStream);
    ASSERT_EQ(ret, ERR_IMAGE_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegCodedDataTest001 end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of WriteJpegUncodedData
             when auxPicture == nullptr, return ERR_IMAGE_ENCODE_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, WriteJpegUncodedDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest001 start";
    ExtEncoder extEncoder;
    auto auxPicture = std::make_shared<AuxiliaryPicture>();
    auxPicture = nullptr;
    MockSkWStream skStream;
    uint32_t ret = extEncoder.WriteJpegUncodedData(auxPicture, skStream);
    ASSERT_EQ(ret, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest001 end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of WriteJpegCodedData
             when pixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC
             and pixelMap->GetFd() != nullptr, return SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, WriteJpegCodedDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegCodedDataTest002 start";
    ExtEncoder extEncoder;
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> tmpPixelMap = PixelMap::Create(color, 8, options);
    std::shared_ptr<PixelMap> pixelMap = std::move(tmpPixelMap);
    ASSERT_NE(pixelMap->GetAllocatorType(), AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap->GetFd(), nullptr);
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {2, 3};
    std::unique_ptr<AuxiliaryPicture> tmpAuxPicture = AuxiliaryPicture::Create(pixelMap, type, size);
    std::shared_ptr<AuxiliaryPicture> auxPicture = std::move(tmpAuxPicture);
    MockSkWStream skStream;
    uint32_t ret = extEncoder.WriteJpegCodedData(auxPicture, skStream);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegCodedDataTest002 end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of WriteJpegUncodedData
             when pixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC
             and pixelMap->GetFd() != nullptr, return SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, WriteJpegUncodedDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest002 start";
    ExtEncoder extEncoder;
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> tmpPixelMap = PixelMap::Create(color, 8, options);
    std::shared_ptr<PixelMap> pixelMap = std::move(tmpPixelMap);
    ASSERT_NE(pixelMap->GetAllocatorType(), AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap->GetFd(), nullptr);
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {2, 3};
    std::unique_ptr<AuxiliaryPicture> tmpAuxPicture = AuxiliaryPicture::Create(pixelMap, type, size);
    std::shared_ptr<AuxiliaryPicture> auxPicture = std::move(tmpAuxPicture);
    MockSkWStream skStream;
    uint32_t ret = extEncoder.WriteJpegUncodedData(auxPicture, skStream);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest002 end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of WriteJpegCodedData
             when pixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC
             and pixelMap->GetFd() == nullptr, return SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, WriteJpegCodedDataTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegCodedDataTest003 start";
    ExtEncoder extEncoder;
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> tmpPixelMap = PixelMap::Create(color, 8, options);
    std::shared_ptr<PixelMap> pixelMap = std::move(tmpPixelMap);
    ASSERT_NE(pixelMap->GetAllocatorType(), AllocatorType::DMA_ALLOC);
    pixelMap->context_ = nullptr;
    ASSERT_EQ(pixelMap->GetFd(), nullptr);
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {2, 3};
    std::unique_ptr<AuxiliaryPicture> tmpAuxPicture = AuxiliaryPicture::Create(pixelMap, type, size);
    std::shared_ptr<AuxiliaryPicture> auxPicture = std::move(tmpAuxPicture);
    MockSkWStream skStream;
    uint32_t ret = extEncoder.WriteJpegCodedData(auxPicture, skStream);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegCodedDataTest003 end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of WriteJpegUncodedData
             when pixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC
             and pixelMap->GetFd() == nullptr, return SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, WriteJpegUncodedDataTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest003 start";
    ExtEncoder extEncoder;
    const uint32_t color[8] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    InitializationOptions options;
    options.size.width = 2;
    options.size.height = 3;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> tmpPixelMap = PixelMap::Create(color, 8, options);
    std::shared_ptr<PixelMap> pixelMap = std::move(tmpPixelMap);
    ASSERT_NE(pixelMap->GetAllocatorType(), AllocatorType::DMA_ALLOC);
    pixelMap->context_ = nullptr;
    ASSERT_EQ(pixelMap->GetFd(), nullptr);
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {2, 3};
    std::unique_ptr<AuxiliaryPicture> tmpAuxPicture = AuxiliaryPicture::Create(pixelMap, type, size);
    std::shared_ptr<AuxiliaryPicture> auxPicture = std::move(tmpAuxPicture);
    MockSkWStream skStream;
    uint32_t ret = extEncoder.WriteJpegUncodedData(auxPicture, skStream);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest003 end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of WriteJpegCodedData
             when pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC
             and pixelMap->GetFd() != nullptr, return ERR_IMAGE_ENCODE_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, WriteJpegCodedDataTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegCodedDataTest004 start";
    ExtEncoder extEncoder;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.allocatorType = AllocatorType::DMA_ALLOC;
    std::unique_ptr<PixelMap> tmpPixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(tmpPixelMap, nullptr);
    std::shared_ptr<PixelMap> pixelMap = std::move(tmpPixelMap);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_EQ(pixelMap->GetAllocatorType(), AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap->GetFd(), nullptr);
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {2, 3};
    std::unique_ptr<AuxiliaryPicture> tmpAuxPicture = AuxiliaryPicture::Create(pixelMap, type, size);
    std::shared_ptr<AuxiliaryPicture> auxPicture = std::move(tmpAuxPicture);
    MockSkWStream skStream;
    uint32_t ret = extEncoder.WriteJpegCodedData(auxPicture, skStream);
    ASSERT_EQ(ret, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegCodedDataTest004 end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of WriteJpegUncodedData
             when pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC
             and pixelMap->GetFd() != nullptr, return SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, WriteJpegUncodedDataTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest004 start";
    ExtEncoder extEncoder;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.allocatorType = AllocatorType::DMA_ALLOC;
    std::unique_ptr<PixelMap> tmpPixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(tmpPixelMap, nullptr);
    std::shared_ptr<PixelMap> pixelMap = std::move(tmpPixelMap);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_EQ(pixelMap->GetAllocatorType(), AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap->GetFd(), nullptr);
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {2, 3};
    std::unique_ptr<AuxiliaryPicture> tmpAuxPicture = AuxiliaryPicture::Create(pixelMap, type, size);
    std::shared_ptr<AuxiliaryPicture> auxPicture = std::move(tmpAuxPicture);
    MockSkWStream skStream;
    uint32_t ret = extEncoder.WriteJpegUncodedData(auxPicture, skStream);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest004 end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of WriteJpegUncodedData
             when auxiliaryPictureType == AuxiliaryPictureType::DEPTH_MAP
             pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC
             and pixelMap->GetFd() != nullptr, return SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, WriteJpegUncodedDataTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest005 start";
    ExtEncoder extEncoder;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.allocatorType = AllocatorType::DMA_ALLOC;
    std::unique_ptr<PixelMap> tmpPixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(tmpPixelMap, nullptr);
    std::shared_ptr<PixelMap> pixelMap = std::move(tmpPixelMap);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_EQ(pixelMap->GetAllocatorType(), AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap->GetFd(), nullptr);
    AuxiliaryPictureType type = AuxiliaryPictureType::DEPTH_MAP;
    Size size = {2, 3};
    std::unique_ptr<AuxiliaryPicture> tmpAuxPicture = AuxiliaryPicture::Create(pixelMap, type, size);
    std::shared_ptr<AuxiliaryPicture> auxPicture = std::move(tmpAuxPicture);
    MockSkWStream skStream;
    uint32_t ret = extEncoder.WriteJpegUncodedData(auxPicture, skStream);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest005 end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of WriteJpegUncodedData
             when auxiliaryPictureType == AuxiliaryPictureType::LINEAR_MAP
             pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC
             and pixelMap->GetFd() != nullptr, return SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, WriteJpegUncodedDataTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest006 start";
    ExtEncoder extEncoder;
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_PATH, opts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions decodeOpts;
    decodeOpts.allocatorType = AllocatorType::DMA_ALLOC;
    std::unique_ptr<PixelMap> tmpPixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_NE(tmpPixelMap, nullptr);
    std::shared_ptr<PixelMap> pixelMap = std::move(tmpPixelMap);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_EQ(pixelMap->GetAllocatorType(), AllocatorType::DMA_ALLOC);
    ASSERT_NE(pixelMap->GetFd(), nullptr);
    AuxiliaryPictureType type = AuxiliaryPictureType::LINEAR_MAP;
    Size size = {2, 3};
    std::unique_ptr<AuxiliaryPicture> tmpAuxPicture = AuxiliaryPicture::Create(pixelMap, type, size);
    std::shared_ptr<AuxiliaryPicture> auxPicture = std::move(tmpAuxPicture);
    MockSkWStream skStream;
    uint32_t ret = extEncoder.WriteJpegUncodedData(auxPicture, skStream);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "ExtDecoderTest: WriteJpegUncodedDataTest006 end";
}

/**
 * @tc.name: ExtDecoderTest
 * @tc.desc: test the function of EncodeJpegPicture
             when opts_.desiredDynamicRange == EncodeDynamicRange::HDR_VIVID_SINGLE
             return ERR_IMAGE_DECODE_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, EncodeJpegPictureTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeJpegPictureTest001 start";
    ExtEncoder extEncoder;
    extEncoder.opts_.desiredDynamicRange = EncodeDynamicRange::HDR_VIVID_SINGLE;
    MockSkWStream skStream;
    uint32_t ret = extEncoder.EncodeJpegPicture(skStream);
    ASSERT_EQ(ret, ERR_IMAGE_DECODE_FAILED);
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeJpegPictureTest001 end";
}

/**
 * @tc.name: EncodeJpegPictureTest002
 * @tc.desc: Verify that EncodeJpegPicture returns ERR_IMAGE_INVALID_PARAMETER
 *           when desiredDynamicRange is set to HDR_VIVID_DUAL or an invalid value.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, EncodeJpegPictureTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeJpegPictureTest002 start";
    ExtEncoder extEncoder;
    extEncoder.opts_.desiredDynamicRange = EncodeDynamicRange::HDR_VIVID_DUAL;
    ExtWStream skStream;
    Picture picture;
    extEncoder.AddPicture(picture);
    uint32_t code = extEncoder.EncodeJpegPicture(skStream);
    EXPECT_EQ(code, ERR_IMAGE_INVALID_PARAMETER);
    extEncoder.opts_.desiredDynamicRange = static_cast<EncodeDynamicRange>(INVALID_ENCODE_DYNAMIC_RANGE_VALUE);
    code = extEncoder.EncodeJpegPicture(skStream);
    EXPECT_EQ(code, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeJpegPictureTest002 end";
}

/**
 * @tc.name: SkOHOSCodecTest001
 * @tc.desc: Verify SkOHOSCodec returns nullptr when input null codec.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, SkOHOSCodecTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: SkOHOSCodecTest001 start";
#ifdef SK_ENABLE_OHOS_CODEC
    auto ret = SkOHOSCodec::MakeFromCodec(nullptr);
    EXPECT_EQ(ret, nullptr);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: SkOHOSCodecTest001 end";
}

/**
 * @tc.name: SkOHOSCodecTest002
 * @tc.desc: Verify SkOHOSCodec returns nullptr when input null data or decoder
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, SkOHOSCodecTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: SkOHOSCodecTest002 start";
#ifdef SK_ENABLE_OHOS_CODEC
    auto ret = SkOHOSCodec::MakeFromData(nullptr, nullptr);
    EXPECT_EQ(ret, nullptr);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: SkOHOSCodecTest002 end";
}

/**
 * @tc.name: SkOHOSCodecTest003
 * @tc.desc: Verify SkOHOSCodec dimension and subset operations with different sampling sizes.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, SkOHOSCodecTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: SkOHOSCodecTest003 start";
#ifdef SK_ENABLE_OHOS_CODEC
    const int fd = open("/data/local/tmp/image/test_hw1.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    auto codec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(streamPtr.get()));
    ASSERT_NE(codec, nullptr);
    auto skOHOSCodec = SkOHOSCodec::MakeFromCodec(std::move(codec));
    ASSERT_NE(skOHOSCodec, nullptr);
    auto size = skOHOSCodec->getSampledDimensions(1);
    size = skOHOSCodec->getSampledDimensions(2);
    size = skOHOSCodec->getSampledDimensions(0);
    EXPECT_EQ(size.width(), 0);
    auto isSupport = skOHOSCodec->getSupportedSubset(nullptr);
    EXPECT_EQ(isSupport, false);
    SkIRect subset;
    auto scaledSize = skOHOSCodec->getSampledSubsetDimensions(0, subset);
    EXPECT_EQ(scaledSize.width(), 0);
    scaledSize = skOHOSCodec->getSampledSubsetDimensions(1, subset);
    EXPECT_EQ(scaledSize.width(), 0);
    SkImageInfo decodeInfo;
    SkCodec::Result result = skOHOSCodec->getOHOSPixels(decodeInfo, nullptr, 0, nullptr);
    EXPECT_EQ(result, SkCodec::kInvalidParameters);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: SkOHOSCodecTest003 end";
}

/**
 * @tc.name: PixelmapEncodeTest001
 * @tc.desc: Test PixelmapEncode when desiredDynamicRange changes.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, PixelmapEncodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: PixelmapEncodeTest001 start";
    ExtEncoder extEncoder;
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    extEncoder.SetHdrColorSpaceType(surfaceBuffer);
    extEncoder.opts_.desiredDynamicRange = EncodeDynamicRange::HDR_VIVID_DUAL;
    ExtWStream wStream;
    PixelMap pixelMap;
    extEncoder.AddImage(pixelMap);
    uint32_t ret = extEncoder.PixelmapEncode(wStream);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    extEncoder.opts_.desiredDynamicRange = EncodeDynamicRange::HDR_VIVID_SINGLE;
    ret = extEncoder.PixelmapEncode(wStream);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    extEncoder.opts_.desiredDynamicRange = static_cast<EncodeDynamicRange>(INVALID_ENCODE_DYNAMIC_RANGE_VALUE);
    ret = extEncoder.PixelmapEncode(wStream);
    EXPECT_EQ(ret, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "ExtDecoderTest: PixelmapEncodeTest001 end";
}

/**
 * @tc.name: EncodeHeifByPixelmapTest001
 * @tc.desc: Verify that EncodeHeifByPixelmap returns ERR_IMAGE_INVALID_PARAMETER when given invalid input.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, EncodeHeifByPixelmapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeHeifByPixelmapTest001 start";
    ExtEncoder extEncoder;
    PixelMap pixelMap;
    PlEncodeOptions opts;
    uint32_t code = extEncoder.EncodeHeifByPixelmap(&pixelMap, opts);
    EXPECT_EQ(code, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ExtDecoderTest: EncodeHeifByPixelmapTest001 end";
}

/**
 * @tc.name: EncodeHeifByPixelmapTest002
 * @tc.desc: Verify HEIF encoding fails with invalid PixelMap and null output.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, EncodeHeifByPixelmapTest002, TestSize.Level3)
{
    ExtEncoder encoder;
    PlEncodeOptions opts;
    Media::PixelMap *pixelMap = nullptr;
    encoder.output_ = nullptr;
    uint32_t res = encoder.EncodeHeifByPixelmap(pixelMap, opts);
    EXPECT_EQ(res, ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: TryHardwareEncodePictureTest001
 * @tc.desc: test the function of TryHardwareEncodePicture
             when picture is nullptr, return ERR_IMAGE_DATA_ABNORMAL
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, TryHardwareEncodePictureTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: TryHardwareEncodePictureTest001 start";
    ExtEncoder extEncoder;
    extEncoder.CheckJpegAuxiliaryTagName();
    std::string errorMsg;
    ExtWStream skStream;
    uint32_t code = extEncoder.TryHardwareEncodePicture(skStream, errorMsg);
    EXPECT_EQ(code, ERR_IMAGE_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "ExtDecoderTest: TryHardwareEncodePictureTest001 end";
}

#ifdef EXIF_INFO_ENABLE
/**
 * @tc.name: DecodeToYuv420Test001
 * @tc.desc: Verify that DecodeToYuv420 returns ERR_IMAGE_INVALID_PARAMETER when the codec is null.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, DecodeToYuv420Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: DecodeToYuv420Test001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    uint32_t index = 0;
    DecodeContext context;
    extDecoder->codec_ = nullptr;
    uint32_t ret = extDecoder->DecodeToYuv420(index, context);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ExtDecoderTest: DecodeToYuv420Test001 end";
}

/**
 * @tc.name: IsYuv420FormatTest001
 * @tc.desc: Verify that IsYuv420Format correctly identifies YUV420 formats.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, IsYuv420FormatTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsYuv420FormatTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();

    PixelFormat format = PixelFormat::UNKNOWN;
    bool ret = extDecoder->IsYuv420Format(format);
    EXPECT_EQ(ret, false);
    format = PixelFormat::NV12;
    ret = extDecoder->IsYuv420Format(format);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsYuv420FormatTest001 end";
}

/**
 * @tc.name: GetGainMapOffsetTest001
 * @tc.desc: Verify that GetGainMapOffset returns the correct gain map offset value.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetGainMapOffsetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetGainMapOffsetTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();

    extDecoder->gainMapOffset_ = 0;
    uint32_t ret = extDecoder->GetGainMapOffset();
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetGainMapOffsetTest001 end";
}

/**
 * @tc.name: DecodeHeifGainMapTest001
 * @tc.desc: Verify that DecodeHeifGainMap returns false when decoding the HEIF gain map fails.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, DecodeHeifGainMapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: DecodeHeifGainMapTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();

    DecodeContext context;
    bool ret = extDecoder->DecodeHeifGainMap(context);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: DecodeHeifGainMapTest001 end";
}

/**
 * @tc.name: GetHeifHdrColorSpaceTest001
 * @tc.desc: Verify that GetHeifHdrColorSpace returns false when it fails to retrieve the HEIF HDR color space.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetHeifHdrColorSpaceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetHeifHdrColorSpaceTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();

    ColorManager::ColorSpaceName gainmap;
    ColorManager::ColorSpaceName hdr;
    bool ret = extDecoder->GetHeifHdrColorSpace(gainmap, hdr);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetHeifHdrColorSpaceTest001 end";
}

/**
 * @tc.name: DecodeHeifAuxiliaryMapTest001
 * @tc.desc: Verify that DecodeHeifAuxiliaryMap returns false when decoding the HEIF auxiliary map fails.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, DecodeHeifAuxiliaryMapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: DecodeHeifAuxiliaryMapTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();

    DecodeContext context;
    Media::AuxiliaryPictureType type = Media::AuxiliaryPictureType::NONE;
    bool ret = extDecoder->DecodeHeifAuxiliaryMap(context, type);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: DecodeHeifAuxiliaryMapTest001 end";
}

/**
 * @tc.name: CheckAuxiliaryMapTest001
 * @tc.desc: Verify that CheckAuxiliaryMap returns false for unsupported auxiliary picture types,
 *           including NONE and GAINMAP.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, CheckAuxiliaryMapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: CheckAuxiliaryMapTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();

    Media::AuxiliaryPictureType type = Media::AuxiliaryPictureType::NONE;
    bool ret = extDecoder->CheckAuxiliaryMap(type);
    EXPECT_EQ(ret, false);
    type = Media::AuxiliaryPictureType::GAINMAP;
    ret = extDecoder->CheckAuxiliaryMap(type);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: CheckAuxiliaryMapTest001 end";
}

/**
 * @tc.name: GetHeifFragmentMetadataTest001
 * @tc.desc: Verify that GetHeifFragmentMetadata returns false when it fails to retrieve HEIF fragment metadata.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetHeifFragmentMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetHeifFragmentMetadataTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();

    Media::Rect metadata;
    bool ret = extDecoder->GetHeifFragmentMetadata(metadata);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetHeifFragmentMetadataTest001 end";
}

/**
 * @tc.name: GetSoftwareScaledSizeTest001
 * @tc.desc: test the function of TryHardwareEncodePicture
             when picture is nullptr, return ERR_IMAGE_DATA_ABNORMAL
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetSoftwareScaledSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetSoftwareScaledSizeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    ASSERT_NE(extDecoder, nullptr);
    extDecoder->codec_ = nullptr;
    extDecoder->stream_ = nullptr;

    int code = extDecoder->GetSoftwareScaledSize(0, 0);
    EXPECT_EQ(code, DEFAULT_SCALE_SIZE);
    extDecoder->dstSubset_ = SkIRect::MakeXYWH(0, 0, 0, 0);
    code = extDecoder->GetSoftwareScaledSize(1, 1);
    EXPECT_EQ(code, DEFAULT_SCALE_SIZE);
    extDecoder->dstSubset_ = SkIRect::MakeXYWH(0, 0, SUBSET_SIZE_SMALL, SUBSET_SIZE_SMALL);
    code = extDecoder->GetSoftwareScaledSize(1, 0);
    EXPECT_EQ(code, FOURTH_SCALE_SIZE);
    extDecoder->dstSubset_ = SkIRect::MakeXYWH(0, 0, SUBSET_SIZE_LARGE, SUBSET_SIZE_LARGE);
    code = extDecoder->GetSoftwareScaledSize(1, 0);
    EXPECT_EQ(code, MAX_SCALE_SIZE);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetSoftwareScaledSizeTest001 end";
}

/**
 * @tc.name: IsRegionDecodeSupportedTest001
 * @tc.desc: test the function of TryHardwareEncodePicture
             when picture is nullptr, return ERR_IMAGE_DATA_ABNORMAL
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, IsRegionDecodeSupportedTest001, TestSize.Level3)
{
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    ASSERT_NE(extDecoder, nullptr);
    PixelDecodeOptions opts;
    PlImageInfo info;
    extDecoder->codec_ = nullptr;
    bool isRegionDecodeSupport = extDecoder->IsRegionDecodeSupported(0, opts, info);
    EXPECT_FALSE(isRegionDecodeSupport);
}

/**
 * @tc.name: DoHeifSharedMemDecodeTest001
 * @tc.desc: test the function of TryHardwareEncodePicture
             when picture is nullptr, return ERR_IMAGE_DATA_ABNORMAL
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, DoHeifSharedMemDecodeTest001, TestSize.Level3)
{
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    ASSERT_NE(extDecoder, nullptr);
    const int fd = open(IMAGE_INPUT_JPEG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    DecodeContext context;
    uint32_t code = extDecoder->DoHeifSharedMemDecode(context);
    close(fd);
    EXPECT_EQ(code, ERR_IMAGE_DATA_UNSUPPORT);
}

/**
 * @tc.name: HandleGifCacheTest001
 * @tc.desc: test the function of TryHardwareEncodePicture
             when picture is nullptr, return ERR_IMAGE_DATA_ABNORMAL
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HandleGifCacheTest001, TestSize.Level3)
{
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    ASSERT_NE(extDecoder, nullptr);
    extDecoder->SetHeifParseError();
    uint32_t code = extDecoder->HandleGifCache(nullptr, nullptr, 0, 0);
    EXPECT_EQ(code, ERR_IMAGE_DECODE_ABNORMAL);
}

/**
 * @tc.name: GetGainMapOffsetTest002
 * @tc.desc: test the function of TryHardwareEncodePicture
             when picture is nullptr, return ERR_IMAGE_DATA_ABNORMAL
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetGainMapOffsetTest002, TestSize.Level3)
{
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    ASSERT_NE(extDecoder, nullptr);
    extDecoder->codec_ = nullptr;
    uint32_t code = extDecoder->GetGainMapOffset();
    EXPECT_EQ(code, 0);
}

/**
 * @tc.name: computeOutputColorTypeTest001
 * @tc.desc: Verify that computeOutputColorType correctly maps various SkColorType inputs to their expected outputs.
 */
HWTEST_F(ExtDecoderTest, computeOutputColorTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: computeOutputColorTypeTest001 start";
#ifdef SK_ENABLE_OHOS_CODEC
    const int fd = open(IMAGE_INPUT_JPEG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    auto codec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(streamPtr.get()));
    ASSERT_NE(codec, nullptr);
    auto skOHOSCodec = SkOHOSCodec::MakeFromCodec(std::move(codec));
    ASSERT_NE(skOHOSCodec, nullptr);

    SkColorType skColorType= skOHOSCodec->computeOutputColorType(SkColorType::kARGB_4444_SkColorType);
    EXPECT_EQ(skColorType, SkColorType::kN32_SkColorType);
    skColorType= skOHOSCodec->computeOutputColorType(SkColorType::kN32_SkColorType);
    EXPECT_EQ(skColorType, SkColorType::kN32_SkColorType);
    skColorType= skOHOSCodec->computeOutputColorType(SkColorType::kAlpha_8_SkColorType);
    EXPECT_EQ(skColorType, SkColorType::kN32_SkColorType);
    skColorType= skOHOSCodec->computeOutputColorType(SkColorType::kRGB_565_SkColorType);
    EXPECT_EQ(skColorType, SkColorType::kRGB_565_SkColorType);
    skColorType= skOHOSCodec->computeOutputColorType(SkColorType::kRGBA_F16_SkColorType);
    EXPECT_EQ(skColorType, SkColorType::kRGBA_F16_SkColorType);
    skColorType= skOHOSCodec->computeOutputColorType(static_cast<SkColorType>(INVALID_ENCODE_DYNAMIC_RANGE_VALUE));
    EXPECT_EQ(skColorType, SkColorType::kN32_SkColorType);
    close(fd);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: computeOutputColorTypeTest001 end";
}

/**
 * @tc.name: computeOutputAlphaTypeTest001
 * @tc.desc: Verify that computeOutputAlphaType correctly returns kOpaque_SkAlphaType when the input is true.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, computeOutputAlphaTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: computeOutputAlphaTypeTest001 start";
#ifdef SK_ENABLE_OHOS_CODEC
    const int fd = open(IMAGE_INPUT_JPEG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    auto codec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(streamPtr.get()));
    ASSERT_NE(codec, nullptr);
    auto skOHOSCodec = SkOHOSCodec::MakeFromCodec(std::move(codec));
    ASSERT_NE(skOHOSCodec, nullptr);
    SkAlphaType skaType = skOHOSCodec->computeOutputAlphaType(true);
    EXPECT_EQ(skaType, SkAlphaType::kOpaque_SkAlphaType);
    close(fd);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: computeOutputAlphaTypeTest001 end";
}

/**
 * @tc.name: computeOutputColorSpaceTest001
 * @tc.desc: Verify that computeOutputColorSpace handles valid and invalid inputs correctly,
 *           returning appropriate SkColorSpace or null.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, computeOutputColorSpaceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: computeOutputColorSpaceTest001 start";
#ifdef SK_ENABLE_OHOS_CODEC
    const int fd = open(IMAGE_INPUT_JPEG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    auto codec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(streamPtr.get()));
    ASSERT_NE(codec, nullptr);
    auto skOHOSCodec = SkOHOSCodec::MakeFromCodec(std::move(codec));
    ASSERT_NE(skOHOSCodec, nullptr);
    sk_sp<SkColorSpace> colorSpace = SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, SkNamedGamut::kSRGB);
    ASSERT_NE(colorSpace, nullptr);

    auto skColorSpace = skOHOSCodec->computeOutputColorSpace(SkColorType::kRGBA_F16_SkColorType, colorSpace);
    EXPECT_NE(skColorSpace, nullptr);
    skColorSpace = skOHOSCodec->computeOutputColorSpace(SkColorType::kRGBA_F16_SkColorType, nullptr);
    EXPECT_NE(skColorSpace, nullptr);
    skColorSpace = skOHOSCodec->computeOutputColorSpace(static_cast<SkColorType>(INVALID_COLOR_TYPE), nullptr);
    EXPECT_EQ(skColorSpace, nullptr);
    close(fd);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: computeOutputColorSpaceTest001 end";
}

/**
 * @tc.name: getSampledSubsetDimensionsTest001
 * @tc.desc: Verify the behavior of SkOHOSCodec with invalid inputs for size and subset queries.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, getSampledSubsetDimensionsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: getSampledSubsetDimensionsTest001 start";
#ifdef SK_ENABLE_OHOS_CODEC
    const int fd = open(IMAGE_INPUT_JPEG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    auto codec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(streamPtr.get()));
    ASSERT_NE(codec, nullptr);
    auto skOHOSCodec = SkOHOSCodec::MakeFromCodec(std::move(codec));
    ASSERT_NE(skOHOSCodec, nullptr);

    SkISize skiSize = skOHOSCodec->getSampledDimensions(0);
    EXPECT_EQ(skiSize.width(), 0);

    bool isSupport = skOHOSCodec->getSupportedSubset(nullptr);
    EXPECT_EQ(isSupport, false);

    SkIRect subset;
    skiSize = skOHOSCodec->getSampledSubsetDimensions(0, subset);
    EXPECT_EQ(skiSize.width(), 0);
    close(fd);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: getSampledSubsetDimensionsTest001 end";
}

/**
 * @tc.name: getOHOSPixelsTest001
 * @tc.desc: Verify that SkOHOSCodec::getOHOSPixels handles null PixelMap, invalid conversion,
 *           and rewind failures correctly.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, getOHOSPixelsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: getOHOSPixelsTest001 start";
#ifdef SK_ENABLE_OHOS_CODEC
    const int fd = open(IMAGE_INPUT_JPEG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    auto codec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(streamPtr.get()));
    ASSERT_NE(codec, nullptr);
    auto skOHOSCodec = SkOHOSCodec::MakeFromCodec(std::move(codec));
    ASSERT_NE(skOHOSCodec, nullptr);
    SkISize skiSize{OFFSET_2, OFFSET_2};
    SkColorInfo colorInfo;
    SkImageInfo decodeInfo(skiSize, colorInfo);

    SkCodec::Result result = skOHOSCodec->getOHOSPixels(decodeInfo, nullptr, 0, nullptr);
    EXPECT_EQ(result, SkCodec::kInvalidParameters);
    PixelMap pixelMap;
    result = skOHOSCodec->getOHOSPixels(decodeInfo, &pixelMap, 0, nullptr);
    EXPECT_EQ(result, SkCodec::kInvalidConversion);
    result = skOHOSCodec->getOHOSPixels(decodeInfo, &pixelMap, INVALID_COLOR_TYPE, nullptr);
    EXPECT_EQ(result, SkCodec::kCouldNotRewind);
    close(fd);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: getOHOSPixelsTest001 end";
}

/**
 * @tc.name: accountForNativeScalingTest001
 * @tc.desc: Verify that SkOHOSSampledCodec::accountForNativeScaling correctly calculates the scaled size
 *           and returns a empty SkISize.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, accountForNativeScalingTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: accountForNativeScalingTest001 start";
#ifdef SK_ENABLE_OHOS_CODEC
    const int fd = open(IMAGE_INPUT_JPEG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    auto codec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(streamPtr.get()));
    ASSERT_NE(codec, nullptr);
    SkOHOSSampledCodec skOHOSSampledCodec(codec.release());
    int sampleSize = DEFAULT_SAMPLE_SIZE;
    int nativeSampleSize = 1;

    SkISize size = skOHOSSampledCodec.accountForNativeScaling(&sampleSize, &nativeSampleSize);
    EXPECT_FALSE(size.isEmpty());
    close(fd);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: accountForNativeScalingTest001 end";
}

/**
 * @tc.name: sampledDecodeTest001
 * @tc.desc: Verify that SkOHOSSampledCodec::sampledDecode returns kInvalidConversion
 *           when the input parameters are invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, sampledDecodeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: sampledDecodeTest001 start";
#ifdef SK_ENABLE_OHOS_CODEC
    const int fd = open(IMAGE_INPUT_JPEG_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    auto codec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(streamPtr.get()));
    ASSERT_NE(codec, nullptr);
    SkOHOSSampledCodec skOHOSSampledCodec(codec.release());
    SkISize skiSize{OFFSET_2, OFFSET_2};
    SkColorInfo colorInfo;
    SkImageInfo decodeInfo(skiSize, colorInfo);
    PixelMap pixelMap;
    SkOHOSCodec::OHOSOptions ohosOptions;

    SkCodec::Result result = skOHOSSampledCodec.sampledDecode(decodeInfo, &pixelMap, 0, ohosOptions);
    EXPECT_EQ(result, SkCodec::kInvalidConversion);
    close(fd);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: sampledDecodeTest001 end";
}
#endif

/**
 * @tc.name: IsHeifValidCropTest001
 * @tc.desc: Verify that IsHeifValidCrop returns false when the crop rectangle contains invalid values.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, IsHeifValidCropTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsHeifValidCropTest001 start";
    #ifdef EXIF_INFO_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    ASSERT_NE(extDecoder, nullptr);

    OHOS::Media::Rect crop{-1, -1, -1, -1};
    SkImageInfo info;
    bool isHeifValidCrop = extDecoder->IsHeifValidCrop(crop, info, 0, 0);
    EXPECT_FALSE(isHeifValidCrop);
    #endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: IsHeifValidCropTest001 end";
}

/**
 * @tc.name: EncodePixelMapTest001
 * @tc.desc: Test HEIF encoding from a YCRCB_P010 format PixelMap and verify output image.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, EncodePixelMapTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_HEIFHDR_SRC.c_str(),
                                                                              sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions opts;
    opts.photoDesiredPixelFormat = PixelFormat::YCBCR_P010;
    opts.desiredDynamicRange = DecodeDynamicRange::HDR;
    std::shared_ptr<PixelMap> pixelmap = imageSource->CreatePixelMap(opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(pixelmap, nullptr);
    EXPECT_EQ(pixelmap->GetPixelFormat(), PixelFormat::YCBCR_P010);
    ImagePacker packer;
    PackOption option;
    option.format = "image/heif";
    option.needsPackProperties = true;
    option.desiredDynamicRange = EncodeDynamicRange::AUTO;
    uint32_t startpc = packer.StartPacking(IMAGE_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddImage = packer.AddImage(*pixelmap);
    ASSERT_EQ(retAddImage, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = packer.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_DEST, sourceOpts, errorCode);
    EXPECT_EQ(errorCode, OHOS::Media::SUCCESS);
    EXPECT_NE(imageSourceDest, nullptr);
}

/*
 * @tc.name: Encode10bit709Test001
 * @tc.desc: Test JPEG decode to YCBCR_P010 format PixelMap and set to BT709 then convert to RGBA_1010102
 * and encode 8bit sdr decode to sdr pixelmap with BT601 colorspace.
 * @tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, Encode10bit709Test001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_JPG_THREE_GAINMAP_HDR_PATH.c_str(), sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions opts;
    opts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    opts.photoDesiredPixelFormat = PixelFormat::YCBCR_P010;
    std::shared_ptr<PixelMap> pixelmap = imageSource->CreatePixelMap(opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(pixelmap, nullptr);
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(pixelmap, PixelFormat::RGBA_1010102);
    ASSERT_EQ(ret, SUCCESS);
    PixelFormat format = pixelmap->GetPixelFormat();
    ASSERT_EQ(format, PixelFormat::RGBA_1010102);
#ifdef IMAGE_COLORSPACE_FLAG
    pixelmap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::BT709));
#endif
    ImagePacker packer;
    PackOption option;
    option.format = "image/jpeg";
    option.needsPackProperties = true;
    option.desiredDynamicRange = EncodeDynamicRange::AUTO;
    uint32_t startpc = packer.StartPacking(IMAGE_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddImage = packer.AddImage(*pixelmap);
    ASSERT_EQ(retAddImage, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = packer.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_DEST, sourceOpts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
    DecodeOptions optsForDest;
    optsForDest.desiredDynamicRange = DecodeDynamicRange::AUTO;
    std::shared_ptr<PixelMap> pixelmapAfterPacker = imageSourceDest->CreatePixelMap(optsForDest, errorCode);
    ASSERT_NE(pixelmapAfterPacker, nullptr);
    ASSERT_EQ(pixelmapAfterPacker->IsHdr(), false);
#ifdef IMAGE_COLORSPACE_FLAG
    PixelFormat encodeAndDecodeFormat = pixelmapAfterPacker->GetPixelFormat();
    ASSERT_EQ(encodeAndDecodeFormat, PixelFormat::RGBA_8888);
    auto newColorspace = pixelmapAfterPacker->InnerGetGrColorSpace();
    auto newColorSpaceName = newColorspace.GetColorSpaceName();
    EXPECT_EQ(newColorSpaceName, ColorManager::ColorSpaceName::SRGB);
#endif
}

/**
 * @tc.name: Encode10bit709Test002
 * @tc.desc: Test JPEG decode to YCBCR_P010 format PixelMap and set to BT709
 * and encode 8bit sdr decode to sdr pixelmap with BT601 colorspace.
 * @tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, Encode10bit709Test002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_JPG_THREE_GAINMAP_HDR_PATH.c_str(), sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions opts;
    opts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    opts.photoDesiredPixelFormat = PixelFormat::YCBCR_P010;
    std::shared_ptr<PixelMap> pixelmap = imageSource->CreatePixelMap(opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(pixelmap, nullptr);
    PixelFormat format = pixelmap->GetPixelFormat();
    ASSERT_EQ(format, PixelFormat::YCBCR_P010);
#ifdef IMAGE_COLORSPACE_FLAG
    pixelmap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(
        OHOS::ColorManager::ColorSpaceName::BT709_LIMIT));
    ASSERT_EQ(pixelmap->IsHdr(), false);
#endif
    // init packer to packfile
    ImagePacker packer;
    PackOption option;
    option.format = "image/jpeg";
    option.needsPackProperties = true;
    option.desiredDynamicRange = EncodeDynamicRange::AUTO;
    uint32_t startpc = packer.StartPacking(IMAGE_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddImage = packer.AddImage(*pixelmap);
    ASSERT_EQ(retAddImage, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = packer.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_DEST, sourceOpts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
    DecodeOptions optsForDest;
    optsForDest.desiredDynamicRange = DecodeDynamicRange::AUTO;
    std::shared_ptr<PixelMap> pixelmapAfterPacker = imageSourceDest->CreatePixelMap(optsForDest, errorCode);
    ASSERT_NE(pixelmapAfterPacker, nullptr);
    ASSERT_EQ(pixelmapAfterPacker->IsHdr(), false);
    PixelFormat encodeAndDecodeFormat = pixelmapAfterPacker->GetPixelFormat();
    ASSERT_EQ(encodeAndDecodeFormat, PixelFormat::RGBA_8888);
#ifdef IMAGE_COLORSPACE_FLAG
    auto newColorspace = pixelmapAfterPacker->InnerGetGrColorSpace();
    auto newColorSpaceName = newColorspace.GetColorSpaceName();
    EXPECT_EQ(newColorSpaceName, ColorManager::ColorSpaceName::SRGB);
#endif
}

/**
 * @tc.name: Encode10bit709Test003
 * @tc.desc: Test JPEG decode to YCBCR_P010 format PixelMap and set to BT709
 * and encode 8bit sdr decode to sdr pixelmap with BT601 colorspace.
 * @tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, Encode10bit709Test003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_JPG_THREE_GAINMAP_HDR_PATH.c_str(), sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions opts;
    opts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    std::shared_ptr<PixelMap> pixelmap = imageSource->CreatePixelMap(opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(pixelmap, nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    pixelmap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(
        OHOS::ColorManager::ColorSpaceName::BT709));
    ASSERT_EQ(pixelmap->IsHdr(), false);
#endif
    ImagePacker packer;
    PackOption option;
    option.format = "image/jpg";
    option.needsPackProperties = true;
    option.desiredDynamicRange = EncodeDynamicRange::AUTO;
    uint32_t startpc = packer.StartPacking(IMAGE_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddImage = packer.AddImage(*pixelmap);
    ASSERT_EQ(retAddImage, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = packer.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_DEST, sourceOpts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
    DecodeOptions optsForDest;
    optsForDest.desiredDynamicRange = DecodeDynamicRange::AUTO;
    std::shared_ptr<PixelMap> pixelmapAfterPacker = imageSourceDest->CreatePixelMap(optsForDest, errorCode);
    ASSERT_NE(pixelmapAfterPacker, nullptr);
    ASSERT_EQ(pixelmapAfterPacker->IsHdr(), false);
    PixelFormat encodeAndDecodeFormat = pixelmapAfterPacker->GetPixelFormat();
    ASSERT_EQ(encodeAndDecodeFormat, PixelFormat::RGBA_1010102);
#ifdef IMAGE_COLORSPACE_FLAG
    auto newColorspace = pixelmapAfterPacker->InnerGetGrColorSpace();
    auto newColorSpaceName = newColorspace.GetColorSpaceName();
    EXPECT_EQ(newColorSpaceName, ColorManager::ColorSpaceName::SRGB);
#endif
}

/**
 * @tc.name: Encode10bit709Test004
 * @tc.desc: Test JPEG decode to YCBCR_P010 format PixelMap and set to BT709
 * and encode 8bit sdr decode to sdr pixelmap with BT601 colorspace.
 * @tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, Encode10bit709Test004, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_JPG_THREE_GAINMAP_HDR_PATH.c_str(), sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions opts;
    opts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    std::shared_ptr<PixelMap> pixelmap = imageSource->CreatePixelMap(opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(pixelmap, nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    pixelmap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(
        OHOS::ColorManager::ColorSpaceName::BT709));
    ASSERT_EQ(pixelmap->IsHdr(), false);
#endif
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(pixelmap, PixelFormat::RGBA_8888);
    ASSERT_EQ(ret, SUCCESS);
    PixelFormat format = pixelmap->GetPixelFormat();
    ASSERT_EQ(format, PixelFormat::RGBA_8888);
    // init packer to packfile
    ImagePacker packer;
    PackOption option;
    option.format = "image/jpeg";
    option.needsPackProperties = true;
    option.desiredDynamicRange = EncodeDynamicRange::AUTO;
    uint32_t startpc = packer.StartPacking(IMAGE_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddImage = packer.AddImage(*pixelmap);
    ASSERT_EQ(retAddImage, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = packer.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_DEST, sourceOpts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
    DecodeOptions optsForDest;
    optsForDest.desiredDynamicRange = DecodeDynamicRange::AUTO;
    std::shared_ptr<PixelMap> pixelmapAfterPacker = imageSourceDest->CreatePixelMap(optsForDest, errorCode);
    ASSERT_NE(pixelmapAfterPacker, nullptr);
    ASSERT_EQ(pixelmapAfterPacker->IsHdr(), false);
#ifdef IMAGE_COLORSPACE_FLAG
    PixelFormat encodeAndDecodeFormat = pixelmapAfterPacker->GetPixelFormat();
    ASSERT_EQ(encodeAndDecodeFormat, PixelFormat::RGBA_8888);
    auto newColorspace = pixelmapAfterPacker->InnerGetGrColorSpace();
    auto newColorSpaceName = newColorspace.GetColorSpaceName();
    ASSERT_EQ(newColorSpaceName, ColorManager::ColorSpaceName::SRGB);
#endif
}

/**
 * @tc.name: Encode10bit709Test005
 * @tc.desc: Test heic decode to YCBCR_P010 format PixelMap and set to BT709
 * and encode 8bit heic decode to sdr pixelmap with BT601 colorspace.
 * @tc.type: FUNC
*/
HWTEST_F(ExtDecoderTest, Encode10bit709Test005, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_HEIC_THREE_GAINMAP_HDR_PATH.c_str(), sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions opts;
    opts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    opts.photoDesiredPixelFormat = PixelFormat::YCBCR_P010;
    std::shared_ptr<PixelMap> pixelmap = imageSource->CreatePixelMap(opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(pixelmap, nullptr);
    PixelFormat format = pixelmap->GetPixelFormat();
    ASSERT_EQ(format, PixelFormat::YCBCR_P010);
#ifdef IMAGE_COLORSPACE_FLAG
    pixelmap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(
        OHOS::ColorManager::ColorSpaceName::BT709));
    ASSERT_EQ(pixelmap->IsHdr(), false);
#endif
    // init packer to packfile
    ImagePacker packer;
    PackOption option;
    option.format = "image/heic";
    option.needsPackProperties = true;
    option.desiredDynamicRange = EncodeDynamicRange::SDR;
    uint32_t startpc = packer.StartPacking(IMAGE_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddImage = packer.AddImage(*pixelmap);
    ASSERT_EQ(retAddImage, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = packer.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_DEST, sourceOpts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
    DecodeOptions optsForDest;
    optsForDest.desiredDynamicRange = DecodeDynamicRange::AUTO;
    std::shared_ptr<PixelMap> pixelmapAfterPacker = imageSourceDest->CreatePixelMap(optsForDest, errorCode);
    ASSERT_NE(pixelmapAfterPacker, nullptr);
    ASSERT_EQ(pixelmapAfterPacker->IsHdr(), false);
    PixelFormat encodeAndDecodeFormat = pixelmapAfterPacker->GetPixelFormat();
    ASSERT_EQ(encodeAndDecodeFormat, PixelFormat::RGBA_8888);
#ifdef IMAGE_COLORSPACE_FLAG
    auto newColorspace = pixelmapAfterPacker->InnerGetGrColorSpace();
    auto newColorSpaceName = newColorspace.GetColorSpaceName();
    ASSERT_EQ(newColorSpaceName, ColorManager::ColorSpaceName::SRGB);
#endif
}

/**
 * @tc.name: EncodeWideGamutPixelMapAndDecodeTest003
 * @tc.desc: Test JPEG encoding from a RGBA_1010102 format PixelMap and decode to widegamut image.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, EncodeWideGamutPixelMapAndDecodeTest003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_JPG_THREE_GAINMAP_HDR_PATH.c_str(), sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions opts;
    opts.desiredDynamicRange = DecodeDynamicRange::AUTO;
    opts.isCreateWideGamutSdrPixelMap = true;
    std::shared_ptr<PixelMap> pixelmap = imageSource->CreatePixelMap(opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(pixelmap, nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    auto colorSpace = pixelmap->InnerGetGrColorSpace();
    auto colorSpaceName = colorSpace.GetColorSpaceName();
    EXPECT_EQ(colorSpaceName, ColorManager::ColorSpaceName::DISPLAY_BT2020_SRGB);
#endif
    ImagePacker packer;
    PackOption option;
    option.format = "image/heif";
    option.needsPackProperties = true;
    option.desiredDynamicRange = EncodeDynamicRange::AUTO;
    uint32_t startpc = packer.StartPacking(IMAGE_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddImage = packer.AddImage(*pixelmap);
    ASSERT_EQ(retAddImage, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = packer.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_DEST, sourceOpts, errorCode);
    EXPECT_EQ(errorCode, OHOS::Media::SUCCESS);
    EXPECT_NE(imageSourceDest, nullptr);
    DecodeOptions optsForDest;
    optsForDest.desiredDynamicRange = DecodeDynamicRange::AUTO;
    optsForDest.isCreateWideGamutSdrPixelMap = true;
    std::shared_ptr<PixelMap> pixelmapAfterPacker = imageSourceDest->CreatePixelMap(optsForDest, errorCode);
#ifdef IMAGE_COLORSPACE_FLAG
    auto newColorspace = pixelmapAfterPacker->InnerGetGrColorSpace();
    auto newColorSpaceName = newColorspace.GetColorSpaceName();
    EXPECT_EQ(newColorSpaceName, ColorManager::ColorSpaceName::DISPLAY_BT2020_SRGB);
#endif
}

/**
 * @tc.name: EncodeWideGamutPixelMapAndDecodeTest004
 * @tc.desc: Test JPEG encoding from a YCBCR_P010 format PixelMap and decode to widegamut image.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, EncodeWideGamutPixelMapAndDecodeTest004, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_JPG_THREE_GAINMAP_HDR_PATH.c_str(), sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions opts;
    opts.photoDesiredPixelFormat = PixelFormat::YCBCR_P010;
    opts.isCreateWideGamutSdrPixelMap = true;
    std::shared_ptr<PixelMap> pixelmap = imageSource->CreatePixelMap(opts, errorCode);
    ASSERT_NE(errorCode, OHOS::Media::SUCCESS);
    ASSERT_EQ(pixelmap, nullptr);
}

/**
 * @tc.name: DecodeIncompleteGifImageTest001
 * @tc.desc: Test decoding broken gif image.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, DecodeIncompleteGifImageTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INCOMPLETE_GIF_PATH.c_str(), sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    DecodeOptions opts;
    std::shared_ptr<PixelMap> pixelmap = imageSource->CreatePixelMap(opts, errorCode);
    EXPECT_EQ(errorCode, OHOS::Media::SUCCESS);
    EXPECT_NE(pixelmap, nullptr);
}

#ifdef HEIF_HW_DECODE_ENABLE
/**
 * @tc.name: HeifColorSpaceSetter_None
 * @tc.desc: Set NONE colorspace and unsupported flag, verify fields
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifColorSpaceSetter_None, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifColorSpaceSetter_None start";
    auto dec = std::make_shared<HeifDecoderImpl>();
    dec->SetColorSpaceInfoLight(OHOS::ColorManager::ColorSpaceName::NONE, true);
    dec->SetColorSpaceSupportFlag(false);
    ASSERT_EQ(dec->colorSpaceName_, OHOS::ColorManager::ColorSpaceName::NONE);
    ASSERT_TRUE(dec->isColorSpaceFromCicp_);
    ASSERT_FALSE(dec->colorSpaceFrameworkSupported_);
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifColorSpaceSetter_None end";
}

/**
 * @tc.name: HeifColorSpaceSetter_Custom
 * @tc.desc: Set CUSTOM colorspace and unsupported flag, verify fields
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifColorSpaceSetter_Custom, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifColorSpaceSetter_Custom start";
    auto dec = std::make_shared<HeifDecoderImpl>();
    dec->SetColorSpaceInfoLight(OHOS::ColorManager::ColorSpaceName::CUSTOM, false);
    dec->SetColorSpaceSupportFlag(false);
    ASSERT_EQ(dec->colorSpaceName_, OHOS::ColorManager::ColorSpaceName::CUSTOM);
    ASSERT_FALSE(dec->isColorSpaceFromCicp_);
    ASSERT_FALSE(dec->colorSpaceFrameworkSupported_);
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifColorSpaceSetter_Custom end";
}

/**
 * @tc.name: HeifColorSpaceSetter_SupportedEnum
 * @tc.desc: Set a supported colorspace (e.g., BT2020) and supported flag true, verify fields
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifColorSpaceSetter_SupportedEnum, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifColorSpaceSetter_SupportedEnum start";
    auto dec = std::make_shared<HeifDecoderImpl>();
    dec->SetColorSpaceInfoLight(OHOS::ColorManager::ColorSpaceName::BT2020, true);
    dec->SetColorSpaceSupportFlag(true);
    ASSERT_EQ(dec->colorSpaceName_, OHOS::ColorManager::ColorSpaceName::BT2020);
    ASSERT_TRUE(dec->isColorSpaceFromCicp_);
    ASSERT_TRUE(dec->colorSpaceFrameworkSupported_);
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifColorSpaceSetter_SupportedEnum end";
}

/**
 * @tc.name: HeifHdrType_NoneOrCustom
 * @tc.desc: NONE/CUSTOM with unsupported flag should not match HDR path (returns UNKNOWN when no 10-bit or gainmap)
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifHdrType_NoneOrCustom, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifHdrType_NoneOrCustom start";
    auto dec = std::make_shared<HeifDecoderImpl>();
    // Prepare minimal primary image
    auto prim = std::make_shared<HeifImage>(1);
    prim->SetLumaBitNum(8); // not 10-bit, avoid HDR branch
    dec->primaryImage_ = prim;

    // Case NONE
    dec->SetColorSpaceInfoLight(OHOS::ColorManager::ColorSpaceName::NONE, false);
    dec->SetColorSpaceSupportFlag(false);
    auto typeNone = dec->getHdrType();
    ASSERT_EQ(typeNone, HeifImageHdrType::UNKNOWN);

    // Case CUSTOM
    dec->SetColorSpaceInfoLight(OHOS::ColorManager::ColorSpaceName::CUSTOM, true);
    dec->SetColorSpaceSupportFlag(false);
    auto typeCustom = dec->getHdrType();
    ASSERT_EQ(typeCustom, HeifImageHdrType::UNKNOWN);
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifHdrType_NoneOrCustom end";
}

/**
 * @tc.name: HeifHdrType_SupportedBT2020_10bit
 * @tc.desc: Supported mapping with 10-bit should enter SINGLE path; empty UWA -> ISO_SINGLE
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifHdrType_SupportedBT2020_10bit, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifHdrType_SupportedBT2020_10bit start";
    auto dec = std::make_shared<HeifDecoderImpl>();
    auto prim = std::make_shared<HeifImage>(2);
    prim->SetLumaBitNum(10);
    dec->primaryImage_ = prim;

    dec->SetColorSpaceInfoLight(OHOS::ColorManager::ColorSpaceName::BT2020, true);
    dec->SetColorSpaceSupportFlag(true);
    auto type = dec->getHdrType();
    ASSERT_EQ(type, HeifImageHdrType::ISO_SINGLE);
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifHdrType_SupportedBT2020_10bit end";
}
#endif // HEIF_HW_DECODE_ENABLE

}
}