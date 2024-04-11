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
#include <gtest/gtest.h>
#include "ext_pixel_convert.h"
#include "ext_wstream.h"
#include "ext_decoder.h"
#include "plugin_export.h"
#include "ext_encoder.h"
#include "ext_stream.h"
#include "mock_data_stream.h"
#include "file_source_stream.h"

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
const static string CODEC_INITED_KEY = "CodecInited";
const static string ENCODED_FORMAT_KEY = "EncodedFormat";
const static string SUPPORT_SCALE_KEY = "SupportScale";
const static string SUPPORT_CROP_KEY = "SupportCrop";
const static string EXT_SHAREMEM_NAME = "EXT RawData";
class ExtDecoderTest : public testing::Test {
public:
    ExtDecoderTest() {}
    ~ExtDecoderTest() {}
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
 * @tc.name: GetScaledSizeTest001
 * @tc.desc: Test of GetScaledSize
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, GetScaledSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetScaledSizeTest001 start";
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    EXIFInfo exifInfo_;
    int dWidth = 0;
    int dHeight = 0;
    float scale = ZERO;
    extDecoder->codec_ = nullptr;
    bool ret = extDecoder->GetScaledSize(dWidth, dHeight, scale);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetScaledSizeTest001 end";
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
    PlSize size;
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
    PlAlphaType outputType;
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
    PlPixelFormat outputFormat;
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
    PlAlphaType desiredType;
    PlAlphaType outputType;
    desiredType = PlAlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    auto ret = extDecoder->ConvertToAlphaType(desiredType, outputType);
    ASSERT_EQ(outputType, PlAlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
    ASSERT_EQ(ret, SkAlphaType::kOpaque_SkAlphaType);

    desiredType = PlAlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    ret = extDecoder->ConvertToAlphaType(desiredType, outputType);
    ASSERT_EQ(outputType, PlAlphaType::IMAGE_ALPHA_TYPE_PREMUL);
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
    PlPixelFormat format;
    PlPixelFormat outputFormat;
    format = PlPixelFormat::RGBA_8888;
    auto ret = extDecoder->ConvertToColorType(format, outputFormat);
    ASSERT_EQ(outputFormat, PlPixelFormat::RGBA_8888);
    ASSERT_EQ(ret, kRGBA_8888_SkColorType);

    format = PlPixelFormat::UNKNOWN;
    ret = extDecoder->ConvertToColorType(format, outputFormat);
    ASSERT_EQ(outputFormat, PlPixelFormat::RGBA_8888);
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
    ASSERT_EQ(extWStream.stream_, nullptr);
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
    ASSERT_EQ(extWStream.stream_, nullptr);
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
    ASSERT_EQ(extWStream.stream_, nullptr);
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
    PlPixelFormat desiredFormat = PlPixelFormat::UNKNOWN;
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

    desiredFormat = PlPixelFormat::NV21;
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
    PlPixelFormat desiredFormat = PlPixelFormat::UNKNOWN;
    auto ret = extDecoder->GetJpegYuvOutFmt(desiredFormat);
    ASSERT_EQ(ret, JpegYuvFmt::OutFmt_NV12);
    desiredFormat = PlPixelFormat::NV12;
    ret = extDecoder->GetJpegYuvOutFmt(desiredFormat);
    ASSERT_EQ(ret, JpegYuvFmt::OutFmt_NV12);
    GTEST_LOG_(INFO) << "ExtDecoderTest: GetJpegYuvOutFmtTest001 end";
}
}
}