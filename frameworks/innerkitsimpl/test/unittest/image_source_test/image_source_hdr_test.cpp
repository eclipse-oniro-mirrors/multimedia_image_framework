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
#include <gtest/gtest.h>
#include <fstream>
#include <fcntl.h>
#include <dlfcn.h>
#include "abs_image_decoder.h"
#include "hilog/log.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "hdr_helper.h"
#include "log_tags.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "image_source_util.h"
#include "file_source_stream.h"
#include "buffer_source_stream.h"
#include "ext_stream.h"
#include "jpeg_mpf_parser.h"
#include "image_packer.h"
#include "jpeglib.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::HiviewDFX;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL_TEST = {
    LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "ImageSourceHdrTest"
};

constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
constexpr uint8_t JPEG_MARKER_APP2 = 0xE2;
constexpr uint8_t UINT32_BYTE_SIZE = 4;
constexpr uint8_t MAX_IMAGE_NUM = 32;
constexpr uint8_t MP_ENTRY_BYTE_SIZE = 16;
constexpr uint16_t AUXILIARY_TAG_NAME_LENGTH = 8;

static const std::string IMAGE_INPUT_JPEG_SDR_PATH = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_INPUT_HEIF_SDR_PATH = "/data/local/tmp/image/test.heic";
static const std::string IMAGE_INPUT_HEIF_10BIT_SDR_PATH = "/data/local/tmp/image/test-10bit-1.heic";
static const std::string IMAGE_INPUT_JPEG_HDR_PATH = "/data/local/tmp/image/hdr.jpg";
static const std::string IMAGE_INPUT_JPEG_HDR_VIVID_PATH = "/data/local/tmp/image/HdrVivid.jpg";
static const std::string IMAGE_INPUT_JPEG_HDR_MEDIA_TYPE_PATH = "/data/local/tmp/image/hdr_media_type_test.jpg";
static const std::string IMAGE_INPUT_BAD_MPF_OFFSET_PATH = "/data/local/tmp/image/bad_mpf_offset.jpg";
static const std::vector<uint8_t> HDR_METADATA_TYPE_BYTES = {
    0xFF, 0xEB, 0x00, 0x33, 0x75, 0x72, 0x6E, 0x3A, 0x68, 0x61, 0x72, 0x6D, 0x6F, 0x6E, 0x79, 0x6F,
    0x73, 0x3A, 0x6D, 0x75, 0x6C, 0x74, 0x69, 0x6D, 0x65, 0x64, 0x69, 0x61, 0x3A, 0x69, 0x6D, 0x61,
    0x67, 0x65, 0x3A, 0x76, 0x69, 0x64, 0x65, 0x6F, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x3A, 0x76, 0x31,
    0x00, 0x00, 0x00, 0x00, 0x05
};

class ImageSourceHdrTest : public testing::Test {
public:
    ImageSourceHdrTest() {}
    ~ImageSourceHdrTest() {}
};

typedef bool (*GetCuvaGainMapMetadataT)(jpeg_marker_struct* marker, std::vector<uint8_t>& metadata);

static uint32_t GetCuvaGainMapMetadataTest(jpeg_marker_struct* marker, std::vector<uint8_t>& metadata)
{
    auto handle = dlopen("libimage_cuva_parser.z.so", RTLD_LAZY);
    if (!handle) {
        return ERROR;
    }
    GetCuvaGainMapMetadataT getMetadata = (GetCuvaGainMapMetadataT)dlsym(handle, "GetCuvaGainMapMetadata");
    if (!getMetadata) {
        dlclose(handle);
        return ERROR;
    }
    if (getMetadata(marker, metadata)) {
        dlclose(handle);
        return SUCCESS;
    }
    dlclose(handle);
    return ERR_IMAGE_DATA_ABNORMAL;
}

/**
 * @tc.name: GetCuvaGainMapMetadataTest
 * @tc.desc: test the GetCuvaGainMapMetadata
 * @tc.type: when jpegMarker.marker != 0xE5, GetCuvaGainMapMetadata will fail,
            return ERR_IMAGE_DATA_ABNORMAL
 */
HWTEST_F(ImageSourceHdrTest, GetCuvaGainMapMetadataTest, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceHdrTest: GetCuvaGainMapMetadataTest start";
    jpeg_marker_struct jpegMarker;
    jpegMarker.marker = JPEG_MARKER_APP2;
    std::vector<uint8_t> metadata;
    uint32_t ret = GetCuvaGainMapMetadataTest(&jpegMarker, metadata);
    ASSERT_EQ(ret, ERR_IMAGE_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "ImageSourceHdrTest: GetCuvaGainMapMetadataTest end";
}

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
    uint32_t ret = 0;
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
    uint32_t ret = 0;
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

/**
 * @tc.name: GetHdrMetadataTest001
 * @tc.desc: test GetHdrMetadata get hdrMetadataType
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, GetHdrMetadataTest001, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
            ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_MEDIA_TYPE_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions opt;
    opt.desiredDynamicRange = DecodeDynamicRange::HDR;
    opt.desiredPixelFormat = PixelFormat::YCBCR_P010;
    imageSource->CreatePixelMap(opt, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource->jpegGainmapDecoder_, nullptr);
    auto metadata = imageSource->jpegGainmapDecoder_->GetHdrMetadata(ImageHdrType::HDR_CUVA);
    ASSERT_EQ(metadata.hdrMetadataType, 0);
}

/**
 * @tc.name: PackHdrMediaTypeMarkerTest001
 * @tc.desc: test PackHdrMediaTypeMarker
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, PackHdrMediaTypeMarkerTest001, TestSize.Level3)
{
    HdrMetadata hdrMetadata;
    hdrMetadata.hdrMetadataType = 5;
    auto bytes = ImagePlugin::HdrJpegPackerHelper::PackHdrMediaTypeMarker(hdrMetadata);
    ASSERT_EQ(bytes, HDR_METADATA_TYPE_BYTES);
}

/**
 * @tc.name: CheckPhotoDesiredPixelForamt002
 * @tc.desc: Test PhotoDesiredPixelForamt
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPhotoDesiredPixelForamt002, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_VIVID_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::SDR;
    optsPixel.photoDesiredPixelFormat = Media::PixelFormat::YCBCR_P010;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    ASSERT_EQ(pixelMap.get(), nullptr);
}

/**
 * @tc.name: CheckPhotoDesiredPixelForamt003
 * @tc.desc: Test PhotoDesiredPixelForamt
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPhotoDesiredPixelForamt003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_HDR_VIVID_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::HDR;
    optsPixel.photoDesiredPixelFormat = Media::PixelFormat::YCBCR_P010;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    bool isHdr = pixelMap->IsHdr();
    ASSERT_EQ(isHdr, true);
}

/**
 * @tc.name: CheckPhotoDesiredPixelForamt004
 * @tc.desc: Test PhotoDesiredPixelForamt
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPhotoDesiredPixelForamt004, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_JPEG_SDR_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);
#ifdef IMAGE_VPE_FLAG
    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::SDR;
    optsPixel.desiredPixelFormat = Media::PixelFormat::RGBA_8888;
    optsPixel.photoDesiredPixelFormat = Media::PixelFormat::NV12;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    Media::PixelFormat outputPixelFormat = pixelMap->GetPixelFormat();
    bool isNv12Format = (outputPixelFormat == Media::PixelFormat::NV12);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    bool isHdr = pixelMap->IsHdr();
    ASSERT_NE(isHdr, true);
    ASSERT_EQ(isNv12Format, true);
#endif
}

/**
 * @tc.name: CheckPhotoDesiredPixelForamt005
 * @tc.desc: Test PhotoDesiredPixelForamt
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPhotoDesiredPixelForamt005, TestSize.Level3)
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
    optsPixel.photoDesiredPixelFormat = Media::PixelFormat::YCBCR_P010;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    ASSERT_EQ(pixelMap.get(), nullptr);
}

/**
 * @tc.name: CheckPhotoDesiredPixelForamt006
 * @tc.desc: Test PhotoDesiredPixelForamt
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckPhotoDesiredPixelForamt006, TestSize.Level3)
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
    optsPixel.photoDesiredPixelFormat = Media::PixelFormat::YCBCR_P010;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_NE(errorCode, SUCCESS);
    ASSERT_EQ(pixelMap.get(), nullptr);
}

/**
 * @tc.name: CheckMpfOffsetTest001
 * @tc.desc: test CheckMptOffsetTest when data is normal or nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckMpfOffsetTest001, TestSize.Level3)
{
    auto jpegMpfParser = std::make_shared<JpegMpfParser>();
    ASSERT_NE(jpegMpfParser, nullptr);
    uint8_t buf[] = {0, 0, 0, 0, 0};
    uint32_t size = sizeof(buf);
    uint32_t offsetZero = 0;

    bool res = jpegMpfParser->CheckMpfOffset(nullptr, size, offsetZero);
    EXPECT_FALSE(res);

    res = jpegMpfParser->CheckMpfOffset(buf, size, offsetZero);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: CheckMpfOffsetTest002
 * @tc.desc: test CheckMptOffset when data is JPEG_MARKER_PREFIX or JPEG_MARKER_APP2
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckMpfOffsetTest002, TestSize.Level3)
{
    auto jpegMpfParser = std::make_shared<JpegMpfParser>();
    ASSERT_NE(jpegMpfParser, nullptr);
    uint8_t buf[] = {0, 0, 0, 0, 0};
    uint32_t size = sizeof(buf);
    uint32_t offset = 0;

    bool res = jpegMpfParser->CheckMpfOffset(buf, size, offset);
    EXPECT_FALSE(res);

    offset = 0;
    buf[0] = JPEG_MARKER_PREFIX;
    res = jpegMpfParser->CheckMpfOffset(buf, size, offset);
    EXPECT_FALSE(res);

    offset = 0;
    buf[0] = 1;
    buf[1] = JPEG_MARKER_APP2;
    res = jpegMpfParser->CheckMpfOffset(buf, size, offset);
    EXPECT_FALSE(res);

    offset = 0;
    buf[0] = JPEG_MARKER_PREFIX;
    buf[1] = JPEG_MARKER_APP2;
    res = jpegMpfParser->CheckMpfOffset(buf, size, offset);
    EXPECT_TRUE(res);
    EXPECT_EQ(offset, UINT32_BYTE_SIZE);
}

/**
 * @tc.name: CheckMpfOffsetTest003
 * @tc.desc: Test CheckJpegCuvaBadSourceImageDecodeToHdr
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, CheckMpfOffsetTest003, TestSize.Level3)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_INPUT_BAD_MPF_OFFSET_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    uint32_t index = 0;
    DecodeOptions optsPixel;
    optsPixel.desiredDynamicRange = Media::DecodeDynamicRange::AUTO;
    errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(index, optsPixel, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
#ifdef IMAGE_VPE_FLAG
    bool isHdr = pixelMap->IsHdr();
    ASSERT_NE(isHdr, true);
#endif
}

/**
 * @tc.name: ParsingTest001
 * @tc.desc: test Parsing when data is nullptr or size is 0
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, ParsingTest001, TestSize.Level3)
{
    auto jpegMpfParser = std::make_shared<JpegMpfParser>();
    ASSERT_NE(jpegMpfParser, nullptr);
    uint8_t buf[] = {0, 0, 0, 0, 0};
    uint32_t size = sizeof(buf);

    bool res = jpegMpfParser->Parsing(nullptr, size);
    EXPECT_FALSE(res);

    res = jpegMpfParser->Parsing(nullptr, 0);
    EXPECT_FALSE(res);

    res = jpegMpfParser->Parsing(buf, 0);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: ParsingMpIndexIFDTest001
 * @tc.desc: test ParsingMpIndexIFD when size is less than offset
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, ParsingMpIndexIFDTest001, TestSize.Level3)
{
    auto jpegMpfParser = std::make_shared<JpegMpfParser>();
    ASSERT_NE(jpegMpfParser, nullptr);

    bool res = jpegMpfParser->ParsingMpIndexIFD(nullptr, 0, 1, true);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: ParsingMpEntryTest001
 * @tc.desc: test ParsingMpEntry when imageNums is 0 or imageNums multiply MP_ENTRY_BYTE_SIZE over than size or
 *           imageNums over than MAX_IMAGE_NUM
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, ParsingMpEntryTest001, TestSize.Level3)
{
    auto jpegMpfParser = std::make_shared<JpegMpfParser>();
    ASSERT_NE(jpegMpfParser, nullptr);
    uint8_t buf[] = {0, 0, 0, 0, 0};
    uint32_t size = sizeof(buf);

    bool res = jpegMpfParser->ParsingMpEntry(buf, size, true, 0);
    EXPECT_FALSE(res);

    res = jpegMpfParser->ParsingMpEntry(buf, 0, true, 1);
    EXPECT_FALSE(res);

    size = (MAX_IMAGE_NUM + 1) * MP_ENTRY_BYTE_SIZE + 1;
    res = jpegMpfParser->ParsingMpEntry(buf, size, true, MAX_IMAGE_NUM + 1);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: ParsingAuxiliaryPicturesTest001
 * @tc.desc: test ParsingAuxiliaryPictures when data is nullptr or dataSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, ParsingAuxiliaryPicturesTest001, TestSize.Level3)
{
    auto jpegMpfParser = std::make_shared<JpegMpfParser>();
    ASSERT_NE(jpegMpfParser, nullptr);
    uint8_t buf[] = {0, 0, 0, 0, 0};
    uint32_t dataSize = sizeof(buf);

    bool res = jpegMpfParser->ParsingAuxiliaryPictures(nullptr, dataSize, true);
    EXPECT_FALSE(res);

    res = jpegMpfParser->ParsingAuxiliaryPictures(nullptr, 0, true);
    EXPECT_FALSE(res);

    res = jpegMpfParser->ParsingAuxiliaryPictures(buf, 0, true);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: ParsingAuxiliaryPicturesTest002
 * @tc.desc: test ParsingAuxiliaryPictures when size less than AUXILIARY_TAG_NAME_LENGTH
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, ParsingAuxiliaryPicturesTest002, TestSize.Level3)
{
    auto jpegMpfParser = std::make_shared<JpegMpfParser>();
    ASSERT_NE(jpegMpfParser, nullptr);
    uint8_t buf[] = {0, 0, 0, 0, 0};
    uint32_t dataSize = AUXILIARY_TAG_NAME_LENGTH - 1;

    bool res = jpegMpfParser->ParsingAuxiliaryPictures(buf, dataSize, true);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: ParsingFragmentMetadataTest001
 * @tc.desc: test ParsingFragmentMetadata when data is nullptr or dataSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, ParsingFragmentMetadataTest001, TestSize.Level3)
{
    auto jpegMpfParser = std::make_shared<JpegMpfParser>();
    ASSERT_NE(jpegMpfParser, nullptr);
    uint8_t buf[] = {0, 0, 0, 0, 0};
    uint32_t dataSize = sizeof(buf);
    OHOS::Media::Rect fragmentRect;

    bool res = jpegMpfParser->ParsingFragmentMetadata(nullptr, dataSize, fragmentRect, true);
    EXPECT_FALSE(res);

    res = jpegMpfParser->ParsingFragmentMetadata(nullptr, 0, fragmentRect, true);
    EXPECT_FALSE(res);

    res = jpegMpfParser->ParsingFragmentMetadata(buf, 0, fragmentRect, true);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: ParsingFragmentMetadataTest002
 * @tc.desc: test ParsingFragmentMetadata when size is less than the size calculated by offset
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceHdrTest, ParsingFragmentMetadataTest002, TestSize.Level3)
{
    auto jpegMpfParser = std::make_shared<JpegMpfParser>();
    ASSERT_NE(jpegMpfParser, nullptr);
    uint8_t buf[] = {0, 0, 0, 0, 0};
    uint32_t dataSize = sizeof(buf);
    OHOS::Media::Rect fragmentRect;

    bool res = jpegMpfParser->ParsingFragmentMetadata(buf, dataSize, fragmentRect, true);
    EXPECT_FALSE(res);
}
}
}