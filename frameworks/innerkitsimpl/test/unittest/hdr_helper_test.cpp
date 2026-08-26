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
#include <utility>
#include <vector>
#include "hdr_helper.h"
#include "include/codec/SkCodec.h"
#include "include/codec/SkEncodedImageFormat.h"
#include "jpeg_mpf_parser.h"
#include "SkStream.h"
#include "SkData.h"
#include "media_errors.h"
#include "src/codec/SkJpegCodec.h"
#include "src/codec/SkJpegDecoderMgr.h"
#include "jpeglib.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace ImagePlugin {
static const std::string IMAGE_PNG_PATH = "/data/local/tmp/image/test.png";
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_metadata.jpg";
static const uint8_t MOCK_SIZE = 10;
static const uint8_t ARRAY_INDEX_4 = 4;
static const uint8_t ARRAY_INDEX_10 = 10;
static const uint8_t STREAM_SIZE_10 = 10;

class HdrHelperTest : public testing::Test {
public:
    HdrHelperTest() {}
    ~HdrHelperTest() {}
};

class MockInputDataStream : public InputDataStream {
public:
    MockInputDataStream() = default;
    explicit MockInputDataStream(std::vector<uint8_t> data) : data_(std::move(data)) {}
    ~MockInputDataStream() = default;

    bool Read(uint32_t desiredSize, DataStreamBuffer &outData) override { return true; }
    bool Read(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
        { return true; }
    bool Peek(uint32_t desiredSize, DataStreamBuffer &outData) override { return true; }
    bool Peek(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
        { return true; }
    uint32_t Tell() override { return 0; }
    bool Seek(uint32_t position) override { return true; }
    uint8_t *GetDataPtr() override { return data_.empty() ? nullptr : data_.data(); }
    size_t GetStreamSize() override { return data_.empty() ? STREAM_SIZE_10 : data_.size(); }

private:
    std::vector<uint8_t> data_;
};

static std::vector<uint8_t> BuildIsoDualJpeg(bool validGainmapSoi, uint32_t& legacyOffset,
    uint32_t& gainmapOffset)
{
    constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
    constexpr uint8_t JPEG_MARKER_SOI = 0xD8;
    constexpr uint8_t JPEG_MARKER_APP1 = 0xE1;
    constexpr uint8_t JPEG_MARKER_DQT = 0xDB;
    constexpr uint8_t JPEG_MARKER_SOS = 0xDA;
    constexpr uint8_t JPEG_MARKER_EOI = 0xD9;
    constexpr uint32_t JPEG_DQT_SEGMENT_SIZE = 6;
    constexpr uint32_t MPF_TIFF_BASE_FROM_MARKER = 8;
    const std::vector<uint8_t> jpegPrefix = {
        JPEG_MARKER_PREFIX, JPEG_MARKER_SOI,
        JPEG_MARKER_PREFIX, JPEG_MARKER_APP1, 0x00, 0x06, 0x00, JPEG_MARKER_PREFIX, 0xE2, 0x00,
        JPEG_MARKER_PREFIX, JPEG_MARKER_DQT, 0x00, 0x04, 0x00, 0x00,
    };
    const std::vector<uint8_t> primaryTail = {
        JPEG_MARKER_PREFIX, JPEG_MARKER_SOS, 0x00, 0x02,
        JPEG_MARKER_PREFIX, JPEG_MARKER_EOI,
    };
    const uint8_t gainmapPrefix = validGainmapSoi ? JPEG_MARKER_PREFIX : 0x00;
    const uint8_t gainmapSoi = validGainmapSoi ? JPEG_MARKER_SOI : 0x00;
    const std::vector<uint8_t> gainmapJpeg = {
        gainmapPrefix, gainmapSoi,
        JPEG_MARKER_PREFIX, JPEG_MARKER_EOI,
    };
    const uint32_t mpfMarkerOffset = static_cast<uint32_t>(jpegPrefix.size());
    SingleJpegImage baseImage = {
        .offset = 0,
        .size = 0,
    };
    SingleJpegImage gainmapImage = {
        .offset = 0,
        .size = static_cast<uint32_t>(gainmapJpeg.size()),
    };
    std::vector<uint8_t> mpfMarker = JpegMpfPacker::PackHdrJpegMpfMarker(baseImage, gainmapImage);
    gainmapOffset = mpfMarkerOffset + static_cast<uint32_t>(mpfMarker.size()) +
        static_cast<uint32_t>(primaryTail.size());
    gainmapImage.offset = gainmapOffset - mpfMarkerOffset - MPF_TIFF_BASE_FROM_MARKER;
    baseImage.size = gainmapOffset;
    mpfMarker = JpegMpfPacker::PackHdrJpegMpfMarker(baseImage, gainmapImage);
    legacyOffset = mpfMarkerOffset - JPEG_DQT_SEGMENT_SIZE + MPF_TIFF_BASE_FROM_MARKER + gainmapImage.offset;

    std::vector<uint8_t> jpeg = jpegPrefix;
    jpeg.insert(jpeg.end(), mpfMarker.begin(), mpfMarker.end());
    jpeg.insert(jpeg.end(), primaryTail.begin(), primaryTail.end());
    jpeg.insert(jpeg.end(), gainmapJpeg.begin(), gainmapJpeg.end());
    return jpeg;
}

/**
 * @tc.name: CheckHdrTypeTest001
 * @tc.desc: Test CheckHdrType when SkEncodedImageFormat is PNG
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, CheckHdrTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: CheckHdrTypeTest001 start";
    auto data = SkData::MakeFromFileName(IMAGE_PNG_PATH.c_str());
    ASSERT_TRUE(data);
    auto codec = SkCodec::MakeFromData(data);
    ASSERT_NE(codec, nullptr);
    ASSERT_EQ(codec->getEncodedFormat(), SkEncodedImageFormat::kPNG);
    uint32_t offset = 0;
    ImageHdrType type = HdrHelper::CheckHdrType(codec.get(), offset);
    ASSERT_EQ(type, Media::ImageHdrType::SDR);
    GTEST_LOG_(INFO) << "HdrHelperTest: CheckHdrTypeTest001 end";
}

/**
 * @tc.name: CheckGainmapOffsetTest001
 * @tc.desc: Test CheckGainmapOffset when stream is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, CheckGainmapOffsetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: CheckGainmapOffsetTest001 start";
    ImageHdrType type = Media::ImageHdrType::SDR;
    InputDataStream* stream = nullptr;
    uint32_t offset = 0;
    bool result = HdrHelper::CheckGainmapOffset(type, stream, offset);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "HdrHelperTest: CheckGainmapOffsetTest001 end";
}

/**
 * @tc.name: CheckGainmapOffsetTest002
 * @tc.desc: Test CheckGainmapOffset when stream getdataptr is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, CheckGainmapOffsetTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: CheckGainmapOffsetTest002 start";
    ImageHdrType type = Media::ImageHdrType::SDR;
    MockInputDataStream* stream = new MockInputDataStream();
    uint32_t offset = 0;
    bool result = HdrHelper::CheckGainmapOffset(type, stream, offset);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "HdrHelperTest: CheckGainmapOffsetTest002 end";
}

/**
 * @tc.name: CheckGainmapOffsetTest004
 * @tc.desc: Reject an MPF-relative offset whose target is not a JPEG SOI
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, CheckGainmapOffsetTest004, TestSize.Level3)
{
    uint32_t legacyOffset = 0;
    uint32_t gainmapOffset = 0;
    std::vector<uint8_t> jpeg = BuildIsoDualJpeg(false, legacyOffset, gainmapOffset);
    MockInputDataStream stream(std::move(jpeg));
    uint32_t offset = legacyOffset;
    ASSERT_GT(gainmapOffset, legacyOffset);

    bool result = HdrHelper::CheckGainmapOffset(ImageHdrType::HDR_ISO_DUAL, &stream, offset);

    ASSERT_FALSE(result);
    ASSERT_EQ(offset, legacyOffset);
}

/**
 * @tc.name: CheckGainmapOffsetTest005
 * @tc.desc: Reject a truncated MPF APP2 segment without scanning beyond its declared bounds
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, CheckGainmapOffsetTest005, TestSize.Level3)
{
    std::vector<uint8_t> jpeg = {
        0xFF, 0xD8,
        0xFF, 0xE2, 0x00, 0x10, 'M', 'P', 'F', 0x00,
    };
    MockInputDataStream stream(std::move(jpeg));
    uint32_t offset = STREAM_SIZE_10;

    bool result = HdrHelper::CheckGainmapOffset(ImageHdrType::HDR_ISO_DUAL, &stream, offset);

    ASSERT_FALSE(result);
}

/**
 * @tc.name: CheckGainmapOffsetTest006
 * @tc.desc: Reject an ISO dual JPEG without an MPF APP2 segment
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, CheckGainmapOffsetTest006, TestSize.Level3)
{
    std::vector<uint8_t> jpeg = {
        0xFF, 0xD8,
        0xFF, 0xDB, 0x00, 0x04, 0x00, 0x00,
        0xFF, 0xDA, 0x00, 0x02,
        0xFF, 0xD9,
    };
    MockInputDataStream stream(std::move(jpeg));
    uint32_t offset = 0;

    bool result = HdrHelper::CheckGainmapOffset(ImageHdrType::HDR_ISO_DUAL, &stream, offset);

    ASSERT_FALSE(result);
}

/**
 * @tc.name: GetMetadataTest001
 * @tc.desc: Test GetMetadata when SkEncodedImageFormat is PNG
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, GetMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: GetMetadataTest001 start";
    auto data = SkData::MakeFromFileName(IMAGE_PNG_PATH.c_str());
    ASSERT_TRUE(data);
    auto codec = SkCodec::MakeFromData(data);
    ASSERT_NE(codec, nullptr);
    ASSERT_EQ(codec->getEncodedFormat(), SkEncodedImageFormat::kPNG);
    ImageHdrType type = ImageHdrType::HDR_VIVID_DUAL;
    HdrMetadata metadata;
    bool result = HdrHelper::GetMetadata(codec.get(), type, metadata);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "HdrHelperTest: GetMetadataTest001 end";
}

/**
 * @tc.name: PackISOMetadataMarkerTest001
 * @tc.desc: Test PackISOMetadataMarker when useBaseColorFlag is true gainmapChannelNum is 0 baseHeadroom is more than
 * EMPTY_ZISE and alternateHeadroom is less than EMPTY_ZISE
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, PackISOMetadataMarkerTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: PackISOMetadataMarkerTest001 start";
    HdrMetadata metadata;
    metadata.extendMeta.metaISO.useBaseColorFlag = true;
    metadata.extendMeta.metaISO.gainmapChannelNum = 0;
    metadata.extendMeta.metaISO.baseHeadroom = MOCK_SIZE;
    metadata.extendMeta.metaISO.alternateHeadroom = 0;
    auto result = HdrJpegPackerHelper::PackISOMetadataMarker(metadata);
    ASSERT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "HdrHelperTest: PackISOMetadataMarkerTest001 end";
}

/**
 * @tc.name: SpliceLogHdrStreamTest001
 * @tc.desc: Test SpliceLogHdrStream when baseImage is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, SpliceLogHdrStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: SpliceLogHdrStreamTest001 start";
    HdrJpegPackerHelper hdrJpegPackerHelper;
    sk_sp<SkData> baseImage = nullptr;
    SkDynamicMemoryWStream output;
    Media::HdrMetadata metadata;
    uint32_t result = hdrJpegPackerHelper.SpliceLogHdrStream(baseImage, output, metadata);
    ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "HdrHelperTest: SpliceLogHdrStreamTest001 end";
}

/**
 * @tc.name: SpliceLogHdrStreamTest002
 * @tc.desc: Test SpliceLogHdrStream when baseImage is invalid jpeg data
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, SpliceLogHdrStreamTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: SpliceLogHdrStreamTest002 start";
    HdrJpegPackerHelper hdrJpegPackerHelper;
    const char fakeData[ARRAY_INDEX_4] = {'A', 'B', 'C', 'D'};
    sk_sp<SkData> baseImage = SkData::MakeWithCopy(fakeData, sizeof(fakeData));
    SkDynamicMemoryWStream output;
    Media::HdrMetadata metadata;
    uint32_t result = hdrJpegPackerHelper.SpliceLogHdrStream(baseImage, output, metadata);
    ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "HdrHelperTest: SpliceLogHdrStreamTest002 end";
}

/**
 * @tc.name: SpliceLogHdrStreamTest003
 * @tc.desc: Test SpliceLogHdrStream when baseImage is valid jpeg data expect return SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, SpliceLogHdrStreamTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: SpliceLogHdrStreamTest003 start";
    HdrJpegPackerHelper hdrJpegPackerHelper;
    const char fakeData[ARRAY_INDEX_10] = {0xFF, 0xD8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    sk_sp<SkData> baseImage = SkData::MakeWithCopy(fakeData, sizeof(fakeData));
    SkDynamicMemoryWStream output;
    Media::HdrMetadata metadata;
    uint32_t result = hdrJpegPackerHelper.SpliceLogHdrStream(baseImage, output, metadata);
    ASSERT_EQ(result, SUCCESS);
    GTEST_LOG_(INFO) << "HdrHelperTest: SpliceLogHdrStreamTest003 end";
}

/**
 * @tc.name: GetJpegGainMapMetadataTest001
 * @tc.desc: Test GetJpegGainMapMetadata by calling GetMetadata when type is HDR_ISO_DUAL and HDR_ISO_SINGLE
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, GetJpegGainMapMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: GetJpegGainMapMetadataTest001 start";
    auto data = SkData::MakeFromFileName(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_TRUE(data);
    auto codec = SkCodec::MakeFromData(data);
    ASSERT_NE(codec, nullptr);
    ASSERT_EQ(codec->getEncodedFormat(), SkEncodedImageFormat::kJPEG);
    SkJpegCodec* jpegCodec = static_cast<SkJpegCodec*>(codec.get());
    ASSERT_NE(jpegCodec, nullptr);
    ASSERT_NE(jpegCodec->decoderMgr(), nullptr);
    jpeg_marker_struct* markerList = jpegCodec->decoderMgr()->dinfo()->marker_list;
    ASSERT_NE(markerList, nullptr);
    ImageHdrType type = ImageHdrType::HDR_ISO_DUAL;
    HdrMetadata metadata;
    bool result = HdrHelper::GetMetadata(codec.get(), type, metadata);
    ASSERT_FALSE(result);

    type = ImageHdrType::HDR_ISO_SINGLE;
    result = HdrHelper::GetMetadata(codec.get(), type, metadata);
    ASSERT_FALSE(result);
    GTEST_LOG_(INFO) << "HdrHelperTest: GetJpegGainMapMetadataTest001 end";
}

/**
 * @tc.name: CheckJpegGainMapHdrTypeTest001
 * @tc.desc: Test CheckJpegGainMapHdrType by calling CheckHdrType expect return ImageHdrType::SDR
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, CheckJpegGainMapHdrTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: CheckJpegGainMapHdrTypeTest001 start";
    auto data = SkData::MakeFromFileName(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_TRUE(data);
    auto codec = SkCodec::MakeFromData(data);
    ASSERT_NE(codec, nullptr);
    ASSERT_EQ(codec->getEncodedFormat(), SkEncodedImageFormat::kJPEG);
    SkJpegCodec* jpegCodec = static_cast<SkJpegCodec*>(codec.get());
    ASSERT_NE(jpegCodec, nullptr);
    ASSERT_NE(jpegCodec->decoderMgr(), nullptr);
    uint32_t offset = 0;
    ImageHdrType type = HdrHelper::CheckHdrType(codec.get(), offset);
    ASSERT_EQ(type, Media::ImageHdrType::SDR);
    GTEST_LOG_(INFO) << "HdrHelperTest: CheckJpegGainMapHdrTypeTest001 end";
}

/**
 * @tc.name: GetExtendMetadataSizeTest001
 * @tc.desc: Test GetExtendMetadataSize by caliing PackIT35Info when baseMappingFlag and combineMappingFlag > EMPTY_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, GetExtendMetadataSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: GetExtendMetadataSizeTest001 start";
    HdrMetadata metadata;
    metadata.extendMeta.baseColorMeta.baseMappingFlag = MOCK_SIZE;
    metadata.extendMeta.gainmapColorMeta.combineMappingFlag = MOCK_SIZE;
    std::vector<uint8_t> info;
    bool res = HdrHeifPackerHelper::PackIT35Info(metadata, info);
    ASSERT_TRUE(res);
    GTEST_LOG_(INFO) << "HdrHelperTest: GetExtendMetadataSizeTest001 end";
}

/**
 * @tc.name: WriteJpegPreAppTest001
 * @tc.desc: Test WriteJpegPreApp by calling SpliceLogHdrStream when baseImage is invalid jpeg data
 * @tc.type: FUNC
 */
HWTEST_F(HdrHelperTest, WriteJpegPreAppTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HdrHelperTest: WriteJpegPreAppTest001 start";
    HdrJpegPackerHelper hdrJpegPackerHelper;
    const char fakeData[ARRAY_INDEX_4] = {0xFF, 0xD8, 0x00, 0x00};
    sk_sp<SkData> baseImage = SkData::MakeWithCopy(fakeData, sizeof(fakeData));
    SkDynamicMemoryWStream output;
    Media::HdrMetadata metadata;
    uint32_t result = hdrJpegPackerHelper.SpliceLogHdrStream(baseImage, output, metadata);
    ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "HdrHelperTest: WriteJpegPreAppTest001 end";
}
}
}
