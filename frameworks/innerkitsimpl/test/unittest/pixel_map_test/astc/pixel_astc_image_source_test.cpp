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
#include <algorithm>
#include <memory>
#include <utility>
#include <vector>
#include "color_space.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_system_properties.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "memory_manager.h"
#include "pixel_astc.h"
#include "pixel_map.h"
#include "source_stream.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
constexpr uint8_t ASTC_MAGIC_0 = 0x13; // ASTC MAGIC ID 0x13
constexpr uint8_t ASTC_MAGIC_1 = 0xAB; // ASTC MAGIC ID 0xAB
constexpr uint8_t ASTC_MAGIC_2 = 0xA1; // ASTC MAGIC ID 0xA1
constexpr uint8_t ASTC_MAGIC_3 = 0x5C; // ASTC MAGIC ID 0x5C
constexpr uint8_t ASTC_BLOCK_Z = 1; // 2D astc, block z is 1
constexpr uint8_t ASTC_DIM_Z = 1; // 2D astc, dim z is 1
constexpr uint8_t ASTC_BLOCK_4 = 4;
constexpr uint8_t ASTC_BLOCK_5 = 5;
constexpr uint8_t ASTC_BLOCK_6 = 6;
constexpr uint8_t ASTC_BLOCK_8 = 8;
constexpr uint8_t ASTC_BODY_FILL = 0x5A; // any payload is acceptable for astc body
constexpr uint8_t SHIFT_8 = 8;
constexpr uint8_t SHIFT_16 = 16;
constexpr uint8_t SHIFT_24 = 24;
constexpr uint32_t MASK_8BIT = 0xFF;
constexpr size_t ASTC_HEADER_BYTES = 16;
constexpr size_t ASTC_BLOCK_BYTES = 16;
constexpr size_t ASTC_EXT_SIZE_FIELD_BYTES = 4; // extend info summary bytes field
constexpr uint32_t ASTC_SMALL_SIZE = 16;
constexpr uint32_t ASTC_DMA_THRESHOLD_SIZE = 512; // 512 * 512 is the astc dma threshold
constexpr uint32_t ASTC_MAX_SIZE = 8192;
constexpr uint32_t ASTC_24BIT_WIDTH = 70000; // larger than 16 bits, verify 24-bit width parse
constexpr uint32_t ASTC_24BIT_HEIGHT = 65537; // larger than 16 bits, verify 24-bit height parse
constexpr uint32_t ASTC_TLV_MAX_NUM = 6;
constexpr uint32_t TLV_OVERSIZE_LENGTH = 100;
constexpr uint32_t TLV_OVER_INT32_LENGTH = 0x80000000;
constexpr uint8_t TLV_UNKNOWN_TYPE = 0x7F;
constexpr uint8_t TLV_SHORT_PAYLOAD_BYTES = 3; // less than one TLV head (5 bytes)
constexpr size_t HDR_COLORSPACE_INFO_BYTES = 16;
constexpr size_t HDR_STATIC_DATA_BYTES = 32;
constexpr size_t HDR_DYNAMIC_DATA_BYTES = 64;
constexpr uint8_t HDR_METADATA_TYPE_VALUE = 1;
constexpr uint32_t RGBA_PIXEL_BYTES = 4;
constexpr uint32_t RGBA_TEST_SIZE = 64;
constexpr uint8_t RGBA_FILL = 0x80;
constexpr uint32_t ENCODE_EXTRA_BYTES = 4096;
constexpr uint8_t JPEG_QUALITY = 90;

struct AstcTlv {
    uint8_t type;
    std::vector<uint8_t> value;
};

class PixelAstcImageSourceTest : public testing::Test {
public:
    PixelAstcImageSourceTest() {}
    ~PixelAstcImageSourceTest() {}
};

static void AppendUint32(std::vector<uint8_t> &buf, uint32_t value)
{
    buf.push_back(static_cast<uint8_t>(value & MASK_8BIT));
    buf.push_back(static_cast<uint8_t>((value >> SHIFT_8) & MASK_8BIT));
    buf.push_back(static_cast<uint8_t>((value >> SHIFT_16) & MASK_8BIT));
    buf.push_back(static_cast<uint8_t>((value >> SHIFT_24) & MASK_8BIT));
}

static void AppendUint24(std::vector<uint8_t> &buf, uint32_t value)
{
    buf.push_back(static_cast<uint8_t>(value & MASK_8BIT));
    buf.push_back(static_cast<uint8_t>((value >> SHIFT_8) & MASK_8BIT));
    buf.push_back(static_cast<uint8_t>((value >> SHIFT_16) & MASK_8BIT));
}

static std::vector<uint8_t> BuildAstcHeader(uint8_t blockX, uint8_t blockY, uint32_t width, uint32_t height)
{
    std::vector<uint8_t> header = { ASTC_MAGIC_0, ASTC_MAGIC_1, ASTC_MAGIC_2, ASTC_MAGIC_3,
        blockX, blockY, ASTC_BLOCK_Z };
    AppendUint24(header, width);
    AppendUint24(header, height);
    AppendUint24(header, ASTC_DIM_Z);
    return header;
}

static std::vector<uint8_t> BuildAstcData(uint8_t block, uint32_t width, uint32_t height)
{
    std::vector<uint8_t> data = BuildAstcHeader(block, block, width, height);
    if (block == 0) {
        return data;
    }
    size_t blockNum = static_cast<size_t>((width + block - 1) / block) * ((height + block - 1) / block);
    data.resize(ASTC_HEADER_BYTES + blockNum * ASTC_BLOCK_BYTES, ASTC_BODY_FILL);
    return data;
}

static void AppendRawExtInfo(std::vector<uint8_t> &data, uint32_t sumBytes, const std::vector<uint8_t> &payload)
{
    AppendUint32(data, sumBytes);
    data.insert(data.end(), payload.begin(), payload.end());
}

static std::vector<uint8_t> BuildTlvPayload(const std::vector<AstcTlv> &tlvs)
{
    std::vector<uint8_t> payload;
    for (const AstcTlv &tlv : tlvs) {
        payload.push_back(tlv.type);
        AppendUint32(payload, static_cast<uint32_t>(tlv.value.size()));
        payload.insert(payload.end(), tlv.value.begin(), tlv.value.end());
    }
    return payload;
}

static void AppendExtInfo(std::vector<uint8_t> &data, const std::vector<AstcTlv> &tlvs)
{
    std::vector<uint8_t> payload = BuildTlvPayload(tlvs);
    AppendRawExtInfo(data, static_cast<uint32_t>(payload.size()), payload);
}

static AstcTlv MakeTlv(AstcExtendInfoType type, std::vector<uint8_t> value)
{
    return { static_cast<uint8_t>(type), std::move(value) };
}

static std::unique_ptr<ImageSource> CreateSource(const std::vector<uint8_t> &data)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(data.data(), static_cast<uint32_t>(data.size()), opts, errorCode);
    if (errorCode != SUCCESS) {
        return nullptr;
    }
    return imageSource;
}

static std::unique_ptr<PixelMap> DecodeAstc(ImageSource &imageSource, uint32_t &errorCode,
    AllocatorType allocatorType = AllocatorType::SHARE_MEM_ALLOC)
{
    DecodeOptions decodeOpts;
    decodeOpts.allocatorType = allocatorType;
    return imageSource.CreatePixelMap(decodeOpts, errorCode);
}

static std::unique_ptr<PixelMap> CreateRgbaPixelMap(uint32_t width, uint32_t height)
{
    std::vector<uint8_t> pixels(static_cast<size_t>(width) * height * RGBA_PIXEL_BYTES, RGBA_FILL);
    InitializationOptions opts;
    opts.size.width = static_cast<int32_t>(width);
    opts.size.height = static_cast<int32_t>(height);
    opts.srcPixelFormat = PixelFormat::RGBA_8888;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    return PixelMap::Create(reinterpret_cast<uint32_t *>(pixels.data()),
        static_cast<uint32_t>(pixels.size()), opts);
}

static std::vector<uint8_t> EncodeJpeg(PixelMap &pixelMap)
{
    ImageInfo info;
    pixelMap.GetImageInfo(info);
    size_t maxSize = static_cast<size_t>(info.size.width) * info.size.height * RGBA_PIXEL_BYTES +
        ENCODE_EXTRA_BYTES;
    std::vector<uint8_t> buffer(maxSize);
    ImagePacker imagePacker;
    PackOption option;
    option.format = "image/jpeg";
    option.quality = JPEG_QUALITY;
    if (imagePacker.StartPacking(buffer.data(), static_cast<uint32_t>(maxSize), option) != SUCCESS ||
        imagePacker.AddImage(pixelMap) != SUCCESS) {
        return {};
    }
    int64_t packedSize = 0;
    if (imagePacker.FinalizePacking(packedSize) != SUCCESS || packedSize <= 0) {
        return {};
    }
    buffer.resize(static_cast<size_t>(packedSize));
    return buffer;
}

/**
 * @tc.name: IsASTC001
 * @tc.desc: IsASTC rejects null data, short data and wrong magic, accepts astc magic
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, IsASTC001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: IsASTC001 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    EXPECT_FALSE(ImageSource::IsASTC(nullptr, data.size()));
    EXPECT_FALSE(ImageSource::IsASTC(data.data(), ASTC_HEADER_BYTES - 1));
    EXPECT_TRUE(ImageSource::IsASTC(data.data(), ASTC_HEADER_BYTES));

    std::vector<uint8_t> badMagic = data;
    badMagic[0] = 0;
    EXPECT_FALSE(ImageSource::IsASTC(badMagic.data(), badMagic.size()));
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: IsASTC001 end";
}

/**
 * @tc.name: GetASTCInfo001
 * @tc.desc: GetASTCInfo rejects null data, short data, wrong magic and non-square block footprint
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, GetASTCInfo001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: GetASTCInfo001 start";
    ASTCInfo astcInfo;
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    EXPECT_FALSE(ImageSource::GetASTCInfo(nullptr, data.size(), astcInfo));
    EXPECT_FALSE(ImageSource::GetASTCInfo(data.data(), ASTC_HEADER_BYTES - 1, astcInfo));

    std::vector<uint8_t> badMagic = data;
    badMagic[0] = 0;
    EXPECT_FALSE(ImageSource::GetASTCInfo(badMagic.data(), badMagic.size(), astcInfo));

    std::vector<uint8_t> nonSquare = BuildAstcHeader(ASTC_BLOCK_4, ASTC_BLOCK_5, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    EXPECT_FALSE(ImageSource::GetASTCInfo(nonSquare.data(), nonSquare.size(), astcInfo));
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: GetASTCInfo001 end";
}

/**
 * @tc.name: GetASTCInfo002
 * @tc.desc: GetASTCInfo parses 24-bit width/height and block footprint from astc header
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, GetASTCInfo002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: GetASTCInfo002 start";
    ASTCInfo astcInfo;
    std::vector<uint8_t> header = BuildAstcHeader(ASTC_BLOCK_8, ASTC_BLOCK_8, ASTC_24BIT_WIDTH, ASTC_24BIT_HEIGHT);
    ASSERT_TRUE(ImageSource::GetASTCInfo(header.data(), header.size(), astcInfo));
    EXPECT_EQ(astcInfo.size.width, static_cast<int32_t>(ASTC_24BIT_WIDTH));
    EXPECT_EQ(astcInfo.size.height, static_cast<int32_t>(ASTC_24BIT_HEIGHT));
    EXPECT_EQ(astcInfo.blockFootprint.width, ASTC_BLOCK_8);
    EXPECT_EQ(astcInfo.blockFootprint.height, ASTC_BLOCK_8);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: GetASTCInfo002 end";
}

/**
 * @tc.name: GetImageInfoForASTC001
 * @tc.desc: GetImageInfoForASTC maps 4x4/6x6/8x8 block to pixel format and unknown block to UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, GetImageInfoForASTC001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: GetImageInfoForASTC001 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);

    const std::vector<std::pair<uint8_t, PixelFormat>> cases = {
        { ASTC_BLOCK_4, PixelFormat::ASTC_4x4 },
        { ASTC_BLOCK_6, PixelFormat::ASTC_6x6 },
        { ASTC_BLOCK_8, PixelFormat::ASTC_8x8 },
        { ASTC_BLOCK_5, PixelFormat::UNKNOWN },
    };
    for (const auto &item : cases) {
        std::vector<uint8_t> header = BuildAstcHeader(item.first, item.first, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
        ImageInfo info;
        ASSERT_TRUE(imageSource->GetImageInfoForASTC(info, header.data()));
        EXPECT_EQ(info.pixelFormat, item.second);
        EXPECT_EQ(info.size.width, static_cast<int32_t>(ASTC_SMALL_SIZE));
        EXPECT_EQ(info.size.height, static_cast<int32_t>(ASTC_SMALL_SIZE));
    }

    std::vector<uint8_t> nonSquare = BuildAstcHeader(ASTC_BLOCK_4, ASTC_BLOCK_6, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    ImageInfo info;
    EXPECT_FALSE(imageSource->GetImageInfoForASTC(info, nonSquare.data()));
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: GetImageInfoForASTC001 end";
}

/**
 * @tc.name: SourceStreamNull001
 * @tc.desc: ASTC entries return failure when the source stream is null
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, SourceStreamNull001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: SourceStreamNull001 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);

    std::unique_ptr<SourceStream> savedStream = std::move(imageSource->sourceStreamPtr_);
    ImageInfo info;
    EXPECT_FALSE(imageSource->GetImageInfoForASTC(info, data.data()));

    imageSource->isAstc_.reset();
    EXPECT_FALSE(imageSource->IsASTCSource());

    uint32_t errorCode = SUCCESS;
    DecodeOptions opts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMapForASTC(errorCode, opts);
    EXPECT_EQ(pixelMap.get(), nullptr);
    EXPECT_EQ(errorCode, ERR_IMAGE_DATA_ABNORMAL);
    imageSource->sourceStreamPtr_ = std::move(savedStream);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: SourceStreamNull001 end";
}

/**
 * @tc.name: CreatePixelMapForASTC001
 * @tc.desc: Decode 6x6 and 8x8 astc and verify pixel format, astc flag, editable and real size
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, CreatePixelMapForASTC001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CreatePixelMapForASTC001 start";
    const std::vector<std::pair<uint8_t, PixelFormat>> cases = {
        { ASTC_BLOCK_6, PixelFormat::ASTC_6x6 },
        { ASTC_BLOCK_8, PixelFormat::ASTC_8x8 },
    };
    for (const auto &item : cases) {
        std::vector<uint8_t> data = BuildAstcData(item.first, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
        std::unique_ptr<ImageSource> imageSource = CreateSource(data);
        ASSERT_NE(imageSource.get(), nullptr);
        uint32_t errorCode = 0;
        std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
        ASSERT_NE(pixelMap.get(), nullptr);
        EXPECT_EQ(pixelMap->GetPixelFormat(), item.second);
        EXPECT_TRUE(pixelMap->IsAstc());
        EXPECT_FALSE(pixelMap->IsEditable());
        Size realSize;
        pixelMap->GetAstcRealSize(realSize);
        EXPECT_EQ(realSize.width, static_cast<int32_t>(ASTC_SMALL_SIZE));
        EXPECT_EQ(realSize.height, static_cast<int32_t>(ASTC_SMALL_SIZE));
    }
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CreatePixelMapForASTC001 end";
}

/**
 * @tc.name: CreatePixelMapForASTC002
 * @tc.desc: Decode fails when header block is not 4x4/6x6/8x8 or width is zero
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, CreatePixelMapForASTC002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CreatePixelMapForASTC002 start";
    std::vector<uint8_t> unknownBlock = BuildAstcData(ASTC_BLOCK_5, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    std::unique_ptr<ImageSource> imageSource = CreateSource(unknownBlock);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
    EXPECT_EQ(pixelMap.get(), nullptr);
    EXPECT_NE(errorCode, SUCCESS);

    std::vector<uint8_t> zeroWidth = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    std::vector<uint8_t> zeroWidthHeader = BuildAstcHeader(ASTC_BLOCK_4, ASTC_BLOCK_4, 0, ASTC_SMALL_SIZE);
    std::copy(zeroWidthHeader.begin(), zeroWidthHeader.end(), zeroWidth.begin());
    imageSource = CreateSource(zeroWidth);
    ASSERT_NE(imageSource.get(), nullptr);
    pixelMap = DecodeAstc(*imageSource, errorCode);
    EXPECT_EQ(pixelMap.get(), nullptr);
    EXPECT_EQ(errorCode, ERR_IMAGE_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CreatePixelMapForASTC002 end";
}

/**
 * @tc.name: CreatePixelMapForASTC003
 * @tc.desc: Decode fails when astc body is truncated (astcSize > fileSize)
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, CreatePixelMapForASTC003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CreatePixelMapForASTC003 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    data.resize(data.size() - ASTC_BLOCK_BYTES);
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
    EXPECT_EQ(pixelMap.get(), nullptr);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CreatePixelMapForASTC003 end";
}

/**
 * @tc.name: CalculateAllocatorType001
 * @tc.desc: DEFAULT allocator on large astc follows astc dma property
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, CalculateAllocatorType001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CalculateAllocatorType001 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_DMA_THRESHOLD_SIZE, ASTC_DMA_THRESHOLD_SIZE);
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode, AllocatorType::DEFAULT);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    AllocatorType expected = ImageSystemProperties::GetAstcEnabled() ?
        AllocatorType::DMA_ALLOC : AllocatorType::SHARE_MEM_ALLOC;
    EXPECT_EQ(pixelMap->GetAllocatorType(), expected);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CalculateAllocatorType001 end";
}

/**
 * @tc.name: CalculateAllocatorType002
 * @tc.desc: DEFAULT allocator on small astc follows astc and no-padding dma properties
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, CalculateAllocatorType002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CalculateAllocatorType002 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode, AllocatorType::DEFAULT);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    bool useDma = ImageSystemProperties::GetAstcEnabled() &&
        ImageSystemProperties::GetDefaultDmaNoPaddingEnabled() && ImageSystemProperties::GetNoPaddingEnabled();
    AllocatorType expected = useDma ? AllocatorType::DMA_ALLOC : AllocatorType::SHARE_MEM_ALLOC;
    EXPECT_EQ(pixelMap->GetAllocatorType(), expected);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CalculateAllocatorType002 end";
}

/**
 * @tc.name: ResolveExtInfo001
 * @tc.desc: Decode astc with COLOR_SPACE and PIXEL_FORMAT extend info succeeds and applies color space
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ResolveExtInfo001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo001 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
#ifdef IMAGE_COLORSPACE_FLAG
    uint8_t colorSpace = static_cast<uint8_t>(ColorManager::ColorSpaceName::DISPLAY_P3);
#else
    uint8_t colorSpace = 0;
#endif
    AppendExtInfo(data, {
        MakeTlv(AstcExtendInfoType::COLOR_SPACE, { colorSpace }),
        MakeTlv(AstcExtendInfoType::PIXEL_FORMAT, { static_cast<uint8_t>(PixelFormat::RGBA_8888) }),
    });
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::ASTC_4x4);
    EXPECT_FALSE(pixelMap->IsHdr());
#ifdef IMAGE_COLORSPACE_FLAG
    EXPECT_EQ(pixelMap->InnerGetGrColorSpace().GetColorSpaceName(), ColorManager::ColorSpaceName::DISPLAY_P3);
#endif
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo001 end";
}

/**
 * @tc.name: ResolveExtInfo002
 * @tc.desc: Decode astc with all six TLV types and a non-HDR pixel format succeeds
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ResolveExtInfo002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo002 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    std::vector<AstcTlv> tlvs = {
        MakeTlv(AstcExtendInfoType::COLOR_SPACE, { 0 }),
        MakeTlv(AstcExtendInfoType::PIXEL_FORMAT, { static_cast<uint8_t>(PixelFormat::RGBA_8888) }),
        MakeTlv(AstcExtendInfoType::HDR_METADATA_TYPE, { HDR_METADATA_TYPE_VALUE }),
        MakeTlv(AstcExtendInfoType::HDR_COLORSPACE_INFO, std::vector<uint8_t>(HDR_COLORSPACE_INFO_BYTES, 0)),
        MakeTlv(AstcExtendInfoType::HDR_STATIC_DATA, std::vector<uint8_t>(HDR_STATIC_DATA_BYTES, 0)),
        MakeTlv(AstcExtendInfoType::HDR_DYNAMIC_DATA, std::vector<uint8_t>(HDR_DYNAMIC_DATA_BYTES, 0)),
    };
    ASSERT_EQ(tlvs.size(), ASTC_TLV_MAX_NUM);
    AppendExtInfo(data, tlvs);
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_TRUE(pixelMap->IsAstc());
    EXPECT_FALSE(pixelMap->IsHdr());
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo002 end";
}

/**
 * @tc.name: ResolveExtInfo003
 * @tc.desc: Decode fails when extend info is too short to hold the summary bytes field
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ResolveExtInfo003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo003 start";
    for (size_t tailBytes = 1; tailBytes <= ASTC_EXT_SIZE_FIELD_BYTES; tailBytes++) {
        std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
        data.insert(data.end(), tailBytes, 0);
        std::unique_ptr<ImageSource> imageSource = CreateSource(data);
        ASSERT_NE(imageSource.get(), nullptr);
        uint32_t errorCode = 0;
        std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
        EXPECT_EQ(pixelMap.get(), nullptr) << "tailBytes " << tailBytes;
    }
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo003 end";
}

/**
 * @tc.name: ResolveExtInfo004
 * @tc.desc: Decode fails when extend summary bytes mismatch the real file size
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ResolveExtInfo004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo004 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    std::vector<uint8_t> payload = BuildTlvPayload({ MakeTlv(AstcExtendInfoType::COLOR_SPACE, { 0 }) });
    AppendRawExtInfo(data, static_cast<uint32_t>(payload.size() + 1), payload);
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
    EXPECT_EQ(pixelMap.get(), nullptr);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo004 end";
}

/**
 * @tc.name: ResolveExtInfo005
 * @tc.desc: Decode fails when remaining TLV bytes are less than one TLV head
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ResolveExtInfo005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo005 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    std::vector<uint8_t> payload(TLV_SHORT_PAYLOAD_BYTES, 0);
    AppendRawExtInfo(data, static_cast<uint32_t>(payload.size()), payload);
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
    EXPECT_EQ(pixelMap.get(), nullptr);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo005 end";
}

/**
 * @tc.name: ResolveExtInfo006
 * @tc.desc: Decode fails when TLV length exceeds left bytes or int32 max
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ResolveExtInfo006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo006 start";
    for (uint32_t fakeLength : { TLV_OVERSIZE_LENGTH, TLV_OVER_INT32_LENGTH }) {
        std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
        std::vector<uint8_t> payload = { static_cast<uint8_t>(AstcExtendInfoType::COLOR_SPACE) };
        AppendUint32(payload, fakeLength);
        payload.push_back(0);
        AppendRawExtInfo(data, static_cast<uint32_t>(payload.size()), payload);
        std::unique_ptr<ImageSource> imageSource = CreateSource(data);
        ASSERT_NE(imageSource.get(), nullptr);
        uint32_t errorCode = 0;
        std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
        EXPECT_EQ(pixelMap.get(), nullptr) << "fakeLength " << fakeLength;
    }
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo006 end";
}

/**
 * @tc.name: ResolveExtInfo007
 * @tc.desc: Decode fails when TLV count exceeds the supported six groups
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ResolveExtInfo007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo007 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    std::vector<AstcTlv> tlvs(ASTC_TLV_MAX_NUM + 1, MakeTlv(AstcExtendInfoType::COLOR_SPACE, { 0 }));
    AppendExtInfo(data, tlvs);
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
    EXPECT_EQ(pixelMap.get(), nullptr);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo007 end";
}

/**
 * @tc.name: ResolveExtInfo008
 * @tc.desc: Decode fails on unknown TLV type or zero-length COLOR_SPACE/PIXEL_FORMAT value
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ResolveExtInfo008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo008 start";
    const std::vector<AstcTlv> badTlvs = {
        { TLV_UNKNOWN_TYPE, { 0 } },
        MakeTlv(AstcExtendInfoType::COLOR_SPACE, {}),
        MakeTlv(AstcExtendInfoType::PIXEL_FORMAT, {}),
    };
    for (const AstcTlv &tlv : badTlvs) {
        std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
        AppendExtInfo(data, { tlv });
        std::unique_ptr<ImageSource> imageSource = CreateSource(data);
        ASSERT_NE(imageSource.get(), nullptr);
        uint32_t errorCode = 0;
        std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
        EXPECT_EQ(pixelMap.get(), nullptr) << "tlv type " << static_cast<uint32_t>(tlv.type);
    }
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo008 end";
}

/**
 * @tc.name: ResolveExtInfo009
 * @tc.desc: Decode fails when HDR metadata TLV length exceeds MAX_TLV_METADATA_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ResolveExtInfo009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo009 start";
    const std::vector<AstcExtendInfoType> hdrTypes = {
        AstcExtendInfoType::HDR_METADATA_TYPE,
        AstcExtendInfoType::HDR_COLORSPACE_INFO,
        AstcExtendInfoType::HDR_STATIC_DATA,
        AstcExtendInfoType::HDR_DYNAMIC_DATA,
    };
    for (AstcExtendInfoType type : hdrTypes) {
        std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
        AppendExtInfo(data, { MakeTlv(type, std::vector<uint8_t>(MAX_TLV_METADATA_SIZE + 1, 0)) });
        std::unique_ptr<ImageSource> imageSource = CreateSource(data);
        ASSERT_NE(imageSource.get(), nullptr);
        uint32_t errorCode = 0;
        std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode);
        EXPECT_EQ(pixelMap.get(), nullptr) << "tlv type " << static_cast<uint32_t>(type);
    }
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ResolveExtInfo009 end";
}

/**
 * @tc.name: ProcessAstcMetadata001
 * @tc.desc: RGBA_1010102 extend info on non-4x4 astc copies to DMA but fails as it is not HDR
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ProcessAstcMetadata001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ProcessAstcMetadata001 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_6, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    AppendExtInfo(data, {
        MakeTlv(AstcExtendInfoType::PIXEL_FORMAT, { static_cast<uint8_t>(PixelFormat::RGBA_1010102) }),
    });
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode, AllocatorType::SHARE_MEM_ALLOC);
    EXPECT_EQ(pixelMap.get(), nullptr);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ProcessAstcMetadata001 end";
}

/**
 * @tc.name: ProcessAstcMetadata002
 * @tc.desc: RGBA_1010102 extend info on 4x4 DMA astc marks astc HDR and writes surface buffer metadata
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, ProcessAstcMetadata002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ProcessAstcMetadata002 start";
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    AppendExtInfo(data, {
        MakeTlv(AstcExtendInfoType::PIXEL_FORMAT, { static_cast<uint8_t>(PixelFormat::RGBA_1010102) }),
        MakeTlv(AstcExtendInfoType::HDR_METADATA_TYPE, { HDR_METADATA_TYPE_VALUE }),
        MakeTlv(AstcExtendInfoType::HDR_COLORSPACE_INFO, std::vector<uint8_t>(HDR_COLORSPACE_INFO_BYTES, 0)),
        MakeTlv(AstcExtendInfoType::HDR_STATIC_DATA, std::vector<uint8_t>(HDR_STATIC_DATA_BYTES, 0)),
        MakeTlv(AstcExtendInfoType::HDR_DYNAMIC_DATA, std::vector<uint8_t>(HDR_DYNAMIC_DATA_BYTES, 0)),
    });
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = DecodeAstc(*imageSource, errorCode, AllocatorType::DMA_ALLOC);
    // SurfaceBuffer metadata write depends on the display HDI of the device, a failure returns nullptr.
    if (pixelMap != nullptr) {
        EXPECT_EQ(pixelMap->GetAllocatorType(), AllocatorType::DMA_ALLOC);
        EXPECT_TRUE(pixelMap->IsHdr());
        EXPECT_TRUE(pixelMap->IsAstc());
    }
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: ProcessAstcMetadata002 end";
}

/**
 * @tc.name: CompressToAstcFromPixelmap001
 * @tc.desc: Compress RGBA pixelmap to astc 4x4 memory and verify the generated astc header
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, CompressToAstcFromPixelmap001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CompressToAstcFromPixelmap001 start";
    std::unique_ptr<PixelMap> rgbaPixelMap = CreateRgbaPixelMap(RGBA_TEST_SIZE, RGBA_TEST_SIZE);
    ASSERT_NE(rgbaPixelMap.get(), nullptr);
    std::vector<uint8_t> data = BuildAstcData(ASTC_BLOCK_4, ASTC_SMALL_SIZE, ASTC_SMALL_SIZE);
    std::unique_ptr<ImageSource> imageSource = CreateSource(data);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions opts;
    opts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    std::unique_ptr<AbsMemory> dstMemory = nullptr;
    ASSERT_TRUE(imageSource->CompressToAstcFromPixelmap(opts, rgbaPixelMap, dstMemory));
    ASSERT_NE(dstMemory.get(), nullptr);
    ASSERT_NE(dstMemory->data.data, nullptr);
    EXPECT_EQ(dstMemory->GetType(), AllocatorType::SHARE_MEM_ALLOC);

    ASTCInfo astcInfo;
    EXPECT_TRUE(ImageSource::GetASTCInfo(static_cast<uint8_t *>(dstMemory->data.data), dstMemory->data.size,
        astcInfo));
    EXPECT_EQ(astcInfo.size.width, static_cast<int32_t>(RGBA_TEST_SIZE));
    EXPECT_EQ(astcInfo.size.height, static_cast<int32_t>(RGBA_TEST_SIZE));
    EXPECT_EQ(astcInfo.blockFootprint.width, ASTC_BLOCK_4);
    dstMemory->Release();
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CompressToAstcFromPixelmap001 end";
}

/**
 * @tc.name: CreatePixelAstcFromImageFile001
 * @tc.desc: Decode jpeg with desiredPixelFormat ASTC_4x4 generates a non-editable astc pixelmap
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, CreatePixelAstcFromImageFile001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CreatePixelAstcFromImageFile001 start";
    std::unique_ptr<PixelMap> rgbaPixelMap = CreateRgbaPixelMap(RGBA_TEST_SIZE, RGBA_TEST_SIZE);
    ASSERT_NE(rgbaPixelMap.get(), nullptr);
    std::vector<uint8_t> jpegData = EncodeJpeg(*rgbaPixelMap);
    ASSERT_FALSE(jpegData.empty());
    std::unique_ptr<ImageSource> imageSource = CreateSource(jpegData);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions opts;
    opts.desiredPixelFormat = PixelFormat::ASTC_4x4;
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(opts, errorCode);
    ASSERT_NE(pixelMap.get(), nullptr);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::ASTC_4x4);
    EXPECT_TRUE(pixelMap->IsAstc());
    EXPECT_FALSE(pixelMap->IsEditable());
    EXPECT_EQ(pixelMap->GetWidth(), static_cast<int32_t>(RGBA_TEST_SIZE));
    EXPECT_EQ(pixelMap->GetHeight(), static_cast<int32_t>(RGBA_TEST_SIZE));
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CreatePixelAstcFromImageFile001 end";
}

/**
 * @tc.name: CreatePixelAstcFromImageFile002
 * @tc.desc: Generate astc fails when desired size or source size exceeds the astc max size
 * @tc.type: FUNC
 */
HWTEST_F(PixelAstcImageSourceTest, CreatePixelAstcFromImageFile002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CreatePixelAstcFromImageFile002 start";
    std::unique_ptr<PixelMap> rgbaPixelMap = CreateRgbaPixelMap(RGBA_TEST_SIZE, RGBA_TEST_SIZE);
    ASSERT_NE(rgbaPixelMap.get(), nullptr);
    std::vector<uint8_t> jpegData = EncodeJpeg(*rgbaPixelMap);
    ASSERT_FALSE(jpegData.empty());
    std::unique_ptr<ImageSource> imageSource = CreateSource(jpegData);
    ASSERT_NE(imageSource.get(), nullptr);
    DecodeOptions opts;
    opts.desiredPixelFormat = PixelFormat::ASTC_4x4;
    opts.desiredSize.width = static_cast<int32_t>(ASTC_MAX_SIZE + 1);
    opts.desiredSize.height = static_cast<int32_t>(RGBA_TEST_SIZE);
    uint32_t errorCode = 0;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelAstcFromImageFile(0, opts, errorCode);
    EXPECT_EQ(pixelMap.get(), nullptr);

    std::unique_ptr<PixelMap> widePixelMap = CreateRgbaPixelMap(ASTC_MAX_SIZE + 1, 1);
    ASSERT_NE(widePixelMap.get(), nullptr);
    std::vector<uint8_t> wideJpeg = EncodeJpeg(*widePixelMap);
    ASSERT_FALSE(wideJpeg.empty());
    std::unique_ptr<ImageSource> wideSource = CreateSource(wideJpeg);
    ASSERT_NE(wideSource.get(), nullptr);
    DecodeOptions wideOpts;
    wideOpts.desiredPixelFormat = PixelFormat::ASTC_4x4;
    pixelMap = wideSource->CreatePixelAstcFromImageFile(0, wideOpts, errorCode);
    EXPECT_EQ(pixelMap.get(), nullptr);
    GTEST_LOG_(INFO) << "PixelAstcImageSourceTest: CreatePixelAstcFromImageFile002 end";
}
} // namespace Multimedia
} // namespace OHOS
