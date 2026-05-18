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

#include "pixel_map_test_base.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_HDR_PATH = "/data/local/tmp/image/hdr.jpg";

/**
 * @tc.name: HdrPixelMapTlvTest004
 * @tc.desc: Test HdrPixelMapTlv
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, HdrPixelMapTlvTest004, TestSize.Level3)
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
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    vector<uint8_t> buff;
    ASSERT_EQ(pixelMap->EncodeTlv(buff), true);
    std::unique_ptr<PixelMap> hdrPixelMap(PixelMap::DecodeTlv(buff));
    ASSERT_NE(hdrPixelMap, nullptr);
    ASSERT_EQ(hdrPixelMap->GetAllocatorType(), pixelMap->GetAllocatorType());
}

/**
 * @tc.name: HdrPixelMapTlvTest005
 * @tc.desc: Test PixelMapTlv
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, HdrPixelMapTlvTest005, TestSize.Level3)
{
    InitializationOptions opts;
    opts.size.width = 512;
    opts.size.height = 512;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);
    vector<uint8_t> buff;
    ASSERT_EQ(pixelMap->EncodeTlv(buff), true);
    std::unique_ptr<PixelMap> tlvPixelMap(PixelMap::DecodeTlv(buff));
    ASSERT_NE(tlvPixelMap, nullptr);
    ASSERT_NE(tlvPixelMap->GetAllocatorType(), pixelMap->GetAllocatorType());
    ASSERT_EQ(tlvPixelMap->GetAllocatorType(), AllocatorType::HEAP_ALLOC);
}

/**
 * @tc.name: HdrPixelMapTlvTest006
 * @tc.desc: Test HdrPixelMapTlvTest
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, HdrPixelMapTlvTest006, TestSize.Level3)
{
    PixelMap srcPixelMap;
    ImageInfo imageInfo;
    imageInfo.size.width = 200;
    imageInfo.size.height = 300;
    imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    imageInfo.colorSpace = ColorSpace::SRGB;
    srcPixelMap.SetImageInfo(imageInfo);
    int32_t rowDataSize = 200 * 4;
    uint32_t bufferSize = rowDataSize * 300;
    void *buffer = malloc(bufferSize);
    char *ch = static_cast<char *>(buffer);
    for (unsigned int i = 0; i < bufferSize; i++) {
        *(ch++) = static_cast<char>(i);
    }
    srcPixelMap.SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);

    vector<uint8_t> buff;
    ASSERT_EQ(srcPixelMap.EncodeTlv(buff), true);
    std::unique_ptr<PixelMap> tlvPixelMap(PixelMap::DecodeTlv(buff));
    ASSERT_NE(tlvPixelMap, nullptr);
    ASSERT_EQ(tlvPixelMap->GetAllocatorType(), AllocatorType::HEAP_ALLOC);
    ASSERT_EQ(tlvPixelMap->GetAllocatorType(), srcPixelMap.GetAllocatorType());
}

static int g_getPos(std::vector<uint8_t> &buff, uint8_t findTag)
{
    int32_t cursor = 0;
    for (uint8_t tag = PixelMap::ReadUint8(buff, cursor); tag != TLV_END; tag = PixelMap::ReadUint8(buff, cursor)) {
        if (tag == findTag) {
            return cursor - 1;
        }
        int32_t len = ImageUtils::ReadVarint(buff, cursor);
        if (tag == TLV_IMAGE_DATA || tag == TLV_IMAGE_STATICMETADATA || tag == TLV_IMAGE_DYNAMICMETADATA) {
            cursor += len;
            continue;
        }
        ImageUtils::ReadVarint(buff, cursor);
    }
    return -1;
}

/**
 * @tc.name: HdrPixelMapTlvTest007
 * @tc.desc: Test HdrPixelMapTlv
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, HdrPixelMapTlvTest007, TestSize.Level3)
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
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    std::vector<uint8_t> buff1, buff2, buff3, buff4;
    ASSERT_EQ(pixelMap->EncodeTlv(buff1), true);
    ASSERT_EQ(pixelMap->EncodeTlv(buff2), true);
    ASSERT_EQ(pixelMap->EncodeTlv(buff3), true);
    ASSERT_EQ(pixelMap->EncodeTlv(buff4), true);
    uint8_t pos1 = g_getPos(buff1, TLV_IMAGE_COLORTYPE); // record the position of TLV_IMAGE_COLORTYPE
    uint8_t pos2 = g_getPos(buff1, TLV_IMAGE_METADATATYPE); // record the position of TLV_IMAGE_METADATATYPE
    uint8_t pos3 = g_getPos(buff1, TLV_IMAGE_STATICMETADATA); // record the position of TLV_IMAGE_STATICMETADATA
    uint8_t pos4 = g_getPos(buff1, TLV_IMAGE_DYNAMICMETADATA); // record the position of TLV_IMAGE_DYNAMICMETADATA
    uint8_t pos5 = g_getPos(buff1, TLV_IMAGE_CSM); // record the position of TLV_IMAGE_CSM

    buff1.erase(buff1.begin() + pos1, buff1.begin() + pos2); // erase the TLV_IMAGE_COLORTYPE
    buff2.erase(buff2.begin() + pos2, buff2.begin() + pos3); // erase the TLV_IMAGE_METADATATYPE
    buff3.erase(buff3.begin() + pos3, buff3.begin() + pos4); // erase the TLV_IMAGE_STATICMETADATA
    buff4.erase(buff4.begin() + pos4, buff4.begin() + pos5); // erase the TLV_IMAGE_DYNAMICMETADATATYPE

    ASSERT_NE(PixelMap::DecodeTlv(buff1), nullptr); // Test DecodeTlv with TLV_IMAGE_COLORTYPE removed
    ASSERT_NE(PixelMap::DecodeTlv(buff2), nullptr); // Test DecodeTlv with TLV_IMAGE_METADATATYPE removed
    ASSERT_NE(PixelMap::DecodeTlv(buff3), nullptr); // Test DecodeTlv with TLV_IMAGE_STATICMETADATATYPE removed
    ASSERT_NE(PixelMap::DecodeTlv(buff4), nullptr); // Test DecodeTlv with TLV_IMAGE_DYNAMICMETADATA removed
#endif
}

/**
 * @tc.name: Verify parameter validation of PixelMap::Create
 * @tc.desc: Verify invalid size.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreatePixelMapInvalidSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: CreatePixelMapInvalidSizeTest001 start";
    InitializationOptions opts;
    opts.size.width = 0;
    opts.size.height = 0;
    opts.pixelFormat = PixelFormat::NV21;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    EXPECT_EQ(pixelMap, nullptr);
    opts.size.width = 512;
    opts.size.height = 512;
    opts.useDMA = true;
    std::unique_ptr<PixelMap> pixelMap1 = PixelMap::Create(opts);
    EXPECT_EQ(pixelMap1, nullptr);
    GTEST_LOG_(INFO) << "PixelMapTest: CreatePixelMapInvalidSizeTest001 end";
}

/**
 * @tc.name: Verify YUV Format
 * @tc.desc: Verify YUV Format.
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, CreatePixelMapYUVTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: Verify YUV Format Create001 start";

    InitializationOptions opts;
    opts.size.width = 512;
    opts.size.height = 512;
    opts.pixelFormat = PixelFormat::YCBCR_P010;
    opts.useDMA = true;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    EXPECT_NE(pixelMap, nullptr);
    GTEST_LOG_(INFO) << "PixelMapTest: Verify YUV Format Create001 end";
}

/**
 * @tc.name: RecoverAshMemFdClosedTest001
 * @tc.desc: Test Marshalling when fd is closed unexpectedly, trigger WriteRecoveredAshMemToParcel success path
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, RecoverAshMemFdClosedTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: RecoverAshMemFdClosedTest001 start";

    // Create PixelMap with SHARE_MEM_ALLOC type using InitializationOptions
    InitializationOptions opts;
    opts.size.width = SIZE_WIDTH;
    opts.size.height = SIZE_HEIGHT;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap->data_, nullptr);
    ASSERT_NE(pixelMap->context_, nullptr);

    // Store original data for verification (data_ should not be modified by recovery)
    int32_t bufferSize = pixelMap->GetByteCount();
    auto originalData = std::make_unique<uint8_t[]>(bufferSize);
    ASSERT_EQ(memcpy_s(originalData.get(), bufferSize, pixelMap->data_, bufferSize), EOK);

    // Get fd and close it to simulate unexpected closure
    // Note: Do NOT set *fd = -1 here, otherwise the fd < 0 check will
    // return early and skip the recovery logic. We want CheckAshmemSize
    // to detect the invalid fd and trigger WriteRecoveredAshMemToParcel.
    int* fd = static_cast<int*>(pixelMap->context_);
    ASSERT_NE(fd, nullptr);
    ::close(*fd);

    // Marshalling should trigger WriteRecoveredAshMemToParcel and succeed
    Parcel parcel;
    bool ret = pixelMap->Marshalling(parcel);
    EXPECT_TRUE(ret);

    // Verify data_ is not modified by recovery (new impl doesn't update data_)
    EXPECT_EQ(memcmp(pixelMap->data_, originalData.get(), bufferSize), 0);

    // Verify unmarshalling works correctly
    PixelMap* newPixelMap = PixelMap::Unmarshalling(parcel);
    ASSERT_NE(newPixelMap, nullptr);
    EXPECT_EQ(newPixelMap->GetWidth(), SIZE_WIDTH);
    EXPECT_EQ(newPixelMap->GetHeight(), SIZE_HEIGHT);

    GTEST_LOG_(INFO) << "PixelMapTest: RecoverAshMemFdClosedTest001 end";
}

/**
 * @tc.name: RecoverAshMemNullDataTest001
 * @tc.desc: Test Marshalling when data_ is null with SHARE_MEM_ALLOC, should fail
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, RecoverAshMemNullDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: RecoverAshMemNullDataTest001 start";

    InitializationOptions opts;
    opts.size.width = SIZE_WIDTH;
    opts.size.height = SIZE_HEIGHT;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);

    // Save original data pointer
    uint8_t* originalData = pixelMap->data_;
    pixelMap->data_ = nullptr;

    // Close fd to trigger recovery attempt
    int* fd = static_cast<int*>(pixelMap->context_);
    if (fd != nullptr && *fd >= 0) {
        ::close(*fd);
        *fd = -1;
    }

    // Marshalling should fail because data_ is null
    Parcel parcel;
    bool ret = pixelMap->Marshalling(parcel);
    EXPECT_FALSE(ret);

    // Restore for cleanup
    pixelMap->data_ = originalData;

    GTEST_LOG_(INFO) << "PixelMapTest: RecoverAshMemNullDataTest001 end";
}

/**
 * @tc.name: RecoverAshMemNullFdTest001
 * @tc.desc: Test Marshalling when context_ (fd pointer) is null, should fail
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, RecoverAshMemNullFdTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: RecoverAshMemNullFdTest001 start";

    InitializationOptions opts;
    opts.size.width = SIZE_WIDTH;
    opts.size.height = SIZE_HEIGHT;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);

    // Save original context
    void* originalContext = pixelMap->context_;
    pixelMap->context_ = nullptr;

    // Marshalling should fail because fd pointer is null
    Parcel parcel;
    bool ret = pixelMap->Marshalling(parcel);
    EXPECT_FALSE(ret);

    // Restore for cleanup
    pixelMap->context_ = originalContext;

    GTEST_LOG_(INFO) << "PixelMapTest: RecoverAshMemNullFdTest001 end";
}

/**
 * @tc.name: RecoverAshMemNormalTest001
 * @tc.desc: Test normal Marshalling with valid SHARE_MEM_ALLOC, no recovery needed
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, RecoverAshMemNormalTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: RecoverAshMemNormalTest001 start";

    InitializationOptions opts;
    opts.size.width = SIZE_WIDTH;
    opts.size.height = SIZE_HEIGHT;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_NE(pixelMap->data_, nullptr);
    ASSERT_NE(pixelMap->context_, nullptr);

    // Normal Marshalling without closing fd
    Parcel parcel;
    bool ret = pixelMap->Marshalling(parcel);
    EXPECT_TRUE(ret);

    // Unmarshalling and verify
    PixelMap* newPixelMap = PixelMap::Unmarshalling(parcel);
    ASSERT_NE(newPixelMap, nullptr);
    EXPECT_EQ(newPixelMap->GetWidth(), SIZE_WIDTH);
    EXPECT_EQ(newPixelMap->GetHeight(), SIZE_HEIGHT);

    GTEST_LOG_(INFO) << "PixelMapTest: RecoverAshMemNormalTest001 end";
}

/**
 * @tc.name: RecoverAshMemFdReusedTest001
 * @tc.desc: Test Marshalling when fd is closed and potentially reused, trigger recovery
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, RecoverAshMemFdReusedTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: RecoverAshMemFdReusedTest001 start";

    InitializationOptions opts;
    opts.size.width = SIZE_WIDTH;
    opts.size.height = SIZE_HEIGHT;
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    opts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);

    int32_t bufferSize = pixelMap->GetByteCount();
    auto originalData = std::make_unique<uint8_t[]>(bufferSize);
    ASSERT_EQ(memcpy_s(originalData.get(), bufferSize, pixelMap->data_, bufferSize), EOK);

    // Close fd and open another file to potentially reuse the fd number
    int* fd = static_cast<int*>(pixelMap->context_);
    ASSERT_NE(fd, nullptr);
    int oldFd = *fd;
    ::close(*fd);

    // Try to force fd reuse by opening another file
    int tmpFd = open("/dev/null", O_RDONLY);
    if (tmpFd >= 0) {
        // If fd was reused, tmpFd might equal oldFd
        ::close(tmpFd);
    }

    // Set fd to old value (which is now invalid or points to different file)
    *fd = oldFd;

    // Marshalling should detect invalid ashmem and trigger WriteRecoveredAshMemToParcel
    Parcel parcel;
    bool ret = pixelMap->Marshalling(parcel);
    EXPECT_TRUE(ret);

    // Verify data_ is not modified by recovery
    EXPECT_EQ(memcmp(pixelMap->data_, originalData.get(), bufferSize), 0);

    // Verify unmarshalling works correctly
    PixelMap* newPixelMap = PixelMap::Unmarshalling(parcel);
    ASSERT_NE(newPixelMap, nullptr);
    EXPECT_EQ(newPixelMap->GetWidth(), SIZE_WIDTH);
    EXPECT_EQ(newPixelMap->GetHeight(), SIZE_HEIGHT);

    GTEST_LOG_(INFO) << "PixelMapTest: RecoverAshMemFdReusedTest001 end";
}

constexpr uint32_t Y8_SIZE_WIDTH = 8;
constexpr uint32_t Y8_SIZE_HEIGHT = 8;
constexpr uint32_t Y8_SMALL_WIDTH = 4;
constexpr uint32_t Y8_SMALL_HEIGHT = 4;
constexpr uint32_t Y8_BYTE_COUNT = 64;
constexpr uint32_t Y8_PIXEL_BYTES = 1;

/**
 * @tc.name: Y8FormatCreateEmptyTest001
 * @tc.desc: Test Y8 format PixelMap creation via InitializationOptions
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, Y8FormatCreateEmptyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatCreateEmptyTest001 start";
    InitializationOptions opts;
    opts.size.width = Y8_SIZE_WIDTH;
    opts.size.height = Y8_SIZE_HEIGHT;
    opts.pixelFormat = PixelFormat::Y8;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);
    EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::Y8);
    EXPECT_EQ(pixelMap->GetWidth(), Y8_SIZE_WIDTH);
    EXPECT_EQ(pixelMap->GetHeight(), Y8_SIZE_HEIGHT);
    EXPECT_EQ(pixelMap->GetPixelBytes(), Y8_PIXEL_BYTES);
    EXPECT_EQ(pixelMap->GetRowBytes(), Y8_SIZE_WIDTH);
    EXPECT_EQ(pixelMap->GetRowStride(), Y8_SIZE_WIDTH);
    EXPECT_EQ(pixelMap->GetByteCount(), Y8_BYTE_COUNT);
    EXPECT_TRUE(pixelMap->IsYuvFormat());
    EXPECT_EQ(pixelMap->GetAlphaType(), AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);

    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatCreateEmptyTest001 end";
}

/**
 * @tc.name: Y8FormatCreateFromPixelsTest001
 * @tc.desc: Test Y8 format PixelMap creation via CreateFromPixels with same format
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, Y8FormatCreateFromPixelsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatCreateFromPixelsTest001 start";
    constexpr uint32_t bufferSize = Y8_SMALL_WIDTH * Y8_SMALL_HEIGHT;
    uint8_t buffer[bufferSize] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                                   0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF};
    InitializationOptions opts;
    opts.size.width = Y8_SMALL_WIDTH;
    opts.size.height = Y8_SMALL_HEIGHT;
    opts.srcPixelFormat = PixelFormat::Y8;
    opts.pixelFormat = PixelFormat::Y8;
    auto [pixelMap, errCode] = PixelMap::CreateFromPixels(buffer, bufferSize, opts);
    ASSERT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);
    ASSERT_EQ(pixelMap, nullptr);
    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatCreateFromPixelsTest001 end";
}

/**
 * @tc.name: Y8FormatCreateFromPixelsTest002
 * @tc.desc: Test Y8 format PixelMap creation via CreateFromPixels from BGRA source
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, Y8FormatCreateFromPixelsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatCreateFromPixelsTest002 start";
    // Test BGRA->Y8 conversion should fail (Y8 only supports same format conversion)
    constexpr uint32_t bgraBufferSize = Y8_SMALL_WIDTH * Y8_SMALL_HEIGHT * ARGB_8888_BYTES;
    uint8_t bgraBuffer[bgraBufferSize] = {
        0x52, 0xDF, 0x83, 0x78, 0x52, 0xDF, 0x83, 0x78,
        0x52, 0xDF, 0x83, 0x78, 0x52, 0xDF, 0x83, 0x78
    };
    InitializationOptions opts;
    opts.size.width = Y8_SMALL_WIDTH;
    opts.size.height = Y8_SMALL_HEIGHT;
    opts.srcPixelFormat = PixelFormat::BGRA_8888;  // Explicitly set source format
    opts.pixelFormat = PixelFormat::Y8;            // Target format is Y8
    auto [pixelMap, errCode] = PixelMap::CreateFromPixels(bgraBuffer, bgraBufferSize, opts);
    // BGRA->Y8 is blocked by CheckY8FormatConversion (Y8 only supports Y8->Y8)
    EXPECT_EQ(errCode, ERR_IMAGE_INVALID_PARAMETER);
    EXPECT_EQ(pixelMap, nullptr);
    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatCreateFromPixelsTest002 end";
}

/**
 * @tc.name: Y8FormatCreateFromPixelMapTest001
 * @tc.desc: Test creating Y8 PixelMap from another PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, Y8FormatCreateFromPixelMapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatCreateFromPixelMapTest001 start";

    // Test 1: Create Y8 from Y8 source (should fail, YUV format not supported)
    auto srcPixelMap = ConstructPixelMap(Y8_SMALL_WIDTH, Y8_SMALL_HEIGHT, PixelFormat::Y8,
        AlphaType::IMAGE_ALPHA_TYPE_OPAQUE, AllocatorType::HEAP_ALLOC);
    ASSERT_NE(srcPixelMap, nullptr);

    InitializationOptions dstOpts;
    dstOpts.size.width = Y8_SMALL_WIDTH;
    dstOpts.size.height = Y8_SMALL_HEIGHT;
    dstOpts.pixelFormat = PixelFormat::Y8;
    std::unique_ptr<PixelMap> dstPixelMap = PixelMap::Create(*srcPixelMap, dstOpts);
    EXPECT_EQ(dstPixelMap, nullptr);

    // Test 2: Create Y8 from RGBA source (should fail, YUV format not supported)
    auto rgbaPixelMap = ConstructPixelMap(Y8_SMALL_WIDTH, Y8_SMALL_HEIGHT, PixelFormat::RGBA_8888,
        AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN, AllocatorType::HEAP_ALLOC);
    ASSERT_NE(rgbaPixelMap, nullptr);
    dstOpts.pixelFormat = PixelFormat::Y8;
    std::unique_ptr<PixelMap> y8FromRgba = PixelMap::Create(*rgbaPixelMap, dstOpts);
    EXPECT_EQ(y8FromRgba, nullptr);

    // Test 3: Create RGBA from Y8 source (should fail, YUV format not supported)
    dstOpts.pixelFormat = PixelFormat::RGBA_8888;
    std::unique_ptr<PixelMap> rgbaFromY8 = PixelMap::Create(*srcPixelMap, dstOpts);
    EXPECT_EQ(rgbaFromY8, nullptr);

    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatCreateFromPixelMapTest001 end";
}

/**
 * @tc.name: Y8FormatCreateFromColorsTest001
 * @tc.desc: Test Create from colors array only supports Y8->Y8 same format conversion
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, Y8FormatCreateFromColorsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatCreateFromColorsTest001 start";

    // Test 1: BGRA->Y8 should fail (Y8 only supports same format conversion)
    constexpr uint32_t colorLength = Y8_SMALL_WIDTH * Y8_SMALL_HEIGHT;
    uint32_t colors[colorLength] = {0xFF000000, 0xFF111111, 0xFF222222, 0xFF333333,
                                     0xFF444444, 0xFF555555, 0xFF666666, 0xFF777777,
                                     0xFF888888, 0xFF999999, 0xFFAAAAAA, 0xFFBBBBBB,
                                     0xFFCCCCCC, 0xFFDDDDDD, 0xFFEEEEEE, 0xFFFFFFFF};
    InitializationOptions opts;
    opts.size.width = Y8_SMALL_WIDTH;
    opts.size.height = Y8_SMALL_HEIGHT;
    opts.srcPixelFormat = PixelFormat::BGRA_8888;
    opts.pixelFormat = PixelFormat::Y8;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(colors, colorLength, opts);
    EXPECT_EQ(pixelMap, nullptr);

    // Test 2: Y8->Y8 with colors array should succeed
    // Because srcPixelFormat and pixelFormat are both Y8
    opts.srcPixelFormat = PixelFormat::Y8;
    opts.pixelFormat = PixelFormat::Y8;
    pixelMap = PixelMap::Create(colors, colorLength, opts);
    EXPECT_NE(pixelMap, nullptr);
    if (pixelMap != nullptr) {
        EXPECT_EQ(pixelMap->GetPixelFormat(), PixelFormat::Y8);
    }

    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatCreateFromColorsTest001 end";
}

/**
 * @tc.name: Y8FormatNotSupportOperationsTest001
 * @tc.desc: Test Y8 format does not support transform and other operations
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, Y8FormatNotSupportOperationsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatNotSupportOperationsTest001 start";
    auto pixelMap = ConstructPixelMap(Y8_SMALL_WIDTH, Y8_SMALL_HEIGHT, PixelFormat::Y8,
        AlphaType::IMAGE_ALPHA_TYPE_OPAQUE, AllocatorType::HEAP_ALLOC);
    ASSERT_NE(pixelMap, nullptr);

    // Test Transform Operations
    // Scale (uppercase)
    uint32_t ret = pixelMap->Scale(2.0f, 2.0f, AntiAliasingOption::NONE);
    EXPECT_NE(ret, SUCCESS);
    EXPECT_EQ(pixelMap->GetWidth(), Y8_SMALL_WIDTH);
    EXPECT_EQ(pixelMap->GetHeight(), Y8_SMALL_HEIGHT);

    // scale (lowercase)
    pixelMap->scale(2.0f, 2.0f);
    EXPECT_EQ(pixelMap->GetWidth(), Y8_SMALL_WIDTH);
    EXPECT_EQ(pixelMap->GetHeight(), Y8_SMALL_HEIGHT);

    // Translate
    ret = pixelMap->Translate(2.0f, 2.0f);
    EXPECT_NE(ret, SUCCESS);
    EXPECT_EQ(pixelMap->GetWidth(), Y8_SMALL_WIDTH);
    EXPECT_EQ(pixelMap->GetHeight(), Y8_SMALL_HEIGHT);

    // Rotate
    ret = pixelMap->Rotate(90.0f);
    EXPECT_NE(ret, SUCCESS);
    EXPECT_EQ(pixelMap->GetWidth(), Y8_SMALL_WIDTH);
    EXPECT_EQ(pixelMap->GetHeight(), Y8_SMALL_HEIGHT);

    // Test Flip
    ret = pixelMap->Flip(true, false);
    EXPECT_NE(ret, SUCCESS);

    // Test Crop
    Rect rect = {0, 0, SIZE_WIDTH, SIZE_HEIGHT};
    ret = pixelMap->crop(rect);
    EXPECT_NE(ret, SUCCESS);

    // Test Other Operations
    // ConvertAlphaFormat
    auto dstPixelMap = ConstructPixelMap(Y8_SMALL_WIDTH, Y8_SMALL_HEIGHT, PixelFormat::Y8,
        AlphaType::IMAGE_ALPHA_TYPE_OPAQUE, AllocatorType::HEAP_ALLOC);
    ASSERT_NE(dstPixelMap, nullptr);
    ret = pixelMap->ConvertAlphaFormat(*dstPixelMap, true);
    EXPECT_NE(ret, SUCCESS);

    // ToSdr
    ret = pixelMap->ToSdr();
    EXPECT_NE(ret, SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatNotSupportOperationsTest001 end";
}

/**
 * @tc.name: Y8FormatSupportPixelOpsTest001
 * @tc.desc: Test Y8 format supports pixel read/write operations
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, Y8FormatSupportPixelOpsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatSupportPixelOpsTest001 start";
    auto pixelMap = ConstructPixelMap(Y8_SMALL_WIDTH, Y8_SMALL_HEIGHT, PixelFormat::Y8,
        AlphaType::IMAGE_ALPHA_TYPE_OPAQUE, AllocatorType::HEAP_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    pixelMap->SetEditable(true);

    // Test WritePixel and ReadPixel
    uint32_t color = 0xFF000000;
    Position pos;
    pos.x = 0;
    pos.y = 0;
    uint32_t ret = pixelMap->WritePixel(pos, color);
    EXPECT_EQ(ret, SUCCESS);
    uint32_t readColor = 0;
    ret = pixelMap->ReadPixel(pos, readColor);
    EXPECT_EQ(ret, SUCCESS);

    // Test GetAlpha and SetAlpha
    AlphaType alphaType = pixelMap->GetAlphaType();
    EXPECT_EQ(alphaType, AlphaType::IMAGE_ALPHA_TYPE_OPAQUE);
    ret = pixelMap->SetAlpha(0.5f);
    EXPECT_EQ(ret, ERR_IMAGE_DATA_UNSUPPORT);

    // Test WritePixels
    uint8_t writeData[16] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                              0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF};
    ret = pixelMap->WritePixels(writeData, 16);
    EXPECT_EQ(ret, SUCCESS);

    // Test ReadPixels
    uint8_t readData[16] = {0};
    ret = pixelMap->ReadPixels(16, readData);
    EXPECT_EQ(ret, SUCCESS);

    // Test ResetConfig
    Size newSize = {SIZE_WIDTH, SIZE_HEIGHT};
    uint32_t retCode = pixelMap->ResetConfig(newSize, PixelFormat::Y8);
    EXPECT_EQ(retCode, SUCCESS);
    EXPECT_EQ(pixelMap->GetWidth(), SIZE_WIDTH);
    EXPECT_EQ(pixelMap->GetHeight(), SIZE_HEIGHT);

    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatSupportPixelOpsTest001 end";
}

/**
 * @tc.name: Y8FormatSupportSerializeTest001
 * @tc.desc: Test Y8 PixelMap Marshalling and Unmarshalling
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, Y8FormatSupportSerializeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatSupportSerializeTest001 start";
    auto pixelMap = ConstructPixelMap(Y8_SMALL_WIDTH, Y8_SMALL_HEIGHT, PixelFormat::Y8,
        AlphaType::IMAGE_ALPHA_TYPE_OPAQUE, AllocatorType::HEAP_ALLOC);
    ASSERT_NE(pixelMap, nullptr);

    // Test Marshalling and Unmarshalling
    Parcel parcel;
    bool ret = pixelMap->Marshalling(parcel);
    EXPECT_TRUE(ret);
    std::unique_ptr<PixelMap> newPixelMap(PixelMap::Unmarshalling(parcel));
    ASSERT_NE(newPixelMap, nullptr);
    EXPECT_EQ(newPixelMap->GetPixelFormat(), PixelFormat::Y8);
    EXPECT_EQ(newPixelMap->GetWidth(), Y8_SMALL_WIDTH);
    EXPECT_EQ(newPixelMap->GetHeight(), Y8_SMALL_HEIGHT);
    EXPECT_TRUE(newPixelMap->IsYuvFormat());

    GTEST_LOG_(INFO) << "PixelMapTest: Y8FormatSupportSerializeTest001 end";
}

}
}
