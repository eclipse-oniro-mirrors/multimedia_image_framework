/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <chrono>
#include <future>
#include <mutex>

#include <gtest/gtest.h>
#include <vector>

#define protected public
#define private public
#include "pixel_map.h"
#include "pixel_map_parcel.h"
#undef protected
#undef private
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class PixelMapParcelTest : public testing::Test {
public:
    PixelMapParcelTest() {}
    ~PixelMapParcelTest() {}
};

class PixelMapRecordParcelTestHelper {
public:
    static bool MarshallingPixelMapForRecord(Parcel& parcel, PixelMap& pixelMap)
    {
        return PixelMapRecordParcel::MarshallingPixelMapForRecord(parcel, pixelMap);
    }

    static PixelMap *UnmarshallingPixelMapForRecord(Parcel& parcel)
    {
        return PixelMapRecordParcel::UnmarshallingPixelMapForRecord(parcel);
    }
};

static void WriteAstcRecordParcelPrefix(Parcel &parcel, int32_t realWidth, int32_t realHeight)
{
    constexpr int32_t imageSize = 1;
    ASSERT_TRUE(parcel.WriteInt32(imageSize));
    ASSERT_TRUE(parcel.WriteInt32(imageSize));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(PixelFormat::ASTC_4x4)));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(ColorSpace::SRGB)));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteString(""));
    ASSERT_TRUE(parcel.WriteBool(false));
    ASSERT_TRUE(parcel.WriteBool(false));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(AllocatorType::HEAP_ALLOC)));
    ASSERT_TRUE(parcel.WriteInt32(ERR_MEDIA_INVALID_VALUE));
    const int32_t rowDataSize = ImageUtils::GetRowDataSizeByPixelFormat(imageSize, PixelFormat::ASTC_4x4);
    ASSERT_GT(rowDataSize, 0);
    ASSERT_TRUE(parcel.WriteInt32(rowDataSize));
    ASSERT_TRUE(parcel.WriteInt32(realWidth));
    ASSERT_TRUE(parcel.WriteInt32(realHeight));
    constexpr int32_t astcBufferSize = 16; // ASTC header size when either block count is zero
    ASSERT_TRUE(parcel.WriteInt32(astcBufferSize));
    std::vector<uint8_t> pixels(astcBufferSize, 0);
    ASSERT_TRUE(parcel.WriteUnpadBuffer(pixels.data(), pixels.size()));
    constexpr int32_t transformFloatCount = 9;
    for (int32_t i = 0; i < transformFloatCount; ++i) {
        ASSERT_TRUE(parcel.WriteFloat(0.0f));
    }
    ASSERT_TRUE(parcel.WriteBool(false));
    ASSERT_TRUE(parcel.WriteBool(false));
}

std::unique_ptr<PixelMap> CreatePixelMap(int32_t width, int32_t height, PixelFormat format, AlphaType alphaType,
    AllocatorType type)
{
    std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = format;
    info.colorSpace = ColorSpace::SRGB;
    info.alphaType = alphaType;
    pixelMap->SetImageInfo(info);

    int32_t rowDataSize = ImageUtils::GetRowDataSizeByPixelFormat(width, format);
    if (rowDataSize <= 0) {
        return nullptr;
    }
    size_t bufferSize = rowDataSize * height;
    void* buffer = malloc(bufferSize); // Buffer's lifecycle will be held by pixelMap
    if (buffer == nullptr) {
        return nullptr;
    }
    char* ch = static_cast<char*>(buffer);
    for (unsigned int i = 0; i < bufferSize; i++) {
        *(ch++) = (char)i;
    }

    pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, type, type != AllocatorType::CUSTOM_ALLOC ? nullptr :
        [](void* addr, void* context, uint32_t size) {
            free(addr);
        });

    return pixelMap;
}

/**
 * @tc.name: MarshallingUnmarshallingRecodeParcelTest001
 * @tc.desc: Test marshalling and unmarshalling PixelMap with DEFAULT allocator type
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapParcelTest, MarshallingUnmarshallingRecodeParcelTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapParcelTest: MarshallingUnmarshallingRecodeParcelTest001 start";

    auto pixelMap = CreatePixelMap(1, 1, PixelFormat::BGRA_8888, AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN,
        AllocatorType::DEFAULT);
    EXPECT_TRUE(pixelMap != nullptr);
    Parcel parcel;
    auto ret = PixelMapRecordParcelTestHelper::MarshallingPixelMapForRecord(parcel, *(pixelMap.get()));
    EXPECT_TRUE(ret);
    PixelMap* newPixelMap = PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(parcel);
    EXPECT_EQ(newPixelMap->GetAllocatorType(), AllocatorType::HEAP_ALLOC);

    GTEST_LOG_(INFO) << "PixelMapParcelTest: MarshallingUnmarshallingRecodeParcelTest001 end";
}

std::unique_ptr<PixelMap> CreatePixelmapUsingOpt(int32_t size, PixelFormat format, bool useDma,
    AllocatorType allocType = AllocatorType::DEFAULT)
{
    InitializationOptions opts;
    opts.size.width = size;
    opts.size.height = size;
    opts.srcPixelFormat = format;
    opts.pixelFormat = format;
    opts.useDMA = useDma;
    opts.allocatorType = allocType;
    return PixelMap::Create(opts);
}

/**
 * @tc.name: MarshallingUnmarshallingRecodeParcelTest002
 * @tc.desc: Test marshalling and unmarshalling PixelMap with DEFAULT allocator type
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapParcelTest, MarshallingUnmarshallingRecodeParcelTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapParcelTest: MarshallingUnmarshallingRecodeParcelTest002 start";
    const int32_t size = 100;
    const int32_t dmaSize = 512;
    for (int i = 0; i <= static_cast<int>(PixelFormat::EXTERNAL_MAX); i++) {
        auto pixelmap = CreatePixelmapUsingOpt(size, PixelFormat(i), false);
        if (pixelmap == nullptr || PixelFormat(i) == PixelFormat::RGBA_F16) {
            continue;
        }
        Parcel dataRecord;
        EXPECT_TRUE(PixelMapRecordParcelTestHelper::MarshallingPixelMapForRecord(dataRecord, *(pixelmap.get())));
        PixelMap *pixelMapRecord = PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(dataRecord);
        EXPECT_NE(pixelMapRecord, nullptr);
        delete pixelMapRecord; // Clean up the unmarshalled PixelMap
    }
    for (int i = 0; i <= static_cast<int>(PixelFormat::EXTERNAL_MAX); i++) {
        auto pixelmap = CreatePixelmapUsingOpt(dmaSize, PixelFormat(i), false);
        if (pixelmap == nullptr || PixelFormat(i) == PixelFormat::RGBA_F16) {
            continue;
        }
        Parcel dataRecord;
        EXPECT_TRUE(PixelMapRecordParcelTestHelper::MarshallingPixelMapForRecord(dataRecord, *(pixelmap.get())));
        PixelMap *pixelMapRecord = PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(dataRecord);
        EXPECT_NE(pixelMapRecord, nullptr);
        delete pixelMapRecord; // Clean up the unmarshalled PixelMap
    }
    for (int i = 0; i <= static_cast<int>(PixelFormat::EXTERNAL_MAX); i++) {
        auto pixelmap = CreatePixelmapUsingOpt(size, PixelFormat(i), true);
        if (pixelmap == nullptr || PixelFormat(i) == PixelFormat::RGBA_F16) {
            continue;
        }
        Parcel dataRecord;
        EXPECT_TRUE(PixelMapRecordParcelTestHelper::MarshallingPixelMapForRecord(dataRecord, *(pixelmap.get())));
        PixelMap *pixelMapRecord = PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(dataRecord);
        EXPECT_NE(pixelMapRecord, nullptr);
        delete pixelMapRecord; // Clean up the unmarshalled PixelMap
    }
    for (int i = 0; i <= static_cast<int>(PixelFormat::EXTERNAL_MAX); i++) {
        auto pixelmap = CreatePixelmapUsingOpt(dmaSize, PixelFormat(i), true);
        if (pixelmap == nullptr || PixelFormat(i) == PixelFormat::RGBA_F16) {
            continue;
        }
        Parcel dataRecord;
        EXPECT_TRUE(PixelMapRecordParcelTestHelper::MarshallingPixelMapForRecord(dataRecord, *(pixelmap.get())));
        PixelMap *pixelMapRecord = PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(dataRecord);
        EXPECT_NE(pixelMapRecord, nullptr);
        delete pixelMapRecord; // Clean up the unmarshalled PixelMap
    }
    GTEST_LOG_(INFO) << "PixelMapParcelTest: MarshallingUnmarshallingRecodeParcelTest002 end";
}

static bool RecodeParcelTest(int32_t size, PixelFormat format, bool useDma)
{
    InitializationOptions opts;
    opts.size.width = size;
    opts.size.height = size;
    opts.srcPixelFormat = format;
    opts.pixelFormat = format;
    opts.useDMA = useDma;
    auto pixelMap = PixelMap::Create(opts);
    if (pixelMap == nullptr) {
        return true; // Skip if pixelMap creation fails
    }
    Parcel parcel;
    PixelMapRecordParcelTestHelper::MarshallingPixelMapForRecord(parcel, *(pixelMap.get()));
    PixelMap* newPixelMap = PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(parcel);
    if (newPixelMap == nullptr) {
        return false; // Return false if unmarshalling fails
    }
    delete newPixelMap; // Clean up the unmarshalled PixelMap
    return true;
}

/**
 * @tc.name: MarshallingUnmarshallingRecodeParcelTest003
 * @tc.desc: Test marshalling and unmarshalling PixelMap with DEFAULT allocator type
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapParcelTest, MarshallingUnmarshallingRecodeParcelTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapParcelTest: MarshallingUnmarshallingRecodeParcelTest003 start";
    for (int i = 0; i <= static_cast<int>(PixelFormat::EXTERNAL_MAX); i++) {
        EXPECT_TRUE(RecodeParcelTest(10, PixelFormat(i), false)); // Test with smaller size 10
        EXPECT_TRUE(RecodeParcelTest(10, PixelFormat(i), true)); // Test with smaller size 10
        EXPECT_TRUE(RecodeParcelTest(512, PixelFormat(i), false)); // Test with larger size 512
        EXPECT_TRUE(RecodeParcelTest(512, PixelFormat(i), true)); // Test with larger size 512
    }
    GTEST_LOG_(INFO) << "PixelMapParcelTest: MarshallingUnmarshallingRecodeParcelTest003 end";
}

/**
 * @tc.name: MarshallingUnmarshallingRecodeParcelTest004
 * @tc.desc: Test record unmarshalling YUV PixelMap without YUVDataInfo payload
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapParcelTest, MarshallingUnmarshallingRecodeParcelTest004, TestSize.Level3)
{
    constexpr int32_t width = 4;
    constexpr int32_t height = 4;
    ImageInfo imageInfo;
    imageInfo.size.width = width;
    imageInfo.size.height = height;
    imageInfo.pixelFormat = PixelFormat::NV12;
    imageInfo.colorSpace = ColorSpace::SRGB;
    imageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    const int32_t bufferSize = PixelMap::GetYUVByteCount(imageInfo);
    ASSERT_GT(bufferSize, 0);

    Parcel parcel;
    ASSERT_TRUE(parcel.WriteInt32(width));
    ASSERT_TRUE(parcel.WriteInt32(height));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(imageInfo.pixelFormat)));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(imageInfo.colorSpace)));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(imageInfo.alphaType)));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteString(""));
    ASSERT_TRUE(parcel.WriteBool(false));
    ASSERT_TRUE(parcel.WriteBool(false));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(AllocatorType::HEAP_ALLOC)));
    ASSERT_TRUE(parcel.WriteInt32(ERR_MEDIA_INVALID_VALUE));
    ASSERT_TRUE(parcel.WriteInt32(ImageUtils::GetRowDataSizeByPixelFormat(width, imageInfo.pixelFormat)));
    ASSERT_TRUE(parcel.WriteInt32(bufferSize));

    std::vector<uint8_t> pixels(bufferSize, 0);
    ASSERT_TRUE(parcel.WriteUnpadBuffer(pixels.data(), pixels.size()));

    PixelMap *pixelMapRecord = PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(parcel);
    ASSERT_NE(pixelMapRecord, nullptr);
    EXPECT_EQ(pixelMapRecord->GetPixelFormat(), PixelFormat::NV12);
    delete pixelMapRecord;
}

/**
 * @tc.name: MarshallingUnmarshallingRecodeParcelTest005
 * @tc.desc: Test record marshalling waits for unmapMutex_ when serializing SHARE_MEM_ALLOC context
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapParcelTest, MarshallingUnmarshallingRecodeParcelTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapParcelTest: MarshallingUnmarshallingRecodeParcelTest005 start";
    constexpr int32_t size = 64;
    auto pixelMap = CreatePixelmapUsingOpt(size, PixelFormat::RGBA_8888, false, AllocatorType::SHARE_MEM_ALLOC);
    ASSERT_NE(pixelMap, nullptr);
    ASSERT_EQ(pixelMap->GetAllocatorType(), AllocatorType::SHARE_MEM_ALLOC);

    std::unique_lock<std::mutex> lock(*pixelMap->unmapMutex_);
    std::promise<void> marshallingStarted;
    auto startedFuture = marshallingStarted.get_future();
    Parcel parcel;
    auto marshallingTask = std::async(std::launch::async, [&pixelMap, &parcel, &marshallingStarted]() {
        marshallingStarted.set_value();
        return PixelMapRecordParcelTestHelper::MarshallingPixelMapForRecord(parcel, *pixelMap);
    });

    EXPECT_EQ(startedFuture.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    EXPECT_EQ(marshallingTask.wait_for(std::chrono::milliseconds(100)), std::future_status::timeout);

    lock.unlock();
    EXPECT_TRUE(marshallingTask.get());
    GTEST_LOG_(INFO) << "PixelMapParcelTest: MarshallingUnmarshallingRecodeParcelTest005 end";
}

/**
 * @tc.name: ReadAstcInfoRejectsNonPositiveSize
 * @tc.desc: Test that ASTC real sizes read from Parcel must be positive
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapParcelTest, ReadAstcInfoRejectsNonPositiveSize, TestSize.Level3)
{
    PixelMap pixelMap;
    pixelMap.SetAstc(true);

    Parcel zeroWidthParcel;
    ASSERT_TRUE(zeroWidthParcel.WriteInt32(0));
    ASSERT_TRUE(zeroWidthParcel.WriteInt32(1));
    EXPECT_FALSE(pixelMap.ReadAstcInfo(zeroWidthParcel, &pixelMap));

    Parcel negativeHeightParcel;
    ASSERT_TRUE(negativeHeightParcel.WriteInt32(1));
    ASSERT_TRUE(negativeHeightParcel.WriteInt32(-1));
    EXPECT_FALSE(pixelMap.ReadAstcInfo(negativeHeightParcel, &pixelMap));

    Parcel validParcel;
    ASSERT_TRUE(validParcel.WriteInt32(1));
    ASSERT_TRUE(validParcel.WriteInt32(1));
    ASSERT_TRUE(validParcel.WriteBool(false));
    EXPECT_TRUE(pixelMap.ReadAstcInfo(validParcel, &pixelMap));
    Size realSize;
    pixelMap.GetAstcRealSize(realSize);
    EXPECT_EQ(realSize.width, 1);
    EXPECT_EQ(realSize.height, 1);
}

/**
 * @tc.name: RecordParcelRejectsNonPositiveAstcRealSize
 * @tc.desc: Test that record Parcel unmarshalling rejects non-positive ASTC real sizes
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapParcelTest, RecordParcelRejectsNonPositiveAstcRealSize, TestSize.Level3)
{
    Parcel zeroWidthParcel;
    WriteAstcRecordParcelPrefix(zeroWidthParcel, 0, 1);
    EXPECT_EQ(PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(zeroWidthParcel), nullptr);

    Parcel zeroHeightParcel;
    WriteAstcRecordParcelPrefix(zeroHeightParcel, 1, 0);
    EXPECT_EQ(PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(zeroHeightParcel), nullptr);
}
}
}
