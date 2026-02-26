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

#include <gtest/gtest.h>

#include "pixel_map.h"
#include "pixel_map_parcel.h"
#include "image_type.h"
#include "image_utils.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class PixelMapParcelTest : public testing::Test {
public:
    PixelMapParcelTest() {}
    ~PixelMapParcelTest() {}
};

/**
 * @tc.name: PixelMapParcelTest001
 * @tc.desc: CreateFromParcel
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapParcelTest, PixelMapParcelTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapParcelTest: PixelMapParcelTest001 start";

    MessageParcel data1;
    data1.WriteInt32(100);
    data1.WriteInt32(100);
    data1.WriteInt32((int32_t)PixelFormat::UNKNOWN);
    data1.WriteInt32((int32_t)ColorSpace::SRGB);
    data1.WriteInt32((int32_t)AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
    data1.WriteInt32(0);
    data1.WriteInt32(0);
    data1.WriteInt32((int32_t)AllocatorType::SHARE_MEM_ALLOC);
    data1.WriteFileDescriptor(-1);
    auto pixelMap1 = PixelMapParcel::CreateFromParcel(data1);
    EXPECT_TRUE(pixelMap1 == nullptr);

    MessageParcel data2;
    data2.WriteInt32(100);
    data2.WriteInt32(100);
    data1.WriteInt32((int32_t)PixelFormat::UNKNOWN);
    data1.WriteInt32((int32_t)ColorSpace::SRGB);
    data1.WriteInt32((int32_t)AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
    data2.WriteInt32(0);
    data2.WriteInt32(0);
    data2.WriteInt32((int32_t)AllocatorType::SHARE_MEM_ALLOC);
    data2.WriteFileDescriptor(100);
    auto pixelMap2 = PixelMapParcel::CreateFromParcel(data2);
    EXPECT_TRUE(pixelMap2 == nullptr);

    MessageParcel data3;
    data3.WriteInt32(100);
    data3.WriteInt32(100);
    data1.WriteInt32((int32_t)PixelFormat::UNKNOWN);
    data1.WriteInt32((int32_t)ColorSpace::SRGB);
    data1.WriteInt32((int32_t)AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
    data3.WriteInt32(0);
    data3.WriteInt32(4);
    data3.WriteInt32((int32_t)AllocatorType::HEAP_ALLOC);
    auto pixelMap3 = PixelMapParcel::CreateFromParcel(data3);
    EXPECT_TRUE(pixelMap3 == nullptr);

    GTEST_LOG_(INFO) << "PixelMapParcelTest: PixelMapParcelTest001 end";
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
    auto ret = PixelMapRecordParcel::MarshallingPixelMapForRecord(parcel, *(pixelMap.get()));
    EXPECT_TRUE(ret);
    PixelMap* newPixelMap = PixelMapRecordParcel::UnmarshallingPixelMapForRecord(parcel);
    EXPECT_EQ(newPixelMap->GetAllocatorType(), AllocatorType::HEAP_ALLOC);

    GTEST_LOG_(INFO) << "PixelMapParcelTest: MarshallingUnmarshallingRecodeParcelTest001 end";
}

std::unique_ptr<PixelMap> CreatePixelmapUsingOpt(int32_t size, PixelFormat format, bool useDma)
{
    InitializationOptions opts;
    opts.size.width = size;
    opts.size.height = size;
    opts.srcPixelFormat = format;
    opts.pixelFormat = format;
    opts.useDMA = useDma;
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
        EXPECT_TRUE(PixelMapRecordParcel::MarshallingPixelMapForRecord(dataRecord, *(pixelmap.get())));
        PixelMap *pixelMapRecord = PixelMapRecordParcel::UnmarshallingPixelMapForRecord(dataRecord);
        EXPECT_NE(pixelMapRecord, nullptr);
        delete pixelMapRecord; // Clean up the unmarshalled PixelMap
    }
    for (int i = 0; i <= static_cast<int>(PixelFormat::EXTERNAL_MAX); i++) {
        auto pixelmap = CreatePixelmapUsingOpt(dmaSize, PixelFormat(i), false);
        if (pixelmap == nullptr || PixelFormat(i) == PixelFormat::RGBA_F16) {
            continue;
        }
        Parcel dataRecord;
        EXPECT_TRUE(PixelMapRecordParcel::MarshallingPixelMapForRecord(dataRecord, *(pixelmap.get())));
        PixelMap *pixelMapRecord = PixelMapRecordParcel::UnmarshallingPixelMapForRecord(dataRecord);
        EXPECT_NE(pixelMapRecord, nullptr);
        delete pixelMapRecord; // Clean up the unmarshalled PixelMap
    }
    for (int i = 0; i <= static_cast<int>(PixelFormat::EXTERNAL_MAX); i++) {
        auto pixelmap = CreatePixelmapUsingOpt(size, PixelFormat(i), true);
        if (pixelmap == nullptr || PixelFormat(i) == PixelFormat::RGBA_F16) {
            continue;
        }
        Parcel dataRecord;
        EXPECT_TRUE(PixelMapRecordParcel::MarshallingPixelMapForRecord(dataRecord, *(pixelmap.get())));
        PixelMap *pixelMapRecord = PixelMapRecordParcel::UnmarshallingPixelMapForRecord(dataRecord);
        EXPECT_NE(pixelMapRecord, nullptr);
        delete pixelMapRecord; // Clean up the unmarshalled PixelMap
    }
    for (int i = 0; i <= static_cast<int>(PixelFormat::EXTERNAL_MAX); i++) {
        auto pixelmap = CreatePixelmapUsingOpt(dmaSize, PixelFormat(i), true);
        if (pixelmap == nullptr || PixelFormat(i) == PixelFormat::RGBA_F16) {
            continue;
        }
        Parcel dataRecord;
        EXPECT_TRUE(PixelMapRecordParcel::MarshallingPixelMapForRecord(dataRecord, *(pixelmap.get())));
        PixelMap *pixelMapRecord = PixelMapRecordParcel::UnmarshallingPixelMapForRecord(dataRecord);
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
    PixelMapRecordParcel::MarshallingPixelMapForRecord(parcel, *(pixelMap.get()));
    PixelMap* newPixelMap = PixelMapRecordParcel::UnmarshallingPixelMapForRecord(parcel);
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
}
}