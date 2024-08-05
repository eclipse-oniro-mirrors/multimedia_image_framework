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

#define protected public
#include <gtest/gtest.h>
#include <surface.h>
#include "auxiliary_picture.h"
#include "image_type.h"
#include "image_utils.h"
#include "pixel_map.h"
#include "picture.h"
#include "media_errors.h"
#include "metadata.h"
#include "exif_metadata.h"
#include "fragment_metadata.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {

class AuxiliaryPictureTest : public testing::Test {
public:
    AuxiliaryPictureTest() {}
    ~AuxiliaryPictureTest() {}
};

static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_metadata.jpg";
constexpr int32_t infoRowstride = 1;
constexpr int32_t sizeWidth = 2;
constexpr int32_t sizeHeight = 3;
constexpr int32_t bufferLength = 8;

static std::shared_ptr<PixelMap> CreatePixelMap()
{
    const uint32_t color[bufferLength] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    InitializationOptions options;
    options.size.width = sizeWidth;
    options.size.height = sizeHeight;
    options.srcPixelFormat = PixelFormat::UNKNOWN;
    options.pixelFormat = PixelFormat::UNKNOWN;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> tmpPixelMap = PixelMap::Create(color, bufferLength, options);
    std::shared_ptr<PixelMap> pixelmap = std::move(tmpPixelMap);
    return pixelmap;
}

static std::unique_ptr<AuxiliaryPicture> CreateAuxiliaryPicture(AuxiliaryPictureType type)
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    EXPECT_NE(pixelmap, nullptr);
    Size size = {sizeWidth, sizeHeight};
    return AuxiliaryPicture::Create(pixelmap, type, size);
}

/**
 * @tc.name: CreateTest001
 * @tc.desc: Create an auxiliaryPicture using pixelmap, gain map type, and normal size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest001, TestSize.Level1)
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {sizeWidth, sizeWidth};
    std::unique_ptr<AuxiliaryPicture> auxPicture = AuxiliaryPicture::Create(pixelmap, type, size);
    EXPECT_NE(auxPicture, nullptr);
}

/**
 * @tc.name: CreateTest002
 * @tc.desc: Create an auxiliaryPicture using an empty pixelmap, none type, and zero size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest002, TestSize.Level3)
{
    std::shared_ptr<PixelMap> pixelmap = nullptr;
    AuxiliaryPictureType type = AuxiliaryPictureType::NONE;
    Size size = {0, 0};
    std::unique_ptr<AuxiliaryPicture> auxPicture = AuxiliaryPicture::Create(pixelmap, type, size);
    EXPECT_EQ(auxPicture, nullptr);
}

/**
 * @tc.name: CreateTest003
 * @tc.desc: Create an auxiliaryPicture using an empty pixelmap, gain map type, and zero size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest003, TestSize.Level3)
{
    std::shared_ptr<PixelMap> pixelmap = nullptr;
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {0, 0};
    std::unique_ptr<AuxiliaryPicture> auxPicture = AuxiliaryPicture::Create(pixelmap, type, size);
    EXPECT_EQ(auxPicture, nullptr);
}

/**
 * @tc.name: CreateTest004
 * @tc.desc: Create an auxiliaryPicture using an empty pixelmap, none type, and normal size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest004, TestSize.Level3)
{
    std::shared_ptr<PixelMap> pixelmap = nullptr;
    AuxiliaryPictureType type = AuxiliaryPictureType::NONE;
    Size size = {sizeWidth, sizeHeight};
    std::unique_ptr<AuxiliaryPicture> auxPicture = AuxiliaryPicture::Create(pixelmap, type, size);
    EXPECT_EQ(auxPicture, nullptr);
}

/**
 * @tc.name: CreateTest005
 * @tc.desc: Create an auxiliaryPicture using an empty pixelmap, gain map type, and normal size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest005, TestSize.Level3)
{
    std::shared_ptr<PixelMap> pixelmap = nullptr;
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {sizeWidth, sizeHeight};
    std::unique_ptr<AuxiliaryPicture> auxPicture = AuxiliaryPicture::Create(pixelmap, type, size);
    EXPECT_EQ(auxPicture, nullptr);
}

/**
 * @tc.name: CreateTest006
 * @tc.desc: Create an auxiliaryPicture using pixelmap, none type, and zero size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest006, TestSize.Level1)
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    AuxiliaryPictureType type = AuxiliaryPictureType::NONE;
    Size size = {0, 0};
    std::unique_ptr<AuxiliaryPicture> auxPicture = AuxiliaryPicture::Create(pixelmap, type, size);
    EXPECT_NE(auxPicture, nullptr);
}

/**
 * @tc.name: CreateTest007
 * @tc.desc: Create an auxiliaryPicture using pixelmap, gain map type, and zero size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest007, TestSize.Level1)
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {0, 0};
    std::unique_ptr<AuxiliaryPicture> auxPicture = AuxiliaryPicture::Create(pixelmap, type, size);
    EXPECT_NE(auxPicture, nullptr);
}

/**
 * @tc.name: CreateTest008
 * @tc.desc: Create an auxiliaryPicture using pixelmap, none type, and normal size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest008, TestSize.Level1)
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    AuxiliaryPictureType type = AuxiliaryPictureType::NONE;
    Size size = {sizeWidth, sizeHeight};
    std::unique_ptr<AuxiliaryPicture> auxPicture = AuxiliaryPicture::Create(pixelmap, type, size);
    EXPECT_NE(auxPicture, nullptr);
}

/**
 * @tc.name: CreateTest009
 * @tc.desc: Create an auxiliaryPicture using surfaceBuffer, gain map type, and normal size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest009, TestSize.Level1)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = SurfaceBuffer::Create();
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {sizeWidth, sizeHeight};
    auto auxPicture = AuxiliaryPicture::Create(buffer, type, size);
    EXPECT_NE(nullptr, auxPicture);
}

/**
 * @tc.name: CreateTest010
 * @tc.desc: Create an auxiliaryPicture using an empty surfaceBuffer, none type, and zero size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest010, TestSize.Level3)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    AuxiliaryPictureType type = AuxiliaryPictureType::NONE;
    Size size = {0, 0};
    auto auxPicture = AuxiliaryPicture::Create(buffer, type, size);
    EXPECT_EQ(nullptr, auxPicture);
}

/**
 * @tc.name: CreateTest011
 * @tc.desc: Create an auxiliaryPicture using an empty surfaceBuffer, gain map type, and normal size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest011, TestSize.Level3)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {sizeWidth, sizeHeight};
    auto auxPicture = AuxiliaryPicture::Create(buffer, type, size);
    EXPECT_EQ(nullptr, auxPicture);
}

/**
 * @tc.name: CreateTest012
 * @tc.desc: Create an auxiliaryPicture using an empty surfaceBuffer, gain map type, and zero size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest012, TestSize.Level3)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {0, 0};
    auto auxPicture = AuxiliaryPicture::Create(buffer, type, size);
    EXPECT_EQ(nullptr, auxPicture);
}

/**
 * @tc.name: CreateTest013
 * @tc.desc: Create an auxiliaryPicture using a surfaceBuffer, none type, and normal size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest013, TestSize.Level3)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    AuxiliaryPictureType type = AuxiliaryPictureType::NONE;
    Size size = {sizeWidth, sizeHeight};
    auto auxPicture = AuxiliaryPicture::Create(buffer, type, size);
    EXPECT_EQ(nullptr, auxPicture);
}

/**
 * @tc.name: CreateTest014
 * @tc.desc: Create an auxiliaryPicture using surfaceBuffer, none type, and normal size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest014, TestSize.Level1)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = SurfaceBuffer::Create();
    AuxiliaryPictureType type = AuxiliaryPictureType::NONE;
    Size size = {sizeWidth, sizeHeight};
    auto auxPicture = AuxiliaryPicture::Create(buffer, type, size);
    EXPECT_NE(nullptr, auxPicture);
}

/**
 * @tc.name: CreateTest015
 * @tc.desc: Create an auxiliaryPicture using surfaceBuffer, gain map type, and zero size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, CreateTest015, TestSize.Level1)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = SurfaceBuffer::Create();
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    Size size = {0, 0};
    auto auxPicture = AuxiliaryPicture::Create(buffer, type, size);
    EXPECT_NE(nullptr, auxPicture);
}

/**
 * @tc.name: GetAuxiliaryPictureInfoTest001
 * @tc.desc: Get auxiliaryPictureInfo of the auxiliaryPicture.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, GetAuxiliaryPictureInfoTest001, TestSize.Level1)
{
    AuxiliaryPictureType type = AuxiliaryPictureType::DEPTH_MAP;
    std::unique_ptr<AuxiliaryPicture> auxPicture = CreateAuxiliaryPicture(type);
    ASSERT_NE(auxPicture, nullptr);
    EXPECT_EQ(AuxiliaryPictureType::DEPTH_MAP, auxPicture->GetAuxiliaryPictureInfo().auxiliaryPictureType);
    EXPECT_EQ(sizeWidth, auxPicture->GetAuxiliaryPictureInfo().size.width);
    EXPECT_EQ(sizeHeight, auxPicture->GetAuxiliaryPictureInfo().size.height);
}

/**
 * @tc.name: SetAuxiliaryPictureInfoTest001
 * @tc.desc: Set auxiliaryPictureInfo to the auxiliaryPicture.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, SetAuxiliaryPictureInfoTest001, TestSize.Level1)
{
    AuxiliaryPictureType type = AuxiliaryPictureType::DEPTH_MAP;
    std::unique_ptr<AuxiliaryPicture> auxPicture = CreateAuxiliaryPicture(type);
    ASSERT_NE(auxPicture, nullptr);
    AuxiliaryPictureInfo auxiliaryPictureInfo;
    auxiliaryPictureInfo.auxiliaryPictureType = AuxiliaryPictureType::GAINMAP;
    auxiliaryPictureInfo.colorSpace = ColorSpace::SRGB;
    auxiliaryPictureInfo.pixelFormat = PixelFormat::RGBA_8888;
    auxiliaryPictureInfo.rowStride = infoRowstride;
    auxiliaryPictureInfo.size = {sizeWidth, sizeHeight};
    auxPicture->SetAuxiliaryPictureInfo(auxiliaryPictureInfo);
    AuxiliaryPictureInfo info = auxPicture->GetAuxiliaryPictureInfo();
    EXPECT_EQ(AuxiliaryPictureType::GAINMAP, info.auxiliaryPictureType);
    EXPECT_EQ(ColorSpace::SRGB, info.colorSpace);
    EXPECT_EQ(PixelFormat::RGBA_8888, info.pixelFormat);
    EXPECT_EQ(infoRowstride, info.rowStride);
    EXPECT_EQ(sizeWidth, info.size.width);
    EXPECT_EQ(sizeHeight, info.size.height);
}

/**
 * @tc.name: GetTypeTest001
 * @tc.desc: When the auxiliaryPicture type is gain map, obtain the type.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, GetTypeTest001, TestSize.Level1)
{
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    std::unique_ptr<AuxiliaryPicture> auxPicture = CreateAuxiliaryPicture(type);
    ASSERT_NE(auxPicture, nullptr);
    AuxiliaryPictureType auxType = auxPicture->GetType();
    EXPECT_EQ(auxType, AuxiliaryPictureType::GAINMAP);
}

/**
 * @tc.name: GetTypeTest002
 * @tc.desc: When the auxiliaryPicture type is linear map, obtain the type.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, GetTypeTest002, TestSize.Level1)
{
    AuxiliaryPictureType type = AuxiliaryPictureType::LINEAR_MAP;
    std::unique_ptr<AuxiliaryPicture> auxPicture = CreateAuxiliaryPicture(type);
    ASSERT_NE(auxPicture, nullptr);
    AuxiliaryPictureType auxType = auxPicture->GetType();
    EXPECT_EQ(auxType, AuxiliaryPictureType::LINEAR_MAP);
}

/**
 * @tc.name: GetTypeTest003
 * @tc.desc: When the auxiliaryPicture type is fragment map, obtain the type.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, GetTypeTest003, TestSize.Level1)
{
    AuxiliaryPictureType type = AuxiliaryPictureType::FRAGMENT_MAP;
    std::unique_ptr<AuxiliaryPicture> auxPicture = CreateAuxiliaryPicture(type);
    ASSERT_NE(auxPicture, nullptr);
    AuxiliaryPictureType auxType = auxPicture->GetType();
    EXPECT_EQ(auxType, AuxiliaryPictureType::FRAGMENT_MAP);
}

/**
 * @tc.name: GetTypeTest004
 * @tc.desc: When the auxiliaryPicture type is unrefocus map, obtain the type.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, GetTypeTest004, TestSize.Level1)
{
    AuxiliaryPictureType type = AuxiliaryPictureType::UNREFOCUS_MAP;
    std::unique_ptr<AuxiliaryPicture> auxPicture = CreateAuxiliaryPicture(type);
    ASSERT_NE(auxPicture, nullptr);
    AuxiliaryPictureType auxType = auxPicture->GetType();
    EXPECT_EQ(auxType, AuxiliaryPictureType::UNREFOCUS_MAP);
}

/**
 * @tc.name: GetTypeTest005
 * @tc.desc: When the auxiliaryPicture type is depth map, obtain the type.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, GetTypeTest005, TestSize.Level1)
{
    AuxiliaryPictureType type = AuxiliaryPictureType::DEPTH_MAP;
    std::unique_ptr<AuxiliaryPicture> auxPicture = CreateAuxiliaryPicture(type);
    ASSERT_NE(auxPicture, nullptr);
    AuxiliaryPictureType auxType = auxPicture->GetType();
    EXPECT_EQ(auxType, AuxiliaryPictureType::DEPTH_MAP);
}

/**
 * @tc.name: ReadPixelsTest001
 * @tc.desc: Read auxiliary picture pixels to buffer successfully.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, ReadPixelsTest001, TestSize.Level1)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    uint64_t bufferSize = auxiliaryPicture->GetContentPixel()->GetCapacity();
    auto dst = new uint8_t[bufferSize];
    ASSERT_NE(dst, nullptr);
    uint32_t ret = auxiliaryPicture->ReadPixels(bufferSize, dst);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: ReadPixelsTest002
 * @tc.desc: Read auxiliary picture pixels to buffer with invalid buffer size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, ReadPixelsTest002, TestSize.Level2)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    uint64_t bufferSize = auxiliaryPicture->GetContentPixel()->GetCapacity();
    auto dst = new uint8_t[bufferSize];
    ASSERT_NE(dst, nullptr);
    bufferSize = 0;
    uint32_t ret = auxiliaryPicture->ReadPixels(bufferSize, dst);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: ReadPixelsTest003
 * @tc.desc: Read auxiliary picture pixels to buffer but dst buffer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, ReadPixelsTest003, TestSize.Level2)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    uint64_t bufferSize = auxiliaryPicture->GetContentPixel()->GetCapacity();
    uint8_t *dst = nullptr;
    uint32_t ret = auxiliaryPicture->ReadPixels(bufferSize, dst);
    EXPECT_EQ(ret, ERR_IMAGE_READ_PIXELMAP_FAILED);
}

/**
 * @tc.name: ReadPixelsTest004
 * @tc.desc: Read auxiliary picture pixels to buffer but the pixelmap in auxiliary picture is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, ReadPixelsTest004, TestSize.Level2)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    uint64_t bufferSize = auxiliaryPicture->GetContentPixel()->GetCapacity();
    auto dst = new uint8_t[bufferSize];
    ASSERT_NE(dst, nullptr);
    std::shared_ptr<PixelMap> emptyPixelmap = nullptr;
    auxiliaryPicture->SetContentPixel(emptyPixelmap);
    uint32_t ret = auxiliaryPicture->ReadPixels(bufferSize, dst);
    EXPECT_EQ(ret, ERR_MEDIA_NULL_POINTER);
}

/**
 * @tc.name: WritePixelsTest001
 * @tc.desc: Write buffer to pixels successfully.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, WritePixelsTest001, TestSize.Level1)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->GetContentPixel()->SetEditable(true);
    uint64_t bufferSize = auxiliaryPicture->GetContentPixel()->GetCapacity();
    auto buffer = new uint8_t[bufferSize];
    ASSERT_NE(buffer, nullptr);
    uint32_t ret = auxiliaryPicture->WritePixels(buffer, bufferSize);
    EXPECT_EQ(ret, SUCCESS);
}

/**
 * @tc.name: WritePixelsTest002
 * @tc.desc: Write buffer to pixels but buffer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, WritePixelsTest002, TestSize.Level2)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->GetContentPixel()->SetEditable(true);
    uint64_t bufferSize = auxiliaryPicture->GetContentPixel()->GetCapacity();
    uint8_t* buffer = nullptr;
    uint32_t ret = auxiliaryPicture->WritePixels(buffer, bufferSize);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: WritePixelsTest003
 * @tc.desc: Write buffer to pixels with invalid buffer size.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, WritePixelsTest003, TestSize.Level2)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->GetContentPixel()->SetEditable(true);
    uint64_t bufferSize = auxiliaryPicture->GetContentPixel()->GetCapacity();
    auto buffer = new uint8_t[bufferSize];
    ASSERT_NE(buffer, nullptr);
    bufferSize = 0;
    uint32_t ret = auxiliaryPicture->WritePixels(buffer, bufferSize);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: WritePixelsTest004
 * @tc.desc: Write buffer to pixels but the pixelmap in auxiliary picture is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, WritePixelsTest004, TestSize.Level2)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->GetContentPixel()->SetEditable(true);
    uint64_t bufferSize = auxiliaryPicture->GetContentPixel()->GetCapacity();
    auto buffer = new uint8_t[bufferSize];
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<PixelMap> emptyPixelmap = nullptr;
    auxiliaryPicture->SetContentPixel(emptyPixelmap);
    uint32_t ret = auxiliaryPicture->WritePixels(buffer, bufferSize);
    EXPECT_EQ(ret, ERR_MEDIA_NULL_POINTER);
}

/**
 * @tc.name: WritePixelsTest005
 * @tc.desc: Write buffer to pixels but the pixelmap in auxiliary picture is not editable.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, WritePixelsTest005, TestSize.Level2)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->GetContentPixel()->SetEditable(false);
    uint64_t bufferSize = auxiliaryPicture->GetContentPixel()->GetCapacity();
    auto buffer = new uint8_t[bufferSize];
    ASSERT_NE(buffer, nullptr);
    uint32_t ret = auxiliaryPicture->WritePixels(buffer, bufferSize);
    EXPECT_EQ(ret, ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY);
}

/**
 * @tc.name: WritePixelsTest006
 * @tc.desc: Write buffer to pixels with invalid image info for pixelmap in auxiliary picture.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, WritePixelsTest006, TestSize.Level2)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    std::shared_ptr<PixelMap> pixelmap = auxiliaryPicture->GetContentPixel();
    ASSERT_NE(pixelmap, nullptr);
    ImageInfo info;
    pixelmap->GetImageInfo(info);
    info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    ASSERT_EQ(pixelmap->SetImageInfo(info), SUCCESS);
    pixelmap->SetImageInfo(info);
    pixelmap->SetEditable(true);
    uint64_t bufferSize = pixelmap->GetCapacity();
    auto buffer = new uint8_t[bufferSize];
    ASSERT_NE(buffer, nullptr);
    uint32_t ret = auxiliaryPicture->WritePixels(buffer, bufferSize);
    EXPECT_EQ(ret, ERR_IMAGE_WRITE_PIXELMAP_FAILED);
}

/**
 * @tc.name: SetMetadata001
 * @tc.desc: Set exif metadata successfully.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, SetMetadata001, TestSize.Level1)
{
    const std::string srcValue = "9, 9, 8";
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::shared_ptr<ExifMetadata> srcExifMetadata = std::make_shared<ExifMetadata>(exifData);
    ASSERT_NE(srcExifMetadata, nullptr);
    ASSERT_TRUE(srcExifMetadata->SetValue("BitsPerSample", srcValue));
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->SetMetadata(MetadataType::EXIF, srcExifMetadata);
    std::shared_ptr<ImageMetadata> dstExifMetadata = auxiliaryPicture->GetMetadata(MetadataType::EXIF);
    ASSERT_NE(dstExifMetadata, nullptr);
    std::string dstValue;
    EXPECT_EQ(dstExifMetadata->GetValue("BitsPerSample", dstValue), SUCCESS);
    EXPECT_EQ(dstValue, srcValue);
}

/**
 * @tc.name: SetMetadata002
 * @tc.desc: Set fragment metadata successfully.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, SetMetadata002, TestSize.Level1)
{
    std::string srcValue = "2";
    std::shared_ptr<FragmentMetadata> srcFragmentMetadata = std::make_shared<FragmentMetadata>();
    ASSERT_NE(srcFragmentMetadata, nullptr);
    ASSERT_TRUE(srcFragmentMetadata->SetValue("WIDTH", srcValue));
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->SetMetadata(MetadataType::FRAGMENT, srcFragmentMetadata);
    std::shared_ptr<ImageMetadata> dstFragmentMetadata = auxiliaryPicture->GetMetadata(MetadataType::FRAGMENT);
    ASSERT_NE(dstFragmentMetadata, nullptr);
    std::string dstValue;
    EXPECT_EQ(dstFragmentMetadata->GetValue("WIDTH", dstValue), SUCCESS);
    EXPECT_EQ(dstValue, srcValue);
}

/**
 * @tc.name: SetMetadata003
 * @tc.desc: Set nullptr to auxiliary picture metadata.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, SetMetadata003, TestSize.Level1)
{
    std::shared_ptr<ExifMetadata> srcExifMetadata = nullptr;
    std::shared_ptr<FragmentMetadata> srcFragmentMetadata = nullptr;
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->SetMetadata(MetadataType::EXIF, srcExifMetadata);
    auxiliaryPicture->SetMetadata(MetadataType::FRAGMENT, srcFragmentMetadata);
    EXPECT_TRUE(auxiliaryPicture->HasMetadata(MetadataType::EXIF));
    EXPECT_TRUE(auxiliaryPicture->HasMetadata(MetadataType::FRAGMENT));
    std::shared_ptr<ImageMetadata> dstExifMetadata = auxiliaryPicture->GetMetadata(MetadataType::EXIF);
    EXPECT_EQ(dstExifMetadata, nullptr);
    std::shared_ptr<ImageMetadata> dstFragmentMetadata = auxiliaryPicture->GetMetadata(MetadataType::FRAGMENT);
    EXPECT_EQ(dstFragmentMetadata, nullptr);
}

/**
 * @tc.name: GetMetadata001
 * @tc.desc: Get exif metadata successfully.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, GetMetadata001, TestSize.Level1)
{
    const std::string srcValue = "9, 9, 8";
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::shared_ptr<ExifMetadata> srcExifMetadata = std::make_shared<ExifMetadata>(exifData);
    ASSERT_NE(srcExifMetadata, nullptr);
    ASSERT_TRUE(srcExifMetadata->SetValue("BitsPerSample", srcValue));
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->SetMetadata(MetadataType::EXIF, srcExifMetadata);
    std::shared_ptr<ImageMetadata> dstExifMetadata = auxiliaryPicture->GetMetadata(MetadataType::EXIF);
    ASSERT_NE(dstExifMetadata, nullptr);
    std::string dstValue;
    EXPECT_EQ(dstExifMetadata->GetValue("BitsPerSample", dstValue), SUCCESS);
    EXPECT_EQ(dstValue, srcValue);
}

/**
 * @tc.name: GetMetadata002
 * @tc.desc: Get fragment metadata successfully.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, GetMetadata002, TestSize.Level1)
{
    std::string srcValue = "2";
    std::shared_ptr<FragmentMetadata> srcFragmentMetadata = std::make_shared<FragmentMetadata>();
    ASSERT_NE(srcFragmentMetadata, nullptr);
    ASSERT_TRUE(srcFragmentMetadata->SetValue("WIDTH", srcValue));
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->SetMetadata(MetadataType::FRAGMENT, srcFragmentMetadata);
    std::shared_ptr<ImageMetadata> dstFragmentMetadata = auxiliaryPicture->GetMetadata(MetadataType::FRAGMENT);
    ASSERT_NE(dstFragmentMetadata, nullptr);
    std::string dstValue;
    EXPECT_EQ(dstFragmentMetadata->GetValue("WIDTH", dstValue), SUCCESS);
    EXPECT_EQ(dstValue, srcValue);
}

/**
 * @tc.name: GetMetadata003
 * @tc.desc: Get metadata from a auxiliary picture without metadata.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, GetMetadata003, TestSize.Level1)
{
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_FALSE(auxiliaryPicture->HasMetadata(MetadataType::EXIF));
    EXPECT_FALSE(auxiliaryPicture->HasMetadata(MetadataType::FRAGMENT));
    std::shared_ptr<ImageMetadata> metadata = auxiliaryPicture->GetMetadata(MetadataType::EXIF);
    EXPECT_EQ(metadata, nullptr);
    metadata = auxiliaryPicture->GetMetadata(MetadataType::FRAGMENT);
    EXPECT_EQ(metadata, nullptr);
}

/**
 * @tc.name: GetMetadata004
 * @tc.desc: Set exif metadata with unformated value and get exif metadata with formated value.
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryPictureTest, GetMetadata004, TestSize.Level1)
{
    const std::string srcValue = "9, 9, 8";
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::shared_ptr<ExifMetadata> srcExifMetadata = std::make_shared<ExifMetadata>(exifData);
    ASSERT_NE(srcExifMetadata, nullptr);
    ASSERT_TRUE(srcExifMetadata->SetValue("BitsPerSample", "9,9,8"));
    std::unique_ptr<AuxiliaryPicture> auxiliaryPicture = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    auxiliaryPicture->SetMetadata(MetadataType::EXIF, srcExifMetadata);
    std::shared_ptr<ImageMetadata> dstExifMetadata = auxiliaryPicture->GetMetadata(MetadataType::EXIF);
    ASSERT_NE(dstExifMetadata, nullptr);
    std::string dstValue;
    EXPECT_EQ(dstExifMetadata->GetValue("BitsPerSample", dstValue), SUCCESS);
    EXPECT_EQ(dstValue, srcValue);
}
} // namespace Media
} // namespace OHOS