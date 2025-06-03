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
#include "picture.h"
#include "image_type.h"
#include "image_utils.h"
#include "pixel_map.h"
#include "metadata.h"
#include "exif_metadata.h"
#include "fragment_metadata.h"
#include "media_errors.h"
#include "surface_buffer.h"
#include "surface_buffer_impl.h"
#include "tiff_parser.h"
#include "securec.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {

class PictureTest : public testing::Test {
public:
    PictureTest() {}
    ~PictureTest() {}
};

static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test_metadata.jpg";
static const std::string IMAGE_INPUT_EXIF_JPEG_PATH = "/data/local/tmp/image/test_exif.jpg";
static const int32_t SIZE_WIDTH = 2;
static const int32_t SIZE_HEIGHT = 3;
static const int32_t SIZE_STRIDE = 8;
static const int32_t BUFFER_LENGTH = 25;

static std::shared_ptr<PixelMap> CreatePixelMap()
{
    const uint32_t color[BUFFER_LENGTH] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08,
        0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08, 0x80, 0x02 };
    InitializationOptions options;
    options.size.width = SIZE_WIDTH;
    options.size.height = SIZE_HEIGHT;
    options.srcPixelFormat = PixelFormat::RGBA_8888;
    options.pixelFormat = PixelFormat::RGBA_8888;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    std::unique_ptr<PixelMap> tmpPixelMap = PixelMap::Create(color, BUFFER_LENGTH, options);
    std::shared_ptr<PixelMap> pixelmap = std::move(tmpPixelMap);
    return pixelmap;
}

static std::unique_ptr<Picture> CreatePicture()
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    EXPECT_NE(pixelmap, nullptr);
    if (pixelmap == nullptr) {
        return nullptr;
    }
    return Picture::Create(pixelmap);
}

static std::shared_ptr<AuxiliaryPicture> CreateAuxiliaryPicture(AuxiliaryPictureType type)
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    EXPECT_NE(pixelmap, nullptr);
    if (pixelmap == nullptr) {
        return nullptr;
    }
    Size size = {SIZE_WIDTH, SIZE_HEIGHT};
    std::unique_ptr<AuxiliaryPicture> tmpAuxiliaryPicture = AuxiliaryPicture::Create(pixelmap, type, size);
    AuxiliaryPictureInfo auxiliaryPictureInfo;
    auxiliaryPictureInfo.size = size;
    auxiliaryPictureInfo.pixelFormat = PixelFormat::RGBA_8888;
    auxiliaryPictureInfo.rowStride = SIZE_STRIDE;
    auxiliaryPictureInfo.auxiliaryPictureType = AuxiliaryPictureType::GAINMAP;
    tmpAuxiliaryPicture->SetAuxiliaryPictureInfo(auxiliaryPictureInfo);
    EXPECT_NE(tmpAuxiliaryPicture, nullptr);
    if (tmpAuxiliaryPicture == nullptr) {
        return nullptr;
    }
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = std::move(tmpAuxiliaryPicture);
    return auxiliaryPicture;
}

/**
 * @tc.name: GetMainPixelTest001
 * @tc.desc: Get the mainPixelmap of the picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, GetMainPixelTest001, TestSize.Level1)
{
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<PixelMap> picPixelMap = picture->GetMainPixel();
    EXPECT_NE(picPixelMap, nullptr);
}

/**
 * @tc.name: SurfaceBuffer2PixelMapTest001
 * @tc.desc: Obtain pixelmap through an empty surfaceBuffer.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SurfaceBuffer2PixelMapTest001, TestSize.Level3)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<PixelMap> pixelmap = Picture::SurfaceBuffer2PixelMap(buffer);
    EXPECT_EQ(nullptr, pixelmap);
}

/**
 * @tc.name: SurfaceBuffer2PixelMapTest002
 * @tc.desc: Obtain pixelmap through surfaceBuffer.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SurfaceBuffer2PixelMapTest002, TestSize.Level1)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = SurfaceBuffer::Create();
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<PixelMap> pixelmap = Picture::SurfaceBuffer2PixelMap(buffer);
    EXPECT_NE(nullptr, pixelmap);
}

/**
 * @tc.name: SurfaceBuffer2PixelMapTest003
 * @tc.desc: Obtain pixelmap through surfaceBuffer.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SurfaceBuffer2PixelMapTest003, TestSize.Level1)
{
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = SurfaceBuffer::Create();
    ASSERT_NE(buffer, nullptr);
    BufferRequestConfig requestConfig = {
        .width = 10,
        .height = 20,
        .format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCRCB_420_SP,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
    GSError ret = buffer->Alloc(requestConfig);
    ASSERT_EQ(ret, GSERROR_OK);
    std::shared_ptr<PixelMap> pixelmap = Picture::SurfaceBuffer2PixelMap(buffer);
    EXPECT_NE(nullptr, pixelmap);
}

/**
 * @tc.name: SetAuxiliaryPictureTest001
 * @tc.desc: Set gainmap to picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetAuxiliaryPictureTest001, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> gainmap = CreateAuxiliaryPicture(type);
    ASSERT_NE(gainmap, nullptr);
    picture->SetAuxiliaryPicture(gainmap);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_EQ(auxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: SetAuxiliaryPictureTest002
 * @tc.desc: Set depth map to picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetAuxiliaryPictureTest002, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::DEPTH_MAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> depthMap = CreateAuxiliaryPicture(type);
    ASSERT_NE(depthMap, nullptr);
    picture->SetAuxiliaryPicture(depthMap);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_EQ(auxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: SetAuxiliaryPictureTest003
 * @tc.desc: Set unrefocus map to picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetAuxiliaryPictureTest003, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::UNREFOCUS_MAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> unrefocusMap = CreateAuxiliaryPicture(type);
    ASSERT_NE(unrefocusMap, nullptr);
    picture->SetAuxiliaryPicture(unrefocusMap);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_EQ(auxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: SetAuxiliaryPictureTest004
 * @tc.desc: Set linear map to picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetAuxiliaryPictureTest004, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::LINEAR_MAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> linearMap = CreateAuxiliaryPicture(type);
    ASSERT_NE(linearMap, nullptr);
    picture->SetAuxiliaryPicture(linearMap);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_EQ(auxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: SetAuxiliaryPictureTest005
 * @tc.desc: Set fragment map to picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetAuxiliaryPictureTest005, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::FRAGMENT_MAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> fragmentMap = CreateAuxiliaryPicture(type);
    ASSERT_NE(fragmentMap, nullptr);
    picture->SetAuxiliaryPicture(fragmentMap);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_EQ(auxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: SetAuxiliaryPictureTest006
 * @tc.desc: Set a auxiliary picture which type is AuxiliaryPictureType::NONE to the picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetAuxiliaryPictureTest006, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::NONE;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> srcAuxiliaryPicture = CreateAuxiliaryPicture(type);
    ASSERT_NE(srcAuxiliaryPicture, nullptr);
    picture->SetAuxiliaryPicture(srcAuxiliaryPicture);
    std::shared_ptr<AuxiliaryPicture> dstAuxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(dstAuxiliaryPicture, nullptr);
    EXPECT_EQ(dstAuxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: GetAuxiliaryPictureTest001
 * @tc.desc: Get gainmap from picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, GetAuxiliaryPictureTest001, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> gainmap = CreateAuxiliaryPicture(type);
    ASSERT_NE(gainmap, nullptr);
    picture->SetAuxiliaryPicture(gainmap);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_EQ(auxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: GetAuxiliaryPictureTest002
 * @tc.desc: Get depth map from picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, GetAuxiliaryPictureTest002, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::DEPTH_MAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> depthMap = CreateAuxiliaryPicture(type);
    ASSERT_NE(depthMap, nullptr);
    picture->SetAuxiliaryPicture(depthMap);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_EQ(auxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: GetAuxiliaryPictureTest003
 * @tc.desc: Get unrefocus map from picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, GetAuxiliaryPictureTest003, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::UNREFOCUS_MAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> unrefocusMap = CreateAuxiliaryPicture(type);
    ASSERT_NE(unrefocusMap, nullptr);
    picture->SetAuxiliaryPicture(unrefocusMap);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_EQ(auxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: GetAuxiliaryPictureTest004
 * @tc.desc: Get linear map from picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, GetAuxiliaryPictureTest004, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::LINEAR_MAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> linearMap = CreateAuxiliaryPicture(type);
    ASSERT_NE(linearMap, nullptr);
    picture->SetAuxiliaryPicture(linearMap);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_EQ(auxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: GetAuxiliaryPictureTest005
 * @tc.desc: Get fragment cut map from picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, GetAuxiliaryPictureTest005, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::FRAGMENT_MAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> fragmentMap = CreateAuxiliaryPicture(type);
    ASSERT_NE(fragmentMap, nullptr);
    picture->SetAuxiliaryPicture(fragmentMap);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(auxiliaryPicture, nullptr);
    EXPECT_EQ(auxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: GetAuxiliaryPictureTest006
 * @tc.desc: Get auxiliary picture with AuxiliaryPictureType::NONE from picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, GetAuxiliaryPictureTest006, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::NONE;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> srcAuxiliaryPicture = CreateAuxiliaryPicture(type);
    ASSERT_NE(srcAuxiliaryPicture, nullptr);
    picture->SetAuxiliaryPicture(srcAuxiliaryPicture);
    std::shared_ptr<AuxiliaryPicture> dstAuxiliaryPicture = picture->GetAuxiliaryPicture(type);
    ASSERT_NE(dstAuxiliaryPicture, nullptr);
    EXPECT_EQ(srcAuxiliaryPicture, dstAuxiliaryPicture);
    EXPECT_EQ(dstAuxiliaryPicture->GetType(), type);
}

/**
 * @tc.name: GetAuxiliaryPictureTest007
 * @tc.desc: Get gainmap from a picture without gainamap.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, GetAuxiliaryPictureTest007, TestSize.Level1)
{
    const AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    EXPECT_FALSE(picture->HasAuxiliaryPicture(type));
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = picture->GetAuxiliaryPicture(type);
    EXPECT_EQ(auxiliaryPicture, nullptr);
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Marshalling picture without auxiliary picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, MarshallingTest001, TestSize.Level1)
{
    std::unique_ptr<Picture> srcPicture = CreatePicture();
    ASSERT_NE(srcPicture, nullptr);
    Parcel data;
    bool ret = srcPicture->Marshalling(data);
    ASSERT_TRUE(ret);
    auto dstPicture = Picture::Unmarshalling(data);
    ASSERT_NE(dstPicture, nullptr);
    std::shared_ptr<PixelMap> dstMainPixelMap = dstPicture->GetMainPixel();
    ASSERT_NE(dstMainPixelMap, nullptr);
    EXPECT_EQ(dstMainPixelMap->GetWidth(), SIZE_WIDTH);
    EXPECT_EQ(dstMainPixelMap->GetHeight(), SIZE_HEIGHT);
}

/**
 * @tc.name: MarshallingTest002
 * @tc.desc: Marshalling picture which main pixelmap is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, MarshallingTest002, TestSize.Level2)
{
    std::unique_ptr<Picture> srcPicture = CreatePicture();
    ASSERT_NE(srcPicture, nullptr);
    std::shared_ptr<PixelMap> emptyPixelmap = nullptr;
    srcPicture->SetMainPixel(emptyPixelmap);
    Parcel data;
    bool ret = srcPicture->Marshalling(data);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MarshallingTest003
 * @tc.desc: Marshalling the picture with a auxiliary picture without metadata.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, MarshallingTest003, TestSize.Level1)
{
    std::unique_ptr<Picture> srcPicture = CreatePicture();
    ASSERT_NE(srcPicture, nullptr);
    std::shared_ptr<AuxiliaryPicture> gainmap = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(gainmap, nullptr);
    srcPicture->SetAuxiliaryPicture(gainmap);
    Parcel data;
    bool ret = srcPicture->Marshalling(data);
    ASSERT_TRUE(ret);
    auto dstPicture = Picture::Unmarshalling(data);
    ASSERT_NE(dstPicture, nullptr);
    std::shared_ptr<PixelMap> dstMainPixelMap = dstPicture->GetMainPixel();
    ASSERT_NE(dstMainPixelMap, nullptr);
    EXPECT_EQ(dstMainPixelMap->GetWidth(), SIZE_WIDTH);
    EXPECT_EQ(dstMainPixelMap->GetHeight(), SIZE_HEIGHT);
    std::shared_ptr<PixelMap> dstGainmapPixelMap = dstPicture->GetGainmapPixelMap();
    ASSERT_NE(dstGainmapPixelMap, nullptr);
    EXPECT_EQ(dstGainmapPixelMap->GetWidth(), SIZE_WIDTH);
    EXPECT_EQ(dstGainmapPixelMap->GetHeight(), SIZE_HEIGHT);
}

/**
 * @tc.name: MarshallingTest004
 * @tc.desc: Marshalling the picture with a auxiliary picture with exif metadata but empty exifdata.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, MarshallingTest004, TestSize.Level2)
{
    std::unique_ptr<Picture> srcPicture = CreatePicture();
    ASSERT_NE(srcPicture, nullptr);
    std::shared_ptr<AuxiliaryPicture> gainmap = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(gainmap, nullptr);
    std::shared_ptr<ExifMetadata> metadata = std::make_shared<ExifMetadata>();
    gainmap->SetMetadata(MetadataType::EXIF, metadata);
    srcPicture->SetAuxiliaryPicture(gainmap);
    Parcel data;
    bool ret = srcPicture->Marshalling(data);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MarshallingTest005
 * @tc.desc: Marshalling the picture with a auxiliary picture with exif metadata.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, MarshallingTest005, TestSize.Level1)
{
    const std::string srcValue = "9, 9, 8";
    std::string realPath;
    bool cond = ImageUtils::PathToRealPath(IMAGE_INPUT_JPEG_PATH.c_str(), realPath);
    ASSERT_EQ(cond, true);
    auto exifData = exif_data_new_from_file(IMAGE_INPUT_JPEG_PATH.c_str());
    ASSERT_NE(exifData, nullptr);
    std::shared_ptr<ExifMetadata> srcExifMetadata = std::make_shared<ExifMetadata>(exifData);
    ASSERT_NE(srcExifMetadata, nullptr);
    std::unique_ptr<Picture> srcPicture = CreatePicture();
    ASSERT_NE(srcPicture, nullptr);
    std::shared_ptr<AuxiliaryPicture> gainmap = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(gainmap, nullptr);
    ASSERT_TRUE(srcExifMetadata->SetValue("BitsPerSample", srcValue));
    gainmap->SetMetadata(MetadataType::EXIF, srcExifMetadata);
    srcPicture->SetAuxiliaryPicture(gainmap);
    Parcel data;
    bool ret = srcPicture->Marshalling(data);
    ASSERT_TRUE(ret);
    Picture *dstPicture = Picture::Unmarshalling(data);
    ASSERT_NE(dstPicture, nullptr);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture =
        dstPicture->GetAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    std::shared_ptr<ImageMetadata> dstExifMetadata = auxiliaryPicture->GetMetadata(MetadataType::EXIF);
    ASSERT_NE(dstExifMetadata, nullptr);
    std::string dstValue;
    EXPECT_EQ(dstExifMetadata->GetValue("BitsPerSample", dstValue), SUCCESS);
    EXPECT_EQ(dstValue, srcValue);
}

/**
 * @tc.name: MarshallingTest006
 * @tc.desc: Marshalling the picture with a auxiliary picture with fragment metadata.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, MarshallingTest006, TestSize.Level1)
{
    const std::string srcValue = "2";
    std::shared_ptr<FragmentMetadata> srcFragmentMetadata = std::make_shared<FragmentMetadata>();
    ASSERT_NE(srcFragmentMetadata, nullptr);
    std::unique_ptr<Picture> srcPicture = CreatePicture();
    ASSERT_NE(srcPicture, nullptr);
    std::shared_ptr<AuxiliaryPicture> gainmap = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(gainmap, nullptr);
    ASSERT_TRUE(srcFragmentMetadata->SetValue(FRAGMENT_METADATA_KEY_WIDTH, srcValue));
    gainmap->SetMetadata(MetadataType::FRAGMENT, srcFragmentMetadata);
    srcPicture->SetAuxiliaryPicture(gainmap);
    Parcel data;
    bool ret = srcPicture->Marshalling(data);
    ASSERT_TRUE(ret);
    Picture *dstPicture = Picture::Unmarshalling(data);
    ASSERT_NE(dstPicture, nullptr);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture =
        dstPicture->GetAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(auxiliaryPicture, nullptr);
    std::shared_ptr<ImageMetadata> dstFragmentMetadata = auxiliaryPicture->GetMetadata(MetadataType::FRAGMENT);
    ASSERT_NE(dstFragmentMetadata, nullptr);
    std::string dstValue;
    EXPECT_EQ(dstFragmentMetadata->GetValue(FRAGMENT_METADATA_KEY_WIDTH, dstValue), SUCCESS);
    EXPECT_EQ(dstValue, srcValue);
}

/**
* @tc.name: CreateTest001
* @tc.desc: Create a Picture using the correct PixelMap.
* @tc.type: FUNC
*/
HWTEST_F(PictureTest, CreateTest001, TestSize.Level1)
{
    std::shared_ptr<PixelMap> pixelmap = CreatePixelMap();
    ASSERT_NE(pixelmap, nullptr);
    std::unique_ptr<Picture> picture = Picture::Create(pixelmap);
    EXPECT_NE(picture, nullptr);
}

/**
* @tc.name: CreateTest002
* @tc.desc: Create a Picture using PixelMap with null ptr.
* @tc.type: FUNC
*/
HWTEST_F(PictureTest, CreateTest002, TestSize.Level2)
{
    std::shared_ptr<PixelMap> pixelmap = nullptr;
    std::unique_ptr<Picture> picture = Picture::Create(pixelmap);
    EXPECT_EQ(picture, nullptr);
}

/**
* @tc.name: CreateTest003
* @tc.desc: Create a Picture using the correct SurfaceBuffer.
* @tc.type: FUNC
*/
HWTEST_F(PictureTest, CreateTest003, TestSize.Level1)
{
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = OHOS::SurfaceBuffer::Create();
    ASSERT_NE(surfaceBuffer, nullptr);
    std::unique_ptr<Picture> picture = Picture::Create(surfaceBuffer);
    EXPECT_NE(picture, nullptr);
}

/**
* @tc.name: CreateTest004
* @tc.desc: Create a Picture using the SurfaceBuffer with null ptr.
* @tc.type: FUNC
*/
HWTEST_F(PictureTest, CreateTest004, TestSize.Level2)
{
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    std::unique_ptr<Picture> picture = Picture::Create(surfaceBuffer);
    EXPECT_EQ(picture, nullptr);
}

/**
* @tc.name: createPictureFromParcelTest001
* @tc.desc: Create a Picture using the correct Parcel.
* @tc.type: FUNC
*/
HWTEST_F(PictureTest, createPictureFromParcelTest001, TestSize.Level1)
{
    Parcel data;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    auto ret = picture->Marshalling(data);
    EXPECT_TRUE(ret);
    Picture *newPicture = Picture::Unmarshalling(data);
    EXPECT_EQ(newPicture->GetMainPixel()->GetHeight(), picture->GetMainPixel()->GetHeight());
}

/**
* @tc.name: GetGainmapPixelmapTest001
* @tc.desc: There is an auxiliary map of type GainMap, and the corresponding Pixelmap is obtained.
* @tc.type: FUNC
*/
HWTEST_F(PictureTest, GetGainmapPixelmapTest001, TestSize.Level1)
{
    std::shared_ptr<AuxiliaryPicture> gainmapAuxiliaryPic = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    ASSERT_NE(gainmapAuxiliaryPic, nullptr);
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    picture->SetAuxiliaryPicture(gainmapAuxiliaryPic);
    auto mainPixelMap = picture->GetGainmapPixelMap();
    EXPECT_NE(mainPixelMap, nullptr);
    EXPECT_EQ(mainPixelMap->GetHeight(), SIZE_HEIGHT);
}

/**
* @tc.name: GetGainmapPixelmapTest002
* @tc.desc: There is no auxiliary map of type gain map, obtain null ptr.
* @tc.type: FUNC
*/
HWTEST_F(PictureTest, GetGainmapPixelmapTest002, TestSize.Level2)
{
    std::shared_ptr<AuxiliaryPicture> gainmapAuxiliaryPic = CreateAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP);
    ASSERT_NE(gainmapAuxiliaryPic, nullptr);
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    picture->SetAuxiliaryPicture(gainmapAuxiliaryPic);
    std::shared_ptr<PixelMap> desPixelMap = picture->GetGainmapPixelMap();
    EXPECT_EQ(desPixelMap, nullptr);
}

/**
 * @tc.name: CreateExifMetadataTest001
 * @tc.desc: test the Create ExifMetadata of Picture
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, CreateExifMetadataTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "PictureTest: CreateExifMetadataTest001 start";
    std::unique_ptr<Picture> picture = CreatePicture();
    EXPECT_EQ(picture->GetExifMetadata(), nullptr);
    picture->CreateExifMetadata();
    EXPECT_NE(picture->GetExifMetadata(), nullptr);
    GTEST_LOG_(INFO) << "PictureTest: CreateExifMetadataTest001 end";
}

/**
 * @tc.name: SetExifMetadataByExifMetadataTest001
 * @tc.desc: Set nullptr to picture exifMetadata_.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetExifMetadataByExifMetadataTest001, TestSize.Level2)
{
    std::shared_ptr<ExifMetadata> exifMetadata = nullptr;
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    int32_t result = picture->SetExifMetadata(exifMetadata);
    EXPECT_EQ(result, ERR_IMAGE_INVALID_PARAMETER);
}

/**
 * @tc.name: SetExifMetadataTest001
 * @tc.desc: test the SetExifMetadata of Picture
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetExifMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PictureTest: SetExifMetadataTest001 start";
    std::unique_ptr<Picture> picture = CreatePicture();
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    int32_t ret = picture->SetExifMetadata(surfaceBuffer);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PictureTest: SetExifMetadataTest001 end";
}

/**
 * @tc.name: SetExifMetadataTest002
 * @tc.desc: test the SetExifMetadata of Picture
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetExifMetadataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PictureTest: SetExifMetadataTest002 start";
    std::unique_ptr<Picture> picture = CreatePicture();
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    sptr<BufferExtraData> bedata = nullptr;
    surfaceBuffer->SetExtraData(bedata);
    int32_t ret = picture->SetExifMetadata(surfaceBuffer);
    ASSERT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "PictureTest: SetExifMetadataTest002 end";
}

/**
 * @tc.name: SetAuxiliaryPictureTest007
 * @tc.desc: Verify that SetAuxiliaryPicture correctly handles a nullptr AuxiliaryPicture and GetAuxiliaryPicture
 *           returns nullptr for AuxiliaryPictureType::NONE.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetAuxiliaryPictureTest007, TestSize.Level3)
{
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPicture = nullptr;
    picture->SetAuxiliaryPicture(auxiliaryPicture);
    auto auxiliaryPictureByGet = picture->GetAuxiliaryPicture(AuxiliaryPictureType::NONE);
    EXPECT_EQ(auxiliaryPictureByGet, nullptr);
}

/**
 * @tc.name: SetMaintenanceDataTest001
 * @tc.desc: Verify that SetMaintenanceData returns false when a nullptr SurfaceBuffer is provided.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, SetMaintenanceDataTest001, TestSize.Level3)
{
    std::unique_ptr<Picture> picture = CreatePicture();
    ASSERT_NE(picture, nullptr);
    sptr<SurfaceBuffer> surfaceBuffer = nullptr;
    bool isSetMaintenanceData = picture->SetMaintenanceData(surfaceBuffer);
    EXPECT_EQ(isSetMaintenanceData, false);
}

/**
 * @tc.name: dropAuxiliaryPictureTest001
 * @tc.desc: Verify whether the auxiliary picture set is successfully deleted based on the stored type.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, dropAuxiliaryPictureTest001, TestSize.Level1)
{
    std::unique_ptr<Picture> picture = CreatePicture();
    std::shared_ptr<AuxiliaryPicture> auxiliaryPictureGainmap = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPictureFragment =
        CreateAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP);
    picture->SetAuxiliaryPicture(auxiliaryPictureGainmap);
    picture->SetAuxiliaryPicture(auxiliaryPictureFragment);

    picture->DropAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP);
    EXPECT_TRUE(picture->HasAuxiliaryPicture(AuxiliaryPictureType::GAINMAP));
    EXPECT_FALSE(picture->HasAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP));
}

/**
 * @tc.name: dropAuxiliaryPictureTest002
 * @tc.desc: Verify whether the auxiliary picture set is successfully deleted based on the unstored type.
 * @tc.type: FUNC
 */
HWTEST_F(PictureTest, dropAuxiliaryPictureTest002, TestSize.Level1)
{
    std::unique_ptr<Picture> picture = CreatePicture();
    std::shared_ptr<AuxiliaryPicture> auxiliaryPictureGainmap = CreateAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    std::shared_ptr<AuxiliaryPicture> auxiliaryPictureFragment =
        CreateAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP);
    picture->SetAuxiliaryPicture(auxiliaryPictureGainmap);
    picture->SetAuxiliaryPicture(auxiliaryPictureFragment);

    picture->DropAuxiliaryPicture(AuxiliaryPictureType::DEPTH_MAP);
    EXPECT_TRUE(picture->HasAuxiliaryPicture(AuxiliaryPictureType::GAINMAP));
    EXPECT_TRUE(picture->HasAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP));
}

} // namespace Media
} // namespace OHOS