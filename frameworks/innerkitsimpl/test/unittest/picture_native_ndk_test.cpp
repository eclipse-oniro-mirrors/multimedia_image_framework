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

#include <gtest/gtest.h>
#include "exif_metadata.h"
#include "image_common.h"
#include "image_common_impl.h"
#include "image_source_native.h"
#include "metadata.h"
#include "picture_native.h"
#include "pixelmap_native_impl.h"
#include "pixel_map.h"
#include "pixelmap_native.h"
#include "securec.h"
using namespace testing::ext;
namespace OHOS {
namespace Media {
class PictureNdkTest : public testing::Test {
public:
    PictureNdkTest() {}
    ~PictureNdkTest() {}
};

constexpr int32_t sizeWidth = 820;
constexpr int32_t sizeHeight = 312;
constexpr int32_t bufferLength = 255900;
constexpr int32_t sizeWidthExceed = 20;
constexpr int32_t sizeHeightExceed = 50;
constexpr int32_t bufferLengthExceed = 8;
constexpr int32_t sizeBuffer = 2017220;
constexpr int32_t bufferSize = 256;
static const std::string IMAGE_JPEG_PATH = "/data/local/tmp/image/test.jpg";
constexpr int8_t NUM_0 = 0;
constexpr int32_t errorAuxiliaryPictureType = 20;
constexpr uint32_t rowStride = 10;
static constexpr Image_MetadataType INVALID_METADATA = static_cast<Image_MetadataType>(-1);

OH_PictureNative *CreateNativePicture()
{
    size_t length = IMAGE_JPEG_PATH.size();
    char filePath[bufferSize];
    if (strcpy_s(filePath, sizeof(filePath), IMAGE_JPEG_PATH.c_str()) != EOK) {
        return nullptr;
    }
    OH_ImageSourceNative *source = nullptr;

    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromUri(filePath, length, &source);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_DecodingOptions *opts = nullptr;
    OH_PixelmapNative *pixelmap = nullptr;
    OH_DecodingOptions_Create(&opts);

    ret = OH_ImageSourceNative_CreatePixelmap(source, opts, &pixelmap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_DecodingOptions_Release(opts);

    OH_PictureNative *picture = nullptr;
    ret = OH_PictureNative_CreatePicture(pixelmap, &picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    return picture;
}

OH_AuxiliaryPictureNative *CreateAuxiliaryPictureNative()
{
    uint32_t color[bufferLength] = {0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08};
    size_t dataLength = bufferLength;
    Image_Size size;
    size.width = sizeWidth;
    size.height = sizeHeight;
    OH_AuxiliaryPictureNative *picture = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color), dataLength, &size,
        Image_AuxiliaryPictureType::GAINMAP, &picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    return picture;
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_CreateTest001
 * @tc.desc: Creating OH_AuxiliaPictureNative with all normal parameters.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_CreateTest001, TestSize.Level1)
{
    uint32_t color[bufferLength] = {0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08};
    size_t dataLength = bufferLength;
    Image_Size size;
    size.width = sizeWidth;
    size.height = sizeHeight;
    OH_AuxiliaryPictureNative *picture = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color), dataLength, &size,
        Image_AuxiliaryPictureType::GAINMAP, &picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);

    ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color), dataLength, &size,
        Image_AuxiliaryPictureType::DEPTH_MAP, &picture);
    EXPECT_EQ(ret, ::IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);

    ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color), dataLength, &size,
        Image_AuxiliaryPictureType::FRAGMENT_MAP, &picture);
    EXPECT_EQ(ret, ::IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);

    ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color), dataLength, &size,
        Image_AuxiliaryPictureType::LINEAR_MAP, &picture);
    EXPECT_EQ(ret, ::IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);

    ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color), dataLength, &size,
        Image_AuxiliaryPictureType::UNREFOCUS_MAP, &picture);
    EXPECT_EQ(ret, ::IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_CreateTest002
 * @tc.desc: Create OH_AuxiliaryPictureNative, pass null parameter, return IMAGE_BAD_PARAMETER.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_CreateTest002, TestSize.Level2)
{
    uint8_t *color = nullptr;
    size_t dataLength = bufferLength;
    Image_Size size;
    size.width = sizeWidth;
    size.height = sizeHeight;
    OH_AuxiliaryPictureNative *picture = nullptr;
    Image_AuxiliaryPictureType type = Image_AuxiliaryPictureType::GAINMAP;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(color, dataLength, &size, type, &picture);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_CreateTest003
 * @tc.desc: Create OH_AuxiliaryPictureNative, pass in error parameters, return IMAGE_ALLOC_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_CreateTest003, TestSize.Level2)
{
    uint32_t color[bufferLengthExceed] = {0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08};
    size_t dataLength = bufferLengthExceed;
    Image_Size size;
    size.width = sizeWidthExceed;
    size.height = sizeHeightExceed;
    OH_AuxiliaryPictureNative *picture = nullptr;
    Image_AuxiliaryPictureType type = Image_AuxiliaryPictureType::GAINMAP;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color),
        dataLength, &size, type, &picture);
    EXPECT_EQ(ret, IMAGE_UNKNOWN_ERROR);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_CreateTest004
 * @tc.desc: Pass in a non-existent AuxiliaryPictureType and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_CreateTest004, TestSize.Level2)
{
    uint32_t color[bufferLength] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    size_t dataLength = bufferLength;
    Image_Size size;
    size.width = sizeWidth;
    size.height = sizeHeight;
    OH_AuxiliaryPictureNative *picture = nullptr;
    Image_AuxiliaryPictureType type = static_cast<Image_AuxiliaryPictureType>(-1);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color),
        dataLength, &size, type, &picture);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_WritePixelsTest001
 * @tc.desc: Pass in the correct parameters to WritePixels and return success.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_WritePixelsTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();
    size_t size = sizeBuffer;
    std::unique_ptr<uint8_t[]> source = std::make_unique<uint8_t[]>(size);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_WritePixels(picture, source.get(), size);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_WritePixelsTest002
 * @tc.desc: Passing an exception buff to WritePixels returns an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_WritePixelsTest002, TestSize.Level1)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();
    size_t size = bufferLengthExceed;
    std::unique_ptr<uint8_t[]> source = std::make_unique<uint8_t[]>(size);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_WritePixels(picture, source.get(), size);
    EXPECT_EQ(ret, IMAGE_UNKNOWN_ERROR);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_WritePixelsTest003
 * @tc.desc: Passing an empty parameter to WritePixels and returning an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_WritePixelsTest003, TestSize.Level2)
{
    OH_AuxiliaryPictureNative *picture = nullptr;
    uint8_t *source = nullptr;
    size_t bufferSize = NUM_0;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_WritePixels(picture, source, bufferSize);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_ReadPixelsTest001
 * @tc.desc: Passing a normal buff to ReadPixels returns success.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_ReadPixelsTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();
    size_t size = sizeBuffer;
    std::unique_ptr<uint8_t[]> destination = std::make_unique<uint8_t[]>(size);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_ReadPixels(picture, destination.get(), &size);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_ReadPixelsTest002
 * @tc.desc: Passing an exception buff to ReadPixels returns an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_ReadPixelsTest002, TestSize.Level2)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();
    size_t size = bufferLengthExceed;
    std::unique_ptr<uint8_t[]> destination = std::make_unique<uint8_t[]>(size);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_ReadPixels(picture, destination.get(), &size);
    EXPECT_EQ(ret, IMAGE_UNKNOWN_ERROR);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_ReadPixelsTest003
 * @tc.desc: Pass an empty parameter to ReadPixels and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_ReadPixelsTest003, TestSize.Level3)
{
    OH_AuxiliaryPictureNative *picture = nullptr;
    uint8_t *destination = nullptr;
    size_t *bufferSize = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_ReadPixels(picture, destination, bufferSize);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_GetTypeTest001
 * @tc.desc: The input auxiliary image is GAINMAP, and the returned type is GAINMAP.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_GetTypeTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();
    Image_AuxiliaryPictureType type;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetType(picture, &type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(type, Image_AuxiliaryPictureType::GAINMAP);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_GetTypeTest002
 * @tc.desc: Pass in an empty parameter and return an empty type.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_GetTypeTest002, TestSize.Level2)
{
    OH_AuxiliaryPictureNative *picture = nullptr;
    Image_AuxiliaryPictureType *typeptr = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetType(picture, typeptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
    EXPECT_EQ(typeptr, nullptr);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_GetInfoTest001
 * @tc.desc: Pass in the correct parameters and compare the type of info with the original type of AuxiliaryPicture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_GetInfoTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();
    OH_AuxiliaryPictureInfo *infoptr = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetInfo(picture, &infoptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    Image_AuxiliaryPictureType type;
    ret = OH_AuxiliaryPictureInfo_GetType(infoptr, &type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(type, Image_AuxiliaryPictureType::GAINMAP);

    OH_AuxiliaryPictureInfo_Release(infoptr);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_GetInfoTest002
 * @tc.desc: Pass in incorrect parameter, get empty.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_GetInfoTest002, TestSize.Level2)
{
    OH_AuxiliaryPictureNative *picture = nullptr;
    OH_AuxiliaryPictureInfo *infoptr = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetInfo(picture, &infoptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
    EXPECT_EQ(infoptr, nullptr);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_SetInfoTest001
 * @tc.desc: Passing in the correct parameter settings info returned a success message.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_SetInfoTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();
    OH_AuxiliaryPictureInfo *infoptr = nullptr;
    OH_AuxiliaryPictureInfo_Create(&infoptr);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_SetInfo(picture, infoptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_SetInfoTest002
 * @tc.desc: Passing empty parameter setting info returns an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_SetInfoTest002, TestSize.Level3)
{
    OH_AuxiliaryPictureNative *picture = nullptr;
    OH_AuxiliaryPictureInfo *infoptr = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_SetInfo(picture, infoptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_GetMetadataTest001
 * @tc.desc: Pass in normal parameters to obtain Metadata.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_GetMetadataTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();
    OH_PictureMetadata *metadataptr = nullptr;
    Image_MetadataType type = Image_MetadataType::EXIF_METADATA;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetMetadata(picture, type, &metadataptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_PictureMetadata_Release(metadataptr);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_GetMetadataTest002
 * @tc.desc: Pass in a non-existent Metadata Type and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_GetMetadataTest002, TestSize.Level2)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();
    OH_PictureMetadata *metadataptr = nullptr;
    Image_MetadataType type = static_cast<Image_MetadataType>(9);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetMetadata(picture, type, &metadataptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
    EXPECT_EQ(metadataptr, nullptr);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_GetMetadataTest003
 * @tc.desc: Pass in an empty parameter and return a null pointer.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_GetMetadataTest003, TestSize.Level2)
{
    OH_AuxiliaryPictureNative *picture = nullptr;
    OH_PictureMetadata *metadataptr = nullptr;
    Image_MetadataType type = Image_MetadataType::EXIF_METADATA;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetMetadata(picture, type, &metadataptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
    EXPECT_EQ(metadataptr, nullptr);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_SetMetadataTest001
 * @tc.desc: Pass in the normal parameter SetMetadata and return success.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_SetMetadataTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();

    std::shared_ptr<OHOS::Media::ImageMetadata> metadata = std::make_shared<OHOS::Media::ExifMetadata>();
    auto exifMetadata = static_cast<OHOS::Media::ExifMetadata *>(metadata.get());
    exifMetadata->CreateExifdata();
    std::unique_ptr<OH_PictureMetadata> metadataptr = std::make_unique<OH_PictureMetadata>(metadata);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_SetMetadata(picture,
        Image_MetadataType::EXIF_METADATA, metadataptr.get());
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_SetMetadataTest002
 * @tc.desc: Pass in empty parameter SetMetadata, return exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_SetMetadataTest002, TestSize.Level2)
{
    OH_AuxiliaryPictureNative *picture = nullptr;
    OH_PictureMetadata *metadata = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_SetMetadata(picture,
        Image_MetadataType::FRAGMENT_METADATA, metadata);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_CreatePicture001
 * @tc.desc: Verify that a native picture can be successfully created.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_CreatePicture001, TestSize.Level1)
{
    OH_PictureNative *picture = CreateNativePicture();
    EXPECT_NE(picture, nullptr);
    OH_PictureNative_Release(picture);
}

/**
 * @tc.name: OH_PictureNative_CreatePicture002
 * @tc.desc: Verify error handling when creating a native picture with a null pixelmap.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_CreatePicture002, TestSize.Level3)
{
    OH_PictureNative *picture = nullptr;
    Image_ErrorCode ret = OH_PictureNative_CreatePicture(nullptr, &picture);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_GetMainPixelmap001
 * @tc.desc: Verify retrieval of the main pixelmap from a native picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetMainPixelmap001, TestSize.Level1)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_PixelmapNative *mainPixelmap = nullptr;

    Image_ErrorCode ret = OH_PictureNative_GetMainPixelmap(picture, &mainPixelmap);
    EXPECT_NE(mainPixelmap, nullptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PictureNative_Release(picture);
}

/**
 * @tc.name: OH_PictureNative_GetMainPixelmap002
 * @tc.desc: Verify error handling when attempting to retrieve the main pixelmap from a null picture object.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetMainPixelmap002, TestSize.Level3)
{
    OH_PixelmapNative *mainPixelmap = nullptr;
    Image_ErrorCode ret = OH_PictureNative_GetMainPixelmap(nullptr, &mainPixelmap);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_GetGainmapPixelmap001
 * @tc.desc: Verify retrieval of the gainmap pixelmap from a native picture with an auxiliary gainmap set.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetGainmapPixelmap001, TestSize.Level1)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture, Image_AuxiliaryPictureType::GAINMAP,
        auxiliaryPicture);
    ASSERT_EQ(ret, IMAGE_SUCCESS);

    OH_PixelmapNative *gainmapPixelmap = nullptr;
    ret = OH_PictureNative_GetGainmapPixelmap(picture, &gainmapPixelmap);
    EXPECT_NE(gainmapPixelmap, nullptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_PictureNative_Release(picture);
    OH_AuxiliaryPictureNative_Release(auxiliaryPicture);
}

/**
 * @tc.name: OH_PictureNative_GetGainmapPixelmap002
 * @tc.desc: Verify that the auxiliary gain map cannot retrieve the gain map pixel map from the local
 *           image using the auxiliary gain map set.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetGainmapPixelmap002, TestSize.Level3)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture, Image_AuxiliaryPictureType::FRAGMENT_MAP,
        auxiliaryPicture);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);

    OH_PixelmapNative *gainmapPixelmap = nullptr;
    ret = OH_PictureNative_GetGainmapPixelmap(picture, &gainmapPixelmap);
    EXPECT_EQ(gainmapPixelmap, nullptr);
    EXPECT_EQ(ret, IMAGE_ALLOC_FAILED);

    OH_PictureNative_Release(picture);
    OH_AuxiliaryPictureNative_Release(auxiliaryPicture);
}

/**
 * @tc.name: OH_PictureNative_GetGainmapPixelmap003
 * @tc.desc: Verify error handling when attempting to retrieve a gainmap pixelmap from a null picture pointer.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetGainmapPixelmap003, TestSize.Level3)
{
    OH_PixelmapNative *gainmapPixelmap = nullptr;
    Image_ErrorCode ret = OH_PictureNative_GetGainmapPixelmap(nullptr, &gainmapPixelmap);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_GetAuxiliaryPicture001
 * @tc.desc: Verify the functionality of retrieving an auxiliary picture of type gainmap
 *           that has been previously set on a native picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetAuxiliaryPicture001, TestSize.Level1)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_AuxiliaryPictureType type = Image_AuxiliaryPictureType::GAINMAP;
    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture, type, auxiliaryPicture);
    ASSERT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureNative *auxPicture = nullptr;
    ret = OH_PictureNative_GetAuxiliaryPicture(picture, type, &auxPicture);
    EXPECT_NE(auxPicture, nullptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_PictureNative_Release(picture);
    OH_AuxiliaryPictureNative_Release(auxiliaryPicture);
}

/**
 * @tc.name: OH_PictureNative_GetAuxiliaryPicture002
 * @tc.desc: The passed AuxiliaryFigureType does not exist, return exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetAuxiliaryPicture002, TestSize.Level3)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture, Image_AuxiliaryPictureType::GAINMAP,
        auxiliaryPicture);
    ASSERT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureNative *auxPicture = nullptr;
    Image_AuxiliaryPictureType type = static_cast<Image_AuxiliaryPictureType>(-1);
    ret = OH_PictureNative_GetAuxiliaryPicture(picture, type, &auxPicture);
    EXPECT_EQ(auxPicture, nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);

    OH_PictureNative_Release(picture);
    OH_AuxiliaryPictureNative_Release(auxiliaryPicture);
}

/**
 * @tc.name: OH_PictureNative_GetAuxiliaryPicture003
 * @tc.desc: Get the desired AuxiliaryFigureType is not set and returns an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetAuxiliaryPicture003, TestSize.Level3)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture, Image_AuxiliaryPictureType::GAINMAP,
        auxiliaryPicture);
    ASSERT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureNative *auxPicture = nullptr;
    ret = OH_PictureNative_GetAuxiliaryPicture(picture, Image_AuxiliaryPictureType::FRAGMENT_MAP, &auxPicture);
    EXPECT_EQ(auxPicture, nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);

    OH_PictureNative_Release(picture);
    OH_AuxiliaryPictureNative_Release(auxiliaryPicture);
}

/**
 * @tc.name: OH_PictureNative_GetAuxiliaryPicture004
 * @tc.desc: Verify the behavior of OH_PictureNative_GetAuxiliaryPicture when attempting
 *           to retrieve an auxiliary picture of type GAINMAP from a null picture pointer.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetAuxiliaryPicture004, TestSize.Level3)
{
    OH_AuxiliaryPictureNative *auxiliaryPicture = nullptr;
    Image_ErrorCode ret = OH_PictureNative_GetAuxiliaryPicture(nullptr, Image_AuxiliaryPictureType::GAINMAP,
        &auxiliaryPicture);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_SetAuxiliaryPicture001
 * @tc.desc: Verify the functionality of OH_PictureNative_SetAuxiliaryPicture by creating
 *           a native picture and setting an auxiliary picture of type gainmap.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_SetAuxiliaryPicture001, TestSize.Level1)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture, Image_AuxiliaryPictureType::GAINMAP,
        auxiliaryPicture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_PictureNative_Release(picture);
    OH_AuxiliaryPictureNative_Release(auxiliaryPicture);
}

/**
 * @tc.name: OH_PictureNative_SetAuxiliaryPicture002
 * @tc.desc: Pass in a non-existent AuxiliaryFigureType and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_SetAuxiliaryPicture002, TestSize.Level3)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_AuxiliaryPictureType type = static_cast<Image_AuxiliaryPictureType>(-1);
    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture, type, auxiliaryPicture);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);

    OH_PictureNative_Release(picture);
    OH_AuxiliaryPictureNative_Release(auxiliaryPicture);
}

/**
 * @tc.name: OH_PictureNative_SetAuxiliaryPicture003
 * @tc.desc: Passing in different AuxiliaryPicture Types when creating AuxiliaryPicture, returns an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_SetAuxiliaryPicture003, TestSize.Level3)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture, Image_AuxiliaryPictureType::FRAGMENT_MAP,
        auxiliaryPicture);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);

    OH_PictureNative_Release(picture);
    OH_AuxiliaryPictureNative_Release(auxiliaryPicture);
}

/**
 * @tc.name: OH_PictureNative_SetAuxiliaryPicture004
 * @tc.desc: Verify the behavior of OH_PictureNative_SetAuxiliaryPicture when attempting
 *           to set an auxiliary picture of type gainmap on a null picture pointer.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_SetAuxiliaryPicture004, TestSize.Level3)
{
    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(nullptr, Image_AuxiliaryPictureType::GAINMAP, nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_Release001
 * @tc.desc: Verify the functionality of OH_PictureNative_Release by creating a native picture
 *           and releasing it successfully using OH_PictureNative_Release.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_Release001, TestSize.Level1)
{
    OH_PictureNative *picture = CreateNativePicture();
    Image_ErrorCode ret = OH_PictureNative_Release(picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_PictureNative_Release002
 * @tc.desc: Verify the behavior of OH_PictureNative_Release when attempting to release
 *           a null pointer to a native picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_Release002, TestSize.Level3)
{
    Image_ErrorCode ret = OH_PictureNative_Release(nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_ReleaseTest001
 * @tc.desc: Release a valid object and return success.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_ReleaseTest001, TestSize.Level1)
{
    uint32_t color[bufferLength] = {0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08};
    size_t dataLength = bufferLength;
    Image_Size size;
    size.width = sizeWidth;
    size.height = sizeHeight;
    OH_AuxiliaryPictureNative *auxiliaryPictureNative = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t *>(color), dataLength, &size,
        Image_AuxiliaryPictureType::GAINMAP, &auxiliaryPictureNative);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureNative, nullptr);

    ret = OH_AuxiliaryPictureNative_Release(auxiliaryPictureNative);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_ReleaseTest002
 * @tc.desc: Pass in an empty object and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_ReleaseTest002, TestSize.Level3)
{
    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Release(nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_CreateTest001
 * @tc.desc: Create an OH_AuxiliaryPictureInfo object using valid parameters.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_CreateTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureInfo_Release(auxiliaryPictureInfo);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_CreateTest002
 * @tc.desc: Pass in null pointer and return exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_CreateTest002, TestSize.Level3)
{
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_SetTypeTest001
 * @tc.desc: Pass in valid OH_AuxiliaryPictureInfo object and type, and then return success.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_SetTypeTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);

    Image_AuxiliaryPictureType type = GAINMAP;
    ret = OH_AuxiliaryPictureInfo_SetType(auxiliaryPictureInfo, type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureInfo_Release(auxiliaryPictureInfo);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_SetTypeTest002
 * @tc.desc: Passing in invalid AuxiliaryPictureType, returning exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_SetTypeTest002, TestSize.Level3)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);

    Image_AuxiliaryPictureType type = (Image_AuxiliaryPictureType)errorAuxiliaryPictureType;
    ret = OH_AuxiliaryPictureInfo_SetType(auxiliaryPictureInfo, type);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_GetTypeTest001
 * @tc.desc: Set the type and then get the type. Compare the parameters before and after.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_GetTypeTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);

    Image_AuxiliaryPictureType type = GAINMAP;
    Image_AuxiliaryPictureType retType;
    ret = OH_AuxiliaryPictureInfo_SetType(auxiliaryPictureInfo, type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_AuxiliaryPictureInfo_GetType(auxiliaryPictureInfo, &retType);
    EXPECT_EQ(retType, type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    type = FRAGMENT_MAP;
    ret = OH_AuxiliaryPictureInfo_SetType(auxiliaryPictureInfo, type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_AuxiliaryPictureInfo_GetType(auxiliaryPictureInfo, &retType);
    EXPECT_EQ(retType, type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureInfo_Release(auxiliaryPictureInfo);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_GetTypeTest002
 * @tc.desc: Pass in an empty object and return exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_GetTypeTest002, TestSize.Level3)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_AuxiliaryPictureType type;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_GetType(auxiliaryPictureInfo, &type);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_SetSizeTest001
 * @tc.desc: Pass in valid OH_AuxiliaryPictureInfo object and size, and then return success.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_SetSizeTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);

    Image_Size size;
    size.height = sizeHeight;
    size.width = sizeWidth;
    ret = OH_AuxiliaryPictureInfo_SetSize(auxiliaryPictureInfo, &size);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureInfo_Release(auxiliaryPictureInfo);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_SetSizeTest002
 * @tc.desc: Pass in an empty object and return exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_SetSizeTest002, TestSize.Level3)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_Size *size = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_SetSize(auxiliaryPictureInfo, size);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_GetSizeTest001
 * @tc.desc: Set the size and then get the size. Compare the parameters before and after.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_GetSizeTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);

    Image_Size size;
    size.height = sizeHeight;
    size.width = sizeWidth;
    ret = OH_AuxiliaryPictureInfo_SetSize(auxiliaryPictureInfo, &size);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    Image_Size retSize;
    ret = OH_AuxiliaryPictureInfo_GetSize(auxiliaryPictureInfo, &retSize);
    EXPECT_EQ(retSize.height, sizeHeight);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureInfo_Release(auxiliaryPictureInfo);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_GetSizeTest002
 * @tc.desc: Pass in an empty object and return exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_GetSizeTest002, TestSize.Level3)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_Size retSize;

    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_GetSize(auxiliaryPictureInfo, &retSize);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_SetRowStrideTest001
 * @tc.desc: Pass in valid OH_AuxiliaryPictureInfo object and RowStride, and then return success.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_SetRowStrideTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);

    ret = OH_AuxiliaryPictureInfo_SetRowStride(auxiliaryPictureInfo, rowStride);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureInfo_Release(auxiliaryPictureInfo);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_SetRowStrideTest002
 * @tc.desc: Pass in an empty object and return exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_SetRowStrideTest002, TestSize.Level3)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_SetRowStride(auxiliaryPictureInfo, rowStride);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_GetRowStrideTest001
 * @tc.desc: Set the RowStride and then get the RowStride. Compare the parameters before and after.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_GetRowStrideTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);

    ret = OH_AuxiliaryPictureInfo_SetRowStride(auxiliaryPictureInfo, rowStride);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    uint32_t retRowStride;
    ret = OH_AuxiliaryPictureInfo_GetRowStride(auxiliaryPictureInfo, &retRowStride);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(retRowStride, rowStride);

    OH_AuxiliaryPictureInfo_Release(auxiliaryPictureInfo);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_GetRowStrideTest002
 * @tc.desc: Pass in an empty object and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_GetRowStrideTest002, TestSize.Level3)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    uint32_t retRowStride;

    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_GetRowStride(auxiliaryPictureInfo, &retRowStride);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_SetPixelFormatTest001
 * @tc.desc: Pass in valid OH_AuxiliaryPictureInfo object and PixelFormat, and then return success.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_SetPixelFormatTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);

    PIXEL_FORMAT pixelFormat = PIXEL_FORMAT_NV21;
    ret = OH_AuxiliaryPictureInfo_SetPixelFormat(auxiliaryPictureInfo, pixelFormat);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureInfo_Release(auxiliaryPictureInfo);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_SetPixelFormatTest002
 * @tc.desc: Pass in an empty object and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_SetPixelFormatTest002, TestSize.Level3)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    PIXEL_FORMAT pixelFormat = PIXEL_FORMAT_NV21;

    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_SetPixelFormat(auxiliaryPictureInfo, pixelFormat);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_GetPixelFormatTest001
 * @tc.desc: Set the PixelFormat and then get the PixelFormat. Compare the parameters before and after.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_GetPixelFormatTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);

    PIXEL_FORMAT pixelFormat = PIXEL_FORMAT_NV21;
    ret = OH_AuxiliaryPictureInfo_SetPixelFormat(auxiliaryPictureInfo, pixelFormat);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    PIXEL_FORMAT retPixelFormat;
    ret = OH_AuxiliaryPictureInfo_GetPixelFormat(auxiliaryPictureInfo, &retPixelFormat);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(retPixelFormat, pixelFormat);

    OH_AuxiliaryPictureInfo_Release(auxiliaryPictureInfo);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_GetPixelFormatTest002
 * @tc.desc: Pass in an empty object and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_GetPixelFormatTest002, TestSize.Level3)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    PIXEL_FORMAT retPixelFormat;

    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_GetPixelFormat(auxiliaryPictureInfo, &retPixelFormat);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_ReleaseTest001
 * @tc.desc: Release a valid object and return success.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_ReleaseTest001, TestSize.Level1)
{
    OH_AuxiliaryPictureInfo *auxiliaryPictureInfo = nullptr;
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Create(&auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(auxiliaryPictureInfo, nullptr);

    ret = OH_AuxiliaryPictureInfo_Release(auxiliaryPictureInfo);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_AuxiliaryPictureInfo_ReleaseTest002
 * @tc.desc: Pass in an empty object and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureInfo_ReleaseTest002, TestSize.Level3)
{
    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_Release(nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_SetMetadataTest001
 * @tc.desc: test OH_PictureNative_SetMetadata with null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_SetMetadataTest001, TestSize.Level3)
{
    Image_ErrorCode ret = OH_PictureNative_SetMetadata(nullptr, EXIF_METADATA, nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_SetMetadataTest002
 * @tc.desc: test OH_PictureNative_SetMetadata with a invalid metadataType.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_SetMetadataTest002, TestSize.Level3)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_PictureMetadata *metadata = nullptr;
    Image_ErrorCode ret = OH_PictureMetadata_Create(FRAGMENT_METADATA, &metadata);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PictureNative_SetMetadata(picture, INVALID_METADATA, metadata);
    EXPECT_EQ(ret, IMAGE_UNSUPPORTED_METADATA);
    ret = OH_PictureNative_Release(picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
}
/**
 * @tc.name: OH_PictureNative_GetMetadataTest001
 * @tc.desc: test OH_PictureNative_GetMetadata with null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetMetadataTest001, TestSize.Level3)
{
    Image_ErrorCode ret = OH_PictureNative_GetMetadata(nullptr, EXIF_METADATA, nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_GetMetadataTest002
 * @tc.desc: test OH_PictureNative_GetMetadata with a invalid metadataType.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetMetadataTest002, TestSize.Level3)
{
    OH_PictureNative *picture = CreateNativePicture();
    OH_PictureMetadata *metadata = nullptr;
    Image_ErrorCode ret = OH_PictureNative_GetMetadata(picture, INVALID_METADATA, &metadata);
    EXPECT_EQ(ret, IMAGE_UNSUPPORTED_METADATA);
    ret = OH_PictureNative_Release(picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_PictureNative_SetAndGetMetadataTest001
 * @tc.desc: Tests setting and getting metadata on a native picture.
 *           The test checks if the metadata is set and get successfully on the picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_SetAndGetMetadataTest001, TestSize.Level1)
{
    OH_PictureNative *picture = CreateNativePicture();
    Image_MetadataType metadataType = EXIF_METADATA;
    OH_PictureMetadata *metadata = nullptr;
    Image_ErrorCode ret = OH_PictureMetadata_Create(metadataType, &metadata);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    ret = OH_PictureNative_SetMetadata(picture, metadataType, metadata);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_PictureMetadata *metadataGet = nullptr;
    ret = OH_PictureNative_GetMetadata(picture, metadataType, &metadataGet);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    ret = OH_PictureNative_Release(picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PictureMetadata_Release(metadata);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
}

} // namespace Media
} // namespace OHOS