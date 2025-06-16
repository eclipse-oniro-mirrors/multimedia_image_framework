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
#include "image_utils.h"
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

static const int32_t SIZE_WIDTH = 820;
static const int32_t SIZE_HEIGHT = 312;
static const int32_t INIT_BUFFER_LENGTH = 8;
static const int32_t BUFFER_LENGTH = 255900;
static const int32_t SIZE_WIDTH_EXCEED = 20;
static const int32_t SIZE_HEIGHT_EXCEED = 50;
static const int32_t SIZE_BUFFER = 2017220;
static const int32_t BUFFER_SIZE = 256;
static const std::string IMAGE_JPEG_PATH = "/data/local/tmp/image/test_picture.jpg";
static const int8_t NUM_0 = 0;
static const int32_t ERRER_AUXILIARY_PICTURE_TYPE = 20;
static const uint32_t ROW_STRIDE = 10;
static const Image_MetadataType INVALID_METADATA = static_cast<Image_MetadataType>(-1);

static void ReleasingLocalResources(OH_ImageSourceNative *source, OH_DecodingOptions *opts,
    OH_DecodingOptionsForPicture *options)
{
    if (source != nullptr) {
        OH_ImageSourceNative_Release(source);
        source = nullptr;
    }
    if (opts != nullptr) {
        OH_DecodingOptions_Release(opts);
        opts = nullptr;
    }
    if (options != nullptr) {
        OH_DecodingOptionsForPicture_Release(options);
        options = nullptr;
    }
}

OH_PictureNative *CreateNativePicture(std::vector<Image_AuxiliaryPictureType>& ayxTypeList)
{
    std::string realPath;
    if (!ImageUtils::PathToRealPath(IMAGE_JPEG_PATH.c_str(), realPath)) {
        return nullptr;
    }
    char filePath[BUFFER_SIZE];
    if (strcpy_s(filePath, sizeof(filePath), realPath.c_str()) != EOK) {
        return nullptr;
    }
    size_t length = realPath.size();
    OH_ImageSourceNative *source = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromUri(filePath, length, &source);
    if (source == nullptr) {
        return nullptr;
    }

    OH_DecodingOptions *opts = nullptr;
    OH_PixelmapNative *pixelmap = nullptr;
    OH_DecodingOptions_Create(&opts);
    if (opts == nullptr) {
        ReleasingLocalResources(source, opts, nullptr);
        return nullptr;
    }
    OH_DecodingOptionsForPicture *options = nullptr;
    ret = OH_DecodingOptionsForPicture_Create(&options);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    if (options == nullptr) {
        ReleasingLocalResources(source, opts, options);
        return nullptr;
    }
    ret = OH_ImageSourceNative_CreatePixelmap(source, opts, &pixelmap);
    if (pixelmap == nullptr) {
        ReleasingLocalResources(source, opts, options);
        return nullptr;
    }
    ret = OH_DecodingOptionsForPicture_SetDesiredAuxiliaryPictures(options, ayxTypeList.data(), ayxTypeList.size());
    OH_PictureNative *picture = nullptr;
    ret = OH_PictureNative_CreatePicture(pixelmap, &picture);
    if (picture == nullptr) {
        ReleasingLocalResources(source, opts, options);
        return nullptr;
    }
    ret = OH_ImageSourceNative_CreatePicture(source, options, &picture);
    if (picture == nullptr) {
        ReleasingLocalResources(source, opts, options);
        return nullptr;
    }
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ReleasingLocalResources(source, opts, options);
    return picture;
}

OH_AuxiliaryPictureNative *CreateAuxiliaryPictureNative()
{
    std::unique_ptr<uint32_t[]> color = std::make_unique<uint32_t[]>(BUFFER_LENGTH);
    if (color == nullptr) {
        return nullptr;
    }
    uint32_t colorTmp[INIT_BUFFER_LENGTH] = {0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08};
    if (EOK != memcpy_s(color.get(), INIT_BUFFER_LENGTH, colorTmp, INIT_BUFFER_LENGTH)) {
        return nullptr;
    }
    size_t dataLength = BUFFER_LENGTH;
    Image_Size size;
    size.width = SIZE_WIDTH;
    size.height = SIZE_HEIGHT;
    OH_AuxiliaryPictureNative *picture = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color.get()), dataLength, &size,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP, &picture);
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
    std::unique_ptr<uint32_t[]> color = std::make_unique<uint32_t[]>(BUFFER_LENGTH);
    ASSERT_NE(color, nullptr);
    uint32_t colorTmp[INIT_BUFFER_LENGTH] = {0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08};
    errno_t res = memcpy_s(color.get(), INIT_BUFFER_LENGTH, colorTmp, INIT_BUFFER_LENGTH);
    ASSERT_EQ(res, EOK);
    size_t dataLength = BUFFER_LENGTH;
    Image_Size size;
    size.width = SIZE_WIDTH;
    size.height = SIZE_HEIGHT;
    OH_AuxiliaryPictureNative *picture = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color.get()), dataLength, &size,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP, &picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);
    picture = nullptr;

    ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color.get()), dataLength, &size,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_DEPTH_MAP, &picture);
    EXPECT_EQ(ret, ::IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);
    picture = nullptr;

    ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color.get()), dataLength, &size,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_FRAGMENT_MAP, &picture);
    EXPECT_EQ(ret, ::IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);
    picture = nullptr;

    ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color.get()), dataLength, &size,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_LINEAR_MAP, &picture);
    EXPECT_EQ(ret, ::IMAGE_SUCCESS);
    OH_AuxiliaryPictureNative_Release(picture);
    picture = nullptr;

    ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color.get()), dataLength, &size,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_UNREFOCUS_MAP, &picture);
    OH_AuxiliaryPictureNative_Release(picture);
    picture = nullptr;
    EXPECT_EQ(ret, ::IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_CreateTest002
 * @tc.desc: Create OH_AuxiliaryPictureNative, pass null parameter, return IMAGE_BAD_PARAMETER.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_CreateTest002, TestSize.Level2)
{
    uint8_t *color = nullptr;
    size_t dataLength = BUFFER_LENGTH;
    Image_Size size;
    size.width = SIZE_WIDTH;
    size.height = SIZE_HEIGHT;
    OH_AuxiliaryPictureNative *picture = nullptr;
    Image_AuxiliaryPictureType type = Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP;

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
    uint32_t color[INIT_BUFFER_LENGTH] = {0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08};
    size_t dataLength = INIT_BUFFER_LENGTH;
    Image_Size size;
    size.width = SIZE_WIDTH_EXCEED;
    size.height = SIZE_HEIGHT_EXCEED;
    OH_AuxiliaryPictureNative *picture = nullptr;
    Image_AuxiliaryPictureType type = Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color),
        dataLength, &size, type, &picture);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_CreateTest004
 * @tc.desc: Pass in a non-existent AuxiliaryPictureType and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_CreateTest004, TestSize.Level2)
{
    std::unique_ptr<uint32_t[]> color = std::make_unique<uint32_t[]>(BUFFER_LENGTH);
    ASSERT_NE(color, nullptr);
    uint32_t colorTmp[INIT_BUFFER_LENGTH] = { 0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08 };
    errno_t res = memcpy_s(color.get(), INIT_BUFFER_LENGTH, colorTmp, INIT_BUFFER_LENGTH);
    ASSERT_EQ(res, EOK);
    size_t dataLength = BUFFER_LENGTH;
    Image_Size size;
    size.width = SIZE_WIDTH;
    size.height = SIZE_HEIGHT;
    OH_AuxiliaryPictureNative *picture = nullptr;
    Image_AuxiliaryPictureType type = static_cast<Image_AuxiliaryPictureType>(-1);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t*>(color.get()),
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
    ASSERT_NE(picture, nullptr);
    size_t size = SIZE_BUFFER;
    std::unique_ptr<uint8_t[]> source = std::make_unique<uint8_t[]>(size);
    ASSERT_NE(source, nullptr);

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
    ASSERT_NE(picture, nullptr);
    size_t size = INIT_BUFFER_LENGTH;
    std::unique_ptr<uint8_t[]> source = std::make_unique<uint8_t[]>(size);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_WritePixels(picture, source.get(), size);
    EXPECT_EQ(ret, IMAGE_COPY_FAILED);
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
    size_t BUFFER_SIZE = NUM_0;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_WritePixels(picture, source, BUFFER_SIZE);
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
    ASSERT_NE(picture, nullptr);
    size_t size = SIZE_BUFFER;
    std::unique_ptr<uint8_t[]> destination = std::make_unique<uint8_t[]>(size);
    ASSERT_NE(destination, nullptr);

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
    ASSERT_NE(picture, nullptr);
    size_t size = INIT_BUFFER_LENGTH;
    std::unique_ptr<uint8_t[]> destination = std::make_unique<uint8_t[]>(size);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_ReadPixels(picture, destination.get(), &size);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
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
    size_t *BUFFER_SIZE = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_ReadPixels(picture, destination, BUFFER_SIZE);
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
    ASSERT_NE(picture, nullptr);
    Image_AuxiliaryPictureType type;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetType(picture, &type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(type, Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP);
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
    ASSERT_NE(picture, nullptr);
    OH_AuxiliaryPictureInfo *infoptr = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetInfo(picture, &infoptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    Image_AuxiliaryPictureType type;
    ret = OH_AuxiliaryPictureInfo_GetType(infoptr, &type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(type, Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP);

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
    ASSERT_NE(picture, nullptr);
    OH_AuxiliaryPictureInfo *infoptr = nullptr;
    OH_AuxiliaryPictureInfo_Create(&infoptr);

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_SetInfo(picture, infoptr);
    Image_ErrorCode expectRet = ImageUtils::GetAPIVersion() > APIVERSION_13 ? IMAGE_BAD_PARAMETER : IMAGE_SUCCESS;
    EXPECT_EQ(ret, expectRet);
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
 * @tc.desc: Pass in a non-existent Metadata Type and return an exception.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_GetMetadataTest001, TestSize.Level2)
{
    OH_AuxiliaryPictureNative *picture = CreateAuxiliaryPictureNative();
    ASSERT_NE(picture, nullptr);
    OH_PictureMetadata *metadataptr = nullptr;
    Image_MetadataType type = static_cast<Image_MetadataType>(9); // wrong type

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetMetadata(picture, type, &metadataptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
    EXPECT_EQ(metadataptr, nullptr);
    OH_AuxiliaryPictureNative_Release(picture);
}

/**
 * @tc.name: OH_AuxiliaryPictureNative_GetMetadataTest002
 * @tc.desc: Pass in an empty parameter and return a null pointer.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_AuxiliaryPictureNative_GetMetadataTest002, TestSize.Level2)
{
    OH_AuxiliaryPictureNative *picture = nullptr;
    OH_PictureMetadata *metadataptr = nullptr;
    Image_MetadataType metadataType = EXIF_METADATA;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_GetMetadata(picture, metadataType, &metadataptr);
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
    ASSERT_NE(picture, nullptr);

    Image_MetadataType metadataType = EXIF_METADATA;
    OH_PictureMetadata *metadataptr = nullptr;
    Image_ErrorCode ret = OH_PictureMetadata_Create(metadataType, &metadataptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(metadataptr, nullptr);

    ret = OH_AuxiliaryPictureNative_SetMetadata(picture, metadataType, metadataptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PictureMetadata *metadataPtrGet = nullptr;
    ret = OH_AuxiliaryPictureNative_GetMetadata(picture, metadataType, &metadataPtrGet);
    EXPECT_EQ(ret, IMAGE_UNSUPPORTED_METADATA);
    OH_PictureMetadata_Release(metadataptr);
    OH_PictureMetadata_Release(metadataPtrGet);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
    ASSERT_NE(picture, nullptr);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
    ASSERT_NE(picture, nullptr);
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP, auxiliaryPicture);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {AUXILIARY_PICTURE_TYPE_FRAGMENT_MAP};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    OH_PixelmapNative *gainmapPixelmap = nullptr;
    Image_ErrorCode ret = OH_PictureNative_GetGainmapPixelmap(picture, &gainmapPixelmap);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_AuxiliaryPictureType type = Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP;
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP, auxiliaryPicture);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP, auxiliaryPicture);
    ASSERT_EQ(ret, IMAGE_SUCCESS);

    OH_AuxiliaryPictureNative *auxPicture = nullptr;
    ret = OH_PictureNative_GetAuxiliaryPicture(picture,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_FRAGMENT_MAP, &auxPicture);
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
    Image_ErrorCode ret = OH_PictureNative_GetAuxiliaryPicture(nullptr,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP, &auxiliaryPicture);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP, auxiliaryPicture);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
    OH_AuxiliaryPictureNative *auxiliaryPicture = CreateAuxiliaryPictureNative();

    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(picture,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_FRAGMENT_MAP, auxiliaryPicture);
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
    Image_ErrorCode ret = OH_PictureNative_SetAuxiliaryPicture(nullptr,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP, nullptr);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
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
    std::unique_ptr<uint32_t[]> color = std::make_unique<uint32_t[]>(BUFFER_LENGTH);
    ASSERT_NE(color, nullptr);
    uint32_t colorTmp[INIT_BUFFER_LENGTH] = {0x80, 0x02, 0x04, 0x08, 0x40, 0x02, 0x04, 0x08};
    errno_t res = memcpy_s(color.get(), INIT_BUFFER_LENGTH, colorTmp, INIT_BUFFER_LENGTH);
    ASSERT_EQ(res, EOK);
    size_t dataLength = BUFFER_LENGTH;
    Image_Size size;
    size.width = SIZE_WIDTH;
    size.height = SIZE_HEIGHT;
    OH_AuxiliaryPictureNative *auxiliaryPictureNative = nullptr;

    Image_ErrorCode ret = OH_AuxiliaryPictureNative_Create(reinterpret_cast<uint8_t *>(color.get()), dataLength, &size,
        Image_AuxiliaryPictureType::AUXILIARY_PICTURE_TYPE_GAINMAP, &auxiliaryPictureNative);
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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);
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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);

    Image_AuxiliaryPictureType type = AUXILIARY_PICTURE_TYPE_GAINMAP;
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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);

    Image_AuxiliaryPictureType type = (Image_AuxiliaryPictureType)ERRER_AUXILIARY_PICTURE_TYPE;
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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);

    Image_AuxiliaryPictureType type = AUXILIARY_PICTURE_TYPE_GAINMAP;
    Image_AuxiliaryPictureType retType;
    ret = OH_AuxiliaryPictureInfo_SetType(auxiliaryPictureInfo, type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_AuxiliaryPictureInfo_GetType(auxiliaryPictureInfo, &retType);
    EXPECT_EQ(retType, type);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    type = AUXILIARY_PICTURE_TYPE_FRAGMENT_MAP;
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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);

    Image_Size size;
    size.height = SIZE_HEIGHT;
    size.width = SIZE_WIDTH;
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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);

    Image_Size size;
    size.height = SIZE_HEIGHT;
    size.width = SIZE_WIDTH;
    ret = OH_AuxiliaryPictureInfo_SetSize(auxiliaryPictureInfo, &size);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    Image_Size retSize;
    ret = OH_AuxiliaryPictureInfo_GetSize(auxiliaryPictureInfo, &retSize);
    EXPECT_EQ(retSize.height, SIZE_HEIGHT);
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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);

    ret = OH_AuxiliaryPictureInfo_SetRowStride(auxiliaryPictureInfo, ROW_STRIDE);
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

    Image_ErrorCode ret = OH_AuxiliaryPictureInfo_SetRowStride(auxiliaryPictureInfo, ROW_STRIDE);
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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);

    ret = OH_AuxiliaryPictureInfo_SetRowStride(auxiliaryPictureInfo, ROW_STRIDE);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    uint32_t retRowStride;
    ret = OH_AuxiliaryPictureInfo_GetRowStride(auxiliaryPictureInfo, &retRowStride);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(retRowStride, ROW_STRIDE);

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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);

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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);

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
    ASSERT_NE(auxiliaryPictureInfo, nullptr);

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
    Image_MetadataType metadataType = EXIF_METADATA;
    Image_ErrorCode ret = OH_PictureNative_SetMetadata(nullptr, metadataType, nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_SetMetadataTest002
 * @tc.desc: test OH_PictureNative_SetMetadata with a invalid metadataType.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_SetMetadataTest002, TestSize.Level3)
{
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
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
    Image_MetadataType metadataType = EXIF_METADATA;
    Image_ErrorCode ret = OH_PictureNative_GetMetadata(nullptr, metadataType, nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureNative_GetMetadataTest002
 * @tc.desc: test OH_PictureNative_GetMetadata with a invalid metadataType.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_GetMetadataTest002, TestSize.Level3)
{
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
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
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
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

/**
 * @tc.name: OH_PictureNative_SetAndGetMetadataTest003
 * @tc.desc: Tests setting and getting gif metadata on a native picture.
 *           The test checks if the metadata is set and get successfully on the picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureNdkTest, OH_PictureNative_SetAndGetMetadataTest003, TestSize.Level1)
{
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
    Image_MetadataType metadataType = GIF_METADATA;
    OH_PictureMetadata *metadata = nullptr;
    Image_ErrorCode ret = OH_PictureMetadata_Create(metadataType, &metadata);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    ret = OH_PictureNative_SetMetadata(picture, metadataType, metadata);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_PictureMetadata *metadataGet = nullptr;
    ret = OH_PictureNative_GetMetadata(picture, metadataType, &metadataGet);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(metadataGet, nullptr);

    ret = OH_PictureNative_Release(picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PictureMetadata_Release(metadata);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
}
} // namespace Media
} // namespace OHOS