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

#include "exif_metadata.h"
#include "fragment_metadata.h"
#include "image_common.h"
#include "image_common_impl.h"
#include <cstring>
#include <gtest/gtest.h>
using namespace testing::ext;
namespace OHOS {
namespace Media {
class ImageCommonNdkTest : public testing::Test {
public:
    ImageCommonNdkTest() {}
    ~ImageCommonNdkTest() {}
};
static constexpr Image_MetadataType INVALID_METADATA = static_cast<Image_MetadataType>(3);

static void TestMetaDataClone(Image_MetadataType metadataType)
{
    OH_PictureMetadata *oldMetadata = nullptr;
    Image_ErrorCode res = OH_PictureMetadata_Create(metadataType, &oldMetadata);
    EXPECT_EQ(res, IMAGE_SUCCESS);
    OH_PictureMetadata *newMetadata = nullptr;
    res = OH_PictureMetadata_Clone(oldMetadata, &newMetadata);
    EXPECT_EQ(res, IMAGE_SUCCESS);
    res = OH_PictureMetadata_Release(oldMetadata);
    EXPECT_EQ(res, IMAGE_SUCCESS);
    res = OH_PictureMetadata_Release(newMetadata);
    EXPECT_EQ(res, IMAGE_SUCCESS);
}

static void TestPictureMetadataGetSetProperty(Image_MetadataType metadataType, const std::string &keyString)
{
    OH_PictureMetadata *metadataPtr = nullptr;
    Image_ErrorCode res = OH_PictureMetadata_Create(metadataType, &metadataPtr);
    ASSERT_NE(metadataPtr, nullptr);

    Image_String key;
    key.data = strdup(keyString.c_str());
    key.size = strlen(key.data);
    Image_String srcValue;
    char bufferValue[] = "666";
    srcValue.data = bufferValue;
    srcValue.size = strlen(bufferValue);
    res = OH_PictureMetadata_SetProperty(metadataPtr, &key, &srcValue);
    EXPECT_EQ(res, IMAGE_SUCCESS);

    Image_String dstValue;
    res = OH_PictureMetadata_GetProperty(metadataPtr, &key, &dstValue);
    EXPECT_EQ(res, IMAGE_SUCCESS);
    ASSERT_NE(dstValue.data, nullptr);
    EXPECT_EQ(srcValue.size, dstValue.size);
    EXPECT_EQ(strncmp(srcValue.data, dstValue.data, srcValue.size), 0);
    
    res = OH_PictureMetadata_Release(metadataPtr);
    EXPECT_EQ(res, IMAGE_SUCCESS);
    free(key.data);
    delete[] dstValue.data;
}

/**
 * @tc.name: OH_PictureMetadata_CreateTest001
 * @tc.desc: Tests the creation and release of picture metadata for EXIF_METADATA.
 *           The test checks if the metadata is created and released successfully.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_CreateTest001, TestSize.Level3)
{
    Image_MetadataType metadataType = EXIF_METADATA;
    OH_PictureMetadata *metadataPtr = nullptr;
    Image_ErrorCode res = OH_PictureMetadata_Create(metadataType, &metadataPtr);
    EXPECT_EQ(res, IMAGE_SUCCESS);
    OH_PictureMetadata_Release(metadataPtr);
    EXPECT_EQ(res, IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_PictureMetadata_CreateTest001
 * @tc.desc: Tests the creation and release of picture metadata for FRAGMENT_METADATA.
 *           The test checks if the metadata is created and released successfully.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_CreateTest002, TestSize.Level1)
{
    Image_MetadataType metadataType = FRAGMENT_METADATA;
    OH_PictureMetadata *metadataPtr = nullptr;
    Image_ErrorCode res = OH_PictureMetadata_Create(metadataType, &metadataPtr);
    EXPECT_EQ(res, IMAGE_SUCCESS);
    OH_PictureMetadata_Release(metadataPtr);
    EXPECT_EQ(res, IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_PictureMetadata_CreateTest003
 * @tc.desc: Tests creating picture metadata with a null pointer for the metadata pointer.
 *           The test checks if the function returns the correct error code when a null pointer is provided.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_CreateTest003, TestSize.Level3)
{
    Image_MetadataType metadataType = EXIF_METADATA;
    Image_ErrorCode res = OH_PictureMetadata_Create(metadataType, nullptr);
    EXPECT_EQ(res, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureMetadata_CreateTest004
 * @tc.desc: Tests creating picture metadata with an invalid metadata type.
 *           The test checks if the function returns the correct error code when an invalid type is provided.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_CreateTest004, TestSize.Level3)
{
    OH_PictureMetadata *metadataPtr = nullptr;
    Image_ErrorCode res = OH_PictureMetadata_Create(INVALID_METADATA, &metadataPtr);
    EXPECT_EQ(res, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureMetadata_GetProperty001
 * @tc.desc: Test OH_PictureMetadata_GetProperty with null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_GetPropertyTest001, TestSize.Level3)
{
    Image_ErrorCode res = OH_PictureMetadata_GetProperty(nullptr, nullptr, nullptr);
    EXPECT_EQ(res, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureMetadata_SetProperty001
 * @tc.desc: Test OH_PictureMetadata_SetProperty with null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_SetPropertyTest001, TestSize.Level3)
{
    Image_ErrorCode res = OH_PictureMetadata_SetProperty(nullptr, nullptr, nullptr);
    EXPECT_EQ(res, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureMetadata_GetSetPropertyTest1
 * @tc.desc: Tests setting and getting a property in picture metadata for EXIF_METADATA.
 *           The test checks if the metadata can be created, properties set and retrieved correctly.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_GetSetPropertyTest1, TestSize.Level1)
{
    TestPictureMetadataGetSetProperty(EXIF_METADATA, "ImageWidth");
}

/**
 * @tc.name: OH_PictureMetadata_GetSetPropertyTest
 * @tc.desc: Tests setting and getting a property in picture metadata for FRAGMENT_METADATA.
 *           The test checks if the metadata can be created, properties set and retrieved correctly.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_GetSetPropertyTest2, TestSize.Level1)
{
    TestPictureMetadataGetSetProperty(FRAGMENT_METADATA, "WIDTH");
}
/**
 * @tc.name: OH_PictureMetadata_ReleaseTest001
 * @tc.desc: Test OH_PictureMetadata_Release with null a pointer.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_ReleaseTest001, TestSize.Level3)
{
    Image_ErrorCode res = OH_PictureMetadata_Release(nullptr);
    EXPECT_EQ(res, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureMetadata_CloneTest001
 * @tc.desc: test OH_PictureMetadata_Clone with null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_CloneTest001, TestSize.Level3)
{
    Image_ErrorCode res = OH_PictureMetadata_Clone(nullptr, nullptr);
    EXPECT_EQ(res, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_PictureMetadata_CloneTest002
 * @tc.desc: Tests cloning picture metadata for EXIF_METADATA.
 *           The test checks if the metadata is cloned successfully.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_CloneTest002, TestSize.Level1)
{
    TestMetaDataClone(EXIF_METADATA);
}

/**
 * @tc.name: OH_PictureMetadata_CloneTest003
 * @tc.desc: Tests cloning picture metadata for FRAGMENT_METADATA.
 *           The test checks if the metadata is cloned successfully.
 * @tc.type: FUNC
 */
HWTEST_F(ImageCommonNdkTest, OH_PictureMetadata_CloneTest003, TestSize.Level1)
{
    TestMetaDataClone(FRAGMENT_METADATA);
}

} // namespace Media
} // namespace OHOS