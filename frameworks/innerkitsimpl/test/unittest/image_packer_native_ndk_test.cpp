/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "image_packer_native.h"
#include "image_packer_native_impl.h"
#include "file_packer_stream.h"
#include <fcntl.h>
#include "securec.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {

constexpr int8_t ARGB_8888_BYTES = 4;
constexpr int32_t OUT_DATA_LENGTH = 1000;
class ImagePackerNdk2Test : public testing::Test {
public:
    ImagePackerNdk2Test() {}
    ~ImagePackerNdk2Test() {}
};

/**
 * @tc.name: OH_ImageSourceInfo_Create
 * @tc.desc: test OH_ImageSourceInfo_Create
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_PackingOptions_Create, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImageSourceInfo_Create start";
    OH_PackingOptions *ops = nullptr;
    Image_ErrorCode ret = OH_PackingOptions_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_PackingOptions_Release(ops);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImageSourceInfo_Create end";
}

/**
 * @tc.name: OH_PackingOptions_SetGetMimeType
 * @tc.desc: test OH_PackingOptions_SetGetMimeType
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_PackingOptions_SetGetMimeType, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_PackingOptions_SetGetMimeType start";
    OH_PackingOptions *ops = nullptr;
    char str[10] = "";
    char str2[10] = "12";
    Image_MimeType *mimeType = new Image_MimeType();
    mimeType->data = str;
    mimeType->size = 0;
    Image_MimeType *mimeType2 = new Image_MimeType();
    mimeType2->data = str2;
    mimeType2->size = 2;
    Image_ErrorCode ret = OH_PackingOptions_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_PackingOptions_SetMimeType(ops, mimeType2);
    OH_PackingOptions_GetMimeType(ops, mimeType);
    ASSERT_EQ(mimeType->size, 2);
    string res(mimeType->data, mimeType->size);
    ASSERT_EQ(res, "12");
    OH_PackingOptions_Release(ops);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_PackingOptions_SetGetMimeType end";
}

/**
 * @tc.name: OH_PackingOptions_GetMimeTypeWithNullTest001
 * @tc.desc: test OH_PackingOptions_GetMimeTypeWithNull with null pointer
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_PackingOptions_GetMimeTypeWithNullTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_PackingOptions_GetMimeTypeWithNullTest001 start";
    OH_PackingOptions *ops = nullptr;
    Image_MimeType *mimeType = nullptr;
    Image_ErrorCode ret = OH_PackingOptions_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PackingOptions_GetMimeTypeWithNull(ops, mimeType);
    ASSERT_NE(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_PackingOptions_GetMimeTypeWithNullTest001 end";
}

/**
 * @tc.name: OH_PackingOptions_GetMimeTypeWithNullTest002
 * @tc.desc: test OH_PackingOptions_GetMimeTypeWithNull with right value
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_PackingOptions_GetMimeTypeWithNullTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_PackingOptions_GetMimeTypeWithNullTest002 start";
    OH_PackingOptions *ops = nullptr;
    char str[10] = "";
    char str2[10] = "12";
    Image_MimeType *mimeType = new Image_MimeType();
    mimeType->data = str;
    mimeType->size = 0;
    Image_MimeType *mimeType2 = new Image_MimeType();
    mimeType2->data = str2;
    mimeType2->size = 2;
    Image_ErrorCode ret = OH_PackingOptions_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_PackingOptions_SetMimeType(ops, mimeType2);
    OH_PackingOptions_GetMimeTypeWithNull(ops, mimeType);
    ASSERT_EQ(mimeType->size, 2);
    string res(mimeType->data, mimeType->size);
    ASSERT_EQ(res, "12");
    OH_PackingOptions_Release(ops);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_PackingOptions_GetMimeTypeWithNullTest002 end";
}

/**
 * @tc.name: OH_PackingOptions_Release
 * @tc.desc: test OH_PackingOptions_Release
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_PackingOptions_Release, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_PackingOptions_Release start";
    OH_PackingOptions *ops = nullptr;
    Image_ErrorCode ret = OH_PackingOptions_Release(ops);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_PackingOptions_Release end";
}

/**
 * @tc.name: OH_ImagePackerNative_Create
 * @tc.desc: test OH_ImagePackerNative_Create
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_Create, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_Create start";
    OH_ImagePackerNative *imagePacker = nullptr;
    Image_ErrorCode ret = OH_ImagePackerNative_Create(&imagePacker);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_Create end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToDataFromImageSource
 * @tc.desc: test OH_ImagePackerNative_PackToDataFromImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToDataFromImageSource, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromImageSource start";
    OH_ImagePackerNative *imagePacker = nullptr;
    OH_PackingOptions* option = nullptr;
    OH_ImageSourceNative* imageSource = nullptr;
    uint8_t* outData = nullptr;
    size_t *size = nullptr;
    Image_ErrorCode ret = OH_ImagePackerNative_PackToDataFromImageSource(imagePacker, option, imageSource,
        outData, size);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromImageSource end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToDataFromPixelmap
 * @tc.desc: test OH_ImagePackerNative_PackToDataFromPixelmap
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToDataFromPixelmap, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmap start";
    OH_ImagePackerNative *imagePacker = nullptr;
    OH_PackingOptions* option = nullptr;
    OH_PixelmapNative* pixelMap = nullptr;
    uint8_t* outData = nullptr;
    size_t *size = nullptr;
    Image_ErrorCode ret = OH_ImagePackerNative_PackToDataFromPixelmap(imagePacker, option, pixelMap, outData, size);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmap end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToDataFromPixelmapSequence001
 * @tc.desc: test imagePacker is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToDataFromPixelmapSequence001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmapSequence001 start";
    OH_ImagePackerNative *imagePacker = nullptr;

    OH_PackingOptionsForSequence* option = nullptr;
    Image_ErrorCode errCode = OH_PackingOptionsForSequence_Create(&option);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(option, nullptr);

    size_t dataSize = ARGB_8888_BYTES;
    uint8_t data[] = {0x01, 0x02, 0x03, 0xFF};
    OH_Pixelmap_InitializationOptions *createOpts;
    OH_PixelmapInitializationOptions_Create(&createOpts);
    OH_PixelmapInitializationOptions_SetWidth(createOpts, 1);
    OH_PixelmapInitializationOptions_SetHeight(createOpts, 1);
    OH_PixelmapInitializationOptions_SetPixelFormat(createOpts, PIXEL_FORMAT_BGRA_8888);
    std::vector<OH_PixelmapNative*> pixelMaps;
    OH_PixelmapNative* pixelMap = nullptr;
    errCode = OH_PixelmapNative_CreatePixelmap(data, dataSize, createOpts, &pixelMap);
    pixelMaps.push_back(pixelMap);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(pixelMaps.data(), nullptr);

    std::unique_ptr<uint8_t[]> outData = std::make_unique<uint8_t[]>(OUT_DATA_LENGTH);
    ASSERT_NE(outData.get(), nullptr);

    size_t outDataSize = 0;
    Image_ErrorCode ret = OH_ImagePackerNative_PackToDataFromPixelmapSequence(imagePacker, option,
        pixelMaps.data(), 0, outData.get(), &outDataSize);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmapSequence001 end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToDataFromPixelmapSequence002
 * @tc.desc: test options is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToDataFromPixelmapSequence002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmapSequence002 start";
    OH_ImagePackerNative *imagePacker = nullptr;
    Image_ErrorCode errCode = OH_ImagePackerNative_Create(&imagePacker);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(imagePacker, nullptr);

    OH_PackingOptionsForSequence* option = nullptr;

    size_t dataSize = ARGB_8888_BYTES;
    uint8_t data[] = {0x01, 0x02, 0x03, 0xFF};
    OH_Pixelmap_InitializationOptions *createOpts;
    OH_PixelmapInitializationOptions_Create(&createOpts);
    OH_PixelmapInitializationOptions_SetWidth(createOpts, 1);
    OH_PixelmapInitializationOptions_SetHeight(createOpts, 1);
    OH_PixelmapInitializationOptions_SetPixelFormat(createOpts, PIXEL_FORMAT_BGRA_8888);
    std::vector<OH_PixelmapNative*> pixelMaps;
    OH_PixelmapNative* pixelMap = nullptr;
    errCode = OH_PixelmapNative_CreatePixelmap(data, dataSize, createOpts, &pixelMap);
    pixelMaps.push_back(pixelMap);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(pixelMaps.data(), nullptr);

    std::unique_ptr<uint8_t[]> outData = std::make_unique<uint8_t[]>(OUT_DATA_LENGTH);
    ASSERT_NE(outData.get(), nullptr);

    size_t outDataSize = 0;
    Image_ErrorCode ret = OH_ImagePackerNative_PackToDataFromPixelmapSequence(imagePacker, option,
        pixelMaps.data(), 0, outData.get(), &outDataSize);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmapSequence001 end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToDataFromPixelmapSequence003
 * @tc.desc: test pixelmapSequence is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToDataFromPixelmapSequence003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmapSequence003 start";
    OH_ImagePackerNative *imagePacker = nullptr;
    Image_ErrorCode errCode = OH_ImagePackerNative_Create(&imagePacker);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(imagePacker, nullptr);

    OH_PackingOptionsForSequence* option = nullptr;
    errCode = OH_PackingOptionsForSequence_Create(&option);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(option, nullptr);

    OH_PixelmapNative **pixelMaps = nullptr;

    std::unique_ptr<uint8_t[]> outData = std::make_unique<uint8_t[]>(OUT_DATA_LENGTH);
    ASSERT_NE(outData.get(), nullptr);

    size_t outDataSize = 0;
    Image_ErrorCode ret = OH_ImagePackerNative_PackToDataFromPixelmapSequence(imagePacker, option,
        pixelMaps, 0, outData.get(), &outDataSize);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmapSequence003 end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToDataFromPixelmapSequence004
 * @tc.desc: test outData is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToDataFromPixelmapSequence004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmapSequence004 start";
    OH_ImagePackerNative *imagePacker = nullptr;
    Image_ErrorCode errCode = OH_ImagePackerNative_Create(&imagePacker);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(imagePacker, nullptr);

    OH_PackingOptionsForSequence* option = nullptr;
    errCode = OH_PackingOptionsForSequence_Create(&option);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(option, nullptr);

    size_t dataSize = ARGB_8888_BYTES;
    uint8_t data[] = {0x01, 0x02, 0x03, 0xFF};
    OH_Pixelmap_InitializationOptions *createOpts;
    OH_PixelmapInitializationOptions_Create(&createOpts);
    OH_PixelmapInitializationOptions_SetWidth(createOpts, 1);
    OH_PixelmapInitializationOptions_SetHeight(createOpts, 1);
    OH_PixelmapInitializationOptions_SetPixelFormat(createOpts, PIXEL_FORMAT_BGRA_8888);
    std::vector<OH_PixelmapNative*> pixelMaps;
    OH_PixelmapNative* pixelMap = nullptr;
    errCode = OH_PixelmapNative_CreatePixelmap(data, dataSize, createOpts, &pixelMap);
    pixelMaps.push_back(pixelMap);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(pixelMaps.data(), nullptr);

    uint8_t* outData = nullptr;

    size_t outDataSize = 0;
    Image_ErrorCode ret = OH_ImagePackerNative_PackToDataFromPixelmapSequence(imagePacker, option,
        pixelMaps.data(), 0, outData, &outDataSize);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmapSequence004 end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToFileFromImageSource
 * @tc.desc: test OH_ImagePackerNative_PackToFileFromImageSource
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToFileFromImageSource, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToFileFromImageSource start";
    OH_ImagePackerNative *imagePacker = nullptr;
    OH_PackingOptions* option = nullptr;
    OH_ImageSourceNative* imageSource = nullptr;
    int32_t fd = 0;
    Image_ErrorCode ret = OH_ImagePackerNative_PackToFileFromImageSource(imagePacker, option, imageSource, fd);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToFileFromImageSource end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToFileFromPixelmap
 * @tc.desc: test OH_ImagePackerNative_PackToFileFromPixelmap
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToFileFromPixelmap, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToFileFromPixelmap start";
    OH_ImagePackerNative *imagePacker = nullptr;
    OH_PackingOptions* option = nullptr;
    OH_PixelmapNative* pixelMap = nullptr;
    int32_t fd = 0;
    Image_ErrorCode ret = OH_ImagePackerNative_PackToFileFromPixelmap(imagePacker, option, pixelMap, fd);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToFileFromPixelmap end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToFileFromPixelmapSequence001
 * @tc.desc: test imagePacker is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToFileFromPixelmapSequence001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToFileFromPixelmapSequence001 start";
    OH_ImagePackerNative *imagePacker = nullptr;

    OH_PackingOptionsForSequence* option = nullptr;
    Image_ErrorCode errCode = OH_PackingOptionsForSequence_Create(&option);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(option, nullptr);

    size_t dataSize = ARGB_8888_BYTES;
    uint8_t data[] = {0x01, 0x02, 0x03, 0xFF};
    OH_Pixelmap_InitializationOptions *createOpts;
    OH_PixelmapInitializationOptions_Create(&createOpts);
    OH_PixelmapInitializationOptions_SetWidth(createOpts, 1);
    OH_PixelmapInitializationOptions_SetHeight(createOpts, 1);
    OH_PixelmapInitializationOptions_SetPixelFormat(createOpts, PIXEL_FORMAT_BGRA_8888);
    std::vector<OH_PixelmapNative*> pixelMaps;
    OH_PixelmapNative* pixelMap = nullptr;
    errCode = OH_PixelmapNative_CreatePixelmap(data, dataSize, createOpts, &pixelMap);
    pixelMaps.push_back(pixelMap);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(pixelMaps.data(), nullptr);

    int32_t fd = 0;
    Image_ErrorCode ret =
        OH_ImagePackerNative_PackToFileFromPixelmapSequence(imagePacker, option, pixelMaps.data(), 0, fd);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToFileFromPixelmapSequence001 end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToFileFromPixelmapSequence002
 * @tc.desc: test option is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToFileFromPixelmapSequence002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToFileFromPixelmapSequence002 start";
    OH_ImagePackerNative *imagePacker = nullptr;
    Image_ErrorCode errCode = OH_ImagePackerNative_Create(&imagePacker);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(imagePacker, nullptr);

    OH_PackingOptionsForSequence* option = nullptr;

    size_t dataSize = ARGB_8888_BYTES;
    uint8_t data[] = {0x01, 0x02, 0x03, 0xFF};
    OH_Pixelmap_InitializationOptions *createOpts;
    OH_PixelmapInitializationOptions_Create(&createOpts);
    OH_PixelmapInitializationOptions_SetWidth(createOpts, 1);
    OH_PixelmapInitializationOptions_SetHeight(createOpts, 1);
    OH_PixelmapInitializationOptions_SetPixelFormat(createOpts, PIXEL_FORMAT_BGRA_8888);
    std::vector<OH_PixelmapNative*> pixelMaps;
    OH_PixelmapNative* pixelMap = nullptr;
    errCode = OH_PixelmapNative_CreatePixelmap(data, dataSize, createOpts, &pixelMap);
    pixelMaps.push_back(pixelMap);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(pixelMaps.data(), nullptr);

    int32_t fd = 0;
    Image_ErrorCode ret =
        OH_ImagePackerNative_PackToFileFromPixelmapSequence(imagePacker, option, pixelMaps.data(), 0, fd);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToFileFromPixelmapSequence002 end";
}

/**
 * @tc.name: OH_ImagePackerNative_PackToFileFromPixelmapSequence003
 * @tc.desc: test pixelmapSequence is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_PackToFileFromPixelmapSequence003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToFileFromPixelmapSequence003 start";
    OH_ImagePackerNative *imagePacker = nullptr;
    Image_ErrorCode errCode = OH_ImagePackerNative_Create(&imagePacker);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(imagePacker, nullptr);

    OH_PackingOptionsForSequence* option = nullptr;
    errCode = OH_PackingOptionsForSequence_Create(&option);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(option, nullptr);

    OH_PixelmapNative **pixelMaps = nullptr;

    int32_t fd = 0;
    Image_ErrorCode ret = OH_ImagePackerNative_PackToFileFromPixelmapSequence(imagePacker, option, pixelMaps, 0, fd);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToFileFromPixelmapSequence003 end";
}

/**
 * @tc.name: OH_ImagePackerNative_Release
 * @tc.desc: test OH_ImagePackerNative_Release
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_Release, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_Release start";
    OH_ImagePackerNative *imagePacker = nullptr;
    Image_ErrorCode ret = OH_ImagePackerNative_Release(imagePacker);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_Release end";
}

/**
 * @tc.name: OH_ImageSourceNative_GetSupportedFormatTest001
 * @tc.desc: Verify GetSupportedFormat returns valid format list with non-empty data and correct size.
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_GetSupportedFormatTest001, TestSize.Level3)
{
    Image_MimeType* supportedFormat = nullptr;
    size_t length = 0;
    Image_ErrorCode ret = OH_ImagePackerNative_GetSupportedFormats(&supportedFormat, &length);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    for (size_t i = 0; i < length; i++) {
        EXPECT_NE(supportedFormat[i].data, nullptr);
        EXPECT_NE(supportedFormat[i].size, 0);
    }
    EXPECT_NE(length, 0);
}

/**
 * @tc.name: OH_ImagePackerNative_GetSupportedFormatTest002
 * @tc.desc: Verify GetSupportedFormat returns IMAGE_PACKER_INVALID_PARAMETER when given null input parameters.
 * @tc.type: FUNC
 */
HWTEST_F(ImagePackerNdk2Test, OH_ImagePackerNative_GetSupportedFormatTest002, TestSize.Level3)
{
    Image_MimeType* supportedFormat = nullptr;
    size_t length = 0;
    Image_ErrorCode ret = OH_ImagePackerNative_GetSupportedFormats(nullptr, &length);
    EXPECT_EQ(ret, IMAGE_PACKER_INVALID_PARAMETER);
    ret = OH_ImagePackerNative_GetSupportedFormats(&supportedFormat, nullptr);
    EXPECT_EQ(ret, IMAGE_PACKER_INVALID_PARAMETER);
    ret = OH_ImagePackerNative_GetSupportedFormats(nullptr, nullptr);
    EXPECT_EQ(ret, IMAGE_PACKER_INVALID_PARAMETER);
}
}
}