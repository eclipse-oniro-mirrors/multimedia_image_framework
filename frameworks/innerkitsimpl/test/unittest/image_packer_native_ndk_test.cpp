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

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
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
    size_t *size = 0;
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
    size_t *size = 0;
    Image_ErrorCode ret = OH_ImagePackerNative_PackToDataFromPixelmap(imagePacker, option, pixelMap, outData, size);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagePackerNdk2Test: OH_ImagePackerNative_PackToDataFromPixelmap end";
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

}
}