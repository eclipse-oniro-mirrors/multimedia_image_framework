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
#include "common_utils.h"

#include "image_mdk.h"
#include "image_mdk_kits.h"
#include "image_receiver_mdk.h"
#include "image_receiver_mdk_kits.h"

using namespace testing::ext;
namespace OHOS {
namespace Media {
static constexpr int32_t UNSUCCESS = -1;
class ImageNdkTest : public testing::Test {
public:
    ImageNdkTest() {}
    ~ImageNdkTest() {}
};

struct ImageReceiverNative_ {
    ImageReceiverNapi* napi = nullptr;
    napi_env env = nullptr;
};

struct ImageNative_ {
    ImageNapi* napi = nullptr;
};

/**
 * @tc.name: OH_Image_ClipRectTest
 * @tc.desc: OH_Image_ClipRect
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_ClipRectTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_ClipRectTest start";
    const ImageNative* native = nullptr;
    struct OhosImageRect* rect = nullptr;
    int32_t result = OHOS::Media::OH_Image_ClipRect(native, rect);
    ASSERT_EQ(result, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_ClipRectTest end";
}

/**
 * @tc.name: OH_Image_SizeTest
 * @tc.desc: OH_Image_Size
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_SizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_SizeTest start";
    const ImageNative* native = nullptr;
    struct OhosImageSize* size = nullptr;
    int32_t result = OHOS::Media::OH_Image_Size(native, size);
    ASSERT_EQ(result, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_SizeTest end";
}

/**
 * @tc.name: OH_Image_FormatTest
 * @tc.desc: OH_Image_Format
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_FormatTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_FormatTest start";
    const ImageNative* native = nullptr;
    int32_t* format = nullptr;
    int32_t result = OHOS::Media::OH_Image_Format(native, format);
    ASSERT_EQ(result, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_FormatTest end";
}

/**
 * @tc.name: OH_Image_GetComponentTest
 * @tc.desc: OH_Image_GetComponent
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_GetComponentTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_GetComponentTest start";
    const ImageNative* native = nullptr;
    int32_t componentType = 0;
    struct OhosImageComponent* componentNative = nullptr;
    int32_t result = OHOS::Media::OH_Image_GetComponent(native, componentType, componentNative);
    ASSERT_EQ(result, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_GetComponentTest end";
}

/**
 * @tc.name: OH_Image_ReleaseTest
 * @tc.desc: OH_Image_Release
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_ReleaseTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_ReleaseTest start";
    ImageNative* native = nullptr;
    int32_t result = OHOS::Media::OH_Image_Release(native);
    ASSERT_EQ(result, 0);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_ReleaseTest end";
}

/**
 * @tc.name: OH_Image_Receiver_InitImageReceiverNativeTest
 * @tc.desc: OH_Image_Receiver_InitImageReceiverNative
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_Receiver_InitImageReceiverNativeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_InitImageReceiverNativeTest start";
    napi_env env = nullptr;
    napi_value source = nullptr;
    ImageReceiverNative* res = OHOS::Media::OH_Image_Receiver_InitImageReceiverNative(env, source);
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_InitImageReceiverNativeTest end";
}

/**
 * @tc.name: OH_Image_Receiver_GetReceivingSurfaceIdTest
 * @tc.desc: OH_Image_Receiver_GetReceivingSurfaceId
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_Receiver_GetReceivingSurfaceIdTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_GetReceivingSurfaceIdTest start";
    const ImageReceiverNative *p = nullptr;
    char* id = nullptr;
    size_t len = 100;
    int32_t res = OHOS::Media::OH_Image_Receiver_GetReceivingSurfaceId(p, id, len);
    ASSERT_EQ(res, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_GetReceivingSurfaceIdTest end";
}

/**
 * @tc.name: OH_Image_Receiver_ReadLatestImageTest
 * @tc.desc: OH_Image_Receiver_ReadLatestImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_Receiver_ReadLatestImageTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_ReadLatestImageTest start";
    const ImageReceiverNative *p = nullptr;
    napi_value* image = nullptr;
    int32_t res = OHOS::Media::OH_Image_Receiver_ReadLatestImage(p, image);
    ASSERT_EQ(res, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_ReadLatestImageTest end";
}

/**
 * @tc.name: OH_Image_Receiver_ReadNextImageTest
 * @tc.desc: OH_Image_Receiver_ReadNextImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_Receiver_ReadNextImageTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_ReadNextImageTest start";
    const ImageReceiverNative *p = nullptr;
    napi_value* image = nullptr;
    int32_t res = OHOS::Media::OH_Image_Receiver_ReadNextImage(p, image);
    ASSERT_EQ(res, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_ReadNextImageTest end";
}

/**
 * @tc.name: OH_Image_Receiver_OnTest
 * @tc.desc: OH_Image_Receiver_On
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_Receiver_OnTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_OnTest start";
    const ImageReceiverNative *p = nullptr;
    OH_Image_Receiver_On_Callback callback = nullptr;
    int32_t res = OHOS::Media::OH_Image_Receiver_On(p, callback);
    ASSERT_EQ(res, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_OnTest end";
}

/**
 * @tc.name: OH_Image_Receiver_GetSizeTest
 * @tc.desc: OH_Image_Receiver_GetSize
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_Receiver_GetSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_GetSizeTest start";
    const ImageReceiverNative *p = nullptr;
    struct OhosImageSize* size = nullptr;
    int32_t res = OHOS::Media::OH_Image_Receiver_GetSize(p, size);
    ASSERT_EQ(res, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_GetSizeTest end";
}

/**
 * @tc.name: OH_Image_Receiver_GetCapacityTest
 * @tc.desc: OH_Image_Receiver_GetCapacity
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_Receiver_GetCapacityTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_GetCapacityTest start";
    const ImageReceiverNative *p = nullptr;
    int32_t* capacity = nullptr;
    int32_t res = OHOS::Media::OH_Image_Receiver_GetCapacity(p, capacity);
    ASSERT_EQ(res, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_GetCapacityTest end";
}

/**
 * @tc.name: OH_Image_Receiver_GetFormatTest
 * @tc.desc: OH_Image_Receiver_GetFormat
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_Receiver_GetFormatTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_GetFormatTest start";
    const ImageReceiverNative *p = nullptr;
    int32_t* format = nullptr;
    int32_t res = OHOS::Media::OH_Image_Receiver_GetFormat(p, format);
    ASSERT_EQ(res, UNSUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_GetFormatTest end";
}

/**
 * @tc.name: OH_Image_Receiver_ReleaseTest
 * @tc.desc: OH_Image_Receiver_Release
 * @tc.type: FUNC
 */
HWTEST_F(ImageNdkTest, OH_Image_Receiver_ReleaseTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_ReleaseTest start";
    ImageReceiverNative *p = nullptr;
    int32_t res = OHOS::Media::OH_Image_Receiver_Release(p);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_SUCCESS);

    GTEST_LOG_(INFO) << "ImageNdkTest: OH_Image_Receiver_ReleaseTest end";
}
}
}

