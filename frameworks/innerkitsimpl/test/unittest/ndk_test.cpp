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
#include "image_pixel_map_napi.h"
#include "common_utils.h"
#include "image_pixel_map_napi_kits.h"

using namespace testing::ext;
namespace OHOS {
namespace Media {
class NdkTest : public testing::Test {
public:
    NdkTest() {}
    ~NdkTest() {}
};

struct NativePixelMap {
    PixelMapNapi* napi = nullptr;
};

/**
 * @tc.name: NdkTest001
 * @tc.desc: OH_PixelMap_GetBytesNumberPerRow
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest001 start";
    const NativePixelMap *p = nullptr;
    int* num = nullptr;
    int32_t res = OHOS::Media::OH_PixelMap_GetBytesNumberPerRow(p, num);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest001 end";
}

/**
 * @tc.name: NdkTest002
 * @tc.desc: OH_PixelMap_GetIsEditable
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest002 start";
    const NativePixelMap *p = nullptr;
    int* num = nullptr;
    int32_t res = OHOS::Media::OH_PixelMap_GetIsEditable(p, num);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest002 end";
}

/**
 * @tc.name: NdkTest003
 * @tc.desc: OH_PixelMap_IsSupportAlpha
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest003 start";
    const NativePixelMap *p = nullptr;
    int* num = nullptr;
    int32_t res = OHOS::Media::OH_PixelMap_IsSupportAlpha(p, num);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest003 end";
}

/**
 * @tc.name: NdkTest004
 * @tc.desc: OH_PixelMap_SetAlphaAble
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest004 start";
    const NativePixelMap *p = nullptr;
    int num = 0;
    int32_t res = OHOS::Media::OH_PixelMap_SetAlphaAble(p, num);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest004 end";
}

/**
 * @tc.name: NdkTest005
 * @tc.desc: GetFilterRowType
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest005 start";
    const NativePixelMap *p = nullptr;
    int* num = nullptr;
    int32_t res = OHOS::Media::OH_PixelMap_GetDensity(p, num);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest005 end";
}

/**
 * @tc.name: NdkTest006
 * @tc.desc: OH_PixelMap_SetDensity
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest006 start";
    const NativePixelMap *p = nullptr;
    int num = 0;
    int32_t res = OHOS::Media::OH_PixelMap_SetDensity(p, num);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest006 end";
}

/**
 * @tc.name: NdkTest007
 * @tc.desc: OH_PixelMap_SetOpacity
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest007 start";
    const NativePixelMap *p = nullptr;
    float num = 0.5;
    int32_t res = OHOS::Media::OH_PixelMap_SetOpacity(p, num);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest007 end";
}

/**
 * @tc.name: NdkTest008
 * @tc.desc: OH_PixelMap_Scale
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest008 start";
    const NativePixelMap *p = nullptr;
    float x = 0.5;
    float y = 0.5;
    int32_t res = OHOS::Media::OH_PixelMap_Scale(p, x, y);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest008 end";
}

/**
 * @tc.name: NdkTest009
 * @tc.desc: OH_PixelMap_Translate
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest009 start";
    const NativePixelMap *p = nullptr;
    float x = 0.5;
    float y = 0.5;
    int32_t res = OHOS::Media::OH_PixelMap_Translate(p, x, y);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest009 end";
}

/**
 * @tc.name: NdkTest0010
 * @tc.desc: OH_PixelMap_Rotate
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest0010 start";
    const NativePixelMap *p = nullptr;
    float x = 0.5;
    int32_t res = OHOS::Media::OH_PixelMap_Rotate(p, x);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest0010 end";
}

/**
 * @tc.name: NdkTest0011
 * @tc.desc: OH_PixelMap_Flip
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest0011 start";
    const NativePixelMap *p = nullptr;
    int32_t x = 0;
    int32_t y = 0;
    int32_t res = OHOS::Media::OH_PixelMap_Flip(p, x, y);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest0011 end";
}

/**
 * @tc.name: NdkTest0012
 * @tc.desc: OH_PixelMap_Crop
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest0012 start";
    const NativePixelMap *p = nullptr;
    int32_t x = 0;
    int32_t y = 0;
    int32_t width = 0;
    int32_t height = 0;
    int32_t res = OHOS::Media::OH_PixelMap_Crop(p, x, y, width, height);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest0012 end";
}

/**
 * @tc.name: NdkTest0013
 * @tc.desc: OH_PixelMap_Crop
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest0013 start";
    const NativePixelMap *p = nullptr;
    OhosPixelMapInfo *info = nullptr;
    int32_t res = OHOS::Media::OH_PixelMap_GetImageInfo(p, info);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest0013 end";
}

/**
 * @tc.name: NdkTest0014
 * @tc.desc: OH_PixelMap_AccessPixels
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest0014 start";
    const NativePixelMap *p = nullptr;
    void **info = nullptr;
    int32_t res = OHOS::Media::OH_PixelMap_AccessPixels(p, info);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest0014 end";
}

/**
 * @tc.name: NdkTest0015
 * @tc.desc: OH_PixelMap_UnAccessPixels
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, NdkTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: NdkTest0015 start";
    const NativePixelMap *p = nullptr;
    int32_t res = OHOS::Media::OH_PixelMap_UnAccessPixels(p);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest0015 end";
}
}
}

