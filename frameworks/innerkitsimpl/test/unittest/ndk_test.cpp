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
#include "image_pixel_map_mdk.h"
#include "image_pixel_map_napi.h"
#include "common_utils.h"
#include "image_pixel_map_napi_kits.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Media {
class NdkTest : public testing::Test {
public:
    NdkTest() {}
    ~NdkTest() {}
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
    int32_t res = OH_PixelMap_GetBytesNumberPerRow(p, num);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_GetIsEditable(p, num);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_IsSupportAlpha(p, num);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_SetAlphaAble(p, num);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_GetDensity(p, num);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_SetDensity(p, num);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_SetOpacity(p, num);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_Scale(p, x, y);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_Translate(p, x, y);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_Rotate(p, x);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_Flip(p, x, y);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_Crop(p, x, y, width, height);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    OhosPixelMapInfos *info = nullptr;
    int32_t res = OH_PixelMap_GetImageInfo(p, info);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_AccessPixels(p, info);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

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
    int32_t res = OH_PixelMap_UnAccessPixels(p);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: NdkTest0015 end";
}

/**
 * @tc.name: OH_PixelMap_InitNativePixelMapTest
 * @tc.desc: OH_PixelMap_InitNativePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, OH_PixelMap_InitNativePixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: OH_PixelMap_InitNativePixelMapTest start";
    napi_env env = nullptr;
    napi_value source = nullptr;
    NativePixelMap* res = OH_PixelMap_InitNativePixelMap(env, source);
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "NdkTest: OH_PixelMap_InitNativePixelMapTest end";
}

/**
 * @tc.name: OH_PixelMap_CreatePixelMapTest
 * @tc.desc: OH_PixelMap_CreatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, OH_PixelMap_CreatePixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: OH_PixelMap_CreatePixelMapTest start";
    napi_env env = nullptr;
    OhosPixelMapCreateOps info;
    void* buf = nullptr;
    size_t len = 0;
    napi_value* res = nullptr;
    int32_t ret = OH_PixelMap_CreatePixelMap(env, info, buf, len, res);
    ASSERT_EQ(ret, IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: OH_PixelMap_CreatePixelMapTest end";
}

/**
 * @tc.name: OH_PixelMap_CreateAlphaPixelMapTest
 * @tc.desc: OH_PixelMap_CreateAlphaPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, OH_PixelMap_CreateAlphaPixelMapTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: OH_PixelMap_CreateAlphaPixelMapTest start";
    napi_env env = nullptr;
    napi_value source = nullptr;
    napi_value* alpha = nullptr;
    int32_t res = OH_PixelMap_CreateAlphaPixelMap(env, source, alpha);
    ASSERT_EQ(res, IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: OH_PixelMap_CreateAlphaPixelMapTest end";
}

/**
 * @tc.name: OH_AccessPixelsTest
 * @tc.desc: OH_AccessPixels
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, OH_AccessPixelsTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: OH_AccessPixelsTest start";
    napi_env env = nullptr;
    napi_value value = nullptr;
    void** addr = nullptr;
    int32_t res = OH_AccessPixels(env, value, addr);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: OH_AccessPixelsTest end";
}

/**
 * @tc.name: OH_UnAccessPixelsTest
 * @tc.desc: OH_UnAccessPixels
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, OH_UnAccessPixelsTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: OH_UnAccessPixelsTest start";
    napi_env env = nullptr;
    napi_value value = nullptr;
    int32_t res = OH_UnAccessPixels(env, value);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: OH_UnAccessPixelsTest end";
}

/**
 * @tc.name: OH_GetImageInfoTest
 * @tc.desc: OH_GetImageInfo
 * @tc.type: FUNC
 */
HWTEST_F(NdkTest, OH_GetImageInfoTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NdkTest: OH_GetImageInfoTest start";
    napi_env env = nullptr;
    napi_value value = nullptr;;
    OhosPixelMapInfo *info = nullptr;
    int32_t res = OH_GetImageInfo(env, value, info);
    ASSERT_EQ(res, OHOS_IMAGE_RESULT_BAD_PARAMETER);

    GTEST_LOG_(INFO) << "NdkTest: OH_GetImageInfoTest end";
}
}
}
