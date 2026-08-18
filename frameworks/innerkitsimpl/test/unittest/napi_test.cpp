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
#include <limits>
#include "image_pixel_map_napi_kits.h"
#include "image_napi_utils.h"
#include "pixel_map_napi.h"
#include "image_packer_napi.h"
#include "image_source_napi.h"

using namespace testing::ext;
namespace OHOS {
namespace Media {
class NapiTest : public testing::Test {
public:
    NapiTest() {}
    ~NapiTest() {}
};

class AntiAliasingOptionRecordingPixelMap : public PixelMap {
public:
    void scale(float, float, const AntiAliasingOption &option) override
    {
        lastOption_ = option;
    }

    AntiAliasingOption lastOption_ = AntiAliasingOption::HIGH;
};

/**
 * @tc.name: PixelMapNapiScaleWithAntiAliasingOutOfRangeUsesNone
 * @tc.desc: Use NONE when NAPI receives a public anti-aliasing level that is out of range.
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, PixelMapNapiScaleWithAntiAliasingOutOfRangeUsesNone, TestSize.Level3)
{
    PixelMapNapi pixelMapNapi;
    auto recordingPixelMap = std::make_shared<AntiAliasingOptionRecordingPixelMap>();
    *(pixelMapNapi.GetPixelMap()) = recordingPixelMap;

    PixelMapNapiArgs args = {};
    args.inFloat0 = 0.5f;
    args.inFloat1 = 0.5f;
    args.inNum0 = -1;
    ASSERT_EQ(PixelMapNapiNativeCtxCall(CTX_FUNC_SCALE, &pixelMapNapi, &args), IMAGE_RESULT_SUCCESS);
    EXPECT_EQ(recordingPixelMap->lastOption_, AntiAliasingOption::NONE);

    recordingPixelMap->lastOption_ = AntiAliasingOption::HIGH;
    args.inNum0 = static_cast<int32_t>(AntiAliasingOption::HIGH) + 1;
    ASSERT_EQ(PixelMapNapiNativeCtxCall(CTX_FUNC_SCALE, &pixelMapNapi, &args), IMAGE_RESULT_SUCCESS);
    EXPECT_EQ(recordingPixelMap->lastOption_, AntiAliasingOption::NONE);

    args.inNum0 = static_cast<int32_t>(AntiAliasingOption::HIGH);
    ASSERT_EQ(PixelMapNapiNativeCtxCall(CTX_FUNC_SCALE, &pixelMapNapi, &args), IMAGE_RESULT_SUCCESS);
    EXPECT_EQ(recordingPixelMap->lastOption_, AntiAliasingOption::HIGH);
}

/**
 * @tc.name: ImageNapiUtilsConvertDoubleToInt32RejectsInvalidValues
 * @tc.desc: Reject non-finite and out-of-range values before converting them to int32.
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, ImageNapiUtilsConvertDoubleToInt32RejectsInvalidValues, TestSize.Level3)
{
    int32_t result = 0;
    constexpr double int32Max = static_cast<double>(std::numeric_limits<int32_t>::max());
    constexpr double int32Min = static_cast<double>(std::numeric_limits<int32_t>::min());

    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToInt32(int32Max + 1.0, &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToInt32(int32Min - 1.0, &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToInt32(4294967297.0, &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToInt32(std::numeric_limits<double>::infinity(), &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToInt32(-std::numeric_limits<double>::infinity(), &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToInt32(std::numeric_limits<double>::quiet_NaN(), &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToInt32(0.0, nullptr));
}

/**
 * @tc.name: ImageNapiUtilsConvertDoubleToInt32PreservesCompatibleValues
 * @tc.desc: Accept int32 boundaries and preserve truncation for finite fractional values in range.
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, ImageNapiUtilsConvertDoubleToInt32PreservesCompatibleValues, TestSize.Level3)
{
    int32_t result = 0;

    ASSERT_TRUE(ImageNapiUtils::ConvertDoubleToInt32(
        static_cast<double>(std::numeric_limits<int32_t>::max()), &result));
    EXPECT_EQ(result, std::numeric_limits<int32_t>::max());

    ASSERT_TRUE(ImageNapiUtils::ConvertDoubleToInt32(
        static_cast<double>(std::numeric_limits<int32_t>::min()), &result));
    EXPECT_EQ(result, std::numeric_limits<int32_t>::min());

    ASSERT_TRUE(ImageNapiUtils::ConvertDoubleToInt32(1.75, &result));
    EXPECT_EQ(result, 1);

    ASSERT_TRUE(ImageNapiUtils::ConvertDoubleToInt32(-1.75, &result));
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: ImageNapiUtilsConvertDoubleToFloatRejectsInvalidValues
 * @tc.desc: Reject non-finite and out-of-float-range values before converting them to float.
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, ImageNapiUtilsConvertDoubleToFloatRejectsInvalidValues, TestSize.Level3)
{
    float result = 0.0f;
    constexpr double floatMax = static_cast<double>(std::numeric_limits<float>::max());

    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToFloat(floatMax * 2.0, &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToFloat(-floatMax * 2.0, &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToFloat(std::numeric_limits<double>::infinity(), &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToFloat(-std::numeric_limits<double>::infinity(), &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToFloat(std::numeric_limits<double>::quiet_NaN(), &result));
    EXPECT_FALSE(ImageNapiUtils::ConvertDoubleToFloat(0.0, nullptr));
}

/**
 * @tc.name: ImageNapiUtilsConvertDoubleToFloatPreservesCompatibleValues
 * @tc.desc: Accept finite values within the float range.
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, ImageNapiUtilsConvertDoubleToFloatPreservesCompatibleValues, TestSize.Level3)
{
    float result = 0.0f;

    ASSERT_TRUE(ImageNapiUtils::ConvertDoubleToFloat(1.25, &result));
    EXPECT_FLOAT_EQ(result, 1.25f);

    ASSERT_TRUE(ImageNapiUtils::ConvertDoubleToFloat(
        static_cast<double>(std::numeric_limits<float>::max()), &result));
    EXPECT_EQ(result, std::numeric_limits<float>::max());
}

/**
 * @tc.name: NapiTest001
 * @tc.desc: IsLockPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest001 start";
    PixelMapNapi napi;
    bool res = napi.IsLockPixelMap();
    ASSERT_EQ(res, false);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest001 end";
}

/**
 * @tc.name: NapiTest002
 * @tc.desc: LockPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest002 start";
    PixelMapNapi napi;
    bool res = napi.LockPixelMap();
    ASSERT_EQ(res, true);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest002 end";
}

/**
 * @tc.name: NapiTest003
 * @tc.desc: UnlockPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest003 start";
    PixelMapNapi napi;
    napi.UnlockPixelMap();
    bool res = napi.LockPixelMap();
    ASSERT_EQ(res, true);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest003 end";
}

/**
 * @tc.name: NapiTest004
 * @tc.desc: GetPixelMap(env, pixelmap)
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest004 start";
    PixelMapNapi napi;
    napi_env env = nullptr;
    napi_value pixelmap = nullptr;
    std::shared_ptr<PixelMap> res = napi.GetPixelMap(env, pixelmap);
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest004 end";
}

/**
 * @tc.name: NapiTest005
 * @tc.desc: GetPixelMap()
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest005 start";
    PixelMapNapi napi;
    std::shared_ptr<PixelMap>* res = napi.GetPixelMap();
    ASSERT_NE(res, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest005 end";
}

/**
 * @tc.name: NapiTest006
 * @tc.desc: OH_PixelMap_SetDensity
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest006 start";
    PixelMapNapi napi;
    napi_env env = nullptr;
    napi_value exports = nullptr;
    napi_value res = napi.Init(env, exports);
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest006 end";
}

/**
 * @tc.name: NapiTest007
 * @tc.desc: OH_PixelMap_SetOpacity
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest007 start";
    PixelMapNapi napi;
    napi_env env = nullptr;
    std::shared_ptr<PixelMap> pixelmap = nullptr;
    napi_value res = napi.CreatePixelMap(env, pixelmap);
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest007 end";
}

/**
 * @tc.name: NapiTest008
 * @tc.desc: Init
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest008 start";
    ImagePackerNapi napi;
    napi_env env = nullptr;
    napi_value exports = nullptr;
    napi_value res = napi.Init(env, exports);
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest008 end";
}

/**
 * @tc.name: NapiTest009
 * @tc.desc: CreateImagePacker
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest009 start";
    ImagePackerNapi napi;
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    napi_value res = napi.CreateImagePacker(env, info);
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest009 end";
}

/**
 * @tc.name: NapiTest0010
 * @tc.desc: OH_PixelMap_SetOpacity
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest0010 start";
    ImageSourceNapi napi;
    napi_env env = nullptr;
    napi_value exports = nullptr;
    napi_value res = napi.Init(env, exports);
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest0010 end";
}

/**
 * @tc.name: NapiTest0011
 * @tc.desc: OH_PixelMap_SetOpacity
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest0011 start";
    ImageSourceNapi napi;
    std::shared_ptr<IncrementalPixelMap> res = napi.GetIncrementalPixelMap();
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest0011 end";
}

/**
 * @tc.name: NapiTest0012
 * @tc.desc: SetIncrementalPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest0012 start";
    ImageSourceNapi napi;
    std::shared_ptr<IncrementalPixelMap> incrementalPixelMap = nullptr;
    napi.SetIncrementalPixelMap(incrementalPixelMap);
    std::shared_ptr<IncrementalPixelMap> ret = napi.GetIncrementalPixelMap();
    ASSERT_EQ(ret, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest0012 end";
}

/**
 * @tc.name: NapiTest0013
 * @tc.desc: GetIncrementalPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest0013 start";
    ImageSourceNapi napi;
    std::shared_ptr<ImageSource> imageSource = nullptr;
    napi.SetNativeImageSource(imageSource);
    ASSERT_EQ(napi.nativeImgSrc, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest0013 end";
}

/**
 * @tc.name: NapiTest0014
 * @tc.desc: OH_PixelMap_SetOpacity
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest0014 start";
    ImageSourceNapi napi;
    ImageResource resource;
    napi.SetImageResource(resource);
    ImageResource ret = napi.GetImageResource();
    ASSERT_EQ(ret.buffer, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest0014 end";
}

/**
 * @tc.name: NapiTest0016
 * @tc.desc: The same MessageSequence native object uses the same unmarshalling mutex.
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest0016 start";
    int32_t messageSequence = 0;
    std::mutex& firstMutex = ImageNapiUtils::GetMessageSequenceMutex(&messageSequence);
    std::mutex& secondMutex = ImageNapiUtils::GetMessageSequenceMutex(&messageSequence);

    EXPECT_EQ(&firstMutex, &secondMutex);
    GTEST_LOG_(INFO) << "NapiTest: NapiTest0016 end";
}
}
}
