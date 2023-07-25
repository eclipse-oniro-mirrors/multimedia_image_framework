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

    GTEST_LOG_(INFO) << "NapiTest: NapiTest0014 end";
}
/**
 * @tc.name: NapiTest0015
 * @tc.desc: OH_PixelMap_SetOpacity
 * @tc.type: FUNC
 */
HWTEST_F(NapiTest, NapiTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NapiTest: NapiTest0015 start";
    ImageSourceNapi napi;
    ImageResource resource = napi.GetImageResource();
    ASSERT_EQ(resource.buffer, nullptr);

    GTEST_LOG_(INFO) << "NapiTest: NapiTest0015 end";
}
}
}

