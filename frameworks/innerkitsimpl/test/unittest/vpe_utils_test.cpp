/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define private public

#include <gtest/gtest.h>
#include <memory>
#include "vpe_utils.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Media {
class VpeUtilsTest : public testing::Test {
public:
    VpeUtilsTest() {}
    ~VpeUtilsTest() {}
};

/**
 * @tc.name: ColorSpaceConverterCreateTest001
 * @tc.desc: test ColorSpaceConverterCreate method when handle is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceConverterCreateTest001, TestSize.Level3)
{
    auto vpeUtils = std::make_shared<VpeUtils>();
    ASSERT_NE(vpeUtils, nullptr);

    int32_t res = vpeUtils->ColorSpaceConverterCreate(nullptr, nullptr);
    EXPECT_EQ(res, VPE_ERROR_FAILED);
}

/**
 * @tc.name: ColorSpaceConverterDestoryTest001
 * @tc.desc: test ColorSpaceConverterDestory method when instanceId is VPE_ERROR_FAILED or handle is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceConverterDestoryTest001, TestSize.Level3)
{
    int32_t vpeErrFailed = -1;
    int32_t vppErrOk = 0;
    auto vpeUtils = std::make_shared<VpeUtils>();
    ASSERT_NE(vpeUtils, nullptr);
    int32_t* instanceId = &vpeErrFailed;

    int32_t res = vpeUtils->ColorSpaceConverterDestory(nullptr, instanceId);
    EXPECT_EQ(res, VPE_ERROR_FAILED);

    instanceId = &vppErrOk;
    res = vpeUtils->ColorSpaceConverterDestory(nullptr, instanceId);
    EXPECT_EQ(res, VPE_ERROR_FAILED);
}

/**
 * @tc.name: ColorSpaceConverterComposeImageTest001
 * @tc.desc: test ColorSpaceConverterComposeImage method when dlHandler is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceConverterComposeImageTest001, TestSize.Level3)
{
    VpeSurfaceBuffers bufs;
    auto vpeUtils = std::make_shared<VpeUtils>();
    ASSERT_NE(vpeUtils, nullptr);
    vpeUtils->dlHandler_ = nullptr;

    int32_t res = vpeUtils->ColorSpaceConverterComposeImage(bufs, true);
    EXPECT_EQ(res, VPE_ERROR_FAILED);

    int mockHandler = 0;
    vpeUtils->dlHandler_ = &mockHandler;
    res = vpeUtils->ColorSpaceConverterComposeImage(bufs, true);
    EXPECT_EQ(res, VPE_ERROR_FAILED);
}

/**
 * @tc.name: ColorSpaceConverterDecomposeImageTest001
 * @tc.desc: test ColorSpaceConverterDecomposeImage method when dlHandler is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceConverterDecomposeImageTest001, TestSize.Level3)
{
    VpeSurfaceBuffers bufs;
    auto vpeUtils = std::make_shared<VpeUtils>();
    ASSERT_NE(vpeUtils, nullptr);
    vpeUtils->dlHandler_ = nullptr;

    int32_t res = vpeUtils->ColorSpaceConverterDecomposeImage(bufs);
    EXPECT_EQ(res, VPE_ERROR_FAILED);

    int mockHandler = 0;
    vpeUtils->dlHandler_ = &mockHandler;
    res = vpeUtils->ColorSpaceConverterDecomposeImage(bufs);
    EXPECT_EQ(res, VPE_ERROR_FAILED);
}

/**
 * @tc.name: DetailEnhancerCreateTest001
 * @tc.desc: test DetailEnhancerCreate method when handle is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, DetailEnhancerCreateTest001, TestSize.Level3)
{
    int32_t vpeErrFailed = -1;
    auto vpeUtils = std::make_shared<VpeUtils>();
    ASSERT_NE(vpeUtils, nullptr);

    uint32_t res = vpeUtils->DetailEnhancerCreate(nullptr, &vpeErrFailed);
    EXPECT_EQ(res, VPE_ERROR_FAILED);
}

/**
 * @tc.name: DetailEnhancerDestoryTest001
 * @tc.desc: test DetailEnhancerDestory method when handle is instanceId is VPE_ERROR_FAILED or nullptr
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, DetailEnhancerDestoryTest001, TestSize.Level3)
{
    int32_t vpeErrFailed = -1;
    int32_t vppErrOk = 0;
    auto vpeUtils = std::make_shared<VpeUtils>();
    ASSERT_NE(vpeUtils, nullptr);

    uint32_t res = vpeUtils->DetailEnhancerCreate(nullptr, &vpeErrFailed);
    EXPECT_EQ(res, VPE_ERROR_FAILED);

    res = vpeUtils->DetailEnhancerCreate(nullptr, &vppErrOk);
    EXPECT_EQ(res, VPE_ERROR_FAILED);
}
}
}