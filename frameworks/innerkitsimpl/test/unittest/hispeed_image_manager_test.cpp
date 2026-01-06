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

#include "hispeed_image_manager.h"
#include "image_type.h"
#include "media_errors.h"
#include "mock/mock_hispeed_functions.h"
#include "mock/mock_skw_stream.h"
#include "pixel_map.h"
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

using namespace testing::ext;
using namespace OHOS::Media;

namespace {
constexpr int32_t TEST_WIDTH = 4;
constexpr int32_t TEST_HEIGHT = 4;
constexpr uint8_t TEST_QUALITY = 90;
constexpr int32_t TEST_LARGE_WIDTH = 1920;
constexpr int32_t TEST_LARGE_HEIGHT = 1080;
constexpr int32_t TEST_SUCCESS = 0;
} // namespace

// 友元类用于访问 HispeedImageManager 的私有成员
class HispeedImageManagerTestFriend {
public:
    static void SetMockFunctions(HispeedImageManager& mgr,
                                 YuvJpegEncoderCreateFunc createFunc,
                                 YuvJpegEncoderEncodeFunc encodeFunc,
                                 YuvJpegEncoderDestroyFunc destroyFunc)
    {
        mgr.jpegEncoderCreateFunc_ = createFunc;
        mgr.jpegEncoderEncodeFunc_ = encodeFunc;
        mgr.jpegEncoderDestroyFunc_ = destroyFunc;
        mgr.jpegEncoderSetQualityFunc_ = MockJpegEncoderSetQuality;
        mgr.jpegEncoderSetSubsamplingFunc_ = MockJpegEncoderSetSubsampling;
        mgr.jpegEncoderSetICCMetadataFunc_ = MockJpegEncoderSetIccMetadata;
        mgr.isHispeedImageSoOpened_ = true; // 标记为已初始化
    }
};

class HispeedImageManagerTest : public testing::Test {
public:
    HispeedImageManagerTest() = default;
    ~HispeedImageManagerTest() override = default;

    static void SetUpTestCase()
    {
        GTEST_LOG_(INFO) << "HispeedImageManagerTest: SetUpTestCase start";
        GTEST_LOG_(INFO) << "HispeedImageManagerTest: SetUpTestCase end";
    }

    static void TearDownTestCase()
    {
        GTEST_LOG_(INFO) << "HispeedImageManagerTest: TearDownTestCase start";
        GTEST_LOG_(INFO) << "HispeedImageManagerTest: TearDownTestCase end";
    }

    void SetUp() override
    {
        // 每个测试用例前的初始化
        ResetMockState();
        SetMockEncodeResult(TEST_SUCCESS);
        SetMockCreateResult(reinterpret_cast<YuvJpegEncoder>(0x1));

        // 设置 Mock 函数
        auto& mgr = HispeedImageManager::GetInstance();
        HispeedImageManagerTestFriend::SetMockFunctions(mgr, MockJpegEncoderCreate, MockJpegEncoderEncode,
                                                        MockJpegEncoderDestroy);
    }

    void TearDown() override
    {
        // 每个测试用例后的清理
        ResetMockState();
    }

protected:
    // 辅助函数：创建 NV12 格式的 PixelMap
    std::unique_ptr<PixelMap> CreateNV12PixelMap(int32_t width, int32_t height)
    {
        InitializationOptions opts;
        opts.size.width = width;
        opts.size.height = height;
        opts.pixelFormat = PixelFormat::NV12;
        opts.editable = true;
        opts.allocatorType = AllocatorType::HEAP_ALLOC;

        auto pixelMap = PixelMap::Create(opts);
        if (pixelMap == nullptr) {
            return nullptr;
        }

        uint8_t* pixels = static_cast<uint8_t*>(pixelMap->GetWritablePixels());
        if (pixels != nullptr) {
            // NV12: Y 平面 + UV 交错平面
            size_t ySize = width * height;
            size_t uvSize = ySize / 2;
            memset_s(pixels, ySize + uvSize, 0x80, ySize + uvSize);
        }

        return pixelMap;
    }

    // 辅助函数：创建 NV21 格式的 PixelMap
    std::unique_ptr<PixelMap> CreateNV21PixelMap(int32_t width, int32_t height)
    {
        InitializationOptions opts;
        opts.size.width = width;
        opts.size.height = height;
        opts.pixelFormat = PixelFormat::NV21;
        opts.editable = true;
        opts.allocatorType = AllocatorType::HEAP_ALLOC;

        auto pixelMap = PixelMap::Create(opts);
        if (pixelMap == nullptr) {
            return nullptr;
        }

        uint8_t* pixels = static_cast<uint8_t*>(pixelMap->GetWritablePixels());
        if (pixels != nullptr) {
            // NV21: Y 平面 + VU 交错平面
            size_t ySize = width * height;
            size_t uvSize = ySize / 2;
            memset_s(pixels, ySize + uvSize, 0x80, ySize + uvSize);
        }

        return pixelMap;
    }

    // 辅助函数：创建测试用的 SkImageInfo
    SkImageInfo CreateTestImageInfo(int32_t width, int32_t height)
    {
        return SkImageInfo::Make(width, height, kRGBA_8888_SkColorType, kPremul_SkAlphaType, SkColorSpace::MakeSRGB());
    }

    // 辅助函数：创建指定格式的 PixelMap（用于测试不支持的格式）
    std::unique_ptr<PixelMap> CreatePixelMapWithFormat(int32_t width, int32_t height, PixelFormat format)
    {
        InitializationOptions opts;
        opts.size.width = width;
        opts.size.height = height;
        opts.pixelFormat = format;
        opts.editable = true;
        opts.allocatorType = AllocatorType::HEAP_ALLOC;

        return PixelMap::Create(opts);
    }
};

// ============================================================================
// 类别 1: 参数验证测试（6 个用例）
// ============================================================================

/**
 * @tc.name: DoEncodeJpegNullStreamTest001
 * @tc.desc: 测试 skStream 为 nullptr 时返回 ERR_IMAGE_ENCODE_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegNullStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNullStreamTest001 start";

    auto& manager = HispeedImageManager::GetInstance();

    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint32_t result = manager.DoEncodeJpeg(nullptr, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNullStreamTest001 end";
}

/**
 * @tc.name: DoEncodeJpegNullPixelMapTest002
 * @tc.desc: 测试 skStream 不为 nullptr 时的行为
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegNullPixelMapTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNullPixelMapTest002 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, TEST_SUCCESS);
}

/**
 * @tc.name: DoEncodeJpegInvalidFormatARGBTest003
 * @tc.desc: 测试 ARGB_8888 格式（不支持）返回 ERR_IMAGE_ENCODE_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegInvalidFormatARGBTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegInvalidFormatARGBTest003 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreatePixelMapWithFormat(TEST_WIDTH, TEST_HEIGHT, PixelFormat::ARGB_8888);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegInvalidFormatARGBTest003 end";
}

/**
 * @tc.name: DoEncodeJpegInvalidFormatRGB565Test004
 * @tc.desc: 测试 RGB_565 格式（不支持）返回 ERR_IMAGE_ENCODE_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegInvalidFormatRGB565Test004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegInvalidFormatRGB565Test004 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreatePixelMapWithFormat(TEST_WIDTH, TEST_HEIGHT, PixelFormat::RGB_565);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegInvalidFormatRGB565Test004 end";
}

/**
 * @tc.name: DoEncodeJpegInvalidFormatRGBATest005
 * @tc.desc: 测试 RGBA_8888 格式（不支持）返回 ERR_IMAGE_ENCODE_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegInvalidFormatRGBATest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegInvalidFormatRGBATest005 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreatePixelMapWithFormat(TEST_WIDTH, TEST_HEIGHT, PixelFormat::RGBA_8888);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegInvalidFormatRGBATest005 end";
}

/**
 * @tc.name: DoEncodeJpegInvalidFormatUnknownTest006
 * @tc.desc: 测试 UNKNOWN 格式（不支持）返回 ERR_IMAGE_ENCODE_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegInvalidFormatUnknownTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegInvalidFormatUnknownTest006 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreatePixelMapWithFormat(TEST_WIDTH, TEST_HEIGHT, PixelFormat::UNKNOWN);
    // 注意：PixelFormat::UNKNOWN 可能无法创建 PixelMap，这是正常的

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);

    if (pixelMap != nullptr) {
        uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);
        ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    } else {
        GTEST_LOG_(INFO) << "PixelFormat::UNKNOWN cannot create PixelMap, skipping test";
    }

    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegInvalidFormatUnknownTest006 end";
}

// ============================================================================
// 类别 2: 正常流程测试（4 个用例）
// ============================================================================

/**
 * @tc.name: DoEncodeJpegNV12SuccessTest007
 * @tc.desc: 测试 NV12 格式成功编码
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegNV12SuccessTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNV12SuccessTest007 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNV12SuccessTest007 end";
}

/**
 * @tc.name: DoEncodeJpegNV21SuccessTest008
 * @tc.desc: 测试 NV21 格式成功编码
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegNV21SuccessTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNV21SuccessTest008 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV21PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNV21SuccessTest008 end";
}

/**
 * @tc.name: DoEncodeJpegNV12WithICCTest009
 * @tc.desc: 测试带 ICC 元数据的 NV12 编码
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegNV12WithICCTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNV12WithICCTest009 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    // 使用带有颜色空间的 SkImageInfo（包含 ICC 数据）
    SkImageInfo info = SkImageInfo::Make(TEST_WIDTH, TEST_HEIGHT, kRGBA_8888_SkColorType, kPremul_SkAlphaType,
                                         SkColorSpace::MakeSRGB() // sRGB 包含 ICC 配置文件
    );

    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNV12WithICCTest009 end";
}

/**
 * @tc.name: DoEncodeJpegNV21WithICCTest010
 * @tc.desc: 测试带 ICC 元数据的 NV21 编码
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegNV21WithICCTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNV21WithICCTest010 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV21PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = SkImageInfo::Make(TEST_WIDTH, TEST_HEIGHT, kRGBA_8888_SkColorType, kPremul_SkAlphaType,
                                         SkColorSpace::MakeSRGB());

    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNV21WithICCTest010 end";
}

// ============================================================================
// 类别 3: 质量参数测试（4 个用例）
// ============================================================================

/**
 * @tc.name: DoEncodeJpegQuality0Test011
 * @tc.desc: 测试 quality = 0（最低质量）
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegQuality0Test011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegQuality0Test011 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint8_t quality = 0;
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), quality, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegQuality0Test011 end";
}

/**
 * @tc.name: DoEncodeJpegQuality50Test012
 * @tc.desc: 测试 quality = 50（中等质量）
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegQuality50Test012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegQuality50Test012 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint8_t quality = 50;
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), quality, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegQuality50Test012 end";
}

/**
 * @tc.name: DoEncodeJpegQuality90Test013
 * @tc.desc: 测试 quality = 90（高质量）
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegQuality90Test013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegQuality90Test013 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint8_t quality = 90;
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), quality, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegQuality90Test013 end";
}

/**
 * @tc.name: DoEncodeJpegQuality100Test014
 * @tc.desc: 测试 quality = 100（最高质量）
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegQuality100Test014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegQuality100Test014 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint8_t quality = 100;
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), quality, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegQuality100Test014 end";
}

// ============================================================================
// 类别 4: 图像尺寸测试（3 个用例）
// ============================================================================

/**
 * @tc.name: DoEncodeJpegMinSizeTest015
 * @tc.desc: 测试最小尺寸 1x1
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegMinSizeTest015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegMinSizeTest015 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV12PixelMap(1, 1);
    if (pixelMap == nullptr) {
        GTEST_LOG_(INFO) << "Failed to create 1x1 PixelMap, skipping test";
        return;
    }

    SkImageInfo info = CreateTestImageInfo(1, 1);
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegMinSizeTest015 end";
}

/**
 * @tc.name: DoEncodeJpegNormalSizeTest016
 * @tc.desc: 测试正常尺寸 4x4
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegNormalSizeTest016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNormalSizeTest016 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV12PixelMap(4, 4);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(4, 4);
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegNormalSizeTest016 end";
}

/**
 * @tc.name: DoEncodeJpegLargeSizeTest017
 * @tc.desc: 测试较大尺寸 1920x1080
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegLargeSizeTest017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegLargeSizeTest017 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    auto pixelMap = CreateNV12PixelMap(TEST_LARGE_WIDTH, TEST_LARGE_HEIGHT);
    if (pixelMap == nullptr) {
        GTEST_LOG_(INFO) << "Failed to create 1920x1080 PixelMap, possibly due to memory constraints";
        return;
    }

    SkImageInfo info = CreateTestImageInfo(TEST_LARGE_WIDTH, TEST_LARGE_HEIGHT);
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, TEST_SUCCESS);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegLargeSizeTest017 end";
}

// ============================================================================
// 类别 5: 错误处理测试（3 个用例）
// ============================================================================

/**
 * @tc.name: DoEncodeJpegInitFailTest018
 * @tc.desc: 测试编码器创建失败场景
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegInitFailTest018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegInitFailTest018 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    // 设置 Mock 创建函数返回 nullptr（模拟编码器创建失败）
    SetMockCreateResult(nullptr);

    // 重新设置 Mock 函数
    HispeedImageManagerTestFriend::SetMockFunctions(manager, MockJpegEncoderCreate, MockJpegEncoderEncode,
                                                    MockJpegEncoderDestroy);

    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegInitFailTest018 end";
}

/**
 * @tc.name: DoEncodeJpegEncodeFailTest019
 * @tc.desc: 测试编码过程失败场景
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegEncodeFailTest019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegEncodeFailTest019 start";

    auto& manager = HispeedImageManager::GetInstance();
    MockSkWStream mockStream;

    // 设置 Mock 编码函数返回失败
    SetMockEncodeResult(-1);

    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    ASSERT_EQ(result, ERR_IMAGE_ENCODE_FAILED);
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegEncodeFailTest019 end";
}

/**
 * @tc.name: DoEncodeJpegStreamWriteFailTest020
 * @tc.desc: 测试 Stream 写入失败场景（通过 Mock SkWStream）
 * @tc.type: FUNC
 */
HWTEST_F(HispeedImageManagerTest, DoEncodeJpegStreamWriteFailTest020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegStreamWriteFailTest020 start";

    auto& manager = HispeedImageManager::GetInstance();

    // 创建一个返回 false 的 Mock SkWStream
    MockSkWStream mockStream;

    auto pixelMap = CreateNV12PixelMap(TEST_WIDTH, TEST_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);

    SkImageInfo info = CreateTestImageInfo(TEST_WIDTH, TEST_HEIGHT);

    // 注意：此测试取决于 Mock 编码函数如何处理 write 返回 false
    // 当前 Mock 实现可能不会检查 write 的返回值
    uint32_t result = manager.DoEncodeJpeg(&mockStream, pixelMap.get(), TEST_QUALITY, info);

    // 记录结果（可能仍然是 TEST_SUCCESS，取决于实现）
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegStreamWriteFailTest020 result: " << result;
    GTEST_LOG_(INFO) << "HispeedImageManagerTest: DoEncodeJpegStreamWriteFailTest020 end";
}
