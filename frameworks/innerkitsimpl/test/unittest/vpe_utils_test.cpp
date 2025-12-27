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
#include "surface_buffer.h"
#include "sync_fence.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Media {
class VpeUtilsTest : public testing::Test {
public:
    VpeUtilsTest() {}
    ~VpeUtilsTest() {}
};

class MockSurfaceBuffer : public SurfaceBuffer {
public:
    MockSurfaceBuffer() = default;
    ~MockSurfaceBuffer() = default;

    bool shouldSetMetadataFail = false;
    bool shouldGetMetadataFail = false;

    GSError GetPlanesInfo(void** planes) override
    {
        if (planes != nullptr) {
            static OH_NativeBuffer_Planes mockPlanes;
            mockPlanes.planeCount = 1;
            *planes = &mockPlanes;
            return GSERROR_OK;
        }
        return GSERROR_INVALID_ARGUMENTS;
    }

    GSError SetMetadata(uint32_t key, const std::vector<uint8_t>& value, bool enableCache = true) override
    {
        if (shouldSetMetadataFail) {
            return GSERROR_API_FAILED;
        }
        return GSERROR_OK;
    }

    GSError GetMetadata(uint32_t key, std::vector<uint8_t>& value) override
    {
        if (shouldGetMetadataFail) {
            return GSERROR_API_FAILED;
        }
        return GSERROR_OK;
    }

    int32_t GetWidth() const override { return 1280; }
    int32_t GetHeight() const override { return 720; }
    int32_t GetFormat() const override { return GRAPHIC_PIXEL_FMT_RGBA_8888; }

    BufferHandle *GetBufferHandle() const override { return nullptr; }
    int32_t GetStride() const override { return 1280 * 4; }
    uint64_t GetUsage() const override { return 0; }
    uint64_t GetPhyAddr() const override { return 0; }
    void* GetVirAddr() override { return nullptr; }
    int32_t GetFileDescriptor() const override { return -1; }
    uint32_t GetSize() const override { return 1280 * 720 * 4; }
    GraphicColorGamut GetSurfaceBufferColorGamut() const override { return GRAPHIC_COLOR_GAMUT_SRGB; }
    GraphicTransformType GetSurfaceBufferTransform() const override { return GRAPHIC_ROTATE_NONE; }
    void SetSurfaceBufferColorGamut(const GraphicColorGamut& colorGamut) override {}
    void SetSurfaceBufferTransform(const GraphicTransformType& transform) override {}
    int32_t GetSurfaceBufferWidth() const override { return 1280; }
    int32_t GetSurfaceBufferHeight() const override { return 720; }
    void SetSurfaceBufferWidth(int32_t width) override {}
    void SetSurfaceBufferHeight(int32_t height) override {}
    uint32_t GetSeqNum() const override { return 0; }
    void SetExtraData(sptr<BufferExtraData> bedata) override {}
    sptr<BufferExtraData> GetExtraData() const override { return nullptr; }
    GSError WriteToMessageParcel(MessageParcel &parcel) override { return GSERROR_NOT_SUPPORT; }
    GSError ReadFromMessageParcel(MessageParcel &parcel, std::function<int(MessageParcel &parcel,
        std::function<int(Parcel &)>readFdDefaultFunc)> readSafeFdFunc = nullptr) override {return GSERROR_NOT_SUPPORT;}
    void SetBufferHandle(BufferHandle *handle) override {}
    GSError Alloc(const BufferRequestConfig &config, const sptr<SurfaceBuffer>& previousBuffer = nullptr) override
        { return GSERROR_NOT_SUPPORT; }
    GSError Map() override { return GSERROR_OK; }
    GSError Unmap() override { return GSERROR_OK; }
    GSError FlushCache() override { return GSERROR_OK; }
    GSError InvalidateCache() override { return GSERROR_OK; }
    GSError ListMetadataKeys(std::vector<uint32_t>& keys) override { return GSERROR_NOT_SUPPORT; }
    GSError EraseMetadataKey(uint32_t key) override { return GSERROR_NOT_SUPPORT; }
    OH_NativeBuffer* SurfaceBufferToNativeBuffer() override { return nullptr; }
    void SetAndMergeSyncFence(const sptr<OHOS::SyncFence>& syncFence) override {}
    sptr<OHOS::SyncFence> GetSyncFence() const override { return nullptr; }
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
    vpeUtils->dlHandler_->handle_ = nullptr;

    int32_t res = vpeUtils->ColorSpaceConverterComposeImage(bufs, true);
    EXPECT_EQ(res, VPE_ERROR_FAILED);

    int mockHandler = 0;
    vpeUtils->dlHandler_->handle_ = &mockHandler;
    res = vpeUtils->ColorSpaceConverterComposeImage(bufs, true);
    EXPECT_EQ(res, VPE_ERROR_FAILED);
}

/**
 * @tc.name: ColorSpaceConverterComposeImageTest002
 * @tc.desc: test ColorSpaceConverterComposeImage method when sb.sdr or sb.gainmap or sb.hdr is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceConverterComposeImageTest002, TestSize.Level3)
{
    auto vpeUtils = std::make_shared<VpeUtils>();
    ASSERT_NE(vpeUtils, nullptr);

    VpeSurfaceBuffers bufsSdr;
    bufsSdr.sdr = nullptr;
    bufsSdr.gainmap = new MockSurfaceBuffer();
    bufsSdr.hdr = new MockSurfaceBuffer();
    int32_t res = vpeUtils->ColorSpaceConverterComposeImage(bufsSdr, true);
    EXPECT_EQ(res, VPE_ERROR_FAILED);

    VpeSurfaceBuffers bufsGainmap;
    bufsGainmap.sdr = new MockSurfaceBuffer();
    bufsGainmap.gainmap = nullptr;
    bufsGainmap.hdr = new MockSurfaceBuffer();
    res = vpeUtils->ColorSpaceConverterComposeImage(bufsGainmap, true);
    EXPECT_EQ(res, VPE_ERROR_FAILED);

    VpeSurfaceBuffers bufsHdr;
    bufsHdr.sdr = new MockSurfaceBuffer();
    bufsHdr.gainmap = new MockSurfaceBuffer();
    bufsHdr.hdr = nullptr;
    res = vpeUtils->ColorSpaceConverterComposeImage(bufsHdr, true);
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
    vpeUtils->dlHandler_->handle_ = nullptr;

    int32_t res = vpeUtils->ColorSpaceConverterDecomposeImage(bufs);
    EXPECT_EQ(res, VPE_ERROR_FAILED);

    int mockHandler = 0;
    vpeUtils->dlHandler_->handle_ = &mockHandler;
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

/**
 * @tc.name: ColorSpaceConverterImageProcessTest001
 * @tc.desc: Verify that VpeUtils call ColorSpaceConverterImageProcess when dlHandler_->handle_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceConverterImageProcessTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceConverterImageProcessTest001 start";
    VpeUtils mockVpeUtils;
    ASSERT_NE(mockVpeUtils.dlHandler_->handle_, nullptr);
    void* storeP = mockVpeUtils.dlHandler_->handle_;
    mockVpeUtils.dlHandler_->handle_ = nullptr;
    sptr<SurfaceBuffer> src = SurfaceBuffer::Create();
    sptr<SurfaceBuffer> des = SurfaceBuffer::Create();
    auto ret = mockVpeUtils.ColorSpaceConverterImageProcess(src, des);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    mockVpeUtils.dlHandler_->handle_ = storeP;
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceConverterImageProcessTest001 end";
}

/**
 * @tc.name: ColorSpaceConverterImageProcessTest002
 * @tc.desc: Verify that VpeUtils call ColorSpaceConverterImageProcess when instanceId or res is fail.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceConverterImageProcessTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceConverterImageProcessTest002 start";
    VpeUtils mockVpeUtils;
    ASSERT_NE(mockVpeUtils.dlHandler_->handle_, nullptr);
    sptr<SurfaceBuffer> src = SurfaceBuffer::Create();
    sptr<SurfaceBuffer> des = SurfaceBuffer::Create();
    int mockHandler = 0;
    mockVpeUtils.dlHandler_->handle_ = &mockHandler;
    auto ret = mockVpeUtils.ColorSpaceConverterImageProcess(src, des);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceConverterImageProcessTest002 end";
}

/**
 * @tc.name: ColorSpaceConverterImageProcessTest003
 * @tc.desc: Verify that VpeUtils call ColorSpaceConverterImageProcess when input or output is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceConverterImageProcessTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceConverterImageProcessTest003 start";
    VpeUtils mockVpeUtils;
    ASSERT_NE(mockVpeUtils.dlHandler_->handle_, nullptr);
    sptr<SurfaceBuffer> src = SurfaceBuffer::Create();
    sptr<SurfaceBuffer> des = SurfaceBuffer::Create();
    sptr<SurfaceBuffer> nullInput = nullptr;
    sptr<SurfaceBuffer> nullOutput = nullptr;
    auto ret = mockVpeUtils.ColorSpaceConverterImageProcess(src, nullOutput);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);

    ret = mockVpeUtils.ColorSpaceConverterImageProcess(nullInput, nullOutput);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);

    ret = mockVpeUtils.ColorSpaceConverterImageProcess(nullInput, des);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceConverterImageProcessTest003 end";
}

/**
 * @tc.name: SetSbColorSpaceTypeTest001
 * @tc.desc: Verify that VpeUtils call SetSbColorSpaceType when buffer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, SetSbColorSpaceTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: SetSbColorSpaceTypeTest001 start";
    VpeUtils mockVpeUtils;
    sptr<SurfaceBuffer> mockBuffer;
    auto ret = mockVpeUtils.SetSbColorSpaceType(mockBuffer, HDI::Display::Graphic::Common::V1_0::CM_SRGB_FULL);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "VpeUtilsTest: SetSbColorSpaceTypeTest001 end";
}

/**
 * @tc.name: SetSbMetadataTypeTest001
 * @tc.desc: Verify that VpeUtils call SetSbMetadataType when buffer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, SetSbMetadataTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: SetSbMetadataTypeTest001 start";
    VpeUtils mockVpeUtils;
    sptr<SurfaceBuffer> mockBuffer;
    auto ret = mockVpeUtils.SetSbMetadataType(mockBuffer,
        HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type::CM_METADATA_NONE);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "VpeUtilsTest: SetSbMetadataTypeTest001 end";
}

/**
 * @tc.name: DetailEnhancerDestoryTest002
 * @tc.desc: Verify that VpeUtils call DetailEnhancerDestory when condition is not correct.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, DetailEnhancerDestoryTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: DetailEnhancerDestoryTest002 start";
    VpeUtils mockVpeUtils;
    sptr<SurfaceBuffer> mockBuffer;
    int32_t mockInstanceId{VPE_ERROR_FAILED};
    auto ret = mockVpeUtils.DetailEnhancerDestory(nullptr, &mockInstanceId);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    mockInstanceId = 0;
    ret = mockVpeUtils.DetailEnhancerDestory(nullptr, &mockInstanceId);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    GTEST_LOG_(INFO) << "VpeUtilsTest: DetailEnhancerDestoryTest002 end";
}

/**
 * @tc.name: DetailEnhancerImageProcessTest001
 * @tc.desc: Verify that VpeUtils call DetailEnhancerImageProcess when dlHandle_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, DetailEnhancerImageProcessTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: DetailEnhancerImageProcessTest001 start";
    VpeUtils mockVpeUtils;
    ASSERT_NE(mockVpeUtils.dlHandler_->handle_, nullptr);
    void* storeP = mockVpeUtils.dlHandler_->handle_;
    mockVpeUtils.dlHandler_->handle_ = nullptr;
    sptr<SurfaceBuffer> src = SurfaceBuffer::Create();
    sptr<SurfaceBuffer> des = SurfaceBuffer::Create();
    auto ret = mockVpeUtils.DetailEnhancerImageProcess(src, des, 0);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    mockVpeUtils.dlHandler_->handle_ = storeP;
    GTEST_LOG_(INFO) << "VpeUtilsTest: DetailEnhancerImageProcessTest001 end";
}

/**
 * @tc.name: DetailEnhancerImageProcessTest002
 * @tc.desc: Verify that VpeUtils call DetailEnhancerImageProcess when instanceId or res is fail.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, DetailEnhancerImageProcessTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: DetailEnhancerImageProcessTest002 start";
    VpeUtils mockVpeUtils;
    ASSERT_NE(mockVpeUtils.dlHandler_->handle_, nullptr);
    int mockHandler = 0;
    mockVpeUtils.dlHandler_->handle_ = &mockHandler;
    sptr<SurfaceBuffer> src = SurfaceBuffer::Create();
    sptr<SurfaceBuffer> des = SurfaceBuffer::Create();
    auto ret = mockVpeUtils.DetailEnhancerImageProcess(src, des, 0);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    GTEST_LOG_(INFO) << "VpeUtilsTest: DetailEnhancerImageProcessTest002 end";
}

/**
 * @tc.name: DetailEnhancerImageProcessTest003
 * @tc.desc: Verify that VpeUtils call DetailEnhancerImageProcess when input or output is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, DetailEnhancerImageProcessTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: DetailEnhancerImageProcessTest003 start";
    VpeUtils mockVpeUtils;
    ASSERT_NE(mockVpeUtils.dlHandler_->handle_, nullptr);
    sptr<SurfaceBuffer> src = SurfaceBuffer::Create();
    sptr<SurfaceBuffer> des = SurfaceBuffer::Create();
    sptr<SurfaceBuffer> nullInput = nullptr;
    sptr<SurfaceBuffer> nullOutput = nullptr;
    auto ret = mockVpeUtils.DetailEnhancerImageProcess(src, nullOutput, 0);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);

    ret = mockVpeUtils.DetailEnhancerImageProcess(nullInput, des, 0);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);

    ret = mockVpeUtils.DetailEnhancerImageProcess(nullInput, nullOutput, 0);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    GTEST_LOG_(INFO) << "VpeUtilsTest: DetailEnhancerImageProcessTest003 end";
}

/**
 * @tc.name: SetSbColorSpaceDefaultTest001
 * @tc.desc: Verify that VpeUtils call SetSbColorSpaceDefault when buffer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, SetSbColorSpaceDefaultTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: SetSbColorSpaceDefaultTest001 start";
    VpeUtils mockVpeUtils;
    sptr<SurfaceBuffer> mockBuffer;
    auto ret = mockVpeUtils.SetSbColorSpaceDefault(mockBuffer);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "VpeUtilsTest: SetSbColorSpaceDefaultTest001 end";
}

/**
 * @tc.name: SetSbMetadataTypeTest002
 * @tc.desc: Verify that VpeUtils call SetSbMetadataType when ret is not GSERROR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, SetSbMetadataTypeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: SetSbMetadataTypeTest002 start";
    VpeUtils mockVpeUtils;
    sptr<SurfaceBuffer> buffer = new MockSurfaceBuffer();
    static_cast<MockSurfaceBuffer*>(buffer.GetRefPtr())->shouldSetMetadataFail = true;
    bool result = mockVpeUtils.SetSbMetadataType(buffer,
        HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type::CM_METADATA_NONE);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "VpeUtilsTest: SetSbMetadataTypeTest002 end";
}

/**
 * @tc.name: GetSbMetadataTypeTest001
 * @tc.desc: Verify that VpeUtils call GetSbMetadataType when ret is not GSERROR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, GetSbMetadataTypeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: GetSbMetadataTypeTest001 start";
    VpeUtils mockVpeUtils;
    sptr<SurfaceBuffer> buffer = new MockSurfaceBuffer();
    static_cast<MockSurfaceBuffer*>(buffer.GetRefPtr())->shouldGetMetadataFail = true;
    HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type metadataType;
    bool result = mockVpeUtils.GetSbMetadataType(buffer, metadataType);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "VpeUtilsTest: GetSbMetadataTypeTest001 end";
}

/**
 * @tc.name: TruncateBufferTest001
 * @tc.desc: Verify that VpeUtils call TruncateBuffer when shouldCalDiff is true.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, TruncateBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: TruncateBufferTest001 start";
    VpeUtils mockVpeUtils;
    VpeSurfaceBuffers buffers;
    buffers.hdr = new MockSurfaceBuffer();
    buffers.sdr = new MockSurfaceBuffer();
    auto ret = mockVpeUtils.TruncateBuffer(buffers, true);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    GTEST_LOG_(INFO) << "VpeUtilsTest: TruncateBufferTest001 end";
}

/**
 * @tc.name: TruncateBufferTest002
 * @tc.desc: Verify that VpeUtils call TruncateBuffer when srcPixelFormat is not GRAPHIC_PIXEL_FMT_RGBA_1010102.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, TruncateBufferTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: TruncateBufferTest002 start";
    VpeUtils mockVpeUtils;
    VpeSurfaceBuffers buffers;
    buffers.hdr = new MockSurfaceBuffer();
    buffers.sdr = new MockSurfaceBuffer();
    auto ret = mockVpeUtils.TruncateBuffer(buffers, false);
    ASSERT_EQ(ret, VPE_ERROR_OK);
    GTEST_LOG_(INFO) << "VpeUtilsTest: TruncateBufferTest002 end";
}

/**
 * @tc.name: ColorSpaceCalGainmapTest001
 * @tc.desc: Verify that VpeUtils call ColorSpaceCalGainmap when dlHandler_->handle_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceCalGainmapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceCalGainmapTest001 start";
    VpeUtils mockVpeUtils;
    VpeSurfaceBuffers buffers;
    void* storeP = mockVpeUtils.dlHandler_->handle_;
    mockVpeUtils.dlHandler_->handle_ = nullptr;
    auto ret = mockVpeUtils.ColorSpaceCalGainmap(buffers);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    mockVpeUtils.dlHandler_->handle_ = storeP;
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceCalGainmapTest001 end";
}

/**
 * @tc.name: ColorSpaceCalGainmapTest002
 * @tc.desc: Verify that VpeUtils call ColorSpaceCalGainmap when instancedId or res is equal.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceCalGainmapTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceCalGainmapTest002 start";
    VpeUtils mockVpeUtils;
    ASSERT_NE(mockVpeUtils.dlHandler_->handle_, nullptr);
    VpeSurfaceBuffers buffers;
    int mockHandler = 0;
    mockVpeUtils.dlHandler_->handle_ = &mockHandler;
    auto ret = mockVpeUtils.ColorSpaceCalGainmap(buffers);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceCalGainmapTest002 end";
}

/**
 * @tc.name: ColorSpaceCalGainmapTest003
 * @tc.desc: Verify that VpeUtils call ColorSpaceCalGainmap when sb.sdr or sb.gainmap or sb.hdr is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(VpeUtilsTest, ColorSpaceCalGainmapTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceCalGainmapTest003 start";
    VpeUtils mockVpeUtils;
    ASSERT_NE(mockVpeUtils.dlHandler_->handle_, nullptr);
    VpeSurfaceBuffers buffersSdr;
    buffersSdr.sdr = nullptr;
    buffersSdr.gainmap = new MockSurfaceBuffer();
    buffersSdr.hdr = new MockSurfaceBuffer();
    auto ret = mockVpeUtils.ColorSpaceCalGainmap(buffersSdr);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);

    VpeSurfaceBuffers buffersGainmap;
    buffersGainmap.sdr = new MockSurfaceBuffer();
    buffersGainmap.gainmap = nullptr;
    buffersGainmap.hdr = new MockSurfaceBuffer();
    ret = mockVpeUtils.ColorSpaceCalGainmap(buffersGainmap);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);

    VpeSurfaceBuffers buffersHdr;
    buffersHdr.sdr = new MockSurfaceBuffer();
    buffersHdr.gainmap = new MockSurfaceBuffer();
    buffersHdr.hdr = nullptr;
    ret = mockVpeUtils.ColorSpaceCalGainmap(buffersHdr);
    ASSERT_EQ(ret, VPE_ERROR_FAILED);
    GTEST_LOG_(INFO) << "VpeUtilsTest: ColorSpaceCalGainmapTest003 end";
}
}
}