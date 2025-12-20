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

#define private public
#define protected public
#include <gtest/gtest.h>
#include "media_errors.h"
#include "metadata_helper.h"
#include "native_image.h"
#include "image_creator.h"
#include "surface_buffer.h"
#include "buffer_extra_data_impl.h"
#include "sync_fence.h"

using namespace testing::ext;
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
namespace OHOS {
namespace Media {
const std::string DATA_SIZE_TAG = "dataSize";
static constexpr int32_t NUMI_0 = 0;
static constexpr uint32_t NUM_0 = 0;
static constexpr int32_t NUMI_2 = 2;
static constexpr uint32_t BUFFER_SIZE_1000 = 1000;
static constexpr uint32_t BUFFER_SIZE_100 = 100;
static constexpr uint32_t BUFFER_SIZE_10 = 10;
static constexpr uint32_t BUFFER_SIZE_190 = 190;
static constexpr int32_t DATA_SIZE_2 = 2;
static constexpr int32_t DATA_SIZE_200 = 200;
static constexpr int32_t RECEIVER_TEST_WIDTH = 8192;
static constexpr int32_t RECEIVER_TEST_HEIGHT = 8;
static constexpr int32_t RECEIVER_TEST_CAPACITY = 8;
static constexpr int32_t RECEIVER_TEST_FORMAT = 4;
static constexpr int32_t ROWSTRIDE = 2;
static constexpr int32_t WIDTH = 10;
static constexpr int32_t WIDTH_100000 = 100000;
static constexpr int32_t HEIGHT = 10;
static constexpr int32_t HEIGHT_30000 = 30000;
static constexpr int32_t SIZE_WIDTH = 100;
static constexpr int32_t SIZE_HEIGHT = 100;
class NativeImageTest : public testing::Test {
public:
    NativeImageTest() {}
    ~NativeImageTest() {}
};

class MockSurfaceBuffer : public SurfaceBuffer {
public:
    MockSurfaceBuffer() = default;
    ~MockSurfaceBuffer() = default;

    int32_t GetFormat() const override
    {
        return mockFormat_;
    }

    void* GetVirAddr() override
    {
        return mockVirAddr_;
    }

    uint32_t GetSize() const override
    {
        return mockSize_;
    }

    int32_t GetWidth() const override
    {
        return mockWidth_;
    }

    int32_t GetHeight() const override
    {
        return mockHeight_;
    }

    sptr<BufferExtraData> GetExtraData() const override
    {
        return mockExtraData_;
    }

    void SetMockFormat(int32_t format)
    {
        mockFormat_ = format;
    }

    void SetMockVirAddr(void* addr)
    {
        mockVirAddr_ = addr;
    }

    void SetMockSize(uint32_t size)
    {
        mockSize_ = size;
    }

    void SetMockWidth(int32_t width)
    {
        mockWidth_ = width;
    }

    void SetMockHeight(int32_t height)
    {
        mockHeight_ = height;
    }

    void SetMockExtraData(sptr<BufferExtraData> extraData)
    {
        mockExtraData_ = extraData;
    }

    BufferHandle *GetBufferHandle() const override { return nullptr; }
    int32_t GetStride() const override { return mockWidth_ * 4; }
    uint64_t GetUsage() const override { return 0; }
    uint64_t GetPhyAddr() const override { return 0; }
    int32_t GetFileDescriptor() const override { return -1; }
    GraphicColorGamut GetSurfaceBufferColorGamut() const override { return GRAPHIC_COLOR_GAMUT_SRGB; }
    GraphicTransformType GetSurfaceBufferTransform() const override { return GRAPHIC_ROTATE_NONE; }
    void SetSurfaceBufferColorGamut(const GraphicColorGamut& colorGamut) override {}
    void SetSurfaceBufferTransform(const GraphicTransformType& transform) override {}
    int32_t GetSurfaceBufferWidth() const override { return mockWidth_; }
    int32_t GetSurfaceBufferHeight() const override { return mockHeight_; }
    void SetSurfaceBufferWidth(int32_t width) override {}
    void SetSurfaceBufferHeight(int32_t height) override {}
    uint32_t GetSeqNum() const override { return 0; }
    void SetExtraData(sptr<BufferExtraData> bedata) override {}
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
    GSError SetMetadata(uint32_t key, const std::vector<uint8_t>& value, bool enableCache = true) override
        { return GSERROR_OK; }
    GSError GetMetadata(uint32_t key, std::vector<uint8_t>& value) override
    {
        CM_ColorSpaceType type = CM_ColorSpaceType::CM_BT601_EBU_FULL;
        CM_ColorSpaceInfo info;
        MetadataHelper::ConvertColorSpaceTypeToInfo(type, info);
        return MetadataHelper::ConvertMetadataToVec(info, value);
    }
    GSError ListMetadataKeys(std::vector<uint32_t>& keys) override { return GSERROR_NOT_SUPPORT; }
    GSError EraseMetadataKey(uint32_t key) override { return GSERROR_NOT_SUPPORT; }
    OH_NativeBuffer* SurfaceBufferToNativeBuffer() override { return nullptr; }
    GSError GetPlanesInfo(void** planes) override { return GSERROR_OK; }
    void SetAndMergeSyncFence(const sptr<OHOS::SyncFence>& syncFence) override {}
    sptr<OHOS::SyncFence> GetSyncFence() const override { return nullptr; }

private:
    int32_t mockFormat_ = 0;
    void* mockVirAddr_ = nullptr;
    uint32_t mockSize_ = 0;
    int32_t mockWidth_ = 0;
    int32_t mockHeight_ = 0;
    sptr<BufferExtraData> mockExtraData_ = nullptr;
};

/**
 * @tc.name: NativeImageTest001
 * @tc.desc: GetSize
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    int32_t width = 0;
    int32_t height = 0;
    int32_t res = image.GetSize(width, height);
    ASSERT_EQ(res, ERR_MEDIA_DEAD_OBJECT);

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest001 end";
}

/**
 * @tc.name: NativeImageTest002
 * @tc.desc: GetDataSize
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest002 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    uint64_t size = 96;
    int32_t res = image.GetDataSize(size);
    ASSERT_EQ(res, ERR_MEDIA_DEAD_OBJECT);

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest002 end";
}

/**
 * @tc.name: GetDataSizeTest003
 * @tc.desc: Test that GetDataSize returns buffer size when ExtraData is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetDataSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetDataSizeTest003 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    uint32_t bufferSize = BUFFER_SIZE_1000;
    mockBuffer->SetMockSize(bufferSize);
    mockBuffer->SetMockExtraData(nullptr);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(mockBuffer, releaser);
    uint64_t size = 0;
    int32_t res = image.GetDataSize(size);
    ASSERT_EQ(res, SUCCESS);
    ASSERT_EQ(size, bufferSize);
    GTEST_LOG_(INFO) << "NativeImageTest: GetDataSizeTest003 end";
}

/**
 * @tc.name: GetDataSizeTest004
 * @tc.desc: Test that GetDataSize returns buffer size when ExtraData exists but its dataSize is zero.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetDataSizeTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetDataSizeTest004 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    uint32_t bufferSize = BUFFER_SIZE_1000;
    mockBuffer->SetMockSize(bufferSize);
    sptr<BufferExtraData> extraData = new BufferExtraDataImpl();
    ASSERT_NE(extraData, nullptr);
    int32_t zeroDataSize = 0;
    extraData->ExtraSet(DATA_SIZE_TAG, zeroDataSize);
    mockBuffer->SetMockExtraData(extraData);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(mockBuffer, releaser);
    uint64_t size = 0;
    int32_t res = image.GetDataSize(size);
    ASSERT_EQ(res, SUCCESS);
    ASSERT_EQ(size, bufferSize);
    GTEST_LOG_(INFO) << "NativeImageTest: GetDataSizeTest004 end";
}

/**
 * @tc.name: GetDataSizeTest005
 * @tc.desc: Test that GetDataSize returns buffer size when ExtraData's dataSize is greater than buffer size.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetDataSizeTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetDataSizeTest005 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    uint32_t bufferSize = BUFFER_SIZE_100;
    mockBuffer->SetMockSize(bufferSize);
    sptr<BufferExtraData> extraData = new BufferExtraDataImpl();
    ASSERT_NE(extraData, nullptr);
    int32_t extraDataSize = DATA_SIZE_200;
    extraData->ExtraSet(DATA_SIZE_TAG, extraDataSize);
    mockBuffer->SetMockExtraData(extraData);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(mockBuffer, releaser);
    uint64_t size = 0;
    int32_t res = image.GetDataSize(size);
    ASSERT_EQ(res, SUCCESS);
    ASSERT_EQ(size, bufferSize);
    GTEST_LOG_(INFO) << "NativeImageTest: GetDataSizeTest005 end";
}

/**
 * @tc.name: GetDataSizeTest006
 * @tc.desc: Test that GetDataSize returns ExtraData's dataSize when it is valid and less than buffer size.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetDataSizeTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetDataSizeTest006 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    uint32_t bufferSize = BUFFER_SIZE_100;
    mockBuffer->SetMockSize(bufferSize);
    sptr<BufferExtraData> extraData = new BufferExtraDataImpl();
    ASSERT_NE(extraData, nullptr);
    int32_t extraDataSize = DATA_SIZE_2;
    extraData->ExtraSet(DATA_SIZE_TAG, extraDataSize);
    mockBuffer->SetMockExtraData(extraData);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(mockBuffer, releaser);
    uint64_t size = 0;
    int32_t res = image.GetDataSize(size);
    ASSERT_EQ(res, SUCCESS);
    ASSERT_EQ(size, static_cast<uint64_t>(extraDataSize));
    GTEST_LOG_(INFO) << "NativeImageTest: GetDataSizeTest006 end";
}

/**
 * @tc.name: NativeImageTest003
 * @tc.desc: GetFormat
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest003 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    int32_t format = 4;
    int32_t res = image.GetFormat(format);
    ASSERT_EQ(res, ERR_MEDIA_DEAD_OBJECT);

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest003 end";
}

/**
 * @tc.name: NativeImageTest004
 * @tc.desc: GetFormat
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest004 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    int32_t type = 4;
    NativeComponent* res = image.GetComponent(type);
    ASSERT_EQ(res, nullptr);

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest004 end";
}

/**
 * @tc.name: NativeImageTest005
 * @tc.desc: CombineYUVComponents
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest005 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    uint32_t res = image.CombineYUVComponents();
    ASSERT_NE(res, SUCCESS);

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest005 end";
}

/**
 * @tc.name: NativeImageTest006
 * @tc.desc: CombineYUVComponents
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest006 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    image.release();

    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest006 end";
}

/**
 * @tc.name: NativeImageTest008
 * @tc.desc: Test that CombineYUVComponents returns ERR_MEDIA_DATA_UNSUPPORT when buffer size is zero.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest008 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    int dummyAddr = 0;
    mockBuffer->SetMockVirAddr(&dummyAddr);
    mockBuffer->SetMockFormat(static_cast<int32_t>(GRAPHIC_PIXEL_FMT_YCBCR_422_SP));
    mockBuffer->SetMockSize(0);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(mockBuffer, releaser);
    int32_t res = image.CombineYUVComponents();
    ASSERT_EQ(res, ERR_MEDIA_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest008 end";
}

/**
 * @tc.name: NativeImageTest009
 * @tc.desc: Test that CombineYUVComponents returns SUCCESS when buffer size is valid and format is YCBCR_422_SP.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest009 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    int dummyAddr = 0;
    mockBuffer->SetMockVirAddr(&dummyAddr);
    mockBuffer->SetMockFormat(static_cast<int32_t>(GRAPHIC_PIXEL_FMT_YCBCR_422_SP));
    mockBuffer->SetMockSize(BUFFER_SIZE_10);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(mockBuffer, releaser);
    int32_t res = image.CombineYUVComponents();
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest009 end";
}

/**
 * @tc.name: NativeImageTest006
 * @tc.desc: SplitSurfaceToComponent***
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, SplitSurfaceToComponent, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: SplitSurfaceToComponent start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    image.buffer_ = nullptr;
    int32_t ret = image.SplitSurfaceToComponent();
    ASSERT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "NativeImageTest: SplitSurfaceToComponent end";
}

/**
 * @tc.name: SplitSurfaceToComponent002
 * @tc.desc: Test that SplitSurfaceToComponent returns SUCCESS when buffer is valid and format is YCBCR_422_SP.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, SplitSurfaceToComponent002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: SplitSurfaceToComponent002 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    size_t bufferSize = SIZE_WIDTH * SIZE_HEIGHT * NUMI_2;
    std::vector<uint8_t> buffer(bufferSize, 0);
    mockBuffer->SetMockVirAddr(buffer.data());
    mockBuffer->SetMockFormat(GRAPHIC_PIXEL_FMT_YCBCR_422_SP);
    mockBuffer->SetMockWidth(SIZE_WIDTH);
    mockBuffer->SetMockHeight(SIZE_HEIGHT);
    mockBuffer->SetMockSize(SIZE_WIDTH * SIZE_HEIGHT * NUMI_2);

    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage nativeImage(mockBuffer, releaser);
    int32_t ret = nativeImage.SplitSurfaceToComponent();
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "NativeImageTest: SplitSurfaceToComponent002 end";
}

/**
 * @tc.name: SplitSurfaceToComponent003
 * @tc.desc: Test that SplitSurfaceToComponent returns SUCCESS when buffer is valid and format is JPEG.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, SplitSurfaceToComponent003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: SplitSurfaceToComponent003 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    int dummyAddr = 0;
    mockBuffer->SetMockVirAddr(&dummyAddr);
    mockBuffer->SetMockFormat(static_cast<int32_t>(ImageFormat::JPEG));
    mockBuffer->SetMockWidth(SIZE_WIDTH);
    mockBuffer->SetMockHeight(SIZE_HEIGHT);
    mockBuffer->SetMockSize(SIZE_WIDTH * SIZE_HEIGHT);

    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage nativeImage(mockBuffer, releaser);
    int32_t ret = nativeImage.SplitSurfaceToComponent();
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "NativeImageTest: SplitSurfaceToComponent003 end";
}

/**
 * @tc.name: CreateComponent001
 * @tc.desc: CreateComponent
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, CreateComponent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: CreateComponent001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    int32_t type = 1;
    size_t size = 0;
    int32_t row = 1;
    int32_t pixel = 1;
    uint8_t *vir = nullptr;
    std::shared_ptr<IBufferProcessor> release = nullptr;
    NativeImage image(buffer, release);
    NativeComponent *native = new(NativeComponent);
    image.components_.insert(std::make_pair(1, native));
    NativeComponent* ret = image.CreateComponent(type, size, row, pixel, vir);
    ASSERT_NE(ret, nullptr);
    ret = image.CreateComponent(2, size, row, pixel, vir);
    ASSERT_EQ(ret, nullptr);
    size = 1;
    vir = new(uint8_t);
    ret = image.CreateComponent(type, size, row, pixel, vir);
    ASSERT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: CreateComponent001 end";
}

/**
 * @tc.name: GetCachedComponent001
 * @tc.desc: GetCachedComponent
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetCachedComponent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetCachedComponent001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> release = nullptr;
    NativeImage image(buffer, release);
    NativeComponent* ret = image.GetCachedComponent(1);
    ASSERT_EQ(ret, nullptr);
    NativeComponent *native = new(NativeComponent);
    image.components_.insert(std::make_pair(1, native));
    ret = image.GetCachedComponent(1);
    ASSERT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: GetCachedComponent001 end";
}

/**
 * @tc.name: SplitYUV422SPComponent001
 * @tc.desc: SplitYUV422SPComponent
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, SplitYUV422SPComponent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> release = nullptr;
    NativeImage image(buffer, release);
    image.buffer_ = nullptr;
    int32_t ret = image.SplitYUV422SPComponent();
    ASSERT_EQ(ret, ERR_MEDIA_NULL_POINTER);
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent001 end";
}

/**
 * @tc.name: SplitYUV422SPComponent002
 * @tc.desc: Test that SplitYUV422SPComponent returns ERR_MEDIA_DATA_UNSUPPORT when buffer size is zero.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, SplitYUV422SPComponent002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent002 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    int dummyAddr = 0;
    mockBuffer->SetMockVirAddr(&dummyAddr);
    mockBuffer->SetMockSize(0);
    std::shared_ptr<IBufferProcessor> release = nullptr;
    NativeImage image(mockBuffer, release);
    int32_t ret = image.SplitYUV422SPComponent();
    ASSERT_EQ(ret, ERR_MEDIA_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent002 end";
}

/**
 * @tc.name: SplitYUV422SPComponent003
 * @tc.desc: Test that SplitYUV422SPComponent returns ERR_MEDIA_DATA_UNSUPPORT when width or height is zero.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, SplitYUV422SPComponent003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent003 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    int dummyAddr = 0;
    mockBuffer->SetMockVirAddr(&dummyAddr);
    std::shared_ptr<IBufferProcessor> release = nullptr;
    NativeImage image(mockBuffer, release);
    mockBuffer->SetMockSize(BUFFER_SIZE_10);
    mockBuffer->SetMockWidth(0);
    mockBuffer->SetMockHeight(HEIGHT);
    int32_t ret = image.SplitYUV422SPComponent();
    ASSERT_EQ(ret, ERR_MEDIA_DATA_UNSUPPORT);

    mockBuffer->SetMockWidth(WIDTH);
    mockBuffer->SetMockHeight(0);
    ret = image.SplitYUV422SPComponent();
    ASSERT_EQ(ret, ERR_MEDIA_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent003 end";
}

/**
 * @tc.name: SplitYUV422SPComponent004
 * @tc.desc: Test that SplitYUV422SPComponent returns ERR_MEDIA_DATA_UNSUPPORT when buffer size is too large.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, SplitYUV422SPComponent004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent004 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    int dummyAddr = 0;
    mockBuffer->SetMockVirAddr(&dummyAddr);
    std::shared_ptr<IBufferProcessor> release = nullptr;
    NativeImage image(mockBuffer, release);
    mockBuffer->SetMockSize(BUFFER_SIZE_10);
    mockBuffer->SetMockWidth(WIDTH_100000);
    mockBuffer->SetMockHeight(HEIGHT_30000);
    int32_t ret = image.SplitYUV422SPComponent();
    ASSERT_EQ(ret, ERR_MEDIA_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent004 end";
}

/**
 * @tc.name: SplitYUV422SPComponent005
 * @tc.desc: Test that SplitYUV422SPComponent returns ERR_MEDIA_DATA_UNSUPPORT when buffer size not match.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, SplitYUV422SPComponent005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent005 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    int dummyAddr = 0;
    mockBuffer->SetMockVirAddr(&dummyAddr);
    std::shared_ptr<IBufferProcessor> release = nullptr;
    NativeImage image(mockBuffer, release);
    mockBuffer->SetMockWidth(WIDTH);
    mockBuffer->SetMockHeight(HEIGHT);
    mockBuffer->SetMockSize(BUFFER_SIZE_190);
    int32_t ret = image.SplitYUV422SPComponent();
    ASSERT_EQ(ret, ERR_MEDIA_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "NativeImageTest: SplitYUV422SPComponent005 end";
}

/**
 * @tc.name: BuildComponent001
 * @tc.desc: BuildComponent
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, BuildComponent001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: BuildComponent001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    size_t size = 10;
    int32_t row = 10;
    int32_t pixel = 10;
    uint8_t *vir = new uint8_t;
    int32_t type = 1;
    image.components_.clear();
    image.CreateComponent(type, size, row, pixel, vir);
    ASSERT_EQ(1, image.components_.size());
    image.components_.clear();
    image.CreateComponent(type, size, row, pixel, vir);
    ASSERT_EQ(1, image.components_.size());
    GTEST_LOG_(INFO) << "NativeImageTest: BuildComponent001 end";
}

/**
 * @tc.name: NativeImageTest007
 * @tc.desc: NativeImage
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, NativeImageTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest007 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    sptr<SurfaceBuffer> buffer = creator->DequeueImage();
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);

    int32_t ret1 = image.SplitYUV422SPComponent();
    ASSERT_EQ(ret1, SUCCESS);

    uint64_t size = 0;
    auto extraData = image.buffer_->GetExtraData();
    int32_t extraDataSize = NUMI_0;
    auto res = extraData->ExtraGet(DATA_SIZE_TAG, extraDataSize);
    ASSERT_NE(res, NUM_0);
    int32_t ret2 = image.GetDataSize(size);
    ASSERT_EQ(ret2, SUCCESS);

    int32_t width = 0;
    int32_t height = 0;
    int32_t ret3 = image.GetSize(width, height);
    ASSERT_EQ(ret3, SUCCESS);

    int32_t format = 0;
    int32_t ret4 = image.GetFormat(format);
    ASSERT_EQ(format, image.buffer_->GetFormat());
    ASSERT_EQ(ret4, SUCCESS);

    int32_t ret5 = image.SplitSurfaceToComponent();
    ASSERT_EQ(ret5, ERR_MEDIA_DATA_UNSUPPORT);

    uint32_t ret6 = image.CombineYUVComponents();
    ASSERT_EQ(ret6, SUCCESS);

    int32_t type = 0;
    auto ret7 = image.CreateCombineComponent(type);
    ASSERT_NE(ret7, nullptr);

    type = 1;
    NativeComponent* ret8 = image.GetComponent(type);
    ASSERT_NE(ret8, nullptr);
    type = image.buffer_->GetFormat();
    ret8 = image.GetComponent(type);
    ASSERT_NE(ret8, nullptr);
    NativeComponent nativeComponent;
    NativeComponent *native = &nativeComponent;
    image.components_.insert(std::make_pair(type, native));
    ret8 = image.GetComponent(type);
    ASSERT_NE(ret8, nullptr);

    uint8_t *ret9 = image.GetSurfaceBufferAddr();
    ASSERT_NE(ret9, nullptr);
    image.buffer_ = nullptr;
    ret9 = image.GetSurfaceBufferAddr();
    ASSERT_EQ(ret9, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: NativeImageTest007 end";
}

/**
 * @tc.name: BuildComponentTest002
 * @tc.desc: BuildComponent
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, BuildComponentTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: BuildComponentTest002 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    size_t size = 10;
    int32_t row = 10;
    int32_t pixel = 10;
    uint8_t *vir = nullptr;
    int32_t type = 10;
    image.components_.clear();
    auto ret = image.CreateComponent(type, size, row, pixel, vir);
    auto iter = image.components_.find(type);
    ASSERT_EQ(iter->first, 10);
    ASSERT_NE(iter->second.get(), nullptr);
    ASSERT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: BuildComponentTest002 end";
}

/**
 * @tc.name: GetTimestampTest001
 * @tc.desc: GetTimestamp
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetTimestampTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetTimestampTest001 start";
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);
    int64_t timestamp = 0;
    int32_t ret = image.GetTimestamp(timestamp);
    ASSERT_EQ(ret, ERR_MEDIA_DEAD_OBJECT);

    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    buffer = creator->DequeueImage();
    ASSERT_NE(buffer, nullptr);
    NativeImage nativeImage(buffer, releaser);
    ret = nativeImage.GetTimestamp(timestamp);
    ASSERT_EQ(timestamp, nativeImage.timestamp_);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "NativeImageTest: GetTimestampTest001 end";
}

/**
 * @tc.name: releaseTest002
 * @tc.desc: release
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, releaseTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: releaseTest002 start";
    std::shared_ptr<ImageCreator> creator = ImageCreator::CreateImageCreator(1, 1, 1, 1);
    ASSERT_NE(creator, nullptr);
    sptr<SurfaceBuffer> buffer = creator->DequeueImage();
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<ImageReceiver> imageReceiver;
    imageReceiver = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    std::shared_ptr<IBufferProcessor> releaser = imageReceiver->GetBufferProcessor();
    ASSERT_NE(releaser, nullptr);
    NativeImage image(buffer, releaser);

    int32_t type = image.buffer_->GetFormat();
    image.GetComponent(type);
    NativeComponent nativeComponent;
    NativeComponent *native = &nativeComponent;
    image.components_.insert(std::make_pair(type, native));
    image.GetComponent(type);
    ASSERT_TRUE(image.components_.size() > 0);
    image.release();
    ASSERT_EQ(image.releaser_, nullptr);
    ASSERT_EQ(image.buffer_, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: releaseTest002 end";
}

/**
 * @tc.name: GetYUVByteCountTest001
 * @tc.desc: GetYUVByteCount
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetYUVByteCountTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetYUVByteCountTest001 start";
    PixelMap pixelmap;
    ImageInfo imginfo;
    imginfo.pixelFormat = PixelFormat::RGB_888;
    int32_t ret = pixelmap.GetYUVByteCount(imginfo);
    ASSERT_EQ(ret, -1);
    imginfo.pixelFormat = PixelFormat::NV21;
    imginfo.size.width = 0;
    imginfo.size.height = 10;
    ret = pixelmap.GetYUVByteCount(imginfo);
    ASSERT_EQ(ret, -1);
    imginfo.pixelFormat = PixelFormat::NV21;
    imginfo.size.width = 10;
    imginfo.size.height = 0;
    ret = pixelmap.GetYUVByteCount(imginfo);
    ASSERT_EQ(ret, -1);
    GTEST_LOG_(INFO) << "NativeImageTest: GetYUVByteCountTest001 end";
}

/**
 * @tc.name: GetRGBxByteCountTest001
 * @tc.desc: GetRGBxByteCount
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetRGBxByteCountTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetRGBxByteCountTest001 start";
    PixelMap pixelmap;
    ImageInfo imginfo;
    imginfo.pixelFormat = PixelFormat::NV21;
    int32_t ret = pixelmap.GetRGBxByteCount(imginfo);
    ASSERT_EQ(ret, -1);
    imginfo.pixelFormat = PixelFormat::NV12;
    ret = pixelmap.GetRGBxByteCount(imginfo);
    ASSERT_EQ(ret, -1);
    imginfo.pixelFormat = PixelFormat::ASTC_6x6;
    ret = pixelmap.GetRGBxByteCount(imginfo);
    ASSERT_EQ(ret, -1);
    GTEST_LOG_(INFO) << "NativeImageTest: GetRGBxByteCountTest001 end";
}

/**
 * @tc.name: CheckParamsTest001
 * @tc.desc: CheckParams
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, CheckParamsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: CheckParamsTest001 start";
    PixelMap pixelmap;
    uint32_t colors = 1;
    uint32_t colorLength = 1;
    int32_t offset = 0;
    int32_t width = 10;
    InitializationOptions opts;
    opts.size.width = 100;
    opts.size.height = 100;
    bool ret = pixelmap.CheckParams(&colors, colorLength, offset, width, opts);
    ASSERT_EQ(ret, false);
    width = (INT32_MAX >> 2) + 1;
    ASSERT_EQ(width > opts.size.width, true);
    ret = pixelmap.CheckParams(&colors, colorLength, offset, width, opts);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "NativeImageTest: CheckParamsTest001 end";
}

/**
 * @tc.name: CheckParamsTest002
 * @tc.desc: Verify CheckParams returns false with invalid input params.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, CheckParamsTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: CheckParamsTest002 start";
    PixelMap pixelmap;
    uint32_t colors = 1;
    uint32_t colorLength = 1;
    int32_t offset = 0;
    int32_t width = WIDTH;
    InitializationOptions opts;
    opts.size.width = SIZE_WIDTH;
    opts.size.height = SIZE_HEIGHT;
    opts.srcRowStride = ROWSTRIDE;
    bool ret = pixelmap.CheckParams(&colors, colorLength, offset, width, opts);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "NativeImageTest: CheckParamsTest002 end";
}

/**
 * @tc.name: GetAllocatedByteCountTest001
 * @tc.desc: GetAllocatedByteCount
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetAllocatedByteCountTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetAllocatedByteCountTest001 start";
    PixelMap pixelmap;
    ImageInfo imginfo;
    imginfo.pixelFormat = PixelFormat::NV21;
    pixelmap.GetAllocatedByteCount(imginfo);
    imginfo.pixelFormat = PixelFormat::NV12;
    pixelmap.GetAllocatedByteCount(imginfo);
    imginfo.pixelFormat = PixelFormat::ASTC_6x6;
    pixelmap.GetAllocatedByteCount(imginfo);
    GTEST_LOG_(INFO) << "NativeImageTest: GetAllocatedByteCountTest001 end";
}

/**
 * @tc.name: ScalePixelMapTest001
 * @tc.desc: ScalePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, ScalePixelMapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: ScalePixelMapTest001 start";
    PixelMap pixelmap;
    Size targetSize;
    targetSize.width = 100;
    targetSize.height = 100;
    Size dstSize;
    dstSize.width = 200;
    dstSize.height = 200;
    ScaleMode scaleMode = ScaleMode::FIT_TARGET_SIZE;
    PixelMap dstPixelMap;
    bool ret = pixelmap.ScalePixelMap(targetSize, dstSize, scaleMode, dstPixelMap);
    ASSERT_EQ(ret, false);
    scaleMode = ScaleMode::CENTER_CROP;
    targetSize.width = 100;
    targetSize.height = 100;
    dstSize.width = 200;
    dstSize.height = 200;
    ret = pixelmap.ScalePixelMap(targetSize, dstSize, scaleMode, dstPixelMap);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "NativeImageTest: ScalePixelMapTest001 end";
}

/**
 * @tc.name: IsYUV422SPFormat001
 * @tc.desc: Test that CombineYUVComponents when format is YCBCR_422_SP and buffer address is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, IsYUV422SPFormat001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: IsYUV422SPFormat001 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    mockBuffer->SetMockFormat(static_cast<int32_t>(ImageFormat::YCBCR_422_SP));
    mockBuffer->SetMockVirAddr(nullptr);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(mockBuffer, releaser);
    int32_t res = image.CombineYUVComponents();
    ASSERT_EQ(res, ERR_MEDIA_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "NativeImageTest: IsYUV422SPFormat001 end";
}

/**
 * @tc.name: IsYUV422SPFormat002
 * @tc.desc: Test that CombineYUVComponents when format is GRAPHIC_PIXEL_FMT_YCBCR_422_SP and buffer address is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, IsYUV422SPFormat002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: IsYUV422SPFormat002 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    mockBuffer->SetMockFormat(static_cast<int32_t>(GRAPHIC_PIXEL_FMT_YCBCR_422_SP));
    mockBuffer->SetMockVirAddr(nullptr);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(mockBuffer, releaser);
    int32_t res = image.CombineYUVComponents();
    ASSERT_EQ(res, ERR_MEDIA_DATA_UNSUPPORT);
    GTEST_LOG_(INFO) << "NativeImageTest: IsYUV422SPFormat002 end";
}

/**
 * @tc.name: Release001
 * @tc.desc: Test that release correctly resets buffer and releaser to nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, Release001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: Release001 start";
    sptr<MockSurfaceBuffer> mockBuffer = new MockSurfaceBuffer();
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(mockBuffer, releaser);
    ASSERT_EQ(image.components_.size(), 0);
    image.release();
    ASSERT_EQ(image.buffer_, nullptr);
    ASSERT_EQ(image.releaser_, nullptr);
    GTEST_LOG_(INFO) << "NativeImageTest: Release001 end";
}

/**
 * @tc.name: GetColorSpaceTest001
 * @tc.desc: test GetColorSpace buffer_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(NativeImageTest, GetColorSpaceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "NativeImageTest: GetColorSpaceTest001 start";
    sptr<SurfaceBuffer> buffer = new MockSurfaceBuffer();
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage image(buffer, releaser);

    int32_t colorSpace = 0;
    image.GetColorSpace(colorSpace);
    EXPECT_EQ(colorSpace, static_cast<int32_t>(CM_ColorSpaceType::CM_BT601_EBU_FULL));
    GTEST_LOG_(INFO) << "NativeImageTest: GetColorSpaceTest001 end";
}
}
}