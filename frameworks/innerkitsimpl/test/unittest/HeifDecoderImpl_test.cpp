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
#ifdef HEIF_HW_DECODE_ENABLE
#include <gtest/gtest.h>
#include <memory>
#include "HeifDecoderImpl.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {

static constexpr SkHeifColorFormat INVALID_HEIF_COLOR_FORMAT = static_cast<SkHeifColorFormat>(8);

class HeifDecoderImplTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

struct MockHeifStream : public HeifStream {
    virtual size_t read(void*, size_t)
    {
        return 0;
    }
    virtual bool rewind()
    {
        return false;
    }
    virtual bool seek(size_t)
    {
        return false;
    }
    virtual bool hasLength() const
    {
        return false;
    }
    virtual size_t getLength() const
    {
        return 0;
    }
    virtual bool hasPosition() const
    {
        return false;
    }
    virtual size_t getPosition() const
    {
        return 0;
    }
};

/**
 * @tc.name: SkHeifColorFormat2PixelFormatTest001
 * @tc.desc: Verify HeifDecoderImpl::setOutputColor works with valid/invalid SkHeifColorFormat,Cover all valid enum
 *           branches and default invalid branch of SkHeifColorFormat2PixelFormat.
 * @tc.type: FUNC
 */
HWTEST_F(HeifDecoderImplTest, SkHeifColorFormat2PixelFormatTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: SkHeifColorFormat2PixelFormatTest001 start";
    std::shared_ptr<HeifDecoderImpl> heifDecoderImpl = std::make_shared<HeifDecoderImpl>();
    SkHeifColorFormat heifColor = SkHeifColorFormat::kHeifColorFormat_RGB565;

    auto ret = heifDecoderImpl->setOutputColor(heifColor);
    EXPECT_EQ(ret, true);

    heifColor = SkHeifColorFormat::kHeifColorFormat_BGRA_8888;
    ret = heifDecoderImpl->setOutputColor(heifColor);
    EXPECT_EQ(ret, true);

    heifColor = SkHeifColorFormat::kHeifColorFormat_P010_NV12;
    ret = heifDecoderImpl->setOutputColor(heifColor);
    EXPECT_EQ(ret, true);

    heifColor = SkHeifColorFormat::kHeifColorFormat_P010_NV21;
    ret = heifDecoderImpl->setOutputColor(heifColor);
    EXPECT_EQ(ret, true);

    heifColor = INVALID_HEIF_COLOR_FORMAT;
    ret = heifDecoderImpl->setOutputColor(heifColor);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: SkHeifColorFormat2PixelFormatTest001 end";
}

/**
 * @tc.name: InitTest001
 * @tc.desc: Verify HeifDecoderImpl::setOutputColor works with valid/invalid SkHeifColorFormat,Cover all valid enum
 *           branches and default invalid branch of SkHeifColorFormat2PixelFormat.
 * @tc.type: FUNC
 */
HWTEST_F(HeifDecoderImplTest, InitTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: InitTest001 start";
    std::shared_ptr<HeifDecoderImpl> heifDecoderImpl = std::make_shared<HeifDecoderImpl>();
    HeifStream *stream = nullptr;
    HeifFrameInfo *frameInfo = nullptr;
    auto ret = heifDecoderImpl->init(stream, frameInfo);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: InitTest001 end";
}

/**
 * @tc.name: InitTest002
 * @tc.desc: Verify HeifDecoderImpl::init returns false when stream getLength() is 0 (file size is 0).
 * @tc.type: FUNC
 */
HWTEST_F(HeifDecoderImplTest, InitTest002, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: InitTest002 start";
    std::shared_ptr<HeifDecoderImpl> heifDecoderImpl = std::make_shared<HeifDecoderImpl>();
    HeifStream* stream = new MockHeifStream();
    HeifFrameInfo frameInfo{};
    auto ret = heifDecoderImpl->init(stream, &frameInfo);
    EXPECT_EQ(ret, false);
    delete stream;
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: InitTest002 end";
}

/**
 * @tc.name: CheckAuxiliaryMapTest001
 * @tc.desc: Verify HeifDecoderImpl::CheckAuxiliaryMap returns false when parser_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifDecoderImplTest, CheckAuxiliaryMapTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: CheckAuxiliaryMapTest001 start";
    std::shared_ptr<HeifDecoderImpl> heifDecoderImpl = std::make_shared<HeifDecoderImpl>();
    heifDecoderImpl->parser_ = nullptr;
    Media::AuxiliaryPictureType type = Media::AuxiliaryPictureType::NONE;
    auto ret = heifDecoderImpl->CheckAuxiliaryMap(type);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: CheckAuxiliaryMapTest001 end";
}

/**
 * @tc.name: CheckAuxiliaryMapTest002
 * @tc.desc: Verify HeifDecoderImpl::CheckAuxiliaryMap returns false when AuxiliaryPictureType is NONE.
 * @tc.type: FUNC
 */
HWTEST_F(HeifDecoderImplTest, CheckAuxiliaryMapTest002, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: CheckAuxiliaryMapTest002 start";
    std::shared_ptr<HeifDecoderImpl> heifDecoderImpl = std::make_shared<HeifDecoderImpl>();
    heifDecoderImpl->parser_ = std::make_shared<HeifParser>();
    Media::AuxiliaryPictureType type = Media::AuxiliaryPictureType::NONE;
    auto ret = heifDecoderImpl->CheckAuxiliaryMap(type);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: CheckAuxiliaryMapTest002 end";
}

/**
 * @tc.name: InitFrameInfoTest001
 * @tc.desc: Verify HeifDecoderImpl::InitFrameInfo outputs error log and returns when info or image is null.
 * @tc.type: FUNC
 */
HWTEST_F(HeifDecoderImplTest, InitFrameInfoTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: InitFrameInfoTest001 start";
    std::shared_ptr<HeifDecoderImpl> heifDecoderImpl = std::make_shared<HeifDecoderImpl>();
    HeifFrameInfo *info = nullptr;
    uint32_t itemId = 0;
    std::shared_ptr<HeifImage> image = std::make_shared<HeifImage>(itemId);
    EXPECT_NO_FATAL_FAILURE(heifDecoderImpl->InitFrameInfo(info, image));

    info = new HeifFrameInfo;
    image = nullptr;
    EXPECT_NO_FATAL_FAILURE(heifDecoderImpl->InitFrameInfo(info, image));
    delete info;

    info = nullptr;
    image = nullptr;
    EXPECT_NO_FATAL_FAILURE(heifDecoderImpl->InitFrameInfo(info, image));
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: InitFrameInfoTest001 end";
}

/**
 * @tc.name: SeekRefGridRangeInfoTest001
 * @tc.desc: Verify HeifDecoderImpl::SeekRefGridRangeInfo returns false when parser_ or image is null.
 * @tc.type: FUNC
 */
HWTEST_F(HeifDecoderImplTest, SeekRefGridRangeInfoTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: SeekRefGridRangeInfoTest001 start";
    std::shared_ptr<HeifDecoderImpl> heifDecoderImpl = std::make_shared<HeifDecoderImpl>();
    heifDecoderImpl->parser_ = nullptr;
    std::shared_ptr<HeifImage> image = nullptr;
    auto ret = heifDecoderImpl->SeekRefGridRangeInfo(image);
    EXPECT_EQ(ret, false);

    heifDecoderImpl->parser_ = nullptr;
    uint32_t itemId = 0;
    image = std::make_shared<HeifImage>(itemId);
    ret = heifDecoderImpl->SeekRefGridRangeInfo(image);
    EXPECT_EQ(ret, false);

    heifDecoderImpl->parser_ = std::make_shared<HeifParser>();
    image = nullptr;
    ret = heifDecoderImpl->SeekRefGridRangeInfo(image);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: SeekRefGridRangeInfoTest001 end";
}

/**
 * @tc.name: InitGridInfoTest001
 * @tc.desc: Verify HeifDecoderImpl::InitGridInfo handles null image correctly (no crash, cover target branch).
 * @tc.type: FUNC
 */
HWTEST_F(HeifDecoderImplTest, InitGridInfoTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: InitGridInfoTest001 start";
    std::shared_ptr<HeifDecoderImpl> heifDecoderImpl = std::make_shared<HeifDecoderImpl>();
    std::shared_ptr<HeifImage> image = nullptr;
    GridInfo gridInfo = {};
    EXPECT_NO_FATAL_FAILURE(heifDecoderImpl->InitGridInfo(image, gridInfo));
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: InitGridInfoTest001 end";
}

/**
 * @tc.name: HwSetColorSpaceDataTest001
 * @tc.desc: Verify HeifDecoderImpl::HwSetColorSpaceData returns GSERROR_NO_BUFFER when buffer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(HeifDecoderImplTest, HwSetColorSpaceDataTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: HwSetColorSpaceDataTest001 start";
    std::shared_ptr<HeifDecoderImpl> heifDecoderImpl = std::make_shared<HeifDecoderImpl>();
    sptr<SurfaceBuffer> buffer = nullptr;
    GridInfo gridInfo = {};
    auto ret = heifDecoderImpl->HwSetColorSpaceData(buffer, gridInfo);
    EXPECT_EQ(ret, GSERROR_NO_BUFFER);
    GTEST_LOG_(INFO) << "HeifDecoderImplTest: HwSetColorSpaceDataTest001 end";
}
} // namespace ImagePlugin
} // namespace OHOS
#endif
