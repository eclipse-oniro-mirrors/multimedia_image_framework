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
#define protected public
#include <gtest/gtest.h>

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {
class HeifDecodeImplTest : public testing::Test {
public:
    HeifDecodeImplTest() {}
    ~HeifDecodeImplTest() {}
};

/**
 * @tc.name: HeifDecoderImpl_initTest001
 * @tc.desc: Verify that HeifDecoderImpl call init when stream is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_initTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_initTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    ret = mockDecoderImpl->init(nullptr, nullptr);
    ASSERT_EQ(ret, false);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_initTest001 end";
}

/**
 * @tc.name: HeifDecoderImpl_initTest002
 * @tc.desc: Verify that HeifDecoderImpl call init when err is heif_error_ok.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_initTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_initTest002 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    ret = mockDecoderImpl->init(new MockHeifStream(), nullptr);
    ASSERT_EQ(ret, false);
    auto copyData = mockDecoderImpl->srcMemory_;
    mockDecoderImpl->srcMemory_ = nullptr;
    ret = mockDecoderImpl->init(new MockHeifStream(), nullptr);
    ASSERT_EQ(ret, false);
    mockDecoderImpl->srcMemory_ = copyData;
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_initTest002 end";
}

/**
 * @tc.name: HeifDecoderImpl_initTest003
 * @tc.desc: Verify HEIF decoder initialization fails with null stream and frameInfo.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_initTest003, TestSize.Level3)
{
#ifdef HEIF_HW_DECODE_ENABLE
    HeifDecoderImpl decoder;
    HeifStream *stream = nullptr;
    HeifFrameInfo *frameInfo = nullptr;
    bool ret = decoder.init(stream, frameInfo);
    EXPECT_FALSE(ret);
#endif
}

/**
 * @tc.name: HeifDecoderImpl_CheckAuxiliaryMapTest001
 * @tc.desc: Verify that CheckAuxiliaryMap call init when parser_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_CheckAuxiliaryMapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_CheckAuxiliaryMapTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    auto copyParser = mockDecoderImpl->parser_;
    mockDecoderImpl->parser_ = nullptr;
    ret = mockDecoderImpl->CheckAuxiliaryMap(AuxiliaryPictureType::GAINMAP);
    ASSERT_EQ(ret, false);
    mockDecoderImpl->parser_ = copyParser;
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_CheckAuxiliaryMapTest001 end";
}

/**
 * @tc.name: HeifDecoderImpl_CheckAuxiliaryMapTest002
 * @tc.desc: Verify that CheckAuxiliaryMap call init when AuxiliaryPictureType is NONE.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_CheckAuxiliaryMapTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_CheckAuxiliaryMapTest002 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    ASSERT_NE(mockDecoderImpl->parser_, nullptr);
    ret = mockDecoderImpl->CheckAuxiliaryMap(AuxiliaryPictureType::NONE);
    ASSERT_EQ(ret, false);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_CheckAuxiliaryMapTest002 end";
}

/**
 * @tc.name: HeifDecoderImpl_CheckAuxiliaryMapTest003
 * @tc.desc: Verify CheckAuxiliaryMap returns false when parser is null.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_CheckAuxiliaryMapTest003, TestSize.Level3)
{
#ifdef HEIF_HW_DECODE_ENABLE
    HeifDecoderImpl decoder;
    decoder.parser_ = nullptr;
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    bool ret = decoder.CheckAuxiliaryMap(type);
    EXPECT_FALSE(ret);
#endif
}

/**
 * @tc.name: HeifDecoderImpl_ReinitTest001
 * @tc.desc: Verify that Reinit call init when primaryImage_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_ReinitTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_ReinitTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    mockDecoderImpl->primaryImage_.reset();
    mockDecoderImpl->GetTileSize(mockDecoderImpl->primaryImage_, mockDecoderImpl->gridInfo_);
    ret = mockDecoderImpl->Reinit(nullptr);
    ASSERT_EQ(ret, true);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_ReinitTest001 end";
}

/**
 * @tc.name: HeifDecoderImpl_HwDecodeImageTest001
 * @tc.desc: Verify that HwDecodeImage call init when outPixelFormat_ is UNKNOWN.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_HwDecodeImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_HwDecodeImageTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    mockDecoderImpl->outPixelFormat_ = PixelFormat::UNKNOWN;
    ret = mockDecoderImpl->HwDecodeImage(nullptr, mockDecoderImpl->primaryImage_,
        mockDecoderImpl->gridInfo_, nullptr, false);
    ASSERT_EQ(ret, false);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_HwDecodeImageTest001 end";
}

/**
 * @tc.name: HeifDecoderImpl_HwDecodeImageTest002
 * @tc.desc: Verify that HwDecodeImage call init when outBuffer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_HwDecodeImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_HwDecodeImageTest002 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    mockDecoderImpl->outPixelFormat_ = PixelFormat::ARGB_8888;
    ret = mockDecoderImpl->HwDecodeImage(nullptr, mockDecoderImpl->primaryImage_,
        mockDecoderImpl->gridInfo_, nullptr, false);
    ASSERT_EQ(ret, false);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_HwDecodeImageTest002 end";
}

/**
 * @tc.name: HeifDecoderImpl_HwDecodeGridsTest001
 * @tc.desc: Verify that HwDecodeGrids call init when the conditions before decoding are not met.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_HwDecodeGridsTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_HwDecodeGridsTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    sptr<SurfaceBuffer> mockHwBuffer;
    ret = mockDecoderImpl->HwDecodeGrids(nullptr, mockDecoderImpl->primaryImage_,
        mockDecoderImpl->gridInfo_, mockHwBuffer);
    ASSERT_EQ(ret, false);
    HeifHardwareDecoder mockHeifHwDecoder;
    ASSERT_NE(mockDecoderImpl->primaryImage_, nullptr);
    ASSERT_NE(mockDecoderImpl->parser_, nullptr);
    decltype(mockDecoderImpl->parser_->infeBoxes_) copyMockParserMap;
    std::swap(mockDecoderImpl->parser_->infeBoxes_, copyMockParserMap);
    ret = mockDecoderImpl->HwDecodeGrids(&mockHeifHwDecoder, mockDecoderImpl->primaryImage_,
        mockDecoderImpl->gridInfo_, mockHwBuffer);
    ASSERT_EQ(ret, false);
    std::swap(mockDecoderImpl->parser_->infeBoxes_, copyMockParserMap);
    GridInfo mockGridInfo;
    ret = mockDecoderImpl->HwDecodeGrids(&mockHeifHwDecoder, mockDecoderImpl->primaryImage_,
        mockGridInfo, mockHwBuffer);
    ASSERT_EQ(ret, false);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_HwDecodeGridsTest001 end";
}

/**
 * @tc.name: HeifDecoderImpl_HwDecodeSingleImageTest001
 * @tc.desc: Verify that HwDecodeSingleImage call init when the conditions before decoding are not met.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_HwDecodeSingleImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_HwDecodeSingleImageTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    sptr<SurfaceBuffer> mockHwBuffer;
    ret = mockDecoderImpl->HwDecodeSingleImage(nullptr, mockDecoderImpl->primaryImage_,
        mockDecoderImpl->gridInfo_, mockHwBuffer);
    ASSERT_EQ(ret, false);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_HwDecodeSingleImageTest001 end";
}

/**
 * @tc.name: HeifDecoderImpl_HwDecodeMimeImageTest001
 * @tc.desc: Verify that call HwDecodeMimeImage when the conditions before decoding are not met.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_HwDecodeMimeImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_HwDecodeMimeImageTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    std::shared_ptr<HeifImage> mockHeifImage;
    ret = mockDecoderImpl->HwDecodeMimeImage(mockHeifImage);
    ASSERT_EQ(ret, false);
    auto copyAuxiDstMem = mockDecoderImpl->auxiliaryDstMemory_;
    mockDecoderImpl->auxiliaryDstMemory_ = nullptr;
    ret = mockDecoderImpl->HwDecodeMimeImage(mockDecoderImpl->primaryImage_);
    ASSERT_EQ(ret, false);
    mockDecoderImpl->auxiliaryDstMemory_ = copyAuxiDstMem;
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_HwDecodeMimeImageTest001 end";
}

/**
 * @tc.name: HeifDecoderImpl_SwDecodeImageTest001
 * @tc.desc: Verify that call SwDecodeImage when the conditions before decoding are not met.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_SwDecodeImageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_SwDecodeImageTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    mockDecoderImpl->outPixelFormat_ = PixelFormat::UNKNOWN;
    HevcSoftDecodeParam mockParam;
    std::shared_ptr<HeifImage> mockHeifImage;
    ret = mockDecoderImpl->SwDecodeImage(mockHeifImage, mockParam, mockDecoderImpl->gridInfo_, false);
    ASSERT_EQ(ret, false);
    mockDecoderImpl->outPixelFormat_ = PixelFormat::RGBA_8888;
    ret = mockDecoderImpl->SwDecodeImage(mockHeifImage, mockParam, mockDecoderImpl->gridInfo_, false);
    ASSERT_EQ(ret, false);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_SwDecodeImageTest001 end";
}

/**
 * @tc.name: HeifDecoderImpl_ProcessChunkHeadTest001
 * @tc.desc: Verify that call ProcessChunkHead when len less than CHUNK_HEAD_SIZE.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_ProcessChunkHeadTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_ProcessChunkHeadTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    ret = mockDecoderImpl->ProcessChunkHead(nullptr, SIZE_ZERO);
    ASSERT_EQ(ret, false);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_ProcessChunkHeadTest001 end";
}

/**
 * @tc.name: HeifDecoderImpl_getTmapInfoTest001
 * @tc.desc: Verify that call getTmapInfo when frameInfo is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ExtDecoderTest, HeifDecoderImpl_getTmapInfoTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_getTmapInfoTest001 start";
#ifdef HEIF_HW_DECODE_ENABLE
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    const int fd = open("/data/local/tmp/image/test_heif.heic", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(streamPtr, nullptr);
    extDecoder->SetSource(*streamPtr);
    ASSERT_NE(extDecoder->stream_, nullptr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    bool ret = extDecoder->CheckCodec();
    ASSERT_NE(extDecoder->codec_, nullptr);
    ASSERT_EQ(ret, true);
    auto mockDecoderImpl = reinterpret_cast<HeifDecoderImpl*>(extDecoder->codec_->getHeifContext());
    ASSERT_NE(mockDecoderImpl, nullptr);
    ret = mockDecoderImpl->getTmapInfo(nullptr);
    ASSERT_EQ(ret, true);
    HeifFrameInfo mockFrameInfo;
    ret = mockDecoderImpl->getTmapInfo(&mockFrameInfo);
    ASSERT_EQ(ret, true);
#endif
    GTEST_LOG_(INFO) << "ExtDecoderTest: HeifDecoderImpl_getTmapInfoTest001 end";
}
} // namespace ImagePlugin
} // namespace OHOS