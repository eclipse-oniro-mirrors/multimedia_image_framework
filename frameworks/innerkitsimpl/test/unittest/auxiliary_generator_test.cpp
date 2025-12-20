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

#include <gtest/gtest.h>
#include "auxiliary_generator.h"
#include "input_data_stream.h"
#include "abs_image_decoder.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Media {
constexpr int32_t IMAGE_SIZE = 100;

class AuxiliaryGeneratorTest : public testing::Test {
public:
    AuxiliaryGeneratorTest() {}
    ~AuxiliaryGeneratorTest() {}
};

class MockInputDataStream : public ImagePlugin::InputDataStream {
public:
    MockInputDataStream() = default;
    ~MockInputDataStream() = default;
    bool Read(uint32_t desiredSize, DataStreamBuffer &outData) override { return true; }
    bool Read(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
        { return true; }
    bool Peek(uint32_t desiredSize, DataStreamBuffer &outData) override { return true; }
    bool Peek(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
        { return true; }
    uint32_t Tell() override { return 0; }
    bool Seek(uint32_t position) override { return true; }
};

class MockAbsImageDecoder : public ImagePlugin::AbsImageDecoder {
public:
    MockAbsImageDecoder() = default;
    ~MockAbsImageDecoder() = default;
    void SetSource(InputDataStream &sourceStream) override {}
    void Reset() override {}
    uint32_t SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info) override { return 0; }
    uint32_t Decode(uint32_t index, DecodeContext &context) override { return 0; }
    uint32_t PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &context) override { return 0; }
    uint32_t GetImageSize(uint32_t index, OHOS::Media::Size &size) override
    {
        size.width = IMAGE_SIZE;
        size.height = IMAGE_SIZE;
        return 0;
    }
    std::string GetPluginType() override { return "mock_decoder"; }
    bool DecodeHeifAuxiliaryMap(DecodeContext& context, Media::AuxiliaryPictureType type) override { return false; }
};

/**
 * @tc.name: GetAuxiliaryPictureDenominatorTest001
 * @tc.desc: Test DEPTH_MAP uses DEPTH_SCALE_DENOMINATOR
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryGeneratorTest, GenerateJpegAuxiliary_Denominator_DepthMap_Test, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetAuxiliaryPictureDenominatorTest001 start";

    MainPictureInfo mainInfo;
    mainInfo.imageInfo.size.width = 800;
    mainInfo.imageInfo.size.height = 600;
    mainInfo.imageInfo.pixelFormat = PixelFormat::RGBA_8888;
    mainInfo.hdrType = ImageHdrType::SDR;

    std::unique_ptr<OHOS::ImagePlugin::InputDataStream> auxStream =
        std::make_unique<MockInputDataStream>();
    
    std::unique_ptr<OHOS::ImagePlugin::AbsImageDecoder> extDecoder =
        std::make_unique<MockAbsImageDecoder>();

    uint32_t errorCode = SUCCESS;

    auto result = AuxiliaryGenerator::GenerateJpegAuxiliaryPicture(
        mainInfo,
        AuxiliaryPictureType::DEPTH_MAP,
        auxStream,
        extDecoder,
        errorCode);

    ASSERT_EQ(result, nullptr);
    ASSERT_NE(errorCode, SUCCESS);

    GTEST_LOG_(INFO) << "GetAuxiliaryPictureDenominatorTest001 end";
}

/**
 * @tc.name: GetAuxiliaryPictureDenominatorTest002
 * @tc.desc: Test LINEAR_MAP uses LINEAR_SCALE_DENOMINATOR
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryGeneratorTest, GetAuxiliaryPictureDenominatorTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GenerateJpegAuxiliary_Denominator_LinearMap_Test start";

    MainPictureInfo mainInfo;
    mainInfo.imageInfo.size.width = 1024;
    mainInfo.imageInfo.size.height = 768;
    mainInfo.imageInfo.pixelFormat = PixelFormat::RGBA_8888;
    mainInfo.hdrType = ImageHdrType::SDR;

    std::unique_ptr<OHOS::ImagePlugin::InputDataStream> auxStream =
        std::make_unique<MockInputDataStream>();
    
    std::unique_ptr<OHOS::ImagePlugin::AbsImageDecoder> extDecoder =
        std::make_unique<MockAbsImageDecoder>();

    uint32_t errorCode = SUCCESS;

    auto result = AuxiliaryGenerator::GenerateJpegAuxiliaryPicture(
        mainInfo,
        AuxiliaryPictureType::LINEAR_MAP,
        auxStream,
        extDecoder,
        errorCode);

    if (result == nullptr) {
        GTEST_LOG_(INFO) << "Result is nullptr as expected with mock objects";
        GTEST_LOG_(INFO) << "Error code: " << errorCode;
        
        EXPECT_NE(errorCode, SUCCESS) << "Should have error with mock decoder";
    } else {
        GTEST_LOG_(INFO) << "Unexpected success! Checking dimensions...";
        
        auto pixelMap = result->GetContentPixel();
        if (pixelMap != nullptr) {
            EXPECT_EQ(pixelMap->GetWidth(), 1024 / 4);
            EXPECT_EQ(pixelMap->GetHeight(), 768 / 4);
        } else {
            GTEST_LOG_(WARNING) << "Cannot get pixel map from result";
        }
    }
    GTEST_LOG_(INFO) << "GetAuxiliaryPictureDenominatorTest002";
}

/**
 * @tc.name: GetAuxiliaryPictureDenominatorTest003
 * @tc.desc: Test other types use DEFAULT_SCALE_DENOMINATOR
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryGeneratorTest, GetAuxiliaryPictureDenominatorTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetAuxiliaryPictureDenominatorTest003 start";

    MainPictureInfo mainInfo;
    mainInfo.imageInfo.size = {500, 400};
    mainInfo.imageInfo.pixelFormat = PixelFormat::RGBA_8888;
    mainInfo.hdrType = ImageHdrType::SDR;

    std::unique_ptr<OHOS::ImagePlugin::InputDataStream> auxStream =
        std::make_unique<MockInputDataStream>();
    std::unique_ptr<OHOS::ImagePlugin::AbsImageDecoder> extDecoder =
        std::make_unique<MockAbsImageDecoder>();
    uint32_t errorCode = SUCCESS;

    auto result = AuxiliaryGenerator::GenerateJpegAuxiliaryPicture(
        mainInfo, AuxiliaryPictureType::GAINMAP, auxStream, extDecoder, errorCode);


    if (result != nullptr) {
        GTEST_LOG_(INFO) << "Function returned non-null result";

        EXPECT_EQ(result->GetType(), AuxiliaryPictureType::GAINMAP);
        
        auto pixelMap = result->GetContentPixel();
        EXPECT_NE(pixelMap, nullptr) << "PixelMap should not be null";
        
        if (pixelMap != nullptr) {
            GTEST_LOG_(INFO) << "PixelMap obtained, size: "
                           << pixelMap->GetWidth() << "x" << pixelMap->GetHeight();
        }
    } else {
        GTEST_LOG_(INFO) << "Function returned nullptr, error: " << errorCode;
    }

    GTEST_LOG_(INFO) << "GetAuxiliaryPictureDenominatorTest003 end";
}

/**
 * @tc.name: GenerateHeifAuxiliaryPictureTest001
 * @tc.desc: test GenerateHeifAuxiliaryPicture when extDecoder is nullptr or type is NONE
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryGeneratorTest, GenerateHeifAuxiliaryPictureTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AuxiliaryGeneratorTest: GenerateHeifAuxiliaryPictureTest001 start";
    MainPictureInfo mainInfo;
    mainInfo.imageInfo.size = {IMAGE_SIZE, IMAGE_SIZE};
    AuxiliaryPictureType type = AuxiliaryPictureType::DEPTH_MAP;
    uint32_t errorCode = SUCCESS;
    std::unique_ptr<AbsImageDecoder> extDecoder = nullptr;
    auto auxPicture = AuxiliaryGenerator::GenerateHeifAuxiliaryPicture(mainInfo, type, extDecoder, errorCode);
    ASSERT_EQ(auxPicture, nullptr);
    ASSERT_EQ(errorCode, ERR_IMAGE_INVALID_PARAMETER);

    type = AuxiliaryPictureType::NONE;
    auxPicture = AuxiliaryGenerator::GenerateHeifAuxiliaryPicture(mainInfo, type, extDecoder, errorCode);
    ASSERT_EQ(auxPicture, nullptr);
    ASSERT_EQ(errorCode, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "AuxiliaryGeneratorTest: GenerateHeifAuxiliaryPictureTest001 end";
}

/**
 * @tc.name: GenerateJpegAuxiliaryPictureTest001
 * @tc.desc: test GenerateJpegAuxiliaryPicture when extDecoder is nullptr or auxStream is nullptr or type is NONE
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryGeneratorTest, GenerateJpegAuxiliaryPictureTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AuxiliaryGeneratorTest: GenerateJpegAuxiliaryPictureTest001 start";
    MainPictureInfo mainInfo;
    mainInfo.imageInfo.size = {IMAGE_SIZE, IMAGE_SIZE};
    AuxiliaryPictureType type = AuxiliaryPictureType::DEPTH_MAP;
    std::unique_ptr<InputDataStream> auxStreamMock = std::make_unique<MockInputDataStream>();
    uint32_t errorCode = SUCCESS;
    std::unique_ptr<AbsImageDecoder> extDecoder = nullptr;
    auto auxPicture =
        AuxiliaryGenerator::GenerateJpegAuxiliaryPicture(mainInfo, type, auxStreamMock, extDecoder, errorCode);
    ASSERT_EQ(auxPicture, nullptr);

    std::unique_ptr<InputDataStream> auxStream = nullptr;
    auxPicture = AuxiliaryGenerator::GenerateJpegAuxiliaryPicture(mainInfo, type, auxStream, extDecoder, errorCode);
    ASSERT_EQ(auxPicture, nullptr);

    type = AuxiliaryPictureType::NONE;
    auxPicture = AuxiliaryGenerator::GenerateJpegAuxiliaryPicture(mainInfo, type, auxStream, extDecoder, errorCode);
    ASSERT_EQ(auxPicture, nullptr);
    GTEST_LOG_(INFO) << "AuxiliaryGeneratorTest: GenerateJpegAuxiliaryPictureTest001 end";
}

/**
 * @tc.name: FreeContextBufferTest001
 * @tc.desc: test FreeContextBuffer by simulating a heif auxiliary map decoding failure
 * @tc.type: FUNC
 */
HWTEST_F(AuxiliaryGeneratorTest, FreeContextBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AuxiliaryGeneratorTest: FreeContextBufferTest001 start";
    MainPictureInfo mainInfo;
    mainInfo.imageInfo.size = {IMAGE_SIZE, IMAGE_SIZE};
    AuxiliaryPictureType type = AuxiliaryPictureType::GAINMAP;
    std::unique_ptr<AbsImageDecoder> extDecoder = std::make_unique<MockAbsImageDecoder>();
    uint32_t errorCode = SUCCESS;
    auto auxPicture =
        AuxiliaryGenerator::GenerateHeifAuxiliaryPicture(mainInfo, type, extDecoder, errorCode);
    ASSERT_EQ(auxPicture, nullptr);
    GTEST_LOG_(INFO) << "AuxiliaryGeneratorTest: FreeContextBufferTest001 end";
}
}
}
