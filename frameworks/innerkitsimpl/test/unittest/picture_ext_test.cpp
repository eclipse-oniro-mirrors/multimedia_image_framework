/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <fstream>
#include <cstring>
#include <surface.h>
#include "picture.h"
#include "picture_native_impl.h"
#include "image_source.h"
#include "image_utils.h"
#include "image_packer.h"
#include "image_packer_native.h"
#include "image_packer_native_impl.h"
#include "media_errors.h"
#include "securec.h"
using namespace OHOS::Media;
using namespace testing::ext;
namespace OHOS {
namespace Multimedia {

static const int32_t SIZE_WIDTH = 2;
static const int32_t SIZE_HEIGHT = 3;
static const int32_t STRIDE_ALIGNMENT = 8;
static const int32_t BUFFER_SIZE = 256;
static const int32_t DEFAULT_BUFF_SIZE = 25 * 1024 * 1024;
static const int32_t DEFAULT_QUALITY = 98;
static const std::string IMAGE_JPEG_SRC = "/data/local/tmp/image/test_jpeg.jpg";
static const std::string IMAGE_JPEG_DEST = "/data/local/tmp/image/test_jpeg_out.jpg";
static const std::string IMAGE_HEIF_SRC = "/data/local/tmp/image/test_heif.heic";
static const std::string IMAGE_HEIF_DEST = "/data/local/tmp/image/test_heif_out.heic";
static const std::string IMAGE_INPUT_JPEGHDR_PATH = "/data/local/tmp/image/test_jpeg_hdr.jpg";
static const std::string IMAGE_INPUT_HEIFHDR_PATH = "/data/local/tmp/image/test_heif_hdr.heic";

class PictureExtTest : public testing::Test {
public:
    PictureExtTest() {}
    ~PictureExtTest() {}
};

static std::shared_ptr<Picture> ImageSourceCreatePicture(std::string srcFormat, std::string srcPathName)
{
    uint32_t errorCode = -1;
    SourceOptions opts;
    opts.formatHint = srcFormat;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(srcPathName.c_str(), opts, errorCode);
    EXPECT_EQ(errorCode, OHOS::Media::SUCCESS);
    EXPECT_NE(imageSource.get(), nullptr);

    DecodeOptions dstOpts;
    dstOpts.desiredPixelFormat = PixelFormat::NV12;
    std::shared_ptr<PixelMap> pixelMap = imageSource->CreatePixelMapEx(0, dstOpts, errorCode);
    EXPECT_EQ(errorCode, OHOS::Media::SUCCESS);
    EXPECT_NE(pixelMap, nullptr);

    std::unique_ptr<Picture> tmpPicture = Picture::Create(pixelMap);
    EXPECT_NE(tmpPicture, nullptr);
    std::shared_ptr<Picture> picture = std::move(tmpPicture);
    EXPECT_NE(picture, nullptr);
    return picture;
}

static OH_PictureNative* CreatePictureNative()
{
    std::string realPath;
    if (!ImageUtils::PathToRealPath(IMAGE_JPEG_SRC.c_str(), realPath)) {
        return nullptr;
    }
    if (realPath.c_str() == nullptr) {
        return nullptr;
    }
    char filePath[BUFFER_SIZE];
    if (strcpy_s(filePath, sizeof(filePath), realPath.c_str()) != EOK) {
        return nullptr;
    }
    size_t length = realPath.size();
    OH_ImageSourceNative *source = nullptr;

    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromUri(filePath, length, &source);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    if (source == nullptr) {
        return nullptr;
    }

    OH_DecodingOptions *opts = nullptr;
    OH_PixelmapNative *pixelmap = nullptr;
    OH_DecodingOptions_Create(&opts);
    int32_t format = PIXEL_FORMAT_NV12;
    OH_DecodingOptions_SetPixelFormat(opts, format);
    ret = OH_ImageSourceNative_CreatePixelmap(source, opts, &pixelmap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_DecodingOptions_Release(opts);

    OH_PictureNative *picture = nullptr;
    ret = OH_PictureNative_CreatePicture(pixelmap, &picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    return picture;
}

OH_PictureNative *CreateNativePicture(std::vector<Image_AuxiliaryPictureType>& ayxTypeList)
{
    std::string realPath;
    if (!ImageUtils::PathToRealPath(IMAGE_INPUT_JPEGHDR_PATH.c_str(), realPath)) {
        return nullptr;
    }
    if (realPath.c_str() == nullptr) {
        return nullptr;
    }
    char filePath[BUFFER_SIZE];
    if (strcpy_s(filePath, sizeof(filePath), realPath.c_str()) != EOK) {
        return nullptr;
    }
    size_t length = realPath.size();
    OH_ImageSourceNative *source = nullptr;

    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromUri(filePath, length, &source);
    if (source == nullptr) {
        return nullptr;
    }

    OH_DecodingOptions *opts = nullptr;
    OH_PixelmapNative *pixelmap = nullptr;
    OH_DecodingOptions_Create(&opts);
    if (opts == nullptr) {
        return nullptr;
    }
    OH_DecodingOptionsForPicture *options = nullptr;
    ret = OH_DecodingOptionsForPicture_Create(&options);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    if (options == nullptr) {
        return nullptr;
    }

    ret = OH_ImageSourceNative_CreatePixelmap(source, opts, &pixelmap);
    ret = OH_DecodingOptionsForPicture_SetDesiredAuxiliaryPictures(options, ayxTypeList.data(), ayxTypeList.size());

    OH_PictureNative *picture = nullptr;
    ret = OH_PictureNative_CreatePicture(pixelmap, &picture);
    ret = OH_ImageSourceNative_CreatePicture(source, options, &picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_DecodingOptions_Release(opts);
    EXPECT_NE(picture, nullptr);
    return picture;
}

/**
 * @tc.name: CreatePicture001
 * @tc.desc: Tests whether the ImageSource class can correctly return a null pointer
 *           when creating a Picture object with default parameters.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, CreatePicture001, TestSize.Level3)
{
    uint32_t errorCode = -1;
    const IncrementalSourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    const DecodingOptionsForPicture opts;
    std::unique_ptr<Picture> picture = imageSource->CreatePicture(opts, errorCode);
    ASSERT_EQ(picture, nullptr);
}

/**
 * @tc.name: CreatePicture002
 * @tc.desc: Verifies that the ImageSource class can create a Picture object from a JPEG image
 *           with the specified format hint.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, CreatePicture002, TestSize.Level3)
{
    uint32_t errorCode = -1;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_JPEG_SRC, sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    const DecodingOptionsForPicture opts;
    std::unique_ptr<Picture> picture = imageSource->CreatePicture(opts, errorCode);
    ASSERT_NE(picture, nullptr);
}

/**
 * @tc.name: CreatePicture003
 * @tc.desc: Checks the successful creation of an ImageSource and Picture object from a HEIF file
 *           with default options.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, CreatePicture003, TestSize.Level3)
{
    uint32_t errorCode = -1;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_HEIF_SRC, sourceOpts, errorCode);
    ASSERT_NE(imageSource, nullptr);
    const DecodingOptionsForPicture opts;
    std::unique_ptr<Picture> picture = imageSource->CreatePicture(opts, errorCode);
    ASSERT_NE(picture, nullptr);
}

/**
 * @tc.name: EncoderPicture001
 * @tc.desc: Test packaging a jpeg image source data and writing the data to a jpeg file.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, EncoderPicture001, TestSize.Level1)
{
    auto picture = ImageSourceCreatePicture("image/jpeg", IMAGE_JPEG_SRC);
    ASSERT_NE(picture, nullptr);
    uint32_t errorCode = -1;

    const int fileSize = 1024 * 1024 * 10;
    ImagePacker pack;
    std::vector<uint8_t> outputData(fileSize);
    ASSERT_EQ(outputData.size(), fileSize);
    PackOption option;
    option.format = "image/jpeg";
    uint32_t startpc = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    std::ofstream fileDestJpg(IMAGE_JPEG_DEST, std::ios::binary);
    ASSERT_TRUE(fileDestJpg.is_open());
    uint32_t retAddPicture = pack.AddPicture(*picture);
    ASSERT_EQ(retAddPicture, OHOS::Media::SUCCESS);
    int64_t packedSize = 0;
    uint32_t retFinalizePacking = pack.FinalizePacking(packedSize);
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    fileDestJpg.write(reinterpret_cast<char *>(outputData.data()), packedSize);
    ASSERT_FALSE(fileDestJpg.bad());
    fileDestJpg.close();
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSourceDest =
        ImageSource::CreateImageSource(outputData.data(), fileSize, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
}

/**
 * @tc.name: EncoderPicture002
 * @tc.desc: Test packaging a jpeg image source data into a jpeg file.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, EncoderPicture002, TestSize.Level1)
{
    auto picture = ImageSourceCreatePicture("image/jpeg", IMAGE_JPEG_SRC);
    ASSERT_NE(picture, nullptr);
    uint32_t errorCode = -1;

    ImagePacker pack;
    PackOption option;
    option.format = "image/jpeg";
    uint32_t startpc = pack.StartPacking(IMAGE_JPEG_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddPicture = pack.AddPicture(*picture);
    ASSERT_EQ(retAddPicture, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_JPEG_DEST, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
}

/**
 * @tc.name: EncoderPicture003
 * @tc.desc: Test packing a jpeg image source data and writing it to a jpeg file through an output stream.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, EncoderPicture003, TestSize.Level1)
{
    auto picture = ImageSourceCreatePicture("image/jpeg", IMAGE_JPEG_SRC);
    ASSERT_NE(picture, nullptr);

    ImagePacker pack;
    PackOption option;
    option.format = "image/jpeg";
    std::ofstream stream(IMAGE_JPEG_DEST, std::ios::binary);
    ASSERT_TRUE(stream.is_open());
    uint32_t startpc = pack.StartPacking(stream, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddPicture = pack.AddPicture(*picture);
    ASSERT_EQ(retAddPicture, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
}

/**
 * @tc.name: EncoderPicture004
 * @tc.desc: Test packaging a jpeg image source data into a file descriptor.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, EncoderPicture004, TestSize.Level1)
{
    auto picture = ImageSourceCreatePicture("image/jpeg", IMAGE_JPEG_SRC);
    ASSERT_NE(picture, nullptr);
    uint32_t errorCode = -1;

    ImagePacker pack;
    const int fd = open(IMAGE_JPEG_DEST.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    PackOption option;
    option.format = "image/jpeg";
    uint32_t startpc = pack.StartPacking(fd, option);
    close(fd);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddPicture = pack.AddPicture(*picture);
    ASSERT_EQ(retAddPicture, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);

    const int fdDest = open(IMAGE_JPEG_DEST.c_str(), O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_NE(fdDest, -1);
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(fdDest, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
    close(fdDest);
}

/**
 * @tc.name: EncoderPicture005
 * @tc.desc: Test packaging a heif image source data and writing the data to a heif file.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, EncoderPicture005, TestSize.Level1)
{
    auto picture = ImageSourceCreatePicture("image/heif", IMAGE_HEIF_SRC);
    ASSERT_NE(picture, nullptr);
    uint32_t errorCode = -1;

    const int fileSize = 1024 * 1024 * 10;
    ImagePacker pack;
    std::vector<uint8_t> outputData(fileSize);
    ASSERT_EQ(outputData.size(), fileSize);
    PackOption option;
    option.format = "image/heif";
    uint32_t startpc = pack.StartPacking(outputData.data(), fileSize, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    std::ofstream fileDestHeif(IMAGE_HEIF_DEST, std::ios::binary);
    ASSERT_TRUE(fileDestHeif.is_open());
    uint32_t retAddPicture = pack.AddPicture(*picture);
    ASSERT_EQ(retAddPicture, OHOS::Media::SUCCESS);
    int64_t packedSize = 0;
    uint32_t retFinalizePacking = pack.FinalizePacking(packedSize);
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    fileDestHeif.write(reinterpret_cast<char *>(outputData.data()), packedSize);
    ASSERT_FALSE(fileDestHeif.bad());
    fileDestHeif.close();
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSourceDest =
        ImageSource::CreateImageSource(outputData.data(), fileSize, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
}

/**
 * @tc.name: EncoderPicture006
 * @tc.desc: Test packaging a heif image source data into a heif file.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, EncoderPicture006, TestSize.Level1)
{
    auto picture = ImageSourceCreatePicture("image/heif", IMAGE_HEIF_SRC);
    ASSERT_NE(picture, nullptr);
    uint32_t errorCode = -1;

    ImagePacker pack;
    PackOption option;
    option.format = "image/heif";
    uint32_t startpc = pack.StartPacking(IMAGE_HEIF_DEST, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddPicture = pack.AddPicture(*picture);
    ASSERT_EQ(retAddPicture, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(IMAGE_HEIF_DEST, opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
}

/**
 * @tc.name: EncoderPicture007
 * @tc.desc: Test packing a heif image source data and writing it to a heif file through an output stream.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, EncoderPicture007, TestSize.Level1)
{
    auto picture = ImageSourceCreatePicture("image/heif", IMAGE_HEIF_SRC);
    ASSERT_NE(picture, nullptr);
    uint32_t errorCode = -1;

    ImagePacker pack;
    PackOption option;
    option.format = "image/heif";
    std::ofstream stream(IMAGE_HEIF_DEST, std::ios::binary);
    ASSERT_TRUE(stream.is_open());
    uint32_t startpc = pack.StartPacking(stream, option);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddPicture = pack.AddPicture(*picture);
    ASSERT_EQ(retAddPicture, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);
    std::unique_ptr<std::ifstream> istreamDest = std::make_unique<std::ifstream>(IMAGE_HEIF_DEST, std::ios::binary);
    ASSERT_TRUE(istreamDest->is_open());
    SourceOptions opts;
    std::unique_ptr<ImageSource> ImageSourceDest =
        ImageSource::CreateImageSource(std::move(istreamDest), opts, errorCode);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(ImageSourceDest, nullptr);
}

/**
 * @tc.name: EncoderPicture008
 * @tc.desc: Test packaging a heif image source data into a file descriptor.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, EncoderPicture008, TestSize.Level1)
{
    auto picture = ImageSourceCreatePicture("image/heif", IMAGE_HEIF_SRC);
    ASSERT_NE(picture, nullptr);
    uint32_t errorCode = -1;

    ImagePacker pack;
    const int fd = open(IMAGE_HEIF_DEST.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_NE(fd, -1);
    PackOption option;
    option.format = "image/heif";
    uint32_t startpc = pack.StartPacking(fd, option);
    close(fd);
    ASSERT_EQ(startpc, OHOS::Media::SUCCESS);
    uint32_t retAddPicture = pack.AddPicture(*picture);
    ASSERT_EQ(retAddPicture, OHOS::Media::SUCCESS);
    uint32_t retFinalizePacking = pack.FinalizePacking();
    ASSERT_EQ(retFinalizePacking, OHOS::Media::SUCCESS);


    const int fdDest = open(IMAGE_HEIF_DEST.c_str(), O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_NE(fdDest, -1);
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSourceDest = ImageSource::CreateImageSource(fdDest, opts, errorCode);
    close(fdDest);
    ASSERT_EQ(errorCode, OHOS::Media::SUCCESS);
    ASSERT_NE(imageSourceDest, nullptr);
}

/**
 * @tc.name: getHDRComposedPixelmapTest001
 * @tc.desc: Verifies that HDR composed PixelMap is correctly created with expected properties from a JPEG image source.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, getHDRComposedPixelmapTest001, TestSize.Level1)
{
    uint32_t res = 0;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEGHDR_PATH.c_str(),
                                                                              sourceOpts, res);
    ASSERT_NE(imageSource, nullptr);
    DecodingOptionsForPicture opts;
    opts.desireAuxiliaryPictures.insert(AuxiliaryPictureType::GAINMAP);
    uint32_t error_code;
    std::unique_ptr<Picture> picture = imageSource->CreatePicture(opts, error_code);
    ASSERT_NE(picture, nullptr);
    std::unique_ptr<PixelMap> pixelmap = picture->GetHdrComposedPixelMap();
    ASSERT_NE(pixelmap, nullptr);
    EXPECT_TRUE(pixelmap->IsHdr());
    PixelFormat format= pixelmap->GetPixelFormat();
    EXPECT_EQ(format, PixelFormat::RGBA_1010102);
}

/**
 * @tc.name: getHDRComposedPixelmapTest002
 * @tc.desc: Verifies that HDR composed PixelMap is null when the picture is created with a fragment map
 *           auxiliary picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, getHDRComposedPixelmapTest002, TestSize.Level2)
{
    uint32_t res = 0;
    SourceOptions sourceOpts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPEGHDR_PATH.c_str(),
                                                                              sourceOpts, res);
    ASSERT_NE(imageSource, nullptr);
    DecodingOptionsForPicture opts;
    opts.desireAuxiliaryPictures.insert(AuxiliaryPictureType::FRAGMENT_MAP);
    uint32_t error_code;
    std::unique_ptr<Picture> picture = imageSource->CreatePicture(opts, error_code);
    ASSERT_NE(picture, nullptr);

    std::unique_ptr<PixelMap> pixelmap = picture->GetHdrComposedPixelMap();
    EXPECT_EQ(pixelmap, nullptr);
}

/**
 * @tc.name: getHDRComposedPixelmapTest003
 * @tc.desc: Verifies that HDR composed PixelMap is correctly created with expected properties from a HEIF image source.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, getHDRComposedPixelmapTest003, TestSize.Level1)
{
    uint32_t res = 0;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIFHDR_PATH.c_str(),
                                                                              sourceOpts, res);
    ASSERT_NE(imageSource, nullptr);
    DecodingOptionsForPicture opts;
    opts.desireAuxiliaryPictures.insert(AuxiliaryPictureType::GAINMAP);
    uint32_t error_code;
    std::unique_ptr<Picture> picture = imageSource->CreatePicture(opts, error_code);
    ASSERT_NE(picture, nullptr);
    std::unique_ptr<PixelMap> pixelmap = picture->GetHdrComposedPixelMap();
    ASSERT_NE(pixelmap, nullptr);
    EXPECT_TRUE(pixelmap->IsHdr());
    PixelFormat format= pixelmap->GetPixelFormat();
    EXPECT_EQ(format, PixelFormat::RGBA_1010102);
}

/**
 * @tc.name: getHDRComposedPixelmapTest004
 * @tc.desc: Verifies that requesting an HDR composed PixelMap from a picture with a fragment map returns null.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, getHDRComposedPixelmapTest004, TestSize.Level2)
{
    uint32_t res = 0;
    SourceOptions sourceOpts;
    sourceOpts.formatHint = "image/heif";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_HEIFHDR_PATH.c_str(),
                                                                              sourceOpts, res);
    ASSERT_NE(imageSource, nullptr);
    DecodingOptionsForPicture opts;
    opts.desireAuxiliaryPictures.insert(AuxiliaryPictureType::FRAGMENT_MAP);
    uint32_t error_code;
    std::unique_ptr<Picture> picture = imageSource->CreatePicture(opts, error_code);
    ASSERT_NE(picture, nullptr);

    std::unique_ptr<PixelMap> pixelmap = picture->GetHdrComposedPixelMap();
    EXPECT_EQ(pixelmap, nullptr);
}

/**
 * @tc.name: SetMaintenanceDataTest001
 * @tc.desc: Set maintenance data successfully.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, SetMaintenanceDataTest001, TestSize.Level1)
{
    uint8_t dataBlob[] = "Test set maintenance data";
    uint32_t size = sizeof(dataBlob);
    ASSERT_NE(size, 0);
    std::shared_ptr<Picture> picture = ImageSourceCreatePicture("image/jpeg", IMAGE_JPEG_SRC);
    ASSERT_NE(picture, nullptr);
    sptr<SurfaceBuffer> maintenanceBuffer = SurfaceBuffer::Create();
    ASSERT_NE(maintenanceBuffer, nullptr);
    BufferRequestConfig requestConfig = {
        .width = SIZE_WIDTH,
        .height = SIZE_HEIGHT,
        .strideAlignment = STRIDE_ALIGNMENT,
        .format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_BGRA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError ret = maintenanceBuffer->Alloc(requestConfig);
    ASSERT_EQ(ret, GSERROR_OK);
    bool result = memcpy_s(maintenanceBuffer->GetVirAddr(), size, dataBlob, size);
    ASSERT_EQ(result, EOK);
    result = picture->SetMaintenanceData(maintenanceBuffer);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: GetMaintenanceDataTest001
 * @tc.desc: Get maintenance data successfully.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, GetMaintenanceDataTest001, TestSize.Level1)
{
    uint8_t dataBlob[] = "Test get maintenance data";
    uint32_t size = sizeof(dataBlob);
    ASSERT_NE(size, 0);
    std::shared_ptr<Picture> picture = ImageSourceCreatePicture("image/jpeg", IMAGE_JPEG_SRC);
    ASSERT_NE(picture, nullptr);
    sptr<SurfaceBuffer> maintenanceBuffer = SurfaceBuffer::Create();
    ASSERT_NE(maintenanceBuffer, nullptr);
    BufferRequestConfig requestConfig = {
        .width = SIZE_WIDTH,
        .height = SIZE_HEIGHT,
        .strideAlignment = STRIDE_ALIGNMENT,
        .format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_BGRA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError ret = maintenanceBuffer->Alloc(requestConfig);
    ASSERT_EQ(ret, GSERROR_OK);
    bool result = memcpy_s(maintenanceBuffer->GetVirAddr(), size, dataBlob, size);
    ASSERT_EQ(result, EOK);
    auto handle = maintenanceBuffer->GetBufferHandle();
    ASSERT_NE(handle, nullptr);
    handle->size = size;
    result = picture->SetMaintenanceData(maintenanceBuffer);
    ASSERT_EQ(result, true);
    sptr<SurfaceBuffer> newMaintenanceData = picture->GetMaintenanceData();
    EXPECT_NE(newMaintenanceData, nullptr);
    EXPECT_EQ(newMaintenanceData->GetSize(), size);
}

/**
 * @tc.name: OH_ImagePackerNative_PackToDataFromPictureTest001
 * @tc.desc: Test OH_ImagePackerNative_PackToDataFromPicture with null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, OH_ImagePackerNative_PackToDataFromPictureTest001, TestSize.Level3)
{
    Image_ErrorCode res = OH_ImagePackerNative_PackToDataFromPicture(nullptr, nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(res, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_ImagePackerNative_PackToDataFromPictureTest002
 * @tc.desc: Tests packing a picture into data using OH_ImagePackerNative.
 *           The test checks if the packer and options are created, and if the picture is packed successfully.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, OH_ImagePackerNative_PackToDataFromPictureTest002, TestSize.Level1)
{
    OH_ImagePackerNative *imagePacker = nullptr;
    OH_PackingOptions *options = nullptr;
    OH_PictureNative *picture = nullptr;
    auto outData = std::make_unique<uint8_t[]>(DEFAULT_BUFF_SIZE);
    ASSERT_NE(outData, nullptr);
    size_t size = 0;
    Image_ErrorCode errCode = OH_PackingOptions_Create(&options);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(options, nullptr);
    errCode = OH_PackingOptions_SetQuality(options, DEFAULT_QUALITY);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    errCode = OH_ImagePackerNative_Create(&imagePacker);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(imagePacker, nullptr);

    Image_MimeType format;
    char formatStr[] = "image/jpeg";
    format.size = strlen(formatStr);
    format.data = formatStr;
    errCode = OH_PackingOptions_SetMimeType(options, &format);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    picture = CreatePictureNative();
    EXPECT_NE(picture, nullptr);
    errCode = OH_ImagePackerNative_PackToDataFromPicture(imagePacker, options, picture, outData.get(), &size);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    EXPECT_GT(size, 0);

    errCode = OH_PackingOptions_Release(options);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    errCode = OH_ImagePackerNative_Release(imagePacker);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    errCode = OH_PictureNative_Release(picture);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_ImagePackerNative_PackToFileFromPictureTest001
 * @tc.desc: test OH_ImagePackerNative_PackToDataFromPicture with null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, OH_ImagePackerNative_PackToFileFromPictureTest001, TestSize.Level3)
{
    int32_t fd = 0;
    Image_ErrorCode res = OH_ImagePackerNative_PackToFileFromPicture(nullptr, nullptr, nullptr, fd);
    EXPECT_EQ(res, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_ImagePackerNative_PackToFileFromPictureTest002
 * @tc.desc: Tests packing a picture into file using OH_ImagePackerNative.
 *           The test checks if the packer and options are created, and if the picture is packed successfully.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, OH_ImagePackerNative_PackToFileFromPictureTest002, TestSize.Level1)
{
    OH_ImagePackerNative *imagePacker = nullptr;
    OH_PackingOptions *options = nullptr;
    OH_PictureNative *picture = nullptr;
    Image_ErrorCode errCode = OH_PackingOptions_Create(&options);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(options, nullptr);
    errCode = OH_PackingOptions_SetQuality(options, DEFAULT_QUALITY);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    errCode = OH_ImagePackerNative_Create(&imagePacker);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_NE(imagePacker, nullptr);

    Image_MimeType format;
    char formatStr[] = "image/jpeg";
    format.size = strlen(formatStr);
    format.data = formatStr;
    errCode = OH_PackingOptions_SetMimeType(options, &format);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    picture = CreatePictureNative();
    EXPECT_NE(picture, nullptr);
    int32_t fd = 0;
    fd = open(IMAGE_JPEG_DEST.c_str(), O_WRONLY | O_CREAT);
    ASSERT_NE(fd, -1);
    errCode = OH_ImagePackerNative_PackToFileFromPicture(imagePacker, options, picture, fd);
    close(fd);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    errCode = OH_PackingOptions_Release(options);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    errCode = OH_ImagePackerNative_Release(imagePacker);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    errCode = OH_PictureNative_Release(picture);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_PictureNative_GetHdrComposedPixelmap001
 * @tc.desc: Verify retrieval of the hdr pixelmap from a native picture.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, OH_PictureNative_GetHdrComposedPixelmap001, TestSize.Level1)
{
    std::vector<Image_AuxiliaryPictureType> auxTypeList = {AUXILIARY_PICTURE_TYPE_GAINMAP};
    OH_PictureNative *picture = CreateNativePicture(auxTypeList);
    ASSERT_NE(picture, nullptr);

    OH_PixelmapNative *hdrPixelmap = nullptr;
    Image_ErrorCode ret = OH_PictureNative_GetHdrComposedPixelmap(picture, &hdrPixelmap);
    EXPECT_NE(hdrPixelmap, nullptr);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_PictureNative_Release(picture);
}

/**
 * @tc.name: OH_PictureNative_GetHdrComposedPixelmap002
 * @tc.desc: Verify error handling when attempting to retrieve the hdr pixelmap from a null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(PictureExtTest, OH_PictureNative_GetHdrComposedPixelmap002, TestSize.Level3)
{
    Image_ErrorCode ret = OH_PictureNative_GetHdrComposedPixelmap(nullptr, nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}
} // namespace Multimedia
} // namespace OHOS