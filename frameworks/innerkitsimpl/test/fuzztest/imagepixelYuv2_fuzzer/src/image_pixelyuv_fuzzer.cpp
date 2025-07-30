/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "image_pixelyuv_fuzzer.h"
#include "common_fuzztest_function.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <securec.h>
#define protected public
#define private public
#include "pixel_map.h"

#include "image_log.h"
#include "image_source.h"
#include "pixel_yuv.h"
#include "pixel_yuv_ext_utils.h"

namespace OHOS {
namespace Media {

FuzzedDataProvider* FDP;
static constexpr uint32_t OPT_SIZE = 40;
static constexpr uint32_t DEGREES_MODULO = 4;
static constexpr uint32_t YUVFORMATS_MODULO = 4;

void PixelMapYuvFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data, size, opts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    DecodeOptions decodeOpts;
    SetFdpDecodeOptions(FDP, decodeOpts);
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    if (pixelMap == nullptr) {
        return;
    }

    float degrees = FDP->ConsumeFloatingPoint<float>();
    pixelMap->rotate(degrees);

    float dstWidth = FDP->ConsumeFloatingPoint<float>();
    float dstHeight = FDP->ConsumeFloatingPoint<float>();
    AntiAliasingOption option = static_cast<AntiAliasingOption>(FDP->ConsumeIntegral<uint8_t>() % 11);
    pixelMap->scale(dstWidth, dstHeight, option);
}

std::unique_ptr<PixelMap> CreateYuvPixelMap(std::string pathName)
{
    SourceOptions opts;
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imageSource == nullptr) {
        return nullptr;
    }
    DecodeOptions decodeOpts;
    std::vector<PixelFormat> yuvFormats = {
        PixelFormat::NV12,
        PixelFormat::NV21,
        PixelFormat::YCRCB_P010,
        PixelFormat::YCBCR_P010,
    };
    uint32_t index = FDP->ConsumeIntegral<uint32_t>() % YUVFORMATS_MODULO;
    decodeOpts.desiredPixelFormat = yuvFormats[index];
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    return pixelMap;
}

void PixelYuvUtilsFuzzTest(std::string pathName)
{
    std::unique_ptr<PixelMap> pixelMap = CreateYuvPixelMap(pathName);
    PixelYuv* pixelYuv = reinterpret_cast<PixelYuv*>(pixelMap.get());
    Size srcSize;
    srcSize.width = FDP->ConsumeIntegral<uint32_t>();
    srcSize.height = FDP->ConsumeIntegral<uint32_t>();
    std::vector<int32_t> degrees = {0, 90, 180, 270};
    int32_t count = FDP->ConsumeIntegral<uint32_t>() % DEGREES_MODULO;
    int32_t degree = degrees[count];
    Size dstSize;
    dstSize.width = FDP->ConsumeIntegral<uint32_t>();
    dstSize.height = FDP->ConsumeIntegral<uint32_t>();
    OpenSourceLibyuv::RotationMode rotateNum;
    YUVDataInfo yuvDataInfo;
    pixelYuv->YuvRotateConvert(srcSize, degree, dstSize, rotateNum, yuvDataInfo);
    float rotateDegrees = 90;
    pixelYuv->rotate(rotateDegrees);
    float xAxis = 0.5;
    float yAxis = 0.5;
    pixelYuv->resize(xAxis, yAxis);
    bool flipxAxis = true;
    bool flipyAxis = true;
    pixelYuv->flip(flipxAxis, flipyAxis);
}

void PixelYuvExtUtilsFuzzTest(std::string pathName)
{
#ifdef EXT_PIXEL
    std::unique_ptr<PixelMap> pixelMap = CreateYuvPixelMap(pathName);
    if (pixelMap == nullptr) {
        return;
    }
    std::vector<uint8_t> dstArgb = {};
    Size size;
    PixelFormat pixelFormat = static_cast<PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    YUVDataInfo info;
    PixelYuvExtUtils::Yuv420ToARGB(pixelMap->data_, dstArgb.data(), size, pixelFormat, info);
    
    pixelMap = CreateYuvPixelMap(pathName);
    if (pixelMap == nullptr) {
        return;
    }
    PixelSize nv12RotateSize;
    OpenSourceLibyuv::RotationMode rotateNum;
    std::vector<uint8_t> dstNV12Rotate = {};
    YUVStrideInfo dstStrides;
    PixelYuvExtUtils::NV12Rotate(pixelMap->data_, nv12RotateSize, info, rotateNum, dstNV12Rotate.data(), dstStrides);

    pixelMap = CreateYuvPixelMap(pathName);
    if (pixelMap == nullptr) {
        return;
    }
    const PixelFormat format = pixelMap->GetPixelFormat();
    Size dstSize;
    std::vector<uint8_t> dstYuvRotate = {};
    PixelYuvExtUtils::YuvRotate(pixelMap->data_, format, info, dstSize, dstYuvRotate.data(), dstStrides, rotateNum);

    pixelMap = CreateYuvPixelMap(pathName);
    if (pixelMap == nullptr) {
        return;
    }
    float xAxis = FDP->ConsumeFloatingPoint<float>();
    float yAxis = FDP->ConsumeFloatingPoint<float>();
    const AntiAliasingOption option = static_cast<AntiAliasingOption>(FDP->ConsumeIntegral<int32_t>() % 11);
    YuvImageInfo scaleYuvInfo;
    std::vector<uint8_t> dstYuv420 = {};
    PixelYuvExtUtils::ScaleYuv420(xAxis, yAxis, option, scaleYuvInfo, pixelMap->data_, dstYuv420.data(), dstStrides);

    pixelMap = CreateYuvPixelMap(pathName);
    if (pixelMap == nullptr) {
        return;
    }
    int32_t dstWidth = FDP->ConsumeIntegral<int32_t>();
    int32_t dstHeight = FDP->ConsumeIntegral<int32_t>();
    YuvImageInfo yuvInfo;
    std::vector<uint8_t> dst = {};
    PixelYuvExtUtils::ScaleYuv420(dstWidth, dstHeight, option, yuvInfo, pixelMap->data_, dst.data(), dstStrides);
#endif
}
}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    OHOS::Media::PixelMapYuvFuzzTest(data, size);
    static const std::string pathName = "/data/local/tmp/test_decode_bmp.bmp";
    WriteDataToFile(data, size - OHOS::Media::OPT_SIZE, pathName);
    OHOS::Media::PixelYuvUtilsFuzzTest(pathName);
    OHOS::Media::PixelYuvExtUtilsFuzzTest(pathName);
    return 0;
}
