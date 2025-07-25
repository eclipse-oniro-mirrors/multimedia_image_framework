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
#include <fuzzer/FuzzedDataProvider.h>
#include "image_png_plugin_fuzz.h"

#define private public
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>

#include "common_fuzztest_function.h"
#include "image_source.h"
#include "png_decoder.h"
#include "nine_patch_listener.h"
#include "image_log.h"
#include "data_buf.h"
#include "png_image_chunk_utils.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PNG_PLUGIN_FUZZ"

constexpr uint32_t OPT_SIZE = 40;
constexpr size_t OFFSET_ZERO = 0;
constexpr uint8_t BYTE_ONE = 1;
constexpr uint8_t TEXTCHUNKTYPE_MODULE = 3;

namespace OHOS {
namespace Media {
FuzzedDataProvider *FDP;
const std::string NINE_PATCH = "ninepatch";
using namespace OHOS::ImagePlugin;

void DoPrivateFun(PngDecoder *pngDecoder)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    DecodeContext context;
    pngDecoder->AllocOutputBuffer(context);
    uint32_t num;
    pngDecoder->GetTopLevelImageNum(num);
    png_structp pngPtr = nullptr;
    png_const_charp message;
    pngDecoder->PngWarning(pngPtr, message);
    pngDecoder->PngWarningMessage(pngPtr, message);
    pngDecoder->PngErrorMessage(pngPtr, message);
    png_bytep row = nullptr;
    png_uint_32 rowNum = 0;
    int pass = 0;
    pngDecoder->GetAllRows(pngPtr, row, rowNum, pass);
    pngDecoder->GetInterlacedRows(pngPtr, row, rowNum, pass);
    png_structp png_ptr = nullptr;
    png_unknown_chunkp chunk = nullptr;
    pngDecoder->ReadUserChunk(png_ptr, chunk);
    rowNum = 1;
    pngDecoder->SaveRows(const_cast<png_bytep>(new uint8_t), rowNum);
    pngDecoder->SaveInterlacedRows(const_cast<png_bytep>(new uint8_t), rowNum, pass);
    PngImageInfo info;
    pngDecoder->ReadIncrementalHead(nullptr, info);
    png_byte chunkData[] = {0, 0, 0, 0, 'I', 'D', 'A', 'T'};
    pngDecoder->IsChunk(const_cast<png_byte *>(&chunkData[0]), "IDAT");
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void PngDecoderFuncTest001(const std::string &filename)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(filename, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    imageSource->sourceInfo_.encodedFormat = "image/png";
    auto pngDecoder = static_cast<PngDecoder *>(imageSource->CreateDecoder(errorCode));
    if (pngDecoder == nullptr) {
        return;
    }
    pngDecoder->HasProperty(NINE_PATCH);
    if (SUCCESS != pngDecoder->DecodeHeader()) {
        IMAGE_LOGI("%{public}s png DecodeHeader failed", __func__);
        delete pngDecoder;
        pngDecoder = nullptr;
        return;
    }
    PixelDecodeOptions plOpts;
    SetFdpPixelDecodeOptions(FDP, plOpts);

    PlImageInfo plInfo;
    pngDecoder->SetDecodeOptions(0, plOpts, plInfo);
    DecodeContext context;
    if (pngDecoder->Decode(0, context) != SUCCESS) {
        pngDecoder->Reset();
        delete pngDecoder;
        pngDecoder = nullptr;
        return;
    }
    Size size;
    pngDecoder->GetImageSize(0, size);
    DoPrivateFun(pngDecoder);
    ProgDecodeContext progContext;
    pngDecoder->PromoteIncrementalDecode(0, progContext);
    pngDecoder->SetSource(*(pngDecoder->inputStreamPtr_));
    pngDecoder->Reset();
    delete pngDecoder;
    pngDecoder = nullptr;
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void CreateImageSourceByFDFuzz001(const uint8_t *data, size_t size)
{
    std::string filename = "/data/local/tmp/test_decode_png.png";
    if (!WriteDataToFile(data, size, filename)) {
        IMAGE_LOGE("WriteDataToFile failed");
        return;
    }
    PngDecoderFuncTest001(filename);
}

void CreateImageSourceByNinePatchFuzz001(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    NinePatchListener ninepath;
    const std::string tag = "npTc";
    ninepath.ReadChunk(tag, reinterpret_cast<void *>(const_cast<uint8_t *>(data)), size);

    float scaleX = FDP->ConsumeFloatingPoint<float>();
    float scaleY = FDP->ConsumeFloatingPoint<float>();
    int32_t scaledWidth = FDP->ConsumeIntegral<int32_t>();
    int32_t scaledHeight = FDP->ConsumeIntegral<int32_t>();
    ninepath.Scale(scaleX, scaleY, scaledWidth, scaledHeight);
}

void PngImageChunkUtilsTest()
{
    size_t bufferSize = FDP->ConsumeIntegral<size_t>();
    DataBuf chunkData(bufferSize);
    DataBuf tiffData(bufferSize);
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ONE);
    bool isCompressed = FDP->ConsumeBool();
    PngImageChunkUtils::TextChunkType textChunkType =
        static_cast<PngImageChunkUtils::TextChunkType>(FDP->ConsumeIntegral<uint8_t>() % TEXTCHUNKTYPE_MODULE);
    PngImageChunkUtils::ParseTextChunk(chunkData, textChunkType, tiffData, isCompressed);
    PngImageChunkUtils::FindExifFromTxt(chunkData);
}

}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (size < OPT_SIZE) {
        return -1;
    }
    FuzzedDataProvider fdp(data + size - OPT_SIZE, OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    uint8_t action = fdp.ConsumeBool();
    switch (action) {
        case 0:
            OHOS::Media::CreateImageSourceByFDFuzz001(data, size);
            break;
        case 1:
            OHOS::Media::CreateImageSourceByNinePatchFuzz001(data, size);
            break;
        default:
            OHOS::Media::PngImageChunkUtilsTest();
            break;
    }
    return 0;
}
