/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "image_png_plugin_fuzz.h"

#define private public
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>

#include "convert_utils.h"
#include "image_source.h"
#include "png_decoder.h"
#include "nine_patch_listener.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PNG_PLUGIN_FUZZ"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;

const std::string NINE_PATCH = "ninepatch";

void DoPrivateFun(PngDecoder* pngDecoder)
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
    png_byte chunkData[] = { 0, 0, 0, 0, 'I', 'D', 'A', 'T' };
    pngDecoder->IsChunk(const_cast<png_byte *>(&chunkData[0]), "IDAT");
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void PngDecoderFuncTest001(int fd)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(fd, srcOpts, errorCode);

    imageSource->sourceInfo_.encodedFormat = "image/png";
    auto pngDecoder = static_cast<PngDecoder*>(imageSource->CreateDecoder(errorCode));
    if (pngDecoder == nullptr) {
        return;
    }
    pngDecoder->HasProperty(NINE_PATCH);
    if (SUCCESS != pngDecoder->DecodeHeader()) {
        IMAGE_LOGI("%{public}s png DecodeHeader failed", __func__);
        return;
    }
    PixelDecodeOptions plOpts;
    PlImageInfo plInfo;
    pngDecoder->SetDecodeOptions(0, plOpts, plInfo);
    DecodeContext context;
    if (pngDecoder->Decode(0, context) != SUCCESS) {
        pngDecoder->Reset();
        delete pngDecoder;
        pngDecoder = nullptr;
        return;
    }
    DoPrivateFun(pngDecoder);
    Size size;
    pngDecoder->GetImageSize(0, size);
    ProgDecodeContext progContext;
    pngDecoder->PromoteIncrementalDecode(0, progContext);
    pngDecoder->SetSource(*(pngDecoder->inputStreamPtr_));
    pngDecoder->Reset();
    delete pngDecoder;
    pngDecoder = nullptr;
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void CreateImageSourceByFDFuzz001(const uint8_t* data, size_t size)
{
    int fd = ConvertDataToFd(data, size, "image/png");
    if (fd < 0) {
        return;
    }
    PngDecoderFuncTest001(fd);
    close(fd);
}

void CreateImageSourceByNinePatchFuzz001(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    NinePatchListener ninepath;
    const std::string tag = "npTc";
    ninepath.ReadChunk(tag, reinterpret_cast<void *>(const_cast<uint8_t *>(data)), size);

    float scaleX = 1.0;
    float scaleY = 2.0;
    int32_t scaledWidth = 3;
    int32_t scaledHeight = 4;
    ninepath.Scale(scaleX, scaleY, scaledWidth, scaledHeight);
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::CreateImageSourceByFDFuzz001(data, size);
    OHOS::Media::CreateImageSourceByNinePatchFuzz001(data, size);
    return 0;
}