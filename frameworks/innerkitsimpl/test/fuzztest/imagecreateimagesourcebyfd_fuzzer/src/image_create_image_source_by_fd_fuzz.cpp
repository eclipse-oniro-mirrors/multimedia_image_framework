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

#include "image_create_image_source_by_fd_fuzz.h"

#define private public
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>

#include "ext_decoder.h"
#include "image_source.h"
#include "metadata_accessor_factory.h"
#include "svg_decoder.h"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
void ExtDecoderFuncTest001(int fd)
{
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(fd, srcOpts, errorCode);
    Media::DecodeOptions dopts;
    imageSource->CreatePixelMap(dopts, errorCode);

    imageSource->sourceInfo_.encodedFormat = "image/x-skia";
    auto extDecoder = static_cast<ExtDecoder*>(imageSource->CreateDecoder(errorCode));
    DecodeContext context;
    extDecoder->HeifYUVMemAlloc(context);
    int dWidth;
    int dHeight;
    float scale;
    extDecoder->GetScaledSize(dWidth, dHeight, scale);
    extDecoder->GetHardwareScaledSize(dWidth, dHeight, scale);
    extDecoder->IsSupportScaleOnDecode();
    PixelDecodeOptions plOpts;
    PlImageInfo plInfo;
    extDecoder->SetDecodeOptions(0, plOpts, plInfo);
    PlPixelFormat dstFormat = PlPixelFormat::UNKNOWN;
    extDecoder->PreDecodeCheckYuv(0, dstFormat);
    extDecoder->DoHardWareDecode(context);
    extDecoder->GetJpegYuvOutFmt(dstFormat);
    extDecoder->DecodeToYuv420(0, context);
    OHOS::HDI::Codec::Image::V1_0::CodecImageBuffer outputBuffer;
    extDecoder->AllocOutputBuffer(context, outputBuffer);
    extDecoder->CheckContext(context);
    AllocatorType allocatorType = AllocatorType::DEFAULT;
    extDecoder->ReleaseOutputBuffer(context, allocatorType);
    extDecoder->HardWareDecode(context);
    SkAlphaType alphaType;
    PlAlphaType outputType;
    extDecoder->ConvertInfoToAlphaType(alphaType, outputType);
    SkColorType format;
    PlPixelFormat outputFormat;
    extDecoder->ConvertInfoToColorType(format, outputFormat);
    std::string key = "ImageWidth";
    std::string value = "500";
    int32_t valInt = 0;
    extDecoder->GetImagePropertyInt(0, key, valInt);
    extDecoder->GetImagePropertyString(0, key, value);
    extDecoder->GetMakerImagePropertyString(key, value);
    extDecoder->DoHeifToYuvDecode(context);
    extDecoder->Reset();

    DecodeOptions dstOpts;
    imageSource = ImageSource::CreateImageSource(fd, srcOpts, errorCode);
    imageSource->CreatePixelMap(0, dstOpts, errorCode);
    imageSource->Reset();
}

void SvgDecoderFuncTest001(int fd)
{
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(fd, srcOpts, errorCode);

    imageSource->sourceInfo_.encodedFormat = "image/svg+xml";
    auto svgDecoder = static_cast<SvgDecoder*>(imageSource->CreateDecoder(errorCode));
    PixelDecodeOptions plOpts;
    PlImageInfo plInfo;
    svgDecoder->SetDecodeOptions(0, plOpts, plInfo);
    DecodeContext context;
    svgDecoder->Decode(0, context);
    uint32_t num;
    svgDecoder->GetTopLevelImageNum(num);
    context.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    svgDecoder->AllocBuffer(context);
    context.allocatorType = AllocatorType::DMA_ALLOC;
    svgDecoder->AllocBuffer(context);
    context.allocatorType = AllocatorType::HEAP_ALLOC;
    svgDecoder->AllocBuffer(context);
    svgDecoder->DoSetDecodeOptions(0, plOpts, plInfo);
    PlSize plSize;
    svgDecoder->DoGetImageSize(0, plSize);
    svgDecoder->DoDecode(0, context);

    DecodeOptions dstOpts;
    imageSource = ImageSource::CreateImageSource(fd, srcOpts, errorCode);
    imageSource->CreatePixelMapExtended(0, dstOpts, errorCode);
    imageSource->Reset();
}

void MetadataAccessorFuncTest001(std::shared_ptr<MetadataAccessor>& metadataAccessor)
{
    metadataAccessor->Read();
    auto exifMetadata = metadataAccessor->Get();
    if (exifMetadata == nullptr) {
        return;
    }
    std::string key = "ImageWidth";
    exifMetadata->SetValue(key, "500");
    std::string value;
    exifMetadata->GetValue(key, value);
    metadataAccessor->Write();
    metadataAccessor->Set(exifMetadata);
    DataBuf inputBuf;
    metadataAccessor->ReadBlob(inputBuf);
    metadataAccessor->WriteBlob(inputBuf);
}

void CreateImageSourceByFDFuzz(const uint8_t* data, size_t size)
{
    std::string pathName = "/tmp/test.jpg";
    int fd = open(pathName.c_str(), O_RDWR, O_CREAT);
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        return;
    }
    ExtDecoderFuncTest001(fd);
    SvgDecoderFuncTest001(fd);
    BufferMetadataStream::MemoryMode mode = BufferMetadataStream::MemoryMode::Dynamic;
    std::shared_ptr<MetadataAccessor> metadataAccessor1 = MetadataAccessorFactory::Create(const_cast<uint8_t*>(data),
        size, mode);
    MetadataAccessorFuncTest001(metadataAccessor1);
    std::shared_ptr<MetadataAccessor> metadataAccessor2 = MetadataAccessorFactory::Create(fd);
    MetadataAccessorFuncTest001(metadataAccessor2);
    std::shared_ptr<MetadataAccessor> metadataAccessor3 = MetadataAccessorFactory::Create(pathName);
    MetadataAccessorFuncTest001(metadataAccessor3);
    close(fd);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::CreateImageSourceByFDFuzz(data, size);
    return 0;
}