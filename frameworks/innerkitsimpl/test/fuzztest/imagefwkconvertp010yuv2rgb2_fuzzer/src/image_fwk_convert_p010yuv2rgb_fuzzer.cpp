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
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "image_fwk_convert_p010yuv2rgb_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <fstream>
#include <vector>
#include <fcntl.h>

#include <filesystem>
#include <iostream>
#include <unistd.h>

#include "buffer_packer_stream.h"
#include "image_format_convert.h"
#include "image_log.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "message_parcel.h"

constexpr uint32_t MAX_LENGTH_MODULO = 0xfff;
constexpr uint32_t PIXELFORMAT_MODULO = 105;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;

void YuvP010ToRgbFuzzTest001()
{
	PixelFormat destFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
	
	Media::InitializationOptions opts;
    opts.size.width = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO;
    opts.size.height = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO;
    opts.srcPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    opts.pixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    opts.alphaType = static_cast<Media::AlphaType>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    opts.scaleMode = static_cast<Media::ScaleMode>(FDP->ConsumeIntegral<uint8_t>() % SCALEMODE_MODULO);
    opts.editable = FDP->ConsumeBool();
    opts.useSourceIfMatch = FDP->ConsumeBool();
    int32_t pixelbytes = Media::ImageUtils::GetPixelBytes(opts.srcPixelFormat);
    size_t datalength = opts.size.width * opts.size.height * pixelbytes;
    std::unique_ptr<uint8_t[]> colorData = std::make_unique<uint8_t[]>(datalength);
    if(colorData == nullptr)
            return;
    FDP->ConsumeData(colorData.get(), datalength);
    auto pixelmap = Media::PixelMap::Create(reinterpret_cast<uint32_t*>(colorData.get()), datalength, opts);
    if(pixelmap.get() ==nullptr)
	    return;
	
	std::shared_ptr<PixelMap> srcPixelMap = std::move(pixelmap);
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    if (ret != SUCCESS) {
        srcPixelMap->FreePixelMap();
        IMAGE_LOGE("YuvP010ConvertToRgb: CreatePixelMap fail");
        return;
    }

    srcPixelMap->rotate(FDP->ConsumeFloatingPoint<float>());
    srcPixelMap->scale(FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO, FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO);
    srcPixelMap->FreePixelMap();
}

void PixelMapMarshallingTest001()
{
    Media::InitializationOptions opts;
    opts.size.width = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO;
    opts.size.height = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO;
    opts.srcPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    opts.pixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    opts.alphaType = static_cast<Media::AlphaType>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    opts.scaleMode = static_cast<Media::ScaleMode>(FDP->ConsumeIntegral<uint8_t>() % SCALEMODE_MODULO);
    opts.editable = FDP->ConsumeBool();
    opts.useSourceIfMatch = FDP->ConsumeBool();
    int32_t pixelbytes = Media::ImageUtils::GetPixelBytes(opts.srcPixelFormat);
    size_t datalength = opts.size.width * opts.size.height * pixelbytes;
    std::unique_ptr<uint8_t[]> colorData = std::make_unique<uint8_t[]>(datalength);
    if(colorData == nullptr)
            return;
    FDP->ConsumeData(colorData.get(), datalength);
    auto pixelmap = Media::PixelMap::Create(reinterpret_cast<uint32_t*>(colorData.get()), datalength, opts);
    if(pixelmap.get() == nullptr)
	    return;
	
	MessageParcel parcel;
    pixelmap->SetMemoryName("MarshallingPixelMap");
    if (!pixelmap->Marshalling(parcel)) {
        IMAGE_LOGI("g_pixelMapIpcTest Marshalling failed id: %{public}d, isUnmap: %{public}d",
            pixelmap->GetUniqueId(), pixelmap->IsUnMap());
        return;
    }
}

void PixelMapUnmarshallingTest001()
{
	MessageParcel parcel;
	size_t size = FDP->remaining_bytes();
	void* data = malloc(size);
    if(data == nullptr)
            return;
    FDP->ConsumeData(data, size);
	parcel.WriteBuffer(data, size);
	
    Media::PixelMap* unmarshallingPixelmap = Media::PixelMap::Unmarshalling(parcel);
    if (!unmarshallingPixelmap) {
	free(data);
        return;
    }
    unmarshallingPixelmap->SetMemoryName("unmarshallingPixelMap");
    IMAGE_LOGI("g_pixelMapIpcTest unmarshallingPixelMap failed id: %{public}d, isUnmap: %{public}d",
        unmarshallingPixelmap->GetUniqueId(), unmarshallingPixelmap->IsUnMap());
    unmarshallingPixelmap->FreePixelMap();
    delete unmarshallingPixelmap;
    unmarshallingPixelmap = nullptr;
    free(data);
    return;
}

void YuvP010PixelMapIPCFuzzTest001()
{
    PixelMapMarshallingTest001();
    PixelMapUnmarshallingTest001();
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    OHOS::Media::YuvP010ToRgbFuzzTest001();
    OHOS::Media::YuvP010PixelMapIPCFuzzTest001();
    return 0;
}
