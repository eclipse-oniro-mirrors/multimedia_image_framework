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
#include "image_fwk_decode_gif_fuzzer.h"

#define private public
#define protected public
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

#include "image_utils.h"
#include "common_fuzztest_function.h"
#include "image_source.h"
#include "ext_decoder.h"
#include "svg_decoder.h"
#include "bmp_decoder.h"
#include "image_log.h"
#include "pixel_yuv.h"
#include "gif_encoder.h"
#include "buffer_packer_stream.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_DECODE_GIF_FUZZ"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider* FDP;

void GifTest001()
{
    IMAGE_LOGI("%{public}s IN", __func__);
	InitializationOptions opts;
    opts.size.width = FDP->ConsumeIntegral<uint16_t>() & 0xfff;
    opts.size.height = FDP->ConsumeIntegral<uint16_t>() & 0xfff;
    opts.pixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>());
    opts.alphaType = static_cast<AlphaType>(FDP->ConsumeIntegral<uint8_t>());
    opts.scaleMode = static_cast<ScaleMode>(FDP->ConsumeIntegral<uint8_t>());
    opts.editable = FDP->ConsumeBool();
    opts.useSourceIfMatch = FDP->ConsumeBool();
	
	PlEncodeOptions plOpts;
	//plOpts.format = optformat[FDP->ConsumeIntegral<uint8_t>() % 9];
	plOpts.quality = FDP->ConsumeIntegral<uint8_t>();
	plOpts.numberHint = FDP->ConsumeIntegral<uint32_t>();
	plOpts.desiredDynamicRange = static_cast<Media::EncodeDynamicRange>(FDP->ConsumeIntegral<uint8_t>());
	plOpts.needsPackProperties = FDP->ConsumeBool();
	plOpts.isEditScene = FDP->ConsumeBool();
	plOpts.loop = FDP->ConsumeIntegral<uint16_t>();
	plOpts.disposalTypes = FDP->ConsumeBytes<uint8_t>(FDP->ConsumeIntegral<uint8_t>());
	uint8_t delaytimessize = FDP->ConsumeIntegral<uint8_t>();
	std::vector<uint16_t> delaytimes(delaytimessize);
	FDP->ConsumeData(delaytimes.data(), delaytimessize*2);
	plOpts.delayTimes = delaytimes;
    
    int32_t pixelbytes = Media::ImageUtils::GetPixelBytes(opts.srcPixelFormat);
        size_t datalength = opts.size.width * opts.size.height * pixelbytes;
        std::unique_ptr<uint8_t[]> colorData = std::make_unique<uint8_t[]>(datalength);
        if(colorData == nullptr)
                return;
    FDP->ConsumeData(colorData.get(), datalength);	
    std::shared_ptr<Media::PixelMap> pixelmap = Media::PixelMap::Create(reinterpret_cast<uint32_t*>(colorData.get()), datalength, opts);
    if (pixelmap.get() == nullptr) {
        return;
    }	
	
	auto gifEncoder = std::make_shared<GifEncoder>();
	auto outputData = std::make_unique<uint8_t[]>(pixelmap->GetByteCount());
	size_t stream_size = pixelmap->GetByteCount();
	auto stream = std::make_shared<BufferPackerStream>(outputData.get(), stream_size);
	auto result = gifEncoder->StartEncode(*stream.get(), plOpts);
	result = gifEncoder->AddImage(*pixelmap.get());
	result = gifEncoder->FinalizeEncode();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
	FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    OHOS::Media::GifTest001();
    return 0;
}
