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
#include "image_pixelmap_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
 
#include "pixel_map.h"
#include "image_utils.h"

#include <chrono>
#include <thread>
#include "image_log.h"

constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 105;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;
/*
* describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
* tips: only support basic type
*/
void PixelMapEncodeTest(){
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
    if(pixelmap ==nullptr)
	return;
    std::vector<uint8_t> buff;
    pixelmap->EncodeTlv(buff);
}

void PixelMapDecodeTest(){
    std::vector<uint8_t> buff = FDP->ConsumeRemainingBytes<uint8_t>();
    PixelMap *pixelmapTlv = PixelMap::DecodeTlv(buff);
    if (pixelmapTlv != nullptr) {
        delete pixelmapTlv;
        pixelmapTlv = nullptr;
    }
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    uint8_t action = fdp.ConsumeIntegral<uint8_t>();
	switch(action){
        case 0:
            OHOS::Media::PixelMapEncodeTest();
            break;
        default:
            OHOS::Media::PixelMapDecodeTest();
            break;
    }
    return 0;
}
