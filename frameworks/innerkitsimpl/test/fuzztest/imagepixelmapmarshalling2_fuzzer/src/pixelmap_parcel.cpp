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
#include <chrono>
#include <thread>
#include "pixel_map.h"
#include "image_log.h"
#include "image_utils.h"
#include "parcel.h"
#include "message_parcel.h"
 
constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 105;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;
 
namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;

std::unique_ptr<PixelMap> ConstructPixelMap(AllocatorType allocType)
{
    std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
    ImageInfo info;
    info.size.width = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO;
    info.size.height = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO;
    info.pixelFormat = static_cast<PixelFormat>((FDP->ConsumeIntegral<uint8_t>() % (PIXELFORMAT_MODULO - 1)) + 1); // 1 ~ 7
    info.alphaType = static_cast<Media::AlphaType>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    pixelMap->SetImageInfo(info);

    int32_t rowDataSize = ImageUtils::GetRowDataSizeByPixelFormat(info.size.width, info.pixelFormat);
    if (rowDataSize <= 0) {
        return nullptr;
    }
    size_t bufferSize = rowDataSize * info.size.height;
    void* buffer = malloc(bufferSize); // Buffer's lifecycle will be held by pixelMap
    if (buffer == nullptr) {
        return nullptr;
    }
    char* ch = static_cast<char*>(buffer);
    FDP->ConsumeData(ch, bufferSize);

    pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, allocType, allocType != AllocatorType::CUSTOM_ALLOC ? nullptr :
        [](void* addr, void* context, uint32_t size) {
            free(addr);
        });

    return pixelMap;
}
 
/*
 * test pixelmap IPC interface
 */
bool PixelMapParcelMarshallTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    // test parcel pixelmap
    MessageParcel parcel;
    pixelMap->SetMemoryName("MarshallingPixelMap");
    if (!pixelMap->Marshalling(parcel)) {
        IMAGE_LOGI("PixelMapParcelTest Marshalling failed id: %{public}d, isUnmap: %{public}d",
            pixelMap->GetUniqueId(), pixelMap->IsUnMap());
        return false;
    }
    return true;
}

bool PixelMapParcelUnmarshallTest(const uint8_t* data, size_t size){
    MessageParcel parcel;
    parcel.WriteBuffer(data, size);
    Media::PixelMap* unmarshallingPixelMap = Media::PixelMap::Unmarshalling(parcel);
    if (!unmarshallingPixelMap) {
        return false;
    }
    unmarshallingPixelMap->SetMemoryName("unmarshallingPixelMap");
    IMAGE_LOGI("PixelMapParcelUnmarshallTest unmarshallingPixelMap failed id: %{public}d, isUnmap: %{public}d",
        unmarshallingPixelMap->GetUniqueId(), unmarshallingPixelMap->IsUnMap());
    unmarshallingPixelMap->FreePixelMap();
    delete unmarshallingPixelMap;
    unmarshallingPixelMap = nullptr;
    return true;
}

bool PixelMapFromOptsMainFuzzTest()
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
                return false;
    FDP->ConsumeData(colorData.get(), datalength);
    auto pixelmap = Media::PixelMap::Create(reinterpret_cast<uint32_t*>(colorData.get()), datalength, opts);
    if (pixelmap.get() == nullptr) {
        return false;
    }

	PixelMapParcelMarshallTest(pixelmap);
    return true;
}

bool PixelMapCustomAllocMainFuzzTest()
{
    // Test for CUSTOM_ALLOC PixelMap
    auto pixelMapCustomAlloc = ConstructPixelMap(AllocatorType::CUSTOM_ALLOC);
    if (!pixelMapCustomAlloc) {
        return false;
    }
    PixelMapParcelMarshallTest(pixelMapCustomAlloc);
    return true;
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
            OHOS::Media::PixelMapParcelUnmarshallTest(data + 1, size - 1);
            break;
		case 1:
            OHOS::Media::PixelMapFromOptsMainFuzzTest();
            break;
        default:
            OHOS::Media::PixelMapCustomAllocMainFuzzTest();
            break;
    }
    return 0;
}
