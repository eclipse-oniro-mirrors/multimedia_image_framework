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

#include "image_pixelmap_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include <chrono>
#include <thread>
#include "pixel_map.h"
#include "image_log.h"
#include "parcel.h"
#include "message_parcel.h"

constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;

namespace OHOS {
namespace Media {
namespace {
const uint8_t* g_data = nullptr;
size_t g_size = 0;
size_t g_pos;
} // namespace

/*
 * describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
 * tips: only support basic type
 */
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (g_data == nullptr || objectSize > g_size - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_data + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

/*
 * get a pixelmap from opts
 */
std::unique_ptr<Media::PixelMap> GetPixelMapFromOpts(Media::PixelFormat pixelFormat = PixelFormat::UNKNOWN)
{
    int32_t width = GetData<int32_t>() % MAX_LENGTH_MODULO;
    int32_t height = GetData<int32_t>() % MAX_LENGTH_MODULO;
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.srcPixelFormat = pixelFormat == PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(GetData<int32_t>() % PIXELFORMAT_MODULO) : pixelFormat;
    opts.pixelFormat = pixelFormat == PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(GetData<int32_t>() % PIXELFORMAT_MODULO) : pixelFormat;
    opts.alphaType = static_cast<Media::AlphaType>(GetData<int32_t>() % ALPHATYPE_MODULO);
    opts.scaleMode = static_cast<Media::ScaleMode>(GetData<int32_t>() % SCALEMODE_MODULO);
    opts.editable = GetData<bool>();
    opts.useSourceIfMatch = GetData<bool>();
    auto pixelmap = Media::PixelMap::Create(opts);
    if (pixelmap == nullptr) {
        return nullptr;
    }
    return pixelmap;
}

/*
 * test pixelmap IPC interface
 */
bool PixelMapParcelTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    // test parcel pixelmap
    MessageParcel parcel;
    pixelMap->SetMemoryName("MarshallingPixelMap");
    if (!pixelMap->Marshalling(parcel)) {
        IMAGE_LOGI("PixelMapParcelTest Marshalling failed id: %{public}d, isUnmap: %{public}d",
            pixelMap->GetUniqueId(), pixelMap->IsUnMap());
        return false;
    }
    Media::PixelMap* unmarshallingPixelMap = Media::PixelMap::Unmarshalling(parcel);
    if (!unmarshallingPixelMap) {
        return false;
    }
    unmarshallingPixelMap->SetMemoryName("unmarshallingPixelMap");
    IMAGE_LOGI("PixelMapParcelTest unmarshallingPixelMap failed id: %{public}d, isUnmap: %{public}d",
        unmarshallingPixelMap->GetUniqueId(), unmarshallingPixelMap->IsUnMap());
    unmarshallingPixelMap->FreePixelMap();
    delete unmarshallingPixelMap;
    unmarshallingPixelMap = nullptr;
    return true;
}

bool PixelMapFromOptsMainFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    // create from opts
    std::unique_ptr<Media::PixelMap> pixelMapFromOpts = GetPixelMapFromOpts(Media::PixelFormat::RGBA_8888);
    if (!pixelMapFromOpts) {
        return false;
    }
    PixelMapParcelTest(pixelMapFromOpts);

    return true;
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::PixelMapFromOptsMainFuzzTest(data, size);
    return 0;
}