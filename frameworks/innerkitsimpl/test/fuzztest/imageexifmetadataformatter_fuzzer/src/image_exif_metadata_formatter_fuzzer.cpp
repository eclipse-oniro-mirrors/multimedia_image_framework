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
#include "image_exif_metadata_formatter_fuzzer.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include "securec.h"

#include "common_fuzztest_function.h"
#include "webp_exif_metadata_accessor.h"
#include "image_log.h"
#include "exif_metadata_formatter.h"

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;
using namespace std;

namespace {
    static constexpr size_t MAX_SIZE = 1000;
}

void ExifMetadataFormatterFuzzTest()
{
    size_t maxStrSize = 20;
    std::string value = FDP->ConsumeRandomLengthString(maxStrSize);
    for (auto it = ExifMetadatFormatter::GetInstance().valueFormatConvertConfig_.begin();
        it != ExifMetadatFormatter::GetInstance().valueFormatConvertConfig_.end(); it++) {
        auto func = (it->second).first;
        func(value, (it->second).second);
    }
}

void WebpExifMetadataAccessorFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    if (size == 0 || size > MAX_SIZE) {
        return;
    }
    std::unique_ptr<uint8_t[]> copyData = std::make_unique<uint8_t[]>(size);
    if (!copyData) {
        return;
    }
    if (EOK != memcpy_s(copyData.get(), size, data, size)) {
        return;
    }
    std::shared_ptr<MetadataStream> srcStream = std::make_shared<BufferMetadataStream>(
        copyData.get(), size, BufferMetadataStream::MemoryMode::Dynamic);
    if (!srcStream) {
        return;
    }
    std::shared_ptr<WebpExifMetadataAccessor> accessor = std::make_shared<WebpExifMetadataAccessor>(srcStream);
    if (!accessor) {
        return;
    }
    std::vector<uint8_t> mockVec = FDP->ConsumeBytes<uint8_t>(size);
    if (!mockVec.data()) {
        return;
    }
    DataBuf dataBuf(mockVec.data(), mockVec.size());
    accessor->WriteBlob(dataBuf);
}
}  // namespace Media
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;

    OHOS::Media::ExifMetadataFormatterFuzzTest();
    OHOS::Media::WebpExifMetadataAccessorFuzzTest(data, size);
    return 0;
}
