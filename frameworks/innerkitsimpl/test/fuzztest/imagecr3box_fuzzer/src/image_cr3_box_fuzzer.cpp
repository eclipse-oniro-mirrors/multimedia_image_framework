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
#include "cr3_box.h"
#include "cr3_parser.h"
#include "common_fuzztest_function.h"
#include "heif_utils.h"
#include "image_log.h"
#include "image_cr3_box_fuzzer.h"
#include "securec.h"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;

FuzzedDataProvider* FDP;

static constexpr uint32_t Invalid_BOX_TYPE = 0x61626364;
static constexpr uint32_t SMALL_RANGE = 1025;
static constexpr uint32_t LARGE_OFFSET_RANGE = 10001;
static constexpr uint32_t PAGE_SIZE_RANGE = 4097;
static constexpr uint32_t TINY_RANGE = 17;

void Cr3BoxMakeCr3BoxFuzzTest()
{
    uint32_t types[] = { BOX_TYPE_FTYP, BOX_TYPE_UUID, CR3_BOX_TYPE_MOOV, CR3_BOX_TYPE_PRVW, Invalid_BOX_TYPE };
    const size_t typeCount = sizeof(types) / sizeof(types[0]);
    size_t randomIndex = static_cast<size_t>(FDP->ConsumeIntegral<uint32_t>() % typeCount);
    Cr3Box::MakeCr3Box(types[randomIndex]);
}

void Cr3BoxMakeCr3FromReaderErrorFuzzTest(const uint8_t *data, size_t size)
{
    bool needCopy = FDP->ConsumeBool();
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    size_t length = size;
    std::shared_ptr<HeifStreamReader> reader = std::make_shared<HeifStreamReader>(stream, 0, length);
    std::shared_ptr<Cr3Box> box = nullptr;
    uint32_t recursionCount = 0;
    Cr3Box::MakeCr3FromReader(*reader, box, recursionCount);

    recursionCount = FDP->ConsumeIntegral<uint32_t>();
    Cr3Box::MakeCr3FromReader(*reader, box, recursionCount);
}

void Cr3UuidBoxParseContentChildrenFuzzTest()
{
    Cr3UuidBox uuidBox;
    bool needCopy = FDP->ConsumeBool();
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, needCopy);
    HeifStreamReader reader(stream, 0, 0);
    Cr3UuidBox::Cr3UuidType types[] = { Cr3UuidBox::Cr3UuidType::CANON, Cr3UuidBox::Cr3UuidType::PREVIEW,
        Cr3UuidBox::Cr3UuidType::UNKNOWN };
    const size_t typeCount = sizeof(types) / sizeof(types[0]);
    size_t randomIndex = static_cast<size_t>(FDP->ConsumeIntegral<uint32_t>() % typeCount);
    uint32_t recursion = 0;
    uuidBox.cr3UuidType_ = types[randomIndex];
    uuidBox.ParseContentChildren(reader, recursion);
}

void Cr3MoovBoxParseContentChildrenFuzzTest()
{
    Cr3MoovBox moovBox;
    bool needCopy = FDP->ConsumeBool();
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, needCopy);
    HeifStreamReader reader(stream, 0, 0);
    uint32_t recursionNormal = 0;
    moovBox.ParseContentChildren(reader, recursionNormal);
    uint32_t recursionTooDeep = FDP->ConsumeIntegral<uint32_t>();
    moovBox.ParseContentChildren(reader, recursionTooDeep);
}

void Cr3BoxReadDataCaseFuzzTest()
{
    Cr3Box box;
    std::vector<uint8_t> out;
    std::shared_ptr<HeifInputStream> nullStream;
    uint64_t start1 = static_cast<uint64_t>(FDP->ConsumeIntegral<uint32_t>() % SMALL_RANGE);
    uint64_t length1 = static_cast<uint64_t>(FDP->ConsumeIntegral<uint32_t>() % SMALL_RANGE);
    box.ReadData(nullStream, start1, length1, out);

    std::shared_ptr<HeifInputStream> emptyStream = std::make_shared<HeifBufferInputStream>(nullptr, 0, false);
    uint64_t start2 = static_cast<uint64_t>(FDP->ConsumeIntegral<uint32_t>() % LARGE_OFFSET_RANGE);
    uint64_t length2 = static_cast<uint64_t>(FDP->ConsumeIntegral<uint32_t>() % PAGE_SIZE_RANGE);
    box.ReadData(emptyStream, start2, length2, out);
    box.ReadData(emptyStream, 0, 0, out);

    uint64_t start3 = static_cast<uint64_t>(FDP->ConsumeIntegral<uint32_t>() % TINY_RANGE);
    uint64_t length3 = static_cast<uint64_t>(FDP->ConsumeIntegral<uint32_t>() % TINY_RANGE);
    box.ReadData(emptyStream, start3, length3, out);
}

void Cr3FtypAndPrvwParseFuzzTest()
{
    bool needCopy = FDP->ConsumeBool();
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(nullptr, 0, needCopy);
    HeifStreamReader reader(stream, 0, 0);
    Cr3FtypBox ftyp;
    ftyp.ParseContent(reader);
    Cr3PrvwBox prvw;
    prvw.ParseContent(reader);
}
} // namespace Media
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;

    OHOS::Media::Cr3BoxMakeCr3BoxFuzzTest();
    OHOS::Media::Cr3BoxMakeCr3FromReaderErrorFuzzTest(data, size);
    OHOS::Media::Cr3UuidBoxParseContentChildrenFuzzTest();
    OHOS::Media::Cr3MoovBoxParseContentChildrenFuzzTest();
    OHOS::Media::Cr3BoxReadDataCaseFuzzTest();
    OHOS::Media::Cr3FtypAndPrvwParseFuzzTest();
    return 0;
}