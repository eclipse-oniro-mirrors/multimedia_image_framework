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
#include "image_cr3_parser_fuzzer.h"
#include "image_log.h"
#include "securec.h"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;

FuzzedDataProvider* FDP;

static constexpr uint32_t MIN_BOX_SIZE = 1;
static constexpr uint32_t MIN_HEADER_SIZE = 1;

void Cr3ParserMakeFromMemoryFuzzTest(const uint8_t *data, size_t size)
{
    bool needCopy = FDP->ConsumeBool();
    std::shared_ptr<Cr3Parser> out = std::make_shared<Cr3Parser>();
    Cr3Parser::MakeFromMemory(data, size, needCopy, out);
}

void Cr3ParserParseCr3BoxesFuzzTest(const uint8_t *data, size_t size)
{
    bool needCopy = FDP->ConsumeBool();
    std::shared_ptr<HeifInputStream> inputStream =
        std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    std::shared_ptr<OHOS::ImagePlugin::Cr3Parser> cr3Parser =
        std::make_shared<OHOS::ImagePlugin::Cr3Parser>(inputStream);
    OHOS::ImagePlugin::HeifStreamReader reader(inputStream, 0, size);
    cr3Parser->ParseCr3Boxes(reader);
    cr3Parser->ftypBox_ = nullptr;
    cr3Parser->moovBox_ = nullptr;
    cr3Parser->ParseCr3Boxes(reader);
}

void Cr3ParserGetPreviewImageInfoFuzzTest()
{
    std::shared_ptr<Cr3Parser> cr3Parser = std::make_shared<Cr3Parser>();
    cr3Parser->prvwBox_ = std::make_shared<Cr3PrvwBox>();
    cr3Parser->GetPreviewImageInfo();
}

void Cr3ParserGetCr3BoxDataFuzzTest(const uint8_t *data, size_t size)
{
    bool needCopy = FDP->ConsumeBool();
    std::shared_ptr<HeifInputStream> inputStream =
        std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    std::shared_ptr<OHOS::ImagePlugin::Cr3Parser> cr3Parser =
        std::make_shared<OHOS::ImagePlugin::Cr3Parser>(inputStream);
    uint32_t boxSize = MIN_BOX_SIZE + (FDP->ConsumeIntegral<uint32_t>() % static_cast<uint32_t>(size));
    uint32_t headerSize = MIN_HEADER_SIZE + (FDP->ConsumeIntegral<uint32_t>() % boxSize);
    auto cr3Box = std::make_shared<Cr3Box>();
    cr3Box->boxSize_ = static_cast<uint64_t>(boxSize);
    cr3Box->headerSize_ = headerSize;
    cr3Box->startPos_ = 0;
    cr3Box->boxType_ = FDP->ConsumeIntegral<uint32_t>();
    cr3Parser->GetCr3BoxData(cr3Box);
    cr3Parser->GetCr3BoxData(nullptr);
    cr3Parser->inputStream_ = nullptr;
    cr3Parser->GetCr3BoxData(cr3Box);
}

void Cr3ParserGetExifDataMultipleIfdsFuzzTest()
{
    std::shared_ptr<Cr3Parser> cr3Parser = std::make_shared<Cr3Parser>();
    cr3Parser->GetExifDataIfd0();
    cr3Parser->GetExifDataIfdExif();
    cr3Parser->GetExifDataIfdGps();
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    /* Run your code on data */
    OHOS::Media::Cr3ParserMakeFromMemoryFuzzTest(data, size);
    OHOS::Media::Cr3ParserParseCr3BoxesFuzzTest(data, size);
    OHOS::Media::Cr3ParserGetPreviewImageInfoFuzzTest();
    OHOS::Media::Cr3ParserGetCr3BoxDataFuzzTest(data, size);
    OHOS::Media::Cr3ParserGetExifDataMultipleIfdsFuzzTest();
    return 0;
}