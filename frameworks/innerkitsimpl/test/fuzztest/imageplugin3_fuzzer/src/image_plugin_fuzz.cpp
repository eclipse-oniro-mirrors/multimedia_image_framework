/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "image_plugin_fuzz.h"

#define private public
#define protected public
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <securec.h>

#include "common_fuzztest_function.h"
#include "image_source.h"
#include "ext_decoder.h"
#include "image_log.h"
#include "ext_wstream.h"
#include "hdr_helper.h"
#include "file_source_stream.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PLUGIN_HDR_FUZZ"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider *FDP;
static const std::string JPG_PATH = "/data/local/tmp/test_hw.jpg";

constexpr uint32_t OPT_SIZE = 80;
constexpr uint8_t ITUT35_TAG_SIZE = 6;
constexpr uint32_t HDRTYPE_MODULO = 8;


void HdrHelperFucTest2(const uint8_t *data, size_t size, const std::string &filename)
{
    HdrMetadata metadata;
    Media::ImageHdrType hdrType = static_cast<Media::ImageHdrType>(FDP->ConsumeIntegral<uint8_t>() % HDRTYPE_MODULO);
    ImagePlugin::HdrHelper::ValidateAndCorrectMetaData(metadata, hdrType);

    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    std::unique_ptr<FileSourceStream> streamPtr = FileSourceStream::CreateSourceStream(filename);
    extDecoder->SetSource(*streamPtr);
    extDecoder->codec_ = SkCodec::MakeFromStream(std::make_unique<ExtStream>(extDecoder->stream_));
    extDecoder->CheckCodec();
    ImagePlugin::HdrHelper::GetMetadata(extDecoder->codec_.get(), hdrType, metadata);

    sk_sp<SkData> imageData = SkData::MakeWithCopy(data, size);
    ExtWStream extWStream(nullptr);
    ImagePlugin::HdrJpegPackerHelper::SpliceHdrStream(imageData, imageData, extWStream, metadata);
}

void HdrHelperFucTest()
{
    HdrMetadata metadataOne;
    metadataOne.extendMeta.baseColorMeta.baseMappingFlag = ITUT35_TAG_SIZE;
    metadataOne.extendMeta.gainmapColorMeta.combineMappingFlag = ITUT35_TAG_SIZE;
    ImagePlugin::HdrJpegPackerHelper::PackVividMetadataMarker(metadataOne);

    HdrMetadata metadataTwo;
    metadataTwo.extendMeta.baseColorMeta.baseMappingFlag = ITUT35_TAG_SIZE;
    metadataTwo.extendMeta.gainmapColorMeta.combineMappingFlag = ITUT35_TAG_SIZE;
    ImagePlugin::HdrJpegPackerHelper::PackISOMetadataMarker(metadataTwo);

    HdrMetadata metadataThree;
    metadataThree.extendMeta.baseColorMeta.baseMappingFlag = ITUT35_TAG_SIZE;
    metadataThree.extendMeta.gainmapColorMeta.combineMappingFlag = ITUT35_TAG_SIZE;
    sk_sp<SkData> baseImageData;
    sk_sp<SkData> gainMapImageData;
    ExtWStream extWStream(nullptr);
    ImagePlugin::HdrJpegPackerHelper::SpliceHdrStream(baseImageData, gainMapImageData, extWStream, metadataThree);

    HdrMetadata metadataFour;
    metadataFour.extendMeta.baseColorMeta.baseMappingFlag = ITUT35_TAG_SIZE;
    metadataFour.extendMeta.gainmapColorMeta.combineMappingFlag = ITUT35_TAG_SIZE;
    std::vector<uint8_t> it35Info;
    ImagePlugin::HdrHeifPackerHelper::PackIT35Info(metadataFour, it35Info);
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::Media::OPT_SIZE) {
        return 0;
    }
    FuzzedDataProvider fdp(data + size - OHOS::Media::OPT_SIZE, OHOS::Media::OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    static const std::string filename = "/data/local/tmp/test_hdr_decode.jpg";
    WriteDataToFile(data, size - OHOS::Media::OPT_SIZE, filename);
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 2;
    switch (action) {
        case 0:
            OHOS::Media::HdrHelperFucTest();
            break;
        case 1:
            OHOS::Media::HdrHelperFucTest2(data, size - OHOS::Media::OPT_SIZE, filename);
            break;
        default:
            break;
    }
    return 0;
}