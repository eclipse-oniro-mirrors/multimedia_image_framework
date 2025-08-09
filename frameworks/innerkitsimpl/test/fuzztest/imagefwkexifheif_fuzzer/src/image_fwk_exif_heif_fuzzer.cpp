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

#include "image_fwk_exif_heif_fuzzer.h"
#define private public

#include <cstdint>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include "securec.h"

#include "common_fuzztest_function.h"
#include "metadata_accessor_factory.h"
#include "dng_exif_metadata_accessor.h"
#include "heif_exif_metadata_accessor.h"
#include "jpeg_exif_metadata_accessor.h"
#include "png_exif_metadata_accessor.h"
#include "webp_exif_metadata_accessor.h"
#include "file_metadata_stream.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_EXIF_HEIF_FUZZER"

namespace OHOS {
namespace Media {
using namespace std;

static const std::string HEIF_EXIF_PATH = "/data/local/tmp/test_exif.heic";

void MetadataAccessorFuncTest001(std::shared_ptr<MetadataAccessor>& metadataAccessor)
{
    if (metadataAccessor == nullptr) {
        return;
    }
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

void HeifAccessorTest001(const uint8_t* data, size_t size)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    int fd = open(HEIF_EXIF_PATH.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return;
    }

    std::shared_ptr<MetadataStream> stream = std::make_shared<FileMetadataStream>(fd);
    if (stream == nullptr || !stream->Open(OpenMode::ReadWrite)) {
        IMAGE_LOGE("Failed to open the stream with file descriptor: %{public}d", fd);
        close(fd);
        return;
    }
    uint32_t error = 0;
    EncodedFormat type = MetadataAccessorFactory::GetImageType(stream, error);
    if (type != EncodedFormat::HEIF) {
        IMAGE_LOGI("%{public}s type is not HEIF", __func__);
        close(fd);
        return;
    }
    std::shared_ptr<MetadataAccessor> metadataAccessor1 = MetadataAccessorFactory::Create(fd);
    MetadataAccessorFuncTest001(metadataAccessor1);
    close(fd);

    BufferMetadataStream::MemoryMode mode = BufferMetadataStream::MemoryMode::Dynamic;
    std::shared_ptr<MetadataAccessor> metadataAccessor2 = MetadataAccessorFactory::Create(const_cast<uint8_t*>(data),
        size, mode);
    if (metadataAccessor2 == nullptr) {
        IMAGE_LOGE("Create metadata accessor failed");
        return;
    }
    MetadataAccessorFuncTest001(metadataAccessor2);
    auto heifMetadataAccessor = reinterpret_cast<HeifExifMetadataAccessor*>(metadataAccessor2.get());
    heifMetadataAccessor->Read();
    heifMetadataAccessor->Write();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void DataBufTest(const uint8_t *data, size_t size)
{
    if (size == 0) {
        return;
    }
    DataBuf dataBuf(data, size);
    dataBuf.ReadUInt8(0);
    dataBuf.Resize(size);
    dataBuf.WriteUInt8(0, 0);
    dataBuf.Reset();
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::DataBufTest(data, size);
    OHOS::Media::HeifAccessorTest001(data, size);
    return 0;
}