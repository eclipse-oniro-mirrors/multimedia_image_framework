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

#include "image_create_image_source_by_istream_fuzzer.h"

#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>

#include "image_source.h"
namespace OHOS {
void CreateImageSourceByIstreamFuzz(const uint8_t* data, size_t size)
{
    std::string pathName = "/tmp/test.jpg";
    int fd = open(pathName.c_str(), O_RDWR, O_CREAT);
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return;
    }
    std::filebuf fb;
    fb.open(pathName, std::ios_base::in);
    std::unique_ptr<std::istream> is = std::make_unique<std::istream>(&fb);
    Media::SourceOptions opts;
    uint32_t errorCode;
    Media ::DecodeOptions dopts;
    auto imagesource = Media::ImageSource::CreateImageSource(std::move(is), opts, errorCode);
    imagesource->CreatePixelMap(dopts, errorCode);
    close(fd);
    fb.close();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CreateImageSourceByIstreamFuzz(data, size);
    return 0;
}