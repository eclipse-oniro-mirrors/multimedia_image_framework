/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "file_packer_stream.h"

#include <cerrno>

#include "directory_ex.h"
#include "image_log.h"
#include "image_utils.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "FilePackerStream"

namespace OHOS {
namespace Media {

FilePackerStream::FilePackerStream(const std::string &filePath)
{
    int lastSlash = filePath.rfind("/");
    std::string dirPath;
    std::string fileName;
    if (lastSlash >= 0) {
        dirPath = ExtractFilePath(filePath);
        fileName = ExtractFileName(filePath);
    } else {
        dirPath = "";
        fileName = filePath;
    }
    std::string realPath;
    if (!ImageUtils::PathToRealPath(dirPath, realPath)) {
        file_ = nullptr;
        IMAGE_LOGE("convert to real path failed.");
        return;
    }

    if (!ForceCreateDirectory(realPath)) {
        file_ = nullptr;
        IMAGE_LOGE("create directory failed.");
        return;
    }

    std::string fullPath = realPath + "/" + fileName;
    file_ = fopen(fullPath.c_str(), "wb");
    if (file_ == nullptr) {
        IMAGE_LOGE("fopen file failed, error:%{public}d", errno);
        return;
    }
}
FilePackerStream::FilePackerStream(const int fd)
{
    file_ = fdopen(fd, "wb");
    if (file_ == nullptr) {
        IMAGE_LOGE("fopen file failed, error:%{public}d", errno);
        return;
    }
}
FilePackerStream::~FilePackerStream()
{
    if (file_ != nullptr) {
        fclose(file_);
        file_ = nullptr;
    }
}

bool FilePackerStream::Write(const uint8_t *buffer, uint32_t size)
{
    if ((buffer == nullptr) || (size == 0)) {
        IMAGE_LOGE("input parameter invalid.");
        return false;
    }
    if (file_ == nullptr) {
        IMAGE_LOGE("output file is null.");
        return false;
    }
    if (fwrite(buffer, sizeof(uint8_t), size, file_) != size) {
        IMAGE_LOGE("write %{public}u bytes failed.", size);
        fclose(file_);
        file_ = nullptr;
        return false;
    }
    return true;
}

void FilePackerStream::Flush()
{
    if (file_ != nullptr) {
        fflush(file_);
    }
}

int64_t FilePackerStream::BytesWritten()
{
    return (file_ != nullptr) ? ftell(file_) : 0;
}
} // namespace Media
} // namespace OHOS
