/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef JPEG_COMMAND_PARSER_H
#define JPEG_COMMAND_PARSER_H

#include <string>

namespace OHOS::ImagePlugin {
enum class UserColorFormat {
    YUV = 1,
    RGB = 2
};

struct CommandOpt {
    uint32_t width = 0;
    uint32_t height = 0;
    UserColorFormat colorFmt = UserColorFormat::YUV;
    uint32_t sampleSize = 1;
    std::string inputFile;
    std::string outputPath = "/storage/media/100/local/files/jpegdecdump";

    void Print() const;
};

CommandOpt Parse(int argc, char *argv[]);
void ShowUsage();
} // OHOS::ImagePlugin

#endif // JPEG_COMMAND_PARSER_H