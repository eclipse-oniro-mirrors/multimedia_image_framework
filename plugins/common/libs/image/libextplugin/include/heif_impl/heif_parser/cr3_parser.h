/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_CR3_PARSER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_CR3_PARSER_H

#include "box/cr3_box.h"

namespace OHOS {
namespace ImagePlugin {

struct Cr3DataInfo {
    uint64_t fileOffset = 0;
    uint32_t size = 0;
    uint32_t boxType = 0;
};

class Cr3Parser {
public:
    Cr3Parser() = default;
    explicit Cr3Parser(const std::shared_ptr<HeifInputStream> &inputStream) : inputStream_(inputStream) {};
    ~Cr3Parser() = default;

    static heif_error MakeFromStream(const std::shared_ptr<HeifInputStream> &stream, std::shared_ptr<Cr3Parser> &out);
    static heif_error MakeFromMemory(const uint8_t *data, size_t size, bool needCopy, std::shared_ptr<Cr3Parser> &out);

    Cr3DataInfo GetPreviewImageInfo();
    std::vector<uint8_t> GetExifDataIfd0();
    std::vector<uint8_t> GetExifDataIfdExif();
    std::vector<uint8_t> GetExifDataIfdGps();

private:
    // Reading functions for boxes
    heif_error ParseCr3Boxes(HeifStreamReader &reader);
    std::vector<uint8_t> GetCr3BoxData(const std::shared_ptr<Cr3Box> &cr3Box);

    // stream
    std::shared_ptr<HeifInputStream> inputStream_;

    // boxes
    std::shared_ptr<Cr3FtypBox> ftypBox_ = nullptr;
    std::shared_ptr<Cr3MoovBox> moovBox_ = nullptr;
    std::shared_ptr<Cr3UuidBox> uuidCanonBox_ = nullptr;
    std::shared_ptr<Cr3UuidBox> uuidPrvwBox_ = nullptr;
    std::shared_ptr<Cr3Box> cmt1Box_ = nullptr;
    std::shared_ptr<Cr3Box> cmt2Box_ = nullptr;
    std::shared_ptr<Cr3Box> cmt3Box_ = nullptr;
    std::shared_ptr<Cr3Box> cmt4Box_ = nullptr;
    std::shared_ptr<Cr3PrvwBox> prvwBox_ = nullptr;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_CR3_PARSER_H
