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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_CR3_BOX_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_CR3_BOX_H

#include "heif_box.h"

namespace OHOS {
namespace ImagePlugin {
class Cr3Box : public HeifBox {
public:
    Cr3Box() = default;
    explicit Cr3Box(uint32_t boxType): HeifBox(boxType) {}

    static heif_error MakeCr3FromReader(HeifStreamReader &reader,
        std::shared_ptr<Cr3Box> &result, uint32_t &recursionCount);

    static std::shared_ptr<Cr3Box> MakeCr3Box(uint32_t boxType);

    heif_error ReadData(const std::shared_ptr<HeifInputStream> &stream,
        uint64_t start, uint64_t length, std::vector<uint8_t> &outData) const;

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;
    heif_error ReadCr3Children(HeifStreamReader &reader, uint32_t &recursionCount);

    std::streampos startPos_;
};

class Cr3FtypBox : public Cr3Box {
public:
    Cr3FtypBox() : Cr3Box(BOX_TYPE_FTYP) {}
    uint32_t GetMajorBrand() const { return majorBrand_; };

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    uint32_t majorBrand_ = 0;
    uint32_t minorVersion_ = 0;
    std::vector<heif_brand> compatibleBrands_;
};

class Cr3UuidBox : public Cr3Box {
public:
    enum Cr3UuidType {
        UNKNOWN,
        CANON,
        PREVIEW,
        XMP,
    };

    Cr3UuidBox() : Cr3Box(BOX_TYPE_UUID) {}
    Cr3UuidType GetCr3UuidType();

protected:
    heif_error ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount) override;

private:
    Cr3UuidType cr3UuidType_ = Cr3UuidType::UNKNOWN;
};

class Cr3MoovBox : public Cr3Box {
public:
    Cr3MoovBox() : Cr3Box(CR3_BOX_TYPE_MOOV) {}

protected:
    heif_error ParseContentChildren(HeifStreamReader &reader, uint32_t &recursionCount) override;
};

class Cr3PrvwBox : public Cr3Box {
public:
    Cr3PrvwBox() : Cr3Box(CR3_BOX_TYPE_PRVW) {}
    uint64_t GetJpegFileOffset() const { return jpegFileOffset_; };
    uint32_t GetJpegSize() const { return jpegSize_; };

protected:
    heif_error ParseContent(HeifStreamReader &reader) override;

private:
    uint16_t width_ = 0;
    uint16_t height_ = 0;
    uint64_t jpegFileOffset_ = 0;
    uint32_t jpegSize_ = 0;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_CR3_BOX_H
