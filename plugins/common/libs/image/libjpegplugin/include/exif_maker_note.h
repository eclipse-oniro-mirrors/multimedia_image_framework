/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef EXIF_MAKER_NOTE_H
#define EXIF_MAKER_NOTE_H
#include <string>
#include <vector>
#include <libexif/exif-data.h>
namespace OHOS {
namespace ImagePlugin {
class ExifMakerNote {
public:
    ExifMakerNote();
    ~ExifMakerNote();

    std::string hwCaptureMode;
    std::string hwPhysicalAperture;

    static const uint16_t HW_MNOTE_TAG_SCENE_INFO_OFFSET = 0x0000;
    static const uint16_t HW_MNOTE_TAG_FACE_INFO_OFFSET = 0x0100;
    static const uint16_t HW_MNOTE_TAG_CAPTURE_MODE = 0x0200;
    static const uint16_t HW_MNOTE_TAG_BURST_CAPTURE_NUMBER = 0x0201;
    static const uint16_t HW_MNOTE_TAG_FRONT_CAMERA = 0x0202;
    static const uint16_t HW_MNOTE_TAG_PHYSICAL_APERTURE = 0x0205;
    static const uint16_t HW_MNOTE_IFD_SCENE_INFO_OFFSET = HW_MNOTE_TAG_SCENE_INFO_OFFSET;
    static const uint16_t HW_MNOTE_IFD_FACE_INFO_OFFSET = HW_MNOTE_TAG_FACE_INFO_OFFSET;
    static const uint16_t HW_MNOTE_IFD_DEFAULT = 0xffff;

    uint32_t Parser(ExifData *exif, const unsigned char *data, uint32_t size);
    [[nodiscard]] bool IsParsed() const;

private:
    static bool FindExifLocation(const unsigned char *data, uint32_t size, const unsigned char *&newData,
        uint32_t &newSize);
    static bool FindJpegAPP1(const unsigned char *data, uint32_t size, const unsigned char *&newData,
        uint32_t &newSize);
    uint32_t ParserMakerNote(ExifData* exif, bool &moreCheck);
    uint32_t ParserMakerNote(const unsigned char *data, uint32_t size);

private:
    struct ExifItem {
        uint16_t ifd {0};
        uint16_t tag {0};
        uint16_t format {0};
        uint32_t count {0};
        std::vector<unsigned char> data;

    public:
        ExifItem();
        explicit ExifItem(const ExifItem& item);
        ~ExifItem();
        ExifItem& operator=(const ExifItem& item);

        bool GetValue(std::string &value, const ExifByteOrder &order, bool mock = false);
        bool GetValue(std::string &value, ExifData *exifData, bool mock = false);
        void Dump(const std::string &info, const ExifByteOrder &order);

        static bool GetValue(std::string &value, const ExifByteOrder &order, ExifItem &item, bool mock = false);
        static bool GetValue(std::string &value, ExifData *exifData, ExifItem &item, bool mock = false);
        static void Dump(const std::string &info, const ExifItem &item, const ExifByteOrder &order);

    private:
        void CopyItem(const ExifItem& item);

        static bool GetValue(std::string &value, ExifContent *exifContent, ExifItem &item, bool &mock);
        static bool GetValue(std::string &value, ExifEntry *exifEntry, ExifItem &item, bool &mock);
    };

    bool IsHwMakerNote(const unsigned char *data, uint32_t size);
    bool ParserHwMakerNote();
    bool ParserIFD(uint32_t offset, uint32_t ifd, uint32_t deep = 0);
    bool ParserItem(uint32_t offset, uint32_t ifd, uint32_t deep = 0);
    bool SetValue(const ExifItem &entry, const std::string &value);

private:
    bool GetUInt16AndMove(uint32_t &offset, uint16_t &value);
    bool GetUInt32AndMove(uint32_t &offset, uint32_t &value);
    bool GetDataAndMove(size_t &offset, size_t count, std::vector<unsigned char> &value);
    bool GetUInt16(uint32_t offset, uint16_t &value);
    bool GetUInt32(uint32_t offset, uint32_t &value);
    bool GetData(size_t offset, size_t count, std::vector<unsigned char> &value);

    static bool GetUInt16(const std::vector<unsigned char> &buffer, ExifByteOrder order,
        size_t offset, uint16_t &value);
    static bool GetUInt32(const std::vector<unsigned char> &buffer, ExifByteOrder order,
        size_t offset, uint32_t &value);
    static bool GetData(const std::vector<unsigned char> &buffer, size_t offset, size_t count,
        std::vector<unsigned char> &value);

    static std::string Dump(const std::vector<unsigned char> &data, uint32_t offset = 0, uint32_t sum = UINT32_MAX);

    std::vector<unsigned char> makerNote_;
    ExifByteOrder order_ {ExifByteOrder::EXIF_BYTE_ORDER_INTEL};
    uint32_t tiff_offset_ {0};
    uint32_t ifd0_offset_ {0};

    std::vector<ExifItem> items_;
};
} // namespace ImagePlugin
} // namespace OHOS
#endif // EXIF_MAKER_NOTE_H