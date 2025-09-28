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

#include "cr3_parser.h"

#include "heif_utils.h"
#include "image_log.h"
#include "securec.h"

namespace OHOS {
namespace ImagePlugin {

heif_error Cr3Parser::MakeFromMemory(const uint8_t *data, size_t size, bool needCopy, std::shared_ptr<Cr3Parser> &out)
{
    CHECK_ERROR_RETURN_RET(data == nullptr, heif_error_no_data);
    auto input_stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    return MakeFromStream(input_stream, out);
}

heif_error Cr3Parser::MakeFromStream(const std::shared_ptr<HeifInputStream> &stream, std::shared_ptr<Cr3Parser> &out)
{
    CHECK_ERROR_RETURN_RET(stream == nullptr, heif_error_no_data);
    std::shared_ptr<Cr3Parser> parser = std::make_shared<Cr3Parser>(stream);
    CHECK_ERROR_RETURN_RET(parser == nullptr, heif_error_no_data);

    auto maxSize = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
    HeifStreamReader reader(stream, 0, maxSize);

    heif_error errorBox = parser->ParseCr3Boxes(reader);
    CHECK_ERROR_RETURN_RET(errorBox != heif_error_ok, errorBox);

    out = std::move(parser);
    return heif_error_ok;
}

heif_error Cr3Parser::ParseCr3Boxes(HeifStreamReader &reader)
{
    while (true) {
        std::shared_ptr<Cr3Box> box = nullptr;
        uint32_t recursionCount = 0;
        heif_error error = Cr3Box::MakeCr3FromReader(reader, box, recursionCount);
        if (reader.IsAtEnd() || error == heif_error_eof) {
            break;
        }
        if (error != heif_error_ok) {
            return error;
        }
        if (box == nullptr) {
            return heif_error_no_data;
        }
        if (box->GetBoxType() == BOX_TYPE_FTYP) {
            ftypBox_ = std::dynamic_pointer_cast<Cr3FtypBox>(box);
        }
        if (box->GetBoxType() == CR3_BOX_TYPE_MOOV) {
            moovBox_ = std::dynamic_pointer_cast<Cr3MoovBox>(box);
        }
        if (box->GetBoxType() == BOX_TYPE_UUID) {
            std::shared_ptr<Cr3UuidBox> tempUuidBox = std::dynamic_pointer_cast<Cr3UuidBox>(box);
            if (tempUuidBox->GetCr3UuidType() == Cr3UuidBox::Cr3UuidType::PREVIEW) {
                uuidPrvwBox_ = tempUuidBox;
            }
        }
    }

    if (ftypBox_ == nullptr || ftypBox_->GetMajorBrand() != CR3_FILE_TYPE_CRX) {
        return heif_error_no_ftyp;
    }

    if (moovBox_ != nullptr) {
        uuidCanonBox_ = moovBox_->GetChild<Cr3UuidBox>(BOX_TYPE_UUID);
    }
    if (uuidCanonBox_ == nullptr) {
        return heif_error_primary_item_not_found;
    }
    cmt1Box_ = uuidCanonBox_->GetChild<Cr3Box>(CR3_BOX_TYPE_CMT1);
    cmt2Box_ = uuidCanonBox_->GetChild<Cr3Box>(CR3_BOX_TYPE_CMT2);
    cmt3Box_ = uuidCanonBox_->GetChild<Cr3Box>(CR3_BOX_TYPE_CMT3);
    cmt4Box_ = uuidCanonBox_->GetChild<Cr3Box>(CR3_BOX_TYPE_CMT4);

    if (uuidPrvwBox_ != nullptr) {
        prvwBox_ = uuidPrvwBox_->GetChild<Cr3PrvwBox>(CR3_BOX_TYPE_PRVW);
    }
    return heif_error_ok;
}

Cr3DataInfo Cr3Parser::GetPreviewImageInfo()
{
    Cr3DataInfo previewInfo;
    if (prvwBox_ != nullptr) {
        previewInfo.fileOffset = prvwBox_->GetJpegFileOffset();
        previewInfo.size = prvwBox_->GetJpegSize();
        previewInfo.boxType = prvwBox_->GetBoxType();
    }
    return previewInfo;
}

std::vector<uint8_t> Cr3Parser::GetCr3BoxData(const std::shared_ptr<Cr3Box> &cr3Box)
{
    std::vector<uint8_t> exifData;
    if (cr3Box != nullptr) {
        uint64_t start = 0;
        uint64_t length = cr3Box->GetBoxSize() - cr3Box->GetHeaderSize();
        if (cr3Box->ReadData(inputStream_, start, length, exifData) != heif_error_ok) {
            std::string boxTypeStr = code_to_fourcc(cr3Box->GetBoxType());
            IMAGE_LOGD("%{public}s boxType[%{public}s] ReadData failed", __func__, boxTypeStr.c_str());
            return {};
        }
    }
    return exifData;
}

std::vector<uint8_t> Cr3Parser::GetExifDataIfd0()
{
    return GetCr3BoxData(cmt1Box_);
}

std::vector<uint8_t> Cr3Parser::GetExifDataIfdExif()
{
    return GetCr3BoxData(cmt2Box_);
}

std::vector<uint8_t> Cr3Parser::GetExifDataIfdGps()
{
    return GetCr3BoxData(cmt4Box_);
}
} // namespace ImagePlugin
} // namespace OHOS
