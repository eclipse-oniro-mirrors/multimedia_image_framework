/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef JPEG_DECODER_H
#define JPEG_DECODER_H

#include <cstdint>
#include <string>
#include "abs_image_decoder.h"
#include "abs_image_decompress_component.h"
#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif
#include "hilog/log.h"
#include "icc_profile_info.h"
#include "jpeg_utils.h"
#include "jpeglib.h"
#include "log_tags.h"
#include "plugin_class_base.h"
#include "plugin_server.h"
#include "exif_info.h"

namespace OHOS {
namespace ImagePlugin {
enum class JpegDecodingState : int32_t {
    UNDECIDED = 0,
    SOURCE_INITED = 1,
    BASE_INFO_PARSING = 2,
    BASE_INFO_PARSED = 3,
    IMAGE_DECODING = 4,
    IMAGE_ERROR = 5,
    IMAGE_PARTIAL = 6,
    IMAGE_DECODED = 7
};

class JpegDecoder : public AbsImageDecoder, public OHOS::MultimediaPlugin::PluginClassBase {
public:
    JpegDecoder();
    ~JpegDecoder() override;
    void SetSource(InputDataStream &sourceStream) override;
    void Reset() override;
    uint32_t SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info) override;
    uint32_t Decode(uint32_t index, DecodeContext &context) override;
    uint32_t GetImageSize(uint32_t index, PlSize &size) override;
    uint32_t PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &context) override;
    uint32_t GetImagePropertyInt(uint32_t index, const std::string &key, int32_t &value) override;
    uint32_t GetImagePropertyString(uint32_t index, const std::string &key, std::string &value) override;
    uint32_t ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
        const std::string &path) override;
    uint32_t ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
        const int fd) override;
    uint32_t ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
        uint8_t *data, uint32_t size) override;
    uint32_t GetFilterArea(const int &privacyType, std::vector<std::pair<uint32_t, uint32_t>> &ranges) override;

#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace getGrColorSpace();
    bool IsSupportICCProfile();
#endif

private:
    DISALLOW_COPY_AND_MOVE(JpegDecoder);
    bool ParseExifData();
    J_COLOR_SPACE GetDecodeFormat(PlPixelFormat format, PlPixelFormat &outputFormat);
    void CreateHwDecompressor();
    uint32_t DoSwDecode(DecodeContext &context);
    void FinishOldDecompress();
    uint32_t DecodeHeader();
    uint32_t StartDecompress(const PixelDecodeOptions &opts);
    uint32_t GetRowBytes();
    void CreateDecoder();
    bool IsMarker(uint8_t rawPrefix, uint8_t rawMarkderCode, uint8_t markerCode);
    bool FindMarker(InputDataStream &stream, uint8_t marker);
    ExifTag getExifTagFromKey(const std::string &key);
    void FormatTimeStamp(std::string &value, std::string &src);

    static MultimediaPlugin::PluginServer &pluginServer_;
    jpeg_decompress_struct decodeInfo_;
    JpegSrcMgr srcMgr_;
    ErrorMgr jerr_;
    AbsImageDecompressComponent *hwJpegDecompress_ = nullptr;
    JpegDecodingState state_ = JpegDecodingState::UNDECIDED;
    uint32_t streamPosition_ = 0;  // may be changed by other decoders, record it and restore if needed.
    PlPixelFormat outputFormat_ = PlPixelFormat::UNKNOWN;
    PixelDecodeOptions opts_;
    EXIFInfo exifInfo_;
    ICCProfileInfo iccProfileInfo_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // JPEG_DECODER_H
