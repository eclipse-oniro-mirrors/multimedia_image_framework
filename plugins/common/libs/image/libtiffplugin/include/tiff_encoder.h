/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef TIFF_ENCODER_H
#define TIFF_ENCODER_H

#include "abs_image_encoder.h"
#include "plugin_class_base.h"
#include "image_type.h"
#include "tiffio.h"

namespace OHOS {
namespace ImagePlugin {

class TiffEncoder : public AbsImageEncoder, public OHOS::MultimediaPlugin::PluginClassBase {
public:
    TiffEncoder();
    ~TiffEncoder() override;

    uint32_t StartEncode(OutputDataStream &outputStream, PlEncodeOptions &option) override;
    uint32_t AddImage(PixelMap &pixelMap) override;
    uint32_t AddPicture(Picture &picture) override;
    uint32_t FinalizeEncode() override;

    uint32_t EncodeBinaryImageToTiff(const PixelBufferInfo* bufferInfo, OutputDataStream &outputStream,
                                     const PlPackingOptionsForTiff &option);

    std::string GetPluginType() const
    {
        return "tiff";
    }

private:
    static tmsize_t ReadProc(thandle_t handle, void *data, tmsize_t size);
    static tmsize_t WriteProc(thandle_t handle, void *data, tmsize_t size);
    static toff_t SeekProc(thandle_t handle, toff_t off, int whence);
    static int CloseProc(thandle_t handle);
    static toff_t SizeProc(thandle_t handle);

    struct TiffEncodeParam {
        uint16_t bitsPerSample = 0;
        uint16_t samplesPerPixel = 0;
        uint16_t photometric = 0;
    };

    bool IsSupportedPixelMapFormat(PixelFormat format);
    uint32_t ValidatePixelBufferInfo(const PixelBufferInfo &bufferInfo);
    uint32_t PrepareEncoding(const PixelBufferInfo &bufferInfo, PixelFormat format);
    uint32_t SelectCompression(PixelFormat formatValue, uint16_t &compression);
    static TiffEncodeParam GetEncodeParam(PixelFormat formatValue);
    static uint64_t GetDefaultRowBytes(uint32_t width, uint64_t bytesPerRow);

    uint32_t DoEncode();
    uint32_t ConfigureTiffTags();
    uint32_t WritePixelData();
    void CleanupTiffCodec();

    PixelBufferInfo bufferInfo_;
    TiffEncodeParam encodeParam_;
    PlPackingOptionsForTiff tiffPackingOption_;
    uint16_t compression_ = COMPRESSION_NONE;
    bool hasEncodeParams_ = false;
    bool isEncoding_ = false;
    TIFF *tifCodec_ = nullptr;
    OutputDataStream *outputStream_ = nullptr;
    PlEncodeOptions encodeOptions_;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // TIFF_ENCODER_H
