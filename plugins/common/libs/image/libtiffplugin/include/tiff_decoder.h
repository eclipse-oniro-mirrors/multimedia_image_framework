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
#ifndef TIFF_DECODER_H
#define TIFF_DECODER_H
#include "abs_image_decoder.h"
#include "plugin_class_base.h"
#include "tiffio.h"
namespace OHOS {
namespace ImagePlugin {
using namespace Media;

class TiffDecoder : public AbsImageDecoder, public OHOS::MultimediaPlugin::PluginClassBase {
public:
    TiffDecoder();
    ~TiffDecoder() override;

public:
    void SetSource(InputDataStream& sourceStream) override;
    void Reset() override;
    bool HasProperty(std::string key) override;
    uint32_t SetDecodeOptions(uint32_t index, const PixelDecodeOptions& opts, PlImageInfo& info) override;
    uint32_t Decode(uint32_t index, DecodeContext& context) override;
    uint32_t PromoteIncrementalDecode(uint32_t index, ProgDecodeContext& progContext) override;
    uint32_t GetTopLevelImageNum(uint32_t& num) override;
    uint32_t GetImageSize(uint32_t index, Size& size) override;
    std::string GetPluginType() override
    {
        return "tiff";
    }
#ifdef IMAGE_COLORSPACE_FLAG
    bool IsSupportICCProfile() override
    {
        return isSupportICCProfile_;
    }
    OHOS::ColorManager::ColorSpace GetPixelMapColorSpace() override
    {
        return grColorSpace_;
    }
#endif

private:
    static tmsize_t ReadProc(thandle_t handle, void* data, tmsize_t size);
    static tmsize_t WriteProc(thandle_t handle, void* data, tmsize_t size);
    static toff_t SeekProc(thandle_t handle, toff_t off, int whence);
    static int CloseProc(thandle_t handle);
    static toff_t SizeProc(thandle_t handle);
    void RegisterTiffLogHandler();

#if !defined(CROSS_PLATFORM)
    bool AllocShareBufferInner(DecodeContext &context, uint64_t byteCount);
#endif
    bool AllocShareBuffer(DecodeContext &context, uint64_t byteCount);
    bool AllocDmaBuffer(DecodeContext &context, uint64_t byteCount);
    bool AllocBuffer(DecodeContext &context, uint64_t byteCount);
    bool AllocHeapBuffer(DecodeContext& context, uint64_t byteCount);

    bool CheckTiffIndex(uint32_t index);
    bool CheckTiffSizeIsOverflow();
    InputDataStream* inputStream_{nullptr};
    PixelDecodeOptions opts_;
    PlImageInfo info_;
    Size tiffSize_;
    TIFF* tifCodec_ = nullptr;

#ifdef IMAGE_COLORSPACE_FLAG
    void ParseICCProfile();
    bool isSupportICCProfile_ = true;
    OHOS::ColorManager::ColorSpace grColorSpace_ =
        OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
#endif
};
} // namespace ImagePlugin
} // namespace OHOS
#endif // TIFF_DECODER_H
