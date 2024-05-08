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

#ifndef ABS_IMAGE_DECODER_H
#define ABS_IMAGE_DECODER_H

#include <map>
#include <string>
#include <vector>
#include <cmath>
#include <unistd.h>
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include <sys/mman.h>
#include "ashmem.h"
#endif
#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif
#include "image_plugin_type.h"
#include "input_data_stream.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "plugin_service.h"
#include "hdr_type.h"

namespace OHOS {
namespace ImagePlugin {
const std::string ACTUAL_IMAGE_ENCODED_FORMAT = "actual_encoded_format";

struct NinePatchContext {
    // png nine patch info
    void *ninePatch = nullptr;
    // png nine patch info size;
    size_t patchSize = 0;
};
struct DecodeContext {
    // In: input the image head info.
    PlImageInfo info;
    // In: input the pixelmap uniqueId.
    uint32_t pixelmapUniqueId_;
    // InOut: input the buffer and bufferSize, output pixels data and dataSize.
    PlImageBuffer pixelsBuffer;
    // In: whether the source data is completed.
    // data incomplete may occur when it is in incremental data source.
    // when this state is false, data incomplete is not an exception,
    // so the decoding cannot be failed because data incomplete,
    // but should decode as much as possible based on the existing data.
    bool ifSourceCompleted = true;
    // Out: output the PixelFormat.
    PlPixelFormat pixelFormat = PlPixelFormat::RGBA_8888;
    // Out: output the ColorSpace.
    PlColorSpace colorSpace = PlColorSpace::UNKNOWN;
    // Out: output if a partial image output.
    bool ifPartialOutput = false;
    // Out: output allocator type.
    Media::AllocatorType allocatorType = Media::AllocatorType::SHARE_MEM_ALLOC;
    // Out: output allocator release function.
    Media::CustomFreePixelMap freeFunc = nullptr;
    // Out: png nine patch context;
    NinePatchContext ninePatchContext;
    // Out: output YUV data info
    PlYuvDataInfo yuvInfo;
    // Out: output the final pixelMap Info, only size is used now.
    PlImageInfo outInfo;
    // Out: Whether to perform hard decoding 0 is no 1 is yes
    bool isHardDecode = false;
    // Out: hard decode error message
    std::string hardDecodeError;
    // Out: hdr type
    Media::ImageHdrType hdrType = Media::ImageHdrType::UNKNOWN;
    Media::ResolutionQuality resolutionQuality = Media::ResolutionQuality::LOW;
    bool isAisr = false;
    // Out: colorSpace
    ColorManager::ColorSpaceName grColorSpaceName = ColorManager::NONE;
};

struct ProgDecodeContext {
    DecodeContext decodeContext;

    static constexpr uint8_t DEFAULT_STEP = 10;
    static constexpr uint8_t FULL_PROGRESS = 100;
    // In: step size requesting advancement, in percentage, 1-100.
    // if it is an incremental data source and the remaining image data does not
    // reach the required amount, try to decode to the maximum possible number.
    uint8_t desiredStep = DEFAULT_STEP;

    // InOut: in percentage, 1-100.
    // input total process progress after last decoding step,
    // output total process progress after current decoding step.
    uint8_t totalProcessProgress = 0;
};

struct PixelDecodeOptions {
    PlRect CropRect;
    PlSize desiredSize;
    float rotateDegrees = 0;
    static constexpr uint32_t DEFAULT_SAMPLE_SIZE = 1;
    uint32_t sampleSize = DEFAULT_SAMPLE_SIZE;
    PlPixelFormat desiredPixelFormat = PlPixelFormat::RGBA_8888;
    PlColorSpace desiredColorSpace = PlColorSpace::UNKNOWN;
    PlAlphaType desireAlphaType = PlAlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    bool allowPartialImage = true;
    bool editable = false;
    PlFillColor plFillColor;
    PlFillColor plStrokeColor;
    PlSVGResize plSVGResize;
    std::shared_ptr<OHOS::ColorManager::ColorSpace> plDesiredColorSpace = nullptr;
};

class AbsImageDecoder {
public:
    static constexpr uint32_t DEFAULT_IMAGE_NUM = 1;
    static constexpr uint32_t E_NO_EXIF = 1;
    static constexpr uint32_t DEFAULT_GAINMAP_OFFSET = 0;

    AbsImageDecoder() = default;

    virtual ~AbsImageDecoder() = default;

    // set image file source, start a new picture decoding process.
    // the InputDataStream points to the beginning of the image file.
    virtual void SetSource(InputDataStream &sourceStream) = 0;

    // reset the decoder, clear all the decoder's status data cache.
    virtual void Reset() = 0;

    // judge a image source has a property or not.
    virtual bool HasProperty(std::string key)
    {
        return false;
    }

    // set decode options before decode and get target decoded image info.
    virtual uint32_t SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info) = 0;

    // One-time decoding.
    virtual uint32_t Decode(uint32_t index, DecodeContext &context) = 0;

    // incremental decoding.
    virtual uint32_t PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &context) = 0;

    // get the number of top level images in the image file.
    virtual uint32_t GetTopLevelImageNum(uint32_t &num)
    {
        num = DEFAULT_IMAGE_NUM;
        return Media::SUCCESS;
    }

    // get image size without decoding image data.
    virtual uint32_t GetImageSize(uint32_t index, PlSize &size) = 0;

    // get image property.
    virtual uint32_t GetImagePropertyInt(uint32_t index, const std::string &key, int32_t &value)
    {
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    // get image property.
    virtual uint32_t GetImagePropertyString(uint32_t index, const std::string &key, std::string &value)
    {
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    // modify image property.
    virtual uint32_t ModifyImageProperty(uint32_t index, const std::string &key,
        const std::string &value, const std::string &path)
    {
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    virtual uint32_t ModifyImageProperty(uint32_t index, const std::string &key,
                                         const std::string &value, const int fd)
    {
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    virtual uint32_t ModifyImageProperty(uint32_t index, const std::string &key,
                                         const std::string &value, uint8_t *data, uint32_t size)
    {
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    // get filter area.
    virtual uint32_t GetFilterArea(const int &privacyType, std::vector<std::pair<uint32_t, uint32_t>> &ranges)
    {
        return E_NO_EXIF;
    }

#ifdef IMAGE_COLORSPACE_FLAG
    // get current source is support icc profile or not.
    virtual bool IsSupportICCProfile()
    {
        return false;
    }

    // if current source support icc. get relevant color gamut information by this method.
    virtual OHOS::ColorManager::ColorSpace getGrColorSpace()
    {
        return OHOS::ColorManager::ColorSpace(OHOS::ColorManager::ColorSpaceName::NONE);
    }
#endif

    virtual Media::ImageHdrType CheckHdrType()
    {
        return Media::ImageHdrType::SDR;
    }

    virtual uint32_t GetGainMapOffset()
    {
        return DEFAULT_GAINMAP_OFFSET;
    }

    virtual Media::HdrMetadata GetHdrMetadata(Media::ImageHdrType type)
    {
        return {};
    }

    virtual bool DecodeHeifGainMap(DecodeContext& context, float scale)
    {
        return false;
    }

    virtual bool GetHeifHdrColorSpace(ColorManager::ColorSpaceName &gainmap, ColorManager::ColorSpaceName &hdr)
    {
        return false;
    }

    virtual uint32_t GetHeifParseErr()
    {
        return 0;
    }

    // define multiple subservices for this interface
    static constexpr uint16_t SERVICE_DEFAULT = 0;
};
} // namespace ImagePlugin
} // namespace OHOS

DECLARE_INTERFACE(OHOS::ImagePlugin::AbsImageDecoder, IMAGE_DECODER_IID)

#endif // ABS_IMAGE_DECODER_H
