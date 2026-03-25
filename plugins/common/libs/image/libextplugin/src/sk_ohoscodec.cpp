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

#include "sk_ohoscodec.h"
#include "src/codec/SkSampler.h"
#include "include/codec/SkCodec.h"
#include "include/core/SkPixmap.h"
#include "src/codec/SkCodecPriv.h"
#include "src/codec/SkSampledCodec.h"
#ifdef USE_M133_SKIA
#include "src/base/SkMathPriv.h"
#else
#include "src/core/SkMathPriv.h"
#endif

static bool is_valid_sample_size(int sampleSize)
{
    return sampleSize > 0;
}

static constexpr int RGB_CHANNEL_COUNT = 3;
static constexpr int SAMPLE_SIZE_TWO = 2;
static constexpr int SAMPLE_SIZE_FOUR = 4;
static constexpr int SAMPLE_SIZE_EIGHT = 8;

static void load_gamut(SkPoint rgb[], int length, const skcms_Matrix3x3& xyz)
{
    // rx = rX / (rX + rY + rZ)
    // ry = rY / (rX + rY + rZ)
    // gx, gy, bx, and gy are calulcated similarly.
    for (int rgbIdx = 0; rgbIdx < length; rgbIdx++) {
        float sum = xyz.vals[rgbIdx][0] + xyz.vals[rgbIdx][1] + xyz.vals[rgbIdx][2];
        rgb[rgbIdx].fX = xyz.vals[rgbIdx][0] / sum;
        rgb[rgbIdx].fY = xyz.vals[rgbIdx][1] / sum;
    }
}

static float calculate_area(SkPoint abc[], int length)
{
    SkPoint a = abc[length - 3];
    SkPoint b = abc[length - 2];
    SkPoint c = abc[length - 1];
    return 0.5f * SkTAbs(a.fX*b.fY + b.fX*c.fY - a.fX*c.fY - c.fX*b.fY - b.fX*a.fY);
}

static constexpr float SRGB_D50_GAMUT_AREA = 0.084f;

static bool is_wide_gamut(const skcms_ICCProfile& profile)
{
    if (profile.has_toXYZD50) {
        SkPoint rgb[3];
        load_gamut(rgb, RGB_CHANNEL_COUNT, profile.toXYZD50);
        return calculate_area(rgb, RGB_CHANNEL_COUNT) > SRGB_D50_GAMUT_AREA;
    }

    return false;
}

static bool supports_any_down_scale(const SkCodec* codec)
{
    return codec->getEncodedFormat() == SkEncodedImageFormat::kWEBP;
}

static inline bool smaller_than(const SkISize& a, const SkISize& b)
{
    return a.width() < b.width() || a.height() < b.height();
}

static inline bool strictly_bigger_than(const SkISize& a, const SkISize& b)
{
    return a.width() > b.width() && a.height() > b.height();
}

SkOHOSCodec::SkOHOSCodec(SkCodec* codec)
    : fInfo(codec->getInfo()), fCodec(codec)
{}

SkOHOSCodec::~SkOHOSCodec() {}

std::unique_ptr<SkOHOSCodec> SkOHOSCodec::MakeFromStream(std::unique_ptr<SkStream> stream,
                                                         SkPngChunkReader* chunkReader)
{
    auto codec = SkCodec::MakeFromStream(std::move(stream), nullptr, chunkReader);
    return MakeFromCodec(std::move(codec));
}

std::unique_ptr<SkOHOSCodec> SkOHOSCodec::MakeFromCodec(std::unique_ptr<SkCodec> codec)
{
    if (nullptr == codec) {
        return nullptr;
    }

    switch ((SkEncodedImageFormat)codec->getEncodedFormat()) {
        case SkEncodedImageFormat::kPNG:
        case SkEncodedImageFormat::kICO:
        case SkEncodedImageFormat::kJPEG:
#ifndef SK_HAS_WUFFS_LIBRARY
        case SkEncodedImageFormat::kGIF:
#endif
        case SkEncodedImageFormat::kBMP:
        case SkEncodedImageFormat::kWBMP:
        case SkEncodedImageFormat::kHEIF:
        case SkEncodedImageFormat::kAVIF:
            return std::make_unique<SkOHOSSampledCodec>(codec.release());
#ifdef SK_HAS_WUFFS_LIBRARY
        case SkEncodedImageFormat::kGIF:
#endif
#ifdef SK_CODEC_DECODES_WEBP
        case SkEncodedImageFormat::kWEBP:
#endif
#ifdef SK_CODEC_DECODES_RAW
        case SkEncodedImageFormat::kDNG:
#endif
#if defined(SK_CODEC_DECODES_WEBP) || defined(SK_CODEC_DECODES_RAW) || defined(SK_HAS_WUFFS_LIBRARY)
            return std::make_unique<SkOHOSCodecAdapter>(codec.release());
#endif

        default:
            return nullptr;
    }
}

std::unique_ptr<SkOHOSCodec> SkOHOSCodec::MakeFromData(sk_sp<SkData> data,
                                                       SkPngChunkReader* chunkReader)
{
    if (!data) {
        return nullptr;
    }

    return MakeFromStream(SkMemoryStream::Make(std::move(data)), chunkReader);
}

SkColorType SkOHOSCodec::computeOutputColorType(SkColorType requestedColorType)
{
    bool highPrecision = fCodec->callGetEncodedInfo().bitsPerComponent() > 8;
    switch (requestedColorType) {
        case kARGB_4444_SkColorType:
            return kN32_SkColorType;
        case kN32_SkColorType:
            break;
        case kAlpha_8_SkColorType:
            // Fall through to kGray_8.  Before kGray_8_SkColorType existed,
            // we allowed clients to request kAlpha_8 when they wanted a
            // grayscale decode.
        case kGray_8_SkColorType:
            if (kGray_8_SkColorType == this->getInfo().colorType()) {
                return kGray_8_SkColorType;
            }
            break;
        case kRGB_565_SkColorType:
            if (kOpaque_SkAlphaType == this->getInfo().alphaType()) {
                return kRGB_565_SkColorType;
            }
            break;
        case kRGBA_F16_SkColorType:
            return kRGBA_F16_SkColorType;
        default:
            break;
    }

    return highPrecision ? kRGBA_F16_SkColorType : kN32_SkColorType;
}

SkAlphaType SkOHOSCodec::computeOutputAlphaType(bool requestedUnpremul)
{
    if (kOpaque_SkAlphaType == this->getInfo().alphaType()) {
        return kOpaque_SkAlphaType;
    }
    return requestedUnpremul ? kUnpremul_SkAlphaType : kPremul_SkAlphaType;
}

sk_sp<SkColorSpace> SkOHOSCodec::computeOutputColorSpace(SkColorType outputColorType,
                                                         sk_sp<SkColorSpace> prefColorSpace)
{
    switch (outputColorType) {
        case kRGBA_F16_SkColorType:
        case kRGB_565_SkColorType:
        case kRGBA_8888_SkColorType:
        case kBGRA_8888_SkColorType: {
            if (prefColorSpace) {
                return prefColorSpace;
            }

            const skcms_ICCProfile* encodedProfile = fCodec->callGetEncodedInfo().profile();
            if (encodedProfile) {
                if (auto encodedSpace = SkColorSpace::Make(*encodedProfile)) {
                    return encodedSpace;
                }

                if (is_wide_gamut(*encodedProfile)) {
                    return SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, SkNamedGamut::kDisplayP3);
                }
            }

            return SkColorSpace::MakeSRGB();
        }
        default:
            return nullptr;
    }
}

int SkOHOSCodec::computeSampleSize(SkISize* desiredSize) const
{
    SkASSERT(desiredSize);

    const auto origDims = fCodec->dimensions();
    if (!desiredSize || *desiredSize == origDims) {
        return 1;
    }

    if (smaller_than(origDims, *desiredSize)) {
        *desiredSize = origDims;
        return 1;
    }

    if (desiredSize->width() < 1 || desiredSize->height() < 1) {
        *desiredSize = SkISize::Make(std::max(1, desiredSize->width()),
                                     std::max(1, desiredSize->height()));
    }

    if (supports_any_down_scale(fCodec.get())) {
        return 1;
    }

    int sampleX = origDims.width()  / desiredSize->width();
    int sampleY = origDims.height() / desiredSize->height();
    int sampleSize = std::min(sampleX, sampleY);
    auto computedSize = this->getSampledDimensions(sampleSize);
    if (computedSize == *desiredSize) {
        return sampleSize;
    }

    if (computedSize == origDims || sampleSize == 1) {
        *desiredSize = computedSize;
        return 1;
    }

    if (strictly_bigger_than(computedSize, *desiredSize)) {
        while (true) {
            auto smaller = this->getSampledDimensions(sampleSize + 1);
            if (smaller == *desiredSize) {
                return sampleSize + 1;
            }
            if (smaller == computedSize || smaller_than(smaller, *desiredSize)) {
                *desiredSize = computedSize;
                return sampleSize;
            }

            sampleSize++;
            computedSize = smaller;
        }

        SkASSERT(false);
    }

    if (!smaller_than(computedSize, *desiredSize)) {
        *desiredSize = computedSize;
        return sampleSize;
    }

    while (sampleSize > SAMPLE_SIZE_TWO) {
        auto bigger = this->getSampledDimensions(sampleSize - 1);
        if (bigger == *desiredSize || !smaller_than(bigger, *desiredSize)) {
            *desiredSize = bigger;
            return sampleSize - 1;
        }
        sampleSize--;
    }

    *desiredSize = origDims;
    return 1;
}

SkISize SkOHOSCodec::getSampledDimensions(int sampleSize) const
{
    if (!is_valid_sample_size(sampleSize)) {
        return {0, 0};
    }

    if (1 == sampleSize) {
        return fCodec->dimensions();
    }

    return this->onGetSampledDimensions(sampleSize);
}

bool SkOHOSCodec::getSupportedSubset(SkIRect* desiredSubset) const
{
#ifdef USE_M133_SKIA
    if (!desiredSubset || !SkCodecPriv::IsValidSubset(*desiredSubset, fCodec->dimensions())) {
#else
    if (!desiredSubset || !is_valid_subset(*desiredSubset, fCodec->dimensions())) {
#endif
        return false;
    }

    return this->onGetSupportedSubset(desiredSubset);
}

SkISize SkOHOSCodec::getSampledSubsetDimensions(int sampleSize, const SkIRect& subset) const
{
    if (!is_valid_sample_size(sampleSize)) {
        return {0, 0};
    }

    SkIRect copySubset = subset;
    if (!this->getSupportedSubset(&copySubset) || copySubset != subset) {
        return {0, 0};
    }

    if (fCodec->dimensions() == subset.size()) {
        return this->getSampledDimensions(sampleSize);
    }

#ifdef USE_M133_SKIA
    return {SkCodecPriv::GetSampledDimension(subset.width(), sampleSize),
            SkCodecPriv::GetSampledDimension(subset.height(), sampleSize)};
#else
    return {get_scaled_dimension(subset.width(), sampleSize),
            get_scaled_dimension(subset.height(), sampleSize)};
#endif
}

SkCodec::Result SkOHOSCodec::getOHOSPixels(const SkImageInfo& requestInfo,
    void* requestPixels, size_t requestRowBytes, const OHOSOptions* options)
{
    if (!requestPixels) {
        return SkCodec::kInvalidParameters;
    }
    if (requestRowBytes < requestInfo.minRowBytes()) {
        return SkCodec::kInvalidParameters;
    }

    OHOSOptions defaultOptions;
    if (!options) {
        options = &defaultOptions;
    } else {
        if (options->fSubset) {
#ifdef USE_M133_SKIA
            if (!SkCodecPriv::IsValidSubset(*options->fSubset, fCodec->dimensions())) {
#else
            if (!is_valid_subset(*options->fSubset, fCodec->dimensions())) {
#endif
                return SkCodec::kInvalidParameters;
            }

            if (SkIRect::MakeSize(fCodec->dimensions()) == *options->fSubset) {
                defaultOptions = *options;
                defaultOptions.fSubset = nullptr;
                options = &defaultOptions;
            }
        }
    }
    auto getPixelsFn = [&](const SkImageInfo& info, void* pixels, size_t rowBytes,
                           const SkCodec::Options& opts, int requiredFrame
                           ) -> SkCodec::Result {
        SkOHOSCodec::OHOSOptions prevFrameOptions(
            reinterpret_cast<const SkOHOSCodec::OHOSOptions&>(opts));
        prevFrameOptions.fFrameIndex = requiredFrame;
        return this->getOHOSPixels(info, pixels, rowBytes, &prevFrameOptions);
    };
    auto result = fCodec->callHandleFrameIndex(requestInfo, requestPixels, requestRowBytes,
        *options, getPixelsFn);
    if (result != SkCodec::kSuccess) {
        return result;
    }

    return this->onGetOHOSPixels(requestInfo, requestPixels, requestRowBytes, *options);
}

SkCodec::Result SkOHOSCodec::getOHOSPixels(const SkImageInfo& info, void* pixels,
    size_t rowBytes)
{
    return this->getOHOSPixels(info, pixels, rowBytes, nullptr);
}

SkOHOSCodecAdapter::SkOHOSCodecAdapter(SkCodec* codec)
    : INHERITED(codec)
{}

SkISize SkOHOSCodecAdapter::onGetSampledDimensions(int sampleSize) const
{
#ifdef USE_M133_SKIA
    float scale = SkCodecPriv::GetScaleFromSampleSize(sampleSize);
#else
    float scale = get_scale_from_sample_size(sampleSize);
#endif
    return this->codec()->getScaledDimensions(scale);
}

bool SkOHOSCodecAdapter::onGetSupportedSubset(SkIRect* desiredSubset) const
{
    return this->codec()->getValidSubset(desiredSubset);
}

SkCodec::Result SkOHOSCodecAdapter::onGetOHOSPixels(const SkImageInfo& info, void* pixels,
    size_t rowBytes, const OHOSOptions& options)
{
    return this->codec()->getPixels(info, pixels, rowBytes, &options);
}

SkOHOSSampledCodec::SkOHOSSampledCodec(SkCodec* codec)
    : INHERITED(codec)
{}

SkISize SkOHOSSampledCodec::accountForNativeScaling(int* sampleSizePtr, int* nativeSampleSize) const
{
    SkISize preSampledSize = this->codec()->dimensions();
    int sampleSize = *sampleSizePtr;
    SkASSERT(sampleSize > 1);

    if (nativeSampleSize) {
        *nativeSampleSize = 1;
    }

    if (this->codec()->getEncodedFormat() == SkEncodedImageFormat::kJPEG) {
        switch (sampleSize) {
            case SAMPLE_SIZE_TWO:
            case SAMPLE_SIZE_FOUR:
            case SAMPLE_SIZE_EIGHT:
                *sampleSizePtr = 1;
#ifdef USE_M133_SKIA
                return this->codec()->getScaledDimensions(SkCodecPriv::GetScaleFromSampleSize(sampleSize));
#else
                return this->codec()->getScaledDimensions(get_scale_from_sample_size(sampleSize));
#endif
            default:
                break;
        }

        int ohosRemainder;
        const int ohosSampleSizes[] = { 8, 4, 2 };
        for (int supportedSampleSize : ohosSampleSizes) {
            int ohosActualSampleSize;
            SkTDivMod(sampleSize, supportedSampleSize, &ohosActualSampleSize, &ohosRemainder);
            if (0 == ohosRemainder) {
#ifdef USE_M133_SKIA
                float scale = SkCodecPriv::GetScaleFromSampleSize(supportedSampleSize);
#else
                float scale = get_scale_from_sample_size(supportedSampleSize);
#endif

                preSampledSize = this->codec()->getScaledDimensions(scale);

                *sampleSizePtr = ohosActualSampleSize;
                if (nativeSampleSize) {
                    *nativeSampleSize = supportedSampleSize;
                }
                break;
            }
        }
    }

    return preSampledSize;
}

SkISize SkOHOSSampledCodec::onGetSampledDimensions(int sampleSize) const
{
    const SkISize size = this->accountForNativeScaling(&sampleSize);
#ifdef USE_M133_SKIA
    return SkISize::Make(SkCodecPriv::GetSampledDimension(size.width(), sampleSize),
                         SkCodecPriv::GetSampledDimension(size.height(), sampleSize));
#else
    return SkISize::Make(get_scaled_dimension(size.width(), sampleSize),
                         get_scaled_dimension(size.height(), sampleSize));
#endif
}

SkCodec::Result SkOHOSSampledCodec::onGetOHOSPixels(const SkImageInfo& info, void* pixels,
    size_t rowBytes, const OHOSOptions& options)
{
    const SkIRect* subset = options.fSubset;
    if (!subset || subset->size() == this->codec()->dimensions()) {
        if (this->codec()->callDimensionsSupported(info.dimensions())) {
            return this->codec()->getPixels(info, pixels, rowBytes, &options);
        }

        return this->sampledDecode(info, pixels, rowBytes, options);
    }

    int sampleSize = options.fSampleSize;
    SkISize scaledSize = this->getSampledDimensions(sampleSize);
    if (!this->codec()->callDimensionsSupported(scaledSize)) {
        return this->sampledDecode(info, pixels, rowBytes, options);
    }

    int scaledSubsetX = subset->x() / sampleSize;
    int scaledSubsetY = subset->y() / sampleSize;
    int scaledSubsetWidth = info.width();
    int subsetScaledHeight = info.height();

    const SkImageInfo scaledInfo = info.makeDimensions(scaledSize);

    {
        SkIRect incrementalSubset = SkIRect::MakeXYWH(scaledSubsetX, scaledSubsetY,
                                                      scaledSubsetWidth, subsetScaledHeight);
        OHOSOptions incrementalOptions = options;
        incrementalOptions.fSubset = &incrementalSubset;
        const SkCodec::Result startIncrementalResult = this->codec()->startIncrementalDecode(
            scaledInfo, pixels, rowBytes, &incrementalOptions);
        if (SkCodec::kSuccess == startIncrementalResult) {
            int decodedRows = 0;
            const SkCodec::Result incrementalResult = this->codec()->incrementalDecode(&decodedRows);
            if (incrementalResult == SkCodec::kSuccess) {
                return SkCodec::kSuccess;
            }
            SkASSERT(incrementalResult == SkCodec::kIncompleteInput || incrementalResult == SkCodec::kErrorInInput);

            this->codec()->callFillIncompleteImage(scaledInfo, pixels, rowBytes,
                options.fZeroInitialized, subsetScaledHeight, decodedRows);
            return incrementalResult;
        } else if (startIncrementalResult != SkCodec::kUnimplemented) {
            return startIncrementalResult;
        }
    }

    SkIRect scanlineSubset = SkIRect::MakeXYWH(scaledSubsetX, 0, scaledSubsetWidth,
        scaledSize.height());
    OHOSOptions subsetOptions = options;
    subsetOptions.fSubset = &scanlineSubset;

    SkCodec::Result result = this->codec()->startScanlineDecode(scaledInfo,
        &subsetOptions);
    if (SkCodec::kSuccess != result) {
        return result;
    }

    SkASSERT(this->codec()->getScanlineOrder() == SkCodec::kTopDown_SkScanlineOrder);
    if (!this->codec()->skipScanlines(scaledSubsetY)) {
        this->codec()->callFillIncompleteImage(info, pixels, rowBytes, options.fZeroInitialized,
            subsetScaledHeight, 0);
        return SkCodec::kIncompleteInput;
    }

    int decodedLines = this->codec()->getScanlines(pixels, subsetScaledHeight, rowBytes);
    if (decodedLines != subsetScaledHeight) {
        return SkCodec::kIncompleteInput;
    }
    return SkCodec::kSuccess;
}

SkCodec::Result SkOHOSSampledCodec::sampledDecode(const SkImageInfo& info, void* pixels,
    size_t rowBytes, const OHOSOptions& options)
{
    SkASSERT(options.fSampleSize > 1);

    int sampleSize = options.fSampleSize;
    int nativeSampleSize;
    SkISize ohosNativeSize = this->accountForNativeScaling(&sampleSize, &nativeSampleSize);

    SkIRect subset;
    int ohosSubsetY = 0;
    int ohosSubsetWidth = ohosNativeSize.width();
    int ohosSubsetHeight = ohosNativeSize.height();
    if (options.fSubset) {
        const SkIRect* subsetPtr = options.fSubset;

        const int subsetX = subsetPtr->x() / nativeSampleSize;
        ohosSubsetY = subsetPtr->y() / nativeSampleSize;

#ifdef USE_M133_SKIA
        ohosSubsetWidth = SkCodecPriv::GetSampledDimension(subsetPtr->width(), nativeSampleSize);
        ohosSubsetHeight = SkCodecPriv::GetSampledDimension(subsetPtr->height(), nativeSampleSize);
#else
        ohosSubsetWidth = get_scaled_dimension(subsetPtr->width(), nativeSampleSize);
        ohosSubsetHeight = get_scaled_dimension(subsetPtr->height(), nativeSampleSize);
#endif

        subset.setXYWH(subsetX, 0, ohosSubsetWidth, ohosNativeSize.height());
    }

    const int ohosSampleX = ohosSubsetWidth / info.width();
    const int ohosSampleY = ohosSubsetHeight / info.height();

#ifdef USE_M133_SKIA
    const int ohosSamplingOffsetY = SkCodecPriv::GetStartCoord(ohosSampleY);
#else
    const int ohosSamplingOffsetY = get_start_coord(ohosSampleY);
#endif
    const int ohosStartY = ohosSamplingOffsetY + ohosSubsetY;
    const int ohosDstHeight = info.height();

    const SkImageInfo nativeInfo = info.makeDimensions(ohosNativeSize);

    {
        OHOSOptions incrementalOptions = options;
        SkIRect incrementalSubset;
        if (options.fSubset) {
            incrementalSubset.fTop     = ohosSubsetY;
            incrementalSubset.fBottom  = ohosSubsetY + ohosSubsetHeight;
            incrementalSubset.fLeft    = subset.fLeft;
            incrementalSubset.fRight   = subset.fRight;
            incrementalOptions.fSubset = &incrementalSubset;
        }
        const SkCodec::Result startResult = this->codec()->startIncrementalDecode(nativeInfo,
            pixels, rowBytes, &incrementalOptions);
        if (SkCodec::kSuccess == startResult) {
            SkSampler* ohosSampler = this->codec()->callGetSampler(true);
            if (!ohosSampler) {
                return SkCodec::kUnimplemented;
            }

            if (ohosSampler->setSampleX(ohosSampleX) != info.width()) {
                return SkCodec::kInvalidScale;
            }
#ifdef USE_M133_SKIA
            if (SkCodecPriv::GetSampledDimension(ohosSubsetHeight, ohosSampleY) != info.height()) {
#else
            if (get_scaled_dimension(ohosSubsetHeight, ohosSampleY) != info.height()) {
#endif
                return SkCodec::kInvalidScale;
            }

            ohosSampler->setSampleY(ohosSampleY);

            int rowsDecoded = 0;
            const SkCodec::Result incrementalResult = this->codec()->incrementalDecode(&rowsDecoded);
            if (incrementalResult == SkCodec::kSuccess) {
                return SkCodec::kSuccess;
            }
            SkASSERT(incrementalResult == SkCodec::kIncompleteInput || incrementalResult == SkCodec::kErrorInInput);

            SkASSERT(rowsDecoded <= info.height());
            this->codec()->callFillIncompleteImage(info, pixels, rowBytes, options.fZeroInitialized,
                                                   info.height(), rowsDecoded);
            return incrementalResult;
        } else if (startResult == SkCodec::kIncompleteInput
                || startResult == SkCodec::kErrorInInput) {
            return SkCodec::kInvalidInput;
        } else if (startResult != SkCodec::kUnimplemented) {
            return startResult;
        }
    }

    OHOSOptions ohosSampledOptions = options;
    if (options.fSubset) {
        ohosSampledOptions.fSubset = &subset;
    }
    SkCodec::Result startScanlineResult = this->codec()->startScanlineDecode(nativeInfo,
        &ohosSampledOptions);
    if (SkCodec::kIncompleteInput == startScanlineResult || SkCodec::kErrorInInput == startScanlineResult) {
        return SkCodec::kInvalidInput;
    } else if (SkCodec::kSuccess != startScanlineResult) {
        return startScanlineResult;
    }

    SkSampler* ohosSampler = this->codec()->callGetSampler(true);
    if (!ohosSampler) {
        return SkCodec::kInternalError;
    }

    if (ohosSampler->setSampleX(ohosSampleX) != info.width()) {
        return SkCodec::kInvalidScale;
    }
#ifdef USE_M133_SKIA
    if (SkCodecPriv::GetSampledDimension(ohosSubsetHeight, ohosSampleY) != info.height()) {
#else
    if (get_scaled_dimension(ohosSubsetHeight, ohosSampleY) != info.height()) {
#endif
        return SkCodec::kInvalidScale;
    }

    switch (this->codec()->getScanlineOrder()) {
        case SkCodec::kTopDown_SkScanlineOrder: {
            if (!this->codec()->skipScanlines(ohosStartY)) {
                this->codec()->callFillIncompleteImage(info, pixels, rowBytes, options.fZeroInitialized,
                    ohosDstHeight, 0);
                return SkCodec::kIncompleteInput;
            }
            void* pixelPtr = pixels;
            for (int y = 0; y < ohosDstHeight; y++) {
                if (1 != this->codec()->getScanlines(pixelPtr, 1, rowBytes)) {
                    this->codec()->callFillIncompleteImage(info, pixels, rowBytes,
                        options.fZeroInitialized, ohosDstHeight, y + 1);
                    return SkCodec::kIncompleteInput;
                }
                if (y < ohosDstHeight - 1) {
                    if (!this->codec()->skipScanlines(ohosSampleY - 1)) {
                        this->codec()->callFillIncompleteImage(info, pixels, rowBytes,
                            options.fZeroInitialized, ohosDstHeight, y + 1);
                        return SkCodec::kIncompleteInput;
                    }
                }
                pixelPtr = SkTAddOffset<void>(pixelPtr, rowBytes);
            }
            return SkCodec::kSuccess;
        }
        case SkCodec::kBottomUp_SkScanlineOrder: {
            SkASSERT(0 == ohosSubsetY && ohosNativeSize.height() == ohosSubsetHeight);
            int y;
            for (y = 0; y < ohosNativeSize.height(); y++) {
                int srcY = this->codec()->nextScanline();
#ifdef USE_M133_SKIA
                if (SkCodecPriv::IsCoordNecessary(srcY, ohosSampleY, ohosDstHeight)) {
                    void* pixelPtr = SkTAddOffset<void>(pixels,
                        rowBytes * SkCodecPriv::GetDstCoord(srcY, ohosSampleY));
#else
                if (is_coord_necessary(srcY, ohosSampleY, ohosDstHeight)) {
                    void* pixelPtr = SkTAddOffset<void>(pixels,
                        rowBytes * get_dst_coord(srcY, ohosSampleY));
#endif
                    if (1 != this->codec()->getScanlines(pixelPtr, 1, rowBytes)) {
                        break;
                    }
                } else {
                    if (!this->codec()->skipScanlines(1)) {
                        break;
                    }
                }
            }

            if (ohosNativeSize.height() == y) {
                return SkCodec::kSuccess;
            }

            const SkImageInfo ohosFillInfo = info.makeWH(info.width(), 1);
            for (; y < ohosNativeSize.height(); y++) {
                int srcY = this->codec()->outputScanline(y);
#ifdef USE_M133_SKIA
                if (!SkCodecPriv::IsCoordNecessary(srcY, ohosSampleY, ohosDstHeight)) {
#else
                if (!is_coord_necessary(srcY, ohosSampleY, ohosDstHeight)) {
#endif
                    continue;
                }

#ifdef USE_M133_SKIA
                void* rowPtr = SkTAddOffset<void>(pixels, rowBytes * SkCodecPriv::GetDstCoord(srcY, ohosSampleY));
#else
                void* rowPtr = SkTAddOffset<void>(pixels, rowBytes * get_dst_coord(srcY, ohosSampleY));
#endif
                SkSampler::Fill(ohosFillInfo, rowPtr, rowBytes, options.fZeroInitialized);
            }
            return SkCodec::kIncompleteInput;
        }
        default:
            SkASSERT(false);
            return SkCodec::kUnimplemented;
    }
}