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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_OHOSCODEC_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_OHOSCODEC_H

#include "include/codec/SkCodec.h"
#include "include/core/SkEncodedImageFormat.h"
#include "include/core/SkStream.h"
#include "include/core/SkTypes.h"

class SK_API SkOHOSCodec : SkNoncopyable {
public:
    enum class ExifOrientationBehavior {
        kIgnore,
        kRespect,
    };

    static std::unique_ptr<SkOHOSCodec> MakeFromCodec(std::unique_ptr<SkCodec>);

    static std::unique_ptr<SkOHOSCodec> MakeFromStream(std::unique_ptr<SkStream>,
                                                       SkPngChunkReader* = nullptr);

    static std::unique_ptr<SkOHOSCodec> MakeFromData(sk_sp<SkData>, SkPngChunkReader* = nullptr);

    virtual ~SkOHOSCodec();

    const SkImageInfo& getInfo() const { return fInfo; }

    const skcms_ICCProfile* getICCProfile() const {
        return fCodec->callGetEncodedInfo().profile();
    }

    SkEncodedImageFormat getEncodedFormat() const { return fCodec->getEncodedFormat(); }

    SkColorType computeOutputColorType(SkColorType requestedColorType);

    SkAlphaType computeOutputAlphaType(bool requestedUnpremul);

    sk_sp<SkColorSpace> computeOutputColorSpace(SkColorType outputColorType,
                                                sk_sp<SkColorSpace> prefColorSpace = nullptr);

    int computeSampleSize(SkISize* size) const;

    SkISize getSampledDimensions(int sampleSize) const;
  
    bool getSupportedSubset(SkIRect* desiredSubset) const;
 
    SkISize getSampledSubsetDimensions(int sampleSize, const SkIRect& subset) const;
    struct OHOSOptions : public SkCodec::Options {
        OHOSOptions()
            : SkCodec::Options(), fSampleSize(1)
        {}

        int fSampleSize;
    };

    SkCodec::Result getOHOSPixels(const SkImageInfo& info, void* pixels, size_t rowBytes,
            const OHOSOptions* options);

    SkCodec::Result getOHOSPixels(const SkImageInfo& info, void* pixels, size_t rowBytes);

    SkCodec::Result getPixels(const SkImageInfo& info, void* pixels, size_t rowBytes) {
        return this->getOHOSPixels(info, pixels, rowBytes);
    }

    SkCodec* codec() const { return fCodec.get(); }

protected:
    SkOHOSCodec(SkCodec*);

    virtual SkISize onGetSampledDimensions(int sampleSize) const = 0;
  
    virtual bool onGetSupportedSubset(SkIRect* desiredSubset) const = 0;
  
    virtual SkCodec::Result onGetOHOSPixels(const SkImageInfo& info, void* pixels,
        size_t rowBytes, const OHOSOptions& options) = 0;

private:
    const SkImageInfo               fInfo;
    std::unique_ptr<SkCodec>        fCodec;
};

class SkOHOSCodecAdapter : public SkOHOSCodec {
    public:

        explicit SkOHOSCodecAdapter(SkCodec*);

        ~SkOHOSCodecAdapter() override {}

    protected:

        SkISize onGetSampledDimensions(int sampleSize) const override;

        bool onGetSupportedSubset(SkIRect* desiredSubset) const override;

        SkCodec::Result onGetOHOSPixels(const SkImageInfo& info, void* pixels, size_t rowBytes,
            const OHOSOptions& options) override;

    private:

        using INHERITED = SkOHOSCodec;
};

class SkOHOSSampledCodec : public SkOHOSCodec {
public:
    explicit SkOHOSSampledCodec(SkCodec*);

    ~SkOHOSSampledCodec() override {}

protected:

    SkISize onGetSampledDimensions(int sampleSize) const override;

    bool onGetSupportedSubset(SkIRect* desiredSubset) const override { return true; }

    SkCodec::Result onGetOHOSPixels(const SkImageInfo& info, void* pixels, size_t rowBytes,
        const OHOSOptions& options) override;

private:
    SkISize accountForNativeScaling(int* sampleSize, int* nativeSampleSize = nullptr) const;

    SkCodec::Result sampledDecode(const SkImageInfo& info, void* pixels, size_t rowBytes,
        const OHOSOptions& options);

    using INHERITED = SkOHOSCodec;
};

#endif // SkOHOSCodec_DEFINED