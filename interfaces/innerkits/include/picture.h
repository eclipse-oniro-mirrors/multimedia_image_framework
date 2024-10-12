/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_INCLUDE_PICTURE_H
#define INTERFACES_INNERKITS_INCLUDE_PICTURE_H

#include "pixel_map.h"
#include "auxiliary_picture.h"
#include "image_type.h"
#include <map>

namespace OHOS {
    class SurfaceBuffer;
}

namespace OHOS {
namespace Media {

class ExifMetadata;

class Picture : public Parcelable {
public:
    virtual ~Picture();

    NATIVEEXPORT static std::unique_ptr<Picture> Create(std::shared_ptr<PixelMap> &PixelMap);
    NATIVEEXPORT static std::unique_ptr<Picture> Create(sptr<SurfaceBuffer> &surfaceBuffer);
    NATIVEEXPORT static std::unique_ptr<PixelMap> SurfaceBuffer2PixelMap(sptr<SurfaceBuffer> &surfaceBuffer);
    NATIVEEXPORT std::shared_ptr<PixelMap> GetMainPixel();
    NATIVEEXPORT void SetMainPixel(std::shared_ptr<PixelMap> PixelMap);
    NATIVEEXPORT std::unique_ptr<PixelMap> GetHdrComposedPixelMap();
    NATIVEEXPORT std::shared_ptr<PixelMap> GetGainmapPixelMap();
    NATIVEEXPORT std::shared_ptr<AuxiliaryPicture> GetAuxiliaryPicture(AuxiliaryPictureType type);
    NATIVEEXPORT void SetAuxiliaryPicture(std::shared_ptr<AuxiliaryPicture> &picture);
    NATIVEEXPORT bool HasAuxiliaryPicture(AuxiliaryPictureType type);
    NATIVEEXPORT virtual bool Marshalling(Parcel &data) const override;
    NATIVEEXPORT static Picture *Unmarshalling(Parcel &data);
    NATIVEEXPORT static Picture *Unmarshalling(Parcel &data, PICTURE_ERR &error);
    NATIVEEXPORT int32_t SetExifMetadata(sptr<SurfaceBuffer> &surfaceBuffer);
    NATIVEEXPORT int32_t SetExifMetadata(std::shared_ptr<ExifMetadata> exifMetadata);
    NATIVEEXPORT std::shared_ptr<ExifMetadata> GetExifMetadata();
    NATIVEEXPORT bool SetMaintenanceData(sptr<SurfaceBuffer> &surfaceBuffer);
    NATIVEEXPORT sptr<SurfaceBuffer> GetMaintenanceData() const;

private:
    std::shared_ptr<PixelMap> mainPixelMap_;
    std::map<AuxiliaryPictureType, std::shared_ptr<AuxiliaryPicture>> auxiliaryPictures_;
    sptr<SurfaceBuffer> maintenanceData_;
    std::shared_ptr<ExifMetadata> exifMetadata_ = nullptr;
};
}
}

#endif //INTERFACES_INNERKITS_INCLUDE_PICTURE_H_