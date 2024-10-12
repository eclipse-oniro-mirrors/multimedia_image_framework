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

#ifndef INTERFACES_INNERKITS_INCLUDE_METADATA_H
#define INTERFACES_INNERKITS_INCLUDE_METADATA_H

#include <string>
#include "parcel.h"
#include "image_type.h"

namespace OHOS {
namespace Media {
class ImageMetadata : public Parcelable {
public:
    using PropertyMap = std::map<std::string, std::string>;
    using PropertyMapPtr = std::shared_ptr<ImageMetadata::PropertyMap>;
    virtual int GetValue(const std::string &key, std::string &value) const = 0;
    virtual bool SetValue(const std::string &key, const std::string &value) = 0;
    virtual bool RemoveEntry(const std::string &key) = 0;
    virtual bool Marshalling(Parcel &parcel) const = 0;
    virtual const ImageMetadata::PropertyMapPtr GetAllProperties() = 0;
    virtual std::shared_ptr<ImageMetadata> CloneMetadata() = 0;
};
} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERKITS_INCLUDE_METADATA_H