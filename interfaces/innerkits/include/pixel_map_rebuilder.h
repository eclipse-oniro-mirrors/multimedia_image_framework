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

#ifndef INTERFACES_INNERKITS_INCLUDE_PIXEL_MAP_REBUILDER_H
#define INTERFACES_INNERKITS_INCLUDE_PIXEL_MAP_REBUILDER_H

#include <memory>
#include <mutex>
#include <shared_mutex>

namespace OHOS {
namespace Media {
class PixelMap;

class PixelMapRebuilder {
public:
    virtual ~PixelMapRebuilder() = default;
    virtual bool Rebuild(std::shared_ptr<PixelMap> &temporaryPixelmap) = 0;
    // A candidate must not adopt caller resources before registration commits.
    virtual void OnRegistered() {}
};

struct PixelMapRebuildState {
    // Execution takes a shared lock; retiring the association or replacing current takes an exclusive lock.
    std::shared_mutex purgeableMutex;
    std::mutex mutex;
    std::unique_ptr<PixelMapRebuilder> current;
    // Immutable after publication. A one-argument backend setter supplies locking only, not our Build dispatch.
    bool hasFrameworkBuilder = true;
};

} // namespace Media
} // namespace OHOS

#endif // INTERFACES_INNERKITS_INCLUDE_PIXEL_MAP_REBUILDER_H
