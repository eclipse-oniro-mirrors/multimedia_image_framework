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

#ifndef FRAMEWORKS_INNERKITSIMPL_CONVERTER_INCLUDE_POST_PROC_SLR_H
#define FRAMEWORKS_INNERKITSIMPL_CONVERTER_INCLUDE_POST_PROC_SLR_H

#include "image_type.h"
#include "include/private/SkMutex.h"
#include "src/core/SkLRUCache.h"

namespace OHOS {
namespace Media {

class SLRMat {
public:
    SLRMat() = default;
    SLRMat(Size size, PixelFormat format, void *data, int32_t rowStride, AllocatorType type)
        :size_(size), format_(format), data_(data), rowStride_(rowStride), type_(type) {}
    ~SLRMat() = default;
    Size size_;
    PixelFormat format_;
    void *data_;
    int32_t rowStride_;
    AllocatorType type_;
};

class SLRWeightKey {
public:
    SLRWeightKey(Size src, Size dst): src_(src), dst_(dst)
    {
        fKey = HashKey();
    }

    uint32_t HashKey()
    {
        uint32_t hash = 0;
        hash = mix(hash, SkGoodHash()(relax(src_.width)));
        hash = mix(hash, SkGoodHash()(relax(src_.height)));
        hash = mix(hash, SkGoodHash()(relax(dst_.width)));
        hash = mix(hash, SkGoodHash()(relax(dst_.height)));
        return hash;
    }

    uint32_t mix(uint32_t hash, uint32_t data)
    {
        hash += data;
        hash += (hash << 10); // 10 hash value
        hash ^= (hash >> 6); // 6 hash value
        return hash;
    }

    int32_t relax(SkScalar a)
    {
        if (SkScalarIsFinite(a)) {
            auto threshold = SkIntToScalar(1 << 12);
            return SkFloat2Bits(SkScalarRoundToScalar(a * threshold) / threshold);
        } else {
            return SkFloat2Bits(a);
        }
    }
    Size src_;
    Size dst_;
    uint32_t fKey;
};

using SLRWeightVec = std::vector<std::vector<float>>;
using SLRWeightMat = std::shared_ptr<SLRWeightVec>;
using SLRWeightTuple = std::tuple<SLRWeightMat, SLRWeightMat, SLRWeightKey>;
using SLRLRUCache = SkLRUCache<uint32_t, std::shared_ptr<SLRWeightTuple>>;
class SkSLRCacheMgr {
public:
    SkSLRCacheMgr(SLRLRUCache& slrCache, SkMutex& mutex)
        :fSLRCache(slrCache), fMutex(mutex)
    {
        fMutex.acquire();
    }
    SkSLRCacheMgr(SkSLRCacheMgr&&) = delete;
    SkSLRCacheMgr(const SkSLRCacheMgr&) = delete;
    SkSLRCacheMgr& operator=(const SkSLRCacheMgr&) = delete;
    SkSLRCacheMgr& operator=(SkSLRCacheMgr&&) = delete;

    ~SkSLRCacheMgr()
    {
        fMutex.release();
    }

    std::shared_ptr<SLRWeightTuple> find(uint32_t key)
    {
        auto weight = fSLRCache.find(key);
        return weight == nullptr ? nullptr : *weight;
    }

    std::shared_ptr<SLRWeightTuple> insert(uint32_t key, std::shared_ptr<SLRWeightTuple> weightTuple)
    {
        auto weight = fSLRCache.insert(key, std::move(weightTuple));
        return weight == nullptr ? nullptr : *weight;
    }

    int Count()
    {
        return fSLRCache.count();
    }

    void Reset()
    {
        fSLRCache.reset();
    }

private:
    SLRLRUCache& fSLRCache;
    SkMutex& fMutex;
};

class SLRProc {
public:
    static SLRWeightMat GetWeights(float coeff, int n);
    static void Serial(const SLRMat &src, SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y);
    static void Parallel(const SLRMat &src, SLRMat &dst, const SLRWeightMat &x, const SLRWeightMat &y);
    static void Laplacian(SLRMat &srcMat, void* data, float alpha);
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_CONVERTER_INCLUDE_POST_PROC_SLR_H