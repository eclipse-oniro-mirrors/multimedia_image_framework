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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_HOLDER_MANAGER_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_HOLDER_MANAGER_H

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <securec.h>

namespace OHOS {
namespace Media {
template<typename ContentType>
class ImageHolderManager {
public:
    ImageHolderManager() {}
    ~ImageHolderManager()
    {
        std::lock_guard<std::mutex> guard(holderMutex_);
        holder_.clear();
    }
    std::string save(std::shared_ptr<ContentType> content)
    {
        std::string id;
        do {
            id = genId();
        } while (exist(id));
        std::lock_guard<std::mutex> guard(holderMutex_);
        holder_.insert(std::pair<std::string, std::shared_ptr<ContentType>>(id, content));
        return id;
    }
    std::string save(std::shared_ptr<ContentType> content, int64_t uniqueId)
    {
        std::string id = std::to_string(uniqueId);
        if (exist(id)) {
            return id;
        }
        std::lock_guard<std::mutex> guard(holderMutex_);
        holder_.insert(std::pair<std::string, std::shared_ptr<ContentType>>(id, content));
        return id;
    }
    std::shared_ptr<ContentType> get(std::string id)
    {
        std::lock_guard<std::mutex> guard(holderMutex_);
        std::string localId = processEof(id);
        auto iter = holder_.find(localId);
        if (iter != holder_.end()) {
            return iter->second.lock();
        }
        return nullptr;
    }
    std::shared_ptr<ContentType> pop(std::string id)
    {
        std::lock_guard<std::mutex> guard(holderMutex_);
        std::string localId = processEof(id);
        auto iter = holder_.find(localId);
        if (iter != holder_.end()) {
            auto res = iter->second;
            while (holder_.count(localId)) {
                holder_.erase(localId);
            }
            return res;
        }
        return nullptr;
    }
    void release(std::string id)
    {
        std::lock_guard<std::mutex> guard(holderMutex_);
        std::string localId = processEof(id);
        while (holder_.count(localId)) {
            holder_.erase(localId);
        }
    }
    bool exist(std::string id)
    {
        std::lock_guard<std::mutex> guard(holderMutex_);
        std::string localId = processEof(id);
        return holder_.count(localId);
    }
private:
    std::map<std::string, std::weak_ptr<ContentType>> holder_;
    std::mutex idMutex_;
    std::mutex holderMutex_;
    uint32_t gId_ = 0;
    std::string genId()
    {
        std::lock_guard<std::mutex> guard(idMutex_);
        std::string res = std::to_string(gId_);
        gId_++;
        return res;
    }
    std::string processEof(std::string id)
    {
        if (!id.empty() && (id.back() == '\0')) {
            std::string tmp = std::string(id);
            tmp.pop_back();
            return tmp;
        }
        return id;
    }
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_HOLDER_MANAGER_H
