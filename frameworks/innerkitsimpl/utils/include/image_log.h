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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_LOG_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_LOG_H

#include "hilog/log.h"
#include "log_tags.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageCode"

#define IMAGE_LOGF(...) HILOG_FATAL(LOG_CORE, __VA_ARGS__)
#define IMAGE_LOGE(...) HILOG_ERROR(LOG_CORE, __VA_ARGS__)
#define IMAGE_LOGW(...) HILOG_WARN(LOG_CORE, __VA_ARGS__)
#define IMAGE_LOGI(...) HILOG_INFO(LOG_CORE, __VA_ARGS__)
#define IMAGE_LOGD(...) HILOG_DEBUG(LOG_CORE, __VA_ARGS__)

#define CHECK_ERROR_RETURN_RET_LOG(cond, ret, ...)      \
    do {                                                \
        if (cond) {                                     \
            HILOG_ERROR(LOG_CORE, __VA_ARGS__);         \
            return ret;                                 \
        }                                               \
    } while (0)                                         \

#define CHECK_ERROR_RETURN(cond)                        \
    do {                                                \
        if (cond) {                                     \
            return;                                     \
        }                                               \
    } while (0)                                         \


#define CHECK_ERROR_RETURN_LOG(cond, ...) \
    do {                                                \
        if (cond) {                                     \
            HILOG_ERROR(LOG_CORE, __VA_ARGS__);         \
            return;                                     \
        }                                               \
    } while (0)

#define CHECK_ERROR_PRINT_LOG(cond, ...)                \
    do {                                                \
        if (cond) {                                     \
            HILOG_ERROR(LOG_CORE, __VA_ARGS__);         \
        }                                               \
    } while (0)


#define CHECK_ERROR_RETURN_RET(cond, ret)               \
    do {                                                \
        if (cond) {                                     \
            return ret;                                 \
        }                                               \
    } while (0)

#define CHECK_DEBUG_RETURN_RET_LOG(cond, ret, ...)      \
    do {                                                \
        if (cond) {                                     \
            HILOG_DEBUG(LOG_CORE, __VA_ARGS__);         \
            return ret;                                 \
        }                                               \
    } while (0)                                         \

#define CHECK_DEBUG_RETURN_LOG(cond, ...) \
    do {                                                \
        if (cond) {                                     \
            HILOG_DEBUG(LOG_CORE, __VA_ARGS__);         \
            return;                                     \
        }                                               \
    } while (0)

#define CHECK_DEBUG_PRINT_LOG(cond, ...)                \
    do {                                                \
        if (cond) {                                     \
            HILOG_DEBUG(LOG_CORE, __VA_ARGS__);         \
        }                                               \
    } while (0)

#define CHECK_INFO_RETURN_RET_LOG(cond, ret, ...)      \
    do {                                                \
        if (cond) {                                     \
            HILOG_INFO(LOG_CORE, __VA_ARGS__);         \
            return ret;                                 \
        }                                               \
    } while (0)                                         \

#endif