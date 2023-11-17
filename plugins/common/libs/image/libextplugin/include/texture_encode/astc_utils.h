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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_ASTC_UTILS_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_TEXTURE_ENCODE_ASTC_UTILS_H
#include <set>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

namespace OHOS {
namespace Media {
class AstcUtils {
public:
    /**
     * @brief Applies a mixing hash function to the given seed.
     *        The function combines bitwise and arithmetic operations to generate a mixed hash value.
     *
     * @param seed The initial seed value to be mixed.
     * @return The resulting mixed hash value.
     */
    static uint32_t SeedMixHash(uint32_t seed);

    /**
     * @brief Calculates seed numbers from the given integer 'num' and stores them in an array.
     *        Each seed number is an 8-bit part extracted from the 32-bit 'num'.
     *        The function then squares each element in the array.
     *
     * @param seedn An array to store the calculated seed numbers (output).
     * @param num   The input integer from which seed numbers are derived.
     */
    static void CalSeedNum(uint8_t seedn[SEED_NUM], uint32_t num);

    /**
     * @brief Calculates and returns the selected partition based on the given block width
     *        and partition values for a block compression algorithm.
     *
     * @param blockWidth       The width of the block for the compression algorithm.
     * @param partitionA       The value of partition A (input/output).
     * @param partitionB       The value of partition B (input/output).
     * @param partitionC       The value of partition C (input/output).
     * @param partitionD       The value of partition D (input/output).
     *
     * @return The selected partition index (0 to 3) for the block.
     */
    static uint8_t CalPartition(int32_t blockWidth, int32_t partitionA, int32_t partitionB,
        int32_t partitionC, int32_t partitionD)

    /**
     * @brief Selects a partition index based on the given parameters.
     *
     * @param seed           The seed value used for hashing and partition selection.
     * @param x              The x-coordinate, modified for small blocks.
     * @param y              The y-coordinate, modified for small blocks.
     * @param partitionCount The count of partitions for selection.
     * @param smallBlock     Flag indicating whether it's a small block (true) or not (false).
     * @return The selected partition index (0 to 3).
     */
    static uint8_t SelectPartition(int32_t seed, int32_t x, int32_t y, int32_t partitionCount, bool smallBlock);
};
} // namespace Media
} // namespace OHOS
#endif