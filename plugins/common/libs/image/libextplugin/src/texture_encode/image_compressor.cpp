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

#include "image_compressor.h"

#include <cmath>
#include <securec.h>

#include "abs_image_encoder.h"
#include "hilog/log.h"
#include "log_tags.h"

namespace OHOS {
namespace Media {
using namespace OHOS::HiviewDFX;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_PLUGIN, "ImageCompressor"};
}

static size_t FileIOGetSize(FILE *fileIn)
{
    size_t ret = 0;
    if (!fileIn) {
        HiLog::Error(LABEL, "fileIn is nullptr !");
        return -1;
    }
    ret = fseek(fileIn, 0, SEEK_END);
    if (ret != 0) {
        HiLog::Error(LABEL, "fseek offset failed !");
        return ret;
    }
    ret = ftell(fileIn);
    if (ret != 0) {
        HiLog::Error(LABEL, "ftell offset failed !");
        return ret;
    }
    ret = fseek(fileIn, 0, SEEK_SET);
    if (ret != 0) {
        HiLog::Error(LABEL, "fseek offset failed !");
        return ret;
    }
    return ret;
}

static int GetCores()
{
    return sysconf(_SC_NPROCESSORS_CONF);
}

static int32_t TidAffinityBindToCpu(unsigned int cpuID)
{
    int cores = GetCores();
    if (static_cast<int>(cpuID) >= cores) {
        HiLog::Error(LABEL, "TidAffinityBindToCpu cpuId failed !");
        return -1;
    }
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpuID, &mask);
    if (sched_setaffinity(getpid(), sizeof(mask), &mask) == -1) {
        HiLog::Error(LABEL, "TidAffinityBindToCpu sched_setaffinity failed !");
        return -1;
    }
    return 0;
}

std::shared_ptr<ImageCompressor> ImageCompressor::instance_ = nullptr;
std::mutex ImageCompressor::instanceMutex_;
std::shared_ptr<ImageCompressor> ImageCompressor::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        if (instance_ == nullptr) {
            instance_.reset(new ImageCompressor());
            instance_->Init();
        }
    }
    return instance_;
}
void ImageCompressor::Init()
{
    switch_  = true;
    if (switch_) {
        clOk_ = OHOS::InitOpenCL();
        if (!clOk_) {
            HiLog::Error(LABEL, "InitOpenCL error !");
        }
        InitPartition();
    }
}
bool ImageCompressor::CanCompress()
{
#ifdef UPLOAD_GPU_DISABLED
    return false;
#else
    return switch_ && clOk_;
#endif
}

cl_program ImageCompressor::LoadShader(cl_context context)
{
    cl_int err;
    sourceSize_ = strlen(g_programSource) + 1;
    cl_program p = clCreateProgramWithSource(context, 1, &g_programSource, &sourceSize_, &err);
    if (err || (!p)) {
        HiLog::Error(LABEL, "clCreateProgramWithSource error !");
        return nullptr;
    }
    return p;
}

std::string ImageCompressor::ReadSourceCode(const char *fileName)
{
    if (fileName == nullptr) {
        HiLog::Error(LABEL, "fileName is null!");
        return "";
    }

    std::fstream file(fileName, (std::fstream::in | std::fstream::binary));
    if (!file.is_open()) {
        HiLog::Error(LABEL, "Failed to open file: %s", fileName);
        return "";
    }

    std::string content;
    file.seekg(0, std::fstream::end);
    content.resize(file.tellg());
    file.seekg(0, std::fstream::beg);

    file.read(&content[0], content.size());
    file.close();

    sourceSize_ = content.size();
    return content;
}

bool ImageCompressor::CreateKernel()
{
    if (!context_ || !kernel_) {
        cl_int err;
        cl_platform_id platform_id;
        cl_device_id device_id;
        clGetPlatformIDs(1, &platform_id, NULL);
        if (!platform_id) {
            HiLog::Error(LABEL, "clGetPlatformIDs err!");
            return false;
        }
        clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, 1, &device_id, NULL);
        if (!device_id) {
            HiLog::Error(LABEL, "clGetDeviceIDs error!");
            return false;
        }
        context_ = clCreateContext(0, 1, &device_id, NULL, NULL, &err);
        if (!context_) {
            HiLog::Error(LABEL, "clCreateContext error %{public}d !", err);
        }
        queue_ = clCreateCommandQueueWithProperties(context_, device_id, 0, &err);
        if (!queue_) {
            HiLog::Error(LABEL, "clCreateCommandQueueWithProperties error %{public}d !", err);
        }
        cl_program program = LoadShader(context_);
        if (!program) {
            HiLog::Error(LABEL, "LoadShaderBin error !");
        }
        clBuildProgram(program, 1, &device_id, compileOption_.c_str(), NULL, NULL);
        kernel_ = clCreateKernel(program, "astc", &err);
        if (!kernel_) {
            HiLog::Error(LABEL, "clCreateKernel error %{public}d !", err);
        }
        clReleaseProgram(program);
    }
    if (!context_ || !kernel_ || !queue_) {
        ReleaseResource();
        HiLog::Error(LABEL, "build opencl program failed !");
        clOk_ = false;
        return false;
    }
    refCount_++;
    return true;
}

void ImageCompressor::ReleaseResource()
{
    clReleaseKernel(kernel_);
    kernel_ = NULL;
    clReleaseCommandQueue(queue_);
    queue_ = NULL;
    clReleaseContext(context_);
    context_ = NULL;
    instance_ = nullptr;
}

void ImageCompressor::GenAstcHeader(uint8_t *buffer, uint8_t blockX, uint8_t blockY, uint32_t dimX, uint32_t dimY)
{
    if (buffer == nullptr) {
        HiLog::Error(LABEL, "GenAstcHeader buffer is null");
        return;
    }
    uint8_t *headInfo = buffer;
    *headInfo++ = MAGIC_FILE_CONSTANT & BYTES_MASK;
    *headInfo++ = (MAGIC_FILE_CONSTANT >> BIT_SHIFT_8BITS) & BYTES_MASK;
    *headInfo++ = (MAGIC_FILE_CONSTANT >> BIT_SHIFT_16BITS) & BYTES_MASK;
    *headInfo++ = (MAGIC_FILE_CONSTANT >> BIT_SHIFT_24BITS) & BYTES_MASK;
    *headInfo++ = static_cast<uint8_t>(blockX);
    *headInfo++ = static_cast<uint8_t>(blockY);
    *headInfo++ = 1;
    *headInfo++ = dimX & BYTES_MASK;
    *headInfo++ = (dimX >> BIT_SHIFT_8BITS)& BYTES_MASK;
    *headInfo++ = (dimX >> BIT_SHIFT_16BITS)& BYTES_MASK;
    *headInfo++ = dimY & BYTES_MASK;
    *headInfo++ = (dimY >> BIT_SHIFT_8BITS)& BYTES_MASK;
    *headInfo++ = (dimY >> BIT_SHIFT_16BITS)& BYTES_MASK;
    *headInfo++ = 1 & BYTES_MASK;
    *headInfo++ = (1 >> BIT_SHIFT_8BITS) & BYTES_MASK;
    *headInfo++ = (1 >> BIT_SHIFT_16BITS) & BYTES_MASK;
}

void GetMaxAndSumVal(int32_t &numBlocks, uint32_t *blockErrs, uint32_t &max_val, uint32_t &sum_val)
{
    for (int32_t i = 0; i < numBlocks; i++) {
        sum_val += blockErrs[i];
        max_val = fmax(max_val, blockErrs[i]);
    }
}

bool ImageCompressor::TextureEncodeCL(uint8_t *data, int32_t strideIn, int32_t width, int32_t height, uint8_t *buffer)
{
    int32_t stride = strideIn >> STRIDE_RGBA_LOG2;
    std::lock_guard<std::mutex> lock(instanceMutex_);
    if (!clOk_ || width <= 0 || height <= 0 || !buffer || !data || (stride < width)) {
        HiLog::Error(LABEL, "TextureEncodeCL input parameters error");
        return  false;
    }
    GenAstcHeader(buffer, DIM, DIM, width, height);
    cl_int err;
    int32_t blockX = (width + DIM - 1) / DIM;
    int32_t blockY = (height + DIM - 1) / DIM;
    int32_t numBlocks = blockX * blockY;
    size_t local[] = {DIM, DIM};

    size_t global[GLOBAL_WH_NUM_CL];
    global[0] = (width % local[0] == 0 ? width : (width + local[0] - width % local[0]));
    global[1] = (height % local[1] == 0 ? height : (height + local[1] - height % local[1]));

    size_t astc_size = numBlocks * DIM * DIM;

    cl_image_format image_format = { CL_RGBA, CL_UNORM_INT8 };
    cl_image_desc desc = { CL_MEM_OBJECT_IMAGE2D, stride, height };
    cl_mem inputImage =
        clCreateImage(context_, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, &image_format, &desc, data, &err);
    cl_mem astcResult = clCreateBuffer(context_, CL_MEM_ALLOC_HOST_PTR, astc_size, NULL, &err);
    cl_mem partInfos =
        clCreateBuffer(context_, CL_MEM_COPY_HOST_PTR, sizeof(PartInfo) * parts_.size(), &parts_[0], &err);
    
    uint32_t *blockErrs = new uint32_t[numBlocks] {0};
    if (!blockErrs) {
        HiLog::Error(LABEL, "TextureEncodeCL blockErrs new failed");
        return false;
    }
    cl_mem clErrs = clCreateBuffer(context_, CL_MEM_USE_HOST_PTR, sizeof(uint32_t) * numBlocks, blockErrs, &err);

    int32_t kernelId = 0;
    err |= clSetKernelArg(kernel_, kernelId++, sizeof(cl_mem), &inputImage);
    err |= clSetKernelArg(kernel_, kernelId++, sizeof(cl_mem), &astcResult);
    err |= clSetKernelArg(kernel_, kernelId++, sizeof(cl_mem), &partInfos);
    err |= clSetKernelArg(kernel_, kernelId++, sizeof(cl_mem), &clErrs);

    err = clEnqueueNDRangeKernel(queue_, kernel_, GLOBAL_WH_NUM_CL, NULL, global, local, 0, NULL, NULL);

    clFinish(queue_);

    uint32_t max_val = 0, sum_val = 0;
    err = clEnqueueReadBuffer(queue_, clErrs, CL_TRUE, 0, sizeof(uint32_t) * numBlocks, blockErrs, 0, NULL, NULL);
    GetMaxAndSumVal(numBlocks, blockErrs, max_val, sum_val);
    clReleaseMemObject(inputImage);
    clReleaseMemObject(partInfos);
    clReleaseMemObject(clErrs);
    delete[] blockErrs;
    
    clEnqueueReadBuffer(queue_, astcResult, CL_TRUE, 0, astc_size, buffer + TEXTURE_HEAD_BYTES, 0, NULL, NULL);
    clReleaseMemObject(astcResult);

    return true;
}

std::function<void()> ImageCompressor::ScheduleReleaseTask()
{
    std::function<void()> task = [this]() {
        if (refCount_ > 0 && clOk_) {
            refCount_--;
            if (refCount_ <= 0) {
                this->ReleaseResource();

                std::ofstream saveFile(recordsPath_);
                if (!saveFile.is_open()) {
                    HiLog::Error(LABEL, "ScheduleReleaseTask saveFile is_open failed");
                    return;
                }
                std::lock_guard<std::mutex> mLock(recordsMutex_);
                for (auto s : failedRecords_) {
                    saveFile << s << "\n";
                }
                saveFile.close();
            }
        }
    };
    return task;
}

bool ImageCompressor::InitPartitionInfo(PartInfo *partInfos, int32_t part_index, int32_t part_count)
{
    if (partInfos == nullptr) {
        HiLog::Error(LABEL, "InitPartitionInfo partInfos is nullptr");
        return false;
    }
    int32_t texIdx = 0;
    int32_t counts[PARTITION_COUNT_4] = {0};
    for (int32_t y = 0; y < DIM; y++) {
        for (int32_t x = 0; x < DIM; x++) {
            int32_t part = AstcUtils::SelectPartition(part_index, x, y, part_count, true);
            partInfos->bitmaps[part] |= 1u << texIdx;
            counts[part]++;
            texIdx++;
        }
    }
    int32_t realPartCount = 0;
    if (counts[0] == 0) {
        realPartCount = 0;
    } else if (counts[1] == 0) {
        realPartCount = 1;
    } else if (counts[PARTITION_COUNT_2] == 0) {
        realPartCount = PARTITION_COUNT_2;
    } else if (counts[PARTITION_COUNT_3] == 0) {
        realPartCount = PARTITION_COUNT_3;
    } else {
        realPartCount = PARTITION_COUNT_4;
    }
    if (realPartCount == part_count) {
        return true;
    }
    return false;
}

void ImageCompressor::InitPartition()
{
    parts_.clear();
    int32_t arrSize = sizeof(partitions_) / sizeof(partitions_[0]);
    for (int32_t i = 0; i < arrSize; i++) {
        PartInfo p = {};
        if (InitPartitionInfo(&p, partitions_[i], PARTITION_COUNT_2)) {
            p.partid = partitions_[i];
            parts_.push_back(p);
        }
    }
    compileOption_ = "-D PARTITION_SERACH_MAX=" + std::to_string(parts_.size());
}
} // namespace Media
} // namespace OHOS