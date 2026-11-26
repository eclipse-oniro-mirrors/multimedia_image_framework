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

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <sstream>
#include <gtest/gtest.h>

#include "image_source.h"
#include "media_errors.h"
#include "pixel_map.h"
#ifdef IMAGE_PURGEABLE_PIXELMAP
#include "image_system_properties.h"
#include "purgeable_mem_base.h"
#include "source_stream.h"
#include "surface_buffer.h"
#endif

using namespace testing::ext;

namespace OHOS {
namespace Media {
#ifdef IMAGE_PURGEABLE_PIXELMAP
namespace {
// Only the stream dependency is controlled; the production admission and snapshot code is exercised unchanged.
class AdmissionSourceStream final : public SourceStream {
public:
    bool Read(uint32_t, ImagePlugin::DataStreamBuffer &) override { return false; }
    bool Peek(uint32_t, ImagePlugin::DataStreamBuffer &) override { return false; }
    bool Peek(uint32_t, uint8_t *, uint32_t, uint32_t &) override { return false; }

    bool Read(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize) override
    {
        ++readCalls;
        readSize = 0;
        if (!readSucceeds || outBuffer == nullptr || desiredSize > bufferSize || desiredSize > data.size()) {
            return false;
        }
        readSize = shortRead && desiredSize > 0 ? desiredSize - 1 : desiredSize;
        std::copy_n(data.data(), readSize, outBuffer);
        position += readSize;
        return true;
    }

    uint32_t Tell() override { return position; }
    bool Seek(uint32_t offset) override
    {
        ++seekCalls;
        if (seekCalls == failedSeekCall) {
            return false;
        }
        position = offset;
        return true;
    }

    size_t GetStreamSize() override { return size; }
    uint8_t *GetDataPtr() override
    {
        ++dataCalls;
        return contiguous ? data.data() : nullptr;
    }

    std::array<uint8_t, 32> data {1, 2, 3, 4, 5, 6, 7, 8};
    size_t size = 8;
    uint32_t position = 3;
    uint32_t failedSeekCall = 0;
    uint32_t dataCalls = 0;
    uint32_t readCalls = 0;
    uint32_t seekCalls = 0;
    bool contiguous = true;
    bool readSucceeds = true;
    bool shortRead = false;
};

// No pixel memory is installed in the base class: it must not free the borrowed test array or handle.
class AdmissionPixelMap final : public PixelMap {
public:
    uint32_t GetAllocationByteCount() override { return allocationSize; }
    const uint8_t *GetPixels() override { return hasPixels ? data.data() : nullptr; }
    AllocatorType GetAllocatorType() override { return allocator; }
    void *GetFd() const override
    {
        ++fdCalls;
        return handle;
    }

    std::array<uint8_t, 64> data {};
    uint32_t allocationSize = 64;
    AllocatorType allocator = AllocatorType::SHARE_MEM_ALLOC;
    bool hasPixels = true;
    void *handle = nullptr;
    mutable uint32_t fdCalls = 0;
};

class AssociatedAdmissionMemory final : public PurgeableMem::PurgeableMemBase {
public:
    int GetPinStatus() const override { return 1; }
};
} // namespace
#endif

class ImageSourcePurgeableTest : public testing::Test {
public:
#ifdef IMAGE_PURGEABLE_PIXELMAP
    void SetUp() override
    {
        const uint8_t data[] = {1};
        uint32_t errorCode = SUCCESS;
        source_ = ImageSource::CreateImageSource(data, sizeof(data), SourceOptions {}, errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
        ASSERT_NE(source_, nullptr);
        auto stream = std::make_unique<AdmissionSourceStream>();
        stream_ = stream.get();
        source_->sourceStreamPtr_ = std::move(stream);
        auto pixelMap = std::make_unique<AdmissionPixelMap>();
        pixels_ = pixelMap.get();
        pixelMap_ = std::move(pixelMap);
        options_.purgeableMode = PurgeableMode::REBUILD;
        // Every rejection test starts with all other eligibility conditions satisfied.
        ASSERT_TRUE(source_->ShouldMakePurgeable(options_, *pixelMap_, false));
    }

    void ExpectNoSnapshot(bool partial = false)
    {
        EXPECT_FALSE(source_->ShouldMakePurgeable(options_, *pixelMap_, partial));
        EXPECT_EQ(source_->TryMakePurgeable(0, options_, pixelMap_, partial), SUCCESS);
        if (stream_ != nullptr) {
            EXPECT_EQ(stream_->dataCalls, 0U);
            EXPECT_EQ(stream_->readCalls, 0U);
        }
        EXPECT_EQ(pixels_->fdCalls, 0U);
    }

    std::unique_ptr<ImageSource> source_;
    std::unique_ptr<PixelMap> pixelMap_;
    AdmissionSourceStream *stream_ = nullptr;
    AdmissionPixelMap *pixels_ = nullptr;
    DecodeOptions options_;
#endif
};

/**
 * @tc.name: InvalidModeRejectedAtCreationEntries001
 * @tc.desc: Invalid modes are rejected even when purgeable association is bypassed.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, InvalidModeRejectedAtCreationEntries001, TestSize.Level3)
{
    const uint8_t data[] = {1};
    uint32_t errorCode = SUCCESS;
    auto source = ImageSource::CreateImageSource(data, sizeof(data), SourceOptions {}, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(source, nullptr);
    DecodeOptions options;
    for (uint32_t mode : {2U, 3U, 4U, UINT32_MAX}) {
        SCOPED_TRACE(mode);
        options.purgeableMode = static_cast<PurgeableMode>(mode);
        errorCode = SUCCESS;
        EXPECT_EQ(source->CreatePixelMap(options, errorCode), nullptr);
        EXPECT_EQ(errorCode, ERR_IMAGE_INVALID_PARAMETER);
        errorCode = SUCCESS;
        EXPECT_EQ(source->CreatePixelMap(0, options, errorCode), nullptr);
        EXPECT_EQ(errorCode, ERR_IMAGE_INVALID_PARAMETER);
        errorCode = SUCCESS;
        EXPECT_EQ(source->CreatePixelMapEx(0, options, errorCode), nullptr);
        EXPECT_EQ(errorCode, ERR_IMAGE_INVALID_PARAMETER);
        errorCode = SUCCESS;
        EXPECT_EQ(source->CreatePixelMapEx(0, options, errorCode, false), nullptr);
        EXPECT_EQ(errorCode, ERR_IMAGE_INVALID_PARAMETER);
        errorCode = SUCCESS;
        EXPECT_EQ(source->CreatePixelMapList(options, errorCode), nullptr);
        EXPECT_EQ(errorCode, ERR_IMAGE_INVALID_PARAMETER);
    }
}

/**
 * @tc.name: AssociationBypassedAtCreation001
 * @tc.desc: The Sendable creation path returns valid ordinary pixels for both supported modes.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, AssociationBypassedAtCreation001, TestSize.Level3)
{
    uint32_t errorCode = SUCCESS;
    auto source = ImageSource::CreateImageSource("/data/local/tmp/image/test.png", SourceOptions {}, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(source, nullptr);
    DecodeOptions options;
    options.desiredSize = {32, 32};
    options.desiredPixelFormat = PixelFormat::RGBA_8888;
    options.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    for (auto mode : {PurgeableMode::NONE, PurgeableMode::REBUILD}) {
        SCOPED_TRACE(static_cast<uint32_t>(mode));
        options.purgeableMode = mode;
        auto pixelMap = source->CreatePixelMapEx(0, options, errorCode, false);
        ASSERT_EQ(errorCode, SUCCESS);
        ASSERT_NE(pixelMap, nullptr);
        EXPECT_EQ(pixelMap->GetWidth(), options.desiredSize.width);
        EXPECT_EQ(pixelMap->GetHeight(), options.desiredSize.height);
        EXPECT_NE(pixelMap->GetPixels(), nullptr);
#ifdef IMAGE_PURGEABLE_PIXELMAP
        EXPECT_FALSE(pixelMap->IsPurgeable());
        EXPECT_EQ(pixelMap->GetPurgeableMemPtr(), nullptr);
#endif
    }
}

#ifdef IMAGE_PURGEABLE_PIXELMAP
/**
 * @tc.name: SourceRatioRejectedAtCreationEntries001
 * @tc.desc: Oversized encoded inputs leave ordinary decoded pixels through every single-image entry.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, SourceRatioRejectedAtCreationEntries001, TestSize.Level3)
{
    uint32_t errorCode = SUCCESS;
    auto source = ImageSource::CreateImageSource("/data/local/tmp/image/test.png", SourceOptions {}, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(source, nullptr);
    DecodeOptions options;
    options.desiredSize = {1, 1};
    options.desiredPixelFormat = PixelFormat::RGBA_8888;
    options.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    options.purgeableMode = PurgeableMode::REBUILD;
    for (uint32_t entry = 0; entry < 3; ++entry) {
        SCOPED_TRACE(entry);
        auto pixelMap = entry == 0 ? source->CreatePixelMap(options, errorCode) :
            entry == 1 ? source->CreatePixelMap(0, options, errorCode) :
            source->CreatePixelMapEx(0, options, errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
        ASSERT_NE(pixelMap, nullptr);
        ASSERT_GT(pixelMap->GetAllocationByteCount(), 0U);
        ASSERT_GT(source->GetSourceSize(), pixelMap->GetAllocationByteCount() / 2);
        EXPECT_FALSE(pixelMap->IsPurgeable());
        EXPECT_NE(pixelMap->GetPixels(), nullptr);
    }
}

/**
 * @tc.name: RequestAndBackupGate001
 * @tc.desc: Explicit requests work independently of the debug setting; backup sources never request association.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, RequestAndBackupGate001, TestSize.Level3)
{
    EXPECT_TRUE(source_->IsPurgeableRequested(options_));
    options_.purgeableMode = PurgeableMode::NONE;
    // Observe, but never change, the device-wide debug parameter. Both parameter values require separate runs.
    EXPECT_EQ(source_->IsPurgeableRequested(options_), ImageSystemProperties::GetPurgeablePixelMapEnabled());
    source_->isPurgeableBackup_ = true;
    ExpectNoSnapshot();
    options_.purgeableMode = PurgeableMode::REBUILD;
    ExpectNoSnapshot();
}

/**
 * @tc.name: NoneModeFollowsDebugSetting001
 * @tc.desc: NONE follows the current debug setting without changing persistent device configuration.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, NoneModeFollowsDebugSetting001, TestSize.Level3)
{
    options_.purgeableMode = PurgeableMode::NONE;
    const bool debugEnabled = ImageSystemProperties::GetPurgeablePixelMapEnabled();
    EXPECT_EQ(source_->ShouldMakePurgeable(options_, *pixelMap_, false), debugEnabled);
    EXPECT_EQ(source_->TryMakePurgeable(0, options_, pixelMap_, false), SUCCESS);
    EXPECT_EQ(stream_->dataCalls, debugEnabled ? 1U : 0U);
    EXPECT_EQ(pixels_->fdCalls, debugEnabled ? 1U : 0U);
    EXPECT_FALSE(pixelMap_->IsPurgeable());
}

/**
 * @tc.name: ReusedPixelMapRejected001
 * @tc.desc: Requesting an existing output PixelMap prevents association before creating a backup.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, ReusedPixelMapRejected001, TestSize.Level3)
{
    options_.reusePixelmap = std::make_shared<PixelMap>();
    ExpectNoSnapshot();
}

/**
 * @tc.name: IncrementalSourceRejected001
 * @tc.desc: Incremental sources remain ineligible even when the source reports complete input.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, IncrementalSourceRejected001, TestSize.Level3)
{
    ASSERT_TRUE(stream_->IsStreamCompleted());
    source_->isIncrementalSource_ = true;
    ExpectNoSnapshot();
}

/**
 * @tc.name: PartialOutputRejected001
 * @tc.desc: Partial decoded output is rejected independently of incremental-source state.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, PartialOutputRejected001, TestSize.Level3)
{
    ExpectNoSnapshot(true);
}

/**
 * @tc.name: AlreadyAssociatedRejected001
 * @tc.desc: Existing purgeable metadata is not replaced and no duplicate backup is created.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, AlreadyAssociatedRejected001, TestSize.Level3)
{
    auto memory = std::make_shared<AssociatedAdmissionMemory>();
    pixelMap_->SetPurgeableMemPtr(memory);
    ASSERT_TRUE(pixelMap_->IsPurgeable());
    ExpectNoSnapshot();
    EXPECT_EQ(pixelMap_->GetPurgeableMemPtr(), memory);
}

/**
 * @tc.name: AllocatorGate001
 * @tc.desc: Only Ashmem and DMA allocators pass the admission predicate.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, AllocatorGate001, TestSize.Level3)
{
    for (auto allocator : {AllocatorType::SHARE_MEM_ALLOC, AllocatorType::DMA_ALLOC}) {
        SCOPED_TRACE(static_cast<int32_t>(allocator));
        pixels_->allocator = allocator;
        EXPECT_TRUE(source_->ShouldMakePurgeable(options_, *pixelMap_, false));
    }
    for (auto allocator : {AllocatorType::DEFAULT, AllocatorType::HEAP_ALLOC, AllocatorType::CUSTOM_ALLOC}) {
        SCOPED_TRACE(static_cast<int32_t>(allocator));
        pixels_->allocator = allocator;
        ExpectNoSnapshot();
    }
}

/**
 * @tc.name: MissingSourceRejected001
 * @tc.desc: An absent source stream cannot provide rebuild data.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, MissingSourceRejected001, TestSize.Level3)
{
    source_->sourceStreamPtr_.reset();
    stream_ = nullptr;
    ExpectNoSnapshot();
    EXPECT_EQ(source_->CreateBackupImageSource(), nullptr);
}

/**
 * @tc.name: SourceSizeGate001
 * @tc.desc: Check zero, UINT32_MAX, and unrepresentable source lengths without allocating large buffers.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, SourceSizeGate001, TestSize.Level3)
{
    stream_->size = 0;
    ExpectNoSnapshot();
    EXPECT_EQ(source_->CreateBackupImageSource(), nullptr);
    stream_->size = UINT32_MAX;
    EXPECT_TRUE(source_->ShouldMakePurgeable(options_, *pixelMap_, false));
    if (sizeof(size_t) > sizeof(uint32_t)) {
        stream_->size = static_cast<size_t>(UINT32_MAX) + 1;
        ExpectNoSnapshot();
        EXPECT_EQ(source_->CreateBackupImageSource(), nullptr);
    }
}

/**
 * @tc.name: NullPixelMapRejected001
 * @tc.desc: No backup is created when decoding supplies no PixelMap.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, NullPixelMapRejected001, TestSize.Level3)
{
    pixelMap_.reset();
    EXPECT_EQ(source_->TryMakePurgeable(0, options_, pixelMap_, false), SUCCESS);
    EXPECT_EQ(pixelMap_, nullptr);
    EXPECT_EQ(stream_->dataCalls, 0U);
}

/**
 * @tc.name: PixelMemoryGate001
 * @tc.desc: Null pixel address and zero allocation each prevent snapshot creation.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, PixelMemoryGate001, TestSize.Level3)
{
    pixels_->hasPixels = false;
    ASSERT_TRUE(source_->ShouldMakePurgeable(options_, *pixelMap_, false));
    EXPECT_EQ(source_->TryMakePurgeable(0, options_, pixelMap_, false), SUCCESS);
    EXPECT_EQ(stream_->dataCalls, 0U);
    pixels_->hasPixels = true;
    pixels_->allocationSize = 0;
    EXPECT_EQ(source_->TryMakePurgeable(0, options_, pixelMap_, false), SUCCESS);
    EXPECT_EQ(stream_->dataCalls, 0U);
    EXPECT_EQ(pixels_->fdCalls, 0U);
    EXPECT_FALSE(pixelMap_->IsPurgeable());
}

/**
 * @tc.name: HalfAllocationBoundary001
 * @tc.desc: Equal and smaller sources reach handle validation; larger ones stop before any snapshot copy.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, HalfAllocationBoundary001, TestSize.Level3)
{
    struct Boundary {
        uint32_t allocation;
        size_t source;
        bool passes;
    };
    for (const auto &boundary : {Boundary {64, 31, true}, Boundary {64, 32, true}, Boundary {64, 33, false},
        Boundary {65, 32, true}, Boundary {65, 33, false}}) {
        SCOPED_TRACE(boundary.allocation);
        SCOPED_TRACE(boundary.source);
        stream_->size = boundary.source;
        stream_->dataCalls = 0;
        pixels_->allocationSize = boundary.allocation;
        pixels_->fdCalls = 0;
        ASSERT_TRUE(source_->ShouldMakePurgeable(options_, *pixelMap_, false));
        // A null handle stops accepted sizes before any real kernel operation.
        ASSERT_EQ(source_->TryMakePurgeable(0, options_, pixelMap_, false), SUCCESS);
        EXPECT_EQ(stream_->dataCalls, boundary.passes ? 1U : 0U);
        EXPECT_EQ(pixels_->fdCalls, boundary.passes ? 1U : 0U);
        EXPECT_FALSE(pixelMap_->IsPurgeable());
    }
}

/**
 * @tc.name: IndependentOfMemoryPreferenceAndEditable001
 * @tc.desc: Low-RAM preference and editable output are not additional admission restrictions.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, IndependentOfMemoryPreferenceAndEditable001, TestSize.Level3)
{
    for (auto preference : {MemoryUsagePreference::DEFAULT, MemoryUsagePreference::LOW_RAM}) {
        SCOPED_TRACE(static_cast<int32_t>(preference));
        source_->SetMemoryUsagePreference(preference);
        for (bool editable : {false, true}) {
            SCOPED_TRACE(editable);
            options_.editable = editable;
            pixelMap_->SetEditable(editable);
            EXPECT_TRUE(source_->ShouldMakePurgeable(options_, *pixelMap_, false));
        }
    }
}

/**
 * @tc.name: InvalidHandlesRejected001
 * @tc.desc: Missing Ashmem/DMA contexts and negative descriptors stop before backend attachment.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, InvalidHandlesRejected001, TestSize.Level3)
{
    int invalidFd = -1;
    auto surface = SurfaceBuffer::Create();
    ASSERT_NE(surface, nullptr);
    ASSERT_LT(surface->GetFileDescriptor(), 0);
    for (auto allocator : {AllocatorType::SHARE_MEM_ALLOC, AllocatorType::DMA_ALLOC}) {
        pixels_->allocator = allocator;
        for (bool missing : {true, false}) {
            SCOPED_TRACE(static_cast<int32_t>(allocator));
            SCOPED_TRACE(missing);
            pixels_->handle = missing ? nullptr : allocator == AllocatorType::SHARE_MEM_ALLOC ?
                static_cast<void *>(&invalidFd) : static_cast<void *>(surface.GetRefPtr());
            pixels_->fdCalls = 0;
            EXPECT_EQ(source_->TryMakePurgeable(0, options_, pixelMap_, false), SUCCESS);
            EXPECT_EQ(pixels_->fdCalls, 1U);
            EXPECT_FALSE(pixelMap_->IsPurgeable());
            EXPECT_EQ(pixelMap_->GetPurgeableMemPtr(), nullptr);
        }
    }
}

/**
 * @tc.name: ContiguousBackupIsIndependent001
 * @tc.desc: A replayable source is copied once and the backup is excluded from association.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, ContiguousBackupIsIndependent001, TestSize.Level3)
{
    auto backup = source_->CreateBackupImageSource();
    ASSERT_NE(backup, nullptr);
    EXPECT_EQ(stream_->dataCalls, 1U);
    EXPECT_EQ(stream_->readCalls, 0U);
    EXPECT_EQ(backup->GetSourceSize(), stream_->size);
    auto *data = backup->sourceStreamPtr_->GetDataPtr();
    ASSERT_NE(data, nullptr);
    EXPECT_NE(data, stream_->data.data());
    EXPECT_EQ(std::memcmp(data, stream_->data.data(), stream_->size), 0);
    stream_->data[0] = 99;
    EXPECT_EQ(data[0], 1);
    EXPECT_FALSE(backup->IsPurgeableRequested(options_));
}

/**
 * @tc.name: IstreamBackupIsIndependent001
 * @tc.desc: A non-contiguous input is retained as an independent buffer while preserving the input position.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, IstreamBackupIsIndependent001, TestSize.Level3)
{
    const std::string encodedData = "not-an-image-but-a-complete-source-snapshot";
    std::unique_ptr<ImageSource> backup;
    {
        auto input = std::make_unique<std::stringstream>(encodedData, std::ios::in | std::ios::binary);
        std::unique_ptr<std::istream> inputStream = std::move(input);
        uint32_t errorCode = SUCCESS;
        auto source = ImageSource::CreateImageSource(std::move(inputStream), SourceOptions {}, errorCode);
        ASSERT_EQ(errorCode, SUCCESS);
        ASSERT_NE(source, nullptr);
        ASSERT_EQ(source->sourceStreamPtr_->GetDataPtr(), nullptr);
        ASSERT_TRUE(source->sourceStreamPtr_->Seek(3));
        backup = source->CreateBackupImageSource();
        ASSERT_NE(backup, nullptr);
        EXPECT_EQ(source->sourceStreamPtr_->Tell(), 3U);
    }
    EXPECT_EQ(backup->sourceStreamPtr_->GetStreamType(), ImagePlugin::BUFFER_SOURCE_TYPE);
    ASSERT_EQ(backup->GetSourceSize(), encodedData.size());
    ASSERT_NE(backup->sourceStreamPtr_->GetDataPtr(), nullptr);
    EXPECT_EQ(std::memcmp(backup->sourceStreamPtr_->GetDataPtr(), encodedData.data(), encodedData.size()), 0);
}

/**
 * @tc.name: UnreplayableStreamRejected001
 * @tc.desc: Bad position, seek failure, read failure, short read, and restore failure prevent attachment.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, UnreplayableStreamRejected001, TestSize.Level3)
{
    for (uint32_t failure = 0; failure < 5; ++failure) {
        SCOPED_TRACE(failure);
        stream_->contiguous = false;
        stream_->position = failure == 0 ? static_cast<uint32_t>(stream_->size + 1) : 3;
        stream_->failedSeekCall = failure == 1 ? 1 : failure == 4 ? 2 : 0;
        stream_->readSucceeds = failure != 2;
        stream_->shortRead = failure == 3;
        stream_->seekCalls = 0;
        stream_->readCalls = 0;
        stream_->dataCalls = 0;
        ASSERT_TRUE(source_->ShouldMakePurgeable(options_, *pixelMap_, false));
        EXPECT_EQ(source_->TryMakePurgeable(0, options_, pixelMap_, false), SUCCESS);
        EXPECT_EQ(stream_->dataCalls, 1U);
        EXPECT_EQ(stream_->readCalls, failure < 2 ? 0U : 1U);
        EXPECT_EQ(pixels_->fdCalls, 0U);
        EXPECT_FALSE(pixelMap_->IsPurgeable());
        if (failure == 2 || failure == 3) {
            EXPECT_EQ(stream_->position, 3U);
        }
    }
}

/**
 * @tc.name: BackupFactorySizeLimitRejected001
 * @tc.desc: Source sizes above the buffer factory limit fall back without copying or accessing pixel handles.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourcePurgeableTest, BackupFactorySizeLimitRejected001, TestSize.Level3)
{
    // Exceeds CreateImageSource's 300 MiB input limit, but passes the ratio and UINT32_MAX checks.
    stream_->size = 300U * 1024 * 1024 + 1;
    pixels_->allocationSize = static_cast<uint32_t>(stream_->size * 2);
    ASSERT_TRUE(source_->ShouldMakePurgeable(options_, *pixelMap_, false));
    EXPECT_EQ(source_->TryMakePurgeable(0, options_, pixelMap_, false), SUCCESS);
    EXPECT_EQ(stream_->dataCalls, 1U);
    EXPECT_EQ(stream_->readCalls, 0U);
    EXPECT_EQ(pixels_->fdCalls, 0U);
    EXPECT_FALSE(pixelMap_->IsPurgeable());
}
#endif // IMAGE_PURGEABLE_PIXELMAP
} // namespace Media
} // namespace OHOS
