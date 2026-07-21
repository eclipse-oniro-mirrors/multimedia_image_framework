# PixelMap Row-Stride Validation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reject PixelMaps whose linear row-stride addressing exceeds their actual backing allocation while leaving YUV validation unchanged.

**Architecture:** Add a shared `PixelMap` layout validator based on the last accessible row and actual allocator capacity. Invoke it after IPC memory attachment and use exact allocation-aware bounds in `CheckValidParam` as defense in depth.

**Tech Stack:** C++17, OpenHarmony Parcel/SurfaceBuffer, GoogleTest/HWTEST.

---

### Task 1: Add failing boundary tests

**Files:**
- Modify: `frameworks/innerkitsimpl/test/unittest/pixel_map_test/pixel_map_test.cpp`
- Modify: `frameworks/innerkitsimpl/test/unittest/pixel_map_test/pixel_map_parcel_test.cpp`

1. Add a direct-access regression test with width 3, height 100, RGBA_8888, 1200-byte storage, and row stride 64; expect last-row pixel access to fail.
2. Add exact-boundary tests for allocation sizes 6348 and 6347.
3. Add a YUV test proving the new linear-layout helper returns success without applying the RGB formula.
4. Run the `pixelmaptest` target and confirm the new tests fail before implementation.

### Task 2: Implement the shared layout validator

**Files:**
- Modify: `interfaces/innerkits/include/pixel_map.h`
- Modify: `frameworks/innerkitsimpl/common/src/pixel_map.cpp`

1. Declare a reusable PixelMap data-layout validation function.
2. Return success immediately for YUV and ASTC special layouts.
3. For linear layouts, reject non-positive or undersized row strides.
4. Calculate `(height - 1) * rowStride + rowDataSize` in `uint64_t` and compare it with `GetAllocationByteCount()` using subtraction-safe bounds.
5. Update `CheckValidParam` to validate the exact pixel end offset against the same actual allocation size.

### Task 3: Enforce the invariant at IPC completion

**Files:**
- Modify: `frameworks/innerkitsimpl/common/src/pixel_map.cpp`
- Modify: `frameworks/innerkitsimpl/common/src/pixel_map_parcel.cpp`

1. Invoke the helper after `UpdatePixelMapMemInfo()` in ordinary PixelMap unmarshalling.
2. Invoke the same helper in the record-parcel unmarshalling completion path.
3. Reject malformed input with the existing PixelMap creation error and normal cleanup.

### Task 4: Verify

**Files:**
- Test: `frameworks/innerkitsimpl/test/unittest/pixel_map_test/pixel_map_test.cpp`
- Test: `frameworks/innerkitsimpl/test/unittest/pixel_map_test/pixel_map_parcel_test.cpp`

1. Build `image_framework` from the configured OpenHarmony source root.
2. Run the existing `pixelmaptest` target.
3. Run `ImagePixelmapBaseFuzzTest` for row-stride mutation coverage.
4. Record unavailable XTS and real-device coverage explicitly; no public API or wire-format change is expected.
