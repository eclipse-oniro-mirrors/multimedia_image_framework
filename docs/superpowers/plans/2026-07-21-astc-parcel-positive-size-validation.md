# ASTC Parcel Positive-Size Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reject non-positive ASTC real dimensions in both PixelMap parcel-reading paths.

**Architecture:** Keep validation at the two parcel trust boundaries. Add the missing check to `PixelMap::ReadAstcInfo`; retain and regression-test the existing equivalent check in `PixelMapRecordParcel::ReadAstcRealSize` without changing the parcel format or public APIs.

**Tech Stack:** C++17, OpenHarmony Parcel, GoogleTest, GN/Ninja.

## Global Constraints

- Width and height must both be greater than zero before `SetAstcRealSize` is called.
- Preserve parcel field order, public APIs, error-code mappings, ASTC encoding/decoding behavior, and language bindings.
- Do not change the existing 8192 maximum enforced by `pixel_map_parcel.cpp`.

---

### Task 1: Add regression coverage and the missing reader check

**Files:**
- Modify: `frameworks/innerkitsimpl/test/unittest/pixel_map_test/pixel_map_parcel_test.cpp`
- Modify: `frameworks/innerkitsimpl/common/src/pixel_map.cpp:3076`
- Verify unchanged behavior: `frameworks/innerkitsimpl/common/src/pixel_map_parcel.cpp:533`

**Interfaces:**
- Consumes: `bool PixelMap::ReadAstcInfo(Parcel &parcel, PixelMap *pixelMap)` and `PixelMap *PixelMapRecordParcel::UnmarshallingPixelMapForRecord(Parcel &parcel)`.
- Produces: Both readers reject ASTC real dimensions where `width <= 0 || height <= 0`.

- [x] **Step 1: Write the failing direct-reader test**

Add a test that writes `(0, 1)` and `(1, -1)` into separate parcels, calls `ReadAstcInfo` on an ASTC PixelMap, and expects `false` for each case. Add a valid `(1, 1, false)` parcel and expect `true` so the accepted path remains covered.

```cpp
HWTEST_F(PixelMapParcelTest, ReadAstcInfoRejectsNonPositiveSize, TestSize.Level3)
{
    PixelMap pixelMap;
    pixelMap.SetAstc(true);

    Parcel zeroWidthParcel;
    ASSERT_TRUE(zeroWidthParcel.WriteInt32(0));
    ASSERT_TRUE(zeroWidthParcel.WriteInt32(1));
    EXPECT_FALSE(pixelMap.ReadAstcInfo(zeroWidthParcel, &pixelMap));

    Parcel negativeHeightParcel;
    ASSERT_TRUE(negativeHeightParcel.WriteInt32(1));
    ASSERT_TRUE(negativeHeightParcel.WriteInt32(-1));
    EXPECT_FALSE(pixelMap.ReadAstcInfo(negativeHeightParcel, &pixelMap));

    Parcel validParcel;
    ASSERT_TRUE(validParcel.WriteInt32(1));
    ASSERT_TRUE(validParcel.WriteInt32(1));
    ASSERT_TRUE(validParcel.WriteBool(false));
    EXPECT_TRUE(pixelMap.ReadAstcInfo(validParcel, &pixelMap));
    Size realSize;
    pixelMap.GetAstcRealSize(realSize);
    EXPECT_EQ(realSize.width, 1);
    EXPECT_EQ(realSize.height, 1);
}
```

- [x] **Step 2: Write the record-parcel regression test**

Add a small helper that serializes the property prefix consumed before `ReadAstcRealSize`, then verify record-parcel unmarshalling returns `nullptr` for zero width and negative height.

```cpp
static void WriteAstcRecordParcelPrefix(Parcel &parcel, int32_t realWidth, int32_t realHeight)
{
    constexpr int32_t imageSize = 1;
    ASSERT_TRUE(parcel.WriteInt32(imageSize));
    ASSERT_TRUE(parcel.WriteInt32(imageSize));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(PixelFormat::ASTC_4x4)));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(ColorSpace::SRGB)));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(AlphaType::IMAGE_ALPHA_TYPE_OPAQUE)));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteString(""));
    ASSERT_TRUE(parcel.WriteBool(false));
    ASSERT_TRUE(parcel.WriteBool(false));
    ASSERT_TRUE(parcel.WriteInt32(static_cast<int32_t>(AllocatorType::HEAP_ALLOC)));
    ASSERT_TRUE(parcel.WriteInt32(ERR_MEDIA_INVALID_VALUE));
    const int32_t rowDataSize = ImageUtils::GetRowDataSizeByPixelFormat(imageSize, PixelFormat::ASTC_4x4);
    ASSERT_GT(rowDataSize, 0);
    ASSERT_TRUE(parcel.WriteInt32(rowDataSize));
    ASSERT_TRUE(parcel.WriteInt32(realWidth));
    ASSERT_TRUE(parcel.WriteInt32(realHeight));
    constexpr int32_t astcBufferSize = 16; // ASTC header size when either block count is zero
    ASSERT_TRUE(parcel.WriteInt32(astcBufferSize));
    std::vector<uint8_t> pixels(astcBufferSize, 0);
    ASSERT_TRUE(parcel.WriteUnpadBuffer(pixels.data(), pixels.size()));
    constexpr int32_t transformFloatCount = 9;
    for (int32_t i = 0; i < transformFloatCount; ++i) {
        ASSERT_TRUE(parcel.WriteFloat(0.0f));
    }
    ASSERT_TRUE(parcel.WriteBool(false));
    ASSERT_TRUE(parcel.WriteBool(false));
}

HWTEST_F(PixelMapParcelTest, RecordParcelRejectsNonPositiveAstcRealSize, TestSize.Level3)
{
    Parcel zeroWidthParcel;
    WriteAstcRecordParcelPrefix(zeroWidthParcel, 0, 1);
    EXPECT_EQ(PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(zeroWidthParcel), nullptr);

    Parcel zeroHeightParcel;
    WriteAstcRecordParcelPrefix(zeroHeightParcel, 1, 0);
    EXPECT_EQ(PixelMapRecordParcelTestHelper::UnmarshallingPixelMapForRecord(zeroHeightParcel), nullptr);
}
```

- [x] **Step 3: Verify the RED execution prerequisite and record the local gap**

This checkout is standalone and does not contain the OpenHarmony root build driver, product output, or a `pixelmaptest` binary. Confirm that limitation with the exact local path check:

```sh
test -x /Users/qihemu/Desktop/pushcode/prebuilts/build-tools/linux-x86/bin/ninja
```

Expected in this workspace: exit 1. Therefore the new tests cannot be executed in RED here; retain them for the configured OpenHarmony build/CI environment and explicitly report the missing prerequisite.

- [x] **Step 4: Implement the minimal reader validation**

In `PixelMap::ReadAstcInfo`, reject invalid dimensions before setting them or reading the HDR flag:

```cpp
if (realSize.width <= 0 || realSize.height <= 0) {
    IMAGE_LOGE("%{public}s invalid astc real size: width=%{public}d, height=%{public}d",
        __func__, realSize.width, realSize.height);
    return false;
}
```

- [x] **Step 5: Run the available local verification**

Run source-level checks in this standalone checkout:

```sh
git diff --check
rg -n "ReadAstcInfoRejectsNonPositiveSize|RecordParcelRejectsNonPositiveAstcRealSize|realSize\\.width <= 0|realSize\\.height <= 0" \
  frameworks/innerkitsimpl/common/src/pixel_map.cpp \
  frameworks/innerkitsimpl/common/src/pixel_map_parcel.cpp \
  frameworks/innerkitsimpl/test/unittest/pixel_map_test/pixel_map_parcel_test.cpp
```

Expected: `git diff --check` exits 0, both test names are present, and both parcel reader implementations contain non-positive dimension guards. The `pixelmaptest` build and filtered execution remain required in a configured OpenHarmony source root.

- [x] **Step 6: Review and commit the implementation**

Verify only the intended implementation, tests, and plan changed, then commit with project trailers:

```sh
git diff --check
git add frameworks/innerkitsimpl/common/src/pixel_map.cpp \
  frameworks/innerkitsimpl/test/unittest/pixel_map_test/pixel_map_parcel_test.cpp \
  docs/superpowers/plans/2026-07-21-astc-parcel-positive-size-validation.md
git commit -s -m "fix(pixelmap): reject invalid ASTC parcel dimensions" \
  -m "Validate ASTC real sizes before accepting parcel data and cover both parcel readers." \
  -m "Co-Authored-By: Agent"
```
