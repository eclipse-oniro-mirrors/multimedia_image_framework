# ASTC Parcel Positive-Size Validation Design

## Goal

Reject ASTC real sizes whose width or height is not greater than zero when reading PixelMap parcel data.

## Scope

- Add the missing positive-size check to `PixelMap::ReadAstcInfo` in `frameworks/innerkitsimpl/common/src/pixel_map.cpp`.
- Keep the equivalent check in `ReadAstcRealSize` in `frameworks/innerkitsimpl/common/src/pixel_map_parcel.cpp` and add regression coverage for that path.
- Return `false` before calling `SetAstcRealSize` when either dimension is zero or negative.
- Preserve the existing parcel field order, error propagation, public API, and error-code mapping.

## Alternatives Considered

1. Validate only at the two parcel readers. This is the selected approach because both functions consume untrusted serialized dimensions and can reject invalid input without changing other callers.
2. Validate in `PixelMap::SetAstcRealSize`. This would affect trusted in-process callers and change a wider behavior surface than requested.
3. Validate both parcel writers and readers. Reader-side validation is required for untrusted parcels; writer-side rejection would additionally change existing marshalling behavior and is outside this fix.

## Error Handling

For ASTC PixelMaps, a non-positive real width or height causes the reader to log the invalid dimensions and return `false`. The enclosing unmarshalling path then follows its existing failure and cleanup behavior. Non-ASTC parcel handling is unchanged.

## Testing

- Add a focused unit test proving `PixelMap::ReadAstcInfo` rejects zero and negative ASTC real dimensions.
- Add or extend a record-parcel test proving `PixelMapRecordParcel` unmarshalling rejects the same malformed dimensions.
- Preserve a positive-dimension case to show valid ASTC parcel data remains accepted.
- Run the nearest `pixelmaptest` target when the configured OpenHarmony build environment is available; otherwise record the environment gap and perform available source-level checks.

## Non-Goals

- No Parcel field-format or compatibility change.
- No change to ASTC encoding, decoding, block-footprint validation, allocator behavior, public APIs, or language bindings.
- No new maximum-dimension policy beyond the existing `pixel_map_parcel.cpp` check.
