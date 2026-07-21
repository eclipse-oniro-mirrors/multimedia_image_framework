# PixelMap Row-Stride Validation Design

## Goal

Reject malformed linear PixelMaps whose row stride makes the last accessible row exceed the actual backing allocation, including DMA PixelMaps received over IPC.

## Scope

- Apply the new row-stride layout validation to linear, non-YUV PixelMaps.
- YUV formats do not participate and continue using the existing plane-aware `CheckYuvPixelMapBufferSize()` validation.
- ASTC continues using its existing block-compressed byte-count validation; the linear row-stride formula does not describe ASTC storage.
- Do not change the Parcel wire format or public API signatures.

## Design

Add one reusable free validation function in `pixel_map_utils.h`. It reads PixelMap state through public getters and obtains the actual allocation size through `GetAllocationByteCount()`, so DMA uses `SurfaceBuffer::GetSize()` while other allocators use `pixelsSize_`.

For a linear image, require a positive stride no smaller than `rowDataSize_`, then calculate the minimum accessible allocation as:

```text
(height - 1) * rowStride + rowDataSize
```

All arithmetic uses `uint64_t` and subtraction-based comparisons to avoid overflow. The IPC unmarshalling completion paths call the helper after `SetPixelsAddr()` has installed the DMA context and refreshed `rowStride_` from the received `SurfaceBuffer`.

`CheckValidParam(x, y)` additionally reuses the full linear-layout validator. This is defense in depth for invalid states created outside IPC, including unrestricted `SetRowStride()` calls.

## Error Handling

Malformed IPC input is rejected by returning `nullptr` from unmarshalling after releasing the attached PixelMap memory through normal destruction. The existing PixelMap creation error family is retained. Invalid direct pixel access returns `nullptr`/`false` through the existing callers.

## Tests

- Reject width 3, height 100, row data size 12, row stride 64, allocation size 1200.
- Accept the exact minimum allocation size 6348 and reject 6347.
- Preserve valid DMA padding behavior by checking the SurfaceBuffer allocation size rather than logical `pixelsSize_`.
- Confirm YUV bypasses the new linear-layout check.
- Confirm invalid local `SetRowStride()` values cannot produce an out-of-bounds pixel pointer.
