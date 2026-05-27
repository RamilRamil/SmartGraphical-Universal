# Implementation Plan: Bundle Subfolder Selection

**Spec**: [spec.md](./spec.md)

## Summary

Frontend-only: after folder staging, infer common path root, list immediate subfolder names, let user filter staged files before `uploadArtifactBundle`. Pure helpers in `bundleFolderFilter.ts`; UI in `UploadPage.tsx`.

## Touch points

- `frontend/src/lib/bundleFolderFilter.ts` (new)
- `frontend/src/lib/bundleFolderFilter.test.ts` (new)
- `frontend/src/pages/UploadPage.tsx`
- `frontend/src/styles.css` (optional subfolder panel)
- `docs/bundle_folder_upload_iterations.md` (iteration note)

## Out of scope

- Server-side `include_prefixes` form field
- Deep arbitrary path tree picker (v2)
