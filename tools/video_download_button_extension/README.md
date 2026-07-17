# Tiny Video Download Button

Chrome/Edge extension that adds a small visible `DL` button on normal HTML5 videos with direct file URLs.

It does not extract YouTube streams, bypass DRM, or rip segmented streaming manifests.

## Load It

1. Open `chrome://extensions`.
2. Turn on Developer mode.
3. Click Load unpacked.
4. Pick this folder:

```text
/Users/alexkkork/Documents/Codex/2026-07-05/build-a-perfect-luau-runtime-with/tools/video_download_button_extension
```

## Behavior

- Direct `.mp4`, `.webm`, etc. videos: button downloads the source URL.
- Blob/stream videos: button explains direct download is unavailable.
- YouTube: button stays tiny/visible but points you to official download/Studio options.
