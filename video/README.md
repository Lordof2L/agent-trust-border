# Stage-1 demo video

`Agent-Trust-Border-Stage1.mp4` is a 74-second caption-first proof walkthrough.
It contains no narration, music, stock footage, analytics, or third-party media.
Every visual comes from the original competition deck in `source/`.

The English subtitle track is embedded in the MP4 and preserved separately as
`captions.srt`. Rebuild with:

```bash
./video/build-video.sh
```

The build is deliberately single-threaded. It requires FFmpeg with H.264 and
`mov_text` support. The video repeats the repository truth boundary: synthetic
offline fixtures, no action execution, no live conformance or world-truth claim.
