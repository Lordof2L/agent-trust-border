# Stage-1 demo video

`Agent-Trust-Border-Stage1.mp4` is a 2-minute narrated proof walkthrough.
It contains [ElevenLabs](https://elevenlabs.io/) Eric narration and no music, stock footage, analytics,
or third-party visual media. The narration was generated on a Free account
after the owner explicitly accepted the commercial-use licence risk recorded in
`RIGHTS-LEDGER.md`.
Every visual is a first-party capture of the committed evidence viewer.

The English subtitle track is embedded in the MP4 and preserved separately as
`captions.srt`. To refresh viewer captures, run `capture-viewer-v2.py`. Rebuild
the final video with:

```bash
./video/build-video.sh
```

The build is deliberately single-threaded. It requires FFmpeg with H.264 and
`mov_text` support plus the committed `capture-v2/` assets and
`narration-v2-master.m4a`. The video repeats the repository truth boundary:
synthetic offline fixtures, no action execution, no live conformance or
world-truth claim.
