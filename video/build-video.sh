#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE_DIR="$PROJECT_DIR/video/source"
OUTPUT="$PROJECT_DIR/video/Agent-Trust-Border-Stage1.mp4"
CAPTIONS="$PROJECT_DIR/video/captions.srt"
FFMPEG_BIN=${FFMPEG_BIN:-ffmpeg}

for slide in 1 2 3 4 5; do
    test -f "$SOURCE_DIR/slide-$slide.png"
done

"$FFMPEG_BIN" -y -hide_banner -loglevel error \
    -threads 1 -filter_threads 1 -filter_complex_threads 1 \
    -loop 1 -framerate 30 -t 6  -i "$SOURCE_DIR/slide-1.png" \
    -loop 1 -framerate 30 -t 12 -i "$SOURCE_DIR/slide-2.png" \
    -loop 1 -framerate 30 -t 12 -i "$SOURCE_DIR/slide-4.png" \
    -loop 1 -framerate 30 -t 20 -i "$SOURCE_DIR/slide-3.png" \
    -loop 1 -framerate 30 -t 14 -i "$SOURCE_DIR/slide-5.png" \
    -loop 1 -framerate 30 -t 10 -i "$SOURCE_DIR/slide-1.png" \
    -i "$CAPTIONS" \
    -filter_complex "\
[0:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:white,setsar=1,setpts=PTS-STARTPTS[v0];\
[1:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:white,setsar=1,setpts=PTS-STARTPTS[v1];\
[2:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:white,setsar=1,setpts=PTS-STARTPTS[v2];\
[3:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:white,setsar=1,setpts=PTS-STARTPTS[v3];\
[4:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:white,setsar=1,setpts=PTS-STARTPTS[v4];\
[5:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:white,setsar=1,setpts=PTS-STARTPTS[v5];\
[v0][v1][v2][v3][v4][v5]concat=n=6:v=1:a=0,fps=30,format=yuv420p,fade=t=in:st=0:d=0.4,fade=t=out:st=73.6:d=0.4[outv]" \
    -map "[outv]" -map 6:s:0 \
    -c:v libx264 -preset veryfast -crf 21 -profile:v high -level:v 4.1 \
    -pix_fmt yuv420p -r 30 -c:s mov_text \
    -metadata:s:s:0 language=eng -disposition:s:0 default \
    -movflags +faststart -shortest "$OUTPUT"

echo "Built $OUTPUT"
