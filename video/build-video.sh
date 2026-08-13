#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CAPTURE_DIR="$PROJECT_DIR/video/capture-v2"
SHOTS="$CAPTURE_DIR/screenshots"
WALKTHROUGH="$CAPTURE_DIR/viewer-walkthrough.webm"
AUDIO="$PROJECT_DIR/video/narration-v2-master.m4a"
CAPTIONS="$PROJECT_DIR/video/captions.srt"
OUTPUT="$PROJECT_DIR/video/Agent-Trust-Border-Stage1.mp4"
FFMPEG_BIN=${FFMPEG_BIN:-ffmpeg}

for source in \
    "$SHOTS/01-hero.png" \
    "$SHOTS/02-metrics.png" \
    "$SHOTS/04-admit.png" \
    "$SHOTS/05-deny.png" \
    "$SHOTS/06-replay.png" \
    "$SHOTS/07-architecture.png" \
    "$SHOTS/08-boundary.png" \
    "$WALKTHROUGH" \
    "$AUDIO" \
    "$CAPTIONS"
do
    test -f "$source"
done

"$FFMPEG_BIN" -y -hide_banner -loglevel error \
    -threads 1 -filter_threads 1 -filter_complex_threads 1 \
    -loop 1 -framerate 30 -t 15 -i "$SHOTS/01-hero.png" \
    -loop 1 -framerate 30 -t 15 -i "$SHOTS/07-architecture.png" \
    -i "$WALKTHROUGH" \
    -loop 1 -framerate 30 -t 8  -i "$SHOTS/05-deny.png" \
    -loop 1 -framerate 30 -t 8  -i "$SHOTS/06-replay.png" \
    -loop 1 -framerate 30 -t 12 -i "$SHOTS/04-admit.png" \
    -loop 1 -framerate 30 -t 17 -i "$SHOTS/02-metrics.png" \
    -loop 1 -framerate 30 -t 16 -i "$SHOTS/08-boundary.png" \
    -loop 1 -framerate 30 -t 14 -i "$SHOTS/01-hero.png" \
    -i "$AUDIO" \
    -i "$CAPTIONS" \
    -filter_complex "\
[0:v]scale=1920:1080,zoompan=z='min(zoom+0.00008,1.04)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=1:s=1920x1080:fps=30,format=yuv420p,setpts=PTS-STARTPTS[v0];\
[1:v]scale=1920:1080,zoompan=z='min(zoom+0.00008,1.04)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=1:s=1920x1080:fps=30,format=yuv420p,setpts=PTS-STARTPTS[v1];\
[2:v]scale=1920:1080,fps=30,format=yuv420p,setpts=PTS-STARTPTS[v2];\
[3:v]scale=1920:1080,zoompan=z='min(zoom+0.00010,1.04)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=1:s=1920x1080:fps=30,format=yuv420p,setpts=PTS-STARTPTS[v3];\
[4:v]scale=1920:1080,zoompan=z='min(zoom+0.00010,1.04)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=1:s=1920x1080:fps=30,format=yuv420p,setpts=PTS-STARTPTS[v4];\
[5:v]scale=1920:1080,zoompan=z='min(zoom+0.00008,1.04)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=1:s=1920x1080:fps=30,format=yuv420p,setpts=PTS-STARTPTS[v5];\
[6:v]scale=1920:1080,zoompan=z='min(zoom+0.00007,1.04)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=1:s=1920x1080:fps=30,format=yuv420p,setpts=PTS-STARTPTS[v6];\
[7:v]scale=1920:1080,zoompan=z='min(zoom+0.00007,1.04)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=1:s=1920x1080:fps=30,format=yuv420p,setpts=PTS-STARTPTS[v7];\
[8:v]scale=1920:1080,zoompan=z='min(zoom+0.00008,1.04)':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':d=1:s=1920x1080:fps=30,format=yuv420p,setpts=PTS-STARTPTS[v8];\
[v0][v1][v2][v3][v4][v5][v6][v7][v8]concat=n=9:v=1:a=0,fade=t=in:st=0:d=0.5,fade=t=out:st=122.7:d=0.5[outv]" \
    -map "[outv]" -map 9:a:0 -map 10:s:0 \
    -c:v libx264 -preset veryfast -crf 20 -profile:v high -level:v 4.1 \
    -pix_fmt yuv420p -r 30 -c:a copy -c:s mov_text \
    -metadata:s:a:0 language=eng \
    -metadata:s:s:0 language=eng -disposition:s:0 default \
    -movflags +faststart -shortest "$OUTPUT"

echo "Built $OUTPUT"
