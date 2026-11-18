# hostenc: RAM encoders backed by an encoding service

`h264_hostenc` and `hevc_hostenc` are RAM encoders that do not encode in this
process. Each NV12 frame is sent over TCP to a `hostencd` service, which
answers with exactly one H.264/H.265 packet (Annex B, no B-frames, parameter
sets in front of every key frame). The use case is a virtual machine without
a hardware encoder next to a host or container that has one.

They sit behind the normal RAM encoder interface (`ffmpeg_ram_new_encoder`,
`ffmpeg_ram_encode`, `ffmpeg_ram_set_bitrate`, `ffmpeg_ram_free_encoder`), so
`hwcodec::ffmpeg_ram::encode::Encoder` and its users need no changes. libavcodec
is not involved; no FFmpeg patch or rebuild is required.

## Files

| File | Content |
| --- | --- |
| `hostenc.h`, `hostenc.c` | libhostenc 0.1, the client library (C11, Winsock and POSIX, no dependencies). Unmodified copies from the hostenc project, which also contains the service `hostencd` and the protocol description `PROTOCOL.md`. Comments and messages are in German. Do not edit here; replace both files together when the protocol changes. |
| `hostenc_ram.h`, `hostenc_ram.cpp` | Glue used by `cpp/ffmpeg_ram/ffmpeg_ram_encode.cpp`: option mapping, timing rules, error codes. |

## When the encoders are offered

`Encoder::available_encoders()` adds the two candidates on Windows and Linux
if the machine-wide client configuration can be loaded:

- Windows: `%ProgramData%\hostenc\config.toml`
- Linux: `/etc/hostenc/client.toml`
- the environment variable `HOSTENC_CONFIG` names another path

```
adresse = "10.10.10.42"   # IP address of the service, no host name
port = 18265
token = "..."
# aktiv = false           # keeps the file but switches the encoders off
# bild_timeout_ms = 250   # frame timeout, see below
```

The file must be readable by the process that runs the check (for an
installed RustDesk on Windows that is the service, i.e. SYSTEM). The GPU
vendor detection is not consulted. The candidates are placed after the real
GPU encoders (QSV, NVENC, AMF, VAAPI): per format only the first candidate
that passes the test frame is kept. Like every candidate they must return one
key frame for a black 1280x720 frame within one second, which needs a running
service.

## Behaviour

- Input is NV12 only, with the line sizes and plane offset reported by
  `ffmpeg_ram_get_linesize_offset_length()`.
- One callback per frame, `pts` as passed in, key flag 0 or 1.
- `fps`, `gop`, rate control and bit rate are passed to the service. The
  service runs its rate control with its own frame rate setting.
- `ffmpeg_ram_set_bitrate()` sends the new bit rate without waiting. The
  service reopens its encoder, so every change costs a key frame.
- Errors are returned as `-1000 + <libhostenc error>` (for example `-1005`
  timeout, `-1006` connection closed, `-1004` connect failed) and logged with
  the text from libhostenc.
- No call blocks longer than its timeout: creating the encoder at most the
  connect plus open timeout (300 ms + 700 ms by default), encoding a frame at
  most the frame timeout (250 ms by default). After a failed frame the next
  call makes one short attempt to open a new session (at most 100 ms + 150 ms)
  and continues with a key frame; see the comment at the top of
  `hostenc_ram.cpp`.
- There is no encryption. The token travels in clear text; service and client
  belong on an internal network.
