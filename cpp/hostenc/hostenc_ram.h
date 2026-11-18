#ifndef HOSTENC_RAM_H
#define HOSTENC_RAM_H

// Glue between the RAM encoder interface (ffmpeg_ram_encode.cpp) and
// libhostenc (hostenc.h / hostenc.c in this directory).
//
// The encoder names "h264_hostenc" and "hevc_hostenc" do not exist in
// libavcodec. They send NV12 frames to a hostencd service over TCP and get
// exactly one H.264/H.265 Annex B packet back per frame. See README.md here.

#include <stdint.h>
#include <string>

#include "hostenc.h"

namespace hostenc_ram {

// Return values of Session::encode() / Session::set_bitrate() are
// ERR_BASE + <libhostenc error>, e.g. -1005 for HOSTENC_ERR_TIMEOUT (-5), so
// they cannot be mistaken for AVERROR codes in the logs.
const int ERR_BASE = -1000;

// True for "h264_hostenc" and "hevc_hostenc".
bool is_hostenc_name(const std::string &name);

class Session {
public:
  // Reads the machine-wide client configuration and opens a session.
  // Returns NULL after logging the reason. Bounded by the connect and open
  // timeouts of the configuration (defaults 300 ms + 700 ms).
  static Session *open(const std::string &name, int width, int height, int fps,
                       int gop, int rc, int kbs, int q);
  ~Session();

  // One NV12 frame in, exactly one packet out. *data stays valid until the
  // next call. Returns 0 or a negative value (see ERR_BASE). Never waits
  // longer than the frame timeout (default 250 ms); see hostenc_ram.cpp for
  // the behaviour after a failure.
  int encode(const uint8_t *y, int y_stride, const uint8_t *uv, int uv_stride,
             int64_t pts, const uint8_t **data, int *size, int *key);

  // Does not wait for an answer. The service reopens its encoder, so the
  // next packet is a key frame.
  int set_bitrate(int kbs);

private:
  Session();
  Session(const Session &);
  Session &operator=(const Session &);
  void drop();
  int reopen();

  hostenc_t *h_;
  hostenc_config cfg_;  // owns address and token, opt_ points into it
  hostenc_options opt_; // as used for the first open
  std::string name_;
};

} // namespace hostenc_ram

extern "C" {
// 1 if the client configuration file exists, is readable, names address and
// token and is not switched off ("aktiv = false"); 0 otherwise. Does not
// contact the service.
int hostenc_ram_available(void);
}

#endif // HOSTENC_RAM_H
