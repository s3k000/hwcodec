#include "hostenc_ram.h"

#include <chrono>
#include <limits.h>
#include <memory>
#include <string.h>

#include "common.h"

#define LOG_MODULE "HOSTENC"
#include "log.h"

// Timing
// ------
// The video thread of the caller must not stall, so every call is bounded:
//
//   Session::open()    connect timeout + open timeout of the configuration
//                      (defaults 300 ms + 700 ms); encoder creation only.
//   Session::encode()  frame timeout of the configuration (default 250 ms).
//
// libhostenc is used with reconnect = 0. With reconnect = 1 the call after a
// failure could take connect + open + frame timeout (1250 ms by default).
// Reconnecting is done here instead, with a small fixed budget:
//
//   - A failed call closes the session and returns an error.
//   - The next encode() tries once to open a new session with the connect and
//     open timeouts capped to REOPEN_CONNECT_MS / REOPEN_OPEN_MS.
//   - If that took less than REOPEN_SPARE_MS the frame is encoded in the same
//     call, otherwise the call returns an error and the following call
//     encodes. Either way the first packet of the new session is a key frame.
//
// So with the default frame timeout no encode() call exceeds about
// max(250, 100 + 150, 50 + 250) = 300 ms, a single disturbance costs one or
// two frames, and a service that stays away produces an error per call
// until the caller gives up (RustDesk: three in a row).
static const int REOPEN_CONNECT_MS = 100;
static const int REOPEN_OPEN_MS = 150;
static const int REOPEN_SPARE_MS = 50;

namespace {

int to_ret(int hostenc_err) { return hostenc_ram::ERR_BASE + hostenc_err; }

uint32_t to_bps(int kbs) {
  if (kbs <= 0)
    return 0;
  return (uint32_t)(kbs > 4000000 ? 4000000 : kbs) * 1000u;
}

// The compiler must not drop this as a dead store.
void wipe(void *p, size_t n) {
  volatile unsigned char *v = (volatile unsigned char *)p;
  while (n--)
    *v++ = 0;
}

std::string describe(const hostenc_options &o) {
  return std::string(o.codec == HOSTENC_CODEC_H264 ? "h264 " : "hevc ") +
         std::to_string(o.width) + "x" + std::to_string(o.height) + ", " +
         std::to_string(o.bitrate / 1000) + " kbit/s, service " + o.address +
         " port " + std::to_string(o.port);
}

} // namespace

namespace hostenc_ram {

bool is_hostenc_name(const std::string &name) {
  return name == "h264_hostenc" || name == "hevc_hostenc";
}

Session::Session() : h_(NULL) {
  memset(&cfg_, 0, sizeof(cfg_));
  memset(&opt_, 0, sizeof(opt_));
}

Session::~Session() {
  drop();
  wipe(&cfg_, sizeof(cfg_));
}

void Session::drop() {
  if (h_) {
    hostenc_close(h_);
    h_ = NULL;
  }
}

Session *Session::open(const std::string &name, int width, int height, int fps,
                       int gop, int rc, int kbs, int q) {
  char err[256] = {0};
  std::unique_ptr<Session> s(new Session());
  s->name_ = name;

  int ret = hostenc_config_load(NULL, &s->cfg_, err, sizeof(err));
  if (ret != HOSTENC_OK || !s->cfg_.enabled) {
    LOG_ERROR(name + ": no usable client configuration" +
              (err[0] ? std::string(": ") + err : std::string()));
    return NULL;
  }

  hostenc_options &o = s->opt_;
  hostenc_options_init(&o);
  hostenc_options_from_config(&o, &s->cfg_);
  o.reconnect = 0; // see "Timing" above
  o.codec = name.find("h264") != std::string::npos ? HOSTENC_CODEC_H264
                                                   : HOSTENC_CODEC_HEVC;
  o.width = width > 0 ? (uint32_t)width : 0;
  o.height = height > 0 ? (uint32_t)height : 0;
  o.fps_num = fps > 0 ? (uint32_t)fps : 30;
  o.fps_den = 1;
  o.bitrate = to_bps(kbs);
  o.max_bitrate = 0;
  // Same rule as util_encode::set_av_codec_ctx(): everything else means
  // "no periodic key frames", which is 0 in the hostenc protocol.
  o.gop = (gop > 0 && gop < INT16_MAX) ? (uint32_t)gop : 0;
  switch (rc) {
  case RC_CBR:
    o.rc_mode = HOSTENC_RC_CBR;
    break;
  case RC_VBR:
    o.rc_mode = HOSTENC_RC_VBR;
    break;
  case RC_CQ:
    o.rc_mode = HOSTENC_RC_CQP;
    o.qp = (q >= 1 && q <= 51) ? (uint32_t)q : 0;
    break;
  default:
    o.rc_mode = HOSTENC_RC_DEFAULT;
    break;
  }

  ret = hostenc_open(&o, &s->h_, err, sizeof(err));
  if (ret != HOSTENC_OK) {
    LOG_ERROR(name + ": open failed (" + hostenc_strerror(ret) + "), " +
              describe(o) + (err[0] ? std::string(": ") + err : std::string()));
    return NULL;
  }

  hostenc_info info;
  if (hostenc_get_info(s->h_, &info) == HOSTENC_OK) {
    LOG_INFO(name + ": " + describe(o) + ", backend " +
             (info.backend == HOSTENC_BACKEND_VAAPI ? "vaapi" : "software") +
             ", rate control at " + std::to_string(info.fps_num) + "/" +
             std::to_string(info.fps_den) + " fps, opened in " +
             std::to_string(info.open_us / 1000) + " ms");
  }
  return s.release();
}

int Session::reopen() {
  char err[256] = {0};
  hostenc_options o = opt_;
  if (o.connect_timeout_ms <= 0 || o.connect_timeout_ms > REOPEN_CONNECT_MS)
    o.connect_timeout_ms = REOPEN_CONNECT_MS;
  if (o.open_timeout_ms <= 0 || o.open_timeout_ms > REOPEN_OPEN_MS)
    o.open_timeout_ms = REOPEN_OPEN_MS;
  int ret = hostenc_open(&o, &h_, err, sizeof(err));
  if (ret != HOSTENC_OK) {
    h_ = NULL;
    LOG_ERROR(name_ + ": reopen failed (" + hostenc_strerror(ret) + ")" +
              (err[0] ? std::string(": ") + err : std::string()));
  }
  return ret;
}

int Session::encode(const uint8_t *y, int y_stride, const uint8_t *uv,
                    int uv_stride, int64_t pts, const uint8_t **data, int *size,
                    int *key) {
  if (!h_) {
    auto start = std::chrono::steady_clock::now();
    int ret = reopen();
    if (ret != HOSTENC_OK)
      return to_ret(ret);
    int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - start)
                     .count();
    if (ms > REOPEN_SPARE_MS) {
      LOG_WARN(name_ + ": session reopened in " + std::to_string(ms) +
               " ms, this frame is skipped");
      return to_ret(HOSTENC_ERR_TIMEOUT);
    }
    LOG_INFO(name_ + ": session reopened in " + std::to_string(ms) + " ms");
  }

  hostenc_packet pkt;
  int ret = hostenc_encode(h_, y, y_stride, uv, uv_stride, pts, 0, &pkt);
  if (ret != HOSTENC_OK) {
    LOG_ERROR(name_ + ": encode failed (" + hostenc_strerror(ret) +
              "): " + hostenc_last_error(h_));
    drop();
    return to_ret(ret);
  }
  if (pkt.size == 0 || pkt.size > (size_t)INT_MAX) {
    LOG_ERROR(name_ + ": packet size out of range");
    drop();
    return to_ret(HOSTENC_ERR_PROTOCOL);
  }
  *data = pkt.data;
  *size = (int)pkt.size;
  *key = pkt.keyframe ? 1 : 0;
  return 0;
}

int Session::set_bitrate(int kbs) {
  if (kbs <= 0)
    return 0; // same as util_encode::change_bit_rate()
  uint32_t bitrate = to_bps(kbs);
  opt_.bitrate = bitrate; // also used when the session is reopened
  if (!h_)
    return 0;
  int ret = hostenc_set_bitrate(h_, bitrate, 0);
  if (ret != HOSTENC_OK) {
    LOG_ERROR(name_ + ": set_bitrate failed (" + hostenc_strerror(ret) +
              "): " + hostenc_last_error(h_));
    drop();
    return to_ret(ret);
  }
  return 0;
}

} // namespace hostenc_ram

extern "C" int hostenc_ram_available(void) {
  try {
    hostenc_config cfg;
    char err[256] = {0};
    int ret = hostenc_config_load(NULL, &cfg, err, sizeof(err));
    bool ok = ret == HOSTENC_OK && cfg.enabled;
    wipe(&cfg, sizeof(cfg));
    if (!ok) {
      LOG_DEBUG(std::string("hostenc not offered: ") +
                (ret == HOSTENC_OK ? "switched off in the configuration" : err));
    }
    return ok ? 1 : 0;
  } catch (...) {
  }
  return 0;
}
