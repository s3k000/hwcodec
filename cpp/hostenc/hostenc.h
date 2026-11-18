/*
 * libhostenc - Client fuer hostencd: schickt NV12-Rohbilder per TCP an den Dienst und bekommt je Bild genau ein
 * H.265- oder H.264-Paket (Annex B) zurueck. Protokoll: ../PROTOCOL.md
 *
 * Portables C11, Winsock und POSIX, keine weiteren Abhaengigkeiten. Eine .c, eine .h.
 *
 * Zeitverhalten: Kein Aufruf blockiert laenger als seine Frist. Vorgaben: Verbindungsaufbau 300 ms, OPEN bis
 * OPEN_ACK 700 ms, ein Bild (Senden bis Paket vollstaendig da) 250 ms. Es gibt keine Namensaufloesung, die Adresse
 * muss eine IP-Adresse sein.
 *
 * Fehler: Jeder Fehler in hostenc_encode() trennt die Verbindung. Mit reconnect = 1 (Vorgabe) baut der naechste
 * Aufruf sie neu auf (wieder mit Frist) und macht mit einem Keyframe weiter; der Aufrufer sieht also einen Fehler
 * je Stoerung, nicht eine dauerhaft tote Sitzung.
 *
 * Threads: Ein Handle gehoert zu einem Thread zur Zeit. Verschiedene Handles sind unabhaengig.
 */
#ifndef HOSTENC_H
#define HOSTENC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HOSTENC_VERSION "0.1"
#define HOSTENC_DEFAULT_PORT 18265
#define HOSTENC_MAX_TOKEN 256

enum hostenc_codec { HOSTENC_CODEC_H264 = 1, HOSTENC_CODEC_HEVC = 2 };
enum hostenc_rc { HOSTENC_RC_DEFAULT = 0, HOSTENC_RC_CBR = 1, HOSTENC_RC_VBR = 2, HOSTENC_RC_CQP = 3 };
enum hostenc_backend { HOSTENC_BACKEND_VAAPI = 1, HOSTENC_BACKEND_SOFTWARE = 2 };

/* Rueckgabewerte. 0 = Erfolg, negativ = Fehler. */
enum hostenc_error {
    HOSTENC_OK = 0,
    HOSTENC_ERR_ARG = -1,      /* Argument ungueltig */
    HOSTENC_ERR_NOMEM = -2,    /* kein Speicher */
    HOSTENC_ERR_ADDRESS = -3,  /* Adresse ist keine IP-Adresse */
    HOSTENC_ERR_CONNECT = -4,  /* Verbindung abgelehnt oder Ziel nicht erreichbar */
    HOSTENC_ERR_TIMEOUT = -5,  /* Frist ueberschritten */
    HOSTENC_ERR_CLOSED = -6,   /* Verbindung von der Gegenseite getrennt bzw. nicht (mehr) verbunden */
    HOSTENC_ERR_IO = -7,       /* sonstiger Socketfehler */
    HOSTENC_ERR_PROTOCOL = -8, /* unerwartete oder ungueltige Antwort */
    HOSTENC_ERR_SERVER = -9,   /* Dienst hat ERROR gemeldet: Code in hostenc_server_error(), Text in hostenc_last_error() */
    HOSTENC_ERR_CONFIG = -10   /* Konfigurationsdatei fehlt oder ist unvollstaendig */
};

typedef struct hostenc hostenc_t;

typedef struct hostenc_options {
    const char *address; /* IPv4 oder IPv6 als Text, kein Name */
    uint16_t port;
    const char *token;
    int codec;            /* HOSTENC_CODEC_* */
    uint32_t width;       /* gerade, 16..8192 */
    uint32_t height;
    uint32_t fps_num;     /* Bildrate, die dem Dienst genannt wird; er misst die tatsaechliche selbst */
    uint32_t fps_den;
    uint32_t bitrate;     /* Bit/s */
    uint32_t max_bitrate; /* Bit/s, nur VBR; 0 = Dienst waehlt */
    uint32_t gop;         /* 0 = praktisch unendlich */
    int rc_mode;          /* HOSTENC_RC_* */
    uint32_t qp;          /* nur CQP; 0 = Vorgabe des Dienstes */
    int connect_timeout_ms;
    int open_timeout_ms;
    int frame_timeout_ms;
    int reconnect;        /* 1 = nach einem Fehler beim naechsten Bild neu verbinden */
    int sndbuf_bytes;     /* SO_SNDBUF; 0 = Vorgabe (Windows 8 MiB, sonst Sache des Betriebssystems) */
} hostenc_options;

/* Fuellt o mit den Vorgaben (Port, Fristen, 30/1 Bilder/s, reconnect = 1). Adresse, Token, Codec, Groesse und
 * Bitrate setzt der Aufrufer. */
void hostenc_options_init(hostenc_options *o);

typedef struct hostenc_packet {
    const uint8_t *data; /* Annex B; gueltig bis zum naechsten Aufruf mit demselben Handle */
    size_t size;
    int keyframe;        /* 1 = Keyframe, beginnt mit den Parametersaetzen */
    int reopened;        /* 1 = der Dienst hat den Encoder vor diesem Bild neu geoeffnet */
    int64_t pts;         /* wie uebergeben */
    uint32_t server_us;  /* Zeit im Dienst fuer dieses Bild in Mikrosekunden */
} hostenc_packet;

/* Was der Dienst im OPEN_ACK gemeldet hat. */
typedef struct hostenc_info {
    int codec;
    uint32_t width, height;
    uint32_t fps_num, fps_den; /* womit die Ratensteuerung rechnet */
    uint32_t bitrate, max_bitrate;
    uint32_t gop;
    int rc_mode;
    uint32_t qp;
    int backend;         /* HOSTENC_BACKEND_* */
    uint32_t max_packet;
    uint32_t open_us;    /* Dauer des Encoder-Oeffnens im Dienst */
} hostenc_info;

/* Verbindet, meldet an, oeffnet den Encoder. Hoechstens connect_timeout_ms + open_timeout_ms.
 * errbuf (optional): Klartext zum Fehler, z. B. die Meldung des Dienstes. */
int hostenc_open(const hostenc_options *o, hostenc_t **out, char *errbuf, size_t errbuf_size);

/* Encodiert ein Bild. y/uv zeigen auf die erste Zeile der Ebenen, *_stride ist der Zeilenabstand in Byte (darf
 * groesser als die Breite und auch negativ sein). uv ist die verschraenkte UV-Ebene (NV12) mit halber Hoehe.
 * keyframe != 0 erzwingt einen Keyframe. Hoechstens frame_timeout_ms, nach einer Stoerung zusaetzlich einmal
 * connect_timeout_ms + open_timeout_ms fuer den Neuaufbau. */
int hostenc_encode(hostenc_t *h, const uint8_t *y, int y_stride, const uint8_t *uv, int uv_stride, int64_t pts,
                   int keyframe, hostenc_packet *pkt);

/* Neue Bitrate in Bit/s (max_bitrate nur fuer VBR, 0 = Dienst waehlt). Kehrt sofort zurueck, wartet auf keine
 * Antwort. Der Dienst oeffnet den Encoder dafuer neu, das naechste Paket ist ein Keyframe. */
int hostenc_set_bitrate(hostenc_t *h, uint32_t bitrate, uint32_t max_bitrate);

/* Schliesst die Sitzung und gibt alles frei. h darf NULL sein. */
void hostenc_close(hostenc_t *h);

int hostenc_get_info(const hostenc_t *h, hostenc_info *info);
/* Klartext zum letzten Fehler dieses Handles (nie NULL). */
const char *hostenc_last_error(const hostenc_t *h);
/* Fehlercode des Dienstes nach HOSTENC_ERR_SERVER (PROTOCOL.md, Abschnitt ERROR), sonst 0. */
uint32_t hostenc_server_error(const hostenc_t *h);
/* Kurzer Name zu einem Rueckgabewert. */
const char *hostenc_strerror(int err);

/*
 * Maschinenweite Konfiguration. Format: eine Angabe je Zeile, schluessel = "wert" (Anfuehrungszeichen wahlweise),
 * # leitet Kommentare ein, Zeilen in eckigen Klammern werden uebergangen. Kein vollstaendiges TOML.
 *
 *   adresse = "10.10.10.42"
 *   port = 18265
 *   token = "..."
 *   aktiv = true                  # wahlweise; false schaltet den Encoder fuer Aufrufer ab
 *   verbindung_timeout_ms = 300   # wahlweise
 *   oeffnen_timeout_ms = 700      # wahlweise
 *   bild_timeout_ms = 250         # wahlweise
 *
 * Ort: Windows %ProgramData%\hostenc\config.toml, sonst /etc/hostenc/client.toml; die Umgebungsvariable
 * HOSTENC_CONFIG nennt einen anderen Pfad.
 */
typedef struct hostenc_config {
    char address[64];
    uint16_t port;
    char token[HOSTENC_MAX_TOKEN + 1];
    int enabled;
    int connect_timeout_ms; /* 0 = nicht gesetzt */
    int open_timeout_ms;
    int frame_timeout_ms;
} hostenc_config;

/* Schreibt den Vorgabepfad nach buf. Rueckgabe HOSTENC_OK oder HOSTENC_ERR_ARG (Puffer zu klein). */
int hostenc_config_default_path(char *buf, size_t size);
/* Liest die Datei. path NULL = Vorgabepfad. Fehlen Adresse oder Token: HOSTENC_ERR_CONFIG. */
int hostenc_config_load(const char *path, hostenc_config *cfg, char *errbuf, size_t errbuf_size);
/* Uebertraegt Adresse, Port, Token und gesetzte Fristen nach o. cfg muss bis nach hostenc_open() bestehen. */
void hostenc_options_from_config(hostenc_options *o, const hostenc_config *cfg);

#ifdef __cplusplus
}
#endif

#endif /* HOSTENC_H */
