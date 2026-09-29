// Native cloud SSH: make `ssh tfa-cloud` reach this user's cloud sandbox.
//
// Protocol (backend ↔ bridge, over the pinned Noise channel):
//   → identity.data.cloudSsh = true                   (capable bridges only)
//   ← {"type":"cloud_ssh_offer"}                       (on auth + every 5 min)
//   → {"type":"cloud_ssh_key","publicKey":"ssh-ed25519 AAAA…"}
//   ← {"type":"cloud_ssh_config","host":"…","port":N,"user":"workspace",
//      "hostKey":"ssh-ed25519 AAAA…","cloudDeviceId":"<uuid>"}
//   → {"type":"cloud_ssh_ready","cloudDeviceId":"<uuid>","ready":true|false}
//
// Everything touching disk or spawning ssh runs in an off-loop job worker
// (jobs.h). Files we own, all inside <pw_dir>/.ssh:
//   tfa_cloud, tfa_cloud.pub   dedicated ed25519 identity (created once, never overwritten)
//   tfa_cloud_config           managed `Host tfa-cloud` block
//   tfa_cloud_known_hosts      pin: `tfa-cloud-<uuid> ssh-ed25519 …`
//   .tfa_cloud.lock            serialises concurrent bridges / profiles
// ~/.ssh/config only ever gains one `Include` line at the top.
// POSIX only: on Windows the bridge never advertises the capability and
// every entry point fails closed.
#ifndef BRIDGE_CLOUD_SSH_H
#define BRIDGE_CLOUD_SSH_H

#include <stddef.h>

#include "jobs.h"

#define CLOUD_SSH_ALIAS "tfa-cloud"

typedef struct {
    char host[254];
    long port;
    char host_key[96];     // "ssh-ed25519 " + 68 base64 chars
    char device_id[37];    // cloudDeviceId (uuid)
    char profile[128];     // credential profile that owns the managed block
} cloud_ssh_cfg_t;

typedef struct {
    char dir[700];         // the .ssh directory
    int  use_F;            // tests: run ssh with -F <dir>/config
    int  skip_connect;     // tests: stop after the `ssh -G` check
} cloud_ssh_env_t;

// Validators (exposed for tests). Return 1 if valid.
int cloud_ssh_valid_host(const char *s, size_t n);
int cloud_ssh_valid_ed25519(const char *s, size_t n);   // "ssh-ed25519 <68 b64>", canonical
int cloud_ssh_valid_uuid(const char *s, size_t n);

// Parse + strictly validate a cloud_ssh_config message (or a job payload of
// the same shape plus "profile"). 0 on success, else -1 with *err set.
int cloud_ssh_parse_config(const char *msg, size_t len, cloud_ssh_cfg_t *c, const char **err);
// Re-emit a validated config (plus profile) as a job payload.
int cloud_ssh_build_payload(const cloud_ssh_cfg_t *c, char *out, size_t cap);
int cloud_ssh_ready_json(const char *device_id, int ready, char *out, size_t cap);

// 1 if user-written ssh_config text already defines the alias (Host/Match).
int cloud_ssh_user_defines_alias(const char *text, size_t n);
// Render the managed Host block. Returns length, or -1 on overflow.
int cloud_ssh_render_config(const char *dir, const cloud_ssh_cfg_t *c, char *out, size_t cap);

// 1 on POSIX with ssh + ssh-keygen on PATH.
int cloud_ssh_supported(void);
// Default env: <pw_dir>/.ssh. -1 if unusable.
int cloud_ssh_default_env(cloud_ssh_env_t *env);
// Ensure the dedicated identity exists; copy "ssh-ed25519 BASE64" into pub.
int cloud_ssh_ensure_key(const cloud_ssh_env_t *env, char *pub, size_t cap, char *err, size_t errcap);
// Write key/config/known_hosts/Include, verify with `ssh -G`, then probe
// `ssh -o BatchMode=yes -o ConnectTimeout=5 tfa-cloud true`. 0 = ready.
int cloud_ssh_apply(const cloud_ssh_env_t *env, const cloud_ssh_cfg_t *c, char *err, size_t errcap);

// Job bodies (run in the `__job` worker).
int cloud_ssh_key_job(const char *payload, size_t len, bridge_job_emit_fn emit, void *ctx);
int cloud_ssh_config_job(const char *payload, size_t len, bridge_job_emit_fn emit, void *ctx);

#endif
