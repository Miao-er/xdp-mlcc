#include <cstdint>
#include "parse_header.h"
#define max(x, y) (((x) > (y)) ? (x) : (y))
#define max_t(type, x, y) max((type)(x), (type)(y))
#define min(x, y) (((x) < (y)) ? (x) : (y))
#define min_t(type, x, y) min((type)(x), (type)(y))
#define USEC_PER_SEC 1000000L
#define NSEC_PER_SEC 1000000000L
#define NSEC_PER_USEC 1000L
#define BITS_PER_BYTE 8
#define BITS_TO_BYTES(nr) __KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(char))
static const unsigned long cwnd_scale = (1UL << 10);
static const unsigned long fallback_host_bw = 1000; /* Mbit/s */
static const unsigned long gamma_scale = (1UL << 10);
static const unsigned long power_scale = (1UL << 16);
static const unsigned long p_norm_cutoff = 0.01 * power_scale;

/* Avoid an "initializer element is not constant" error with gcc before 8.1 by
 * using an enum instead of static const variables. No, I don't want to use
 * macros for constants here :-)
 */
enum {
	default_base_rtt = -1, /* us */
	default_beta = -1, /* Number of packets */
	default_expected_flows = 10,
	default_gamma = 921, /* ~= 0.9 * gamma_scale */
	default_hop_bw = 1000, /* Mbit/s */
	default_host_bw = 1000, /* Mbit/s */
};

long base_rtt = default_base_rtt;
long beta = default_beta; /* Number of packets */
long expected_flows = default_expected_flows;
long gamma = default_gamma;
long hop_bw = default_hop_bw; /* Mbit/s */
long host_bw = fallback_host_bw; /* Mbit/s */

struct old_cwnd {
	uint32_t snd_nxt;
	unsigned long cwnd;
};
        
struct powertcp_info {                                                                \
    unsigned long base_rtt;                                                     \
    unsigned long snd_cwnd;                                                     \
                                                                                        \
    unsigned long beta; /* number of packets scaled by cwnd_scale */            \
                                                                                        \
    struct old_cwnd old_cwnd;                                                   \
                                                                                        \
    unsigned long p_smooth;                                                     \
                                                                                        \
    /* powertcp_cong_control() seems to (unexpectedly) get called once before \
        * powertcp_init(). host_bw is still 0 then, thanks to \
        * tcp_assign_congestion_control(), and we use that as an indicator whether \
        * we are initialized. \
        */ \
    unsigned long host_bw; /* Mbit/s */                                         \                                                             \
};

enum { max_n_hops = 1 };

// #include "powertcp_int.c"
struct powertcp_hop_int {
	uint32_t bandwidth; /* in MByte/s */
	uint32_t ts; /* careful: in ns */
	uint32_t tx_bytes;
	uint32_t qlen;
};

struct powertcp_int {
	int n_hop;
	int path_id;
	struct powertcp_hop_int hops[max_n_hops];
};

/* TCP-INT's swlat field (which we optionally replace with a timestamp), is
 * only 24 bits long.
 */
static const unsigned int max_ts = 0xFFFFFFu;

/* In case the tx_bytes value is taken directly from a less-than-32-bit INT
 * field, its maximum value has to be known for correct wrap-around in
 * calculations.
 */
static const uint32_t max_tx_bytes = 0xFFFFFFFFu;

struct powertcp_int_impl {
	struct powertcp_int cached_int;
	struct powertcp_int prev_int;
};
typedef struct powertcp_int_impl powertcp_int_impl_t;


static const struct powertcp_int *get_int(struct sock *sk,
    const struct powertcp_int *prev_int)
{
    struct ptcp_powertcp *ca = inet_csk_ca(sk);
    struct powertcp_int_impl *int_impl = &ca->int_impl;
    const struct tcp_sock *tp = tcp_sk(sk);
    /* Not using tcp_int_get_state() here since it uses
    * BPF_SK_STORAGE_GET_F_CREATE. We might want to use a missing map entry as
    * an indicator to fall back to RTT-PowerTCP.
    */
    const struct tcp_int_state *tint =
    bpf_sk_storage_get(&map_tcp_int_state, sk, NULL, 0);

    if (tint) {
        uint32_t bandwidth = BITS_TO_BYTES(hop_bw);
#if USE_SWLAT_AS_TIMESTAMP
        uint32_t ts = tcp_int_hoplatecr_to_ns(tint->hoplatecr);
#else
        uint32_t ts = get_tstamp(sk);
#endif
        uint32_t dt = (!prev_int ? tp->srtt_us * (1000u >> 3) : ts - prev_int->hops[0].ts) & max_ts;

        if (dt == 0) {
            int_impl->cached_int.n_hop = 0;
            return NULL;
        }

        int_impl->cached_int.n_hop = 1;
        /* TCP-INT does not provide an identification for the path. */
        /* TODO: Evaluate if it makes sense to use the switch ID as path ID.
        * Could lead to a too frequently detected path change, though.
        */
        int_impl->cached_int.path_id = 1;

        int_impl->cached_int.hops[0].bandwidth = bandwidth;
        int_impl->cached_int.hops[0].qlen = tint->qdepth;
        int_impl->cached_int.hops[0].ts = ts;
        /* In lack of a tx_bytes value, we estimate it here. A factor of
        * MEGA/USEC_PER_SEC is cancelled in the calculation:
        */
        int_impl->cached_int.hops[0].tx_bytes =
        bandwidth *  tcp_int_ival_to_util(tint->intvalecr)/ 100 / NSEC_PER_USEC * dt;

        return &int_impl->cached_int;
    } else {
        int_impl->cached_int.n_hop = 0;
    }

    return NULL;
}

// #include "power_tcp-int.bpf.c"
static const struct powertcp_int *get_prev_int(struct sock *sk)
{
    struct ptcp_powertcp *ca = inet_csk_ca(sk);
    struct powertcp_int_impl *int_impl = &ca->int_impl;
    struct powertcp_int *prev_int = &int_impl->prev_int;

    if (prev_int->n_hop) {
    /* With TCP-INT, the difference in tx_bytes since last ACK is already
    * estimated in get_int(). The previous value must be 0 so
    * ptcp_norm_power() does not calculate a second difference with a
    * value potentially coming from a different switch.
    */
    prev_int->hops[0].tx_bytes = 0;
    return prev_int;
}

return NULL;
}


 #define POWERTCP_CONG_OPS_NAME_CONCAT2(prefix, cong_ops_name)                  \
 prefix##cong_ops_name
#define POWERTCP_CONG_OPS_NAME_CONCAT(prefix, cong_ops_name)                   \
 POWERTCP_CONG_OPS_NAME_CONCAT2(prefix, cong_ops_name)
#define POWERTCP_CONG_OPS_NAME(cong_ops_name)                                  \
 __stringify(POWERTCP_CONG_OPS_NAME_CONCAT(                             \
     POWERTCP_CONG_OPS_NAME_PREFIX, cong_ops_name))

static void clear_old_cwnds(struct sock *sk)
{
    struct powertcp *ca = inet_csk_ca(sk);
    ca->old_cwnd.cwnd = 0;
    ca->old_cwnd.snd_nxt = 0;
}

static unsigned long ewma(unsigned long weight, unsigned long weight_scale,
           unsigned long value, unsigned long old_value)
{
    return (weight * value + (weight_scale - weight) * old_value) / weight_scale;
}

/* Return the snd_cwnd that was set when the newly acknowledged segment(s) were
* sent.
*/
static unsigned long get_cwnd(const struct sock *sk)
{
    const struct powertcp *ca = inet_csk_ca(sk);
    //const struct tcp_sock *tp = tcp_sk(sk);
    //uint32_t ack_seq = tp->snd_una;

    if (ca->old_cwnd.cwnd != 0 && ca->old_cwnd.snd_nxt != 0 /*&&
        before(ca->old_cwnd.snd_nxt, ack_seq)*/) {
        return ca->old_cwnd.cwnd;
    }

    return ca->snd_cwnd;
}

/* Limit a value to positive, non-zero numbers. */
static unsigned long not_zero(unsigned long val)
{
    return max(1UL, val);
}

static void set_cwnd(struct sock *sk, unsigned long cwnd,
          struct powertcp_trace_event *trace_event)
{
    struct powertcp *ca = inet_csk_ca(sk);
    struct tcp_sock *tp = tcp_sk(sk);

    ca->snd_cwnd = cwnd;
    cwnd /= cwnd_scale;
    cwnd = min_t(unsigned long, cwnd, tp->snd_cwnd_clamp);
    tp->snd_cwnd = not_zero(cwnd);
 }
}

/* Look for the base (~= minimum) RTT (in us). */
static void update_base_rtt(struct sock *sk)
{
 struct powertcp *ca = inet_csk_ca(sk);
 const struct tcp_sock *tp = tcp_sk(sk);
 uint32_t min_rtt;

 if (base_rtt > -1) {
     ca->base_rtt = base_rtt;
     return;
 }

 min_rtt = tcp_min_rtt(tp);
 if (min_rtt != ~0U) {
     ca->base_rtt = min_rtt;
     return;
 }

 min_rtt = tp->srtt_us >> 3;
 if (min_rtt) {
     ca->base_rtt = min_rtt;
     return;
 }

 /* bbr_init_pacing_rate_from_rtt() also uses this as fallback. */
 ca->base_rtt = USEC_PER_SEC;
}

static void update_beta(struct sock *sk, unsigned long old_base_rtt)
{
 struct powertcp *ca = inet_csk_ca(sk);
 const struct tcp_sock *tp = tcp_sk(sk);

 if (beta < 0 &&
     (ca->base_rtt < old_base_rtt || old_base_rtt == ULONG_MAX)) {
     unsigned long new_beta =
         BITS_TO_BYTES(cwnd_scale /* * MEGA */ * ca->host_bw *
                   ca->base_rtt / expected_flows) /
         tp->mss_cache /* / USEC_PER_SEC */;
     ca->beta = min(ca->beta, new_beta);
 }
}

static void reset(struct sock *sk, enum tcp_ca_event ev)
{
 struct powertcp *ca = inet_csk_ca(sk);
 struct tcp_sock *tp = tcp_sk(sk);

 if (ev == CA_EVENT_TX_START || ev == CA_EVENT_CWND_RESTART) {
     unsigned long old_base_rtt = ca->base_rtt;
     update_base_rtt(sk);
     update_beta(sk, old_base_rtt);
 }

 /* Only reset those values on a CA_EVENT_CWND_RESTART (used on
  * initialization). Otherwise we would reset cwnd and rate too frequently if
  * there are frequent CA_EVENT_TX_STARTs.
  */
 if (ev == CA_EVENT_CWND_RESTART) {
     unsigned long rate = BITS_TO_BYTES(MEGA * ca->host_bw);
     unsigned long cwnd = cwnd_scale * rate * ca->base_rtt /
                  tp->mss_cache / USEC_PER_SEC;
     set_rate(sk, rate);
     set_cwnd(sk, cwnd, NULL);
     tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

     ca->p_smooth = 0;

     clear_old_cwnds(sk);
 }
}

/* Update the list of recent snd_cwnds. */
static bool update_old(struct sock *sk, unsigned long p_smooth)
{
 struct powertcp *ca = inet_csk_ca(sk);
 const struct tcp_sock *tp = tcp_sk(sk);

 if (before(ca->old_cwnd.snd_nxt, tp->snd_una) ||
     (ca->old_cwnd.cwnd == 0 && ca->old_cwnd.snd_nxt == 0)) {
     ca->old_cwnd.cwnd = ca->snd_cwnd;
     ca->old_cwnd.snd_nxt = tp->snd_nxt;
 }

 ca->p_smooth = p_smooth;

 return true;
}

static unsigned long update_window(struct sock *sk, unsigned long cwnd_old,
                unsigned long norm_power,
                struct powertcp_trace_event *trace_event)
{
 const struct powertcp *ca = inet_csk_ca(sk);
 const struct tcp_sock *tp = tcp_sk(sk);
 unsigned long base_bdp = BITS_TO_BYTES(cwnd_scale) * ca->host_bw *
              ca->base_rtt / tp->mss_cache;
 unsigned long cwnd;

 norm_power = not_zero(norm_power);
 cwnd = ewma(gamma, gamma_scale,
         power_scale * cwnd_old / norm_power + ca->beta,
         ca->snd_cwnd);
 cwnd = not_zero(cwnd);
 cwnd = min(cwnd, base_bdp);
 set_cwnd(sk, cwnd, trace_event);
 return cwnd;
}

static int ptcp_init(struct sock *sk)
{
 return int_impl_init(sk);
}

static unsigned long ptcp_norm_power(struct sock *sk,
                  const struct rate_sample *rs,
                  struct powertcp_trace_event *trace_event)
{
 const struct powertcp *ca = inet_csk_ca(sk);
 unsigned long delta_t = 0;
 unsigned long p_norm = 0;
 unsigned long p_smooth = ca->p_smooth;

 const struct powertcp_int *prev_int = get_prev_int(sk);
 const struct powertcp_int *this_int = get_int(sk, prev_int);
 int i;

 /* TODO: Do something helpful (a full reset?) when the path changes. */
 if (!this_int || !prev_int || this_int->path_id != prev_int->path_id) {
     /* Power calculations will be skipped for the first one or two ACKs.
      * p_smooth will still be 0 then. This is intentional to have power
      * smoothing start with a proper value (=p_norm) at the end of this
      * function.
      */
    return 0;
 }

 /* for each egress port i on the path */
 for (i = 0; i < this_int->n_hop && i < max_n_hops; ++i) {
     const struct powertcp_hop_int *hop_int = &this_int->hops[i];
     const struct powertcp_hop_int *prev_hop_int =
         &prev_int->hops[i];
     unsigned long dt = not_zero((hop_int->ts - prev_hop_int->ts) & max_ts);
     long queue_diff = (long)hop_int->qlen - (long)prev_hop_int->qlen;
     uint32_t tx_bytes_diff = (hop_int->tx_bytes - prev_hop_int->tx_bytes) & max_tx_bytes;
     /* The variable name "current" instead of lambda would conflict with a
      * macro of the same name in asm-generic/current.h.
      */
     unsigned long lambda = not_zero((unsigned long)max(0l, queue_diff + (long)tx_bytes_diff) * (NSEC_PER_SEC / dt));
     unsigned long bdp = hop_int->bandwidth * ca->base_rtt;
     unsigned long voltage = hop_int->qlen + bdp;
     unsigned long hop_p = lambda * voltage;
     unsigned long equilibrium = not_zero((unsigned long)hop_int->bandwidth * hop_int->bandwidth / power_scale * MEGA * ca->base_rtt);
     unsigned long hop_p_norm = hop_p / equilibrium;
     if (hop_p_norm > p_norm || i == 0) {
         p_norm = hop_p_norm;
         delta_t = dt;
     }
 }

    delta_t = min(delta_t, NSEC_PER_USEC * ca->base_rtt);
    p_norm = max(p_norm_cutoff, p_norm);
    p_smooth = p_smooth == 0 ? p_norm :
                  ewma(delta_t, NSEC_PER_USEC * ca->base_rtt,
                 p_norm, p_smooth);


 return p_smooth;
}

static void ptcp_release(struct sock *sk)
{
    int_impl_release(sk);
}

static void ptcp_reset(struct sock *sk, enum tcp_ca_event ev)
{
    struct ptcp_powertcp *ca = inet_csk_ca(sk);
    int_impl_reset(&ca->int_impl, ev);
    reset(sk, ev);
}

static bool ptcp_update_old(struct sock *sk, const struct rate_sample *rs,
             unsigned long p_smooth)
{
    struct ptcp_powertcp *ca = inet_csk_ca(sk);
    int_impl_update_old(&ca->int_impl);
    return update_old(sk, p_smooth);
}

static unsigned long
ptcp_update_window(struct sock *sk, unsigned long cwnd_old,
        unsigned long norm_power,
        struct powertcp_trace_event *trace_event)
{
    return update_window(sk, cwnd_old, norm_power, trace_event);
}



#define DEFINE_POWERTCP_VARIANT(func_prefix, cong_ops_name)                    \
 void POWERTCP_CONG_OPS_FUNC(powertcp_##func_prefix##_cwnd_event,       \
                 struct sock *sk, enum tcp_ca_event ev)     \
 {                                                                      \
     struct powertcp *ca = inet_csk_ca(sk);                         \
                                                                            \
     if (POWERTCP_UNLIKELY(ca->host_bw == 0)) {                     \
         return;                                                \
     }                                                              \
                                                                            \
     if (ev == CA_EVENT_TX_START) {                                 \
         func_prefix##_reset(sk, ev);                           \
     }                                                              \
 }                                                                      \
                                                                            \
 void POWERTCP_CONG_OPS_FUNC(powertcp_##func_prefix##_init,             \
                 struct sock *sk)                           \
 {                                                                      \
     struct powertcp *ca = inet_csk_ca(sk);                         \
                                                                            \
     BUILD_BUG_ON(sizeof(struct powertcp) > ICSK_CA_PRIV_SIZE);     \
     BUILD_BUG_ON(sizeof(struct func_prefix##_powertcp) >           \
              ICSK_CA_PRIV_SIZE);                               \
                                                                            \
     func_prefix##_init(sk);                                        \
                                                                            \
     ca->base_rtt = ULONG_MAX;                                      \
     ca->beta = beta < 0 ? ULONG_MAX : beta * cwnd_scale;           \
     ca->host_bw = get_host_bw(sk);                                 \
                                                                            \
     func_prefix##_reset(sk, CA_EVENT_CWND_RESTART);                \
                                                                            \
     require_hwtstamps(sk);                                         \
     require_pacing(sk);                                            \
 }                                                                      \
                                                                            \
 void POWERTCP_CONG_OPS_FUNC(powertcp_##func_prefix##_cong_control,     \
                 struct sock *sk,                           \
                 const struct rate_sample *rs)              \
 {                                                                      \
     struct powertcp *ca = inet_csk_ca(sk);                         \
     const struct tcp_sock *tp = tcp_sk(sk);                        \
     unsigned long cwnd_old;                                        \
     unsigned long norm_power;                                      \
     unsigned long cwnd;                                            \
     unsigned long rate;                                            \
     bool updated;                                                  \
     struct powertcp_trace_event trace_event = {};                  \
                                                                            \
     if (POWERTCP_UNLIKELY(ca->host_bw == 0)) {                     \
         return;                                                \
     }                                                              \
                                                                            \
     cwnd_old = get_cwnd(sk);                                       \
     norm_power = func_prefix##_norm_power(sk, rs, &trace_event);   \
     if (norm_power) {                                              \
         cwnd = func_prefix##_update_window(                    \
             sk, cwnd_old, norm_power, &trace_event);       \
         rate = (USEC_PER_SEC * cwnd * tp->mss_cache) /         \
                ca->base_rtt / cwnd_scale;                      \
         set_rate(sk, rate);                                    \
     }                                                              \
                                                                            \
     updated = func_prefix##_update_old(sk, rs, norm_power);        \
                                                                            \
     if (tracing_enabled() && updated && norm_power) {              \
         trace_event.rate = rate;                               \
         trace_event.sock_hash = sk->__sk_common.skc_hash;      \
         output_trace_event(&trace_event);                      \
     }                                                              \
 }                                                                      \
                                                                            \
 void POWERTCP_CONG_OPS_FUNC(powertcp_##func_prefix##_release,          \
                 struct sock *sk)                           \
 {                                                                      \
     const struct powertcp *ca = inet_csk_ca(sk);                   \
                                                                            \
     if (POWERTCP_UNLIKELY(ca->host_bw == 0)) {                     \
         return;                                                \
     }                                                              \
                                                                            \
     clear_old_cwnds(sk);                                           \
                                                                            \
     func_prefix##_release(sk);                                     \
 }                                                                      \
                                                                            \
 POWERTCP_CONG_OPS_ATTRS struct tcp_congestion_ops cong_ops_name = {    \
     .cong_avoid = POWERTCP_CONG_OPS_FUNC_PTR powertcp_cong_avoid,  \
     .cong_control = POWERTCP_CONG_OPS_FUNC_PTR                     \
         powertcp_##func_prefix##_cong_control,                 \
     .cwnd_event = POWERTCP_CONG_OPS_FUNC_PTR                       \
         powertcp_##func_prefix##_cwnd_event,                   \
     .init = POWERTCP_CONG_OPS_FUNC_PTR                             \
         powertcp_##func_prefix##_init,                         \
     .name = POWERTCP_CONG_OPS_NAME(cong_ops_name),                 \
     .release = POWERTCP_CONG_OPS_FUNC_PTR                          \
         powertcp_##func_prefix##_release,                      \
     .ssthresh = POWERTCP_CONG_OPS_FUNC_PTR powertcp_ssthresh,      \
     .undo_cwnd = POWERTCP_CONG_OPS_FUNC_PTR powertcp_undo_cwnd,    \
 }

uint32_t POWERTCP_CONG_OPS_FUNC(powertcp_ssthresh, struct sock *sk)
{
 /* We don't do slow starts here! */
 return TCP_INFINITE_SSTHRESH;
}

uint32_t POWERTCP_CONG_OPS_FUNC(powertcp_undo_cwnd, struct sock *sk)
{
 /* Never undo after a loss. */
 return tcp_sk(sk)->snd_cwnd;
}

DEFINE_POWERTCP_VARIANT(ptcp, powertcp);

