#ifndef __POWERTCP_H
#define __POWERTCP_H
#include <stdint.h>
#include "parse_header.h"
#define max(x, y) (((x) > (y)) ? (x) : (y))
#define max_t(type, x, y) max((type)(x), (type)(y))
#define min(x, y) (((x) < (y)) ? (x) : (y))
#define min_t(type, x, y) min((type)(x), (type)(y))
#define ULONG_MAX (-1UL)
#define MEGA 1000000UL
#define USEC_PER_SEC 1000000L
#define NSEC_PER_SEC 1000000000L
#define NSEC_PER_USEC 1000L
#define BITS_PER_BYTE 8
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_TO_BYTES(nr) __KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(char))

static const unsigned long gamma_scale = (1UL << 10);
static const unsigned long power_scale = (1UL << 16);
static const unsigned long p_norm_cutoff = 0.01 * power_scale;

/* Avoid an "initializer element is not constant" error with gcc before 8.1 by
 * using an enum instead of static const variables. No, I don't want to use
 * macros for constants here :-)
 */

const long expected_flows = 10;
const long hop_bw = 10000; /* Mbit/s */


enum { max_n_hops = 1 };

// #in "powertcp_int.c"
struct powertcp_hop_int {
	uint32_t bandwidth; /* in MByte/s */
	uint64_t ts; /* careful: in ns */
	uint32_t tx_bytes;
	uint32_t qlen;
};

struct powertcp_int {
	int n_hop;
	int path_id;
	struct powertcp_hop_int hops[max_n_hops];
};

struct powertcp_int_impl {
	struct powertcp_int cached_int;
	struct powertcp_int prev_int;
};
typedef struct powertcp_int_impl powertcp_int_impl_t;

struct powertcp_info {                                                                                                              
    unsigned long rate; // in Bps      
    unsigned long p_smooth;                                                                                                            
    unsigned long beta;    
    unsigned long base_rtt;  // in us       
    unsigned long gamma;                                                                                                         
    unsigned long host_bw; /* Mbit/s */        
    powertcp_int_impl_t int_impl;                                                                                    
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

static inline bool before(u_int32_t seq1, uint32_t seq2)
{
	return (int32_t)(seq1 - seq2) < 0;
}


static const struct powertcp_int *get_int(struct powertcp_info* ca, struct tcp_int_state *tint, const struct powertcp_int *prev_int)
{
    struct powertcp_int_impl *int_impl = &ca->int_impl;

    if (tint) {
        uint32_t bandwidth = BITS_TO_BYTES(hop_bw);
        uint64_t ts = tint->timestamp;
        // printf("ts:%lu\n", ts);
        uint32_t dt = (!prev_int ? 0 : ts - prev_int->hops[0].ts) & max_ts;
        int_impl->cached_int.n_hop = 1;
        int_impl->cached_int.path_id = 1;
        int_impl->cached_int.hops[0].bandwidth = bandwidth;
        int_impl->cached_int.hops[0].qlen = tint->qdepth;
        int_impl->cached_int.hops[0].ts = ts;
        /* In lack of a tx_bytes value, we estimate it here. A factor of
        * MEGA/USEC_PER_SEC is cancelled in the calculation:
        */
        int_impl->cached_int.hops[0].tx_bytes =
        bandwidth * dt * tint->util/ 100 / NSEC_PER_USEC;
        // printf("bandhwidth:%u,tx_bytes:%u, dt:%u,tcp_int_ival_to_util(tint->intvalecr):%u\n",bandwidth, int_impl->cached_int.hops[0].tx_bytes, dt, tint->util);
        return &int_impl->cached_int;
    }

    return NULL;
}

// #include "power_tcp-int.bpf.c"
static const struct powertcp_int *get_prev_int(struct powertcp_info* ca)
{
    struct powertcp_int *prev_int = &ca->int_impl.prev_int;

    if (prev_int->n_hop && prev_int->path_id) {
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

static unsigned long ewma(unsigned long weight, unsigned long weight_scale,
           unsigned long value, unsigned long old_value)
{
    return (weight * value + (weight_scale - weight) * old_value) / weight_scale;
}


/* Limit a value to positive, non-zero numbers. */
static unsigned long not_zero(unsigned long val)
{
    return max(1UL, val);
}

static void set_rate(struct powertcp_info* ca, unsigned long rate)
{
    ca->rate = min_t(unsigned long, rate, BITS_TO_BYTES(MEGA * ca->host_bw));
}

void update_rate(struct powertcp_info* ca, unsigned long norm_power)
{
    unsigned long rate;

    norm_power = not_zero(norm_power);
    rate = ewma(ca->gamma, gamma_scale, power_scale * ca->rate / norm_power + ca->beta, ca->rate);
    // printf("rate:%lu, norm_power:%lu, gamma:%lu, beta:%lu\n", rate, norm_power, ca->gamma, ca->beta);
    // printf("ca->rate:%lu, ca->beta:%lu\n", ca->rate, ca->beta);
    rate = not_zero(rate);
    set_rate(ca, rate);
    ca->p_smooth = norm_power;
}

unsigned long ptcp_norm_power(struct powertcp_info* ca, struct tcp_int_state *tint)
{
    unsigned long delta_t = 0;
    unsigned long p_norm = 0;
    unsigned long p_smooth = ca->p_smooth;

    const struct powertcp_int *prev_int = get_prev_int(ca);
    const struct powertcp_int *this_int = get_int(ca, tint, prev_int);
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
        const struct powertcp_hop_int *prev_hop_int = &prev_int->hops[i];
        unsigned long dt = not_zero((hop_int->ts - prev_hop_int->ts) & max_ts);
        long queue_diff = (long)hop_int->qlen - (long)prev_hop_int->qlen;
        uint32_t tx_bytes_diff = (hop_int->tx_bytes - prev_hop_int->tx_bytes) & max_tx_bytes;
        /* The variable name "current" instead of lambda would conflict with a
        * macro of the same name in asm-generic/current.h.
        */
        unsigned long lambda = not_zero((unsigned long)max(0l, queue_diff + (long)tx_bytes_diff) * (NSEC_PER_SEC / dt));  //in second
        // printf("lambda:%lu, dt:%lu, queue_diff:%ld, tx_bytes_diff:%u\n", lambda, dt, queue_diff, tx_bytes_diff);
        unsigned long bdp = hop_int->bandwidth * ca->base_rtt; //mB * us = bytes
        unsigned long voltage = hop_int->qlen + bdp; //bytes
        unsigned long hop_p = lambda * voltage; //bytes * bytes/ second
        unsigned long equilibrium = not_zero((unsigned long)hop_int->bandwidth * hop_int->bandwidth  * MEGA * ca->base_rtt / power_scale);
        // printf("hop_p:%lu, equilibrium:%lu\n", hop_p, equilibrium * 65536);
        unsigned long hop_p_norm = hop_p / equilibrium;
        if (hop_p_norm > p_norm || i == 0) {
            p_norm = hop_p_norm;
            delta_t = dt;
        }
    }

    delta_t = min(delta_t, NSEC_PER_USEC * ca->base_rtt);
    p_norm = max(p_norm_cutoff, p_norm);
    // printf("p_smooth:%lu, p_norm:%lu, \n", p_smooth, p_norm);
    p_smooth = p_smooth == 0 ? p_norm : ewma(delta_t, NSEC_PER_USEC * ca->base_rtt, p_norm, p_smooth);
    // printf("p_smooth:%lu, p_norm:%lu, \n", p_smooth, p_norm);
    return p_smooth;
}

void ptcp_reset(struct powertcp_info* ca)
{
    ca->int_impl.prev_int.path_id = 0;
    ca->int_impl.prev_int.n_hop = 0;
    set_rate(ca, BITS_TO_BYTES(MEGA * ca->host_bw));
    ca->p_smooth = 0;
}
   
void update_base_rtt(struct powertcp_info* ca, unsigned long base_rtt)
{
    ca->base_rtt = base_rtt;
}
                                                                            
void powertcp_init(struct powertcp_info* ca, unsigned long base_rtt, unsigned long host_bw, unsigned gamma)                       
{                                                                                                                                                                                                                                                                                                                                     
    ca->base_rtt = base_rtt;   
    ca->host_bw = host_bw;      
    ca->gamma = gamma;
    ca->beta = BITS_TO_BYTES(MEGA * ca->host_bw / expected_flows);                                                                                           
    ptcp_reset(ca);                                                     
}                                                                     
                                                                            
void powertcp_cong_control(struct powertcp_info* ca, struct tcp_int_state *tint)              
{                                                                                                                                                        
    unsigned long norm_power;                                                                                                                                                                                                                                                                                                   
    norm_power = ptcp_norm_power(ca,tint);   
    if (norm_power) {                                              
        update_rate(ca, norm_power);                                                       
    }                     
    ca->int_impl.prev_int = ca->int_impl.cached_int;                                                                                                 
}                                                                      

#endif

