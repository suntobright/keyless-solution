
/*
 * Author: suntobright
 * E-mail: suntobright@gmail.com
 */

#ifndef _NGX_HTTP_KEYSERVER_MODULE_H_INCLUDED_
#define _NGX_HTTP_KEYSERVER_MODULE_H_INCLUDED_


#define NGX_HTTP_KEYSERVER_CREATE         0x0001
#define NGX_HTTP_KEYSERVER_WEIGHT         0x0002
#define NGX_HTTP_KEYSERVER_MAX_FAILS      0x0004
#define NGX_HTTP_KEYSERVER_FAIL_TIMEOUT   0x0008
#define NGX_HTTP_KEYSERVER_DOWN           0x0010
#define NGX_HTTP_KEYSERVER_BACKUP         0x0020
#define NGX_HTTP_KEYSERVER_MAX_CONNS      0x0100


#define NGX_HTTP_KEYSERVER_NOTIFY_CONNECT     0x1


typedef struct {
    ngx_array_t keyservers; /* ngx_http_keyserver_srv_conf_t */
} ngx_http_keyserver_main_conf_t;


typedef struct ngx_http_keyserver_srv_conf_s  ngx_http_keyserver_srv_conf_t;


typedef ngx_int_t (*ngx_http_keyserver_init_pt)(ngx_conf_t *cf,
    ngx_http_keyserver_srv_conf_t *kss);
typedef ngx_int_t (*ngx_http_keyserver_init_peer_pt)(//TODO,
    ngx_http_keyserver_srv_conf_t *kss);


typedef struct {
    ngx_http_keyserver_init_pt init_keyserver;
    ngx_http_keyserver_init_peer_pt init;
    void *data;
} ngx_http_keyserver_peer_t;


typedef struct {
    ngx_str_t name;
    ngx_addr_t *addrs;
    ngx_uint_t naddrs;
    ngx_uint_t weight;
    ngx_uint_t max_conns;
    ngx_uint_t max_fails;
    time_t fail_timeout;
    ngx_msec_t slow_start;

    unsigned down:1;
    unsigned backup:1;

    NGX_COMPAT_BEGIN(4)
    NGX_COMPAT_END
} ngx_http_keyserver_server_t;


struct ngx_http_keyserver_srv_conf_s {
    ngx_http_keyserver_peer_t peer;
    void **srv_conf;

    ngx_array_t *servers; /* ngx_http_keyserver_server_t */

    ngx_uint_t flags;
    ngx_str_t host;
    u_char *file_name;
    ngx_uint_t line;
    in_port_t port;
    ngx_uint_t no_port; /* unsigned no_port:1 */

#if (NGX_HTTP_KEYSERVER_ZONE)
    ngx_shm_zone_t *shm_zone;
#endif
};


typedef struct {
    ngx_msec_t response_time;
    ngx_msec_t connect_time;
    ngx_msec_t first_byte_time;

    ngx_str_t *peer;
} ngx_http_keyserver_state_t;


typedef struct {}


#endif
