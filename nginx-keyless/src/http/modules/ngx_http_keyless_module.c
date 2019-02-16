
/*
 * Author: suntobright
 * E-mail: suntobright@gmail.com
 */


typedef struct {
    ngx_addr_t                       *addr;
    ngx_http_complex_value_t         *value;
} ngx_http_keyserver_local_t;


typedef struct {
    ngx_msec_t                        connect_timeout;
    ngx_msec_t                        timeout;
    ngx_msec_t                        next_keyserver_timeout;
    ngx_uint_t                        next_keyserver_tries;
    ngx_flag_t                        next_keyserver;
    ngx_http_keyserver_local_t       *local;

    ngx_flag_t                        ssl_session_reuse;
    ngx_uint_t                        ssl_protocols;
    ngx_str_t                         ssl_ciphers;
    ngx_http_complex_value_t         *ssl_name;
    ngx_flag_t                        ssl_server_name;

    ngx_flag_t                        ssl_verify;
    ngx_uint_t                        ssl_verify_depth;
    ngx_str_t                         ssl_trusted_certificate;
    ngx_str_t                         ssl_crl;
    ngx_str_t                         ssl_certificate;
    ngx_str_t                         ssl_certificate_key;
    ngx_array_t                      *ssl_passwords;

    ngx_ssl_t                        *ssl;

    ngx_http_keyserver_srv_conf_t    *keyserver;
    ngx_http_complex_value_t         *keyserver_value;
} ngx_http_keyless_srv_conf_t;


static ngx_conf_bitmask_t  ngx_http_keyless_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSV1.2"), NGX_SSL_TLSv1_2 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_keyless_commands[] = {

    { ngx_string("keyless_pass"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_keyless_pass,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("keyless_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("keyless_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, timeout),
      NULL },

    { ngx_string("keyless_next_keyserver"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, next_keyserver),
      NULL },

    { ngx_string("keyless_next_keyserver_tries"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, next_keyserver_tries),
      NULL },

    { ngx_string("keyless_next_keyserver_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, next_keyserver_timeout),
      NULL },

    { ngx_string("keyless_ssl_session_reuse"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_session_reuse),
      NULL },

    { ngx_string("keyless_ssl_protocols"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_protocols),
      &ngx_http_keyless_ssl_protocols },

    { ngx_string("keyless_ssl_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_ciphers),
      NULL },

    { ngx_string("keyless_ssl_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_name),
      NULL },

    { ngx_string("keyless_ssl_server_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_server_name),
      NULL },

    { ngx_string("keyless_ssl_verify"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_verify),
      NULL },

    { ngx_string("keyless_ssl_verify_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_verify_depth),
      NULL },

    { ngx_string("keyless_ssl_trusted_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { ngx_string("keyless_ssl_crl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_crl),
      NULL },

    { ngx_string("keyless_ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_certificate),
      NULL },

    { ngx_string("keyless_ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_keyless_srv_conf_t, ssl_certificate_key),
      NULL },

    { ngx_string("keyless_ssl_password_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_keyless_ssl_password_file,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_keyless_module_ctx = {
    NULL,                               /* preconfiguration */
    NULL,                               /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    ngx_http_keyless_create_srv_conf,   /* create server configuration */
    ngx_http_keyless_merge_srv_conf,    /* merge server configuration */

    NULL,                               /* create loc configuration */
    NULL                                /* merge loc configuration */
};


ngx_module_t  ngx_http_keyless_module = {
    NGX_MODULE_V1,
    &ngx_http_keyless_module_ctx,       /* module context */
    ngx_http_keyless_commands,          /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_keyless_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_keyless_srv_conf_t *klscf = conf;

    ngx_url_t                         u;
    ngx_str_t                        *value, *url;
    ngx_http_complex_value_t          cv;
    ngx_http_core_srv_conf_t         *cscf;
    ngx_http_compile_complex_value_t  ccv;

    if (klscf->keyserver || klscf->keyserver_value) {
        return "is duplicate";
    }

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    cscf->handler = ngx_http_keyless_handler;

    value = cf->args->elts;

    url = &value[1];

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths) {
        klscf->keyserver_value = ngx_palloc(cf->pool,
                                            sizeof(ngx_http_compile_value_t));
        if (klscf->keyserver_value == NULL) {
            return NGX_CONF_ERROR;
        }

        *klscf->keyserver_value = cv;

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = *url;
    u.no_resolve = 1;

    klscf->keyserver = ngx_http_keyserver_add(cf, &u, 0);
    if (klscf->keyserver == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
