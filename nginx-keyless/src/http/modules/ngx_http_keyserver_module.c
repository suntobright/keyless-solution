
/*
 * Author: suntobright
 * E-mail: suntobright@gmail.com
 */


static ngx_command_t  ngx_http_keyserver_commands[] = {

    { ngx_string("keyserver"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_keyserver,
      0,
      0,
      NULL },

    { ngx_string("server"),
      NGX_HTTP_KEYSERVER_CONF|NGX_CONF_1MORE,
      ngx_http_keyserver_server,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_keyserver_module_ctx = {
    ngx_http_keyserver_add_variables,     /* preconfiguration */
    NULL,                                 /* postconfiguration */

    ngx_http_keyserver_create_main_conf,  /* create main configuration */
    ngx_http_keyserver_init_main_conf,    /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    NULL,                                 /* create loc configuration */
    NULL                                  /* merge loc configuration */
};


ngx_module_t  ngx_http_keyserver_module = {
    NGX_MODULE_V1,
    &ngx_http_keyserver_module_ctx,       /* module context */
    ngx_http_keyserver_commands,          /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    NULL,                                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_keyserver_vars[] = {

    { ngx_string("keyserver_addr"), NULL,
      ngx_http_keyserver_addr_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("keyserver_connect_time"), NULL,
      ngx_http_keyserver_response_time_variable, 2,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("keyserver_first_byte_time"), NULL,
      ngx_http_keyserver_response_time_variable, 1,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("keyserver_session_time"), NULL,
      ngx_http_keyserver_response_time_varibale, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_keyserver_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_keyserver_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static char *
ngx_http_keyserver(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                           *rv;
    void                           *mconf;
    ngx_str_t                      *value;
    ngx_url_t                       u;
    ngx_uint_t                      m;
    ngx_conf_t                      pcf;
    ngx_http_module_t              *module;
    ngx_http_conf_ctx_t            *ctx, *http_ctx;
    ngx_http_keyserver_srv_conf_t  *ksscf;

    ngx_memzero(&u, sizeof(ngx_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;
    u.no_port = 1;

    ksscf = ngx_http_keyserver_add(cf, &u, NGX_HTTP_KEYSERVER_CREATE
                                           |NGX_HTTP_KEYSERVER_WEIGHT
                                           |NGX_HTTP_KEYSERVER_MAX_CONNS
                                           |NGX_HTTP_KEYSERVER_MAX_FAILS
                                           |NGX_HTTP_KEYSERVER_FAIL_TIMEOUT
                                           |NGX_HTTP_KEYSERVER_DOWN
                                           |NGX_HTTP_KEYSERVER_BACKUP);
    if (ksscf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    http_ctx = cf->ctx;
    ctx->main_conf = http_ctx->main_conf;

    /* the keyserver{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool,
                                sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->srv_conf[ngx_http_keyserver_module.ctx_index] = ksscf;

    ksscf->srv_conf = ctx->srv_conf;

    for (m = 0; cf->cycle-modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    ksscf->servers = ngx_array_create(cf->pool, 4,
                                      sizeof(ngx_http_keyserver_server_t));
    if (ksscf->servers == NULL) {
        return NGX_CONF_ERROR;
    }


    /* parse inside keyserver{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_KEYSERVER_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (uscf->servers->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no servers are inside keyserver");
        return NGX_CONF_ERROR;
    }

    return rv;
}


static char *
ngx_http_keyserver_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_keyserver_srv_conf_t *ksscf = conf;

    time_t                        fail_timeout;
    ngx_str_t                    *value, s;
    ngx_url_t                     u;
    ngx_int_t                     weight, max_conns, max_fails;
    ngx_uint_t                    i;
    ngx_http_keyserver_server_t  *kss;

    kss = ngx_array_push(ksscf->servers);
    if (kss == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(kss, sizeof(ngx_http_keyserver_server_t));

    value = cf->args->elts;

    weight = 1;
    max_conns = 0;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {
    
        if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {
        
            if (!(ksscf->flags & NGX_HTTP_KEYSERVER_WEIGHT)) {
                goto not_supported;
            }

            weight = ngx_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NGX_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_conns=", 10) == 0) {
        
            if (!(ksscf->flags & NGX_HTTP_KEYSERVER_MAX_CONNS)) {
                goto not_supported;
            }

            max_conns = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (max_conns == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {
        
            if (!(ksscf->flags & NGX_HTTP_KEYSERVER_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {
        
            if (!(ksscf->flags & NGX_HTTP_KEYSERVER_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &data[i].data[13];

            fail_timeout = ngx_parse_time(&s, 1);

            if (fail_timeout == (time_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "backup") == 0) {
        
            if (!(ksscf->flags & NGX_HTTP_KEYSERVER_BACKUP)) {
                goto not_supported;
            }

            kss->backup = 1;

            continue;
        }

        if (ngx_strcmp(value[i].data, "down") == 0) {
        
            if (!(ksscf->flags & NGX_HTTP_KEYSERVER_DOWN)) {
                goto not_supported;
            }

            kss->down = 1;

            continue;
        }

        goto invalid;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in keyserver \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    if (u.no_port) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no port in keyserver \"%V\"", &u.url);
        return NGX_CONF_ERROR;
    }

    kss->name = u.url;
    kss->addrs = u.addrs;
    kss->naddrs = u.naddrs;
    kss->weight = weight;
    kss->max_conns = max_conns;
    kss->max_fails = max_fails;
    kss->fail_timeout = fail_timeout;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;

not_supported:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return NGX_CONF_ERROR;
}


ngx_http_keyserver_srv_conf_t *
ngx_http_keyserver_add(ngx_conf_t *cf, ngx_url_t *u, ngx_uint_t flags)
{
    ngx_uint_t i;
    ngx_http_keyserver_server_t *kss;
    ngx_http_keyserver_srv_conf_t *ksscf, **ksscfp;
    ngx_http_keyserver_main_conf_t *ksmcf;

    if (!(flags & NGX_HTTP_KEYSERVER_CREATE)) {
    
        if (ngx_parse_url(cf->pool, u) != NGX_OK) {
            if (u->err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "%s in keyserver \"%V\"", u->err, &u->url);
            }

            return NULL:
        }
    }

    ksmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_keyserver_module);

    ksscfp = ksmcf->keyservers.elts;

    for (i = 0; i < ksmcf->keyservers.nelts; i++) {
    
        if (ksscfp[i]->host.len != u->host.len
            || ngx_strncasecmp(ksscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & NGX_HTTP_KEYSERVER_CREATE)
             && (ksscfp[i]->flags & NGX_HTTP_KEYSERVER_CREATE))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate keyserver \"%V\"", &u->host);
            return NULL;
        }

        if ((ksscfp[i]->flags & NGX_HTTP_KEYSERVER_CREATE) && !u->no_port) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "keyserver \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

        if ((flags & NGX_HTTP_KEYSERVER_CREATE) && !ksscfp[i]->no_port) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "keyserver \"%V\" may not have port %d in %s:%ui",
                          &u->host, ksscfp[i]->port,
                          ksscfp[i]->file_name, ksscfp[i]->line);
            return NULL;
        }

        if (ksscfp[i]->port != u->port) {
            continue;
        }

        if (flags & NGX_HTTP_KEYSERVER_CREATE) {
            ksscfp[i]->flags = flags;
        }

        return ksscfp[i];
    }

    ksscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_keyserver_srv_conf_t));
    if (ksscf == NULL) {
        return NULL;
    }

    ksscf->flags = flags;
    ksscf->host = u->host;
    ksscf->file_name = cf->conf_file->file.name.data;
    ksscf->line = cf->conf_file->line;
    ksscf->port = u->port;
    ksscf->no_port = u->no_port;

    if (u->naddrs == 1 && (u->port || u->family == AF_UNIX)) {
        ksscf->servers = ngx_array_create(cf->pool, 1,
                                          sizeof(ngx_http_keyserver_server_t));
        if (ksscf->servers == NULL) {
            return NULL;
        }

        kss = ngx_array_push(ksscf->servers);
        if (kss == NULL) {
            return NULL;
        }

        ngx_memzero(kss, sizeof(ngx_http_keyserver_server_t));

        kss->addrs = u->addrs;
        kss->naddrs = 1;
    }

    ksscfp = ngx_array_push(&ksmcf->keyservers);
    if (ksscfp == NULL) {
        return NULL;
    }

    *ksscfp = ksscf;

    return ksscf;
}


static void *
ngx_http_keyserver_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_keyserver_main_conf_t   *ksmcf;

    ksmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_keyserver_main_conf_t));
    if (ksmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&ksmcf->keyserver, cf->pool, 4,
                       sizeof(ngx_http_keyserver_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return ksmcf;
}


static char *
ngx_http_keyserver_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_keyserver_main_conf_t   *ksmcf = conf;

    ngx_uint_t                        i;
    ngx_http_keyserver_init_pt        init;
    ngx_http_keyserver_srv_conf_t   **ksscfp;

    ksscfp = ksmcf->keyserver.elts;

    for (i = 0; i < ksmcf->keyserver.nelts; i++) {
    
        init = ksscfp[i]->peer.init_keyserver
                                          ? ksscfp[i]->peer.init_keyserver
                                          : ngx_http_keyserver_init_round_robin;

        if (init(cf, ksscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
