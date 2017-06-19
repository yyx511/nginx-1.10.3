
/*
 * Copyright (C) ali uc.
 */
 
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef _NGX_HTTP_PROXY_MODULE_H_
#define _NGX_HTTP_PROXY_MODULE_H_

typedef struct {
    ngx_array_t                    caches;  /* ngx_http_file_cache_t * */
} ngx_http_proxy_main_conf_t;


typedef struct ngx_http_proxy_rewrite_s  ngx_http_proxy_rewrite_t;

typedef ngx_int_t (*ngx_http_proxy_rewrite_pt)(ngx_http_request_t *r,
    ngx_table_elt_t *h, size_t prefix, size_t len,
    ngx_http_proxy_rewrite_t *pr);

struct ngx_http_proxy_rewrite_s {
    ngx_http_proxy_rewrite_pt      handler;

    union {
        ngx_http_complex_value_t   complex;
#if (NGX_PCRE)
        ngx_http_regex_t          *regex;
#endif
    } pattern;

    ngx_http_complex_value_t       replacement;
};


typedef struct {
    ngx_str_t                      key_start;
    ngx_str_t                      schema;
    ngx_str_t                      host_header;
    ngx_str_t                      port;
    ngx_str_t                      uri;
} ngx_http_proxy_vars_t;


typedef struct {
    ngx_array_t                   *flushes;
    ngx_array_t                   *lengths;
    ngx_array_t                   *values;
    ngx_hash_t                     hash;
} ngx_http_proxy_headers_t;


typedef struct {
    ngx_http_upstream_conf_t       upstream;

    ngx_array_t                   *body_flushes;
    ngx_array_t                   *body_lengths;
    ngx_array_t                   *body_values;
    ngx_str_t                      body_source;

    ngx_http_proxy_headers_t       headers;
#if (NGX_HTTP_CACHE)
    ngx_http_proxy_headers_t       headers_cache;
#endif
    ngx_array_t                   *headers_source;

    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;

    ngx_array_t                   *redirects;
    ngx_array_t                   *cookie_domains;
    ngx_array_t                   *cookie_paths;

    ngx_str_t                      method;
    ngx_str_t                      location;
    ngx_str_t                      url;
    ngx_str_t                      rewrite_uri;

#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t       cache_key;
#endif

    ngx_http_proxy_vars_t          vars;

    ngx_flag_t                     redirect;

    ngx_uint_t                     http_version;

    ngx_uint_t                     headers_hash_max_size;
    ngx_uint_t                     headers_hash_bucket_size;

#if (NGX_HTTP_SSL)
    ngx_uint_t                     ssl;
    ngx_uint_t                     ssl_protocols;
    ngx_str_t                      ssl_ciphers;
    ngx_uint_t                     ssl_verify_depth;
    ngx_str_t                      ssl_trusted_certificate;
    ngx_str_t                      ssl_crl;
    ngx_str_t                      ssl_certificate;
    ngx_str_t                      ssl_certificate_key;
    ngx_array_t                   *ssl_passwords;
#endif
} ngx_http_proxy_loc_conf_t;


typedef struct {
    ngx_http_status_t              status;
    ngx_http_chunked_t             chunked;
    ngx_http_proxy_vars_t          vars;
    off_t                          internal_body_length;

    ngx_chain_t                   *free;
    ngx_chain_t                   *busy;

    unsigned                       head:1;
    unsigned                       internal_chunked:1;
    unsigned                       header_sent:1;
} ngx_http_proxy_ctx_t;


extern ngx_module_t  ngx_http_proxy_module;


ngx_int_t ngx_http_proxy_eval(ngx_http_request_t *r,
    ngx_http_proxy_ctx_t *ctx, ngx_http_proxy_loc_conf_t *plcf);
#if (NGX_HTTP_CACHE)
ngx_int_t ngx_http_proxy_create_key(ngx_http_request_t *r);
#endif
ngx_int_t ngx_http_proxy_create_request(ngx_http_request_t *r);
ngx_int_t ngx_http_proxy_reinit_request(ngx_http_request_t *r);
ngx_int_t ngx_http_proxy_process_status_line(ngx_http_request_t *r);
ngx_int_t ngx_http_proxy_input_filter_init(void *data);
ngx_int_t ngx_http_proxy_copy_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);

ngx_int_t ngx_http_proxy_non_buffered_copy_filter(void *data,
    ssize_t bytes);

void ngx_http_proxy_abort_request(ngx_http_request_t *r);
void ngx_http_proxy_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

ngx_int_t ngx_http_proxy_rewrite_redirect(ngx_http_request_t *r,
	ngx_table_elt_t *h, size_t prefix);
ngx_int_t ngx_http_proxy_rewrite_cookie(ngx_http_request_t *r, ngx_table_elt_t *h);


#endif

